package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"turnstile-proxy-server/internal/db"
	"turnstile-proxy-server/internal/requestid"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
	"github.com/spf13/afero"
)

const (
	cookieName = "tps-jwt"

	// maskBitsIPv4 / maskBitsIPv6 are how many leading bits of a client IP
	// matter when tracking the client: the exact address for IPv4, and the
	// typical single-customer delegation for IPv6 so privacy-extension
	// rotation within a /64 is invisible. These are deliberately not
	// configurable; the request budget is the tuning knob.
	maskBitsIPv4 = 32
	maskBitsIPv6 = 64

	// defaultMaxChallengeBody / defaultMaxChallengeCache bound the memory a
	// challenge can cost TPS. See [Server.SetChallengeLimits].
	defaultMaxChallengeBody  = 1 << 20   // 1MiB
	defaultMaxChallengeCache = 256 << 20 // 256MiB

	// cachedRequestOverhead is charged against the cache budget for every
	// pending challenge on top of its body, covering the URL and headers that
	// are cached alongside it. It's an estimate — measuring a header map for
	// real costs more than it's worth — but it's what keeps a flood of small
	// bodyless requests from being free.
	cachedRequestOverhead = 4096
)

// trustedProxyCIDRs lists the networks from which TPS will honor
// X-Forwarded-* headers. TPS is intended to run behind a reverse proxy on a
// private network and must never be exposed to the public internet directly,
// so only loopback and RFC 1918 / RFC 4193 ranges are trusted.
var trustedProxyCIDRs = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"::1/128",
	"fc00::/7",
}

type cachedRequest struct {
	Method  string
	Body    []byte
	Headers http.Header
	URL     *url.URL
}

// budgetState tracks how much of its request budget a token has spent, and
// the masked client IP of the token's most recent request so the next
// request can be surcharged if the client moved
type budgetState struct {
	spent  int
	lastIP string
}

// cloudflareVerifyResponse is the structure of the JSON response from Cloudflare
type cloudflareVerifyResponse struct {
	Success     bool     `json:"success"`
	ErrorCodes  []string `json:"error-codes"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
}

// Server wraps a [gin.Engine], encapsulating the handlers' logic and data for
// presenting the turnstile challenge, verifying the challenge, and finally
// proxying successful requests
type Server struct {
	r             *gin.Engine
	render        *templateStore
	logger        *slog.Logger
	db            db.Store
	siteKey       string
	secretKey     string
	jwtSigningKey []byte
	tokenLifetime time.Duration
	bindUserAgent bool
	requestBudget int
	ipSwitchCost  int
	adminSecret   string
	budgetMutex   sync.Mutex
	budgetCache   *cache.Cache
	requestCache  *cache.Cache
	proxyTarget   *url.URL
	templates     map[string]string

	maxChallengeBody  int64
	maxChallengeCache int64
	// cachedBytes is what the pending challenges in requestCache are currently
	// charged against maxChallengeCache. Reserved before an entry goes in and
	// released by the cache's eviction hook, so an expiring entry gives its
	// budget back without anyone having to remember to do it.
	cachedBytes atomic.Int64
}

// NewServer creates and configures a new Server instance. You must manually
// set the proxy target and JWT signing keys. The Turnstile settings are
// pre-filled with test values for an "always pass" challenge, and the logger
// is set to [slog.Default]. Use the various SetX methods to
// change these settings.
func NewServer(router *gin.Engine, store db.Store) *Server {
	// Sweep expired challenges every minute rather than every ten: the
	// eviction hook below is what returns their memory to the cache budget, so
	// a lazy janitor would keep TPS paying for requests that timed out long
	// ago.
	var requestCache = cache.New(5*time.Minute, time.Minute)

	// Templates hot-reload in debug mode, exactly as they would under Gin's
	// own renderers, and are parsed once in release mode
	var render = newTemplateStore(slog.Default(), gin.IsDebugging())

	router.HTMLRender = render
	var err = router.SetTrustedProxies(trustedProxyCIDRs)
	if err != nil {
		panic(fmt.Sprintf("invalid trusted proxy CIDR: %s", err))
	}

	var s = &Server{
		r:             router,
		db:            store,
		render:        render,
		logger:        slog.Default(),
		siteKey:       "1x00000000000000000000AA",
		secretKey:     "1x0000000000000000000000000000000AA",
		tokenLifetime: time.Hour,
		bindUserAgent: true,
		requestBudget: 1000,
		ipSwitchCost:  10,
		budgetCache:   cache.New(time.Hour, 10*time.Minute),
		requestCache:  requestCache,
		templates:     make(map[string]string),

		maxChallengeBody:  defaultMaxChallengeBody,
		maxChallengeCache: defaultMaxChallengeCache,
	}

	// Give a pending challenge's memory back the moment it leaves the cache,
	// however it leaves: expired by the janitor, or deleted after the replay
	// that consumed it.
	requestCache.OnEvicted(func(_ string, v any) {
		if cached, ok := v.(*cachedRequest); ok {
			s.cachedBytes.Add(-cachedRequestCost(cached.Body))
		}
	})

	s.r.Any("/*proxyPath", s.handleProxy)

	return s
}

// cachedRequestCost is what caching a request with the given body charges
// against the cache budget.
func cachedRequestCost(body []byte) int64 {
	return int64(len(body)) + cachedRequestOverhead
}

// SetLogger sets the logger and returns s for chaining
func (s *Server) SetLogger(l *slog.Logger) *Server {
	s.logger = l
	s.render.logger = l
	return s
}

// SetSecretKey sets the turnstile secret key and returns s for chaining
func (s *Server) SetSecretKey(k string) *Server {
	s.secretKey = k
	return s
}

// SetSiteKey sets the turnstile site key and returns s for chaining
func (s *Server) SetSiteKey(k string) *Server {
	s.siteKey = k
	return s
}

// SetProxyTarget parses and stores the single backend every request is
// proxied to. It panics on an unparseable URL because the server cannot
// function without a valid target. Sending different paths to different
// backends is the front proxy's job: route only the paths you want protected
// to TPS, and give TPS one backend that knows what to do with them.
//
// The target is a scheme and host only. Each request keeps its own path and
// query when it goes upstream, so a path on the target would have nowhere to
// go; validateTargetURL refuses one at startup rather than let it look like a
// mount point it isn't.
func (s *Server) SetProxyTarget(target string) *Server {
	var u, err = url.Parse(target)
	if err != nil {
		panic(fmt.Sprintf("invalid proxy target %q: %s", target, err))
	}
	s.proxyTarget = u
	return s
}

// SetJWTSigningKey stores the given key for our tokens, which are used to tell
// if a user has already completed a challenge.
func (s *Server) SetJWTSigningKey(k string) *Server {
	s.jwtSigningKey = []byte(k)
	return s
}

// SetTokenLifetime sets how long an issued token (and its cookie) stays valid
// before the client must pass another challenge.
func (s *Server) SetTokenLifetime(d time.Duration) *Server {
	s.tokenLifetime = d
	return s
}

// SetClientBinding controls whether the User-Agent header is part of the
// binding fingerprint tying a token to the client that solved the challenge.
// The client IP's role isn't configurable: it is hard-bound when the request
// budget is disabled, and surcharged on change when the budget is enabled.
func (s *Server) SetClientBinding(userAgent bool) *Server {
	s.bindUserAgent = userAgent
	return s
}

// SetAdminSecret sets the shared secret that gates /.tps/report. An empty
// secret disables the endpoint entirely (it 404s), so it is opt-in. The public
// /.tps/beacon endpoint is unaffected.
func (s *Server) SetAdminSecret(secret string) *Server {
	s.adminSecret = secret
	return s
}

// SetRequestBudget controls how many requests a single token is good for
// before the client must solve another challenge, and the surcharge applied
// when a request's masked IP differs from the token's previous request. A
// budget of 0 disables the limiter, which also restores hard IP binding:
// with no budget to charge against, an IP change means a re-challenge.
func (s *Server) SetRequestBudget(budget, switchCost int) *Server {
	s.requestBudget = budget
	s.ipSwitchCost = switchCost
	return s
}

// SetChallengeLimits bounds the memory a challenge can cost TPS.
//
// To serve a challenge, TPS has to hold the original request until the client
// solves it, so the request can be replayed afterwards. That is memory an
// unverified client — which is to say, any bot — gets to allocate: body is the
// largest single request TPS will buffer for a client it hasn't verified, and
// total is the ceiling across every challenge pending at once. Over either
// limit TPS refuses the request (413 and 503 respectively) rather than growing
// without bound, because a gate that gets OOM-killed protects nothing.
//
// Neither limit touches verified traffic: a request carrying a live token is
// streamed straight to the backend and never buffered, so a client that solved
// a challenge can upload whatever the backend accepts.
func (s *Server) SetChallengeLimits(body, total int64) *Server {
	s.maxChallengeBody = body
	s.maxChallengeCache = total
	return s
}

// maskClientIP reduces a client IP to the tracked prefix (exact address for
// IPv4, /64 for IPv6) so that address changes within that range are
// invisible — both to hard IP binding (budget disabled) and to switch
// detection (budget enabled).
func (s *Server) maskClientIP(raw string) string {
	var addr, err = netip.ParseAddr(raw)
	if err != nil {
		// Unparseable addresses still get bound, just without masking, so a
		// weird client can't opt out of IP binding entirely
		return raw
	}

	addr = addr.Unmap()
	var bits = maskBitsIPv6
	if addr.Is4() {
		bits = maskBitsIPv4
	}

	var prefix, perr = addr.Prefix(bits)
	if perr != nil {
		return raw
	}
	return prefix.String()
}

// clientFingerprint hashes the binding-relevant attributes of the requesting
// client. It returns "" when all binding options are disabled. The IP is only
// part of the fingerprint when the request budget is disabled: with a budget,
// IP changes are charged against the budget (see chargeToken) instead of
// rejected outright, so binding the token to an IP would defeat that.
func (s *Server) clientFingerprint(c *gin.Context) string {
	var ipPart string
	if s.requestBudget <= 0 {
		ipPart = s.maskClientIP(c.ClientIP())
	}

	var uaPart string
	if s.bindUserAgent {
		uaPart = c.Request.UserAgent()
	}

	if ipPart == "" && !s.bindUserAgent {
		return ""
	}

	var sum = sha256.Sum256([]byte(ipPart + "\n" + uaPart))
	return hex.EncodeToString(sum[:])
}

// tokenMatchesClient reports whether the parsed token's binding claim matches
// the client making the current request. Tokens issued before binding was
// enabled (or with a different binding config) fail the check and force a new
// challenge.
func (s *Server) tokenMatchesClient(token *jwt.Token, c *gin.Context) bool {
	var want = s.clientFingerprint(c)
	if want == "" {
		return true
	}

	var claims, ok = token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	var got, _ = claims["bnd"].(string)
	if got != want {
		s.logger.Debug("Token binding mismatch",
			"want", want, "got", got, "clientIP", c.ClientIP(),
			"userAgent", c.Request.UserAgent())
		return false
	}
	return true
}

// chargeToken debits the token's request budget for the current request: a
// normal request costs 1, while a request whose masked IP differs from the
// token's previous request costs ipSwitchCost. It returns allowed=false when
// the budget can't cover the cost, meaning the client must solve a new
// challenge, and surcharged=true when the request's IP differed from the
// token's previous one (for analytics). Budget state lives in memory; after a
// restart it is rebuilt on first sight of a token, giving that token a fresh
// budget. Tokens without a "jti" claim (issued before budgets existed) are
// rejected so they can't dodge the limit.
func (s *Server) chargeToken(token *jwt.Token, c *gin.Context) (allowed, surcharged bool) {
	if s.requestBudget <= 0 {
		return true, false
	}

	var claims, ok = token.Claims.(jwt.MapClaims)
	if !ok {
		return false, false
	}
	var jti, _ = claims["jti"].(string)
	if jti == "" {
		return false, false
	}

	var ip = s.maskClientIP(c.ClientIP())

	s.budgetMutex.Lock()
	defer s.budgetMutex.Unlock()

	var state *budgetState
	if cached, found := s.budgetCache.Get(jti); found {
		state = cached.(*budgetState)
	} else {
		state = &budgetState{lastIP: ip}
		s.budgetCache.Set(jti, state, s.tokenLifetime)
	}

	var cost = 1
	var switched = ip != state.lastIP
	if switched {
		cost = s.ipSwitchCost
	}
	if state.spent+cost > s.requestBudget {
		return false, switched
	}

	state.spent += cost
	state.lastIP = ip
	return true, switched
}

// baseEvent captures the request dimensions common to every logged decision.
// Callers set Outcome, Reason, and (where applicable) JTI and IPSwitch.
func (s *Server) baseEvent(c *gin.Context) db.Event {
	return db.Event{
		Timestamp: time.Now(),
		ClientIP:  c.ClientIP(),
		MaskedIP:  s.maskClientIP(c.ClientIP()),
		Host:      c.Request.Host,
		Path:      c.Request.URL.Path,
		Method:    c.Request.Method,
		UserAgent: c.Request.UserAgent(),
	}
}

// jtiOf returns the token's "jti" claim, or "" if absent. Used to correlate a
// session's events across requests.
func jtiOf(token *jwt.Token) string {
	var claims, ok = token.Claims.(jwt.MapClaims)
	if !ok {
		return ""
	}
	var jti, _ = claims["jti"].(string)
	return jti
}

// LoadCoreTemplates is a general-case helper to load either from local disk
// for hot-reloads, or from an embedded filesystem, depending on the gin mode
func (s *Server) LoadCoreTemplates(pattern string, fsys fs.FS) {
	var from string
	var af afero.Fs
	if gin.Mode() == gin.ReleaseMode {
		af = afero.FromIOFS{FS: fsys}
		pattern = "*.go.html"
		from = "io/fs.FS"
	} else {
		af = afero.NewOsFs()
		from = "OS Filesystem"
	}

	var templates, err = afero.Glob(af, pattern)
	if err != nil {
		s.logger.Error("Cannot load core templates", "from", from, "pattern", pattern, "error", err)
		panic("Fatal error, cannot continue without templates")
	}

	s.logger.Debug("Reading / mapping core templates", "templates", templates)
	for _, pth := range templates {
		if strings.HasSuffix(pth, ".go.html") {
			var name = "core/" + strings.Replace(filepath.Base(pth), ".go.html", "", 1)
			s.logger.Debug("Adding core template", "name", name, "path", pth)
			var addErr = s.render.addFile(name, af, pth)
			if addErr != nil {
				s.logger.Error("Cannot load core template", "from", from, "path", pth, "error", addErr)
				panic("Fatal error, cannot continue without templates")
			}
			s.templates[name] = pth
		}
	}

	return
}

// LoadCustomTemplates finds all templates under the given path named
// "*.html.go" and registers them for use as custom templates for specific
// proxied URLs' challenge and failed pages.
func (s *Server) LoadCustomTemplates(templatePath string) {
	if templatePath == "" {
		return
	}
	templatePath = filepath.Clean(templatePath)

	var err = filepath.Walk(templatePath, func(pth string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return err
		}

		if strings.HasSuffix(pth, ".go.html") {
			var name, relErr = filepath.Rel(templatePath, pth)
			if relErr != nil {
				s.logger.Error("Cannot name custom template, skipping it", "path", pth, "error", relErr)
				return nil
			}
			name = strings.TrimSuffix(name, ".go.html")
			s.logger.Debug("Adding custom template", "name", name, "path", pth)
			var addErr = s.render.addFile(name, afero.NewOsFs(), pth)
			if addErr != nil {
				// One bad custom template shouldn't cost us the rest of them;
				// the core templates can cover the paths it would have
				s.logger.Error("Cannot load custom template, skipping it", "path", pth, "error", addErr)
				return nil
			}
			s.templates[name] = pth
		}
		return err
	})
	if err != nil {
		s.logger.Error("Failed to load custom templates", "path", templatePath, "error", err)
	}
}

// Run starts the server listening on the configured address
func (s *Server) Run(addr string) error {
	if len(s.jwtSigningKey) == 0 {
		return errors.New("empty JWT signing key")
	}
	if s.proxyTarget == nil {
		return errors.New("no proxy target configured")
	}
	s.r.HTMLRender = s.render

	logger.Debug(
		fmt.Sprintf("s.r.Run(%q)", bindAddr),
		"s.siteKey", s.siteKey,
		// The site key is public by design; the other two are not, and a debug
		// run shouldn't be the thing that leaks them into a log file
		"s.secretKey", redactSecret(s.secretKey),
		"s.jwtSigningKey", redactSecret(string(s.jwtSigningKey)),
		"s.proxyTarget", s.proxyTarget,
		"s.templates", s.templates,
	)

	// Run the HTTP server until a fatal error or a termination signal. On
	// SIGINT/SIGTERM we shut down gracefully and return nil so the caller's
	// deferred cleanup (e.g. flushing the event log) runs.
	var srv = &http.Server{Addr: addr, Handler: s.r}

	var ctx, stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var errCh = make(chan error, 1)
	go func() {
		var err = srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		stop()
		logger.Info("Shutting down, draining in-flight requests")
		var shutdownCtx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// getTemplate picks the template to render for this request, most specific
// first: <hostname>/<path>/<shortname> narrowing a path segment at a time,
// then <hostname>/<shortname>, then a top-level <shortname> covering every
// host, and finally the core template built into TPS. Most sites only ever
// need that top-level pair, so it costs nothing to have the per-host and
// per-path layers available for the sites that do.
func (s *Server) getTemplate(r *http.Request, shortname string) string {
	var host = r.Host
	var path = r.URL.Path

	// Clean the path to prevent directory traversal issues
	path = filepath.Clean(path)

	// Remove leading slash
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}

	var parts = strings.Split(path, "/")
	if len(parts) == 1 && parts[0] == "" {
		parts = []string{}
	}

	for i := len(parts); i >= 0; i-- {
		var source = host + "/" + strings.Join(parts[:i], "/")
		s.logger.Debug("Looking for template", "source", source, "shortname", shortname)
		var name = filepath.Join(source, shortname)
		var template = s.templates[name]
		if template != "" {
			s.logger.Debug("Found custom template", "name", name)
			return name
		}
	}

	if s.templates[shortname] != "" {
		s.logger.Debug("Found site-wide custom template", "name", shortname)
		return shortname
	}

	s.logger.Debug("No custom template found, returning default")
	return "core/" + shortname
}

// originFormURL reports whether the request target is in the "origin-form"
// that every real client sends: an absolute path with no scheme or authority
// of its own, and no leading "//".
//
// TPS echoes the request URL straight back to the browser twice — as the
// challenge form's action and as the post-solve redirect — so a target naming
// another origin turns a link to a protected site into an attack. HTTP/1.1
// allows the absolute-form target "GET http://evil.com/x", and net/http parses
// it faithfully; a path of "//evil.com/x" is likewise a protocol-relative URL
// once a browser resolves it. Either one makes the challenge page POST the
// visitor's Turnstile solution to evil.com and then redirects the visitor
// there, wearing the protected site's "verifying you are human" page as cover.
//
// The test is on EscapedPath rather than Path because that is what URL.String
// emits: a percent-encoded "/%2f%2fevil.com" is unambiguous to a browser and
// stays allowed, while a literal "//evil.com" is not.
func originFormURL(u *url.URL) bool {
	if u.Scheme != "" || u.Host != "" || u.User != nil {
		return false
	}
	var path = u.EscapedPath()
	return strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//")
}

func (s *Server) handleProxy(c *gin.Context) {
	// Refuse anything that doesn't address this origin before it can reach a
	// handler that would echo it back to the browser. Nothing legitimate asks
	// for such a URL, so this is a flat rejection rather than an attempt to
	// rewrite the target into something safe.
	if !originFormURL(c.Request.URL) {
		s.logger.Warn("Refusing request whose target names another origin",
			"url", c.Request.URL.String(), "clientIP", c.ClientIP())
		c.String(http.StatusBadRequest, "Bad request target")
		return
	}

	// The reserved admin prefix is always handled by TPS itself and is never
	// proxied or challenged. It is checked before everything else so these
	// internal endpoints can't be shadowed by a backend path.
	if strings.HasPrefix(c.Request.URL.Path, adminPathPrefix) {
		s.handleAdmin(c)
		return
	}

	// challengeReason records why a challenge is being served, for the event
	// logged at the challenge-serving point below. It defaults to "no cookie"
	// and is overridden when a cookie is present but unusable.
	var challengeReason = db.ReasonNoCookie
	var challengeJTI string

	s.logger.Debug("handleProxy: checking for JWT")
	var cookie, err = c.Cookie(cookieName)
	if err == nil {
		var token, parseErr = jwt.Parse(cookie, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.jwtSigningKey, nil
		})

		switch {
		case parseErr != nil:
			s.logger.Warn("JWT was present but invalid, presenting challenge", "error", parseErr)
			challengeReason = db.ReasonInvalidJWT
		case !s.tokenMatchesClient(token, c):
			s.logger.Warn("JWT is valid but bound to a different client, presenting challenge",
				"clientIP", c.ClientIP())
			challengeReason = db.ReasonClientMismatch
			challengeJTI = jtiOf(token)
		default:
			var allowed, surcharged = s.chargeToken(token, c)
			if !allowed {
				s.logger.Warn("JWT is valid but its request budget is exhausted, presenting challenge",
					"clientIP", c.ClientIP())
				challengeReason = db.ReasonBudgetExhausted
				challengeJTI = jtiOf(token)
				break
			}
			s.logger.Debug("JWT is valid, proxying request", "URL", c.Request.URL.String())
			var e = s.baseEvent(c)
			e.Outcome = db.OutcomeProxied
			e.Reason = db.ReasonValidToken
			e.JTI = jtiOf(token)
			e.IPSwitch = surcharged
			s.db.LogEvent(e)
			s.replayRequest(c, c.Request)
			return
		}
	} else if err == http.ErrNoCookie {
		s.logger.Debug("No JWT, presenting challenge")
	}

	// Everything from here on either verifies a challenge or caches the
	// request so it can be replayed after one, and both need the body in
	// memory. Read it once now and hand the rest of the handler a fresh reader
	// over the same bytes: the form lookups below drain c.Request.Body, so
	// without this a challenged form POST (urlencoded or multipart) is cached
	// with an empty body and replayed to the backend with the user's data
	// gone. The valid-token path above returns before we get here, so ordinary
	// proxied traffic still streams rather than being buffered.
	// Cap what an unverified client can make TPS hold. Without this, any bot
	// can post a body of arbitrary size and TPS buffers all of it — and then
	// keeps it for the five-minute life of the request cache. A verified
	// request never reaches here, so this doesn't limit real uploads.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, s.maxChallengeBody)
	var body, readErr = io.ReadAll(c.Request.Body)
	if readErr != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(readErr, &tooLarge) {
			s.logger.Warn("Request body too large to challenge",
				"limit", s.maxChallengeBody, "clientIP", c.ClientIP(), "path", c.Request.URL.Path)
			c.String(http.StatusRequestEntityTooLarge, "Request body too large")
			return
		}
		s.logger.Error("Could not read original request body", "error", readErr)
		c.String(http.StatusInternalServerError, "Could not buffer request")
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))

	// Not a valid session, check if this is a verification attempt
	s.logger.Debug("handleProxy: checking request for turnstile POST")
	var turnstileResponse = c.PostForm("cf-turnstile-response")
	var requestID = c.PostForm("request_id")
	if c.Request.Method == "POST" && turnstileResponse != "" && requestID != "" {
		s.logger.Debug("Received turnstile response, attempting verification", "requestID", requestID)

		var verifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
		var client = &http.Client{Timeout: 10 * time.Second}
		var resp, err = client.PostForm(verifyURL, url.Values{"secret": {s.secretKey}, "response": {turnstileResponse}})
		if err != nil {
			s.logger.Error("Failed to POST to Cloudflare", "error", err)
			c.String(http.StatusInternalServerError, "Failed to verify token")
			return
		}
		defer resp.Body.Close()

		var verifyResp cloudflareVerifyResponse
		err = json.NewDecoder(resp.Body).Decode(&verifyResp)
		if err != nil {
			s.logger.Error("Failed to decode Cloudflare response", "error", err)
			c.String(http.StatusInternalServerError, "Failed to decode Cloudflare response")
			return
		}

		if verifyResp.Success {
			s.logger.Debug("Turnstile verification successful")
			var e = s.baseEvent(c)
			e.Outcome = db.OutcomeVerifyOK
			e.Reason = db.ReasonVerifiedReplay
			s.db.LogEvent(e)
			s.issueTokenAndReplay(c, requestID)
		} else {
			s.logger.Warn("Turnstile verification failed", "error-codes", verifyResp.ErrorCodes)
			var e = s.baseEvent(c)
			e.Outcome = db.OutcomeVerifyFail
			s.db.LogEvent(e)
			c.HTML(http.StatusForbidden, s.getTemplate(c.Request, "failed"), nil)
		}
		return
	}

	// This is a new request, cache it and serve the challenge
	s.logger.Debug("handleProxy: new request, presenting challenge")

	// Reserve the cache budget before taking the memory. Challenges pending at
	// once are otherwise unbounded: each one holds its request for five
	// minutes whether or not the client is still there, so a flood outlives
	// itself by five minutes and keeps growing. Shedding with a 503 is the
	// right failure here — it costs one client a challenge, where running out
	// of memory costs everyone the whole gate.
	var cost = cachedRequestCost(body)
	if s.cachedBytes.Add(cost) > s.maxChallengeCache {
		s.cachedBytes.Add(-cost)
		s.logger.Warn("Too many challenges pending to cache another request",
			"limit", s.maxChallengeCache, "clientIP", c.ClientIP(), "path", c.Request.URL.Path)
		c.String(http.StatusServiceUnavailable, "Too many challenges in flight, try again shortly")
		return
	}

	var newRequestID = requestid.New()
	var cachedReq = &cachedRequest{
		Method:  c.Request.Method,
		Body:    body,
		Headers: c.Request.Header,
		URL:     c.Request.URL,
	}
	s.requestCache.Set(newRequestID, cachedReq, cache.DefaultExpiration)
	s.logger.Info("No/invalid JWT, serving challenge", "requestID", newRequestID)
	var e = s.baseEvent(c)
	e.Outcome = db.OutcomeChallenged
	e.Reason = challengeReason
	e.JTI = challengeJTI
	s.db.LogEvent(e)
	c.HTML(http.StatusForbidden, s.getTemplate(c.Request, "challenge"), gin.H{
		"SiteKey":    s.siteKey,
		"RequestID":  newRequestID,
		"PostAction": c.Request.URL,
	})
}

func (s *Server) replayRequest(c *gin.Context, req *http.Request) {
	var target = s.proxyTarget
	if target == nil {
		s.logger.Error("No proxy target configured", "path", req.URL.Path)
		c.String(http.StatusBadGateway, "No proxy target configured")
		return
	}
	s.logger.Debug("Replaying request to backend",
		"method", req.Method, "path", req.URL.Path, "target", target.String())
	var director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
	}
	var proxy = &httputil.ReverseProxy{
		Director: director,
		// Log what the backend actually returned. A "blank screen" after a
		// challenge usually means the backend replied with an empty body, a
		// redirect, or an unexpected status, so surface the essentials.
		ModifyResponse: func(resp *http.Response) error {
			s.logger.Debug("Backend responded to replayed request",
				"path", req.URL.Path,
				"status", resp.StatusCode,
				"contentLength", resp.ContentLength,
				"contentType", resp.Header.Get("Content-Type"),
				"contentEncoding", resp.Header.Get("Content-Encoding"),
				"location", resp.Header.Get("Location"))
			return nil
		},
		// The default ErrorHandler writes a 502 with an EMPTY body and logs
		// nothing useful here, which itself looks like a blank screen. Make
		// the failure visible in both the logs and the response.
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			s.logger.Error("Backend proxy error while replaying request",
				"path", req.URL.Path, "target", target.String(), "error", err)
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("Upstream request failed"))
		},
	}
	proxy.ServeHTTP(c.Writer, req)
}

func (s *Server) issueTokenAndReplay(c *gin.Context, requestID string) {
	var jti = requestid.New()
	var claimsMap = jwt.MapClaims{
		"iss": "tps",
		"aud": "caddy",
		"jti": jti,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(s.tokenLifetime).Unix(),
		"nbf": time.Now().Unix(),
	}
	if fp := s.clientFingerprint(c); fp != "" {
		claimsMap["bnd"] = fp
	}
	if s.requestBudget > 0 {
		// Seed the budget state with the solver's IP so the first request
		// from a different address is already recognizable as a switch
		s.budgetMutex.Lock()
		s.budgetCache.Set(jti, &budgetState{lastIP: s.maskClientIP(c.ClientIP())}, s.tokenLifetime)
		s.budgetMutex.Unlock()
	}
	var claims = jwt.NewWithClaims(jwt.SigningMethodHS256, claimsMap)

	var tokenString, err = claims.SignedString(s.jwtSigningKey)
	if err != nil {
		s.logger.Error("Failed to sign JWT", "error", err)
		c.String(http.StatusInternalServerError, "Failed to create session")
		return
	}

	var secure = c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	s.logger.Debug("Issuing session cookie after successful challenge",
		"jti", jti,
		"secure", secure,
		"tls", c.Request.TLS != nil,
		"xForwardedProto", c.GetHeader("X-Forwarded-Proto"),
		"bound", claimsMap["bnd"] != nil,
		"requestID", requestID)
	c.SetCookie(cookieName, tokenString, int(s.tokenLifetime.Seconds()), "/", "", secure, true)

	var cachedReqInterface, ok = s.requestCache.Get(requestID)
	if !ok {
		s.logger.Error("Could not find cached request", "requestID", requestID)
		c.String(http.StatusInternalServerError, "Could not find original request")
		return
	}

	// This challenge is spent: the client has a cookie now, and a reload goes
	// through on its own. Dropping the entry hands its memory straight back to
	// the cache budget instead of holding it for the rest of the five-minute
	// TTL, and closes the window where a leaked request ID could be replayed.
	var cachedReq = cachedReqInterface.(*cachedRequest)
	s.requestCache.Delete(requestID)

	// For a GET, use POST/Redirect/GET: the challenge was solved via a form
	// POST to the original URL, so the browser's history entry for that URL is
	// now a POST. Replaying the GET inline would render the page once, but a
	// refresh re-submits the POST and the backend 404s (or 405s). Redirect to
	// the original URL instead; the cookie set above lets the follow-up GET
	// through, and the browser's history entry becomes a clean GET. Non-GET
	// originals (e.g. an API POST) can't be turned into a GET, so they are
	// still replayed inline.
	if cachedReq.Method == http.MethodGet {
		s.logger.Debug("Redirecting to original GET after challenge", "URL", cachedReq.URL.String())
		c.Redirect(http.StatusSeeOther, cachedReq.URL.String())
		return
	}

	s.logger.Debug("Replaying request", "Method", cachedReq.Method, "URL", cachedReq.URL)

	var req, reqErr = http.NewRequest(cachedReq.Method, cachedReq.URL.String(), bytes.NewReader(cachedReq.Body))
	if reqErr != nil {
		s.logger.Error("Could not create new request from cached", "requestID", requestID, "error", reqErr)
		c.String(http.StatusInternalServerError, "Could not replay original request")
		return
	}
	req.Header = stripConditionalHeaders(cachedReq.Headers)
	s.replayRequest(c, req)
}

// conditionalHeaders are request headers that ask the backend to answer with a
// bodyless 304/412 if the client's cached copy is still current. They are
// meaningless on a post-challenge replay: the response is delivered as the
// result of the challenge-form POST, where the browser has no cached entry to
// revalidate, so a 304 renders as a blank page. We strip them so the replay
// always yields a full response.
var conditionalHeaders = []string{
	"If-None-Match",
	"If-Modified-Since",
	"If-Match",
	"If-Unmodified-Since",
	"If-Range",
}

// stripConditionalHeaders returns a copy of h with the conditional/revalidation
// headers removed. It clones first so the cached original request (which may
// outlive this replay in the request cache) is left untouched.
func stripConditionalHeaders(h http.Header) http.Header {
	var out = h.Clone()
	if out == nil {
		return out
	}
	for _, name := range conditionalHeaders {
		out.Del(name)
	}
	return out
}
