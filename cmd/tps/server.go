package main

import (
	"bytes"
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
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"turnstile-proxy-server/internal/db"
	"turnstile-proxy-server/internal/requestid"

	"github.com/gin-contrib/multitemplate"
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

// parsedProxyRoute is the runtime form of a PROXY_TARGETS entry: a request
// path prefix paired with the parsed backend URL.
type parsedProxyRoute struct {
	Prefix string
	Target *url.URL
}

// Server wraps a [gin.Engine], encapsulating the handlers' logic and data for
// presenting the turnstile challenge, verifying the challenge, and finally
// proxying successful requests
type Server struct {
	r              *gin.Engine
	render         multitemplate.Renderer
	logger         *slog.Logger
	db             db.Store
	siteKey        string
	secretKey      string
	jwtSigningKey  []byte
	tokenLifetime  time.Duration
	bindUserAgent  bool
	requestBudget  int
	ipSwitchCost   int
	navigationOnly bool
	budgetMutex    sync.Mutex
	budgetCache    *cache.Cache
	requestCache   *cache.Cache
	proxyTargets   []parsedProxyRoute
	templates      map[string]string
}

// NewServer creates and configures a new Server instance. You must manually
// set the proxy target and JWT signing keys. The Turnstile settings are
// pre-filled with test values for an "always pass" challenge, and the logger
// is set to [slog.Default]. Use the various SetX methods to
// change these settings.
func NewServer(router *gin.Engine, store db.Store) *Server {
	var requestCache = cache.New(5*time.Minute, 10*time.Minute)

	var render = multitemplate.NewRenderer()

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
	}
	s.r.Any("/*proxyPath", s.handleProxy)

	return s
}

// SetLogger sets the logger and returns s for chaining
func (s *Server) SetLogger(l *slog.Logger) *Server {
	s.logger = l
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

// SetProxyTarget is a convenience wrapper for the single-backend case: it
// installs the given URL as a catch-all route under prefix "/".
func (s *Server) SetProxyTarget(target string) *Server {
	return s.SetProxyTargets([]proxyRoute{{Prefix: "/", Target: target}})
}

// SetProxyTargets parses each route's target URL, sorts the routes by prefix
// length (longest first) so that a longest-match lookup is just a linear
// scan, and stores them. Panics on any unparseable URL because the server
// cannot function without valid targets.
func (s *Server) SetProxyTargets(routes []proxyRoute) *Server {
	var parsed = make([]parsedProxyRoute, 0, len(routes))
	for _, r := range routes {
		var u, err = url.Parse(r.Target)
		if err != nil {
			panic(fmt.Sprintf("invalid proxy target %q: %s", r.Target, err))
		}
		parsed = append(parsed, parsedProxyRoute{Prefix: r.Prefix, Target: u})
	}
	sort.SliceStable(parsed, func(i, j int) bool {
		return len(parsed[i].Prefix) > len(parsed[j].Prefix)
	})
	s.proxyTargets = parsed
	return s
}

// pickTarget returns the backend URL for the longest configured prefix that
// matches reqPath, or nil if no prefix matches.
func (s *Server) pickTarget(reqPath string) *url.URL {
	for _, r := range s.proxyTargets {
		if strings.HasPrefix(reqPath, r.Prefix) {
			return r.Target
		}
	}
	return nil
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

// SetChallengeNavigationOnly controls whether only navigation requests (per
// [isNavigationRequest]) are challenged. When enabled, every non-navigation
// request — a single-page app's REST calls, scripts, images — is proxied
// straight through with no token required, checked, or charged. This keeps
// SPAs working when a token expires mid-session (the next page load
// re-challenges instead), at the cost of leaving those endpoints open to
// clients that present fetch metadata the way a browser's fetch() does.
func (s *Server) SetChallengeNavigationOnly(navOnly bool) *Server {
	s.navigationOnly = navOnly
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
	return got == want
}

// chargeToken debits the token's request budget for the current request: a
// normal request costs 1, while a request whose masked IP differs from the
// token's previous request costs ipSwitchCost. It returns false when the
// budget can't cover the cost, meaning the client must solve a new challenge.
// Budget state lives in memory; after a restart it is rebuilt on first sight
// of a token, giving that token a fresh budget. Tokens without a "jti" claim
// (issued before budgets existed) are rejected so they can't dodge the limit.
func (s *Server) chargeToken(token *jwt.Token, c *gin.Context) bool {
	if s.requestBudget <= 0 {
		return true
	}

	var claims, ok = token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	var jti, _ = claims["jti"].(string)
	if jti == "" {
		return false
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
	if ip != state.lastIP {
		cost = s.ipSwitchCost
	}
	if state.spent+cost > s.requestBudget {
		return false
	}

	state.spent += cost
	state.lastIP = ip
	return true
}

// LoadCoreTemplates is a general-case helper to load either from local disk
// for hot-reloads, or from an embedded filesystem, depending on the gin mode
func (s *Server) LoadCoreTemplates(pattern string, fsys fs.FS) {
	var from string
	var af afero.Fs
	if gin.Mode() == gin.ReleaseMode {
		af = afero.FromIOFS{fsys}
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

	for _, pth := range templates {
		if strings.HasSuffix(pth, ".go.html") {
			var name = "core/" + strings.Replace(filepath.Base(pth), ".go.html", "", 1)
			s.logger.Debug("Adding core template", "name", name, "path", pth)
			s.render.AddFromFS(name, afero.NewIOFS(af), pth)
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

	var err = filepath.Walk(templatePath, func(pth string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return err
		}

		if strings.HasSuffix(pth, ".go.html") {
			var name = strings.Replace(pth, templatePath+"/", "", 1)
			name = strings.Replace(name, ".go.html", "", 1)
			s.logger.Debug("Adding custom template", "name", name, "path", pth)
			s.render.AddFromFiles(name, pth)
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
	if len(s.proxyTargets) == 0 {
		return errors.New("no proxy targets configured")
	}
	s.r.HTMLRender = s.render

	logger.Debug(
		fmt.Sprintf("s.r.Run(%q)", bindAddr),
		"s.siteKey", s.siteKey,
		"s.secretKey", s.secretKey,
		"s.jwtSigningKey", s.jwtSigningKey,
		"s.proxyTargets", s.proxyTargets,
		"s.templates", s.templates,
	)
	return s.r.Run(addr)
}

func (s *Server) getTemplate(r *http.Request, shortname string) string {
	var host = r.URL.Hostname()
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

	s.logger.Debug("No custom template found, returning default")
	return "core/" + shortname
}

// isNavigationRequest reports whether the request is a top-level page
// navigation, as labeled by the browser's fetch-metadata headers. Browsers
// since roughly 2023 (Chrome 76+, Firefox 90+, Safari 16.4+) send
// Sec-Fetch-Mode on every request, and page JavaScript can neither forge nor
// suppress it. A request without the header (an old browser, or a non-browser
// client) is treated as a navigation so that a header-less scraper still gets
// challenged rather than waved through; the corner case this costs is an old
// browser whose token expires mid-session, since its in-page API calls can
// only be recognized by that token.
func isNavigationRequest(r *http.Request) bool {
	var mode = r.Header.Get("Sec-Fetch-Mode")
	return mode == "" || mode == "navigate"
}

func (s *Server) handleProxy(c *gin.Context) {
	if s.navigationOnly && !isNavigationRequest(c.Request) {
		s.logger.Debug("Non-navigation request in navigation-only mode, proxying without challenge",
			"URL", c.Request.URL.String())
		s.db.LogRequest(db.RequestLog{
			ClientIP:  c.ClientIP(),
			Timestamp: time.Now(),
			URL:       c.Request.URL.String(),
		})
		s.replayRequest(c, c.Request)
		return
	}

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
		case !s.tokenMatchesClient(token, c):
			s.logger.Warn("JWT is valid but bound to a different client, presenting challenge",
				"clientIP", c.ClientIP())
		case !s.chargeToken(token, c):
			s.logger.Warn("JWT is valid but its request budget is exhausted, presenting challenge",
				"clientIP", c.ClientIP())
		default:
			s.logger.Debug("JWT is valid, proxying request", "URL", c.Request.URL.String())
			s.db.LogRequest(db.RequestLog{
				ClientIP:      c.ClientIP(),
				Timestamp:     time.Now(),
				URL:           c.Request.URL.String(),
				HadValidToken: true,
			})
			s.replayRequest(c, c.Request)
			return
		}
	} else if err == http.ErrNoCookie {
		s.logger.Debug("No JWT, presenting challenge")
	}

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
			s.db.LogRequest(db.RequestLog{
				ClientIP:              c.ClientIP(),
				Timestamp:             time.Now(),
				URL:                   c.Request.URL.String(),
				WasPresentedChallenge: true,
				ChallengeSucceeded:    true,
			})
			s.issueTokenAndReplay(c, requestID)
		} else {
			s.logger.Warn("Turnstile verification failed", "error-codes", verifyResp.ErrorCodes)
			s.db.LogRequest(db.RequestLog{
				ClientIP:              c.ClientIP(),
				Timestamp:             time.Now(),
				URL:                   c.Request.URL.String(),
				WasPresentedChallenge: true,
				ChallengeSucceeded:    false,
			})
			c.HTML(http.StatusForbidden, s.getTemplate(c.Request, "failed"), nil)
		}
		return
	}

	// This is a new request, cache it and serve the challenge
	s.logger.Debug("handleProxy: new request, presenting challenge")
	var newRequestID = requestid.New()
	var body, readErr = io.ReadAll(c.Request.Body)
	if readErr != nil {
		s.logger.Error("Could not read original request body", "error", readErr)
		c.String(http.StatusInternalServerError, "Could not buffer request")
		return
	}
	var cachedReq = &cachedRequest{
		Method:  c.Request.Method,
		Body:    body,
		Headers: c.Request.Header,
		URL:     c.Request.URL,
	}
	s.requestCache.Set(newRequestID, cachedReq, cache.DefaultExpiration)
	s.logger.Info("No/invalid JWT, serving challenge", "requestID", newRequestID)
	c.HTML(http.StatusForbidden, s.getTemplate(c.Request, "challenge"), gin.H{
		"SiteKey":    s.siteKey,
		"RequestID":  newRequestID,
		"PostAction": c.Request.URL,
	})
}

func (s *Server) replayRequest(c *gin.Context, req *http.Request) {
	var target = s.pickTarget(req.URL.Path)
	if target == nil {
		s.logger.Warn("No proxy target matches request path", "path", req.URL.Path)
		c.String(http.StatusBadGateway, "No proxy target configured for this request")
		return
	}
	var director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
	}
	var proxy = &httputil.ReverseProxy{Director: director}
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
	c.SetCookie(cookieName, tokenString, int(s.tokenLifetime.Seconds()), "/", "", secure, true)

	var cachedReqInterface, ok = s.requestCache.Get(requestID)
	if !ok {
		s.logger.Error("Could not find cached request", "requestID", requestID)
		c.String(http.StatusInternalServerError, "Could not find original request")
		return
	}

	var cachedReq = cachedReqInterface.(*cachedRequest)
	s.logger.Debug("Replaying request", "Method", cachedReq.Method, "URL", cachedReq.URL)

	var req, reqErr = http.NewRequest(cachedReq.Method, cachedReq.URL.String(), bytes.NewReader(cachedReq.Body))
	if reqErr != nil {
		s.logger.Error("Could not create new request from cached", "requestID", requestID, "error", reqErr)
		c.String(http.StatusInternalServerError, "Could not replay original request")
		return
	}
	req.Header = cachedReq.Headers
	s.replayRequest(c, req)
}
