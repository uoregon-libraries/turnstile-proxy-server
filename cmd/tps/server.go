package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"turnstile-proxy-server/internal/db"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
)

const (
	cookieName = "tps-jwt"

	// turnstileVerifyURL is Cloudflare's siteverify endpoint, where a solved
	// challenge is checked before TPS will trust it.
	turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

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
	// verifyURL is Cloudflare's siteverify endpoint. It's a field only so tests
	// can point it at a stub; nothing in the config changes it.
	verifyURL    string
	budgetMutex  sync.Mutex
	budgetCache  *cache.Cache
	requestCache *cache.Cache
	proxyTarget  *url.URL

	// bypassKeys is the in-memory snapshot of the bypass-key table, keyed by
	// key hash and refreshed on a timer (see startBypassRefresh) so the
	// request path never waits on the database. Nil until the first load,
	// which reads as "no keys".
	bypassMu   sync.Mutex
	bypassKeys map[string]*bypassKey

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
		verifyURL:     turnstileVerifyURL,
		tokenLifetime: time.Hour,
		bindUserAgent: true,
		requestBudget: 1000,
		ipSwitchCost:  10,
		budgetCache:   cache.New(time.Hour, 10*time.Minute),
		requestCache:  requestCache,

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
// go; parseProxyTarget refuses one rather than let it look like a mount point
// it isn't. That is the same check startup runs against PROXY_TARGET, so a
// Server built directly (in a test, say) can't be given a target the
// configured path would have rejected.
func (s *Server) SetProxyTarget(target string) *Server {
	var u, err = parseProxyTarget(target)
	if err != nil {
		panic(fmt.Sprintf("invalid proxy target: %s", err))
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

// fillEvent adds the request's own dimensions to a decision event, leaving
// what was decided (Outcome, Reason, and where applicable JTI and IPSwitch) to
// the caller.
func (s *Server) fillEvent(c *gin.Context, e db.Event) db.Event {
	var ip = c.ClientIP()
	e.Timestamp = time.Now()
	e.ClientIP = ip
	e.MaskedIP = maskClientIP(ip)
	e.Host = c.Request.Host
	e.Path = c.Request.URL.Path
	e.Method = c.Request.Method
	e.UserAgent = c.Request.UserAgent()
	return e
}

// logDecision records one decision event: the caller says only what it
// decided, and the request's dimensions are filled in here so no call site can
// forget one. A caller that can't know its outcome until after it has acted on
// the request builds the event with fillEvent first and logs it when it knows
// — see the verification path in handleProxy.
func (s *Server) logDecision(c *gin.Context, e db.Event) {
	s.db.LogEvent(s.fillEvent(c, e))
}

// Run starts the server listening on the configured address
func (s *Server) Run(addr string) error {
	if len(s.jwtSigningKey) == 0 {
		return errors.New("empty JWT signing key")
	}
	if s.proxyTarget == nil {
		return errors.New("no proxy target configured")
	}

	s.logger.Debug(
		fmt.Sprintf("s.r.Run(%q)", addr),
		"s.siteKey", s.siteKey,
		// The site key is public by design; the other two are not, and a debug
		// run shouldn't be the thing that leaks them into a log file
		"s.secretKey", redactSecret(s.secretKey),
		"s.jwtSigningKey", redactSecret(string(s.jwtSigningKey)),
		"s.proxyTarget", s.proxyTarget,
		"s.templates", s.render.names(),
	)

	// Run the HTTP server until a fatal error or a termination signal. On
	// SIGINT/SIGTERM we shut down gracefully and return nil so the caller's
	// deferred cleanup (e.g. flushing the event log) runs.
	var srv = &http.Server{Addr: addr, Handler: s.r}

	var ctx, stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s.startBypassRefresh(ctx)

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
		s.logger.Info("Shutting down, draining in-flight requests")
		var shutdownCtx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
