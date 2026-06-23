package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"turnstile-proxy-server/internal/db"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
)

func TestPickTarget(t *testing.T) {
	routes := []proxyRoute{
		{Prefix: "/", Target: "http://catchall:80"},
		{Prefix: "/protected/", Target: "http://app:8080"},
		{Prefix: "/static-protected/", Target: "http://caddy:8081"},
		{Prefix: "/protected/deep/", Target: "http://app-deep:8080"},
	}
	s := (&Server{}).SetProxyTargets(routes)

	tests := []struct {
		path    string
		wantURL string
	}{
		{"/protected/foo", "http://app:8080"},
		{"/protected/deep/foo", "http://app-deep:8080"},
		{"/static-protected/index.html", "http://caddy:8081"},
		{"/anything-else", "http://catchall:80"},
		{"/", "http://catchall:80"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := s.pickTarget(tc.path)
			if got == nil {
				t.Fatalf("pickTarget(%q) returned nil, want %s", tc.path, tc.wantURL)
			}
			if got.String() != tc.wantURL {
				t.Errorf("pickTarget(%q) = %s, want %s", tc.path, got.String(), tc.wantURL)
			}
		})
	}
}

func TestPickTargetNoMatch(t *testing.T) {
	s := (&Server{}).SetProxyTargets([]proxyRoute{
		{Prefix: "/foo/", Target: "http://foo:8080"},
	})
	if got := s.pickTarget("/bar/baz"); got != nil {
		t.Errorf("pickTarget(/bar/baz) = %v, want nil", got)
	}
}

func TestPickTargetEmpty(t *testing.T) {
	s := &Server{}
	if got := s.pickTarget("/anything"); got != nil {
		t.Errorf("pickTarget on empty Server = %v, want nil", got)
	}
}

// signAndParse signs the given claims with the server's key and parses the
// result back into the *jwt.Token form the server's checks operate on
func signAndParse(t *testing.T, s *Server, claims jwt.MapClaims) *jwt.Token {
	t.Helper()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtSigningKey)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	token, err := jwt.Parse(raw, func(*jwt.Token) (interface{}, error) { return s.jwtSigningKey, nil })
	if err != nil {
		t.Fatalf("parsing token: %v", err)
	}
	return token
}

// newTestContext builds a gin context for a GET request with the given
// User-Agent and client IP, as seen via RemoteAddr
func newTestContext(t *testing.T, ua, clientIP string) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/protected/big-file", nil)
	if ua != "" {
		c.Request.Header.Set("User-Agent", ua)
	}
	c.Request.RemoteAddr = net.JoinHostPort(clientIP, "12345")
	return c
}

func TestMaskClientIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{"v4 exact", "192.0.2.55", "192.0.2.55/32"},
		{"v6 /64", "2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"v6 privacy rotation masks identically", "2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"},
		{"unparseable binds raw", "not-an-ip", "not-an-ip"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{}
			if got := s.maskClientIP(tc.ip); got != tc.want {
				t.Errorf("maskClientIP(%q) = %q, want %q", tc.ip, got, tc.want)
			}
		})
	}
}

func TestClientFingerprint(t *testing.T) {
	s := &Server{bindUserAgent: true}

	base := s.clientFingerprint(newTestContext(t, "Mozilla/5.0", "192.0.2.55"))
	if base == "" {
		t.Fatal("fingerprint is empty with binding enabled")
	}

	same := s.clientFingerprint(newTestContext(t, "Mozilla/5.0", "192.0.2.55"))
	if same != base {
		t.Error("same client produced a different fingerprint")
	}

	diffUA := s.clientFingerprint(newTestContext(t, "curl/8.0", "192.0.2.55"))
	if diffUA == base {
		t.Error("different User-Agent produced the same fingerprint")
	}

	diffIP := s.clientFingerprint(newTestContext(t, "Mozilla/5.0", "192.0.2.56"))
	if diffIP == base {
		t.Error("different IP produced the same fingerprint")
	}

	v6a := s.clientFingerprint(newTestContext(t, "Mozilla/5.0", "2001:db8:1:2:aaaa::1"))
	v6b := s.clientFingerprint(newTestContext(t, "Mozilla/5.0", "2001:db8:1:2:bbbb::2"))
	if v6a != v6b {
		t.Error("IPv6 addresses within the same /64 produced different fingerprints")
	}

	// Without UA binding or a budget, the fingerprint is IP-only, not empty
	uaOff := &Server{}
	if got := uaOff.clientFingerprint(newTestContext(t, "Mozilla/5.0", "192.0.2.55")); got == "" {
		t.Error("fingerprint is empty with UA binding off but no budget; IP should still bind")
	}

	// With a request budget, IP changes are charged rather than rejected, so
	// the IP must not be part of the fingerprint -- only the UA remains hard
	budget := &Server{bindUserAgent: true, requestBudget: 1000}
	ipA := budget.clientFingerprint(newTestContext(t, "Mozilla/5.0", "192.0.2.55"))
	ipB := budget.clientFingerprint(newTestContext(t, "Mozilla/5.0", "203.0.113.7"))
	if ipA == "" {
		t.Fatal("fingerprint is empty with UA binding enabled and a budget")
	}
	if ipA != ipB {
		t.Error("IP affected the fingerprint even though a request budget is enabled")
	}
	if ua := budget.clientFingerprint(newTestContext(t, "curl/8.0", "192.0.2.55")); ua == ipA {
		t.Error("different User-Agent produced the same fingerprint with a budget enabled")
	}

	budgetNoUA := &Server{requestBudget: 1000}
	if got := budgetNoUA.clientFingerprint(newTestContext(t, "Mozilla/5.0", "192.0.2.55")); got != "" {
		t.Errorf("fingerprint with budget enabled and UA binding off = %q, want empty", got)
	}
}

// newBudgetServer builds a server with the request budget enabled and all
// the state needed for chargeToken
func newBudgetServer(budget, switchCost int) *Server {
	return &Server{
		jwtSigningKey: []byte("test-key"),
		tokenLifetime: time.Hour,
		bindUserAgent: true,
		requestBudget: budget,
		ipSwitchCost:  switchCost,
		budgetCache:   cache.New(time.Minute, time.Minute),
	}
}

func TestChargeToken(t *testing.T) {
	claims := func(jti string) jwt.MapClaims {
		m := jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}
		if jti != "" {
			m["jti"] = jti
		}
		return m
	}

	t.Run("budget disabled charges nothing", func(t *testing.T) {
		s := newBudgetServer(0, 10)
		token := signAndParse(t, s, claims(""))
		for i := 0; i < 100; i++ {
			if !s.chargeToken(token, newTestContext(t, "Mozilla/5.0", "192.0.2.55")) {
				t.Fatal("request rejected with the budget disabled")
			}
		}
	})

	t.Run("missing jti is rejected", func(t *testing.T) {
		s := newBudgetServer(1000, 10)
		token := signAndParse(t, s, claims(""))
		if s.chargeToken(token, newTestContext(t, "Mozilla/5.0", "192.0.2.55")) {
			t.Error("token without a jti claim accepted while a budget is enabled")
		}
	})

	t.Run("steady client pays 1 per request until exhaustion", func(t *testing.T) {
		s := newBudgetServer(5, 3)
		token := signAndParse(t, s, claims("token-a"))
		c := newTestContext(t, "Mozilla/5.0", "192.0.2.55")
		for i := 0; i < 5; i++ {
			if !s.chargeToken(token, c) {
				t.Fatalf("request %d rejected before the budget was spent", i+1)
			}
		}
		if s.chargeToken(token, c) {
			t.Error("request accepted after the budget was spent")
		}
		if s.chargeToken(token, c) {
			t.Error("exhausted token recovered without a new challenge")
		}
	})

	t.Run("IP switch pays the surcharge", func(t *testing.T) {
		s := newBudgetServer(5, 3)
		token := signAndParse(t, s, claims("token-b"))
		ipA := newTestContext(t, "Mozilla/5.0", "192.0.2.55")
		ipB := newTestContext(t, "Mozilla/5.0", "203.0.113.7")

		if !s.chargeToken(token, ipA) { // spent 1
			t.Fatal("first request rejected")
		}
		if !s.chargeToken(token, ipB) { // switch: spent 4
			t.Fatal("request after IP switch rejected with budget remaining")
		}
		if !s.chargeToken(token, ipB) { // settled on B: spent 5
			t.Fatal("request from the new IP charged more than 1 after settling")
		}
		if s.chargeToken(token, ipB) {
			t.Error("request accepted after switch surcharges spent the budget")
		}
	})

	t.Run("each flap is its own switch", func(t *testing.T) {
		s := newBudgetServer(10, 3)
		token := signAndParse(t, s, claims("token-c"))
		ipA := newTestContext(t, "Mozilla/5.0", "192.0.2.55")
		ipB := newTestContext(t, "Mozilla/5.0", "2001:db8:1:2:3:4:5:6")

		// A=1, B=3, A=3, B=3 -> spent 10; next request can't be covered
		for i, c := range []*gin.Context{ipA, ipB, ipA, ipB} {
			if !s.chargeToken(token, c) {
				t.Fatalf("flap %d rejected with budget remaining", i+1)
			}
		}
		if s.chargeToken(token, ipA) {
			t.Error("request accepted after flapping spent the budget")
		}
	})

	t.Run("movement within an IPv6 /64 is not a switch", func(t *testing.T) {
		s := newBudgetServer(5, 3)
		token := signAndParse(t, s, claims("token-d"))

		if !s.chargeToken(token, newTestContext(t, "Mozilla/5.0", "2001:db8:1:2:aaaa::1")) {
			t.Fatal("first request rejected")
		}
		// Same /64 (privacy-extension rotation), so this costs 1 (spent 2),
		// not the surcharge (spent 4)
		if !s.chargeToken(token, newTestContext(t, "Mozilla/5.0", "2001:db8:1:2:bbbb::2")) {
			t.Fatal("request within the /64 rejected")
		}
		for i := 0; i < 3; i++ {
			if !s.chargeToken(token, newTestContext(t, "Mozilla/5.0", "2001:db8:1:2:bbbb::2")) {
				t.Errorf("request %d rejected: movement within the /64 was surcharged", i+3)
			}
		}
	})

	t.Run("seeded state makes the first foreign request a switch", func(t *testing.T) {
		s := newBudgetServer(5, 10)
		token := signAndParse(t, s, claims("token-e"))
		solver := newTestContext(t, "Mozilla/5.0", "192.0.2.55")
		s.budgetCache.Set("token-e", &budgetState{lastIP: s.maskClientIP(solver.ClientIP())}, time.Minute)

		if s.chargeToken(token, newTestContext(t, "Mozilla/5.0", "203.0.113.7")) {
			t.Error("surcharge larger than the budget accepted on the first request after a switch")
		}
		if !s.chargeToken(token, solver) {
			t.Error("solver's own request rejected")
		}
	})
}

func TestIsNavigationRequest(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{"", true},
		{"navigate", true},
		{"cors", false},
		{"no-cors", false},
		{"same-origin", false},
		{"websocket", false},
	}

	for _, tc := range tests {
		name := tc.mode
		if name == "" {
			name = "header absent"
		}
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/anything", nil)
			if tc.mode != "" {
				r.Header.Set("Sec-Fetch-Mode", tc.mode)
			}
			if got := isNavigationRequest(r); got != tc.want {
				t.Errorf("isNavigationRequest(Sec-Fetch-Mode: %q) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}

// newChallengeModeServer builds a full Server proxying to the given backend,
// with a stub challenge template registered so the challenge page can render
func newChallengeModeServer(t *testing.T, backendURL string, navOnly bool) *Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s := NewServer(gin.New(), db.NewNoopStore()).
		SetJWTSigningKey("test-key").
		SetProxyTarget(backendURL).
		SetChallengeNavigationOnly(navOnly)
	s.render.AddFromString("core/challenge", "challenge page {{.RequestID}}")
	return s
}

func TestChallengeNavigationOnly(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	// do sends a tokenless GET with the given Sec-Fetch-Mode ("" omits the
	// header) through a live TPS instance and returns the status and body.
	// The reverse proxy needs a real server-backed ResponseWriter, so a bare
	// httptest.NewRecorder won't do here.
	do := func(t *testing.T, s *Server, secFetchMode string) (int, string) {
		t.Helper()
		tps := httptest.NewServer(s.r)
		defer tps.Close()

		req, err := http.NewRequest("GET", tps.URL+"/protected/data", nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		if secFetchMode != "" {
			req.Header.Set("Sec-Fetch-Mode", secFetchMode)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("sending request: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading response body: %v", err)
		}
		return resp.StatusCode, string(body)
	}

	t.Run("navigation mode proxies non-navigations without a token", func(t *testing.T) {
		s := newChallengeModeServer(t, backend.URL, true)
		for _, mode := range []string{"cors", "no-cors", "same-origin", "websocket"} {
			code, body := do(t, s, mode)
			if code != http.StatusOK || !strings.Contains(body, "backend response") {
				t.Errorf("Sec-Fetch-Mode %q: got status %d, want the backend response proxied through", mode, code)
			}
		}
	})

	t.Run("navigation mode still challenges navigations", func(t *testing.T) {
		s := newChallengeModeServer(t, backend.URL, true)
		for _, mode := range []string{"navigate", ""} {
			code, body := do(t, s, mode)
			if code != http.StatusForbidden {
				t.Errorf("Sec-Fetch-Mode %q: got status %d, want %d (challenge)", mode, code, http.StatusForbidden)
			}
			if strings.Contains(body, "backend response") {
				t.Errorf("Sec-Fetch-Mode %q: backend response leaked through without a token", mode)
			}
		}
	})

	t.Run("default mode challenges non-navigations too", func(t *testing.T) {
		s := newChallengeModeServer(t, backend.URL, false)
		code, _ := do(t, s, "cors")
		if code != http.StatusForbidden {
			t.Errorf("got status %d, want %d (challenge)", code, http.StatusForbidden)
		}
	})
}

func TestTokenMatchesClient(t *testing.T) {
	s := &Server{
		logger:        slog.Default(),
		jwtSigningKey: []byte("test-key"),
		tokenLifetime: time.Hour,
		bindUserAgent: true,
	}
	solver := newTestContext(t, "Mozilla/5.0", "192.0.2.55")

	bound := signAndParse(t, s, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
		"bnd": s.clientFingerprint(solver),
	})

	if !s.tokenMatchesClient(bound, solver) {
		t.Error("token rejected for the client that solved the challenge")
	}
	if s.tokenMatchesClient(bound, newTestContext(t, "curl/8.0", "192.0.2.55")) {
		t.Error("token accepted for a client with a different User-Agent")
	}
	if s.tokenMatchesClient(bound, newTestContext(t, "Mozilla/5.0", "203.0.113.7")) {
		t.Error("token accepted for a client with a different IP")
	}

	unbound := signAndParse(t, s, jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()})
	if s.tokenMatchesClient(unbound, solver) {
		t.Error("legacy token without a binding claim accepted while binding is enabled")
	}

	// With a budget enabled and UA binding off there is no fingerprint at
	// all, so unbound tokens pass the binding check (the budget and its jti
	// requirement are the control instead)
	off := &Server{jwtSigningKey: s.jwtSigningKey, requestBudget: 1000}
	if !off.tokenMatchesClient(unbound, solver) {
		t.Error("token rejected even though no fingerprint applies")
	}
}
