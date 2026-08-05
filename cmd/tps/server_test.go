package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"turnstile-proxy-server/internal/db"
	"turnstile-proxy-server/internal/templates"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
)

func TestSetProxyTarget(t *testing.T) {
	s := (&Server{}).SetProxyTarget("http://app:8080")
	if s.proxyTarget == nil {
		t.Fatal("SetProxyTarget stored no target")
	}
	if got := s.proxyTarget.String(); got != "http://app:8080" {
		t.Errorf("proxyTarget = %s, want http://app:8080", got)
	}

	if unset := (&Server{}).proxyTarget; unset != nil {
		t.Errorf("proxyTarget on an unconfigured Server = %v, want nil", unset)
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

// charged calls chargeToken and returns only whether the request was allowed;
// most budget tests don't care about the surcharge flag.
func charged(s *Server, token *jwt.Token, c *gin.Context) bool {
	var allowed, _ = s.chargeToken(token, c)
	return allowed
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
			if !charged(s, token, newTestContext(t, "Mozilla/5.0", "192.0.2.55")) {
				t.Fatal("request rejected with the budget disabled")
			}
		}
	})

	t.Run("missing jti is rejected", func(t *testing.T) {
		s := newBudgetServer(1000, 10)
		token := signAndParse(t, s, claims(""))
		if charged(s, token, newTestContext(t, "Mozilla/5.0", "192.0.2.55")) {
			t.Error("token without a jti claim accepted while a budget is enabled")
		}
	})

	t.Run("steady client pays 1 per request until exhaustion", func(t *testing.T) {
		s := newBudgetServer(5, 3)
		token := signAndParse(t, s, claims("token-a"))
		c := newTestContext(t, "Mozilla/5.0", "192.0.2.55")
		for i := 0; i < 5; i++ {
			if !charged(s, token, c) {
				t.Fatalf("request %d rejected before the budget was spent", i+1)
			}
		}
		if charged(s, token, c) {
			t.Error("request accepted after the budget was spent")
		}
		if charged(s, token, c) {
			t.Error("exhausted token recovered without a new challenge")
		}
	})

	t.Run("IP switch pays the surcharge", func(t *testing.T) {
		s := newBudgetServer(5, 3)
		token := signAndParse(t, s, claims("token-b"))
		ipA := newTestContext(t, "Mozilla/5.0", "192.0.2.55")
		ipB := newTestContext(t, "Mozilla/5.0", "203.0.113.7")

		if !charged(s, token, ipA) { // spent 1
			t.Fatal("first request rejected")
		}
		if !charged(s, token, ipB) { // switch: spent 4
			t.Fatal("request after IP switch rejected with budget remaining")
		}
		if !charged(s, token, ipB) { // settled on B: spent 5
			t.Fatal("request from the new IP charged more than 1 after settling")
		}
		if charged(s, token, ipB) {
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
			if !charged(s, token, c) {
				t.Fatalf("flap %d rejected with budget remaining", i+1)
			}
		}
		if charged(s, token, ipA) {
			t.Error("request accepted after flapping spent the budget")
		}
	})

	t.Run("movement within an IPv6 /64 is not a switch", func(t *testing.T) {
		s := newBudgetServer(5, 3)
		token := signAndParse(t, s, claims("token-d"))

		if !charged(s, token, newTestContext(t, "Mozilla/5.0", "2001:db8:1:2:aaaa::1")) {
			t.Fatal("first request rejected")
		}
		// Same /64 (privacy-extension rotation), so this costs 1 (spent 2),
		// not the surcharge (spent 4)
		if !charged(s, token, newTestContext(t, "Mozilla/5.0", "2001:db8:1:2:bbbb::2")) {
			t.Fatal("request within the /64 rejected")
		}
		for i := 0; i < 3; i++ {
			if !charged(s, token, newTestContext(t, "Mozilla/5.0", "2001:db8:1:2:bbbb::2")) {
				t.Errorf("request %d rejected: movement within the /64 was surcharged", i+3)
			}
		}
	})

	t.Run("seeded state makes the first foreign request a switch", func(t *testing.T) {
		s := newBudgetServer(5, 10)
		token := signAndParse(t, s, claims("token-e"))
		solver := newTestContext(t, "Mozilla/5.0", "192.0.2.55")
		s.budgetCache.Set("token-e", &budgetState{lastIP: s.maskClientIP(solver.ClientIP())}, time.Minute)

		if charged(s, token, newTestContext(t, "Mozilla/5.0", "203.0.113.7")) {
			t.Error("surcharge larger than the budget accepted on the first request after a switch")
		}
		if !charged(s, token, solver) {
			t.Error("solver's own request rejected")
		}
	})
}

// fakeStore captures logged events in memory so tests can assert on the
// decisions handleProxy records.
type fakeStore struct {
	mu     sync.Mutex
	events []db.Event
}

func (f *fakeStore) LogEvent(e db.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

func (f *fakeStore) Close() error { return nil }

func (f *fakeStore) Report(time.Time, time.Time, time.Duration) ([]db.CountBucket, error) {
	return nil, db.ErrReportingUnavailable
}

func (f *fakeStore) snapshot() []db.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]db.Event(nil), f.events...)
}

// newTestServer builds a full Server proxying to the given backend, with a
// stub challenge template registered so the challenge page can render
func newTestServer(t *testing.T, backendURL string) *Server {
	t.Helper()
	return newTestServerWithStore(t, backendURL, db.NewNoopStore())
}

func newTestServerWithStore(t *testing.T, backendURL string, store db.Store) *Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s := NewServer(gin.New(), store).
		SetJWTSigningKey("test-key").
		SetProxyTarget(backendURL)
	if err := s.render.addString("core/challenge", "challenge page {{.RequestID}}"); err != nil {
		t.Fatalf("registering stub challenge template: %v", err)
	}
	return s
}

// TestHandleProxyLogsEvents checks that handleProxy records the expected
// decision event for a tokenless request.
func TestHandleProxyLogsEvents(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	store := &fakeStore{}
	s := newTestServerWithStore(t, backend.URL, store)

	tps := httptest.NewServer(s.r)
	defer tps.Close()
	req, _ := http.NewRequest("GET", tps.URL+"/protected/data", nil)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("sending request: %v", err)
	}
	resp.Body.Close()

	events := store.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	if events[0].Outcome != db.OutcomeChallenged || events[0].Reason != db.ReasonNoCookie {
		t.Errorf("event = {%q, %q}, want {%q, %q}",
			events[0].Outcome, events[0].Reason, db.OutcomeChallenged, db.ReasonNoCookie)
	}
	if events[0].Path != "/protected/data" {
		t.Errorf("event path = %q, want /protected/data", events[0].Path)
	}
}

// TestChallengesEveryRequestKind guards the removal of navigation-only mode:
// anything routed to TPS without a valid token gets challenged, whatever the
// browser says the request is for. Keeping background requests away from TPS
// is the front proxy's job now.
func TestChallengesEveryRequestKind(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	s := newTestServer(t, backend.URL)

	// The reverse proxy needs a real server-backed ResponseWriter, so a bare
	// httptest.NewRecorder won't do here.
	tps := httptest.NewServer(s.r)
	defer tps.Close()

	// "" omits the header entirely
	for _, mode := range []string{"", "navigate", "cors", "no-cors", "same-origin", "websocket"} {
		name := mode
		if name == "" {
			name = "header absent"
		}
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tps.URL+"/protected/data", nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			if mode != "" {
				req.Header.Set("Sec-Fetch-Mode", mode)
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

			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("got status %d, want %d (challenge)", resp.StatusCode, http.StatusForbidden)
			}
			if strings.Contains(string(body), "backend response") {
				t.Error("backend response leaked through without a token")
			}
		})
	}
}

// TestChallengedPostKeepsItsBody covers the body a user is about to lose: the
// handler asks gin for the Turnstile form fields before it caches the original
// request, and gin's form helpers drain the body to answer. If the body isn't
// buffered first, a challenged form submission is cached empty and replayed to
// the backend with the user's data gone.
func TestChallengedPostKeepsItsBody(t *testing.T) {
	var multipartBody = "--XX\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nrye bread\r\n--XX--\r\n"

	var tests = []struct {
		name        string
		contentType string
		body        string
	}{
		{"urlencoded", "application/x-www-form-urlencoded", "q=rye+bread&page=2"},
		{"multipart", "multipart/form-data; boundary=XX", multipartBody},
		{"json", "application/json", `{"q":"rye bread"}`},
		{"no content type", "", "plain old bytes"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
			defer backend.Close()
			s := newTestServer(t, backend.URL)

			req := httptest.NewRequest("POST", "/search", strings.NewReader(tc.body))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			w := httptest.NewRecorder()
			s.r.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Fatalf("got status %d, want %d (challenge)", w.Code, http.StatusForbidden)
			}

			var cached []*cachedRequest
			for _, item := range s.requestCache.Items() {
				cached = append(cached, item.Object.(*cachedRequest))
			}
			if len(cached) != 1 {
				t.Fatalf("got %d cached requests, want 1", len(cached))
			}
			if got := string(cached[0].Body); got != tc.body {
				t.Errorf("cached body = %q (%d bytes), want %q (%d bytes)",
					got, len(got), tc.body, len(tc.body))
			}
			if cached[0].Method != http.MethodPost {
				t.Errorf("cached method = %q, want POST", cached[0].Method)
			}
		})
	}
}

// TestChallengeBodyLimit covers the memory an unverified client gets to make
// TPS allocate. Serving a challenge means buffering the original request and
// holding it for the life of the request cache, so without a cap any bot can
// hand TPS a body of whatever size it likes and have it kept for five minutes.
func TestChallengeBodyLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer backend.Close()

	tests := []struct {
		name     string
		size     int
		wantCode int
	}{
		{"under the limit is challenged", 32, http.StatusForbidden},
		{"at the limit is challenged", 64, http.StatusForbidden},
		{"over the limit is refused", 65, http.StatusRequestEntityTooLarge},
		{"far over the limit is refused", 1 << 16, http.StatusRequestEntityTooLarge},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, backend.URL).SetChallengeLimits(64, 1<<20)

			req := httptest.NewRequest("POST", "/search", strings.NewReader(strings.Repeat("x", tc.size)))
			w := httptest.NewRecorder()
			s.r.ServeHTTP(w, req)

			if w.Code != tc.wantCode {
				t.Errorf("%d-byte body got status %d, want %d", tc.size, w.Code, tc.wantCode)
			}
			// A refused request must not have been cached on the way out.
			wantCached := 0
			if tc.wantCode == http.StatusForbidden {
				wantCached = 1
			}
			if got := s.requestCache.ItemCount(); got != wantCached {
				t.Errorf("%d cached requests after a %d status, want %d", got, w.Code, wantCached)
			}
		})
	}
}

// TestChallengeCacheBudget checks the ceiling across all pending challenges,
// which is the half the per-request limit can't cover: each cached request is
// held for five minutes whether or not its client is still there, so a flood
// of individually-legal requests still adds up without a total.
func TestChallengeCacheBudget(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer backend.Close()

	// Room for exactly three pending challenges, counting the flat per-entry
	// overhead every cached request is charged.
	s := newTestServer(t, backend.URL).SetChallengeLimits(1<<20, 3*cachedRequestOverhead)

	challenge := func() int {
		req := httptest.NewRequest("GET", "/protected/data", nil)
		w := httptest.NewRecorder()
		s.r.ServeHTTP(w, req)
		return w.Code
	}

	for i := range 3 {
		if code := challenge(); code != http.StatusForbidden {
			t.Fatalf("challenge %d got status %d, want %d", i+1, code, http.StatusForbidden)
		}
	}

	if code := challenge(); code != http.StatusServiceUnavailable {
		t.Errorf("challenge past the budget got status %d, want %d", code, http.StatusServiceUnavailable)
	}
	if got := s.requestCache.ItemCount(); got != 3 {
		t.Errorf("%d cached requests, want 3 (the shed request must not be cached)", got)
	}

	// Expiring a pending challenge has to give its budget back, or the cache
	// silently ratchets shut over the life of the process. Delete is the path
	// the janitor takes for a challenge nobody solved (and the one the replay
	// takes for a challenge somebody did) — not Flush, which drops items
	// without running the eviction hook the accounting hangs on.
	for key := range s.requestCache.Items() {
		s.requestCache.Delete(key)
	}
	if got := s.cachedBytes.Load(); got != 0 {
		t.Errorf("cachedBytes = %d after the pending challenges expired, want 0", got)
	}
	if code := challenge(); code != http.StatusForbidden {
		t.Errorf("challenge after the cache drained got status %d, want %d", code, http.StatusForbidden)
	}
}

// TestReplayReleasesCachedRequest pairs with the budget above: a solved
// challenge is spent, so its request should leave the cache immediately rather
// than sitting on its memory for the rest of the TTL.
func TestReplayReleasesCachedRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := NewServer(gin.New(), db.NewNoopStore()).
		SetJWTSigningKey("test-key").
		SetProxyTarget("http://backend:8080")

	body := []byte("q=rye+bread")
	s.cachedBytes.Add(cachedRequestCost(body))
	s.requestCache.Set("req-1", &cachedRequest{
		Method:  http.MethodGet,
		Body:    body,
		Headers: http.Header{},
		URL:     &url.URL{Path: "/protected/data"},
	}, cache.DefaultExpiration)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/protected/data", nil)
	s.issueTokenAndReplay(c, "req-1")

	if _, found := s.requestCache.Get("req-1"); found {
		t.Error("the cached request survived the replay that consumed it")
	}
	if got := s.cachedBytes.Load(); got != 0 {
		t.Errorf("cachedBytes = %d after the replay, want 0", got)
	}
}

// solveChallenge drives a full challenge solution through handleProxy against
// a stubbed Cloudflare that accepts everything, and returns the events logged
// along the way. requestID is submitted as-is, so a caller can hand over one
// that was never cached (or has expired) to exercise the failure path.
// originalMethod goes in the form field of the same name; empty leaves it out,
// standing in for a hand-written challenge form that doesn't send it.
func solveChallenge(t *testing.T, s *Server, requestID, originalMethod string) ([]db.Event, *httptest.ResponseRecorder) {
	t.Helper()

	cloudflare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success": true}`))
	}))
	defer cloudflare.Close()
	s.verifyURL = cloudflare.URL

	form := url.Values{"cf-turnstile-response": {"solved"}, "request_id": {requestID}}
	if originalMethod != "" {
		form.Set("original_method", originalMethod)
	}
	req := httptest.NewRequest("POST", "/protected/data", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	s.r.ServeHTTP(w, req)

	store, ok := s.db.(*fakeStore)
	if !ok {
		t.Fatalf("server's store is %T, not a *fakeStore", s.db)
	}
	return store.snapshot(), w
}

// TestVerifyErrorIsNotCountedAsSolved is the event side of the return value
// above: when Cloudflare accepts a solution but TPS can't act on it, the
// request gets its own outcome. It must not inflate the solved count, and it
// must not land in verify_fail either, which means "the client failed the
// challenge" and drives the bot signal.
func TestVerifyErrorIsNotCountedAsSolved(t *testing.T) {
	t.Run("a replayable request is solved", func(t *testing.T) {
		s := newTestServerWithStore(t, "http://backend:8080", &fakeStore{})
		s.requestCache.Set("req-1", &cachedRequest{
			Method: http.MethodGet, Headers: http.Header{}, URL: &url.URL{Path: "/protected/data"},
		}, cache.DefaultExpiration)

		events, w := solveChallenge(t, s, "req-1", http.MethodGet)
		if len(events) != 1 {
			t.Fatalf("got %d events, want 1: %+v", len(events), events)
		}
		if events[0].Outcome != db.OutcomeVerifyOK {
			t.Errorf("outcome = %q, want %q", events[0].Outcome, db.OutcomeVerifyOK)
		}
		if w.Code != http.StatusSeeOther {
			t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
		}
	})

	t.Run("a solve TPS cannot act on is not solved", func(t *testing.T) {
		s := newTestServerWithStore(t, "http://backend:8080", &fakeStore{})

		events, _ := solveChallenge(t, s, "never-cached", http.MethodPost)
		if len(events) != 1 {
			t.Fatalf("got %d events, want 1: %+v", len(events), events)
		}
		if events[0].Outcome != db.OutcomeVerifyError {
			t.Errorf("outcome = %q, want %q", events[0].Outcome, db.OutcomeVerifyError)
		}
		if events[0].Reason != db.ReasonChallengeExpired {
			t.Errorf("reason = %q, want %q", events[0].Reason, db.ReasonChallengeExpired)
		}
	})
}

// TestExpiredChallengeRecovery covers the client who leaves the challenge page
// sitting for longer than the request cache's TTL. They come back and solve it,
// and the cookie they get is perfectly good -- the only thing missing is the
// request they were making, which the challenge form still describes well
// enough to recover a GET from.
func TestExpiredChallengeRecovery(t *testing.T) {
	tests := []struct {
		name           string
		originalMethod string
		wantStatus     int
		wantSolved     bool
	}{
		{
			name:           "a GET is reissued as a redirect",
			originalMethod: http.MethodGet,
			wantStatus:     http.StatusSeeOther,
			wantSolved:     true,
		},
		{
			// The body is what expired, so there is nothing to send on. Quietly
			// redirecting would turn the user's submission into a page view that
			// looks like it worked.
			name:           "a POST is told what happened",
			originalMethod: http.MethodPost,
			wantStatus:     http.StatusRequestTimeout,
		},
		{
			// A hand-written challenge form that predates the field. Guessing
			// GET would usually be right, and would silently discard data when
			// it wasn't.
			name:       "an undeclared method is not guessed at",
			wantStatus: http.StatusRequestTimeout,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServerWithStore(t, "http://backend:8080", &fakeStore{})

			// Nothing in the cache under this ID is exactly the state a solve
			// after the five-minute TTL arrives in
			events, w := solveChallenge(t, s, "long-expired", tc.originalMethod)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			if w.Result().Cookies() == nil {
				t.Error("no cookie was set; the client solved the challenge and should be verified")
			}
			if tc.wantStatus == http.StatusSeeOther {
				if got := w.Header().Get("Location"); got != "/protected/data" {
					t.Errorf("Location = %q, want the original URL", got)
				}
			}

			if len(events) != 1 {
				t.Fatalf("got %d events, want 1: %+v", len(events), events)
			}
			var wantOutcome = db.OutcomeVerifyError
			if tc.wantSolved {
				wantOutcome = db.OutcomeVerifyOK
			}
			if events[0].Outcome != wantOutcome {
				t.Errorf("outcome = %q, want %q", events[0].Outcome, wantOutcome)
			}
		})
	}
}

// TestChallengePageCarriesOriginalMethod is what makes the recovery above
// possible: the method has to survive the round trip through the challenge
// page, since the cache entry that would otherwise hold it is gone by then.
func TestChallengePageCarriesOriginalMethod(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer backend.Close()

	var mode = gin.Mode()
	gin.SetMode(gin.ReleaseMode)
	defer gin.SetMode(mode)

	s := NewServer(gin.New(), &fakeStore{}).
		SetJWTSigningKey("test-key").
		SetProxyTarget(backend.URL)
	s.LoadCoreTemplates("internal/templates/*.go.html", templates.FS)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.r.ServeHTTP(w, httptest.NewRequest(method, "/protected/data", nil))

			var want = `name="original_method" value="` + method + `"`
			if !strings.Contains(w.Body.String(), want) {
				t.Errorf("challenge page is missing %q:\n%s", want, w.Body.String())
			}
		})
	}
}

// TestVerifiedRequestIsNotBodyLimited guards the other side of the body cap:
// the limit exists to bound what an *unverified* client can allocate, and a
// request carrying a live token is streamed to the backend rather than
// buffered, so a real upload must not be capped by it.
func TestVerifiedRequestIsNotBodyLimited(t *testing.T) {
	var got atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		got.Store(n)
	}))
	defer backend.Close()

	// Budget on and User-Agent binding off leaves nothing for the token to be
	// bound to, so a bare signed token is accepted and takes the proxy path.
	s := newTestServer(t, backend.URL).
		SetChallengeLimits(64, 1<<20).
		SetRequestBudget(10, 1).
		SetClientBinding(false)

	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"jti": "token-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(s.jwtSigningKey)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}

	// Through a real listener rather than a recorder: ReverseProxy needs a
	// ResponseWriter that implements http.CloseNotifier, which
	// httptest.ResponseRecorder doesn't.
	tps := httptest.NewServer(s.r)
	defer tps.Close()

	const size = 4096
	req, err := http.NewRequest("POST", tps.URL+"/upload", strings.NewReader(strings.Repeat("x", size)))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: cookieName, Value: raw})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200 (proxied)", resp.StatusCode)
	}
	if n := got.Load(); n != size {
		t.Errorf("backend received %d bytes, want %d — a verified upload was capped", n, size)
	}
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

func TestStripConditionalHeaders(t *testing.T) {
	orig := http.Header{
		"If-None-Match":       {`"abc123"`},
		"If-Modified-Since":   {"Wed, 21 Oct 2025 07:28:00 GMT"},
		"If-Match":            {`"abc123"`},
		"If-Unmodified-Since": {"Wed, 21 Oct 2025 07:28:00 GMT"},
		"If-Range":            {`"abc123"`},
		"User-Agent":          {"Mozilla/5.0"},
		"Accept":              {"text/html"},
	}

	stripped := stripConditionalHeaders(orig)

	for _, name := range conditionalHeaders {
		if stripped.Get(name) != "" {
			t.Errorf("conditional header %q survived stripping", name)
		}
		// The cached original must be left intact for any later use.
		if orig.Get(name) == "" {
			t.Errorf("stripping mutated the source header %q", name)
		}
	}
	if stripped.Get("User-Agent") != "Mozilla/5.0" {
		t.Error("non-conditional header User-Agent was dropped")
	}
	if stripped.Get("Accept") != "text/html" {
		t.Error("non-conditional header Accept was dropped")
	}
}

func TestOriginFormURL(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"ordinary path", "/protected/data", true},
		{"path with query", "/protected/data?a=1", true},
		{"root", "/", true},
		{"inner double slash is fine", "/protected//data", true},
		{"encoded leading slashes are unambiguous", "/%2f%2fevil.com/x", true},
		{"protocol-relative", "//evil.com/x", false},
		{"protocol-relative with query", "//evil.com/x?a=1", false},
		{"absolute form", "http://evil.com/x", false},
		{"absolute form with userinfo", "http://user@evil.com/x", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.ParseRequestURI(tc.target)
			if err != nil {
				t.Fatalf("parsing %q: %v", tc.target, err)
			}
			if got := originFormURL(u); got != tc.want {
				t.Errorf("originFormURL(%q) = %v, want %v", tc.target, got, tc.want)
			}
		})
	}
}

// TestRejectsOffOriginRequestTarget is the end-to-end half of the check above.
// TPS echoes the request URL into the challenge form's action and into the
// post-solve redirect, so a target naming another origin would have the
// challenge page POST the visitor's Turnstile solution to that origin and then
// redirect the visitor there. Both spellings have to be refused outright, and
// the attacker's host must not appear anywhere in the response.
//
// These targets are sent over a raw socket because net/http's client refuses
// to put them on the wire, which is exactly why they need a test: only a
// hand-rolled request (or a browser following a crafted link) produces them.
func TestRejectsOffOriginRequestTarget(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	tps := httptest.NewServer(newTestServer(t, backend.URL).r)
	defer tps.Close()

	for _, target := range []string{"//evil.com/x", "http://evil.com/x", "//evil.com/x?a=1"} {
		t.Run(target, func(t *testing.T) {
			conn, err := net.Dial("tcp", strings.TrimPrefix(tps.URL, "http://"))
			if err != nil {
				t.Fatalf("dialing test server: %v", err)
			}
			defer conn.Close()

			_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: good.example\r\nConnection: close\r\n\r\n", target)
			if err != nil {
				t.Fatalf("writing request: %v", err)
			}

			raw, err := io.ReadAll(conn)
			if err != nil {
				t.Fatalf("reading response: %v", err)
			}
			resp := string(raw)

			if !strings.HasPrefix(resp, "HTTP/1.1 400 ") {
				t.Errorf("target %q got status line %q, want 400",
					target, strings.SplitN(resp, "\r\n", 2)[0])
			}
			if strings.Contains(resp, "evil.com") {
				t.Errorf("target %q had the off-origin host reflected into the response:\n%s", target, resp)
			}
		})
	}
}

func TestIssueTokenRedirectsForGet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := NewServer(gin.New(), db.NewNoopStore()).
		SetJWTSigningKey("test-key").
		SetProxyTarget("http://backend:8080")

	const reqID = "req-1"
	origURL := httptest.NewRequest(http.MethodGet, "/protected/big-file?page=2", nil).URL
	s.requestCache.Set(reqID, &cachedRequest{
		Method:  http.MethodGet,
		URL:     origURL,
		Headers: http.Header{},
	}, cache.DefaultExpiration)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	// The challenge form POSTs to the original URL; that POST is what reaches
	// issueTokenAndReplay.
	c.Request = httptest.NewRequest(http.MethodPost, "/protected/big-file?page=2", nil)

	s.issueTokenAndReplay(c, reqID)

	// Assert gin's buffered status rather than rec.Code: on a POST redirect
	// http.Redirect writes no body, so gin only flushes the status to the
	// recorder during its engine's end-of-handler pass, which a direct call
	// skips. (Routed through the engine this really is a 303.)
	if c.Writer.Status() != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d (POST/Redirect/GET)", c.Writer.Status(), http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/protected/big-file?page=2" {
		t.Errorf("Location = %q, want the original GET URL", loc)
	}
	if rec.Header().Get("Set-Cookie") == "" {
		t.Error("expected a session cookie to be set before redirecting")
	}
}

// writeCustomTemplates builds a template directory from a map of relative
// path (minus the .go.html suffix) to file content, and returns its root
func writeCustomTemplates(t *testing.T, files map[string]string) string {
	t.Helper()
	var root = t.TempDir()
	for name, content := range files {
		var path = filepath.Join(root, name+".go.html")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatalf("making template dir for %q: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("writing template %q: %v", name, err)
		}
	}
	return root
}

// TestGetTemplateResolution covers the whole lookup order: a path-specific
// template beats a host-specific one, which beats a single top-level pair
// covering every host, which beats the templates built into TPS.
func TestGetTemplateResolution(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := NewServer(gin.New(), db.NewNoopStore()).SetJWTSigningKey("test-key")
	s.LoadCustomTemplates(writeCustomTemplates(t, map[string]string{
		"challenge":                       "site-wide challenge",
		"failed":                          "site-wide failure",
		"example.test/challenge":          "host challenge",
		"example.test/search/challenge":   "path challenge",
		"example.test/search/deep/failed": "deep failure",
	}))

	var tests = []struct {
		name      string
		host      string
		path      string
		shortname string
		want      string
	}{
		{"path beats host", "example.test", "/search", "challenge", "example.test/search/challenge"},
		{"path match covers deeper paths", "example.test", "/search/results/2", "challenge", "example.test/search/challenge"},
		{"host beats site-wide", "example.test", "/elsewhere", "challenge", "example.test/challenge"},
		{"site-wide covers an unknown host", "other.test", "/search", "challenge", "challenge"},
		{"deep path failure page", "example.test", "/search/deep", "failed", "example.test/search/deep/failed"},
		{"site-wide failure page where the host has none", "example.test", "/search", "failed", "failed"},
		{"core template when nothing custom exists", "other.test", "/x", "nosuchpage", "core/nosuchpage"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Host = tc.host
			if got := s.getTemplate(req, tc.shortname); got != tc.want {
				t.Errorf("getTemplate(%q, %q) = %q, want %q", tc.host+tc.path, tc.shortname, got, tc.want)
			}
		})
	}
}

// TestGetTemplateWithoutSiteWide makes sure the per-host templates still fall
// through to the core ones when there's no top-level pair to catch them.
func TestGetTemplateWithoutSiteWide(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := NewServer(gin.New(), db.NewNoopStore()).SetJWTSigningKey("test-key")
	s.LoadCustomTemplates(writeCustomTemplates(t, map[string]string{
		"example.test/challenge": "host challenge",
	}))

	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	req.Host = "other.test"
	if got := s.getTemplate(req, "challenge"); got != "core/challenge" {
		t.Errorf("getTemplate = %q, want core/challenge", got)
	}
}

// TestSiteWideTemplateIsServed is the end-to-end version: drop one
// challenge.go.html at the top of TEMPLATE_PATH and every host gets it.
func TestSiteWideTemplateIsServed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer backend.Close()

	gin.SetMode(gin.TestMode)
	s := NewServer(gin.New(), db.NewNoopStore()).
		SetJWTSigningKey("test-key").
		SetProxyTarget(backend.URL)
	s.LoadCustomTemplates(writeCustomTemplates(t, map[string]string{
		"challenge": "<body><h1>one template for everything</h1><challenge-form></challenge-form></body>",
	}))

	for _, host := range []string{"example.test", "other.test:8080"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/anything", nil)
		req.Host = host
		s.r.ServeHTTP(w, req)

		body := w.Body.String()
		if !strings.Contains(body, "one template for everything") {
			t.Errorf("host %q did not get the site-wide template:\n%s", host, body)
		}
		if !strings.Contains(body, `id="tps-challenge-form"`) {
			t.Errorf("host %q got an unexpanded challenge page:\n%s", host, body)
		}
	}
}

// TestLoadCustomTemplatesTrailingSlash guards a path-handling detail that's
// easy to break: TEMPLATE_PATH with a trailing slash has to name templates
// the same way as one without.
func TestLoadCustomTemplatesTrailingSlash(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := NewServer(gin.New(), db.NewNoopStore()).SetJWTSigningKey("test-key")
	s.LoadCustomTemplates(writeCustomTemplates(t, map[string]string{
		"challenge":              "site-wide",
		"example.test/challenge": "host",
	}) + "/")

	for _, want := range []string{"challenge", "example.test/challenge"} {
		if s.templates[want] == "" {
			t.Errorf("template %q was not registered; got %v", want, s.templates)
		}
	}
}
