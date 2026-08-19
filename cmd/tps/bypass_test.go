package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
	"turnstile-proxy-server/internal/db"
)

const testKeySecret = bypassKeyPrefix + "0123456789abcdef0123456789abcdef"

// headerRecorder is a backend that remembers the headers of the last request
// it served, so tests can prove what did (and did not) reach it.
type headerRecorder struct {
	mu   sync.Mutex
	last http.Header
}

func (h *headerRecorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.last = r.Header.Clone()
		h.mu.Unlock()
		w.Write([]byte("backend response"))
	}
}

func (h *headerRecorder) lastHeaders() http.Header {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last
}

// bypassTestServer builds a running TPS with the given key planted and
// loaded, in front of a header-recording backend.
func bypassTestServer(t *testing.T, key db.Key) (*httptest.Server, *fakeStore, *headerRecorder) {
	t.Helper()
	var rec = &headerRecorder{}
	var backend = httptest.NewServer(rec.handler())
	t.Cleanup(backend.Close)

	var store = &fakeStore{keys: []db.Key{key}}
	var s = newTestServerWithStore(t, backend.URL, store)
	if err := s.reloadBypassKeys(); err != nil {
		t.Fatalf("reloadBypassKeys: %v", err)
	}

	var tps = httptest.NewServer(s.r)
	t.Cleanup(tps.Close)
	return tps, store, rec
}

// testKey is a healthy key with limits far too generous to interfere; tests
// tighten the field they're about.
func testKey() db.Key {
	return db.Key{
		ID:         42,
		Label:      "test-key",
		KeyHash:    hashKeySecret(testKeySecret),
		RatePerSec: 1000,
		Burst:      1000,
		Created:    time.Now(),
		Expires:    time.Now().Add(time.Hour),
	}
}

func TestBypassKeyProxies(t *testing.T) {
	var tps, store, rec = bypassTestServer(t, testKey())

	var req, _ = http.NewRequest("GET", tps.URL+"/protected/data", nil)
	req.Header.Set(bypassKeyHeader, testKeySecret)
	var resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := rec.lastHeaders().Get(bypassKeyHeader); got != "" {
		t.Errorf("backend saw %s: %q; the key must never go upstream", bypassKeyHeader, got)
	}

	var events = store.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	if events[0].Outcome != db.OutcomeProxied || events[0].Reason != db.ReasonBypassKey || events[0].KeyID != 42 {
		t.Errorf("event = {%q, %q, key %d}, want {%q, %q, key 42}",
			events[0].Outcome, events[0].Reason, events[0].KeyID, db.OutcomeProxied, db.ReasonBypassKey)
	}
}

func TestBypassKeyViaBearer(t *testing.T) {
	var tps, _, rec = bypassTestServer(t, testKey())

	var req, _ = http.NewRequest("GET", tps.URL+"/protected/data", nil)
	req.Header.Set("Authorization", "Bearer "+testKeySecret)
	var resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("sending request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := rec.lastHeaders().Get("Authorization"); got != "" {
		t.Errorf("backend saw Authorization %q; a consumed key must never go upstream", got)
	}

	// A Bearer token outside TPS's namespace is the backend's business, not a
	// key attempt: the client is challenged with no key diagnostic, and the
	// header would survive to a post-challenge replay.
	req, _ = http.NewRequest("GET", tps.URL+"/protected/data", nil)
	req.Header.Set("Authorization", "Bearer some-backend-token")
	if resp, err = http.DefaultClient.Do(req); err != nil {
		t.Fatalf("sending request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("foreign Bearer token: status = %d, want 403 (challenged)", resp.StatusCode)
	}
	if got := resp.Header.Get(bypassStatusHeader); got != "" {
		t.Errorf("foreign Bearer token drew %s: %q; TPS should not have judged it", bypassStatusHeader, got)
	}
}

// TestBypassKeyDiagnostics covers every way a presented key can be found
// wanting: each falls through to the ordinary challenge, but names its
// problem in the status header so the client's side is diagnosable.
func TestBypassKeyDiagnostics(t *testing.T) {
	var revoked = testKey()
	revoked.Revoked = time.Now().Add(-time.Minute)

	var expired = testKey()
	expired.Expires = time.Now().Add(-time.Minute)

	var wrongNet = testKey()
	wrongNet.CIDRs = []string{"198.51.100.0/24"}

	var rightNet = testKey()
	rightNet.CIDRs = []string{"203.0.113.0/24"}

	tests := []struct {
		name       string
		key        db.Key
		secret     string
		clientIP   string
		wantStatus int
		wantHeader string
	}{
		{"unknown key", testKey(), bypassKeyPrefix + "not-a-real-key", "", http.StatusForbidden, "unknown"},
		{"revoked key", revoked, testKeySecret, "", http.StatusForbidden, "revoked"},
		{"expired key", expired, testKeySecret, "", http.StatusForbidden, "expired"},
		{"wrong network", wrongNet, testKeySecret, "203.0.113.9", http.StatusForbidden, "wrong_ip"},
		{"right network", rightNet, testKeySecret, "203.0.113.9", http.StatusOK, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var tps, _, _ = bypassTestServer(t, tc.key)
			var req, _ = http.NewRequest("GET", tps.URL+"/protected/data", nil)
			req.Header.Set(bypassKeyHeader, tc.secret)
			if tc.clientIP != "" {
				// The test client connects over loopback, a trusted proxy, so
				// X-Forwarded-For is how a test chooses its client IP
				req.Header.Set("X-Forwarded-For", tc.clientIP)
			}
			var resp, err = http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("sending request: %v", err)
			}
			resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if got := resp.Header.Get(bypassStatusHeader); got != tc.wantHeader {
				t.Errorf("%s = %q, want %q", bypassStatusHeader, got, tc.wantHeader)
			}
		})
	}
}

func TestBypassKeyBurstThen429(t *testing.T) {
	var key = testKey()
	// A refill so slow the wait after the burst is hours: the 4th request
	// must be refused outright, not parked.
	key.RatePerSec = 0.0001
	key.Burst = 3
	var tps, store, _ = bypassTestServer(t, key)

	var send = func() *http.Response {
		var req, _ = http.NewRequest("GET", tps.URL+"/protected/data", nil)
		req.Header.Set(bypassKeyHeader, testKeySecret)
		var resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("sending request: %v", err)
		}
		resp.Body.Close()
		return resp
	}

	for i := range 3 {
		if resp := send(); resp.StatusCode != http.StatusOK {
			t.Fatalf("burst request %d: status = %d, want 200", i+1, resp.StatusCode)
		}
	}

	var resp = send()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over-burst request: status = %d, want 429", resp.StatusCode)
	}
	var retry, err = strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || retry < 1 {
		t.Errorf("Retry-After = %q, want a positive integer", resp.Header.Get("Retry-After"))
	}

	var events = store.snapshot()
	var last = events[len(events)-1]
	if last.Outcome != db.OutcomeRateLimited || last.Reason != db.ReasonBypassRate || last.KeyID != 42 {
		t.Errorf("event = {%q, %q, key %d}, want {%q, %q, key 42}",
			last.Outcome, last.Reason, last.KeyID, db.OutcomeRateLimited, db.ReasonBypassRate)
	}
}

// TestBypassKeyPacesInsteadOfRefusing pins the hybrid behavior: a wait the
// server can absorb is served late rather than refused, so a sequential
// scraper is slowed to its permitted rate without ever seeing an error.
func TestBypassKeyPacesInsteadOfRefusing(t *testing.T) {
	var key = testKey()
	key.RatePerSec = 50 // one token per 20ms: a delay well under bypassMaxWait
	key.Burst = 1
	var tps, _, _ = bypassTestServer(t, key)

	var start = time.Now()
	for i := range 2 {
		var req, _ = http.NewRequest("GET", tps.URL+"/protected/data", nil)
		req.Header.Set(bypassKeyHeader, testKeySecret)
		var resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("sending request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, resp.StatusCode)
		}
	}
	if elapsed := time.Since(start); elapsed < 15*time.Millisecond {
		t.Errorf("two requests at 50/s burst 1 took %v; the second should have been held ~20ms", elapsed)
	}
}

func TestBypassKeyDailyCap(t *testing.T) {
	var key = testKey()
	key.DailyCap = 2
	var tps, store, _ = bypassTestServer(t, key)

	var send = func() *http.Response {
		var req, _ = http.NewRequest("GET", tps.URL+"/protected/data", nil)
		req.Header.Set(bypassKeyHeader, testKeySecret)
		var resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("sending request: %v", err)
		}
		resp.Body.Close()
		return resp
	}

	for i := range 2 {
		if resp := send(); resp.StatusCode != http.StatusOK {
			t.Fatalf("capped request %d: status = %d, want 200", i+1, resp.StatusCode)
		}
	}

	var resp = send()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over-cap request: status = %d, want 429", resp.StatusCode)
	}
	var retry, err = strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || retry < 1 || retry > 86400 {
		t.Errorf("Retry-After = %q, want seconds until UTC midnight", resp.Header.Get("Retry-After"))
	}

	var events = store.snapshot()
	var last = events[len(events)-1]
	if last.Outcome != db.OutcomeRateLimited || last.Reason != db.ReasonBypassDailyCap {
		t.Errorf("event = {%q, %q}, want {%q, %q}",
			last.Outcome, last.Reason, db.OutcomeRateLimited, db.ReasonBypassDailyCap)
	}
}

// TestReloadPreservesLimiterState guards the refresh path's core promise: a
// key that has spent its burst must not get a fresh one just because the
// 30-second refresh re-read the table.
func TestReloadPreservesLimiterState(t *testing.T) {
	var key = testKey()
	key.RatePerSec = 0.0001
	key.Burst = 2
	var backend = httptest.NewServer((&headerRecorder{}).handler())
	defer backend.Close()

	var store = &fakeStore{keys: []db.Key{key}}
	var s = newTestServerWithStore(t, backend.URL, store)
	if err := s.reloadBypassKeys(); err != nil {
		t.Fatalf("reloadBypassKeys: %v", err)
	}

	var k = s.bypassKeys[key.KeyHash]
	k.limiter.Reserve()
	k.limiter.Reserve() // burst spent

	if err := s.reloadBypassKeys(); err != nil {
		t.Fatalf("second reloadBypassKeys: %v", err)
	}
	var r = s.bypassKeys[key.KeyHash].limiter.Reserve()
	defer r.Cancel()
	if r.Delay() == 0 {
		t.Error("burst was replenished by a reload; limiter state must survive refreshes")
	}
}
