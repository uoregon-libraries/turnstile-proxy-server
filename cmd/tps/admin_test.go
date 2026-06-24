package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"turnstile-proxy-server/internal/db"

	"github.com/gin-gonic/gin"
)

// newAdminServer builds a minimal Server wired for the admin endpoints: a hub,
// a fake store, a discard logger, and the given admin secret.
func newAdminServer(secret string) (*Server, *fakeStore) {
	var store = &fakeStore{}
	var s = &Server{
		db:          store,
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		hub:         newEventHub(),
		adminSecret: secret,
	}
	return s, store
}

// adminRequest drives a request through the full proxy entrypoint (so the
// adminPathPrefix interception in handleProxy is exercised too) and returns the
// recorder.
func adminRequest(s *Server, method, target string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	var router = gin.New()
	router.Any("/*proxyPath", s.handleProxy)
	var w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(method, target, nil))
	return w
}

func TestReportWindow(t *testing.T) {
	var now = time.Date(2026, 6, 24, 9, 17, 0, 0, time.UTC)
	tests := []struct {
		period      string
		wantBucket  time.Duration
		wantBuckets int
	}{
		{"1d", time.Hour, 24},
		{"7d", 12 * time.Hour, 14},
		{"1m", 24 * time.Hour, 30},
		{"1y", 14 * 24 * time.Hour, 26},
	}
	for _, tc := range tests {
		t.Run(tc.period, func(t *testing.T) {
			start, end, bucket, ok := reportWindow(tc.period, now)
			if !ok {
				t.Fatalf("reportWindow(%q) not ok", tc.period)
			}
			if bucket != tc.wantBucket {
				t.Errorf("bucket = %v, want %v", bucket, tc.wantBucket)
			}
			var n = int(end.Sub(start) / bucket)
			if n != tc.wantBuckets {
				t.Errorf("bucket count = %d, want %d", n, tc.wantBuckets)
			}
			// End is aligned to a bucket boundary and strictly after now.
			if !end.After(now) {
				t.Errorf("end %v is not after now %v", end, now)
			}
			if end.Truncate(bucket) != end {
				t.Errorf("end %v is not aligned to %v", end, bucket)
			}
		})
	}
}

func TestReportWindowBadPeriod(t *testing.T) {
	if _, _, _, ok := reportWindow("3d", time.Now()); ok {
		t.Error("reportWindow accepted an unknown period")
	}
}

func TestAdminGatingDisabledWhenNoSecret(t *testing.T) {
	var s, _ = newAdminServer("")
	for _, path := range []string{"/.tps/report", "/.tps/watch", "/.tps/watch.html"} {
		var w = adminRequest(s, "GET", path)
		if w.Code != 404 {
			t.Errorf("%s with no secret = %d, want 404", path, w.Code)
		}
	}
}

func TestAdminGatingRejectsWrongKey(t *testing.T) {
	var s, _ = newAdminServer("s3cret")
	var w = adminRequest(s, "GET", "/.tps/report?key=nope")
	if w.Code != 401 {
		t.Errorf("wrong key = %d, want 401", w.Code)
	}
}

func TestAdminReportUnavailableWithoutLogging(t *testing.T) {
	// fakeStore.Report returns ErrReportingUnavailable, mimicking a disabled log.
	var s, _ = newAdminServer("s3cret")
	var w = adminRequest(s, "GET", "/.tps/report?key=s3cret&period=1d")
	if w.Code != 503 {
		t.Fatalf("report with logging off = %d, want 503", w.Code)
	}
}

func TestAdminReportBadPeriod(t *testing.T) {
	var s, _ = newAdminServer("s3cret")
	var w = adminRequest(s, "GET", "/.tps/report?key=s3cret&period=bogus")
	if w.Code != 400 {
		t.Errorf("bad period = %d, want 400", w.Code)
	}
}

func TestBeaconIsPublicAndLogsRendered(t *testing.T) {
	// No admin secret: the beacon must still work (it's intentionally public).
	var s, store = newAdminServer("")
	var w = adminRequest(s, "POST", "/.tps/beacon")
	if w.Code != 204 {
		t.Fatalf("beacon = %d, want 204", w.Code)
	}
	var events = store.snapshot()
	if len(events) != 1 || events[0].Outcome != db.OutcomeChallengeRendered {
		t.Fatalf("beacon logged %+v, want one %s event", events, db.OutcomeChallengeRendered)
	}
}

func TestBeaconBroadcastsToWatchers(t *testing.T) {
	var s, _ = newAdminServer("")
	var ch = s.hub.subscribe()
	defer s.hub.unsubscribe(ch)

	adminRequest(s, "POST", "/.tps/beacon")

	select {
	case e := <-ch:
		if e.Outcome != db.OutcomeChallengeRendered {
			t.Errorf("watcher saw %s, want %s", e.Outcome, db.OutcomeChallengeRendered)
		}
	case <-time.After(time.Second):
		t.Fatal("watcher received no event from the beacon")
	}
}

func TestAdminUnknownPath(t *testing.T) {
	var s, _ = newAdminServer("s3cret")
	var w = adminRequest(s, "GET", "/.tps/nope")
	if w.Code != 404 {
		t.Errorf("unknown admin path = %d, want 404", w.Code)
	}
}

func TestWatchStreamsBroadcastEvents(t *testing.T) {
	// Shorten the keep-alive so the handler notices the closed connection (and
	// teardown completes) quickly instead of waiting the full production interval.
	var savedPing = watchPingInterval
	watchPingInterval = 100 * time.Millisecond
	defer func() { watchPingInterval = savedPing }()

	var s, _ = newAdminServer("s3cret")
	gin.SetMode(gin.TestMode)
	var router = gin.New()
	router.Any("/*proxyPath", s.handleProxy)
	var srv = httptest.NewServer(router)
	defer srv.Close()

	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var req, _ = http.NewRequestWithContext(ctx, "GET", srv.URL+"/.tps/watch?key=s3cret", nil)
	var resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("watch request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("watch status = %d, want 200", resp.StatusCode)
	}

	// Wait for the handler to register its subscription before broadcasting,
	// otherwise the event races ahead of the stream.
	var deadline = time.Now().Add(2 * time.Second)
	for {
		s.hub.mu.Lock()
		var n = len(s.hub.subs)
		s.hub.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("watch never registered a subscriber")
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.recordEvent(db.Event{Timestamp: time.Now(), Outcome: db.OutcomeChallenged, JTI: "watch-me"})

	// Read stream lines until the data payload arrives, then stop.
	type readResult struct {
		line string
		err  error
	}
	var lines = make(chan readResult, 1)
	go func() {
		var r = bufio.NewReader(resp.Body)
		for {
			var line, rerr = r.ReadString('\n')
			if strings.HasPrefix(line, "data:") || rerr != nil {
				lines <- readResult{line, rerr}
				return
			}
		}
	}()

	select {
	case got := <-lines:
		if got.err != nil {
			t.Fatalf("reading stream: %v", got.err)
		}
		if !strings.Contains(got.line, "challenged") {
			t.Errorf("stream data line = %q, want it to mention the outcome", got.line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no data event received from the watch stream")
	}
}

func TestWatchEventUsesFriendlyName(t *testing.T) {
	var we = toWatchEvent(db.Event{JTI: "abc", Outcome: db.OutcomeProxied})
	if we.Name == "" || we.Name == "abc" {
		t.Errorf("watch event Name = %q, want a friendly name", we.Name)
	}
	// A JSON round-trip should keep the friendly name (sanity on tags).
	var b, _ = json.Marshal(we)
	if !json.Valid(b) {
		t.Error("watch event did not marshal to valid JSON")
	}
}
