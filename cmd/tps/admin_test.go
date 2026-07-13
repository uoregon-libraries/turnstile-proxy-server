package main

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"
	"turnstile-proxy-server/internal/db"

	"github.com/gin-gonic/gin"
)

// newAdminServer builds a minimal Server wired for the admin endpoints: a fake
// store, a discard logger, and the given admin secret.
func newAdminServer(secret string) (*Server, *fakeStore) {
	var store = &fakeStore{}
	var s = &Server{
		db:          store,
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	var w = adminRequest(s, "GET", "/.tps/report")
	if w.Code != 404 {
		t.Errorf("report with no secret = %d, want 404", w.Code)
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

func TestAdminUnknownPath(t *testing.T) {
	var s, _ = newAdminServer("s3cret")
	var w = adminRequest(s, "GET", "/.tps/nope")
	if w.Code != 404 {
		t.Errorf("unknown admin path = %d, want 404", w.Code)
	}
}
