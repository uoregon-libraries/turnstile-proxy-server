package db

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestStore opens a store backed by a throwaway file in the test's temp dir.
func newTestStore(t *testing.T, retention time.Duration) *sqliteStore {
	t.Helper()
	var path = filepath.Join(t.TempDir(), "events.db")
	var store, err = NewStore(path, retention, testLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store.(*sqliteStore)
}

func countEvents(t *testing.T, s *sqliteStore) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&n); err != nil {
		t.Fatalf("count events: %v", err)
	}
	return n
}

// TestLogEventAsync exercises the real queue+batch writer path: events logged
// through LogEvent should eventually land in the table.
func TestLogEventAsync(t *testing.T) {
	var s = newTestStore(t, 0)

	var outcomes = []string{OutcomeChallenged, OutcomeVerifyOK, OutcomeProxied}
	for _, o := range outcomes {
		s.LogEvent(Event{Timestamp: time.Now(), Outcome: o, Reason: ReasonValidToken, JTI: "abc"})
	}

	// The writer flushes on a ticker; poll until the rows appear.
	var deadline = time.Now().Add(2 * time.Second)
	for countEvents(t, s) < len(outcomes) {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d events written before timeout", countEvents(t, s), len(outcomes))
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Spot-check that a row's fields round-tripped.
	var outcome, reason, jti string
	var ipSwitch int
	var err = s.db.QueryRow(
		"SELECT outcome, reason, jti, ip_switch FROM events WHERE outcome = ?", OutcomeProxied,
	).Scan(&outcome, &reason, &jti, &ipSwitch)
	if err != nil {
		t.Fatalf("read back row: %v", err)
	}
	if outcome != OutcomeProxied || reason != ReasonValidToken || jti != "abc" || ipSwitch != 0 {
		t.Errorf("round-trip mismatch: outcome=%q reason=%q jti=%q ip_switch=%d", outcome, reason, jti, ipSwitch)
	}
}

// TestFlushIPSwitch confirms the boolean column persists as 1.
func TestFlushIPSwitch(t *testing.T) {
	var s = newTestStore(t, 0)
	s.flush([]Event{{Timestamp: time.Now(), Outcome: OutcomeProxied, IPSwitch: true}})

	var ipSwitch int
	if err := s.db.QueryRow("SELECT ip_switch FROM events").Scan(&ipSwitch); err != nil {
		t.Fatalf("read ip_switch: %v", err)
	}
	if ipSwitch != 1 {
		t.Errorf("ip_switch = %d, want 1", ipSwitch)
	}
}

// TestPrune confirms retention deletes events older than the cutoff and keeps
// newer ones.
func TestPrune(t *testing.T) {
	var s = newTestStore(t, 0) // 0 retention -> no background pruning; we call prune directly

	// Write synchronously so timing is deterministic.
	s.flush([]Event{
		{Timestamp: time.Now().Add(-48 * time.Hour), Outcome: OutcomeChallenged},
		{Timestamp: time.Now(), Outcome: OutcomeProxied},
	})
	if got := countEvents(t, s); got != 2 {
		t.Fatalf("setup: have %d events, want 2", got)
	}

	s.prune(24 * time.Hour)

	if got := countEvents(t, s); got != 1 {
		t.Fatalf("after prune: have %d events, want 1", got)
	}
	var outcome string
	if err := s.db.QueryRow("SELECT outcome FROM events").Scan(&outcome); err != nil {
		t.Fatalf("read survivor: %v", err)
	}
	if outcome != OutcomeProxied {
		t.Errorf("survivor outcome = %q, want %q", outcome, OutcomeProxied)
	}
}

func TestNoopStore(t *testing.T) {
	var s = NewNoopStore()
	s.LogEvent(Event{Outcome: OutcomeProxied})
	if err := s.Close(); err != nil {
		t.Errorf("noop Close: %v", err)
	}
}
