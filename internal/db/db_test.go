package db

import (
	"database/sql"
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

// TestFlushRollsBackPartialBatch covers the failure half of a write: the
// events and the rollups they feed go in one transaction precisely so the two
// can't disagree, which is only true if a failure part-way through takes the
// whole batch with it. Dropping the rollups table makes the second half of the
// write fail after the first half has already inserted rows.
func TestFlushRollsBackPartialBatch(t *testing.T) {
	var s = newTestStore(t, 0)
	if _, err := s.db.Exec("DROP TABLE rollups;"); err != nil {
		t.Fatalf("dropping rollups: %v", err)
	}

	s.flush([]Event{
		{Timestamp: time.Now(), Outcome: OutcomeChallenged},
		{Timestamp: time.Now(), Outcome: OutcomeProxied},
	})

	if n := countEvents(t, s); n != 0 {
		t.Errorf("%d events survived a batch that couldn't finish; the rollups they "+
			"belong to were never written", n)
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

// TestFlushAccumulatesRollups confirms that separate flushes hitting the same
// hour bucket sum into one rollup row rather than replacing it.
func TestFlushAccumulatesRollups(t *testing.T) {
	var s = newTestStore(t, 0)
	var ts = time.Date(2026, 6, 24, 3, 15, 0, 0, time.UTC)

	s.flush([]Event{
		{Timestamp: ts, Outcome: OutcomeChallenged},
		{Timestamp: ts.Add(time.Minute), Outcome: OutcomeChallenged},
	})
	s.flush([]Event{{Timestamp: ts.Add(2 * time.Minute), Outcome: OutcomeChallenged}})

	var n int
	var err = s.db.QueryRow(
		"SELECT n FROM rollups WHERE bucket_ts = ? AND outcome = ?",
		ts.Truncate(time.Hour).UnixMicro(), OutcomeChallenged,
	).Scan(&n)
	if err != nil {
		t.Fatalf("read rollup: %v", err)
	}
	if n != 3 {
		t.Errorf("rollup n = %d, want 3", n)
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

// TestPruneReclaimsSpace confirms that on a fresh database (created in
// incremental auto_vacuum mode), prune's incremental vacuum leaves no pages on
// the freelist — freed space goes back to the OS rather than pooling in the
// file.
func TestPruneReclaimsSpace(t *testing.T) {
	var s = newTestStore(t, 0)

	var mode int
	if err := s.db.QueryRow("PRAGMA auto_vacuum;").Scan(&mode); err != nil || mode != 2 {
		t.Fatalf("auto_vacuum = %d (err %v), want 2 (incremental) on a fresh database", mode, err)
	}

	// Enough bulky rows to spread across many pages, so deleting them
	// actually frees some.
	var batch = make([]Event, 0, 2000)
	var filler = string(make([]byte, 500))
	for i := 0; i < 2000; i++ {
		batch = append(batch, Event{
			Timestamp: time.Now().Add(-48 * time.Hour),
			Outcome:   OutcomeChallenged,
			UserAgent: filler,
		})
	}
	s.flush(batch)

	var pagesBefore int
	if err := s.db.QueryRow("PRAGMA page_count;").Scan(&pagesBefore); err != nil {
		t.Fatalf("page_count: %v", err)
	}

	s.prune(24 * time.Hour)

	var freelist, pagesAfter int
	if err := s.db.QueryRow("PRAGMA freelist_count;").Scan(&freelist); err != nil {
		t.Fatalf("freelist_count: %v", err)
	}
	if freelist != 0 {
		t.Errorf("freelist_count after prune = %d, want 0 (incremental vacuum should drain it)", freelist)
	}
	if err := s.db.QueryRow("PRAGMA page_count;").Scan(&pagesAfter); err != nil {
		t.Fatalf("page_count: %v", err)
	}
	if pagesAfter >= pagesBefore {
		t.Errorf("page_count after prune = %d, want fewer than %d", pagesAfter, pagesBefore)
	}
}

// TestVacuum exercises the manual rebuild against a database in legacy (no
// auto_vacuum) mode — the state a pre-2.x event log is in — and confirms it
// both shrinks the file and switches on incremental auto_vacuum.
func TestVacuum(t *testing.T) {
	var path = filepath.Join(t.TempDir(), "events.db")

	// Build the store on a legacy-mode file: creating the schema on a
	// connection with auto_vacuum=NONE pins the database to that mode.
	var raw, err = sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err = raw.Exec("CREATE TABLE placeholder (x);"); err != nil {
		t.Fatalf("pin legacy mode: %v", err)
	}
	raw.Close()

	var store Store
	if store, err = NewStore(path, 0, testLogger()); err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	var s = store.(*sqliteStore)
	var batch = make([]Event, 0, 2000)
	var filler = string(make([]byte, 500))
	for i := 0; i < 2000; i++ {
		batch = append(batch, Event{Timestamp: time.Now().Add(-48 * time.Hour), Outcome: OutcomeChallenged, UserAgent: filler})
	}
	s.flush(batch)
	s.prune(24 * time.Hour) // legacy mode: deletes rows, cannot shrink the file
	store.Close()

	before, after, err := Vacuum(path)
	if err != nil {
		t.Fatalf("Vacuum: %v", err)
	}
	if after >= before {
		t.Errorf("Vacuum: size went from %d to %d, want smaller", before, after)
	}

	// The rebuild must leave the database in incremental mode so future
	// prunes shrink it without another manual vacuum.
	var db2, err2 = sql.Open("sqlite", path)
	if err2 != nil {
		t.Fatalf("reopen: %v", err2)
	}
	defer db2.Close()
	var mode int
	if err = db2.QueryRow("PRAGMA auto_vacuum;").Scan(&mode); err != nil {
		t.Fatalf("auto_vacuum: %v", err)
	}
	if mode != 2 {
		t.Errorf("auto_vacuum after Vacuum = %d, want 2 (incremental)", mode)
	}
}

// TestVacuumMissingFile confirms a bad path is an error rather than silently
// creating and "vacuuming" a brand-new empty database.
func TestVacuumMissingFile(t *testing.T) {
	var _, _, err = Vacuum(filepath.Join(t.TempDir(), "nope.db"))
	if err == nil {
		t.Fatal("Vacuum on a missing file succeeded, want error")
	}
}

func TestNoopStore(t *testing.T) {
	var s = NewNoopStore()
	s.LogEvent(Event{Outcome: OutcomeProxied})
	if err := s.Close(); err != nil {
		t.Errorf("noop Close: %v", err)
	}
}
