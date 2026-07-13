package db

import (
	"path/filepath"
	"testing"
	"time"
)

// writeEventSync writes a single event through the real flush path (bypassing
// the async queue) so report tests have deterministic, immediately-visible data
// in both the events table and the rollups that Report reads.
func writeEventSync(t *testing.T, s *sqliteStore, e Event) {
	t.Helper()
	s.flush([]Event{e})
}

func TestReportBucketsAndCounts(t *testing.T) {
	var s = newTestStore(t, 0)

	// A fixed window: 24 hourly buckets ending at a round hour.
	var end = time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	var start = end.Add(-24 * time.Hour)
	var bucket = time.Hour

	// Bucket 0 (start .. start+1h): 2 challenged, 1 rendered, 1 solved.
	writeEventSync(t, s, Event{Timestamp: start.Add(5 * time.Minute), Outcome: OutcomeChallenged})
	writeEventSync(t, s, Event{Timestamp: start.Add(10 * time.Minute), Outcome: OutcomeChallenged})
	writeEventSync(t, s, Event{Timestamp: start.Add(15 * time.Minute), Outcome: OutcomeChallengeRendered})
	writeEventSync(t, s, Event{Timestamp: start.Add(20 * time.Minute), Outcome: OutcomeVerifyOK})
	// Bucket 23 (last hour): 1 failed.
	writeEventSync(t, s, Event{Timestamp: start.Add(23*time.Hour + 30*time.Minute), Outcome: OutcomeVerifyFail})
	// Out of window (must not appear): before start and at end.
	writeEventSync(t, s, Event{Timestamp: start.Add(-time.Minute), Outcome: OutcomeChallenged})
	writeEventSync(t, s, Event{Timestamp: end, Outcome: OutcomeChallenged})

	var buckets, err = s.Report(start, end, bucket)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if len(buckets) != 24 {
		t.Fatalf("got %d buckets, want 24", len(buckets))
	}

	if !buckets[0].Start.Equal(start) {
		t.Errorf("bucket[0].Start = %v, want %v", buckets[0].Start, start)
	}
	if buckets[0].Challenged != 2 || buckets[0].Rendered != 1 || buckets[0].Solved != 1 {
		t.Errorf("bucket[0] = %+v, want challenged=2 rendered=1 solved=1", buckets[0])
	}
	if buckets[23].Failed != 1 {
		t.Errorf("bucket[23].Failed = %d, want 1", buckets[23].Failed)
	}

	// Every other bucket should be empty (the out-of-window events were excluded).
	var total int
	for _, b := range buckets {
		total += b.Challenged + b.Rendered + b.Solved + b.Failed
	}
	if total != 5 {
		t.Errorf("total counted events = %d, want 5 (out-of-window events leaked in)", total)
	}
}

// TestReportWiderBuckets confirms hourly rollup rows sum correctly into a
// multi-hour report bucket.
func TestReportWiderBuckets(t *testing.T) {
	var s = newTestStore(t, 0)
	var start = time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)

	// Two different hours, both inside the first 12h bucket.
	writeEventSync(t, s, Event{Timestamp: start.Add(1*time.Hour + 5*time.Minute), Outcome: OutcomeChallenged})
	writeEventSync(t, s, Event{Timestamp: start.Add(7*time.Hour + 20*time.Minute), Outcome: OutcomeChallenged})
	// And one in the second bucket.
	writeEventSync(t, s, Event{Timestamp: start.Add(13 * time.Hour), Outcome: OutcomeVerifyOK})

	var buckets, err = s.Report(start, start.Add(24*time.Hour), 12*time.Hour)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if buckets[0].Challenged != 2 {
		t.Errorf("bucket[0].Challenged = %d, want 2", buckets[0].Challenged)
	}
	if buckets[1].Solved != 1 {
		t.Errorf("bucket[1].Solved = %d, want 1", buckets[1].Solved)
	}
}

// TestReportSurvivesPrune is the point of the rollups table: pruning the raw
// event log must not erase report history.
func TestReportSurvivesPrune(t *testing.T) {
	var s = newTestStore(t, 0)

	writeEventSync(t, s, Event{Timestamp: time.Now().Add(-48 * time.Hour), Outcome: OutcomeChallenged})
	writeEventSync(t, s, Event{Timestamp: time.Now(), Outcome: OutcomeProxied})

	s.prune(24 * time.Hour)
	if got := countEvents(t, s); got != 1 {
		t.Fatalf("after prune: have %d raw events, want 1", got)
	}

	var end = time.Now().UTC().Truncate(time.Hour).Add(time.Hour)
	var buckets, err = s.Report(end.Add(-72*time.Hour), end, time.Hour)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	var challenged int
	for _, b := range buckets {
		challenged += b.Challenged
	}
	if challenged != 1 {
		t.Errorf("challenged after prune = %d, want 1 (pruning raw events lost rollup history)", challenged)
	}
}

// TestRollupBackfill confirms opening a database that has raw events but no
// rollups (one created before the rollups table existed) backfills the rollups,
// and that reopening doesn't double-count.
func TestRollupBackfill(t *testing.T) {
	var path = filepath.Join(t.TempDir(), "events.db")
	var ts = time.Date(2026, 6, 24, 3, 15, 0, 0, time.UTC)

	var open = func() *sqliteStore {
		t.Helper()
		var store, err = NewStore(path, 0, testLogger())
		if err != nil {
			t.Fatalf("NewStore: %v", err)
		}
		return store.(*sqliteStore)
	}

	// Simulate a pre-rollup database: raw events present, rollups table empty.
	var s = open()
	for range 3 {
		var _, err = s.db.Exec(`
			INSERT INTO events (ts, outcome, reason, client_ip, masked_ip, host, path, method, user_agent, jti, ip_switch)
			VALUES (?, ?, '', '', '', '', '', '', '', '', 0)`,
			ts.UnixMicro(), OutcomeChallenged)
		if err != nil {
			t.Fatalf("insert raw event: %v", err)
		}
	}
	s.Close()

	var report = func(s *sqliteStore) int {
		t.Helper()
		var start = ts.Truncate(time.Hour)
		var buckets, err = s.Report(start, start.Add(time.Hour), time.Hour)
		if err != nil {
			t.Fatalf("Report: %v", err)
		}
		return buckets[0].Challenged
	}

	s = open()
	if got := report(s); got != 3 {
		t.Errorf("after backfill: challenged = %d, want 3", got)
	}
	s.Close()

	// A second reopen must not backfill again.
	s = open()
	defer s.Close()
	if got := report(s); got != 3 {
		t.Errorf("after reopen: challenged = %d, want 3 (backfill double-counted)", got)
	}
}

func TestReportRejectsBadWindow(t *testing.T) {
	var s = newTestStore(t, 0)
	var now = time.Now().UTC().Truncate(time.Hour)
	if _, err := s.Report(now, now, time.Hour); err == nil {
		t.Error("Report accepted end == start")
	}
	if _, err := s.Report(now, now.Add(time.Hour), 0); err == nil {
		t.Error("Report accepted zero bucket width")
	}
	if _, err := s.Report(now, now.Add(time.Hour), 30*time.Minute); err == nil {
		t.Error("Report accepted a sub-hour bucket width")
	}
	if _, err := s.Report(now.Add(time.Minute), now.Add(time.Hour), time.Hour); err == nil {
		t.Error("Report accepted a start off the hour boundary")
	}
}

func TestNoopStoreReportUnavailable(t *testing.T) {
	var s = NewNoopStore()
	var _, err = s.Report(time.Now(), time.Now().Add(time.Hour), time.Hour)
	if err != ErrReportingUnavailable {
		t.Errorf("noop Report err = %v, want ErrReportingUnavailable", err)
	}
}
