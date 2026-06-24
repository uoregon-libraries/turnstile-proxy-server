package db

import (
	"testing"
	"time"
)

// writeEventSync inserts a single event directly (bypassing the async queue) so
// report tests have deterministic, immediately-visible data.
func writeEventSync(t *testing.T, s *sqliteStore, e Event) {
	t.Helper()
	var _, err = s.db.Exec(`
		INSERT INTO events (ts, outcome, reason, client_ip, masked_ip, host, path, method, user_agent, jti, ip_switch)
		VALUES (?, ?, '', '', '', '', '', '', '', '', 0)`,
		e.Timestamp.UnixMicro(), e.Outcome, e.Reason)
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
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

func TestReportRejectsBadWindow(t *testing.T) {
	var s = newTestStore(t, 0)
	var now = time.Now()
	if _, err := s.Report(now, now, time.Hour); err == nil {
		t.Error("Report accepted end == start")
	}
	if _, err := s.Report(now, now.Add(time.Hour), 0); err == nil {
		t.Error("Report accepted zero bucket width")
	}
}

func TestNoopStoreReportUnavailable(t *testing.T) {
	var s = NewNoopStore()
	var _, err = s.Report(time.Now(), time.Now().Add(time.Hour), time.Hour)
	if err != ErrReportingUnavailable {
		t.Errorf("noop Report err = %v, want ErrReportingUnavailable", err)
	}
}
