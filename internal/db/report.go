package db

import (
	"errors"
	"time"
)

// ErrReportingUnavailable is returned by [Store.Report] when event logging is
// disabled, so there is no events table to aggregate.
var ErrReportingUnavailable = errors.New("event logging is disabled; no report data available")

// CountBucket is one row of a report: the counts of each tracked outcome whose
// timestamp fell in the half-open interval [Start, Start+width), where width is
// the bucket duration passed to [Store.Report]. Dumb (non-JS) clients can be
// derived as Challenged - Rendered.
type CountBucket struct {
	Start      time.Time `json:"start"`
	Challenged int       `json:"challenged"` // challenge pages served (raw)
	Rendered   int       `json:"rendered"`   // challenge JS executed (beacon) — "smart" clients
	Solved     int       `json:"solved"`     // Turnstile solutions that verified
	Failed     int       `json:"failed"`     // Turnstile solutions that failed verification
}

// Report aggregates events in [start, end) into ceil((end-start)/bucket)
// contiguous buckets of width bucket, the first starting at start. Every bucket
// is returned even when it has no events, so the caller gets a dense series
// (gaps show as zero rows). A single grouped query does the counting; buckets
// are assigned by integer division of each event's offset from start.
func (s *sqliteStore) Report(start, end time.Time, bucket time.Duration) ([]CountBucket, error) {
	if !end.After(start) {
		return nil, errors.New("report end must be after start")
	}
	if bucket <= 0 {
		return nil, errors.New("report bucket width must be positive")
	}

	var startUS = start.UnixMicro()
	var bucketUS = bucket.Microseconds()
	// Ceil division so a partial trailing bucket still gets a row.
	var n = int((end.Sub(start) + bucket - 1) / bucket)

	var buckets = make([]CountBucket, n)
	for i := range buckets {
		buckets[i].Start = start.Add(time.Duration(i) * bucket)
	}

	var rows, err = s.db.Query(`
		SELECT
			CAST((ts - ?) / ? AS INTEGER) AS bucket,
			SUM(CASE WHEN outcome = ? THEN 1 ELSE 0 END),
			SUM(CASE WHEN outcome = ? THEN 1 ELSE 0 END),
			SUM(CASE WHEN outcome = ? THEN 1 ELSE 0 END),
			SUM(CASE WHEN outcome = ? THEN 1 ELSE 0 END)
		FROM events
		WHERE ts >= ? AND ts < ?
		GROUP BY bucket`,
		startUS, bucketUS,
		OutcomeChallenged, OutcomeChallengeRendered, OutcomeVerifyOK, OutcomeVerifyFail,
		startUS, end.UnixMicro())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var idx, challenged, rendered, solved, failed int
		if err = rows.Scan(&idx, &challenged, &rendered, &solved, &failed); err != nil {
			return nil, err
		}
		if idx < 0 || idx >= n {
			continue
		}
		buckets[idx].Challenged = challenged
		buckets[idx].Rendered = rendered
		buckets[idx].Solved = solved
		buckets[idx].Failed = failed
	}
	return buckets, rows.Err()
}
