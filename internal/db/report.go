package db

import (
	"errors"
	"time"
)

// ErrReportingUnavailable is returned by [Store.Report] when event logging is
// disabled, so there is no events table to aggregate.
var ErrReportingUnavailable = errors.New("event logging is disabled; no report data available")

// rollupBucket is the fixed resolution of the rollups table that feeds
// [Store.Report]. Hourly buckets nest exactly into every report bucket width
// the admin API uses (1h, 12h, 24h, 14d), all of which are whole hours and
// UTC-aligned.
const rollupBucket = time.Hour

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

// Report aggregates recorded events in [start, end) into
// ceil((end-start)/bucket) contiguous buckets of width bucket, the first
// starting at start. Every bucket is returned even when it has no events, so
// the caller gets a dense series (gaps show as zero rows).
//
// Counts come from the hourly rollups table, not the raw event log, so reports
// stay cheap regardless of traffic volume and reach back beyond the raw log's
// retention window. The trade-off is hourly resolution: bucket must be a whole
// number of hours and start must fall on an hour boundary, so that every
// rollup row lands wholly inside one report bucket.
func (s *sqliteStore) Report(start, end time.Time, bucket time.Duration) ([]CountBucket, error) {
	if !end.After(start) {
		return nil, errors.New("report end must be after start")
	}
	if bucket <= 0 {
		return nil, errors.New("report bucket width must be positive")
	}
	if bucket%rollupBucket != 0 {
		return nil, errors.New("report bucket width must be a multiple of " + rollupBucket.String())
	}
	if start.UnixMicro()%rollupBucket.Microseconds() != 0 {
		return nil, errors.New("report start must be aligned to " + rollupBucket.String())
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
			CAST((bucket_ts - ?) / ? AS INTEGER) AS bucket,
			SUM(CASE WHEN outcome = ? THEN n ELSE 0 END),
			SUM(CASE WHEN outcome = ? THEN n ELSE 0 END),
			SUM(CASE WHEN outcome = ? THEN n ELSE 0 END),
			SUM(CASE WHEN outcome = ? THEN n ELSE 0 END)
		FROM rollups
		WHERE bucket_ts >= ? AND bucket_ts < ?
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
