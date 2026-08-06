package main

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"
	"turnstile-proxy-server/internal/db"

	"github.com/gin-gonic/gin"
)

// adminPathPrefix is the reserved, collision-resistant path under which all of
// TPS's own endpoints live. The leading dot keeps it clear of real application
// routes (mirroring Anubis's "/.within.website/"). Requests under this prefix
// are always handled by TPS and never proxied to a backend.
const adminPathPrefix = "/.tps/"

// handleAdmin routes a request under adminPathPrefix to the matching internal
// endpoint. The beacon is public; the report endpoint requires the admin
// secret (and 404s when no secret is configured, so the feature is opt-in).
func (s *Server) handleAdmin(c *gin.Context) {
	switch strings.TrimPrefix(c.Request.URL.Path, adminPathPrefix) {
	case "beacon":
		s.handleBeacon(c)
	case "report":
		if s.requireAdmin(c) {
			s.handleReport(c)
		}
	default:
		c.String(http.StatusNotFound, "not found")
	}
}

// requireAdmin gates the report endpoint. It is disabled (404, to avoid
// advertising the feature) unless ADMIN_SECRET is configured; when it is, the
// caller must present it either as a "Bearer" token or a "key" query parameter
// (the latter so a plain browser URL works without any tooling). Returns false
// and writes the response when access is denied.
func (s *Server) requireAdmin(c *gin.Context) bool {
	if s.adminSecret == "" {
		c.String(http.StatusNotFound, "not found")
		return false
	}

	var presented = c.Query("key")
	if presented == "" {
		presented = strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(s.adminSecret)) != 1 {
		c.Header("WWW-Authenticate", "Bearer")
		c.String(http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

// handleBeacon records that a served challenge page's JavaScript actually ran
// in the client. It is intentionally unauthenticated: the challenge page (on
// the protected host) pings it on load, and that ping is the only signal that
// separates clients that execute JS ("smart") from those that never do
// ("dumb"). It responds 204 with no body.
func (s *Server) handleBeacon(c *gin.Context) {
	s.logDecision(c, db.Event{Outcome: db.OutcomeChallengeRendered})
	c.Status(http.StatusNoContent)
}

// reportResponse is the JSON returned by /.tps/report.
type reportResponse struct {
	Period    string           `json:"period"`
	Bucket    string           `json:"bucket"`
	Start     time.Time        `json:"start"`
	End       time.Time        `json:"end"`
	Generated time.Time        `json:"generated"`
	Buckets   []db.CountBucket `json:"buckets"`
}

// handleReport returns the challenged/rendered/solved/failed counts for the
// requested period, bucketed at a granularity that suits the span.
func (s *Server) handleReport(c *gin.Context) {
	var period = c.DefaultQuery("period", "1d")
	var start, end, bucket, ok = reportWindow(period, time.Now())
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": `period must be one of "1d", "7d", "1m", "1y"`})
		return
	}

	var buckets, err = s.db.Report(start, end, bucket)
	if err != nil {
		if errors.Is(err, db.ErrReportingUnavailable) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "event logging is disabled; set LOG_DB_PATH to enable reports"})
			return
		}
		s.logger.Error("report query failed", "period", period, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report query failed"})
		return
	}

	c.JSON(http.StatusOK, reportResponse{
		Period:    period,
		Bucket:    bucket.String(),
		Start:     start,
		End:       end,
		Generated: time.Now().UTC(),
		Buckets:   buckets,
	})
}

// reportWindow maps a period keyword to the aligned [start, end) window and
// bucket width used for the report. The window end is rounded up to the next
// bucket boundary (in UTC) so rows land on tidy wall-clock times — hourly for
// 1d, 00:00/12:00 for 7d, daily for 1m, fortnightly for 1y — and the latest
// (partial) bucket is included. Row counts: 24, 14, 30, 26.
func reportWindow(period string, now time.Time) (start, end time.Time, bucket time.Duration, ok bool) {
	var count int
	switch period {
	case "1d":
		bucket, count = time.Hour, 24
	case "7d":
		bucket, count = 12*time.Hour, 14
	case "1m":
		bucket, count = 24*time.Hour, 30
	case "1y":
		bucket, count = 14*24*time.Hour, 26
	default:
		return time.Time{}, time.Time{}, 0, false
	}

	end = now.UTC().Truncate(bucket).Add(bucket)
	start = end.Add(-time.Duration(count) * bucket)
	return start, end, bucket, true
}
