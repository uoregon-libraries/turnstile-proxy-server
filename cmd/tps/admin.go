package main

import (
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"turnstile-proxy-server/internal/db"
	"turnstile-proxy-server/internal/friendly"

	"github.com/gin-gonic/gin"
)

// adminPathPrefix is the reserved, collision-resistant path under which all of
// TPS's own endpoints live. The leading dot keeps it clear of real application
// routes (mirroring Anubis's "/.within.website/"). Requests under this prefix
// are always handled by TPS and never proxied to a backend.
const adminPathPrefix = "/.tps/"

// eventHub fans out decision events to connected /.tps/watch subscribers. A
// subscriber that can't keep up has events dropped rather than being allowed to
// block the request path; the live view is best-effort, not an audit log.
type eventHub struct {
	mu   sync.Mutex
	subs map[chan db.Event]struct{}
}

func newEventHub() *eventHub {
	return &eventHub{subs: make(map[chan db.Event]struct{})}
}

func (h *eventHub) subscribe() chan db.Event {
	var ch = make(chan db.Event, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *eventHub) unsubscribe(ch chan db.Event) {
	h.mu.Lock()
	if _, ok := h.subs[ch]; ok {
		delete(h.subs, ch)
		close(ch)
	}
	h.mu.Unlock()
}

func (h *eventHub) broadcast(e db.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- e:
		default:
			// Subscriber is behind; drop this event for it.
		}
	}
}

// handleAdmin routes a request under adminPathPrefix to the matching internal
// endpoint. The beacon is public; the analytics endpoints require the admin
// secret (and 404 when no secret is configured, so the feature is opt-in).
func (s *Server) handleAdmin(c *gin.Context) {
	switch strings.TrimPrefix(c.Request.URL.Path, adminPathPrefix) {
	case "beacon":
		s.handleBeacon(c)
	case "report":
		if s.requireAdmin(c) {
			s.handleReport(c)
		}
	case "watch":
		if s.requireAdmin(c) {
			s.handleWatch(c)
		}
	case "watch.html":
		if s.requireAdmin(c) {
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(watchPageHTML))
		}
	default:
		c.String(http.StatusNotFound, "not found")
	}
}

// requireAdmin gates the analytics endpoints. They are disabled (404, to avoid
// advertising the feature) unless ADMIN_SECRET is configured; when it is, the
// caller must present it either as a "Bearer" token or a "key" query parameter
// (the latter so EventSource, which can't set headers, can authenticate).
// Returns false and writes the response when access is denied.
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
	var e = s.baseEvent(c)
	e.Outcome = db.OutcomeChallengeRendered
	s.recordEvent(e)
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

// watchEvent is one decision rendered for the live view: the friendly name
// replaces opaque identifiers, and only the fields useful to a human watching
// traffic are included.
type watchEvent struct {
	Time    time.Time `json:"time"`
	Name    string    `json:"name"`
	Outcome string    `json:"outcome"`
	Reason  string    `json:"reason,omitempty"`
	Method  string    `json:"method"`
	Host    string    `json:"host"`
	Path    string    `json:"path"`
	IP      string    `json:"ip"`
	UA      string    `json:"ua,omitempty"`
}

func toWatchEvent(e db.Event) watchEvent {
	return watchEvent{
		Time:    e.Timestamp,
		Name:    friendly.Name(stableID(e)),
		Outcome: e.Outcome,
		Reason:  e.Reason,
		Method:  e.Method,
		Host:    e.Host,
		Path:    e.Path,
		IP:      e.MaskedIP,
		UA:      e.UserAgent,
	}
}

// stableID picks the most stable identifier available so one client keeps one
// friendly name across requests: the token id when present (a solved session),
// otherwise the masked IP plus User-Agent.
func stableID(e db.Event) string {
	if e.JTI != "" {
		return e.JTI
	}
	return e.MaskedIP + "\n" + e.UserAgent
}

// watchPingInterval is how often the watch stream emits a keep-alive comment.
// It's a package var so tests can shorten it; in production the default keeps
// idle connections alive through buffering proxies without much chatter.
var watchPingInterval = 25 * time.Second

// handleWatch streams decision events to the client as Server-Sent Events until
// the client disconnects. A periodic comment keeps idle connections alive
// through buffering proxies.
func (s *Server) handleWatch(c *gin.Context) {
	var ch = s.hub.subscribe()
	defer s.hub.unsubscribe(ch)

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no") // tell nginx not to buffer the stream

	var ticker = time.NewTicker(watchPingInterval)
	defer ticker.Stop()

	var ctx = c.Request.Context()
	c.Stream(func(w io.Writer) bool {
		select {
		case <-ctx.Done():
			return false
		case e, ok := <-ch:
			if !ok {
				return false
			}
			c.SSEvent("event", toWatchEvent(e))
			return true
		case <-ticker.C:
			_, _ = io.WriteString(w, ": ping\n\n")
			return true
		}
	})
}

// watchPageHTML is a self-contained live viewer for /.tps/watch. It reads the
// "key" from its own query string and passes it through to the EventSource URL
// so a single bookmarked URL (…/watch.html?key=SECRET) works end to end.
const watchPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TPS — live events</title>
<style>
  body { font: 14px/1.4 system-ui, sans-serif; margin: 0; background: #0f1115; color: #e6e6e6; }
  header { padding: .6rem 1rem; background: #171a21; border-bottom: 1px solid #2a2f3a; display: flex; gap: 1rem; align-items: baseline; }
  header h1 { font-size: 1rem; margin: 0; }
  #status { color: #8a93a6; font-size: .85rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: .35rem .75rem; border-bottom: 1px solid #1e222b; white-space: nowrap; }
  th { position: sticky; top: 0; background: #171a21; color: #8a93a6; font-weight: 600; }
  td.path, td.ua { white-space: normal; word-break: break-all; }
  .tag { display: inline-block; padding: .05rem .45rem; border-radius: .65rem; font-size: .75rem; font-weight: 600; }
  .proxied { background: #14361f; color: #7ee2a0; }
  .challenged { background: #3a2f12; color: #f2cf6b; }
  .challenge_rendered { background: #123a36; color: #6fe6d8; }
  .verify_ok { background: #14361f; color: #7ee2a0; }
  .verify_fail { background: #3a1414; color: #f08a8a; }
  .nav_skip { background: #1f2430; color: #9aa6bd; }
  .name { font-weight: 600; }
</style>
</head>
<body>
<header>
  <h1>TPS live events</h1>
  <span id="status">connecting…</span>
</header>
<table>
  <thead>
    <tr><th>Time</th><th>Visitor</th><th>Outcome</th><th>Reason</th><th>Method</th><th>Host</th><th>Path</th><th>IP</th></tr>
  </thead>
  <tbody id="rows"></tbody>
</table>
<script>
  var key = new URLSearchParams(location.search).get('key') || '';
  var url = 'watch' + (key ? '?key=' + encodeURIComponent(key) : '');
  var status = document.getElementById('status');
  var rows = document.getElementById('rows');
  var es = new EventSource(url);
  es.onopen = function () { status.textContent = 'connected'; };
  es.onerror = function () { status.textContent = 'disconnected — retrying…'; };
  es.addEventListener('event', function (msg) {
    var e = JSON.parse(msg.data);
    var tr = document.createElement('tr');
    function cell(text, cls) { var td = document.createElement('td'); if (cls) td.className = cls; td.textContent = text; return td; }
    var t = new Date(e.time).toLocaleTimeString();
    tr.appendChild(cell(t));
    var nameTd = cell(e.name, 'name'); tr.appendChild(nameTd);
    var oTd = document.createElement('td');
    var span = document.createElement('span'); span.className = 'tag ' + e.outcome; span.textContent = e.outcome;
    oTd.appendChild(span); tr.appendChild(oTd);
    tr.appendChild(cell(e.reason || ''));
    tr.appendChild(cell(e.method || ''));
    tr.appendChild(cell(e.host || ''));
    tr.appendChild(cell(e.path || '', 'path'));
    tr.appendChild(cell(e.ip || ''));
    rows.insertBefore(tr, rows.firstChild);
    while (rows.childElementCount > 500) { rows.removeChild(rows.lastChild); }
  });
</script>
</body>
</html>
`
