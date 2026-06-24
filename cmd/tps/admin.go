package main

import (
	"net/http"
	"strings"
	"turnstile-proxy-server/internal/db"

	"github.com/gin-gonic/gin"
)

// adminPathPrefix is the reserved, collision-resistant path under which all of
// TPS's own endpoints live. The leading dot keeps it clear of real application
// routes (mirroring Anubis's "/.within.website/"). Requests under this prefix
// are always handled by TPS and never proxied to a backend.
const adminPathPrefix = "/.tps/"

// handleAdmin routes a request under adminPathPrefix to the matching internal
// endpoint.
func (s *Server) handleAdmin(c *gin.Context) {
	switch strings.TrimPrefix(c.Request.URL.Path, adminPathPrefix) {
	case "beacon":
		s.handleBeacon(c)
	default:
		c.String(http.StatusNotFound, "not found")
	}
}

// handleBeacon records that a served challenge page's JavaScript actually ran
// in the client. It is intentionally unauthenticated: the challenge page (on
// the protected host) pings it on load, and that ping is the only signal that
// separates clients that execute JS ("smart") from those that never do
// ("dumb"). It responds 204 with no body.
func (s *Server) handleBeacon(c *gin.Context) {
	var e = s.baseEvent(c)
	e.Outcome = db.OutcomeChallengeRendered
	s.db.LogEvent(e)
	c.Status(http.StatusNoContent)
}
