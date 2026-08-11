package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"turnstile-proxy-server/internal/db"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// Bypass keys are the second way to be authorized: a provisioned credential
// instead of a solved challenge, for clients (vetted researchers' scrapers,
// mostly) that can't or shouldn't sit through Turnstile. A key never removes
// the limits, it replaces them — each key carries its own token-bucket rate
// and optional daily cap, so "trusted" still can't mean "unlimited".
const (
	// bypassKeyPrefix namespaces the secrets themselves ("tps_..."), so a key
	// is recognizable in a leak, greppable in a client script, and — when sent
	// as a Bearer token — distinguishable from a backend's own Authorization
	// credentials, which TPS must leave alone.
	bypassKeyPrefix = "tps_"

	// bypassKeyHeader is the dedicated way to present a key. Authorization:
	// Bearer works too, for clients that only know how to speak that.
	bypassKeyHeader = "X-TPS-Key"

	// bypassStatusHeader tells a client that presented a bad key why it's
	// looking at a challenge page instead of content: "unknown", "revoked",
	// "expired", or "wrong_ip". Without it, a lapsed key shows up as "my
	// scraper suddenly gets HTML", which is undiagnosable from the client
	// side.
	bypassStatusHeader = "X-TPS-Key-Status"

	// bypassMaxWait is the longest a rate-limited request is held before
	// being proxied rather than refused. A sequential scraper — the common
	// case — is thereby paced to exactly its permitted rate without ever
	// seeing an error; only clients pushing harder than the wait can absorb
	// get 429s.
	bypassMaxWait = 2 * time.Second

	// bypassMaxWaiters caps how many requests one key may have parked in that
	// wait at once, so a parallel scraper can't hold open connections in bulk.
	bypassMaxWaiters = 8

	// bypassRefreshInterval is how often the in-memory key snapshot is
	// re-read from the database, and therefore the longest a new or revoked
	// key takes to be honored. The request path never touches the database.
	bypassRefreshInterval = 30 * time.Second
)

// hashKeySecret is the stored (and looked-up) form of a key secret. Keys are
// long random strings, so a plain SHA-256 — no salt, no work factor — is
// enough to make the database useless to steal, while staying cheap enough
// for the request path.
func hashKeySecret(secret string) string {
	var sum = sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// bypassKey is one key's in-memory runtime state: its settings as of the last
// refresh, plus the rate-limiter and daily counter that must survive
// refreshes (a reload that reset every bucket would hand every key a fresh
// burst each 30 seconds).
type bypassKey struct {
	limiter *rate.Limiter

	mu       sync.Mutex
	key      db.Key
	cidrs    []netip.Prefix // parsed from key.CIDRs; entries that don't parse are dropped
	day      string         // UTC date the daily counter is counting
	daySpent int64
	waiters  int
}

// snapshot returns the key's current settings and parsed CIDRs without
// holding the lock across the caller's slower work.
func (k *bypassKey) snapshot() (db.Key, []netip.Prefix) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.key, k.cidrs
}

// update applies refreshed settings in place, preserving limiter and counter
// state. SetLimit/SetBurst adjust the live bucket rather than replacing it.
func (k *bypassKey) update(key db.Key, cidrs []netip.Prefix) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.key = key
	k.cidrs = cidrs
	if k.limiter.Limit() != rate.Limit(key.RatePerSec) {
		k.limiter.SetLimit(rate.Limit(key.RatePerSec))
	}
	if k.limiter.Burst() != key.Burst {
		k.limiter.SetBurst(key.Burst)
	}
}

// rollDay resets the daily counter when the UTC day has changed. Callers hold
// k.mu.
func (k *bypassKey) rollDay(now time.Time) {
	var today = now.UTC().Format(time.DateOnly)
	if k.day != today {
		k.day = today
		k.daySpent = 0
	}
}

// dayExhausted reports whether the key's daily cap is spent. The counter is
// deliberately approximate: it lives in memory (a restart forgives the day)
// and is read before the rate-limit wait rather than atomically with it, so
// concurrent requests can overshoot the cap by a handful. The cap is a
// volume bound, not an invariant.
func (k *bypassKey) dayExhausted(now time.Time, limit int64) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.rollDay(now)
	return k.daySpent >= limit
}

// chargeDay counts one served request against the daily cap.
func (k *bypassKey) chargeDay(now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.rollDay(now)
	k.daySpent++
}

// addWaiter reserves one of the key's parking spots for a rate-limited
// request that is worth holding rather than refusing. It reports whether a
// spot was free.
func (k *bypassKey) addWaiter() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.waiters >= bypassMaxWaiters {
		return false
	}
	k.waiters++
	return true
}

func (k *bypassKey) dropWaiter() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.waiters--
}

// presentedBypassKey extracts a bypass key from the request, and whether it
// arrived via the Authorization header. X-TPS-Key is TPS's own header, so
// anything in it is a key attempt; Authorization belongs to the backend, so
// only a Bearer token in TPS's own "tps_" namespace is treated as one.
func presentedBypassKey(c *gin.Context) (secret string, viaAuth bool) {
	if v := c.GetHeader(bypassKeyHeader); v != "" {
		return v, false
	}
	if tok, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer "); ok &&
		strings.HasPrefix(tok, bypassKeyPrefix) {
		return tok, true
	}
	return "", false
}

// authorizeBypass serves the request from a presented bypass key when it can.
// It reports whether the request was handled here — proxied, refused with a
// 429, or abandoned by the client mid-wait. When it returns false the request
// carries on to the ordinary token-or-challenge path; if a key was presented
// but found wanting, bypassStatusHeader says why on whatever response that
// path produces.
func (s *Server) authorizeBypass(c *gin.Context) bool {
	var secret, viaAuth = presentedBypassKey(c)
	if secret == "" {
		return false
	}

	// The credential must never reach the backend (or the challenge cache,
	// whose replay would forward it later): X-TPS-Key is ours outright, and a
	// Bearer token in our namespace was addressed to us, whatever becomes of
	// it below.
	c.Request.Header.Del(bypassKeyHeader)
	if viaAuth {
		c.Request.Header.Del("Authorization")
	}

	s.bypassMu.Lock()
	var k = s.bypassKeys[hashKeySecret(secret)]
	s.bypassMu.Unlock()

	if k == nil {
		s.logger.Warn("Unknown bypass key presented", "clientIP", c.ClientIP())
		c.Header(bypassStatusHeader, "unknown")
		return false
	}

	var key, cidrs = k.snapshot()
	var now = time.Now()
	switch {
	case !key.Revoked.IsZero():
		s.logger.Warn("Revoked bypass key presented", "key", key.Label, "clientIP", c.ClientIP())
		c.Header(bypassStatusHeader, "revoked")
		return false
	case !now.Before(key.Expires):
		s.logger.Warn("Expired bypass key presented", "key", key.Label, "clientIP", c.ClientIP())
		c.Header(bypassStatusHeader, "expired")
		return false
	case !clientInCIDRs(c.ClientIP(), key.CIDRs, cidrs):
		s.logger.Warn("Bypass key presented from outside its networks",
			"key", key.Label, "clientIP", c.ClientIP())
		c.Header(bypassStatusHeader, "wrong_ip")
		return false
	}

	if key.DailyCap > 0 && k.dayExhausted(now, key.DailyCap) {
		s.refuseRateLimited(c, key, db.ReasonBypassDailyCap, secondsToUTCMidnight(now))
		return true
	}

	var reservation = k.limiter.Reserve()
	if delay := reservation.Delay(); delay > 0 {
		if delay > bypassMaxWait || !k.addWaiter() {
			reservation.Cancel()
			s.refuseRateLimited(c, key, db.ReasonBypassRate, int(math.Ceil(delay.Seconds())))
			return true
		}
		var held = time.NewTimer(delay)
		defer held.Stop()
		defer k.dropWaiter()
		select {
		case <-held.C:
		case <-c.Request.Context().Done():
			// The client hung up while parked; give the token back and let
			// the connection die. There is no one left to answer.
			reservation.Cancel()
			return true
		}
	}

	if key.DailyCap > 0 {
		k.chargeDay(now)
	}

	s.logDecision(c, db.Event{
		Outcome: db.OutcomeProxied,
		Reason:  db.ReasonBypassKey,
		KeyID:   key.ID,
	})
	s.replayRequest(c, c.Request)
	return true
}

// refuseRateLimited answers a key-authorized request that exceeded its
// limits: a 429 whose Retry-After is when trying again will actually work.
func (s *Server) refuseRateLimited(c *gin.Context, key db.Key, reason string, retryAfter int) {
	s.logger.Warn("Bypass key over its limit", "key", key.Label, "reason", reason,
		"retryAfter", retryAfter, "clientIP", c.ClientIP())
	s.logDecision(c, db.Event{
		Outcome: db.OutcomeRateLimited,
		Reason:  reason,
		KeyID:   key.ID,
	})
	c.Header("Retry-After", strconv.Itoa(retryAfter))
	c.String(http.StatusTooManyRequests, "Bypass key over its request limit; retry after %d seconds", retryAfter)
}

// clientInCIDRs reports whether the client may use a key restricted to the
// given networks. configured is the key's CIDR list as stored; parsed is what
// survived parsing. The distinction fails closed: a key restricted to
// networks that no longer parse matches nothing, rather than falling open to
// everywhere.
func clientInCIDRs(clientIP string, configured []string, parsed []netip.Prefix) bool {
	if len(configured) == 0 {
		return true
	}
	var addr, err = netip.ParseAddr(clientIP)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range parsed {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// secondsToUTCMidnight is the Retry-After for a spent daily cap: the counter
// resets when the UTC day does.
func secondsToUTCMidnight(now time.Time) int {
	var next = now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	return int(math.Ceil(next.Sub(now).Seconds()))
}

// reloadBypassKeys replaces the in-memory key snapshot with the database's
// current contents, carrying each surviving key's limiter and counters over
// so a refresh never hands out a fresh burst.
func (s *Server) reloadBypassKeys() error {
	var keys, err = s.db.ListKeys()
	if err != nil {
		return err
	}

	s.bypassMu.Lock()
	defer s.bypassMu.Unlock()

	var next = make(map[string]*bypassKey, len(keys))
	for _, key := range keys {
		var cidrs []netip.Prefix
		for _, raw := range key.CIDRs {
			var p, perr = netip.ParsePrefix(raw)
			if perr != nil {
				// Dropped from the parsed list but not from key.CIDRs, so the
				// key stays restricted (see clientInCIDRs) instead of opening up
				s.logger.Warn("Ignoring unparseable CIDR on bypass key",
					"key", key.Label, "cidr", raw, "error", perr)
				continue
			}
			cidrs = append(cidrs, p.Masked())
		}

		if prev, ok := s.bypassKeys[key.KeyHash]; ok {
			prev.update(key, cidrs)
			next[key.KeyHash] = prev
			continue
		}
		next[key.KeyHash] = &bypassKey{
			key:     key,
			cidrs:   cidrs,
			limiter: rate.NewLimiter(rate.Limit(key.RatePerSec), key.Burst),
		}
	}
	s.bypassKeys = next
	return nil
}

// startBypassRefresh loads the bypass keys and keeps them fresh until ctx
// ends. With event logging disabled there is no key store, so the feature
// quietly sits out; that's a fact worth one line at startup, not an error.
func (s *Server) startBypassRefresh(ctx context.Context) {
	var err = s.reloadBypassKeys()
	if errors.Is(err, db.ErrKeysUnavailable) {
		s.logger.Info("Bypass keys are disabled; set LOG_DB_PATH to enable them")
		return
	}
	if err != nil {
		s.logger.Error("Could not load bypass keys", "error", err)
	} else {
		s.logger.Info("Loaded bypass keys", "count", len(s.bypassKeys))
	}

	go func() {
		var ticker = time.NewTicker(bypassRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.reloadBypassKeys(); err != nil {
					s.logger.Error("Could not refresh bypass keys", "error", err)
				}
			}
		}
	}()
}
