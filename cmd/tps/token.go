package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// budgetState tracks how much of its request budget a token has spent, and
// the masked client IP of the token's most recent request so the next
// request can be surcharged if the client moved
type budgetState struct {
	spent  int
	lastIP string
}

// maskClientIP reduces a client IP to the tracked prefix (exact address for
// IPv4, /64 for IPv6) so that address changes within that range are
// invisible — both to hard IP binding (budget disabled) and to switch
// detection (budget enabled).
func maskClientIP(raw string) string {
	var addr, err = netip.ParseAddr(raw)
	if err != nil {
		// Unparseable addresses still get bound, just without masking, so a
		// weird client can't opt out of IP binding entirely
		return raw
	}

	addr = addr.Unmap()
	var bits = maskBitsIPv6
	if addr.Is4() {
		bits = maskBitsIPv4
	}

	var prefix, perr = addr.Prefix(bits)
	if perr != nil {
		return raw
	}
	return prefix.String()
}

// clientFingerprint hashes the binding-relevant attributes of the requesting
// client. It returns "" when all binding options are disabled. The IP is only
// part of the fingerprint when the request budget is disabled: with a budget,
// IP changes are charged against the budget (see chargeToken) instead of
// rejected outright, so binding the token to an IP would defeat that.
func (s *Server) clientFingerprint(c *gin.Context) string {
	var ipPart string
	if s.requestBudget <= 0 {
		ipPart = maskClientIP(c.ClientIP())
	}

	var uaPart string
	if s.bindUserAgent {
		uaPart = c.Request.UserAgent()
	}

	if ipPart == "" && !s.bindUserAgent {
		return ""
	}

	var sum = sha256.Sum256([]byte(ipPart + "\n" + uaPart))
	return hex.EncodeToString(sum[:])
}

// tokenClaims is what TPS reads out of a session token: the id that ties a
// session's events and budget together, and the binding fingerprint of the
// client that solved the challenge.
type tokenClaims struct {
	jti string
	bnd string
}

// claimsOf pulls those claims out of a parsed token, once, so the checks that
// follow don't each repeat the assertion. A token whose claims aren't a
// jwt.MapClaims, or that predates one of these entries, yields the zero value
// — which every caller already treats as unusable. So does a nil token, which
// is what jwt.Parse hands back for input malformed enough that there was
// never a token to speak of.
func claimsOf(token *jwt.Token) tokenClaims {
	if token == nil {
		return tokenClaims{}
	}
	var m, ok = token.Claims.(jwt.MapClaims)
	if !ok {
		return tokenClaims{}
	}
	var claims tokenClaims
	claims.jti, _ = m["jti"].(string)
	claims.bnd, _ = m["bnd"].(string)
	return claims
}

// tokenMatchesClient reports whether the token's binding claim matches the
// client making the current request. Tokens issued before binding was enabled
// (or with a different binding config) fail the check and force a new
// challenge.
func (s *Server) tokenMatchesClient(claims tokenClaims, c *gin.Context) bool {
	var want = s.clientFingerprint(c)
	if want == "" {
		return true
	}

	if claims.bnd != want {
		s.logger.Debug("Token binding mismatch",
			"want", want, "got", claims.bnd, "clientIP", c.ClientIP(),
			"userAgent", c.Request.UserAgent())
		return false
	}
	return true
}

// chargeToken debits the token's request budget for the current request: a
// normal request costs 1, while a request whose masked IP differs from the
// token's previous request costs ipSwitchCost. It returns allowed=false when
// the budget can't cover the cost, meaning the client must solve a new
// challenge, and surcharged=true when the request's IP differed from the
// token's previous one (for analytics). Budget state lives in memory; after a
// restart it is rebuilt on first sight of a token, giving that token a fresh
// budget. Tokens without a "jti" claim (issued before budgets existed) are
// rejected so they can't dodge the limit.
func (s *Server) chargeToken(claims tokenClaims, c *gin.Context) (allowed, surcharged bool) {
	if s.requestBudget <= 0 {
		return true, false
	}

	var jti = claims.jti
	if jti == "" {
		return false, false
	}

	var ip = maskClientIP(c.ClientIP())

	s.budgetMutex.Lock()
	defer s.budgetMutex.Unlock()

	var state *budgetState
	if cached, found := s.budgetCache.Get(jti); found {
		state = cached.(*budgetState)
	} else {
		state = &budgetState{lastIP: ip}
		s.budgetCache.Set(jti, state, s.tokenLifetime)
	}

	var cost = 1
	var switched = ip != state.lastIP
	if switched {
		cost = s.ipSwitchCost
	}
	if state.spent+cost > s.requestBudget {
		return false, switched
	}

	state.spent += cost
	state.lastIP = ip
	return true, switched
}
