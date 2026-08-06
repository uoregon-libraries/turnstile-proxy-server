package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
	"turnstile-proxy-server/internal/db"
	"turnstile-proxy-server/internal/requestid"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
)

type cachedRequest struct {
	Method  string
	Body    []byte
	Headers http.Header
	URL     *url.URL
}

// cloudflareVerifyResponse is the structure of the JSON response from Cloudflare
type cloudflareVerifyResponse struct {
	Success     bool     `json:"success"`
	ErrorCodes  []string `json:"error-codes"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
}

// originFormURL reports whether the request target is in the "origin-form"
// that every real client sends: an absolute path with no scheme or authority
// of its own, and no leading "//".
//
// TPS echoes the request URL straight back to the browser twice — as the
// challenge form's action and as the post-solve redirect — so a target naming
// another origin turns a link to a protected site into an attack. HTTP/1.1
// allows the absolute-form target "GET http://evil.com/x", and net/http parses
// it faithfully; a path of "//evil.com/x" is likewise a protocol-relative URL
// once a browser resolves it. Either one makes the challenge page POST the
// visitor's Turnstile solution to evil.com and then redirects the visitor
// there, wearing the protected site's "verifying you are human" page as cover.
//
// The test is on EscapedPath rather than Path because that is what URL.String
// emits: a percent-encoded "/%2f%2fevil.com" is unambiguous to a browser and
// stays allowed, while a literal "//evil.com" is not.
func originFormURL(u *url.URL) bool {
	if u.Scheme != "" || u.Host != "" || u.User != nil {
		return false
	}
	var path = u.EscapedPath()
	return strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//")
}

func (s *Server) handleProxy(c *gin.Context) {
	// Refuse anything that doesn't address this origin before it can reach a
	// handler that would echo it back to the browser. Nothing legitimate asks
	// for such a URL, so this is a flat rejection rather than an attempt to
	// rewrite the target into something safe.
	if !originFormURL(c.Request.URL) {
		s.logger.Warn("Refusing request whose target names another origin",
			"url", c.Request.URL.String(), "clientIP", c.ClientIP())
		c.String(http.StatusBadRequest, "Bad request target")
		return
	}

	// The reserved admin prefix is always handled by TPS itself and is never
	// proxied or challenged. It is checked before everything else so these
	// internal endpoints can't be shadowed by a backend path.
	if strings.HasPrefix(c.Request.URL.Path, adminPathPrefix) {
		s.handleAdmin(c)
		return
	}

	// A live token is the whole fast path: served straight from the cookie and
	// never buffered. Everything past this point is challenge machinery, and
	// pays the costs an unverified client is allowed to impose.
	var served, challengeReason, challengeJTI = s.authorizeToken(c)
	if served {
		return
	}

	var body, ok = s.bufferChallengeBody(c)
	if !ok {
		return
	}

	// Not a valid session, check if this is a verification attempt
	s.logger.Debug("handleProxy: checking request for turnstile POST")
	var turnstileResponse = c.PostForm("cf-turnstile-response")
	var requestID = c.PostForm("request_id")
	if c.Request.Method == http.MethodPost && turnstileResponse != "" && requestID != "" {
		s.handleVerification(c, turnstileResponse, requestID)
		return
	}

	s.serveChallenge(c, body, challengeReason, challengeJTI)
}

// authorizeToken looks for a live session cookie and, when it finds one,
// serves the request from it. It reports whether the request was served; when
// it wasn't, it reports why the client is about to be challenged and the jti
// of the token that failed, where there was a token to name.
//
// A request authorized here streams to the backend like any ordinary proxied
// request. That is the point of doing this first: the buffering, the size
// caps, and the request cache all exist for clients that haven't proved
// anything, and a client that has proved something shouldn't pay for them.
func (s *Server) authorizeToken(c *gin.Context) (served bool, reason, jti string) {
	s.logger.Debug("handleProxy: checking for JWT")

	var cookie, err = c.Cookie(cookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			s.logger.Debug("No JWT, presenting challenge")
		} else {
			// A cookie that's present but unreadable (a malformed
			// percent-escape, say). There's nothing to verify, so it takes the
			// same path as no cookie at all, but silently is the wrong way to
			// do it.
			s.logger.Warn("Could not read the session cookie, presenting challenge", "error", err)
		}
		return false, db.ReasonNoCookie, ""
	}

	var token, parseErr = jwt.Parse(cookie, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSigningKey, nil
	})
	if parseErr != nil {
		s.logger.Warn("JWT was present but invalid, presenting challenge", "error", parseErr)
		return false, db.ReasonInvalidJWT, ""
	}

	var claims = claimsOf(token)
	if !s.tokenMatchesClient(claims, c) {
		s.logger.Warn("JWT is valid but bound to a different client, presenting challenge",
			"clientIP", c.ClientIP())
		return false, db.ReasonClientMismatch, claims.jti
	}

	var allowed, surcharged = s.chargeToken(claims, c)
	if !allowed {
		s.logger.Warn("JWT is valid but its request budget is exhausted, presenting challenge",
			"clientIP", c.ClientIP())
		return false, db.ReasonBudgetExhausted, claims.jti
	}

	s.logger.Debug("JWT is valid, proxying request", "URL", c.Request.URL.String())
	s.logDecision(c, db.Event{
		Outcome:  db.OutcomeProxied,
		Reason:   db.ReasonValidToken,
		JTI:      claims.jti,
		IPSwitch: surcharged,
	})
	s.replayRequest(c, c.Request)
	return true, "", ""
}

// bufferChallengeBody reads the request body into memory and hands the caller
// both the bytes and a fresh reader over them. It reports whether the caller
// should carry on; when it returns false it has already answered the client.
//
// Verifying a challenge and caching a request for replay both need the body in
// memory, and gin's form lookups drain c.Request.Body to answer. Without
// reading it once here, a challenged form POST (urlencoded or multipart) is
// cached with an empty body and replayed to the backend with the user's data
// gone.
//
// The read is capped at maxChallengeBody, because this is memory an unverified
// client gets to allocate: any bot can post a body of whatever size it likes
// and have TPS keep it for the five-minute life of the request cache. A
// request with a live token never reaches here, so real uploads aren't capped.
func (s *Server) bufferChallengeBody(c *gin.Context) ([]byte, bool) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, s.maxChallengeBody)
	var body, readErr = io.ReadAll(c.Request.Body)
	if readErr != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(readErr, &tooLarge) {
			s.logger.Warn("Request body too large to challenge",
				"limit", s.maxChallengeBody, "clientIP", c.ClientIP(), "path", c.Request.URL.Path)
			c.String(http.StatusRequestEntityTooLarge, "Request body too large")
			return nil, false
		}
		s.logger.Error("Could not read original request body", "error", readErr)
		c.String(http.StatusInternalServerError, "Could not buffer request")
		return nil, false
	}

	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	return body, true
}

// handleVerification checks a solved challenge with Cloudflare and, if it's
// genuine, issues the session cookie and delivers the request the challenge
// interrupted.
func (s *Server) handleVerification(c *gin.Context, turnstileResponse, requestID string) {
	s.logger.Debug("Received turnstile response, attempting verification", "requestID", requestID)

	var client = &http.Client{Timeout: 10 * time.Second}
	var resp, err = client.PostForm(s.verifyURL, url.Values{"secret": {s.secretKey}, "response": {turnstileResponse}})
	if err != nil {
		s.logger.Error("Failed to POST to Cloudflare", "error", err)
		c.String(http.StatusInternalServerError, "Failed to verify token")
		return
	}
	defer resp.Body.Close()

	var verifyResp cloudflareVerifyResponse
	err = json.NewDecoder(resp.Body).Decode(&verifyResp)
	if err != nil {
		s.logger.Error("Failed to decode Cloudflare response", "error", err)
		c.String(http.StatusInternalServerError, "Failed to decode Cloudflare response")
		return
	}

	if !verifyResp.Success {
		s.logger.Warn("Turnstile verification failed", "error-codes", verifyResp.ErrorCodes)
		s.logDecision(c, db.Event{Outcome: db.OutcomeVerifyFail})
		c.HTML(http.StatusForbidden, s.getTemplate(c.Request, "failed"), nil)
		return
	}

	s.logger.Debug("Turnstile verification successful")
	// Build the event before the replay (which consumes the request) but log it
	// after: "solved" should mean the client actually got through, and a replay
	// that dies on our side is not the client succeeding. It isn't the client
	// failing either, so it gets its own outcome rather than polluting the
	// verify_fail count with our bugs.
	var e = s.fillEvent(c, db.Event{
		Outcome: db.OutcomeVerifyOK,
		Reason:  db.ReasonVerifiedReplay,
	})
	if served, why := s.issueTokenAndReplay(c, requestID); !served {
		e.Outcome = db.OutcomeVerifyError
		e.Reason = why
	}
	s.db.LogEvent(e)
}

// serveChallenge caches the request the challenge is about to interrupt, so it
// can be replayed once the client solves it, and renders the challenge page.
// reason and jti are what authorizeToken concluded, for the logged event.
func (s *Server) serveChallenge(c *gin.Context, body []byte, reason, jti string) {
	s.logger.Debug("handleProxy: new request, presenting challenge")

	// Reserve the cache budget before taking the memory. Challenges pending at
	// once are otherwise unbounded: each one holds its request for five
	// minutes whether or not the client is still there, so a flood outlives
	// itself by five minutes and keeps growing. Shedding with a 503 is the
	// right failure here — it costs one client a challenge, where running out
	// of memory costs everyone the whole gate.
	var cost = cachedRequestCost(body)
	if s.cachedBytes.Add(cost) > s.maxChallengeCache {
		s.cachedBytes.Add(-cost)
		s.logger.Warn("Too many challenges pending to cache another request",
			"limit", s.maxChallengeCache, "clientIP", c.ClientIP(), "path", c.Request.URL.Path)
		c.String(http.StatusServiceUnavailable, "Too many challenges in flight, try again shortly")
		return
	}

	var newRequestID = requestid.New()
	var cachedReq = &cachedRequest{
		Method:  c.Request.Method,
		Body:    body,
		Headers: c.Request.Header,
		URL:     c.Request.URL,
	}
	s.requestCache.Set(newRequestID, cachedReq, cache.DefaultExpiration)
	s.logger.Info("No/invalid JWT, serving challenge", "requestID", newRequestID)
	s.logDecision(c, db.Event{
		Outcome: db.OutcomeChallenged,
		Reason:  reason,
		JTI:     jti,
	})
	c.HTML(http.StatusForbidden, s.getTemplate(c.Request, "challenge"), gin.H{
		"SiteKey":    s.siteKey,
		"RequestID":  newRequestID,
		"PostAction": c.Request.URL,
		// Carried through the form so a challenge that outlives its cache entry
		// can still be recovered. See recoverExpiredChallenge.
		"OriginalMethod": c.Request.Method,
	})
}

func (s *Server) replayRequest(c *gin.Context, req *http.Request) {
	var target = s.proxyTarget
	if target == nil {
		s.logger.Error("No proxy target configured", "path", req.URL.Path)
		c.String(http.StatusBadGateway, "No proxy target configured")
		return
	}
	s.logger.Debug("Replaying request to backend",
		"method", req.Method, "path", req.URL.Path, "target", target.String())
	var director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
	}
	var proxy = &httputil.ReverseProxy{
		Director: director,
		// Log what the backend actually returned. A "blank screen" after a
		// challenge usually means the backend replied with an empty body, a
		// redirect, or an unexpected status, so surface the essentials.
		ModifyResponse: func(resp *http.Response) error {
			s.logger.Debug("Backend responded to replayed request",
				"path", req.URL.Path,
				"status", resp.StatusCode,
				"contentLength", resp.ContentLength,
				"contentType", resp.Header.Get("Content-Type"),
				"contentEncoding", resp.Header.Get("Content-Encoding"),
				"location", resp.Header.Get("Location"))
			return nil
		},
		// The default ErrorHandler writes a 502 with an EMPTY body and logs
		// nothing useful here, which itself looks like a blank screen. Make
		// the failure visible in both the logs and the response.
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			s.logger.Error("Backend proxy error while replaying request",
				"path", req.URL.Path, "target", target.String(), "error", err)
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("Upstream request failed"))
		},
	}
	proxy.ServeHTTP(c.Writer, req)
}

// issueTokenAndReplay mints the session cookie for a client that just solved a
// challenge and delivers the request the challenge interrupted.
//
// It reports whether the client was actually served, and on failure the
// db.Reason that says why: TPS accepted the solution and then couldn't finish,
// so the client got an error instead of the page they asked for. Only failures
// TPS can see from here count -- once the request is handed to the reverse
// proxy, a backend that then falls over is the backend's problem, not a failed
// challenge.
func (s *Server) issueTokenAndReplay(c *gin.Context, requestID string) (served bool, failReason string) {
	var jti = requestid.New()
	var claimsMap = jwt.MapClaims{
		"iss": "tps",
		"aud": "caddy",
		"jti": jti,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(s.tokenLifetime).Unix(),
		"nbf": time.Now().Unix(),
	}
	if fp := s.clientFingerprint(c); fp != "" {
		claimsMap["bnd"] = fp
	}
	if s.requestBudget > 0 {
		// Seed the budget state with the solver's IP so the first request
		// from a different address is already recognizable as a switch
		s.budgetMutex.Lock()
		s.budgetCache.Set(jti, &budgetState{lastIP: maskClientIP(c.ClientIP())}, s.tokenLifetime)
		s.budgetMutex.Unlock()
	}
	var claims = jwt.NewWithClaims(jwt.SigningMethodHS256, claimsMap)

	var tokenString, err = claims.SignedString(s.jwtSigningKey)
	if err != nil {
		s.logger.Error("Failed to sign JWT", "error", err)
		c.String(http.StatusInternalServerError, "Failed to create session")
		return false, db.ReasonReplayFailed
	}

	var secure = c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	s.logger.Debug("Issuing session cookie after successful challenge",
		"jti", jti,
		"secure", secure,
		"tls", c.Request.TLS != nil,
		"xForwardedProto", c.GetHeader("X-Forwarded-Proto"),
		"bound", claimsMap["bnd"] != nil,
		"requestID", requestID)
	c.SetCookie(cookieName, tokenString, int(s.tokenLifetime.Seconds()), "/", "", secure, true)

	var cachedReqInterface, ok = s.requestCache.Get(requestID)
	if !ok {
		return s.recoverExpiredChallenge(c, requestID)
	}

	// This challenge is spent: the client has a cookie now, and a reload goes
	// through on its own. Dropping the entry hands its memory straight back to
	// the cache budget instead of holding it for the rest of the five-minute
	// TTL, and closes the window where a leaked request ID could be replayed.
	var cachedReq = cachedReqInterface.(*cachedRequest)
	s.requestCache.Delete(requestID)

	// For a GET, use POST/Redirect/GET: the challenge was solved via a form
	// POST to the original URL, so the browser's history entry for that URL is
	// now a POST. Replaying the GET inline would render the page once, but a
	// refresh re-submits the POST and the backend 404s (or 405s). Redirect to
	// the original URL instead; the cookie set above lets the follow-up GET
	// through, and the browser's history entry becomes a clean GET. Non-GET
	// originals (e.g. an API POST) can't be turned into a GET, so they are
	// still replayed inline.
	if cachedReq.Method == http.MethodGet {
		s.logger.Debug("Redirecting to original GET after challenge", "URL", cachedReq.URL.String())
		c.Redirect(http.StatusSeeOther, cachedReq.URL.String())
		return true, ""
	}

	s.logger.Debug("Replaying request", "Method", cachedReq.Method, "URL", cachedReq.URL)

	var req, reqErr = http.NewRequest(cachedReq.Method, cachedReq.URL.String(), bytes.NewReader(cachedReq.Body))
	if reqErr != nil {
		s.logger.Error("Could not create new request from cached", "requestID", requestID, "error", reqErr)
		c.String(http.StatusInternalServerError, "Could not replay original request")
		return false, db.ReasonReplayFailed
	}
	req.Header = stripConditionalHeaders(cachedReq.Headers)
	s.replayRequest(c, req)
	return true, ""
}

// recoverExpiredChallenge deals with a solved challenge whose original request
// is no longer cached, which happens when the client took longer than the
// cache's five-minute TTL to solve it. It returns whether the client was served.
//
// The cookie is already set by the time we get here, so the client is verified;
// the only thing missing is the request the challenge interrupted. The URL
// isn't actually lost with the cache entry — the challenge form posts to the
// original URL, so it's the URL of the request in hand — and handleProxy has
// already refused anything that isn't an ordinary same-origin path, so it's
// safe to send the client back to it.
//
// What the URL can't tell us is the method, so the challenge form carries it.
// A GET is reissued as the same redirect a live cache entry would have
// produced, and the client sees no difference. Anything else had a body, and
// the body is exactly what expired: there is nothing to replay, and quietly
// reissuing a POST as a GET would drop whatever the user typed while looking
// like it worked. Those get told what happened instead.
//
// A hand-written challenge form that doesn't send original_method is treated as
// unknown, and takes the same honest failure — guessing "GET" would be right
// most of the time, but the times it's wrong are the ones that lose data.
func (s *Server) recoverExpiredChallenge(c *gin.Context, requestID string) (served bool, failReason string) {
	var method = strings.ToUpper(c.PostForm("original_method"))
	s.logger.Warn("Challenge solved after its cached request expired",
		"requestID", requestID, "originalMethod", method, "url", c.Request.URL.String())

	if method == http.MethodGet {
		s.logger.Debug("Redirecting to the original URL after an expired challenge",
			"URL", c.Request.URL.String())
		c.Redirect(http.StatusSeeOther, c.Request.URL.String())
		return true, ""
	}

	c.String(http.StatusRequestTimeout,
		"The challenge took too long to solve, and the request it interrupted is no longer "+
			"available to send on. You are verified now, so going back and submitting again "+
			"will work.")
	return false, db.ReasonChallengeExpired
}

// conditionalHeaders are request headers that ask the backend to answer with a
// bodyless 304/412 if the client's cached copy is still current. They are
// meaningless on a post-challenge replay: the response is delivered as the
// result of the challenge-form POST, where the browser has no cached entry to
// revalidate, so a 304 renders as a blank page. We strip them so the replay
// always yields a full response.
var conditionalHeaders = []string{
	"If-None-Match",
	"If-Modified-Since",
	"If-Match",
	"If-Unmodified-Since",
	"If-Range",
}

// stripConditionalHeaders returns a copy of h with the conditional/revalidation
// headers removed. It clones first so the cached original request (which may
// outlive this replay in the request cache) is left untouched.
func stripConditionalHeaders(h http.Header) http.Header {
	var out = h.Clone()
	if out == nil {
		return out
	}
	for _, name := range conditionalHeaders {
		out.Del(name)
	}
	return out
}
