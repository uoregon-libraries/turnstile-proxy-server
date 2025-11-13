package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
	"turnstile-proxy-server/internal/requestid"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
)

const (
	cookieName = "tps-jwt"
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

// Server wraps a [gin.Engine], encapsulating the handlers' logic and data for
// presenting the turnstile challenge, verifying, and redirecting
type Server struct {
	r             *gin.Engine
	logger        *slog.Logger
	siteKey       string
	secretKey     string
	jwtSigningKey []byte
	requestCache  *cache.Cache
	proxyTarget   *url.URL
}

// NewServer creates and configures a new Server instance
func NewServer(router *gin.Engine, siteKey string, secretKey string, jwtSigningKey string, proxyTarget string, logger *slog.Logger) *Server {
	var requestCache = cache.New(5*time.Minute, 10*time.Minute)

	var parsedURL, err = url.Parse(proxyTarget)
	if err != nil {
		logger.Error("Could not parse proxy target URL", "error", err)
		return nil
	}

	var s = &Server{
		r:             router,
		siteKey:       siteKey,
		secretKey:     secretKey,
		jwtSigningKey: []byte(jwtSigningKey),
		logger:        logger,
		requestCache:  requestCache,
		proxyTarget:   parsedURL,
	}

	s.r.Any("/*proxyPath", s.handleProxy)

	return s
}

// loadTemplates is a general-case helper to load either from local disk for
// hot-reloads, or from an embedded filesystem, depending on the gin mode
func (s *Server) loadTemplates(pattern string, fs fs.FS) {
	if gin.Mode() == gin.DebugMode {
		s.r.LoadHTMLGlob(pattern)
		return
	}
	var tmpl = template.Must(template.New("").ParseFS(fs, "*.go.html"))
	s.r.SetHTMLTemplate(tmpl)
}

// Run starts the server listening on the configured address
func (s *Server) Run(addr string) error {
	return s.r.Run(addr)
}

func (s *Server) handleProxy(c *gin.Context) {
	var cookie, err = c.Cookie(cookieName)
	if err == nil {
		var _, parseErr = jwt.Parse(cookie, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.jwtSigningKey, nil
		})

		if parseErr == nil {
			s.logger.Info("JWT is valid, proxying request")
			s.replayRequest(c, c.Request)
			return
		}
		s.logger.Warn("Failed to parse JWT", "error", parseErr)
	}

	// Not a valid session, check if this is a verification attempt
	var turnstileResponse = c.PostForm("cf-turnstile-response")
	var requestID = c.PostForm("request_id")
	if c.Request.Method == "POST" && turnstileResponse != "" && requestID != "" {
		s.logger.Info("Received turnstile response, attempting verification", "requestID", requestID)

		var verifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
		var client = &http.Client{Timeout: 10 * time.Second}
		var resp, err = client.PostForm(verifyURL, url.Values{"secret": {s.secretKey}, "response": {turnstileResponse}})
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

		if verifyResp.Success {
			s.logger.Info("Turnstile verification successful")
			s.issueTokenAndReplay(c, requestID)
		} else {
			s.logger.Warn("Turnstile verification failed", "error-codes", verifyResp.ErrorCodes)
			c.HTML(http.StatusUnauthorized, "failed.go.html", nil)
		}
		return
	}

	// This is a new request, cache it and serve the challenge
	var newRequestID = requestid.New()
	var body, readErr = io.ReadAll(c.Request.Body)
	if readErr != nil {
		s.logger.Error("Could not read original request body", "error", readErr)
		c.String(http.StatusInternalServerError, "Could not buffer request")
		return
	}
	var cachedReq = &cachedRequest{
		Method:  c.Request.Method,
		Body:    body,
		Headers: c.Request.Header,
		URL:     c.Request.URL,
	}
	s.requestCache.Set(newRequestID, cachedReq, cache.DefaultExpiration)
	s.logger.Info("No/invalid JWT, serving challenge", "requestID", newRequestID)
	c.HTML(http.StatusOK, "challenge.go.html", gin.H{
		"SiteKey":    s.siteKey,
		"RequestID":  newRequestID,
		"PostAction": c.Request.URL.Path,
	})
}

func (s *Server) replayRequest(c *gin.Context, req *http.Request) {
	var director = func(req *http.Request) {
		req.URL.Scheme = s.proxyTarget.Scheme
		req.URL.Host = s.proxyTarget.Host
		req.Host = s.proxyTarget.Host
	}
	var proxy = &httputil.ReverseProxy{Director: director}
	proxy.ServeHTTP(c.Writer, req)
}

func (s *Server) issueTokenAndReplay(c *gin.Context, requestID string) {
	var claims = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "tps",
		"aud": "caddy",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
		"nbf": time.Now().Unix(),
	})

	var tokenString, err = claims.SignedString(s.jwtSigningKey)
	if err != nil {
		s.logger.Error("Failed to sign JWT", "error", err)
		c.String(http.StatusInternalServerError, "Failed to create session")
		return
	}

	c.SetCookie(cookieName, tokenString, 3600*24, "/", "", true, true)

	var cachedReqInterface, ok = s.requestCache.Get(requestID)
	if !ok {
		s.logger.Error("Could not find cached request", "requestID", requestID)
		c.String(http.StatusInternalServerError, "Could not find original request")
		return
	}

	var cachedReq = cachedReqInterface.(*cachedRequest)

	var req, reqErr = http.NewRequest(cachedReq.Method, cachedReq.URL.String(), bytes.NewReader(cachedReq.Body))
	if reqErr != nil {
		s.logger.Error("Could not create new request from cached", "requestID", requestID, "error", reqErr)
		c.String(http.StatusInternalServerError, "Could not replay original request")
		return
	}
	req.Header = cachedReq.Headers
	s.replayRequest(c, req)
}
