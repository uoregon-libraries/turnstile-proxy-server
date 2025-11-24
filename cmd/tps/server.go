package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"turnstile-proxy-server/internal/db"
	"turnstile-proxy-server/internal/requestid"

	"github.com/gin-contrib/multitemplate"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
	"github.com/spf13/afero"
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
// presenting the turnstile challenge, verifying the challenge, and finally
// proxying successful requests
type Server struct {
	r             *gin.Engine
	render        multitemplate.Renderer
	logger        *slog.Logger
	db            *db.Store
	siteKey       string
	secretKey     string
	jwtSigningKey []byte
	requestCache  *cache.Cache
	proxyTarget   *url.URL
	templates     map[string]string
}

// NewServer creates and configures a new Server instance. You must manually
// set the proxy target and JWT signing keys. The Turnstile settings are
// pre-filled with test values for an "always pass" challenge, and the logger
// is set to [slog.Default]. Use the various SetX methods to
// change these settings.
func NewServer(router *gin.Engine, db *db.Store) *Server {
	var requestCache = cache.New(5*time.Minute, 10*time.Minute)

	var render = multitemplate.NewRenderer()

	router.HTMLRender = render
	var s = &Server{
		r:            router,
		db:           db,
		render:       render,
		logger:       slog.Default(),
		siteKey:      "1x00000000000000000000AA",
		secretKey:    "1x0000000000000000000000000000000AA",
		requestCache: requestCache,
		templates:    make(map[string]string),
	}
	s.r.Any("/*proxyPath", s.handleProxy)

	return s
}

// SetLogger sets the logger and returns s for chaining
func (s *Server) SetLogger(l *slog.Logger) *Server {
	s.logger = l
	return s
}

// SetSecretKey sets the turnstile secret key and returns s for chaining
func (s *Server) SetSecretKey(k string) *Server {
	s.secretKey = k
	return s
}

// SetSiteKey sets the turnstile site key and returns s for chaining
func (s *Server) SetSiteKey(k string) *Server {
	s.siteKey = k
	return s
}

// SetProxyTarget parses the given target URL and stores it. If there are any
// parse errors, this will panic, as the server can't function without a valid
// proxy target.
func (s *Server) SetProxyTarget(proxyTarget string) *Server {
	var parsedURL, err = url.Parse(proxyTarget)
	if err != nil {
		panic(fmt.Sprintf("invalid proxy target %q: %s", proxyTarget, err))
	}

	s.proxyTarget = parsedURL
	return s
}

// SetJWTSigningKey stores the given key for our tokens, which are used to tell
// if a user has already completed a challenge.
func (s *Server) SetJWTSigningKey(k string) *Server {
	s.jwtSigningKey = []byte(k)
	return s
}

// LoadCoreTemplates is a general-case helper to load either from local disk
// for hot-reloads, or from an embedded filesystem, depending on the gin mode
func (s *Server) LoadCoreTemplates(pattern string, fsys fs.FS) {
	var from string
	var af afero.Fs
	if gin.Mode() == gin.ReleaseMode {
		af = afero.FromIOFS{fsys}
		pattern = "*.go.html"
		from = "io/fs.FS"
	} else {
		af = afero.NewOsFs()
		from = "OS Filesystem"
	}

	var templates, err = afero.Glob(af, pattern)
	if err != nil {
		s.logger.Error("Cannot load core templates", "from", from, "pattern", pattern, "error", err)
		panic("Fatal error, cannot continue without templates")
	}

	for _, pth := range templates {
		if strings.HasSuffix(pth, ".go.html") {
			var name = "core/" + strings.Replace(filepath.Base(pth), ".go.html", "", 1)
			s.logger.Debug("Adding core template", "name", name, "path", pth)
			s.render.AddFromFS(name, afero.NewIOFS(af), pth)
			s.templates[name] = pth
		}
	}

	return
}

// LoadCustomTemplates finds all templates under the given path named
// "*.html.go" and registers them for use as custom templates for specific
// proxied URLs' challenge and failed pages.
func (s *Server) LoadCustomTemplates(templatePath string) {
	if templatePath == "" {
		return
	}

	var err = filepath.Walk(templatePath, func(pth string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return err
		}

		if strings.HasSuffix(pth, ".go.html") {
			var name = strings.Replace(pth, templatePath+"/", "", 1)
			name = strings.Replace(name, ".go.html", "", 1)
			s.logger.Debug("Adding custom template", "name", name, "path", pth)
			s.render.AddFromFiles(name, pth)
			s.templates[name] = pth
		}
		return err
	})
	if err != nil {
		s.logger.Error("Failed to load custom templates", "path", templatePath, "error", err)
	}
}

// Run starts the server listening on the configured address
func (s *Server) Run(addr string) error {
	if len(s.jwtSigningKey) == 0 {
		return errors.New("empty JWT signing key")
	}
	if s.proxyTarget == nil {
		return errors.New("empty proxy target")
	}
	s.r.HTMLRender = s.render
	return s.r.Run(addr)
}

func (s *Server) getTemplate(r *http.Request, shortname string) string {
	var host = r.URL.Hostname()
	var path = r.URL.Path

	// Clean the path to prevent directory traversal issues
	path = filepath.Clean(path)

	// Remove leading slash
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}

	var parts = strings.Split(path, "/")
	if len(parts) == 1 && parts[0] == "" {
		parts = []string{}
	}

	for i := len(parts); i >= 0; i-- {
		var source = host + "/" + strings.Join(parts[:i], "/")
		s.logger.Debug("Looking for template", "source", source, "shortname", shortname)
		var name = filepath.Join(source, shortname)
		var template = s.templates[name]
		if template != "" {
			s.logger.Debug("Found custom template", "name", name)
			return name
		}
	}

	s.logger.Debug("No custom template found, returning default")
	return "core/" + shortname
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
			s.db.LogRequest(db.RequestLog{
				ClientIP:      c.ClientIP(),
				Timestamp:     time.Now(),
				URL:           c.Request.URL.String(),
				HadValidToken: true,
			})
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
			s.db.LogRequest(db.RequestLog{
				ClientIP:              c.ClientIP(),
				Timestamp:             time.Now(),
				URL:                   c.Request.URL.String(),
				WasPresentedChallenge: true,
				ChallengeSucceeded:    true,
			})
			s.issueTokenAndReplay(c, requestID)
		} else {
			s.logger.Warn("Turnstile verification failed", "error-codes", verifyResp.ErrorCodes)
			s.db.LogRequest(db.RequestLog{
				ClientIP:              c.ClientIP(),
				Timestamp:             time.Now(),
				URL:                   c.Request.URL.String(),
				WasPresentedChallenge: true,
				ChallengeSucceeded:    false,
			})
			c.HTML(http.StatusUnauthorized, s.getTemplate(c.Request, "failed"), nil)
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
	c.HTML(http.StatusOK, s.getTemplate(c.Request, "challenge"), gin.H{
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
