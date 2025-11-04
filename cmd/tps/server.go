package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	cookieName = "tps-jwt"
)

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
}

// NewServer creates and configures a new Server instance
func NewServer(router *gin.Engine, siteKey string, secretKey string, jwtSigningKey string, logger *slog.Logger) *Server {
	var s = &Server{
		r:             router,
		siteKey:       siteKey,
		secretKey:     secretKey,
		jwtSigningKey: []byte(jwtSigningKey),
		logger:        logger,
	}

	s.r.GET("/challenge", s.handleChallengePage)
	s.r.POST("/verify", s.handleVerify)
	s.r.GET("/validate", s.handleValidate)

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

// handleChallengePage serves the HTML page with the Turnstile widget.
func (s *Server) handleChallengePage(c *gin.Context) {
	var redirectTo = c.Query("redirect_to")
	if redirectTo == "" {
		s.logger.Error("redirect_to query parameter is missing on challenge page request")
		c.String(http.StatusBadRequest, "Cannot determine redirect destination after challenge.")
		return
	}
	c.HTML(http.StatusOK, "challenge.go.html", gin.H{
		"SiteKey":     s.siteKey,
		"RedirectURL": redirectTo,
	})
}

// handleVerify contacts the Cloudflare API to verify the Turnstile token.
func (s *Server) handleVerify(c *gin.Context) {
	var token = c.PostForm("cf-turnstile-response")
	var redirectTo = c.PostForm("redirect_to")

	if token == "" {
		s.logger.Warn("Missing cf-turnstile-response token in form submission")
		c.String(http.StatusBadRequest, "The cf-turnstile-response field is missing.")
		return
	}
	if redirectTo == "" {
		s.logger.Warn("Missing redirect_to in form submission")
		c.String(http.StatusBadRequest, "Missing redirect_to in form submission")
		return
	}

	var verifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	var client = &http.Client{Timeout: 10 * time.Second}
	var resp, err = client.PostForm(verifyURL, url.Values{"secret": {s.secretKey}, "response": {token}})
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
		s.issueToken(c, redirectTo)
	} else {
		s.logger.Warn("Turnstile verification failed", "error-codes", verifyResp.ErrorCodes)
		c.HTML(http.StatusUnauthorized, "failed.go.html", nil)
	}
}

// handleValidate is the endpoint Caddy will use for `forward_auth`. It checks
// for a valid session cookie. If the cookie is valid, it returns 200 OK.
// Otherwise, it redirects the user to the challenge page.
func (s *Server) handleValidate(c *gin.Context) {
	var cookie, err = c.Cookie(cookieName)
	if err != nil {
		s.logger.Info("No JWT cookie found, redirecting to challenge")
		s.redirectToChallenge(c)
		return
	}

	var _, parseErr = jwt.Parse(cookie, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSigningKey, nil
	})

	if parseErr != nil {
		s.logger.Warn("Failed to parse JWT, redirecting to challenge", "error", parseErr)
		s.redirectToChallenge(c)
		return
	}

	s.logger.Info("JWT is valid")
	c.String(http.StatusOK, "OK")
}

func (s *Server) redirectToChallenge(c *gin.Context) {
	var originalURI = c.GetHeader("X-Forwarded-URI")
	if originalURI == "" {
		s.logger.Error("X-Forwarded-URI header is missing, cannot redirect to challenge")
		c.String(http.StatusBadRequest, "Cannot determine original destination.")
		c.Abort()
		return
	}
	var redirectURL = fmt.Sprintf("/challenge?redirect_to=%s", url.QueryEscape(originalURI))
	c.Redirect(http.StatusFound, redirectURL)
}

func (s *Server) issueToken(c *gin.Context, redirectTo string) {
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
	c.Redirect(http.StatusFound, redirectTo)
}
