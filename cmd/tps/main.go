// Package main is our Turnstile proxy server application's core code
package main

import (
	"log/slog"
	"os"
	"strings"
	"turnstile-proxy-server/internal/templates"

	"github.com/gin-gonic/gin"
	sloggin "github.com/samber/slog-gin"
)

func main() {
	var logger = slog.New(slog.NewTextHandler(os.Stdout, nil))

	var bindAddr = os.Getenv("BIND_ADDR")
	var turnstileSecretKey = os.Getenv("TURNSTILE_SECRET_KEY")
	var turnstileSiteKey = os.Getenv("TURNSTILE_SITE_KEY")
	var jwtSigningKey = os.Getenv("JWT_SIGNING_KEY")

	var errs []string
	if bindAddr == "" {
		errs = append(errs, "BIND_ADDR is not set")
	}
	if turnstileSecretKey == "" {
		errs = append(errs, "TURNSTILE_SECRET_KEY is not set")
	}
	if turnstileSiteKey == "" {
		errs = append(errs, "TURNSTILE_SITE_KEY is not set")
	}
	if jwtSigningKey == "" {
		errs = append(errs, "JWT_SIGNING_KEY is not set")
	}
	if len(errs) != 0 {
		logger.Error("Cannot start server", "error", strings.Join(errs, "; "))
		os.Exit(1)
	}

	var router = gin.New()
	var ginLog = logger.With("from", "gin server")
	router.Use(sloggin.New(ginLog))
	router.Use(gin.Recovery())

	var server = NewServer(router, turnstileSiteKey, turnstileSecretKey, jwtSigningKey, logger)
	server.loadTemplates("internal/templates/*.go.html", templates.FS)

	logger.Info("Starting TPS", "addr", bindAddr)
	var err = server.Run(bindAddr)
	if err != nil {
		logger.Error("Could not start server", "error", err)
		os.Exit(1)
	}
}
