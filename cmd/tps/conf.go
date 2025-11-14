package main

import (
	"os"
	"path/filepath"
	"strings"
)

func getenv() {
	bindAddr = os.Getenv("BIND_ADDR")
	turnstileSecretKey = os.Getenv("TURNSTILE_SECRET_KEY")
	turnstileSiteKey = os.Getenv("TURNSTILE_SITE_KEY")
	jwtSigningKey = os.Getenv("JWT_SIGNING_KEY")
	proxyTarget = os.Getenv("PROXY_TARGET")
	databaseDSN = os.Getenv("DATABASE_DSN")
	templatePath = os.Getenv("TEMPLATE_PATH")

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
	if proxyTarget == "" {
		errs = append(errs, "PROXY_TARGET is not set")
	}
	if databaseDSN == "" {
		errs = append(errs, "DATABASE_DSN is not set")
	}
	if templatePath == "" {
		templatePath = "/var/local/tps/templates"
	}

	var err error
	templatePath, err = filepath.Abs(templatePath)
	if err != nil {
		errs = append(errs, "Unable to get absolute path to templates: "+err.Error())
	}

	if len(errs) != 0 {
		logger.Error("Cannot start server", "error", strings.Join(errs, "; "))
		os.Exit(1)
	}
}
