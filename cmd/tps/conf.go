package main

import (
	"os"
	"strings"
)

func getenv() {
	bindAddr = os.Getenv("BIND_ADDR")
	turnstileSecretKey = os.Getenv("TURNSTILE_SECRET_KEY")
	turnstileSiteKey = os.Getenv("TURNSTILE_SITE_KEY")
	jwtSigningKey = os.Getenv("JWT_SIGNING_KEY")
	proxyTarget = os.Getenv("PROXY_TARGET")
	databaseDSN = os.Getenv("DATABASE_DSN")

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
	if len(errs) != 0 {
		logger.Error("Cannot start server", "error", strings.Join(errs, "; "))
		os.Exit(1)
	}
}
