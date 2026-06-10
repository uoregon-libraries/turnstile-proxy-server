package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func getenv() {
	bindAddr = os.Getenv("BIND_ADDR")
	turnstileSecretKey = os.Getenv("TURNSTILE_SECRET_KEY")
	turnstileSiteKey = os.Getenv("TURNSTILE_SITE_KEY")
	jwtSigningKey = os.Getenv("JWT_SIGNING_KEY")
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

	var rawTargets = os.Getenv("PROXY_TARGETS")
	var legacyTarget = os.Getenv("PROXY_TARGET")
	switch {
	case rawTargets != "":
		var routes, err = parseProxyTargets(rawTargets)
		if err != nil {
			errs = append(errs, "PROXY_TARGETS: "+err.Error())
		} else {
			proxyTargets = routes
		}
		if legacyTarget != "" {
			logger.Warn("Both PROXY_TARGETS and PROXY_TARGET are set; PROXY_TARGET is ignored")
		}
	case legacyTarget != "":
		proxyTargets = []proxyRoute{{Prefix: "/", Target: legacyTarget}}
	default:
		errs = append(errs, "neither PROXY_TARGETS nor PROXY_TARGET is set")
	}

	tokenLifetime = 4 * time.Hour
	if raw := os.Getenv("TOKEN_LIFETIME"); raw != "" {
		var d, derr = time.ParseDuration(raw)
		if derr != nil || d <= 0 {
			errs = append(errs, fmt.Sprintf("TOKEN_LIFETIME %q must be a positive Go duration such as 30m or 2h", raw))
		} else {
			tokenLifetime = d
		}
	}

	tokenBindUserAgent = parseBoolEnv("TOKEN_BIND_USER_AGENT", true, &errs)
	tokenRequestBudget = parseIntEnv("TOKEN_REQUEST_BUDGET", 1000, 0, &errs)
	tokenIPSwitchCost = parseIntEnv("TOKEN_IP_SWITCH_COST", 10, 1, &errs)

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

// parseBoolEnv reads the named env var as a boolean, returning def when the
// var is unset. A value that won't parse appends to errs and returns def.
func parseBoolEnv(name string, def bool, errs *[]string) bool {
	var raw = os.Getenv(name)
	if raw == "" {
		return def
	}
	var b, err = strconv.ParseBool(raw)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("%s %q must be a boolean (true/false)", name, raw))
		return def
	}
	return b
}

// parseIntEnv reads the named env var as an integer no smaller than minVal,
// returning def when the var is unset. An invalid or out-of-range value
// appends to errs and returns def.
func parseIntEnv(name string, def, minVal int, errs *[]string) int {
	var raw = os.Getenv(name)
	if raw == "" {
		return def
	}
	var n, err = strconv.Atoi(raw)
	if err != nil || n < minVal {
		*errs = append(*errs, fmt.Sprintf("%s %q must be an integer no smaller than %d", name, raw, minVal))
		return def
	}
	return n
}

// parseProxyTargets parses the comma-separated "prefix=url[,prefix=url...]"
// format of the PROXY_TARGETS env var. Entries with whitespace around the
// commas or equals are tolerated. Each target URL must parse with a scheme
// and host. Duplicate prefixes are rejected.
func parseProxyTargets(raw string) ([]proxyRoute, error) {
	var entries = strings.Split(raw, ",")
	var routes = make([]proxyRoute, 0, len(entries))
	var seen = make(map[string]bool, len(entries))

	for i, entry := range entries {
		var trimmed = strings.TrimSpace(entry)
		if trimmed == "" {
			return nil, fmt.Errorf("entry %d is empty", i+1)
		}

		var rawPrefix, rawTarget, ok = strings.Cut(trimmed, "=")
		if !ok {
			return nil, fmt.Errorf("entry %d %q is missing '='", i+1, trimmed)
		}
		var prefix = strings.TrimSpace(rawPrefix)
		var target = strings.TrimSpace(rawTarget)
		if prefix == "" {
			return nil, fmt.Errorf("entry %d has an empty prefix", i+1)
		}
		if target == "" {
			return nil, fmt.Errorf("entry %d (prefix %q) has an empty target URL", i+1, prefix)
		}
		if seen[prefix] {
			return nil, fmt.Errorf("prefix %q is defined more than once", prefix)
		}

		var parsed, err = url.Parse(target)
		if err != nil {
			return nil, fmt.Errorf("entry %d (prefix %q): invalid target URL %q: %s", i+1, prefix, target, err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("entry %d (prefix %q): target URL %q must include scheme and host", i+1, prefix, target)
		}

		seen[prefix] = true
		routes = append(routes, proxyRoute{Prefix: prefix, Target: target})
	}

	return routes, nil
}
