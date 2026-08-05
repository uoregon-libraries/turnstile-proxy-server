package main

import (
	"bufio"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// loadEnvFile reads a simple KEY=VALUE ".env"-style file and sets any variables
// that aren't already present in the real environment, so actual env vars (e.g.
// from Docker or the shell) always win. A missing file is not an error: the
// file is a convenience for local development. Blank lines and "#" comments are
// ignored, an optional leading "export " is stripped, and values may be wrapped
// in single or double quotes.
func loadEnvFile(path string) error {
	var f, err = os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	var scanner = bufio.NewScanner(f)
	for line := 0; scanner.Scan(); line++ {
		var text = strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		text = strings.TrimPrefix(text, "export ")

		var key, val, ok = strings.Cut(text, "=")
		if !ok {
			return fmt.Errorf("%s line %d: missing '='", path, line+1)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}

		if _, set := os.LookupEnv(key); !set {
			logger.Info("Setting ENV value from file", "file", path, "key", key, "val", logValue(key, val))
			os.Setenv(key, val)
		}
	}
	return scanner.Err()
}

// sensitiveEnvVars are the settings whose values must never be written to the
// log. An env file is an ordinary way to configure TPS, and loadEnvFile
// announces everything it sets, so without this the signing key and the
// Turnstile secret land in the log in plaintext during a normal startup.
var sensitiveEnvVars = map[string]bool{
	"JWT_SIGNING_KEY":      true,
	"TURNSTILE_SECRET_KEY": true,
}

// logValue is what the named setting's value should look like in the log:
// itself, unless it's a secret.
func logValue(key, val string) string {
	if sensitiveEnvVars[key] {
		return redactSecret(val)
	}
	return val
}

// redactSecret stands in for a secret in log output. It still distinguishes an
// unset value from a set one, which is the only thing about a secret worth
// knowing from a log: a key that silently didn't make it into the environment
// is a real configuration bug, and hiding that would trade one debugging
// problem for another.
func redactSecret(val string) string {
	if val == "" {
		return "[unset]"
	}
	return "[redacted]"
}

// applyEnvFile loads the -env-file into the environment when one was given,
// exiting on an unreadable file. Call it before reading any config from the
// environment.
func applyEnvFile() {
	if envFile == "" {
		return
	}
	logger.Info("Overriding environment from file", "file", envFile)
	if err := loadEnvFile(envFile); err != nil {
		logger.Error("Cannot read env file", "path", envFile, "error", err)
		os.Exit(1)
	}
}

func getenv() {
	applyEnvFile()

	bindAddr = os.Getenv("BIND_ADDR")
	turnstileSecretKey = os.Getenv("TURNSTILE_SECRET_KEY")
	turnstileSiteKey = os.Getenv("TURNSTILE_SITE_KEY")
	jwtSigningKey = os.Getenv("JWT_SIGNING_KEY")
	logDBPath = os.Getenv("LOG_DB_PATH")
	templatePath = os.Getenv("TEMPLATE_PATH")
	adminSecret = os.Getenv("ADMIN_SECRET")

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

	proxyTarget = os.Getenv("PROXY_TARGET")
	if proxyTarget == "" {
		errs = append(errs, "PROXY_TARGET is not set")
	} else if err := validateTargetURL(proxyTarget); err != nil {
		errs = append(errs, "PROXY_TARGET: "+err.Error())
	}

	errs = append(errs, removedVarErrors()...)

	tokenLifetime = 4 * time.Hour
	if raw := os.Getenv("TOKEN_LIFETIME"); raw != "" {
		var d, derr = time.ParseDuration(raw)
		if derr != nil || d <= 0 {
			errs = append(errs, fmt.Sprintf("TOKEN_LIFETIME %q must be a positive Go duration such as 30m or 2h", raw))
		} else {
			tokenLifetime = d
		}
	}

	logRetention = 48 * time.Hour
	if raw := os.Getenv("LOG_RETENTION"); raw != "" {
		var d, derr = time.ParseDuration(raw)
		if derr != nil || d < 0 {
			errs = append(errs, fmt.Sprintf(`LOG_RETENTION %q must be a non-negative Go duration such as 48h, or 0 to keep events forever`, raw))
		} else {
			logRetention = d
		}
	}

	tokenBindUserAgent = parseBoolEnv("TOKEN_BIND_USER_AGENT", true, &errs)
	tokenRequestBudget = parseIntEnv("TOKEN_REQUEST_BUDGET", 1000, 0, &errs)
	tokenIPSwitchCost = parseIntEnv("TOKEN_IP_SWITCH_COST", 10, 1, &errs)

	maxChallengeBody = int64(parseIntEnv("MAX_CHALLENGE_BODY", defaultMaxChallengeBody, 0, &errs))
	maxChallengeCache = int64(parseIntEnv("MAX_CHALLENGE_CACHE", defaultMaxChallengeCache, 0, &errs))
	if cerr := validateChallengeLimits(maxChallengeBody, maxChallengeCache); cerr != nil {
		errs = append(errs, cerr.Error())
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

// validateTargetURL rejects a backend URL that can't be proxied to: it has to
// parse, it has to name a scheme and host, and it has to be *only* a scheme and
// host. TPS forwards each request's own path, query, and credentials to the
// backend unchanged; anything of that sort on the target itself is dropped on
// the floor. Accepting it would mean accepting a config that quietly does
// something other than what it says, so it's a startup error instead.
func validateTargetURL(target string) error {
	var parsed, err = url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %s", target, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("URL %q must include scheme and host, e.g. http://app:8080", target)
	}

	// A bare trailing slash is the same target with nothing added, so it's
	// allowed -- people write it out of habit and it costs nothing to honor
	var extra []string
	if parsed.EscapedPath() != "" && parsed.EscapedPath() != "/" {
		extra = append(extra, "a path")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		extra = append(extra, "a query string")
	}
	if parsed.Fragment != "" {
		extra = append(extra, "a fragment")
	}
	if parsed.User != nil {
		extra = append(extra, "credentials")
	}
	if len(extra) > 0 {
		return fmt.Errorf("URL %q must be only a scheme and host, but it also has %s. TPS "+
			"forwards each request's own path and query to the backend and ignores anything "+
			"extra here, so use %s://%s and have your front proxy rewrite the path if the "+
			"backend needs a prefix", target, strings.Join(extra, " and "), parsed.Scheme, parsed.Host)
	}
	return nil
}

// validateChallengeLimits rejects a pair of challenge memory limits that can't
// work together. The total has to fit at least one request of the largest
// permitted size plus its per-entry overhead, or a request TPS just told the
// client was acceptable would be shed by the cache a moment later — every
// time, for every client, no matter how idle the server is.
func validateChallengeLimits(body, total int64) error {
	if want := body + cachedRequestOverhead; total < want {
		return fmt.Errorf("MAX_CHALLENGE_CACHE (%d) is too small for MAX_CHALLENGE_BODY (%d): it must be "+
			"at least %d so one largest-allowed request fits, otherwise every request that size is refused",
			total, body, want)
	}
	return nil
}

// removedVars maps env vars that used to configure a feature to the advice for
// whoever still has them set. TPS refuses to start while one is present rather
// than quietly behaving differently than the config asks for.
var removedVars = map[string]string{
	"PROXY_TARGETS": "multiple backends are gone; set PROXY_TARGET to a single backend " +
		"and let your front proxy route paths to the right place (see the README)",
	"CHALLENGE_MODE": "navigation-only challenging is gone; keep non-navigation requests " +
		"away from TPS in your front proxy instead (see the README)",
}

// removedVarErrors returns one error string per removed variable still set in
// the environment. A variable set to the empty string doesn't count: that's
// indistinguishable from unset, and nothing is being asked for.
func removedVarErrors() []string {
	var errs []string
	// Sorted so a config with several removed vars reports them the same way
	// every run
	var names = slices.Sorted(maps.Keys(removedVars))
	for _, name := range names {
		if os.Getenv(name) != "" {
			errs = append(errs, fmt.Sprintf("%s is no longer supported: %s", name, removedVars[name]))
		}
	}
	return errs
}
