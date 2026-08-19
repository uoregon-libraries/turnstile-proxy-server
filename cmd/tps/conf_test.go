package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseBoolEnv(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		def     bool
		want    bool
		wantErr bool
	}{
		{"unset returns default", "", true, true, false},
		{"explicit false", "false", true, false, false},
		{"explicit true", "1", false, true, false},
		{"garbage errors and returns default", "yep", true, true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value != "" {
				t.Setenv("TPS_TEST_BOOL", tc.value)
			}
			var errs []string
			got := parseBoolEnv("TPS_TEST_BOOL", tc.def, &errs)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
			if (len(errs) > 0) != tc.wantErr {
				t.Errorf("errs = %v, wantErr = %v", errs, tc.wantErr)
			}
		})
	}
}

func TestParseIntEnv(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		def     int
		min     int
		want    int
		wantErr bool
	}{
		{"unset returns default", "", 1000, 0, 1000, false},
		{"valid value", "250", 1000, 0, 250, false},
		{"zero allowed when min is zero", "0", 1000, 0, 0, false},
		{"below min errors", "0", 10, 1, 10, true},
		{"negative errors", "-5", 1000, 0, 1000, true},
		{"garbage errors", "lots", 1000, 0, 1000, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value != "" {
				t.Setenv("TPS_TEST_INT", tc.value)
			}
			var errs []string
			got := parseIntEnv("TPS_TEST_INT", tc.def, tc.min, &errs)
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
			if (len(errs) > 0) != tc.wantErr {
				t.Errorf("errs = %v, wantErr = %v", errs, tc.wantErr)
			}
		})
	}
}

func TestRedactSecret(t *testing.T) {
	if got := redactSecret("hunter2"); strings.Contains(got, "hunter2") {
		t.Errorf("redactSecret leaked the value: %q", got)
	}
	if got, want := redactSecret(""), "[unset]"; got != want {
		t.Errorf("redactSecret(%q) = %q, want %q", "", got, want)
	}
}

func TestLogValue(t *testing.T) {
	tests := []struct {
		key      string
		val      string
		wantSame bool
	}{
		{key: "BIND_ADDR", val: ":8080", wantSame: true},
		{key: "TURNSTILE_SITE_KEY", val: "public-and-fine", wantSame: true},
		{key: "JWT_SIGNING_KEY", val: "shhhh"},
		{key: "TURNSTILE_SECRET_KEY", val: "shhhh"},
	}

	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			var got = logValue(tc.key, tc.val)
			switch {
			case tc.wantSame && got != tc.val:
				t.Errorf("logValue(%q, %q) = %q, want the value unchanged", tc.key, tc.val, got)
			case !tc.wantSame && strings.Contains(got, tc.val):
				t.Errorf("logValue(%q, ...) = %q, which leaks the secret", tc.key, got)
			}
		})
	}
}

// TestLoadEnvFileRedactsSecrets covers the whole path rather than just
// logValue: the leak was in what loadEnvFile chose to log, so the test watches
// the log itself.
func TestLoadEnvFileRedactsSecrets(t *testing.T) {
	var path = filepath.Join(t.TempDir(), "env")
	var contents = strings.Join([]string{
		`BIND_ADDR=:9999`,
		`JWT_SIGNING_KEY="jwt-secret-value"`,
		`TURNSTILE_SECRET_KEY='turnstile-secret-value'`,
	}, "\n")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("writing env file: %s", err)
	}

	// loadEnvFile only sets vars that aren't already in the environment, so
	// clear them for this test; t.Setenv restores them afterwards
	for _, key := range []string{"BIND_ADDR", "JWT_SIGNING_KEY", "TURNSTILE_SECRET_KEY"} {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}

	var buf bytes.Buffer
	var saved = logger
	logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	defer func() { logger = saved }()

	if err := loadEnvFile(path); err != nil {
		t.Fatalf("loadEnvFile: %s", err)
	}

	// The values still have to reach the environment; only the log is censored
	if got := os.Getenv("JWT_SIGNING_KEY"); got != "jwt-secret-value" {
		t.Errorf("JWT_SIGNING_KEY = %q, want the value from the file", got)
	}

	var logged = buf.String()
	for _, secret := range []string{"jwt-secret-value", "turnstile-secret-value"} {
		if strings.Contains(logged, secret) {
			t.Errorf("log contains the secret %q:\n%s", secret, logged)
		}
	}
	if !strings.Contains(logged, ":9999") {
		t.Errorf("log dropped the non-secret BIND_ADDR value:\n%s", logged)
	}
}

func TestValidateTargetURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "host and port", input: "http://app:8080"},
		{name: "https", input: "https://app.example.edu"},
		{name: "bare trailing slash is the same target", input: "http://app:8080/"},
		{name: "no scheme", input: "app:8080", wantErr: "must include scheme and host"},
		{name: "no host", input: "http://", wantErr: "must include scheme and host"},
		{name: "bare host", input: "app.example.edu", wantErr: "must include scheme and host"},
		{name: "unparseable", input: "http://[::1", wantErr: "invalid URL"},

		// Everything past the host is dropped when the request is forwarded, so
		// it's refused rather than silently ignored
		{name: "path", input: "http://app:8080/base", wantErr: "a path"},
		{name: "path with trailing slash", input: "http://app:8080/base/", wantErr: "a path"},
		{name: "query", input: "http://h/?q=1", wantErr: "a query string"},
		{name: "fragment", input: "http://h/#frag", wantErr: "a fragment"},
		{name: "credentials", input: "http://user:pw@h", wantErr: "credentials"},
		{name: "path and query together", input: "http://h/p?q=1", wantErr: "a path and a query string"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTargetURL(tc.input)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr == "":
				return
			case err == nil:
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateChallengeLimits(t *testing.T) {
	tests := []struct {
		name    string
		body    int64
		total   int64
		wantErr bool
	}{
		{name: "the defaults agree", body: defaultMaxChallengeBody, total: defaultMaxChallengeCache},
		{name: "room for exactly one largest request", body: 1000, total: 1000 + cachedRequestOverhead},
		{name: "no room for the per-entry overhead", body: 1000, total: 1000, wantErr: true},
		{name: "total below body", body: 1 << 20, total: 1 << 10, wantErr: true},
		{name: "bodyless still needs overhead", body: 0, total: 0, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateChallengeLimits(tc.body, tc.total)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateChallengeLimits(%d, %d) = %v, wantErr = %v",
					tc.body, tc.total, err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "MAX_CHALLENGE_CACHE") {
				t.Errorf("error %q doesn't name the setting to change", err)
			}
		})
	}
}

// configEnvVars is every variable getenv reads, so a test can put the whole
// environment in a known state instead of inheriting whatever the developer
// running it happens to have exported.
var configEnvVars = []string{
	"BIND_ADDR", "TURNSTILE_SECRET_KEY", "TURNSTILE_SITE_KEY", "JWT_SIGNING_KEY",
	"PROXY_TARGET", "DB_PATH", "LOG_DB_PATH", "LOG_RETENTION", "TEMPLATE_PATH", "TOKEN_LIFETIME",
	"TOKEN_BIND_USER_AGENT", "TOKEN_REQUEST_BUDGET", "TOKEN_IP_SWITCH_COST",
	"MAX_CHALLENGE_BODY", "MAX_CHALLENGE_CACHE", "ADMIN_SECRET",
	"PROXY_TARGETS", "CHALLENGE_MODE",
}

// setConfigEnv sets the named variables and explicitly clears every other one
// getenv looks at. t.Setenv restores the lot afterwards.
func setConfigEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	for _, name := range configEnvVars {
		if val, ok := vars[name]; ok {
			t.Setenv(name, val)
			continue
		}
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
}

// requiredEnv is the smallest configuration that starts: everything TPS
// refuses to run without, and nothing else.
func requiredEnv() map[string]string {
	return map[string]string{
		"BIND_ADDR":            ":8080",
		"TURNSTILE_SECRET_KEY": "turnstile-secret",
		"TURNSTILE_SITE_KEY":   "turnstile-site",
		"JWT_SIGNING_KEY":      "signing-key",
		"PROXY_TARGET":         "http://app:8080",
	}
}

func TestGetenv(t *testing.T) {
	t.Run("an unset optional setting takes its default", func(t *testing.T) {
		setConfigEnv(t, requiredEnv())

		conf, errs := getenv()
		if len(errs) != 0 {
			t.Fatalf("a complete configuration reported errors: %v", errs)
		}

		if conf.tokenLifetime != 4*time.Hour {
			t.Errorf("tokenLifetime = %s, want 4h", conf.tokenLifetime)
		}
		if conf.logRetention != 48*time.Hour {
			t.Errorf("logRetention = %s, want 48h", conf.logRetention)
		}
		if !conf.tokenBindUserAgent {
			t.Error("tokenBindUserAgent = false, want true")
		}
		if conf.tokenRequestBudget != 1000 {
			t.Errorf("tokenRequestBudget = %d, want 1000", conf.tokenRequestBudget)
		}
		if conf.tokenIPSwitchCost != 10 {
			t.Errorf("tokenIPSwitchCost = %d, want 10", conf.tokenIPSwitchCost)
		}
		if conf.maxChallengeBody != defaultMaxChallengeBody {
			t.Errorf("maxChallengeBody = %d, want %d", conf.maxChallengeBody, defaultMaxChallengeBody)
		}
		if conf.maxChallengeCache != defaultMaxChallengeCache {
			t.Errorf("maxChallengeCache = %d, want %d", conf.maxChallengeCache, defaultMaxChallengeCache)
		}
		if conf.templatePath != "/var/local/tps/templates" {
			t.Errorf("templatePath = %q, want the default", conf.templatePath)
		}
		// Unset means the feature is off, not that it's misconfigured
		if conf.dbPath != "" || conf.adminSecret != "" {
			t.Errorf("dbPath = %q and adminSecret = %q, want both empty", conf.dbPath, conf.adminSecret)
		}
	})

	t.Run("every setting is read from the environment", func(t *testing.T) {
		var env = requiredEnv()
		env["DB_PATH"] = "/var/lib/tps/events.db"
		env["LOG_RETENTION"] = "72h"
		env["TEMPLATE_PATH"] = "/srv/templates"
		env["TOKEN_LIFETIME"] = "30m"
		env["TOKEN_BIND_USER_AGENT"] = "false"
		env["TOKEN_REQUEST_BUDGET"] = "50"
		env["TOKEN_IP_SWITCH_COST"] = "3"
		env["MAX_CHALLENGE_BODY"] = "2048"
		env["MAX_CHALLENGE_CACHE"] = "1048576"
		env["ADMIN_SECRET"] = "admin-secret"
		setConfigEnv(t, env)

		conf, errs := getenv()
		if len(errs) != 0 {
			t.Fatalf("a complete configuration reported errors: %v", errs)
		}

		var got = config{
			bindAddr: conf.bindAddr, turnstileSecretKey: conf.turnstileSecretKey,
			turnstileSiteKey: conf.turnstileSiteKey, jwtSigningKey: conf.jwtSigningKey,
			proxyTarget: conf.proxyTarget, dbPath: conf.dbPath,
			logRetention: conf.logRetention, templatePath: conf.templatePath,
			tokenLifetime: conf.tokenLifetime, tokenBindUserAgent: conf.tokenBindUserAgent,
			tokenRequestBudget: conf.tokenRequestBudget, tokenIPSwitchCost: conf.tokenIPSwitchCost,
			maxChallengeBody: conf.maxChallengeBody, maxChallengeCache: conf.maxChallengeCache,
			adminSecret: conf.adminSecret,
		}
		var want = config{
			bindAddr: ":8080", turnstileSecretKey: "turnstile-secret",
			turnstileSiteKey: "turnstile-site", jwtSigningKey: "signing-key",
			proxyTarget: "http://app:8080", dbPath: "/var/lib/tps/events.db",
			logRetention: 72 * time.Hour, templatePath: "/srv/templates",
			tokenLifetime: 30 * time.Minute, tokenBindUserAgent: false,
			tokenRequestBudget: 50, tokenIPSwitchCost: 3,
			maxChallengeBody: 2048, maxChallengeCache: 1048576,
			adminSecret: "admin-secret",
		}
		if got != want {
			t.Errorf("config =\n%+v\nwant\n%+v", got, want)
		}
	})

	t.Run("the deprecated LOG_DB_PATH still works, with a warning", func(t *testing.T) {
		var env = requiredEnv()
		env["LOG_DB_PATH"] = "/var/lib/tps/events.db"
		setConfigEnv(t, env)

		var buf bytes.Buffer
		var saved = logger
		logger = slog.New(slog.NewTextHandler(&buf, nil))
		defer func() { logger = saved }()

		conf, errs := getenv()
		if len(errs) != 0 {
			t.Fatalf("the deprecated name reported errors: %v", errs)
		}
		if conf.dbPath != "/var/lib/tps/events.db" {
			t.Errorf("dbPath = %q, want the LOG_DB_PATH value", conf.dbPath)
		}
		var logged = buf.String()
		if !strings.Contains(logged, "deprecated") || !strings.Contains(logged, "DB_PATH") {
			t.Errorf("log doesn't warn about the deprecation and name the replacement:\n%s", logged)
		}
	})

	t.Run("DB_PATH and LOG_DB_PATH agreeing is only a warning", func(t *testing.T) {
		var env = requiredEnv()
		env["DB_PATH"] = "/var/lib/tps/events.db"
		env["LOG_DB_PATH"] = "/var/lib/tps/events.db"
		setConfigEnv(t, env)

		var saved = logger
		logger = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
		defer func() { logger = saved }()

		conf, errs := getenv()
		if len(errs) != 0 {
			t.Fatalf("agreeing names reported errors: %v", errs)
		}
		if conf.dbPath != "/var/lib/tps/events.db" {
			t.Errorf("dbPath = %q, want the shared value", conf.dbPath)
		}
	})

	t.Run("DB_PATH and LOG_DB_PATH disagreeing is an error", func(t *testing.T) {
		var env = requiredEnv()
		env["DB_PATH"] = "/new/tps.db"
		env["LOG_DB_PATH"] = "/old/tps.db"
		setConfigEnv(t, env)

		var saved = logger
		logger = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
		defer func() { logger = saved }()

		_, errs := getenv()
		var found bool
		for _, e := range errs {
			if strings.Contains(e, "DB_PATH") && strings.Contains(e, "LOG_DB_PATH") {
				found = true
			}
		}
		if !found {
			t.Errorf("errs = %v, want one naming both DB_PATH and LOG_DB_PATH", errs)
		}
	})

	t.Run("a relative template path is made absolute", func(t *testing.T) {
		var env = requiredEnv()
		env["TEMPLATE_PATH"] = "templates"
		setConfigEnv(t, env)

		conf, _ := getenv()
		if !filepath.IsAbs(conf.templatePath) {
			t.Errorf("templatePath = %q, want an absolute path", conf.templatePath)
		}
	})

	// Zero means different things to the two duration settings, which is the
	// distinction a shared parser is most likely to flatten
	t.Run("zero retention keeps events forever", func(t *testing.T) {
		var env = requiredEnv()
		env["LOG_RETENTION"] = "0"
		setConfigEnv(t, env)

		conf, errs := getenv()
		if len(errs) != 0 {
			t.Fatalf("LOG_RETENTION=0 reported errors: %v", errs)
		}
		if conf.logRetention != 0 {
			t.Errorf("logRetention = %s, want 0", conf.logRetention)
		}
	})

	t.Run("zero token lifetime is refused", func(t *testing.T) {
		var env = requiredEnv()
		env["TOKEN_LIFETIME"] = "0"
		setConfigEnv(t, env)

		conf, errs := getenv()
		if len(errs) != 1 || !strings.Contains(errs[0], "TOKEN_LIFETIME") {
			t.Fatalf("errs = %v, want one complaint about TOKEN_LIFETIME", errs)
		}
		if conf.tokenLifetime != 4*time.Hour {
			t.Errorf("tokenLifetime = %s, want the default to stand", conf.tokenLifetime)
		}
	})

	t.Run("every missing requirement is reported at once", func(t *testing.T) {
		setConfigEnv(t, nil)

		var _, errs = getenv()
		for _, want := range []string{
			"BIND_ADDR", "TURNSTILE_SECRET_KEY", "TURNSTILE_SITE_KEY",
			"JWT_SIGNING_KEY", "PROXY_TARGET",
		} {
			if !strings.Contains(strings.Join(errs, "; "), want) {
				t.Errorf("errs %v does not mention %s", errs, want)
			}
		}
	})

	t.Run("a bad proxy target is reported as one", func(t *testing.T) {
		var env = requiredEnv()
		env["PROXY_TARGET"] = "http://app:8080/base"
		setConfigEnv(t, env)

		var _, errs = getenv()
		if len(errs) != 1 || !strings.HasPrefix(errs[0], "PROXY_TARGET: ") {
			t.Fatalf("errs = %v, want one PROXY_TARGET complaint", errs)
		}
	})

	t.Run("a removed variable still set stops startup", func(t *testing.T) {
		var env = requiredEnv()
		env["CHALLENGE_MODE"] = "navigation"
		setConfigEnv(t, env)

		var _, errs = getenv()
		if len(errs) != 1 || !strings.Contains(errs[0], "CHALLENGE_MODE") {
			t.Fatalf("errs = %v, want one CHALLENGE_MODE complaint", errs)
		}
	})
}

func TestRemovedVarErrors(t *testing.T) {
	t.Run("nothing set", func(t *testing.T) {
		if errs := removedVarErrors(); len(errs) != 0 {
			t.Errorf("got %v, want no errors", errs)
		}
	})

	t.Run("empty value is not set", func(t *testing.T) {
		t.Setenv("PROXY_TARGETS", "")
		if errs := removedVarErrors(); len(errs) != 0 {
			t.Errorf("got %v, want no errors", errs)
		}
	})

	t.Run("each removed var reports once, with advice", func(t *testing.T) {
		t.Setenv("PROXY_TARGETS", "/protected/=http://app:8080")
		t.Setenv("CHALLENGE_MODE", "navigation")

		errs := removedVarErrors()
		if len(errs) != 2 {
			t.Fatalf("got %d errors, want 2: %v", len(errs), errs)
		}
		// Sorted, so CHALLENGE_MODE comes first
		if !strings.HasPrefix(errs[0], "CHALLENGE_MODE is no longer supported") {
			t.Errorf("first error = %q, want the CHALLENGE_MODE message", errs[0])
		}
		if !strings.HasPrefix(errs[1], "PROXY_TARGETS is no longer supported") {
			t.Errorf("second error = %q, want the PROXY_TARGETS message", errs[1])
		}
		for _, e := range errs {
			if !strings.Contains(e, "PROXY_TARGET") && !strings.Contains(e, "front proxy") {
				t.Errorf("error %q offers no migration advice", e)
			}
		}
	})
}
