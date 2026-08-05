package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		{name: "path and query", input: "http://h/p?q=1"},
		{name: "no scheme", input: "app:8080", wantErr: "must include scheme and host"},
		{name: "no host", input: "http://", wantErr: "must include scheme and host"},
		{name: "bare host", input: "app.example.edu", wantErr: "must include scheme and host"},
		{name: "unparseable", input: "http://[::1", wantErr: "invalid URL"},
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
