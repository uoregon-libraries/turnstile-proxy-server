package main

import (
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
