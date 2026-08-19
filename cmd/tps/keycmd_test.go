package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseRateSpec(t *testing.T) {
	tests := []struct {
		spec    string
		want    float64
		wantErr bool
	}{
		{"1/2s", 0.5, false},
		{"10/s", 10, false},
		{"30/m", 0.5, false},
		{"1/s", 1, false},
		{"120/h", 120.0 / 3600, false},
		{"2/500ms", 4, false},
		{"", 0, true},
		{"10", 0, true},        // no duration
		{"/s", 0, true},        // no count
		{"0/s", 0, true},       // zero requests
		{"-1/s", 0, true},      // negative requests
		{"1/0s", 0, true},      // zero duration
		{"1/-2s", 0, true},     // negative duration
		{"1/bananas", 0, true}, // unparseable duration
		{"1.5/s", 0, true},     // whole requests only
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			var got, err = parseRateSpec(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseRateSpec(%q) = %v, want error", tc.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRateSpec(%q): %v", tc.spec, err)
			}
			if got != tc.want {
				t.Errorf("parseRateSpec(%q) = %v, want %v", tc.spec, got, tc.want)
			}
		})
	}
}

func TestFormatRate(t *testing.T) {
	tests := []struct {
		perSec float64
		want   string
	}{
		{10, "10/s"},
		{1, "1/s"},
		{0.5, "1/2s"},
		{1.0 / 3, "1/3s"},
	}
	for _, tc := range tests {
		if got := formatRate(tc.perSec); got != tc.want {
			t.Errorf("formatRate(%v) = %q, want %q", tc.perSec, got, tc.want)
		}
	}
}

func TestParseExpirySpec(t *testing.T) {
	var now = time.Date(2026, 8, 11, 10, 0, 0, 0, time.UTC)

	// A date means through the end of that day: the operator who types a date
	// expects the key to work on it.
	var got, err = parseExpirySpec("2027-02-01", now)
	if err != nil {
		t.Fatalf("parseExpirySpec(date): %v", err)
	}
	if want := time.Date(2027, 2, 2, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("date expiry = %v, want %v", got, want)
	}

	got, err = parseExpirySpec("48h", now)
	if err != nil {
		t.Fatalf("parseExpirySpec(duration): %v", err)
	}
	if want := now.Add(48 * time.Hour); !got.Equal(want) {
		t.Errorf("duration expiry = %v, want %v", got, want)
	}

	for _, bad := range []string{"", "yesterday", "-48h", "0s", "2027-13-45"} {
		if _, err = parseExpirySpec(bad, now); err == nil {
			t.Errorf("parseExpirySpec(%q) succeeded, want error", bad)
		}
	}
}

func TestParseCIDRSpec(t *testing.T) {
	var got, err = parseCIDRSpec("any")
	if err != nil || got != nil {
		t.Errorf(`parseCIDRSpec("any") = %v, %v; want nil, nil`, got, err)
	}

	got, err = parseCIDRSpec("203.0.113.0/24, 198.51.100.7, 2001:db8::/32")
	if err != nil {
		t.Fatalf("parseCIDRSpec: %v", err)
	}
	var want = []string{"203.0.113.0/24", "198.51.100.7/32", "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("parseCIDRSpec = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cidr[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Non-canonical CIDRs are stored masked, so list output and the server's
	// parse agree about what the restriction is
	if got, err = parseCIDRSpec("203.0.113.99/24"); err != nil || got[0] != "203.0.113.0/24" {
		t.Errorf("parseCIDRSpec(unmasked) = %v, %v; want [203.0.113.0/24]", got, err)
	}

	for _, bad := range []string{"", "203.0.113.0/33", "not-a-network", ","} {
		if _, err = parseCIDRSpec(bad); err == nil {
			t.Errorf("parseCIDRSpec(%q) succeeded, want error", bad)
		}
	}
}

func TestNewKeySecret(t *testing.T) {
	var a, b = newKeySecret(), newKeySecret()
	if !strings.HasPrefix(a, bypassKeyPrefix) {
		t.Errorf("key %q lacks the %q prefix", a, bypassKeyPrefix)
	}
	if len(a) != len(bypassKeyPrefix)+48 {
		t.Errorf("key length = %d, want %d", len(a), len(bypassKeyPrefix)+48)
	}
	if a == b {
		t.Error("two generated keys are identical")
	}
}

func TestSecondsToUTCMidnight(t *testing.T) {
	var now = time.Date(2026, 8, 11, 23, 59, 30, 0, time.UTC)
	if got := secondsToUTCMidnight(now); got != 30 {
		t.Errorf("secondsToUTCMidnight(23:59:30) = %d, want 30", got)
	}
	var early = time.Date(2026, 8, 11, 0, 0, 1, 0, time.UTC)
	if got := secondsToUTCMidnight(early); got != 86399 {
		t.Errorf("secondsToUTCMidnight(00:00:01) = %d, want 86399", got)
	}
}
