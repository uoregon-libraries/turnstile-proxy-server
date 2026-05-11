package main

import (
	"strings"
	"testing"
)

func TestParseProxyTargets(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []proxyRoute
		wantErr string
	}{
		{
			name:  "single entry",
			input: "/=http://app:8080",
			want:  []proxyRoute{{Prefix: "/", Target: "http://app:8080"}},
		},
		{
			name:  "multiple entries",
			input: "/protected/=http://app:8080,/static-protected/=http://caddy:8081",
			want: []proxyRoute{
				{Prefix: "/protected/", Target: "http://app:8080"},
				{Prefix: "/static-protected/", Target: "http://caddy:8081"},
			},
		},
		{
			name:  "whitespace around separators is tolerated",
			input: "  /a/ = http://a:1 ,  /b/ = http://b:2  ",
			want: []proxyRoute{
				{Prefix: "/a/", Target: "http://a:1"},
				{Prefix: "/b/", Target: "http://b:2"},
			},
		},
		{
			name:  "target may contain query strings",
			input: "/x=http://h/p?q=1",
			want:  []proxyRoute{{Prefix: "/x", Target: "http://h/p?q=1"}},
		},
		{
			name:    "missing equals",
			input:   "/protected/http://app:8080",
			wantErr: "missing '='",
		},
		{
			name:    "empty prefix",
			input:   "=http://app:8080",
			wantErr: "empty prefix",
		},
		{
			name:    "empty target",
			input:   "/protected/=",
			wantErr: "empty target URL",
		},
		{
			name:    "target without scheme",
			input:   "/protected/=app:8080",
			wantErr: "must include scheme and host",
		},
		{
			name:    "target without host",
			input:   "/protected/=http://",
			wantErr: "must include scheme and host",
		},
		{
			name:    "duplicate prefix",
			input:   "/x=http://a:1,/x=http://b:2",
			wantErr: `prefix "/x" is defined more than once`,
		},
		{
			name:    "empty entry between commas",
			input:   "/a=http://a:1,,/b=http://b:2",
			wantErr: "is empty",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseProxyTargets(tc.input)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (routes=%+v)", tc.wantErr, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d routes, want %d (%+v)", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("route %d: got %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}
