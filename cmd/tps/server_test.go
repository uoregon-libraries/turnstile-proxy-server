package main

import "testing"

func TestPickTarget(t *testing.T) {
	routes := []proxyRoute{
		{Prefix: "/", Target: "http://catchall:80"},
		{Prefix: "/protected/", Target: "http://app:8080"},
		{Prefix: "/static-protected/", Target: "http://caddy:8081"},
		{Prefix: "/protected/deep/", Target: "http://app-deep:8080"},
	}
	s := (&Server{}).SetProxyTargets(routes)

	tests := []struct {
		path    string
		wantURL string
	}{
		{"/protected/foo", "http://app:8080"},
		{"/protected/deep/foo", "http://app-deep:8080"},
		{"/static-protected/index.html", "http://caddy:8081"},
		{"/anything-else", "http://catchall:80"},
		{"/", "http://catchall:80"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := s.pickTarget(tc.path)
			if got == nil {
				t.Fatalf("pickTarget(%q) returned nil, want %s", tc.path, tc.wantURL)
			}
			if got.String() != tc.wantURL {
				t.Errorf("pickTarget(%q) = %s, want %s", tc.path, got.String(), tc.wantURL)
			}
		})
	}
}

func TestPickTargetNoMatch(t *testing.T) {
	s := (&Server{}).SetProxyTargets([]proxyRoute{
		{Prefix: "/foo/", Target: "http://foo:8080"},
	})
	if got := s.pickTarget("/bar/baz"); got != nil {
		t.Errorf("pickTarget(/bar/baz) = %v, want nil", got)
	}
}

func TestPickTargetEmpty(t *testing.T) {
	s := &Server{}
	if got := s.pickTarget("/anything"); got != nil {
		t.Errorf("pickTarget on empty Server = %v, want nil", got)
	}
}
