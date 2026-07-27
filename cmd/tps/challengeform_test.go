package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"turnstile-proxy-server/internal/templates"

	"github.com/gin-gonic/gin"
)

// TestExpandChallengeMarkupPlaceholder checks the whole point of the
// placeholder: a template that says nothing but "put the form here" ends up
// with a complete, working challenge page.
func TestExpandChallengeMarkupPlaceholder(t *testing.T) {
	src := `<html><head><title>Hi</title></head><body><challenge-form></challenge-form></body></html>`
	got, n := expandChallengeMarkup(src)

	if n != 1 {
		t.Errorf("placeholder count = %d, want 1", n)
	}
	for _, want := range []string{
		turnstileScriptTag,
		`id="tps-challenge-form"`,
		`action="{{.PostAction}}"`,
		`value="{{.RequestID}}"`,
		`data-sitekey="{{.SiteKey}}"`,
		`navigator.sendBeacon('/.tps/beacon')`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expanded source is missing %q:\n%s", want, got)
		}
	}
	if strings.Index(got, turnstileScriptTag) > strings.Index(got, "</head>") {
		t.Errorf("Turnstile script was not injected into <head>:\n%s", got)
	}
	if !strings.Contains(got, "</challenge-form>") {
		t.Errorf("expanded source lost the closing tag:\n%s", got)
	}
}

// TestExpandChallengeMarkupNoPlaceholder makes sure hand-written challenge
// pages (and the failure page, which needs none of this) are left exactly as
// their author wrote them.
func TestExpandChallengeMarkupNoPlaceholder(t *testing.T) {
	src := `<html><head><title>Failed</title></head><body><h1>Nope</h1></body></html>`
	got, n := expandChallengeMarkup(src)

	if n != 0 {
		t.Errorf("placeholder count = %d, want 0", n)
	}
	if got != src {
		t.Errorf("source was rewritten:\ngot  %s\nwant %s", got, src)
	}
}

func TestExpandChallengeMarkupVariants(t *testing.T) {
	var tests = []struct {
		name        string
		src         string
		wantCount   int
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:        "attributes and whitespace are preserved",
			src:         `<head></head><body><challenge-form class="box" id="cf" ></challenge-form></body>`,
			wantCount:   1,
			wantContain: []string{`<challenge-form class="box" id="cf">`},
		},
		{
			name:        "self-closing tag gets a real closing tag",
			src:         `<head></head><body><challenge-form /></body>`,
			wantCount:   1,
			wantContain: []string{`<challenge-form>`, `</challenge-form>`},
			wantAbsent:  []string{`<challenge-form />`, `<challenge-form/>`},
		},
		{
			name:        "unclosed placeholder still expands",
			src:         `<head></head><body><challenge-form></body>`,
			wantCount:   1,
			wantContain: []string{`id="tps-challenge-form"`, `</challenge-form>`},
		},
		{
			name:        "inner content is kept as fallback markup",
			src:         `<head></head><body><challenge-form><noscript>JS required</noscript></challenge-form></body>`,
			wantCount:   1,
			wantContain: []string{`<noscript>JS required</noscript>`, `id="tps-challenge-form"`},
		},
		{
			name:        "mixed case tag",
			src:         `<HEAD></HEAD><body><CHALLENGE-FORM></CHALLENGE-FORM></body>`,
			wantCount:   1,
			wantContain: []string{`id="tps-challenge-form"`, turnstileScriptTag},
		},
		{
			name:       "similarly named element is not a placeholder",
			src:        `<head></head><body><challenge-forms></challenge-forms></body>`,
			wantCount:  0,
			wantAbsent: []string{`id="tps-challenge-form"`, turnstileScriptTag},
		},
		{
			name:        "two placeholders are both expanded",
			src:         `<head></head><body><challenge-form></challenge-form><challenge-form></challenge-form></body>`,
			wantCount:   2,
			wantContain: []string{`id="tps-challenge-form"`},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, n := expandChallengeMarkup(tc.src)
			if n != tc.wantCount {
				t.Errorf("placeholder count = %d, want %d", n, tc.wantCount)
			}
			for _, want := range tc.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("output is missing %q:\n%s", want, got)
				}
			}
			for _, unwanted := range tc.wantAbsent {
				if strings.Contains(got, unwanted) {
					t.Errorf("output unexpectedly contains %q:\n%s", unwanted, got)
				}
			}
		})
	}
}

// TestInjectTurnstileScriptPlacement covers where the API script lands when
// there's no </head> to put it in, and that we never load it twice.
func TestInjectTurnstileScriptPlacement(t *testing.T) {
	t.Run("no head, injected after body", func(t *testing.T) {
		got, _ := expandChallengeMarkup(`<body class="x"><challenge-form></challenge-form></body>`)
		if !strings.Contains(got, `<body class="x">`+"\n"+turnstileScriptTag) {
			t.Errorf("script not injected at the top of <body>:\n%s", got)
		}
	})

	t.Run("fragment, injected before the form", func(t *testing.T) {
		got, _ := expandChallengeMarkup(`<div><challenge-form></challenge-form></div>`)
		if strings.Index(got, turnstileScriptTag) > strings.Index(got, "<challenge-form") {
			t.Errorf("script not injected before the challenge form:\n%s", got)
		}
	})

	t.Run("template loading api.js itself is left alone", func(t *testing.T) {
		src := `<head><script src="` + turnstileAPISrc + `" defer></script></head>` +
			`<body><challenge-form></challenge-form></body>`
		got, _ := expandChallengeMarkup(src)
		if n := strings.Count(got, turnstileAPISrc); n != 1 {
			t.Errorf("api.js referenced %d times, want 1:\n%s", n, got)
		}
	})
}

// TestCoreTemplateRendersChallenge renders the embedded core challenge page
// the way a release build does. The core template uses the same
// <challenge-form> placeholder custom templates do, so this is what keeps the
// shipped page honest: if expansion breaks, the default challenge page stops
// working, not just custom ones.
func TestCoreTemplateRendersChallenge(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	var mode = gin.Mode()
	gin.SetMode(gin.ReleaseMode)
	defer gin.SetMode(mode)

	s := NewServer(gin.New(), &fakeStore{}).
		SetJWTSigningKey("test-key").
		SetSiteKey("site-key-here").
		SetProxyTarget(backend.URL)
	s.LoadCoreTemplates("internal/templates/*.go.html", templates.FS)

	w := httptest.NewRecorder()
	s.r.ServeHTTP(w, httptest.NewRequest("GET", "/protected", nil))

	body := w.Body.String()
	for _, want := range []string{
		turnstileScriptTag,
		`<form id="tps-challenge-form" action="/protected" method="POST">`,
		`data-sitekey="site-key-here"`,
		`data-callback="tpsChallengeSolved"`,
		`name="request_id"`,
		`navigator.sendBeacon('/.tps/beacon')`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("core challenge page is missing %q:\n%s", want, body)
		}
	}
}

// TestCustomTemplateRendersChallenge is the end-to-end version: a custom
// template on disk with nothing but a <challenge-form> placeholder must render
// as a page that can actually solve a challenge, with the request's values
// escaped into it.
func TestCustomTemplateRendersChallenge(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "example.test"), 0700); err != nil {
		t.Fatalf("making template dir: %v", err)
	}
	tmpl := "<!DOCTYPE html>\n<html><head><title>Custom</title></head>\n" +
		"<body><h1>Custom challenge</h1><challenge-form></challenge-form></body></html>\n"
	if err := os.WriteFile(filepath.Join(dir, "example.test", "challenge.go.html"), []byte(tmpl), 0600); err != nil {
		t.Fatalf("writing template: %v", err)
	}

	gin.SetMode(gin.TestMode)
	s := NewServer(gin.New(), &fakeStore{}).
		SetJWTSigningKey("test-key").
		SetSiteKey("site-key-here").
		SetProxyTarget(backend.URL)
	s.LoadCustomTemplates(dir)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/search?q=a%26b", nil)
	req.Host = "example.test"
	s.r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	body := w.Body.String()
	for _, want := range []string{
		"<h1>Custom challenge</h1>",
		turnstileScriptTag,
		`data-sitekey="site-key-here"`,
		`action="/search?q=a%26b"`,
		`navigator.sendBeacon('/.tps/beacon')`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("challenge page is missing %q:\n%s", want, body)
		}
	}

	// The request ID in the form has to be the one TPS cached the request
	// under, or the replay after verification can't find it
	_, after, found := strings.Cut(body, `name="request_id" value="`)
	if !found {
		t.Fatalf("challenge page has no request_id input:\n%s", body)
	}
	id, _, _ := strings.Cut(after, `"`)
	if _, found := s.requestCache.Get(id); !found {
		t.Errorf("request ID %q from the page is not in the request cache", id)
	}
}
