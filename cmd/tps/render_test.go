package main

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// renderStore renders a registered template and returns the output
func renderStore(t *testing.T, ts *templateStore, name string, data any) string {
	t.Helper()
	var w = httptest.NewRecorder()
	if err := ts.Instance(name, data).Render(w); err != nil {
		t.Fatalf("rendering %q: %v", name, err)
	}
	return w.Body.String()
}

// writeTemplate puts src in a temp file and hands back its path
func writeTemplate(t *testing.T, src string) string {
	t.Helper()
	var path = filepath.Join(t.TempDir(), "challenge.go.html")
	if err := os.WriteFile(path, []byte(src), 0600); err != nil {
		t.Fatalf("writing template: %v", err)
	}
	return path
}

// TestTemplateStoreReload covers the debug-mode promise: edit a challenge page
// on disk, hit refresh, see the change. Gin's own renderers do this and TPS's
// has to as well, since a challenge page is exactly the kind of thing you sit
// and fiddle with.
func TestTemplateStoreReload(t *testing.T) {
	var path = writeTemplate(t, "<body>before <challenge-form></challenge-form></body>")

	var ts = newTemplateStore(quietLogger(), true)
	if err := ts.addFile("core/challenge", afero.NewOsFs(), path); err != nil {
		t.Fatalf("adding template: %v", err)
	}
	if got := renderStore(t, ts, "core/challenge", nil); !strings.Contains(got, "before") {
		t.Fatalf("first render is missing the original content:\n%s", got)
	}

	if err := os.WriteFile(path, []byte("<body>after <challenge-form></challenge-form></body>"), 0600); err != nil {
		t.Fatalf("rewriting template: %v", err)
	}

	var got = renderStore(t, ts, "core/challenge", nil)
	if !strings.Contains(got, "after") {
		t.Errorf("template was not reloaded:\n%s", got)
	}
	// The edited page still has to come out expanded, not raw
	if !strings.Contains(got, `id="tps-challenge-form"`) || !strings.Contains(got, turnstileScriptTag) {
		t.Errorf("reloaded template was not expanded:\n%s", got)
	}
}

// TestTemplateStoreNoReloadWhenStatic is the release-mode half: templates are
// parsed once, and we don't go to disk per request.
func TestTemplateStoreNoReloadWhenStatic(t *testing.T) {
	var path = writeTemplate(t, "<body>before</body>")

	var ts = newTemplateStore(quietLogger(), false)
	if err := ts.addFile("core/challenge", afero.NewOsFs(), path); err != nil {
		t.Fatalf("adding template: %v", err)
	}
	if err := os.WriteFile(path, []byte("<body>after</body>"), 0600); err != nil {
		t.Fatalf("rewriting template: %v", err)
	}

	var got = renderStore(t, ts, "core/challenge", nil)
	if !strings.Contains(got, "before") {
		t.Errorf("static store reloaded the template:\n%s", got)
	}
}

// TestTemplateStoreReloadFailureKeepsLastGood makes sure a typo saved
// mid-edit doesn't take the challenge page down: TPS serves the last version
// that parsed rather than nothing at all.
func TestTemplateStoreReloadFailureKeepsLastGood(t *testing.T) {
	var path = writeTemplate(t, "<body>good {{.RequestID}}</body>")

	var ts = newTemplateStore(quietLogger(), true)
	if err := ts.addFile("core/challenge", afero.NewOsFs(), path); err != nil {
		t.Fatalf("adding template: %v", err)
	}
	renderStore(t, ts, "core/challenge", templateData("id-1"))

	if err := os.WriteFile(path, []byte("<body>{{.Broken</body>"), 0600); err != nil {
		t.Fatalf("rewriting template: %v", err)
	}

	var got = renderStore(t, ts, "core/challenge", templateData("id-2"))
	if !strings.Contains(got, "good id-2") {
		t.Errorf("broken template didn't fall back to the last good version:\n%s", got)
	}

	// ...and recovers once the file parses again
	if err := os.WriteFile(path, []byte("<body>fixed {{.RequestID}}</body>"), 0600); err != nil {
		t.Fatalf("rewriting template: %v", err)
	}
	if got = renderStore(t, ts, "core/challenge", templateData("id-3")); !strings.Contains(got, "fixed id-3") {
		t.Errorf("store didn't pick the template back up after the fix:\n%s", got)
	}
}

// templateData builds the smallest data set the test templates need
func templateData(requestID string) map[string]any {
	return map[string]any{"RequestID": requestID}
}

// TestTemplateStoreMissingTemplate checks that asking for a template nobody
// registered is an error Gin can report, not a nil dereference.
func TestTemplateStoreMissingTemplate(t *testing.T) {
	var ts = newTemplateStore(quietLogger(), false)
	var w = httptest.NewRecorder()

	var err = ts.Instance("core/nope", nil).Render(w)
	if err == nil {
		t.Fatal("rendering an unregistered template succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "core/nope") {
		t.Errorf("error %q doesn't name the missing template", err)
	}
}

// TestTemplateStoreBadTemplateIsRejected checks that a template which doesn't
// parse is refused at load time (and, in LoadCustomTemplates, skipped) instead
// of taking the process down.
func TestTemplateStoreBadTemplateIsRejected(t *testing.T) {
	var ts = newTemplateStore(quietLogger(), false)

	if err := ts.addString("core/challenge", "{{.Nope"); err == nil {
		t.Error("addString accepted an unparseable template")
	}
	if err := ts.addFile("core/challenge", afero.NewOsFs(), writeTemplate(t, "{{.Nope")); err == nil {
		t.Error("addFile accepted an unparseable template")
	}
	if err := ts.addFile("core/challenge", afero.NewOsFs(), "/no/such/template.go.html"); err == nil {
		t.Error("addFile accepted a missing file")
	}
}
