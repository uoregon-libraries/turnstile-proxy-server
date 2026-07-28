package main

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin/render"
	"github.com/spf13/afero"
)

// templateStore is TPS's HTML renderer for Gin. We can't use an off-the-shelf
// renderer because those parse the files for us, and the <challenge-form>
// expansion has to happen on the template *source*, before it's parsed.
//
// It keeps the behavior Gin's own renderers have: in debug mode a template is
// re-read, re-expanded, and re-parsed on every render, so you can edit a
// challenge page and just hit refresh. In release mode every template is
// parsed once at startup (and comes from the embedded FS anyway, where there
// is nothing to hot-reload).
type templateStore struct {
	mu      sync.Mutex
	logger  *slog.Logger
	dynamic bool
	entries map[string]*templateEntry
}

// templateEntry is one registered template plus where it came from. A
// file-backed entry can be reloaded; one registered from a string can't, so
// fsys is nil for those.
type templateEntry struct {
	tmpl *template.Template
	fsys afero.Fs
	path string
}

func newTemplateStore(logger *slog.Logger, dynamic bool) *templateStore {
	return &templateStore{
		logger:  logger,
		dynamic: dynamic,
		entries: make(map[string]*templateEntry),
	}
}

// addFile registers the template at path, read through fsys so the caller can
// hand us an embedded filesystem or the real one.
func (ts *templateStore) addFile(name string, fsys afero.Fs, path string) error {
	var src, err = afero.ReadFile(fsys, path)
	if err != nil {
		return fmt.Errorf("reading template %q: %w", path, err)
	}

	var tmpl, perr = ts.build(name, string(src), true)
	if perr != nil {
		return perr
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.entries[name] = &templateEntry{tmpl: tmpl, fsys: fsys, path: path}
	return nil
}

// addString registers a template from source that isn't backed by a file, so
// it is never reloaded.
func (ts *templateStore) addString(name, src string) error {
	var tmpl, err = ts.build(name, src, true)
	if err != nil {
		return err
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.entries[name] = &templateEntry{tmpl: tmpl}
	return nil
}

// build expands the challenge markup in src and parses the result. complain
// says whether to report what the expansion found; it's on when a template is
// first registered and off for reloads, which would otherwise repeat the same
// warning on every request.
func (ts *templateStore) build(name, src string, complain bool) (*template.Template, error) {
	var expanded, placeholders = expandChallengeMarkup(src)
	if complain {
		switch {
		case placeholders == 1:
			ts.logger.Debug("Expanded <challenge-form> placeholder", "name", name)
		case placeholders > 1:
			ts.logger.Warn("Template has more than one <challenge-form>; each one becomes its own "+
				"Turnstile widget and challenge form, which is almost certainly not what you want",
				"name", name, "count", placeholders)
		}
	}

	var tmpl, err = template.New(name).Parse(expanded)
	if err != nil {
		return nil, fmt.Errorf("parsing template %q: %w", name, err)
	}
	return tmpl, nil
}

// Instance implements Gin's render.HTMLRender
func (ts *templateStore) Instance(name string, data any) render.Render {
	var tmpl = ts.lookup(name)
	if tmpl == nil {
		return missingTemplate{name: name}
	}
	return render.HTML{Template: tmpl, Data: data}
}

// lookup returns the template to render, reloading it from disk first when
// we're in debug mode. A file that has gone missing or stopped compiling since
// startup is reported and the last good version is served, because dropping a
// challenge page means letting an unverified request through.
func (ts *templateStore) lookup(name string) *template.Template {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	var entry = ts.entries[name]
	if entry == nil {
		return nil
	}
	if !ts.dynamic || entry.fsys == nil {
		return entry.tmpl
	}

	var src, err = afero.ReadFile(entry.fsys, entry.path)
	if err != nil {
		ts.logger.Error("Cannot re-read template, using the version loaded at startup",
			"name", name, "path", entry.path, "error", err)
		return entry.tmpl
	}

	var tmpl, berr = ts.build(name, string(src), false)
	if berr != nil {
		ts.logger.Error("Cannot parse template, using the version loaded at startup",
			"name", name, "path", entry.path, "error", berr)
		return entry.tmpl
	}

	entry.tmpl = tmpl
	return tmpl
}

// missingTemplate stands in for a template nobody registered. Gin collects the
// error and aborts the request rather than writing a half-rendered page.
type missingTemplate struct {
	name string
}

func (m missingTemplate) Render(http.ResponseWriter) error {
	return fmt.Errorf("no template named %q is registered", m.name)
}

func (m missingTemplate) WriteContentType(http.ResponseWriter) {}
