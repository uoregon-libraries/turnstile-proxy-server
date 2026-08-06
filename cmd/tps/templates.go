package main

import (
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spf13/afero"
)

// addTemplate registers one template file under the given name. A core
// template that won't load is fatal — without it TPS has no challenge page to
// serve, and a gate that can't challenge isn't a gate — while a custom one is
// skipped, because the core template it would have overridden still covers
// that path.
func (s *Server) addTemplate(name string, af afero.Fs, pth string, fatal bool) {
	s.logger.Debug("Adding template", "name", name, "path", pth)
	var err = s.render.addFile(name, af, pth)
	if err == nil {
		return
	}
	if fatal {
		s.logger.Error("Cannot load core template", "name", name, "path", pth, "error", err)
		panic("Fatal error, cannot continue without templates")
	}
	s.logger.Error("Cannot load custom template, skipping it", "name", name, "path", pth, "error", err)
}

// LoadCoreTemplates is a general-case helper to load either from local disk
// for hot-reloads, or from an embedded filesystem, depending on the gin mode
func (s *Server) LoadCoreTemplates(pattern string, fsys fs.FS) {
	var from string
	var af afero.Fs
	if gin.Mode() == gin.ReleaseMode {
		af = afero.FromIOFS{FS: fsys}
		pattern = "*.go.html"
		from = "io/fs.FS"
	} else {
		af = afero.NewOsFs()
		from = "OS Filesystem"
	}

	var templates, err = afero.Glob(af, pattern)
	if err != nil {
		s.logger.Error("Cannot load core templates", "from", from, "pattern", pattern, "error", err)
		panic("Fatal error, cannot continue without templates")
	}

	s.logger.Debug("Reading / mapping core templates", "templates", templates)
	for _, pth := range templates {
		if strings.HasSuffix(pth, ".go.html") {
			var name = "core/" + strings.Replace(filepath.Base(pth), ".go.html", "", 1)
			s.addTemplate(name, af, pth, true)
		}
	}
}

// LoadCustomTemplates finds all templates under the given path named
// "*.html.go" and registers them for use as custom templates for specific
// proxied URLs' challenge and failed pages.
func (s *Server) LoadCustomTemplates(templatePath string) {
	if templatePath == "" {
		return
	}
	templatePath = filepath.Clean(templatePath)

	var err = filepath.Walk(templatePath, func(pth string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return err
		}

		if strings.HasSuffix(pth, ".go.html") {
			var name, relErr = filepath.Rel(templatePath, pth)
			if relErr != nil {
				s.logger.Error("Cannot name custom template, skipping it", "path", pth, "error", relErr)
				return nil
			}
			name = strings.TrimSuffix(name, ".go.html")
			s.addTemplate(name, afero.NewOsFs(), pth, false)
		}
		return err
	})
	if err != nil {
		s.logger.Error("Failed to load custom templates", "path", templatePath, "error", err)
	}
}

// getTemplate picks the template to render for this request, most specific
// first: <hostname>/<path>/<shortname> narrowing a path segment at a time,
// then <hostname>/<shortname>, then a top-level <shortname> covering every
// host, and finally the core template built into TPS. Most sites only ever
// need that top-level pair, so it costs nothing to have the per-host and
// per-path layers available for the sites that do.
func (s *Server) getTemplate(r *http.Request, shortname string) string {
	var host = r.Host
	var path = r.URL.Path

	// Clean the path to prevent directory traversal issues
	path = filepath.Clean(path)

	// Remove leading slash
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}

	var parts = strings.Split(path, "/")
	if len(parts) == 1 && parts[0] == "" {
		parts = []string{}
	}

	for i := len(parts); i >= 0; i-- {
		var source = host + "/" + strings.Join(parts[:i], "/")
		s.logger.Debug("Looking for template", "source", source, "shortname", shortname)
		var name = filepath.Join(source, shortname)
		if s.render.has(name) {
			s.logger.Debug("Found custom template", "name", name)
			return name
		}
	}

	if s.render.has(shortname) {
		s.logger.Debug("Found site-wide custom template", "name", shortname)
		return shortname
	}

	s.logger.Debug("No custom template found, returning default")
	return "core/" + shortname
}
