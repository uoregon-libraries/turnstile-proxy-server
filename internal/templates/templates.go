// Package templates exists solely to embed our Go HTML files into the binary
// in a variable that's easily accessed anywhere in the app.
package templates

import "embed"

// FS is the embedded filesystem for all Go HTML
//
//go:embed *.go.html
var FS embed.FS
