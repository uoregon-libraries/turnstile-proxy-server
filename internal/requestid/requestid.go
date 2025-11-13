// Package requestid is a simple id generator like UUID but without all the
// wonky versions or unnecessary hyphens
package requestid

import (
	"crypto/rand"
	"encoding/hex"
)

// New generates a new random request ID.
//
// Note: crypto's [rand.Read] will panic on errors, so it won't return an error
// even if one happens. Because of that, this function doesn't need error
// handling. See https://github.com/golang/go/issues/66821.
func New() string {
	var bytes = make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
