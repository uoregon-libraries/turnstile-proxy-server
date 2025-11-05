package requestid

import (
	"crypto/rand"
	"encoding/hex"
	"log"
)

// New generates a new random request ID.
func New() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("could not generate random bytes for request ID: %v", err)
	}
	return hex.EncodeToString(bytes)
}
