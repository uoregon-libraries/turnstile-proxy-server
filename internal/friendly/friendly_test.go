package friendly

import (
	"strings"
	"testing"
)

func TestNameIsDeterministic(t *testing.T) {
	var a = Name("token-abc")
	var b = Name("token-abc")
	if a != b {
		t.Errorf("Name not deterministic: %q != %q", a, b)
	}
}

func TestNameFormat(t *testing.T) {
	var name = Name("some-id")
	var parts = strings.Fields(name)
	if len(parts) != 2 {
		t.Fatalf("Name(%q) = %q, want two words", "some-id", name)
	}
}

func TestNameEmpty(t *testing.T) {
	if got := Name(""); got != "Unknown Visitor" {
		t.Errorf("Name(\"\") = %q, want placeholder", got)
	}
}

func TestNameVaries(t *testing.T) {
	// Different inputs should usually produce different names; check that the
	// generator isn't collapsing everything to one value.
	var seen = make(map[string]bool)
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		seen[Name(id)] = true
	}
	if len(seen) < 4 {
		t.Errorf("only %d distinct names from 8 inputs; generator looks degenerate", len(seen))
	}
}
