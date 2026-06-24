// Package friendly turns opaque client identifiers (token IDs, IP+UA hashes)
// into short, stable, human-readable names like "Purple Armadillo" so the live
// event view is scannable instead of a wall of UUIDs. The mapping is
// deterministic: the same input always yields the same name.
package friendly

import "crypto/sha256"

// adjectives and animals are the two halves of every generated name. Their
// sizes (len(adjectives) * len(animals)) set how many distinct names exist
// before two different clients can collide; collisions are acceptable for a
// human-facing live view, not a unique key.
var adjectives = []string{
	"Amber", "Azure", "Brave", "Bright", "Calm", "Clever", "Cosmic", "Crimson",
	"Dapper", "Eager", "Fuzzy", "Gentle", "Golden", "Happy", "Jolly", "Lively",
	"Lucky", "Mellow", "Nimble", "Plucky", "Proud", "Purple", "Quiet", "Rapid",
	"Scarlet", "Silent", "Silver", "Sleepy", "Sly", "Swift", "Teal", "Witty",
}

var animals = []string{
	"Armadillo", "Badger", "Beaver", "Bison", "Cobra", "Coyote", "Crane", "Dingo",
	"Falcon", "Ferret", "Gecko", "Heron", "Ibex", "Jackal", "Koala", "Lemur",
	"Lynx", "Magpie", "Marten", "Newt", "Ocelot", "Osprey", "Otter", "Panther",
	"Quokka", "Raven", "Salamander", "Stoat", "Tapir", "Vulture", "Walrus", "Wombat",
}

// Name returns a stable two-word name for id. An empty id maps to a fixed
// placeholder so callers never have to special-case it.
func Name(id string) string {
	if id == "" {
		return "Unknown Visitor"
	}
	// A single hash gives us plenty of bits; use disjoint byte ranges for the
	// two indices so the adjective and animal vary independently.
	var sum = sha256.Sum256([]byte(id))
	var adj = (uint32(sum[0])<<8 | uint32(sum[1])) % uint32(len(adjectives))
	var ani = (uint32(sum[2])<<8 | uint32(sum[3])) % uint32(len(animals))
	return adjectives[adj] + " " + animals[ani]
}
