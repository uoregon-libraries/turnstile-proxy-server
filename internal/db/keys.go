package db

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrKeysUnavailable is returned by the key methods when event logging is
// disabled: bypass keys live in the same database as the event log, so
// without a LOG_DB_PATH there is nowhere to keep them.
var ErrKeysUnavailable = errors.New("event logging is disabled; bypass keys need LOG_DB_PATH to be set")

// ErrNoSuchKey is returned by [Store.RevokeKey] when no active key has the
// given id — it never existed, or it was already revoked.
var ErrNoSuchKey = errors.New("no active key with that id")

// Key is one bypass key: a credential that lets a provisioned client (a
// vetted researcher's scraper, say) through TPS without solving a challenge,
// within the limits recorded here. The key itself is never stored, only its
// SHA-256, so a copy of the database can't be replayed as credentials.
type Key struct {
	ID         int64
	Label      string
	KeyHash    string   // hex SHA-256 of the full presented key
	CIDRs      []string // client networks the key may be used from; empty = anywhere
	RatePerSec float64  // sustained request rate (token-bucket refill)
	Burst      int      // burst allowance (token-bucket capacity)
	DailyCap   int64    // max requests per UTC day; 0 = uncapped
	Notes      string
	Created    time.Time
	Expires    time.Time
	Revoked    time.Time // zero = not revoked
}

// Active reports whether the key authorizes requests as of now: not revoked
// and not expired.
func (k Key) Active(now time.Time) bool {
	return k.Revoked.IsZero() && now.Before(k.Expires)
}

// KeyUsage is what the raw event log remembers about one key's traffic. It
// only reaches back as far as LOG_RETENTION, which is fine for its purpose:
// "is this key behaving right now" is a question about recent traffic.
type KeyUsage struct {
	Requests    int64     // requests authorized by the key
	RateLimited int64     // requests refused with a 429
	LastSeen    time.Time // most recent event naming the key
}

// cidrsToText flattens a key's CIDR list for storage. Comma-joined text is
// enough: CIDRs can't contain commas, and the list is only ever read back
// whole.
func cidrsToText(cidrs []string) string {
	return strings.Join(cidrs, ",")
}

func textToCIDRs(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(text, ",")
}

// CreateKey records a new bypass key and returns its id. The caller has
// already hashed the secret; nothing here ever sees it.
func (s *sqliteStore) CreateKey(k Key) (int64, error) {
	var res, err = s.db.Exec(`
	INSERT INTO bypass_keys (key_hash, label, cidrs, rate_per_sec, burst, daily_cap, notes, created_at, expires_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		k.KeyHash, k.Label, cidrsToText(k.CIDRs), k.RatePerSec, k.Burst, k.DailyCap,
		k.Notes, k.Created.UnixMicro(), k.Expires.UnixMicro())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListKeys returns every bypass key, including revoked and expired ones: the
// server needs the dead ones too, so a request presenting one can be told
// what's wrong with it instead of being shrugged at as unknown.
func (s *sqliteStore) ListKeys() ([]Key, error) {
	var rows, err = s.db.Query(`
	SELECT id, key_hash, label, cidrs, rate_per_sec, burst, daily_cap, notes, created_at, expires_at, revoked_at
	FROM bypass_keys ORDER BY id;`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []Key
	for rows.Next() {
		var k Key
		var cidrs string
		var created, expires int64
		var revoked sql.NullInt64
		if err = rows.Scan(&k.ID, &k.KeyHash, &k.Label, &cidrs, &k.RatePerSec, &k.Burst,
			&k.DailyCap, &k.Notes, &created, &expires, &revoked); err != nil {
			return nil, err
		}
		k.CIDRs = textToCIDRs(cidrs)
		k.Created = time.UnixMicro(created)
		k.Expires = time.UnixMicro(expires)
		if revoked.Valid {
			k.Revoked = time.UnixMicro(revoked.Int64)
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// RevokeKey marks the key dead as of now. Revocation is permanent — the point
// is to end a conversation, not suspend it — so re-revoking is ErrNoSuchKey
// rather than a fresher timestamp.
func (s *sqliteStore) RevokeKey(id int64) error {
	var res, err = s.db.Exec(`
	UPDATE bypass_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL;`,
		time.Now().UnixMicro(), id)
	if err != nil {
		return err
	}
	var n int64
	if n, err = res.RowsAffected(); err != nil {
		return err
	}
	if n == 0 {
		return ErrNoSuchKey
	}
	return nil
}

// KeyUsage aggregates the raw event log per key: how much traffic each key
// has pushed within the retention window, how much of it was refused, and
// when it was last seen. Keys with no logged events simply have no entry.
func (s *sqliteStore) KeyUsage() (map[int64]KeyUsage, error) {
	var rows, err = s.db.Query(`
	SELECT key_id,
		SUM(CASE WHEN outcome = ? THEN 1 ELSE 0 END),
		SUM(CASE WHEN outcome = ? THEN 1 ELSE 0 END),
		MAX(ts)
	FROM events WHERE key_id IS NOT NULL GROUP BY key_id;`,
		OutcomeProxied, OutcomeRateLimited)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usage = make(map[int64]KeyUsage)
	for rows.Next() {
		var id, last int64
		var u KeyUsage
		if err = rows.Scan(&id, &u.Requests, &u.RateLimited, &last); err != nil {
			return nil, err
		}
		u.LastSeen = time.UnixMicro(last)
		usage[id] = u
	}
	return usage, rows.Err()
}

func (noopStore) CreateKey(Key) (int64, error)          { return 0, ErrKeysUnavailable }
func (noopStore) ListKeys() ([]Key, error)              { return nil, ErrKeysUnavailable }
func (noopStore) RevokeKey(int64) error                 { return ErrKeysUnavailable }
func (noopStore) KeyUsage() (map[int64]KeyUsage, error) { return nil, ErrKeysUnavailable }
