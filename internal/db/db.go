// Package db provides primitives for logging proxy decision events to an
// embedded SQLite database for later analytics.
package db

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	// Pure-Go SQLite driver (no cgo), registered as "sqlite".
	_ "modernc.org/sqlite"
)

// Outcome enumerates what TPS decided to do with a request. Each handled
// request produces exactly one event.
const (
	OutcomeProxied           = "proxied"            // request had a valid token and was sent upstream
	OutcomeChallenged        = "challenged"         // a Turnstile challenge page was served
	OutcomeChallengeRendered = "challenge_rendered" // a served challenge page's JS executed (beacon)
	OutcomeVerifyOK          = "verify_ok"          // a challenge solution verified successfully
	OutcomeVerifyFail        = "verify_fail"        // a challenge solution failed verification
)

// Reason gives more detail about an outcome (why a challenge was served, or how
// a request came to be proxied). It may be empty for outcomes that need no
// further detail.
const (
	ReasonNoCookie        = "no_cookie"        // challenged: no JWT cookie present
	ReasonInvalidJWT      = "invalid_jwt"      // challenged: JWT present but unparseable
	ReasonClientMismatch  = "client_mismatch"  // challenged: JWT bound to a different client
	ReasonBudgetExhausted = "budget_exhausted" // challenged: token's request budget is spent
	ReasonValidToken      = "valid_token"      // proxied: a live token authorized the request
	ReasonVerifiedReplay  = "verified_replay"  // proxied/verify_ok: replay after solving a challenge
)

// Event is a single proxy decision to be recorded.
type Event struct {
	Timestamp time.Time
	Outcome   string
	Reason    string
	ClientIP  string
	MaskedIP  string
	Host      string
	Path      string
	Method    string
	UserAgent string
	JTI       string
	IPSwitch  bool
}

// Store records decision events. Implementations may persist to SQLite or
// silently discard entries (see [NewNoopStore]).
type Store interface {
	LogEvent(e Event)
	// Report aggregates recorded events into fixed-width, time-aligned buckets
	// over [start, end), reading from hourly rollups rather than the raw event
	// log. See [sqliteStore.Report]. Implementations without a backing table
	// return [ErrReportingUnavailable].
	Report(start, end time.Time, bucket time.Duration) ([]CountBucket, error)
	Close() error
}

const (
	// eventBufferSize bounds the in-memory queue between request handlers and
	// the background writer. When it fills (DB stalled or a traffic spike),
	// LogEvent drops events rather than blocking the request path.
	eventBufferSize = 4096
	// batchSize is the most events written in a single transaction.
	batchSize = 256
	// flushInterval bounds how long a buffered event waits before being
	// written when the batch isn't full.
	flushInterval = 200 * time.Millisecond
	// pruneInterval is how often expired events are deleted.
	pruneInterval = time.Hour
	// vacuumChunkPages is how many free pages one incremental_vacuum call
	// returns to the OS. Each call is its own short write transaction, so the
	// chunk size bounds how long the vacuum holds the write lock away from the
	// event writer.
	vacuumChunkPages = 1000
)

// dsn builds the SQLite connection string for the database at path. WAL + a
// busy timeout keep the single writer happy alongside ad-hoc readers (e.g. the
// sqlite3 CLI) running analytics queries. auto_vacuum(incremental) only takes
// effect on databases created fresh (or rebuilt by [Vacuum]); on an existing
// database without it, the pragma is a harmless no-op.
func dsn(path string) string {
	return path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=auto_vacuum(incremental)"
}

type sqliteStore struct {
	db      *sql.DB
	logger  *slog.Logger
	events  chan Event
	done    chan struct{}
	wg      sync.WaitGroup
	dropped atomic.Uint64
}

// NewStore opens (creating if needed) a SQLite-backed [Store] at path, creates
// the events and rollups tables, and starts the background writer. If retention
// is greater than zero, events older than retention are pruned hourly;
// retention <= 0 disables pruning (events are kept forever). Retention applies
// only to raw events: the hourly rollups that feed [Store.Report] are tiny and
// are kept forever, so reports remain available long past the raw-log window.
func NewStore(path string, retention time.Duration, logger *slog.Logger) (Store, error) {
	var database, err = sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, err
	}
	if err = database.Ping(); err != nil {
		database.Close()
		return nil, err
	}

	var store = &sqliteStore{
		db:     database,
		logger: logger,
		events: make(chan Event, eventBufferSize),
		done:   make(chan struct{}),
	}
	if err = store.migrate(); err != nil {
		database.Close()
		return nil, err
	}

	// Databases created before incremental auto-vacuum reuse the space freed
	// by pruning but never return it to the OS, so the file stays at its
	// high-water mark. Only a full rebuild can change the mode; point the
	// operator at the subcommand that does it.
	var autoVacuum int
	if err = database.QueryRow("PRAGMA auto_vacuum;").Scan(&autoVacuum); err == nil && autoVacuum != 2 {
		logger.Info("event log database predates incremental auto-vacuum; disk space freed by pruning is reused but never returned to the OS. Run 'tps vacuum' once to compact the file and enable it")
	}

	store.wg.Add(1)
	go store.writeLoop()

	if retention > 0 {
		store.wg.Add(1)
		go store.pruneLoop(retention)
	}

	return store, nil
}

func (s *sqliteStore) migrate() error {
	var query = `
	CREATE TABLE IF NOT EXISTS events(
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		ts         INTEGER NOT NULL,
		outcome    TEXT NOT NULL,
		reason     TEXT,
		client_ip  TEXT,
		masked_ip  TEXT,
		host       TEXT,
		path       TEXT,
		method     TEXT,
		user_agent TEXT,
		jti        TEXT,
		ip_switch  INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_events_ts  ON events(ts);
	CREATE INDEX IF NOT EXISTS idx_events_jti ON events(jti);

	CREATE TABLE IF NOT EXISTS rollups(
		bucket_ts INTEGER NOT NULL,
		outcome   TEXT NOT NULL,
		n         INTEGER NOT NULL,
		PRIMARY KEY (bucket_ts, outcome)
	) WITHOUT ROWID;
	`
	if _, err := s.db.Exec(query); err != nil {
		return err
	}
	return s.backfillRollups()
}

// backfillRollups populates the rollups table from raw events the first time a
// pre-rollup database is opened. Rollup rows are never deleted and every event
// write also updates them, so an empty rollups table alongside existing events
// can only mean the database predates the table.
func (s *sqliteStore) backfillRollups() error {
	var empty bool
	if err := s.db.QueryRow("SELECT NOT EXISTS (SELECT 1 FROM rollups)").Scan(&empty); err != nil {
		return err
	}
	if !empty {
		return nil
	}
	var us = rollupBucket.Microseconds()
	var _, err = s.db.Exec(`
		INSERT INTO rollups (bucket_ts, outcome, n)
		SELECT (ts / ?) * ?, outcome, COUNT(*) FROM events GROUP BY 1, 2;`, us, us)
	return err
}

// LogEvent queues an event for the background writer. It never blocks: if the
// buffer is full the event is dropped and counted so the request path is never
// slowed by the database.
func (s *sqliteStore) LogEvent(e Event) {
	select {
	case <-s.done:
		// Shutting down; the writer has stopped. Dropping is fine.
	case s.events <- e:
	default:
		var n = s.dropped.Add(1)
		// Log on the first drop and then sparsely, to flag the condition
		// without spamming the log during a sustained stall.
		if n == 1 || n%1000 == 0 {
			s.logger.Warn("event log buffer full; dropping events", "dropped_total", n)
		}
	}
}

// writeLoop batches queued events and writes each batch in one transaction. It
// flushes when the batch fills or flushInterval elapses, and drains the queue
// on shutdown.
func (s *sqliteStore) writeLoop() {
	defer s.wg.Done()

	var ticker = time.NewTicker(flushInterval)
	defer ticker.Stop()

	var batch = make([]Event, 0, batchSize)
	var flush = func() {
		if len(batch) == 0 {
			return
		}
		s.flush(batch)
		batch = batch[:0]
	}

	for {
		select {
		case e := <-s.events:
			batch = append(batch, e)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.done:
			// Drain whatever is queued, then exit.
			for {
				select {
				case e := <-s.events:
					batch = append(batch, e)
					if len(batch) >= batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *sqliteStore) flush(batch []Event) {
	var tx, err = s.db.Begin()
	if err != nil {
		s.logger.Error("Could not begin event log transaction", "error", err)
		return
	}

	var stmt *sql.Stmt
	stmt, err = tx.Prepare(`
	INSERT INTO events
		(ts, outcome, reason, client_ip, masked_ip, host, path, method, user_agent, jti, ip_switch)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`)
	if err != nil {
		s.logger.Error("Could not prepare event log insert", "error", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, e := range batch {
		var ipSwitch = 0
		if e.IPSwitch {
			ipSwitch = 1
		}
		if _, err = stmt.Exec(e.Timestamp.UnixMicro(), e.Outcome, e.Reason, e.ClientIP,
			e.MaskedIP, e.Host, e.Path, e.Method, e.UserAgent, e.JTI, ipSwitch); err != nil {
			s.logger.Error("Could not write event to log", "error", err)
			tx.Rollback()
			return
		}
	}

	// Fold the batch's counts into the hourly rollups in the same transaction,
	// so the raw log and its aggregates can never disagree.
	type bucketOutcome struct {
		ts      int64
		outcome string
	}
	var counts = make(map[bucketOutcome]int)
	var us = rollupBucket.Microseconds()
	for _, e := range batch {
		counts[bucketOutcome{(e.Timestamp.UnixMicro() / us) * us, e.Outcome}]++
	}

	var rstmt *sql.Stmt
	rstmt, err = tx.Prepare(`
	INSERT INTO rollups (bucket_ts, outcome, n) VALUES (?, ?, ?)
	ON CONFLICT (bucket_ts, outcome) DO UPDATE SET n = n + excluded.n;
	`)
	if err != nil {
		s.logger.Error("Could not prepare rollup upsert", "error", err)
		tx.Rollback()
		return
	}
	defer rstmt.Close()

	for key, n := range counts {
		if _, err = rstmt.Exec(key.ts, key.outcome, n); err != nil {
			s.logger.Error("Could not update rollup", "error", err)
			tx.Rollback()
			return
		}
	}

	if err = tx.Commit(); err != nil {
		s.logger.Error("Could not commit event log batch", "error", err)
	}
}

func (s *sqliteStore) pruneLoop(retention time.Duration) {
	defer s.wg.Done()

	// Prune once right away — we're already off the startup path, and a
	// service restarted more often than pruneInterval would otherwise never
	// prune at all.
	s.prune(retention)

	var ticker = time.NewTicker(pruneInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.prune(retention)
		}
	}
}

func (s *sqliteStore) prune(retention time.Duration) {
	var cutoff = time.Now().Add(-retention).UnixMicro()
	var res, err = s.db.Exec("DELETE FROM events WHERE ts < ?;", cutoff)
	if err != nil {
		s.logger.Error("Could not prune old events", "error", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.logger.Info("Pruned old events", "deleted", n, "retention", retention.String())
	}
	s.incrementalVacuum()
}

// incrementalVacuum returns freed pages to the OS after a prune, in chunks
// small enough that the event writer is never locked out for long. It is a
// silent no-op when the database is not in incremental auto_vacuum mode (a
// database from before that mode existed; see the hint logged by [NewStore]).
func (s *sqliteStore) incrementalVacuum() {
	var freed int
	for {
		var before, after int
		if err := s.db.QueryRow("PRAGMA freelist_count;").Scan(&before); err != nil || before == 0 {
			break
		}
		// Pragmas don't accept bound parameters, hence the Sprintf.
		if _, err := s.db.Exec(fmt.Sprintf("PRAGMA incremental_vacuum(%d);", vacuumChunkPages)); err != nil {
			s.logger.Error("Could not run incremental vacuum", "error", err)
			break
		}
		if err := s.db.QueryRow("PRAGMA freelist_count;").Scan(&after); err != nil || after >= before {
			// No progress: auto_vacuum is off, or the freelist is drained.
			break
		}
		freed += before - after
	}
	if freed > 0 {
		s.logger.Info("Reclaimed free space from event log database", "pages", freed)
	}
}

func (s *sqliteStore) Close() error {
	close(s.done)
	s.wg.Wait()
	return s.db.Close()
}

// Vacuum rebuilds the database file at path with SQLite's VACUUM, returning
// the file's size in bytes before and after. The rebuild also switches the
// database into incremental auto_vacuum mode, so from then on the hourly prune
// returns freed space to the OS on its own.
//
// It is safe to run against a database a live TPS instance has open: request
// handling never waits on the database, so the worst case is the server's
// background event writer timing out and dropping some batches while the
// rebuild holds the write lock. VACUUM needs temporary disk space up to the
// size of the database file.
func Vacuum(path string) (before, after int64, err error) {
	// Opening a SQLite database creates it, so stat first: a typo'd path
	// should be an error, not a successful vacuum of a fresh empty file.
	var fi os.FileInfo
	if fi, err = os.Stat(path); err != nil {
		return 0, 0, err
	}
	before = fi.Size()

	var database *sql.DB
	if database, err = sql.Open("sqlite", dsn(path)); err != nil {
		return before, 0, err
	}
	defer database.Close()

	if _, err = database.Exec("VACUUM;"); err != nil {
		return before, 0, err
	}
	// Fold the WAL back into the main file so the on-disk size we report is
	// real. Best effort: a concurrent reader can legitimately block it.
	database.Exec("PRAGMA wal_checkpoint(TRUNCATE);")

	if fi, err = os.Stat(path); err != nil {
		return before, 0, err
	}
	return before, fi.Size(), nil
}

type noopStore struct{}

// NewNoopStore returns a [Store] that discards every event. Use it when no
// LOG_DB_PATH is configured.
func NewNoopStore() Store { return noopStore{} }

func (noopStore) LogEvent(Event) {}
func (noopStore) Close() error   { return nil }

func (noopStore) Report(time.Time, time.Time, time.Duration) ([]CountBucket, error) {
	return nil, ErrReportingUnavailable
}
