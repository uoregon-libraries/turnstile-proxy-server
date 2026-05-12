// Package db provides primitives for logging to our database
package db

import (
	"database/sql"
	"log/slog"
	"time"

	// Import for side effects
	_ "github.com/go-sql-driver/mysql"
)

// RequestLog represents a single entry in our request log database.
type RequestLog struct {
	ClientIP              string
	Timestamp             time.Time
	URL                   string
	HadValidToken         bool
	WasPresentedChallenge bool
	ChallengeSucceeded    bool
}

// Store records request logs. Implementations may persist to a database or
// silently discard entries (see [NewNoopStore]).
type Store interface {
	LogRequest(log RequestLog) error
	Close() error
}

type mysqlStore struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewStore opens a MariaDB-backed [Store], pinging the server and creating
// the request log table if it doesn't already exist.
func NewStore(dataSourceName string, logger *slog.Logger) (Store, error) {
	db, err := sql.Open("mysql", dataSourceName)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}

	var store = &mysqlStore{db: db, logger: logger}
	if err := store.migrate(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *mysqlStore) Close() error {
	return s.db.Close()
}

func (s *mysqlStore) migrate() error {
	var query = `
	CREATE TABLE IF NOT EXISTS request_logs(
		id INTEGER PRIMARY KEY AUTO_INCREMENT,
		client_ip TEXT,
		timestamp DATETIME(6),
		url TEXT,
		had_valid_token TINYINT(1),
		was_presented_challenge TINYINT(1),
		challenge_succeeded TINYINT(1)
	);
	`
	_, err := s.db.Exec(query)
	return err
}

func (s *mysqlStore) LogRequest(log RequestLog) error {
	var query = `
	INSERT INTO request_logs (client_ip, timestamp, url, had_valid_token, was_presented_challenge, challenge_succeeded)
	VALUES (?, ?, ?, ?, ?, ?);
	`
	_, err := s.db.Exec(query, log.ClientIP, log.Timestamp, log.URL, log.HadValidToken, log.WasPresentedChallenge, log.ChallengeSucceeded)
	if err != nil {
		s.logger.Error("Could not log request to database", "error", err)
	}
	return err
}

type noopStore struct{}

// NewNoopStore returns a [Store] that discards every log entry. Use it when
// no DATABASE_DSN is configured.
func NewNoopStore() Store { return noopStore{} }

func (noopStore) LogRequest(RequestLog) error { return nil }
func (noopStore) Close() error                { return nil }
