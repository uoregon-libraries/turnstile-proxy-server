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

// Store is a database abstraction that provides methods for storing and
// retrieving request logs.
type Store struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewStore creates a new Store and initializes the database schema if it
// doesn't already exist.
func NewStore(dataSourceName string, logger *slog.Logger) (*Store, error) {
	db, err := sql.Open("mysql", dataSourceName)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}

	var store = &Store{db: db, logger: logger}
	if err := store.migrate(); err != nil {
		return nil, err
	}
	return store, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
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

// LogRequest logs a request to the database.
func (s *Store) LogRequest(log RequestLog) error {
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
