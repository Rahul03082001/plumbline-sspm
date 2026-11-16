// Package store owns the SQLite database: opening it, applying migrations,
// and every SQL query. No other package writes SQL.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// The go:embed directive below copies the .sql files into the compiled binary, so the single
// static binary carries its own schema. No files to ship next to it.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ActiveScanError is returned by CreateScan when the connection already has a
// queued or running scan. It carries that scan's ID so the API can return it
// with the 409 Conflict.
type ActiveScanError struct{ ScanID string }

func (e *ActiveScanError) Error() string { return "a scan is already active: " + e.ScanID }

// Store wraps the database handle.
type Store struct {
	db *sql.DB
}

// querier is satisfied by both *sql.DB and *sql.Tx. Writing helpers against
// this small interface lets the same query code run inside or outside a
// transaction (Go interfaces are satisfied implicitly: no "implements").
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Open opens (or creates) the SQLite file and applies migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	// Pragmas run on every new connection:
	//   journal_mode(WAL)  readers don't block the writer and vice versa
	//   foreign_keys(1)    SQLite has FK enforcement OFF by default
	//   busy_timeout(5000) wait up to 5s for a lock instead of failing at once
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// One connection = one writer at a time, so we never see SQLITE_BUSY from
	// two of our own goroutines fighting. Reads queue behind it; that's fine
	// at demo scale. See DECISIONS.md.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Ping checks the database is reachable (used by /readyz).
func (s *Store) Ping(ctx context.Context) error {
	var one int
	return s.db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
}

// migrate applies every embedded migration that hasn't been applied yet,
// each in its own transaction, in filename order.
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	names, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		version := strings.TrimSuffix(strings.TrimPrefix(name, "migrations/"), ".sql")
		var exists int
		err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version).Scan(&exists)
		if err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		body, err := migrationsFS.ReadFile(name)
		if err != nil {
			return err
		}
		err = s.WithTx(ctx, func(tx *Tx) error {
			if _, err := tx.tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("apply %s: %w", name, err)
			}
			_, err := tx.tx.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
				version, formatTime(time.Now()))
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// Tx is a database transaction used by the scan publisher. Everything done
// through one Tx becomes visible all at once on commit, or not at all.
type Tx struct {
	tx *sql.Tx
}

// WithTx runs fn inside a transaction. If fn returns an error (or panics),
// the transaction is rolled back; otherwise it is committed.
func (s *Store) WithTx(ctx context.Context, fn func(*Tx) error) (err error) {
	sqlTx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	// defer runs when WithTx returns, even on panic. Rollback after a
	// successful Commit is a harmless no-op, so we can always call it.
	defer func() {
		if p := recover(); p != nil {
			_ = sqlTx.Rollback()
			panic(p) // re-panic so the caller's recover sees it
		}
		if err != nil {
			_ = sqlTx.Rollback()
		}
	}()
	if err = fn(&Tx{tx: sqlTx}); err != nil {
		return err
	}
	return sqlTx.Commit()
}

// ---- time helpers ---------------------------------------------------------

// timeLayout is fixed-width (always 9 fractional digits, always UTC "Z"), so
// sorting the text sorts chronologically.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func formatTimePtr(t *time.Time) any {
	if t == nil {
		return nil // stored as SQL NULL
	}
	return formatTime(*t)
}

// dbTime implements sql.Scanner so we can read TIMESTAMP columns whether the
// driver hands us a time.Time (it parses TIMESTAMP-declared columns) or text.
type dbTime struct {
	T     time.Time
	Valid bool
}

func (d *dbTime) Scan(v any) error {
	switch x := v.(type) {
	case nil:
		d.Valid = false
		return nil
	case time.Time:
		d.T, d.Valid = x.UTC(), true
		return nil
	case string:
		return d.parse(x)
	case []byte:
		return d.parse(string(x))
	}
	return fmt.Errorf("dbTime: unsupported type %T", v)
}

func (d *dbTime) parse(s string) error {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return fmt.Errorf("dbTime: %w", err)
	}
	d.T, d.Valid = t.UTC(), true
	return nil
}

func (d dbTime) ptr() *time.Time {
	if !d.Valid {
		return nil
	}
	t := d.T
	return &t
}

// isUniqueViolation reports whether err is SQLite's UNIQUE constraint error.
func isUniqueViolation(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE
}
