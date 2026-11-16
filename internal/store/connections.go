package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

// UpsertConnection inserts a connection or updates its display fields.
func (s *Store) UpsertConnection(ctx context.Context, c model.Connection) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO connections (id, provider, display_name, mode, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET provider = excluded.provider,
			display_name = excluded.display_name, mode = excluded.mode`,
		c.ID, c.Provider, c.DisplayName, string(c.Mode), formatTime(time.Now()))
	return err
}

// ListConnections returns all connections, live ones first.
func (s *Store) ListConnections(ctx context.Context) ([]model.Connection, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, provider, display_name, mode, created_at FROM connections
		ORDER BY CASE mode WHEN 'live' THEN 0 ELSE 1 END, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Connection
	for rows.Next() {
		c, err := scanConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetConnection returns one connection or ErrNotFound.
func (s *Store) GetConnection(ctx context.Context, id string) (model.Connection, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, provider, display_name, mode, created_at FROM connections WHERE id = ?`, id)
	c, err := scanConnection(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Connection{}, ErrNotFound
	}
	return c, err
}

// rowScanner is the shared shape of *sql.Row and *sql.Rows.
type rowScanner interface{ Scan(dest ...any) error }

func scanConnection(r rowScanner) (model.Connection, error) {
	var c model.Connection
	var mode string
	var created dbTime
	if err := r.Scan(&c.ID, &c.Provider, &c.DisplayName, &mode, &created); err != nil {
		return c, err
	}
	c.Mode = model.Mode(mode)
	c.CreatedAt = created.T
	return c, nil
}
