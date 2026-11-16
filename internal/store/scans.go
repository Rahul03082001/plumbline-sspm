package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

// Derive completeness from the atomically published collections so existing
// databases and historical scans get the same protection without a migration.
var scanColumns = fmt.Sprintf(`id, connection_id, status, error, retry_after, score, checks_total,
	checks_assessed, checks_unknown, comparable, created_at, started_at, finished_at,
	(SELECT COUNT(*) FROM collections WHERE scan_id = scans.id AND status = 'complete') <> %d AS collection_incomplete`, len(model.AllKinds))

// CreateScan inserts a queued scan. If the connection already has an active
// scan, the partial unique index rejects the insert and we return
// *ActiveScanError with the active scan's ID.
func (s *Store) CreateScan(ctx context.Context, connectionID string) (model.Scan, error) {
	if _, err := s.GetConnection(ctx, connectionID); err != nil {
		return model.Scan{}, err
	}
	scan := model.Scan{
		ID:           model.NewID(),
		ConnectionID: connectionID,
		Status:       model.ScanQueued,
		CreatedAt:    time.Now().UTC(),
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scans (id, connection_id, status, created_at) VALUES (?, ?, 'queued', ?)`,
		scan.ID, scan.ConnectionID, formatTime(scan.CreatedAt))
	if isUniqueViolation(err) {
		active, aerr := s.ActiveScan(ctx, connectionID)
		if aerr != nil {
			return model.Scan{}, fmt.Errorf("find active scan: %w", aerr)
		}
		return model.Scan{}, &ActiveScanError{ScanID: active.ID}
	}
	if err != nil {
		return model.Scan{}, err
	}
	return scan, nil
}

// MarkRunning moves a queued scan to running.
func (s *Store) MarkRunning(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE scans SET status = 'running', started_at = ? WHERE id = ? AND status = 'queued'`,
		formatTime(time.Now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("scan %s is not queued", id)
	}
	return nil
}

// MarkFailed marks an active scan failed. Nothing is published for a failed
// scan, so the previous succeeded scan stays current.
func (s *Store) MarkFailed(ctx context.Context, id, errText string, retryAfter *time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE scans SET status = 'failed', error = ?, retry_after = ?, finished_at = ?
		WHERE id = ? AND status IN ('queued','running')`,
		errText, formatTimePtr(retryAfter), formatTime(time.Now()), id)
	return err
}

// RecoverInterrupted marks every queued/running scan as failed with
// error="interrupted". Called once at startup: if the process died mid-scan,
// those rows would otherwise block the connection forever (unique index).
func (s *Store) RecoverInterrupted(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE scans SET status = 'failed', error = 'interrupted', finished_at = ?
		WHERE status IN ('queued','running')`, formatTime(time.Now()))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GetScan returns one scan or ErrNotFound.
func (s *Store) GetScan(ctx context.Context, id string) (model.Scan, error) {
	return getScan(ctx, s.db, `SELECT `+scanColumns+` FROM scans WHERE id = ?`, id)
}

// ActiveScan returns the queued/running scan for a connection, or ErrNotFound.
func (s *Store) ActiveScan(ctx context.Context, connectionID string) (model.Scan, error) {
	return getScan(ctx, s.db, `SELECT `+scanColumns+` FROM scans
		WHERE connection_id = ? AND status IN ('queued','running')`, connectionID)
}

// LatestScan returns the newest scan of any status, or ErrNotFound.
func (s *Store) LatestScan(ctx context.Context, connectionID string) (model.Scan, error) {
	return getScan(ctx, s.db, `SELECT `+scanColumns+` FROM scans
		WHERE connection_id = ? ORDER BY created_at DESC LIMIT 1`, connectionID)
}

// LatestSucceeded returns the current (newest succeeded) scan, or ErrNotFound.
func (s *Store) LatestSucceeded(ctx context.Context, connectionID string) (model.Scan, error) {
	return latestSucceeded(ctx, s.db, connectionID)
}

func latestSucceeded(ctx context.Context, q querier, connectionID string) (model.Scan, error) {
	return getScan(ctx, q, `SELECT `+scanColumns+` FROM scans
		WHERE connection_id = ? AND status = 'succeeded' ORDER BY created_at DESC LIMIT 1`, connectionID)
}

// PreviousSucceeded returns the newest succeeded scan created before `scan`,
// or ErrNotFound. Drift for a scan is always computed against this one.
func (s *Store) PreviousSucceeded(ctx context.Context, scan model.Scan) (model.Scan, error) {
	return getScan(ctx, s.db, `SELECT `+scanColumns+` FROM scans
		WHERE connection_id = ? AND status = 'succeeded' AND created_at < ?
		ORDER BY created_at DESC LIMIT 1`, scan.ConnectionID, formatTime(scan.CreatedAt))
}

// NextSucceededAfter returns the first succeeded scan created after scanID.
// Used for "unverifiable since ..." on the finding page.
func (s *Store) NextSucceededAfter(ctx context.Context, connectionID, scanID string) (model.Scan, error) {
	return getScan(ctx, s.db, `SELECT `+scanColumns+` FROM scans
		WHERE connection_id = ? AND status = 'succeeded'
		  AND created_at > (SELECT created_at FROM scans WHERE id = ?)
		ORDER BY created_at ASC LIMIT 1`, connectionID, scanID)
}

// SucceededHistory returns up to limit succeeded scans, oldest first.
func (s *Store) SucceededHistory(ctx context.Context, connectionID string, limit int) ([]model.Scan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT * FROM (
		SELECT `+scanColumns+` FROM scans WHERE connection_id = ? AND status = 'succeeded'
		ORDER BY created_at DESC LIMIT ?) ORDER BY created_at ASC`, connectionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Scan
	for rows.Next() {
		sc, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// CountSucceeded returns how many scans of the connection have succeeded.
func (s *Store) CountSucceeded(ctx context.Context, connectionID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM scans WHERE connection_id = ? AND status = 'succeeded'`, connectionID).Scan(&n)
	return n, err
}

func getScan(ctx context.Context, q querier, query string, args ...any) (model.Scan, error) {
	sc, err := scanScan(q.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Scan{}, ErrNotFound
	}
	return sc, err
}

func scanScan(r rowScanner) (model.Scan, error) {
	var sc model.Scan
	var status string
	var errText sql.NullString
	var score, total, assessed, unknown, comparable sql.NullInt64
	var retryAfter, created, started, finished dbTime
	var incomplete bool
	err := r.Scan(&sc.ID, &sc.ConnectionID, &status, &errText, &retryAfter, &score, &total,
		&assessed, &unknown, &comparable, &created, &started, &finished, &incomplete)
	if err != nil {
		return sc, err
	}
	sc.Status = model.ScanStatus(status)
	sc.Error = errText.String
	sc.RetryAfter = retryAfter.ptr()
	sc.Score = int(score.Int64)
	sc.ChecksTotal = int(total.Int64)
	sc.ChecksAssessed = int(assessed.Int64)
	sc.ChecksUnknown = int(unknown.Int64)
	sc.CollectionIncomplete = incomplete
	sc.Comparable = comparable.Int64 == 1 && !incomplete
	sc.CreatedAt = created.T
	sc.StartedAt = started.ptr()
	sc.FinishedAt = finished.ptr()
	return sc, nil
}
