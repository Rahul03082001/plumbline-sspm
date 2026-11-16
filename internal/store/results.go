package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

// ResultRow is a check result joined with the asset it was evaluated on.
type ResultRow struct {
	model.CheckResult // embedded struct: its fields are promoted onto ResultRow
	Asset             model.Asset
	FirstFailedAt     *time.Time // created_at of FirstFailedScanID, for "first seen"
}

// ResultFilter narrows Results. Zero values mean "no filter".
type ResultFilter struct {
	Result   model.Result
	Severity model.Severity
}

const resultSelect = `SELECT r.id, r.scan_id, r.rule_id, r.asset_id, r.fingerprint, r.result,
	r.severity, r.evidence, r.last_definitive, r.last_definitive_scan_id, r.first_failed_scan_id,
	a.id, a.scan_id, a.kind, a.external_id, a.name, a.attributes, a.carried_forward,
	ff.created_at
	FROM check_results r
	JOIN assets a ON a.id = r.asset_id
	LEFT JOIN scans ff ON ff.id = r.first_failed_scan_id`

// Results returns the check results of a scan, most severe first.
func (s *Store) Results(ctx context.Context, scanID string, f ResultFilter) ([]ResultRow, error) {
	query := resultSelect + ` WHERE r.scan_id = ?`
	args := []any{scanID}
	if f.Result != "" {
		query += ` AND r.result = ?`
		args = append(args, string(f.Result))
	}
	if f.Severity != "" {
		query += ` AND r.severity = ?`
		args = append(args, string(f.Severity))
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ResultRow
	for rows.Next() {
		r, err := scanResultRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	SortResults(out)
	return out, nil
}

// SortResults orders by severity, then rule, then asset name, so every page
// and API response lists results in the same stable order.
func SortResults(rs []ResultRow) {
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() < b.Severity.Rank()
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Asset.Name < b.Asset.Name
	})
}

// GetResult returns one check result with its asset, or ErrNotFound.
func (s *Store) GetResult(ctx context.Context, id string) (ResultRow, error) {
	r, err := scanResultRow(s.db.QueryRowContext(ctx, resultSelect+` WHERE r.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ResultRow{}, ErrNotFound
	}
	return r, err
}

// Collections returns the per-kind collection status of a scan.
func (s *Store) Collections(ctx context.Context, scanID string) ([]model.Collection, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT asset_kind, status, reason FROM collections WHERE scan_id = ? ORDER BY asset_kind`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Collection
	for rows.Next() {
		var c model.Collection
		var kind, status string
		var reason sql.NullString
		if err := rows.Scan(&kind, &status, &reason); err != nil {
			return nil, err
		}
		c.Kind, c.Status, c.Reason = model.AssetKind(kind), model.CollectionStatus(status), reason.String
		out = append(out, c)
	}
	return out, rows.Err()
}

func scanResultRow(r rowScanner) (ResultRow, error) {
	var row ResultRow
	var result, severity, evidence, kind, attrs string
	var lastDef, lastDefScan, firstFailed sql.NullString
	var carried int
	var firstFailedAt dbTime
	err := r.Scan(&row.ID, &row.ScanID, &row.RuleID, &row.AssetID, &row.Fingerprint, &result,
		&severity, &evidence, &lastDef, &lastDefScan, &firstFailed,
		&row.Asset.ID, &row.Asset.ScanID, &kind, &row.Asset.ExternalID, &row.Asset.Name, &attrs, &carried,
		&firstFailedAt)
	if err != nil {
		return row, err
	}
	row.FirstFailedAt = firstFailedAt.ptr()
	row.Result = model.Result(result)
	row.Severity = model.Severity(severity)
	row.LastDefinitive = model.Result(lastDef.String)
	row.LastDefinitiveScanID = lastDefScan.String
	row.FirstFailedScanID = firstFailed.String
	if err := json.Unmarshal([]byte(evidence), &row.Evidence); err != nil {
		return row, fmt.Errorf("decode evidence: %w", err)
	}
	row.Asset.Kind = model.AssetKind(kind)
	row.Asset.CarriedForward = carried == 1
	row.Asset.Attributes, row.Asset.Unknown, err = model.DecodeAttributes(attrs)
	return row, err
}

// ---- transaction methods used by the scan publisher -----------------------

// LatestSucceeded is the transaction-scoped version of Store.LatestSucceeded.
// Reading it inside the publish transaction guarantees we compare against
// exactly the scan that was current when we published.
func (t *Tx) LatestSucceeded(ctx context.Context, connectionID string) (model.Scan, error) {
	return latestSucceeded(ctx, t.tx, connectionID)
}

// Assets returns every asset stored for a scan (including carried-forward).
func (t *Tx) Assets(ctx context.Context, scanID string) ([]model.Asset, error) {
	rows, err := t.tx.QueryContext(ctx, `SELECT id, scan_id, kind, external_id, name, attributes,
		carried_forward FROM assets WHERE scan_id = ? ORDER BY kind, external_id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Asset
	for rows.Next() {
		var a model.Asset
		var kind, attrs string
		var carried int
		if err := rows.Scan(&a.ID, &a.ScanID, &kind, &a.ExternalID, &a.Name, &attrs, &carried); err != nil {
			return nil, err
		}
		a.Kind, a.CarriedForward = model.AssetKind(kind), carried == 1
		if a.Attributes, a.Unknown, err = model.DecodeAttributes(attrs); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Results returns every check result of a scan, keyed by fingerprint.
func (t *Tx) Results(ctx context.Context, scanID string) (map[string]model.CheckResult, error) {
	rows, err := t.tx.QueryContext(ctx, resultSelect+` WHERE r.scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]model.CheckResult{}
	for rows.Next() {
		r, err := scanResultRow(rows)
		if err != nil {
			return nil, err
		}
		out[r.Fingerprint] = r.CheckResult
	}
	return out, rows.Err()
}

// InsertCollection records one kind's collection status.
func (t *Tx) InsertCollection(ctx context.Context, scanID string, c model.Collection) error {
	_, err := t.tx.ExecContext(ctx,
		`INSERT INTO collections (scan_id, asset_kind, status, reason) VALUES (?, ?, ?, ?)`,
		scanID, string(c.Kind), string(c.Status), nullString(c.Reason))
	return err
}

// InsertAsset stores one asset.
func (t *Tx) InsertAsset(ctx context.Context, a model.Asset) error {
	attrs, err := model.EncodeAttributes(a.Attributes, a.Unknown)
	if err != nil {
		return err
	}
	_, err = t.tx.ExecContext(ctx, `INSERT INTO assets
		(id, scan_id, kind, external_id, name, attributes, carried_forward) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.ScanID, string(a.Kind), a.ExternalID, a.Name, attrs, boolInt(a.CarriedForward))
	return err
}

// InsertResult stores one check result.
func (t *Tx) InsertResult(ctx context.Context, r model.CheckResult) error {
	ev, err := json.Marshal(r.Evidence)
	if err != nil {
		return err
	}
	_, err = t.tx.ExecContext(ctx, `INSERT INTO check_results
		(id, scan_id, rule_id, asset_id, fingerprint, result, severity, evidence,
		 last_definitive, last_definitive_scan_id, first_failed_scan_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.ScanID, r.RuleID, r.AssetID, r.Fingerprint, string(r.Result), string(r.Severity),
		string(ev), nullString(string(r.LastDefinitive)), nullString(r.LastDefinitiveScanID),
		nullString(r.FirstFailedScanID))
	return err
}

// FinishScan marks a running scan succeeded and stores its score/coverage.
// It fails if the scan is no longer running (for example, shutdown already
// marked it failed), which rolls the whole publish back.
func (t *Tx) FinishScan(ctx context.Context, sc model.Scan) error {
	res, err := t.tx.ExecContext(ctx, `UPDATE scans SET status = 'succeeded', score = ?,
		checks_total = ?, checks_assessed = ?, checks_unknown = ?, comparable = ?, finished_at = ?
		WHERE id = ? AND status = 'running'`,
		sc.Score, sc.ChecksTotal, sc.ChecksAssessed, sc.ChecksUnknown, boolInt(sc.Comparable),
		formatTime(time.Now()), sc.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("scan %s is not running", sc.ID)
	}
	return nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
