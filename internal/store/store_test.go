package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

// newTestStore opens a fresh database in a temp dir that Go deletes after
// the test. Each test gets its own file, so tests can't affect each other.
func newTestStore(t *testing.T) *Store {
	t.Helper() // makes failures point at the caller's line
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.UpsertConnection(context.Background(), model.Connection{
		ID: "github:acme-demo", Provider: "github", DisplayName: "Acme", Mode: model.ModeSimulated,
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMigrationsAreIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.db")
	for i := 0; i < 2; i++ { // opening twice must not re-apply migrations
		s, err := Open(context.Background(), path)
		if err != nil {
			t.Fatalf("open #%d: %v", i, err)
		}
		s.Close()
	}
}

func TestSecondActiveScanIsRejected(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	first, err := s.CreateScan(ctx, "github:acme-demo")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateScan(ctx, "github:acme-demo")
	var active *ActiveScanError
	if !errors.As(err, &active) {
		t.Fatalf("want ActiveScanError, got %v", err)
	}
	if active.ScanID != first.ID {
		t.Fatalf("409 must point at the active scan %s, got %s", first.ID, active.ScanID)
	}
	// Once the first scan finishes, a new one is allowed again.
	if err := s.MarkFailed(ctx, first.ID, "test", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateScan(ctx, "github:acme-demo"); err != nil {
		t.Fatalf("new scan after finish: %v", err)
	}
}

func TestRawInsertOfTwoQueuedScansFailsOnUniqueIndex(t *testing.T) {
	// Proves the database itself enforces the rule, not just our Go code.
	ctx := context.Background()
	s := newTestStore(t)
	ins := `INSERT INTO scans (id, connection_id, status, created_at) VALUES (?, 'github:acme-demo', 'queued', '2026-01-01T00:00:00.000000000Z')`
	if _, err := s.db.ExecContext(ctx, ins, "a"); err != nil {
		t.Fatal(err)
	}
	_, err := s.db.ExecContext(ctx, ins, "b")
	if !isUniqueViolation(err) {
		t.Fatalf("want unique violation, got %v", err)
	}
}

func TestStartupRecoveryMarksActiveScansFailed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "r.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.UpsertConnection(ctx, model.Connection{ID: "c1", Provider: "github", DisplayName: "c1", Mode: model.ModeLive})
	sc, err := s.CreateScan(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkRunning(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	s.Close() // simulate a crash: the scan is left "running"

	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	n, err := s2.RecoverInterrupted(ctx)
	if err != nil || n != 1 {
		t.Fatalf("recovered %d, err %v", n, err)
	}
	got, _ := s2.GetScan(ctx, sc.ID)
	if got.Status != model.ScanFailed || got.Error != "interrupted" {
		t.Fatalf("got %s/%q", got.Status, got.Error)
	}
}

func TestTxRollsBackOnError(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	sc, _ := s.CreateScan(ctx, "github:acme-demo")
	boom := errors.New("boom")
	err := s.WithTx(ctx, func(tx *Tx) error {
		if err := tx.InsertCollection(ctx, sc.ID, model.Collection{Kind: model.KindRepo, Status: model.CollectionComplete}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	cols, _ := s.Collections(ctx, sc.ID)
	if len(cols) != 0 {
		t.Fatal("insert must be rolled back")
	}
}
