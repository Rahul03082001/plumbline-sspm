package scan

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Rahul03082001/plumbline-sspm/internal/connector"
	"github.com/Rahul03082001/plumbline-sspm/internal/model"
	"github.com/Rahul03082001/plumbline-sspm/internal/rules"
	"github.com/Rahul03082001/plumbline-sspm/internal/store"
)

const testConn = "github:test-org"

// scripted is a fake connector that returns pre-baked snapshots in order.
// It can also return an error or panic at a given step.
type scripted struct {
	mu      sync.Mutex
	steps   []connector.Snapshot
	errs    map[int]error
	panicAt int // 1-based step; 0 = never
	i       int
}

func (s *scripted) Collect(ctx context.Context) (connector.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.i++
	if s.panicAt == s.i {
		panic("connector exploded")
	}
	if err := s.errs[s.i]; err != nil {
		return connector.Snapshot{}, err
	}
	return s.steps[(s.i-1)%len(s.steps)], nil
}

func builtinRules(t *testing.T, ids ...string) []model.Rule {
	t.Helper()
	all, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) == 0 {
		return all
	}
	var out []model.Rule
	for _, r := range all {
		for _, id := range ids {
			if r.ID == id {
				out = append(out, r)
			}
		}
	}
	return out
}

// newHarness builds a Service on a fresh database WITHOUT starting workers.
// Tests drive scans one at a time with runScan, so every step is deterministic.
func newHarness(t *testing.T, ruleset []model.Rule, conn connector.Connector) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := New(st, ruleset, Options{})
	if err := svc.Register(context.Background(), model.Connection{
		ID: testConn, Provider: "github", DisplayName: "test", Mode: model.ModeLive}, conn); err != nil {
		t.Fatal(err)
	}
	return svc, st
}

// runScan requests a scan and processes it synchronously on this goroutine.
func runScan(t *testing.T, svc *Service, connID string) model.Scan {
	t.Helper()
	sc, err := svc.RequestScan(context.Background(), connID)
	if err != nil {
		t.Fatal(err)
	}
	svc.process(<-svc.queue)
	got, err := svc.GetScan(context.Background(), sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func allComplete() map[model.AssetKind]model.Collection {
	m := map[model.AssetKind]model.Collection{}
	for _, k := range model.AllKinds {
		m[k] = model.Collection{Kind: k, Status: model.CollectionComplete}
	}
	return m
}

func withRepoStatus(st model.CollectionStatus) map[model.AssetKind]model.Collection {
	m := allComplete()
	m[model.KindRepo] = model.Collection{Kind: model.KindRepo, Status: st, Reason: model.ReasonPermissionDenied}
	return m
}

// repo builds the single repo asset used in sequence tests.
// protected: "fail" (false), "pass" (true) or "unknown" (absent, 403).
func repo(state string) model.Asset {
	a := model.Asset{Kind: model.KindRepo, ExternalID: "100", Name: "legacy-scripts",
		Attributes: model.Attributes{"visibility": "public"}, Unknown: map[string]model.UnknownReason{}}
	switch state {
	case "fail":
		a.Attributes["default_branch_protected"] = false
	case "pass":
		a.Attributes["default_branch_protected"] = true
	case "unknown":
		a.Unknown["default_branch_protected"] = model.UnknownReason{Reason: model.ReasonPermissionDenied}
	}
	return a
}
