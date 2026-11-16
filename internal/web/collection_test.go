package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/connector"
	"github.com/Rahul03082001/plumbline-sspm/internal/model"
	"github.com/Rahul03082001/plumbline-sspm/internal/rules"
	"github.com/Rahul03082001/plumbline-sspm/internal/scan"
	"github.com/Rahul03082001/plumbline-sspm/internal/store"
)

type incompleteCollector struct{}

func (incompleteCollector) Collect(context.Context) (connector.Snapshot, error) {
	cols := map[model.AssetKind]model.Collection{}
	for _, kind := range model.AllKinds {
		cols[kind] = model.Collection{Kind: kind, Status: model.CollectionComplete}
	}
	cols[model.KindRepo] = model.Collection{Kind: model.KindRepo, Status: model.CollectionFailed, Reason: model.ReasonPermissionDenied}
	return connector.Snapshot{Collections: cols, Assets: []model.Asset{{Kind: model.KindOrg, ExternalID: "1", Name: "test-org",
		Attributes: model.Attributes{"two_factor_required": true, "default_repo_permission": "read", "members_can_create_public_repos": false}}}}, nil
}

// Exercise the real database, workers, API and templates without a TCP listener.
func TestIncompleteCollectionOnDashboardAndAPI(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	svc := scan.New(st, rs, scan.Options{})
	const connID = "github:incomplete"
	if err := svc.Register(ctx, model.Connection{ID: connID, Provider: "github", DisplayName: "Test", Mode: model.ModeLive}, incompleteCollector{}); err != nil {
		t.Fatal(err)
	}
	svc.Start()
	defer func() {
		shutdown, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		svc.Shutdown(shutdown)
	}()
	sc, err := svc.RequestScan(ctx, connID)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for sc.Status.Active() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		sc, err = svc.GetScan(ctx, sc.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if sc.Status != model.ScanSucceeded {
		t.Fatalf("scan did not complete: %+v", sc)
	}
	h, err := New(Options{Service: svc})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/c/" + connID} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		body := w.Body.String()
		if w.Code != 200 || !strings.Contains(body, "Incomplete collection") || !strings.Contains(body, "repo: failed") ||
			!strings.Contains(body, "permission denied") || strings.Contains(body, "Score 100") || strings.Contains(body, `title="Coverage 100%"`) {
			t.Fatalf("%s misrepresented incomplete collection: status=%d body=%s", path, w.Code, body)
		}
	}
	for _, path := range []string{"/api/scans/" + sc.ID, "/api/connections"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		var got scanJSON
		if path == "/api/connections" {
			var envelope struct {
				Connections []connectionJSON `json:"connections"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil || len(envelope.Connections) != 1 || envelope.Connections[0].LatestScan == nil {
				t.Fatalf("connections response: %s, %v", w.Body.String(), err)
			}
			got = *envelope.Connections[0].LatestScan
		} else if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || got.Score != nil || got.CoveragePct != nil || got.InventoryComplete == nil || *got.InventoryComplete ||
			got.KnownChecksCoveragePct == nil || *got.KnownChecksCoveragePct != 100 || got.Comparable == nil || *got.Comparable {
			t.Fatalf("%s misrepresented inventory: %s", path, w.Body.String())
		}
	}
}

func TestTrendBreaksAcrossIncompleteInventory(t *testing.T) {
	complete := model.Scan{Status: model.ScanSucceeded, Comparable: true, Score: 100, ChecksTotal: 3, ChecksAssessed: 3}
	incomplete := complete
	incomplete.CollectionIncomplete = true
	v := newSparkView([]model.Scan{complete, complete, incomplete, complete, complete})
	if len(v.CoverageSegments) != 2 || len(v.ScoreSegments) != 2 || len(v.ScoreDots) != 4 {
		t.Fatalf("trend must not connect across unknown inventory: %+v", v)
	}
}
