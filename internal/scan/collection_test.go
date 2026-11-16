package scan

import (
	"context"
	"testing"

	"github.com/Rahul03082001/plumbline-sspm/internal/connector"
	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

func TestIncompleteInventoryWithholdsScoreAndRecovers(t *testing.T) {
	for _, status := range []model.CollectionStatus{model.CollectionFailed, model.CollectionPartial, ""} {
		t.Run(string(status), func(t *testing.T) {
			cols := allComplete()
			if status == "" {
				delete(cols, model.KindRepo)
			} else {
				cols[model.KindRepo] = model.Collection{Kind: model.KindRepo, Status: status, Reason: model.ReasonPermissionDenied}
			}
			assets := []model.Asset{{Kind: model.KindOrg, ExternalID: "1", Name: "test-org",
				Attributes: model.Attributes{"two_factor_required": true, "default_repo_permission": "read", "members_can_create_public_repos": false}}}
			incomplete := connector.Snapshot{Assets: assets, Collections: cols}
			complete := connector.Snapshot{Assets: assets, Collections: allComplete()}
			svc, st := newHarness(t, builtinRules(t), &scripted{steps: []connector.Snapshot{incomplete, incomplete, complete, complete}})

			for i := 0; i < 4; i++ {
				sc := runScan(t, svc, testConn)
				if sc.Status != model.ScanSucceeded || sc.ChecksAssessed != 3 || sc.ChecksTotal != 3 {
					t.Fatalf("scan %d should retain the three assessed org checks: %+v", i+1, sc)
				}
				wantIncomplete := i < 2
				if sc.CollectionIncomplete != wantIncomplete || sc.ScoreVisible() == wantIncomplete {
					t.Fatalf("scan %d: incomplete=%v visible=%v", i+1, sc.CollectionIncomplete, sc.ScoreVisible())
				}
				if sc.Comparable != (i == 3) {
					t.Fatalf("scan %d: comparable=%v; only two complete inventories may be compared", i+1, sc.Comparable)
				}
			}
			history, err := st.SucceededHistory(context.Background(), testConn, 10)
			if err != nil || len(history) != 4 || !history[0].CollectionIncomplete || history[3].CollectionIncomplete {
				t.Fatalf("historical completeness was not restored from collections: %+v, %v", history, err)
			}
		})
	}
}
