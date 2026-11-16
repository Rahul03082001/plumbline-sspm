package scan

import (
	"context"
	"testing"

	"github.com/Rahul03082001/plumbline-sspm/internal/connector"
	"github.com/Rahul03082001/plumbline-sspm/internal/model"
	"github.com/Rahul03082001/plumbline-sspm/internal/store"
)

// step turns a short label into a snapshot:
//
//	fail / pass / unknown  -> the repo is listed (complete listing)
//	missing(partial)       -> the repo is absent and the repo listing was partial
//	missing(complete)      -> the repo is absent and the listing was complete
func step(label string) connector.Snapshot {
	switch label {
	case "missing(partial)":
		return connector.Snapshot{Collections: withRepoStatus(model.CollectionPartial)}
	case "missing(complete)":
		return connector.Snapshot{Collections: allComplete()}
	default:
		return connector.Snapshot{Assets: []model.Asset{repo(label)}, Collections: allComplete()}
	}
}

// driftState reports what drift says about the one fingerprint in play.
func driftState(d Drift, fp string) string {
	for _, it := range d.New {
		if it.Fingerprint == fp {
			if it.Regressed {
				return "regressed"
			}
			return "new"
		}
	}
	for name, list := range map[string][]DriftItem{
		"resolved": d.Resolved, "removed": d.ResolvedAssetRemoved, "unverifiable": d.Unverifiable} {
		for _, it := range list {
			if it.Fingerprint == fp {
				return name
			}
		}
	}
	if d.PersistingCount > 0 {
		return "persisting"
	}
	return "none"
}

// TestMultiScanSequences is the table from spec section 11. For every step it
// checks the drift state, the "first seen" scan, and whether the asset is
// still present and counted in checks_total.
func TestMultiScanSequences(t *testing.T) {
	type want struct {
		state     string
		firstSeen int  // 1-based scan index of first_failed_scan_id; 0 = none
		present   bool // asset still in this scan (and in checks_total)
	}
	cases := []struct {
		name  string
		steps []string
		want  []want
	}{
		{"fail→unknown→unknown→fail is persisting, not new",
			[]string{"fail", "unknown", "unknown", "fail"},
			[]want{{"new", 1, true}, {"unverifiable", 1, true}, {"unverifiable", 1, true}, {"persisting", 1, true}}},
		{"fail→unknown→unknown→pass is resolved",
			[]string{"fail", "unknown", "unknown", "pass"},
			[]want{{"new", 1, true}, {"unverifiable", 1, true}, {"unverifiable", 1, true}, {"resolved", 0, true}}},
		{"pass→unknown→fail is regressed",
			[]string{"pass", "unknown", "fail"},
			[]want{{"none", 0, true}, {"none", 0, true}, {"regressed", 3, true}}},
		{"missing from partial listings stays carried forward",
			[]string{"fail", "missing(partial)", "missing(partial)", "missing(partial)"},
			[]want{{"new", 1, true}, {"unverifiable", 1, true}, {"unverifiable", 1, true}, {"unverifiable", 1, true}}},
		{"missing after a complete listing is resolved (asset removed)",
			[]string{"fail", "missing(partial)", "missing(complete)"},
			[]want{{"new", 1, true}, {"unverifiable", 1, true}, {"removed", 0, false}}},
		{"spec variant: partial, partial, then complete",
			[]string{"fail", "missing(partial)", "missing(partial)", "missing(complete)"},
			[]want{{"new", 1, true}, {"unverifiable", 1, true}, {"unverifiable", 1, true}, {"removed", 0, false}}},
		{"fail→pass→fail starts a new run at scan 3",
			[]string{"fail", "pass", "fail"},
			[]want{{"new", 1, true}, {"resolved", 0, true}, {"regressed", 3, true}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			conn := &scripted{}
			for _, s := range tc.steps {
				conn.steps = append(conn.steps, step(s))
			}
			svc, st := newHarness(t, builtinRules(t, "SL-REPO-001"), conn)
			fp := model.Fingerprint(testConn, "SL-REPO-001", model.KindRepo, "100")

			var scanIDs []string
			for i, w := range tc.want {
				sc := runScan(t, svc, testConn)
				if sc.Status != model.ScanSucceeded {
					t.Fatalf("step %d: scan %s (%s)", i+1, sc.Status, sc.Error)
				}
				scanIDs = append(scanIDs, sc.ID)

				d, err := svc.Drift(ctx, sc.ID)
				if err != nil {
					t.Fatal(err)
				}
				if got := driftState(d, fp); got != w.state {
					t.Errorf("step %d (%s): drift = %s, want %s", i+1, tc.steps[i], got, w.state)
				}

				results, _ := st.Results(ctx, sc.ID, store.ResultFilter{})
				present := len(results) == 1
				if present != w.present {
					t.Errorf("step %d: asset present = %v, want %v", i+1, present, w.present)
				}
				if present != (sc.ChecksTotal == 1) {
					t.Errorf("step %d: carried-forward asset must stay in checks_total (got %d)", i+1, sc.ChecksTotal)
				}
				if present {
					gotFirst := 0
					for j, id := range scanIDs {
						if id == results[0].FirstFailedScanID {
							gotFirst = j + 1
						}
					}
					if gotFirst != w.firstSeen {
						t.Errorf("step %d: first seen = scan %d, want scan %d", i+1, gotFirst, w.firstSeen)
					}
				}
			}
		})
	}
}

// TestCarriedForwardEvidence checks a carried-forward result explains itself.
func TestCarriedForwardEvidence(t *testing.T) {
	conn := &scripted{steps: []connector.Snapshot{step("fail"), step("missing(partial)")}}
	svc, st := newHarness(t, builtinRules(t, "SL-REPO-001"), conn)
	runScan(t, svc, testConn)
	sc := runScan(t, svc, testConn)
	rs, _ := st.Results(context.Background(), sc.ID, store.ResultFilter{})
	if len(rs) != 1 {
		t.Fatal("asset must be carried forward")
	}
	r := rs[0]
	if !r.Asset.CarriedForward || r.Result != model.Unknown || r.Evidence.Reason != model.ReasonCollectionIncomplete ||
		r.Evidence.CollectionStatus != string(model.CollectionPartial) || r.LastDefinitive != model.Fail {
		t.Fatalf("got %+v / asset %+v", r.CheckResult, r.Asset)
	}
	if len(r.Asset.Attributes) != 0 {
		t.Fatal("carried-forward assets have empty attributes")
	}
}
