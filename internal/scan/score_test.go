package scan

import (
	"testing"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

func res(fp string, r model.Result, sev model.Severity) model.CheckResult {
	return model.CheckResult{Fingerprint: fp, Result: r, Severity: sev}
}

func TestComputeTotals(t *testing.T) {
	cases := []struct {
		name    string
		results []model.CheckResult
		want    Totals
	}{
		{"all pass", []model.CheckResult{res("a", model.Pass, model.SeverityHigh)}, Totals{100, 1, 1, 0}},
		{"one of each severity fails", []model.CheckResult{
			res("a", model.Fail, model.SeverityCritical), res("b", model.Fail, model.SeverityHigh),
			res("c", model.Fail, model.SeverityMedium), res("d", model.Fail, model.SeverityLow),
			res("e", model.Pass, model.SeverityLow), res("f", model.Unknown, model.SeverityCritical),
		}, Totals{Score: 100 - 15 - 8 - 3 - 1, Total: 6, Assessed: 5, Unknown: 1}},
		{"floor at zero", []model.CheckResult{
			res("a", model.Fail, model.SeverityCritical), res("b", model.Fail, model.SeverityCritical),
			res("c", model.Fail, model.SeverityCritical), res("d", model.Fail, model.SeverityCritical),
			res("e", model.Fail, model.SeverityCritical), res("f", model.Fail, model.SeverityCritical),
			res("g", model.Fail, model.SeverityCritical),
		}, Totals{0, 7, 7, 0}},
		{"unknown costs nothing", []model.CheckResult{res("a", model.Unknown, model.SeverityCritical)}, Totals{100, 1, 0, 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := computeTotals(tc.results); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestInsufficientCoverageHidesScore(t *testing.T) {
	// 11 of 14 assessed (79%) -> shown; 8 of 14 (57%) -> "Insufficient coverage".
	ok := model.Scan{Status: model.ScanSucceeded, ChecksTotal: 14, ChecksAssessed: 11}
	low := model.Scan{Status: model.ScanSucceeded, ChecksTotal: 14, ChecksAssessed: 8}
	if !ok.ScoreVisible() || low.ScoreVisible() {
		t.Fatalf("79%% visible=%v, 57%% visible=%v", ok.ScoreVisible(), low.ScoreVisible())
	}
}

func TestComparability(t *testing.T) {
	prevScan := &model.Scan{ChecksTotal: 10, ChecksAssessed: 10}
	prev := map[string]model.CheckResult{
		"a": res("a", model.Fail, model.SeverityCritical),
		"b": res("b", model.Pass, model.SeverityLow),
	}
	cases := []struct {
		name string
		cur  []model.CheckResult
		scan model.Scan
		want bool
	}{
		{"same visibility", []model.CheckResult{res("a", model.Fail, model.SeverityCritical)},
			model.Scan{ChecksTotal: 10, ChecksAssessed: 10}, true},
		// The score goes UP here (critical fail no longer counted) - still not comparable.
		{"fail became unknown", []model.CheckResult{res("a", model.Unknown, model.SeverityCritical)},
			model.Scan{ChecksTotal: 10, ChecksAssessed: 10}, false},
		{"pass became unknown, small drop", []model.CheckResult{res("b", model.Unknown, model.SeverityLow)},
			model.Scan{ChecksTotal: 100, ChecksAssessed: 96}, true},
		{"coverage dropped more than 5 points", nil,
			model.Scan{ChecksTotal: 100, ChecksAssessed: 94}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isComparable(tc.cur, prev, prevScan, tc.scan); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	if !isComparable(nil, nil, nil, model.Scan{}) {
		t.Fatal("the first scan is comparable by definition")
	}
}

func TestBuildAssetsCarryForward(t *testing.T) {
	prev := []model.Asset{
		{Kind: model.KindRepo, ExternalID: "1", Name: "kept"},
		{Kind: model.KindRepo, ExternalID: "2", Name: "missing"},
		{Kind: model.KindWebhook, ExternalID: "9", Name: "gone"},
	}
	collected := []model.Asset{{Kind: model.KindRepo, ExternalID: "1", Name: "kept"}}
	cols := completeCollections(map[model.AssetKind]model.Collection{
		model.KindRepo:    {Status: model.CollectionPartial},
		model.KindWebhook: {Status: model.CollectionComplete},
	})
	out := buildAssets("s2", collected, prev, cols)
	got := map[string]bool{}
	for _, a := range out {
		got[a.Name] = a.CarriedForward
	}
	if len(out) != 2 || got["kept"] || !got["missing"] {
		t.Fatalf("got %v", got)
	}
	if _, ok := got["gone"]; ok {
		t.Fatal("complete listing: the webhook is really removed")
	}
	// Kinds the connector didn't report are treated as failed (never complete).
	if cols[model.KindUser].Status != model.CollectionFailed {
		t.Fatal("unreported kind must be failed")
	}
}
