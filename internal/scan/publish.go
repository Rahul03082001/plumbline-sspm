package scan

import (
	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

// This file holds the pure functions of the publish step: no database, no
// I/O. They are the core of the "trustworthy under failure" story, so they
// are written to be tested one at a time.

// completeCollections returns one Collection per asset kind. A kind the
// connector didn't report is treated as failed: if we don't know whether we
// saw everything, we must assume we didn't.
func completeCollections(got map[model.AssetKind]model.Collection) map[model.AssetKind]model.Collection {
	out := make(map[model.AssetKind]model.Collection, len(model.AllKinds))
	for _, k := range model.AllKinds {
		c, ok := got[k]
		if !ok {
			c = model.Collection{Kind: k, Status: model.CollectionFailed, Reason: "not_collected"}
		}
		c.Kind = k
		out[k] = c
	}
	return out
}

// buildAssets merges this scan's collected assets with carried-forward ones.
//
// Rule "missing is not removed": an asset from the previous scan that is
// missing now is only dropped if its kind's listing was COMPLETE. Otherwise
// it is carried forward with empty attributes (so every check on it is
// unknown), however many incomplete scans happen in a row. That keeps it in
// the coverage denominator, so coverage can't look better just because
// inaccessible assets disappeared.
func buildAssets(scanID string, collected, previous []model.Asset, cols map[model.AssetKind]model.Collection) []model.Asset {
	out := make([]model.Asset, 0, len(collected)+len(previous))
	seen := make(map[string]bool, len(collected))
	for _, a := range collected {
		if seen[a.Key()] {
			continue // defensive: a duplicate would break UNIQUE(scan_id, fingerprint)
		}
		seen[a.Key()] = true
		a.ID, a.ScanID, a.CarriedForward = model.NewID(), scanID, false
		out = append(out, a)
	}
	for _, p := range previous {
		if seen[p.Key()] {
			continue // still here
		}
		if cols[p.Kind].Status == model.CollectionComplete {
			continue // a complete listing says it's gone: really removed
		}
		seen[p.Key()] = true
		out = append(out, model.Asset{
			ID:             model.NewID(),
			ScanID:         scanID,
			Kind:           p.Kind,
			ExternalID:     p.ExternalID,
			Name:           p.Name,
			Attributes:     model.Attributes{},
			CarriedForward: true,
		})
	}
	return out
}

// applyHistory fills last_definitive, last_definitive_scan_id and
// first_failed_scan_id on each new result, from the previous scan's result
// with the same fingerprint.
//
// Rule "unknown doesn't reset history": an unknown result copies the
// previous history forward unchanged, so fail -> unknown -> unknown -> fail
// is still the SAME finding (persisting, first seen at scan 1).
func applyHistory(results []model.CheckResult, prev map[string]model.CheckResult, scanID string) {
	for i := range results {
		r := &results[i] // pointer, so we modify the slice element in place
		p, hadPrev := prev[r.Fingerprint]
		switch r.Result {
		case model.Pass:
			r.LastDefinitive, r.LastDefinitiveScanID = model.Pass, scanID
			r.FirstFailedScanID = "" // a pass ends the run of failures
		case model.Fail:
			r.LastDefinitive, r.LastDefinitiveScanID = model.Fail, scanID
			r.FirstFailedScanID = scanID
			if hadPrev && p.FirstFailedScanID != "" {
				r.FirstFailedScanID = p.FirstFailedScanID // same unresolved run
			}
		case model.Unknown:
			if hadPrev {
				r.LastDefinitive = p.LastDefinitive
				r.LastDefinitiveScanID = p.LastDefinitiveScanID
				r.FirstFailedScanID = p.FirstFailedScanID
			}
		}
	}
}

// Totals are the score and coverage numbers of one scan.
type Totals struct {
	Score, Total, Assessed, Unknown int
}

// computeTotals: start at 100, subtract per failing check (critical 15,
// high 8, medium 3, low 1), floor at 0. Unknown checks cost nothing, which
// is exactly why coverage must always be shown next to the score.
func computeTotals(results []model.CheckResult) Totals {
	t := Totals{Score: 100, Total: len(results)}
	for _, r := range results {
		switch r.Result {
		case model.Fail:
			t.Assessed++
			t.Score -= r.Severity.Weight()
		case model.Pass:
			t.Assessed++
		case model.Unknown:
			t.Unknown++
		}
	}
	if t.Score < 0 {
		t.Score = 0
	}
	return t
}

// maxCoverageDrop: a drop of more than 5 percentage points makes a score
// not comparable with the previous one.
const maxCoverageDrop = 0.05

// isComparable reports whether this scan's score can be compared with the
// previous succeeded scan's. Because unknown checks are excluded, a score can
// RISE just because failing checks became unreadable. So it is NOT comparable
// when (a) any check went fail -> unknown, or (b) coverage dropped > 5 points.
func isComparable(results []model.CheckResult, prev map[string]model.CheckResult, prevScan *model.Scan, cur model.Scan) bool {
	if cur.CollectionIncomplete || (prevScan != nil && prevScan.CollectionIncomplete) {
		return false // the full inventory, and therefore overall coverage, is unknown
	}
	if prevScan == nil {
		return true // nothing to compare against
	}
	for _, r := range results {
		if r.Result == model.Unknown {
			if p, ok := prev[r.Fingerprint]; ok && p.Result == model.Fail {
				return false
			}
		}
	}
	return prevScan.Coverage()-cur.Coverage() <= maxCoverageDrop
}
