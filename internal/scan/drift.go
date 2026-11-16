package scan

import (
	"github.com/Rahul03082001/plumbline-sspm/internal/model"
	"github.com/Rahul03082001/plumbline-sspm/internal/store"
)

// DriftItem is one finding that changed state between two scans.
type DriftItem struct {
	ResultID          string         `json:"result_id"`
	Fingerprint       string         `json:"fingerprint"`
	RuleID            string         `json:"rule_id"`
	Title             string         `json:"title"`
	Severity          model.Severity `json:"severity"`
	AssetKind         string         `json:"asset_kind"`
	AssetName         string         `json:"asset_name"`
	Regressed         bool           `json:"regressed,omitempty"` // new, but it passed before
	FirstFailedScanID string         `json:"first_failed_scan_id,omitempty"`
}

// Drift compares a scan with the previous succeeded scan of its connection.
type Drift struct {
	ScanID               string      `json:"scan_id"`
	PreviousScanID       string      `json:"previous_scan_id,omitempty"`
	New                  []DriftItem `json:"new"`
	Resolved             []DriftItem `json:"resolved"`
	ResolvedAssetRemoved []DriftItem `json:"resolved_asset_removed"`
	Unverifiable         []DriftItem `json:"unverifiable"`
	PersistingCount      int         `json:"persisting_count"`
}

// computeDrift implements the table in spec section 6. It compares each
// current result with the LAST DEFINITIVE state (most recent pass/fail) from
// the previous scan, looking through any unknown scans in between.
//
//	last definitive | current                      | drift state
//	none or pass    | fail                         | new (regressed if it was pass)
//	fail            | fail                         | persisting
//	fail            | pass                         | resolved
//	fail            | unknown (incl. carried fwd)  | unverifiable (NOT resolved)
//	fail            | gone after complete listing  | resolved (asset removed)
//	pass or none    | unknown                      | nothing (only lowers coverage)
func computeDrift(scanID, prevScanID string, cur, prev []store.ResultRow, titles map[string]string) Drift {
	d := Drift{ScanID: scanID, PreviousScanID: prevScanID,
		New: []DriftItem{}, Resolved: []DriftItem{}, ResolvedAssetRemoved: []DriftItem{}, Unverifiable: []DriftItem{}}

	prevByFP := make(map[string]store.ResultRow, len(prev))
	for _, p := range prev {
		prevByFP[p.Fingerprint] = p
	}
	curFP := make(map[string]bool, len(cur))

	for _, r := range cur {
		curFP[r.Fingerprint] = true
		var lastDef model.Result
		if p, ok := prevByFP[r.Fingerprint]; ok {
			lastDef = p.LastDefinitive
		}
		item := toItem(r, titles)
		switch r.Result {
		case model.Fail:
			if lastDef == model.Fail {
				d.PersistingCount++
			} else {
				item.Regressed = lastDef == model.Pass
				d.New = append(d.New, item)
			}
		case model.Pass:
			if lastDef == model.Fail {
				d.Resolved = append(d.Resolved, item)
			}
		case model.Unknown:
			// r.LastDefinitive was copied forward, so this stays
			// "unverifiable" on every following unknown scan, too.
			if r.LastDefinitive == model.Fail {
				d.Unverifiable = append(d.Unverifiable, item)
			}
		}
	}
	// Results that disappeared. Because incomplete listings carry assets
	// forward, a result can only vanish after a COMPLETE listing.
	for _, p := range prev {
		if !curFP[p.Fingerprint] && p.LastDefinitive == model.Fail {
			d.ResolvedAssetRemoved = append(d.ResolvedAssetRemoved, toItem(p, titles))
		}
	}
	return d
}

func toItem(r store.ResultRow, titles map[string]string) DriftItem {
	return DriftItem{
		ResultID: r.ID, Fingerprint: r.Fingerprint, RuleID: r.RuleID, Title: titles[r.RuleID],
		Severity: r.Severity, AssetKind: string(r.Asset.Kind), AssetName: r.Asset.Name,
		FirstFailedScanID: r.FirstFailedScanID,
	}
}
