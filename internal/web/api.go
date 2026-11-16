package web

import (
	"errors"
	"net/http"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
	"github.com/Rahul03082001/plumbline-sspm/internal/scan"
	"github.com/Rahul03082001/plumbline-sspm/internal/store"
)

// JSON shapes. Field names are snake_case and stable; they are the public API.

type scanJSON struct {
	ID                     string     `json:"id"`
	ConnectionID           string     `json:"connection_id"`
	Status                 string     `json:"status"`
	Error                  string     `json:"error,omitempty"`
	RetryAfter             *time.Time `json:"retry_after,omitempty"`
	Score                  *int       `json:"score"` // null when coverage is insufficient
	CoveragePct            *int       `json:"coverage_pct"`
	InventoryComplete      *bool      `json:"inventory_complete"`
	KnownChecksCoveragePct *int       `json:"known_checks_coverage_pct"`
	ChecksTotal            *int       `json:"checks_total"`
	ChecksAssessed         *int       `json:"checks_assessed"`
	ChecksUnknown          *int       `json:"checks_unknown"`
	Comparable             *bool      `json:"comparable"`
	CreatedAt              time.Time  `json:"created_at"`
	StartedAt              *time.Time `json:"started_at,omitempty"`
	FinishedAt             *time.Time `json:"finished_at,omitempty"`
}

// toScanJSON hides numbers that don't exist yet (queued/running/failed) and
// hides the score itself when coverage is under 60%, same as the UI.
func toScanJSON(s model.Scan) scanJSON {
	j := scanJSON{ID: s.ID, ConnectionID: s.ConnectionID, Status: string(s.Status), Error: s.Error,
		RetryAfter: s.RetryAfter, CreatedAt: s.CreatedAt, StartedAt: s.StartedAt, FinishedAt: s.FinishedAt}
	if s.Status == model.ScanSucceeded {
		cov, total, assessed, unknown, comparable := s.CoveragePct(), s.ChecksTotal, s.ChecksAssessed, s.ChecksUnknown, s.Comparable
		complete := !s.CollectionIncomplete
		comparable = comparable && complete
		j.InventoryComplete, j.KnownChecksCoveragePct = &complete, &cov
		j.ChecksTotal, j.ChecksAssessed, j.ChecksUnknown, j.Comparable = &total, &assessed, &unknown, &comparable
		if complete {
			j.CoveragePct = &cov
		}
		if s.ScoreVisible() {
			score := s.Score
			j.Score = &score
		}
	}
	return j
}

type connectionJSON struct {
	ID                  string         `json:"id"`
	Provider            string         `json:"provider"`
	DisplayName         string         `json:"display_name"`
	Mode                string         `json:"mode"`
	LatestScan          *scanJSON      `json:"latest_scan"`
	PreviousCoveragePct *int           `json:"previous_coverage_pct,omitempty"`
	FailCounts          map[string]int `json:"fail_counts"`
	Unverifiable        int            `json:"unverifiable"`
	ActiveScanID        string         `json:"active_scan_id,omitempty"`
	LastFailure         *scanJSON      `json:"last_failure,omitempty"`
}

func (s *Server) apiConnections(w http.ResponseWriter, r *http.Request) {
	sums, err := s.svc.Connections(r.Context())
	if err != nil {
		s.internalJSON(w, err)
		return
	}
	out := make([]connectionJSON, 0, len(sums))
	for _, sum := range sums {
		c := connectionJSON{ID: sum.Connection.ID, Provider: sum.Connection.Provider,
			DisplayName: sum.Connection.DisplayName, Mode: string(sum.Connection.Mode),
			FailCounts: map[string]int{}, Unverifiable: sum.Unverifiable}
		if sum.Latest != nil {
			lj := toScanJSON(*sum.Latest)
			c.LatestScan = &lj
		}
		if sum.Previous != nil && !sum.Previous.CollectionIncomplete {
			p := sum.Previous.CoveragePct()
			c.PreviousCoveragePct = &p
		}
		for _, f := range sum.FailBySeverity {
			c.FailCounts[string(f.Severity)] = f.Count
		}
		if sum.Active != nil {
			c.ActiveScanID = sum.Active.ID
		}
		if f := sum.LastFailure(); f != nil {
			fj := toScanJSON(*f)
			c.LastFailure = &fj
		}
		out = append(out, c)
	}
	writeJSON(w, http.StatusOK, map[string]any{"connections": out})
}

// createScan is shared by the JSON and HTML endpoints: rate limit first,
// then ask the service. It returns the outcome; callers only render it.
type createOutcome int

const (
	created createOutcome = iota
	conflict
	tooMany
	notFound
	unavailable
	failed
)

func (s *Server) createScan(r *http.Request) (createOutcome, model.Scan, string) {
	if !s.limiter.allow(r) {
		return tooMany, model.Scan{}, ""
	}
	sc, err := s.svc.RequestScan(r.Context(), r.PathValue("id"))
	var active *store.ActiveScanError
	switch {
	case err == nil:
		return created, sc, ""
	case errors.As(err, &active):
		return conflict, model.Scan{}, active.ScanID
	case errors.Is(err, scan.ErrUnknownConnection):
		return notFound, model.Scan{}, ""
	case errors.Is(err, scan.ErrShuttingDown), errors.Is(err, scan.ErrQueueFull):
		return unavailable, model.Scan{}, ""
	default:
		s.log.Error("create scan", "error", err)
		return failed, model.Scan{}, ""
	}
}

func (s *Server) apiCreateScan(w http.ResponseWriter, r *http.Request) {
	outcome, sc, activeID := s.createScan(r)
	switch outcome {
	case created:
		w.Header().Set("Location", "/api/scans/"+sc.ID)
		writeJSON(w, http.StatusAccepted, toScanJSON(sc))
	case conflict:
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a scan is already active", "active_scan_id": activeID})
	case tooMany:
		w.Header().Set("Retry-After", "60")
		writeJSONError(w, http.StatusTooManyRequests, "rate limited: at most 5 scans per minute")
	case notFound:
		writeJSONError(w, http.StatusNotFound, "unknown connection")
	case unavailable:
		writeJSONError(w, http.StatusServiceUnavailable, "not accepting scans right now")
	default:
		writeJSONError(w, http.StatusInternalServerError, "internal error")
	}
}

func (s *Server) apiScan(w http.ResponseWriter, r *http.Request) {
	sc, err := s.svc.GetScan(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "scan not found")
		return
	}
	if err != nil {
		s.internalJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toScanJSON(sc))
}

type resultJSON struct {
	ID                   string         `json:"id"`
	RuleID               string         `json:"rule_id"`
	Title                string         `json:"title"`
	Severity             string         `json:"severity"`
	Result               string         `json:"result"`
	Fingerprint          string         `json:"fingerprint"`
	Asset                assetJSON      `json:"asset"`
	Evidence             model.Evidence `json:"evidence"`
	LastDefinitive       string         `json:"last_definitive,omitempty"`
	LastDefinitiveScanID string         `json:"last_definitive_scan_id,omitempty"`
	FirstFailedScanID    string         `json:"first_failed_scan_id,omitempty"`
}

type assetJSON struct {
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	ExternalID     string `json:"external_id"`
	CarriedForward bool   `json:"carried_forward"`
}

func (s *Server) apiResults(w http.ResponseWriter, r *http.Request) {
	res, err := parseResult(r.URL.Query().Get("result"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	sev, err := parseSeverity(r.URL.Query().Get("severity"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	rows, err := s.svc.Results(r.Context(), r.PathValue("id"), store.ResultFilter{Result: res, Severity: sev})
	if errors.Is(err, store.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "scan not found")
		return
	}
	if err != nil {
		s.internalJSON(w, err)
		return
	}
	out := make([]resultJSON, 0, len(rows))
	for _, row := range rows {
		title := ""
		if rule, ok := s.svc.Rule(row.RuleID); ok {
			title = rule.Title
		}
		out = append(out, resultJSON{
			ID: row.ID, RuleID: row.RuleID, Title: title, Severity: string(row.Severity),
			Result: string(row.Result), Fingerprint: row.Fingerprint, Evidence: row.Evidence,
			Asset: assetJSON{Kind: string(row.Asset.Kind), Name: row.Asset.Name,
				ExternalID: row.Asset.ExternalID, CarriedForward: row.Asset.CarriedForward},
			LastDefinitive: string(row.LastDefinitive), LastDefinitiveScanID: row.LastDefinitiveScanID,
			FirstFailedScanID: row.FirstFailedScanID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan_id": r.PathValue("id"), "results": out})
}

func (s *Server) apiDrift(w http.ResponseWriter, r *http.Request) {
	d, err := s.svc.Drift(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "scan not found")
	case errors.Is(err, scan.ErrNotSucceeded):
		writeJSONError(w, http.StatusConflict, "scan has no published results")
	case err != nil:
		s.internalJSON(w, err)
	default:
		writeJSON(w, http.StatusOK, d)
	}
}

func (s *Server) apiRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": s.svc.Rules()})
}

func (s *Server) internalJSON(w http.ResponseWriter, err error) {
	s.log.Error("api error", "error", err)
	writeJSONError(w, http.StatusInternalServerError, "internal error")
}
