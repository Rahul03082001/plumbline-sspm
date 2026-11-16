package web

import (
	"errors"
	"net/http"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
	"github.com/Rahul03082001/plumbline-sspm/internal/scan"
	"github.com/Rahul03082001/plumbline-sspm/internal/store"
)

// ---- full pages -------------------------------------------------------------------

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	sums, err := s.svc.Connections(r.Context())
	if err != nil {
		s.internalPage(w, err)
		return
	}
	cards := make([]cardView, 0, len(sums))
	for _, sum := range sums {
		cards = append(cards, newCardView(sum))
	}
	s.renderPage(w, http.StatusOK, "dashboard", "Dashboard", cards)
}

// connectionPageView is the data for /c/{id}.
type connectionPageView struct {
	Card        cardView
	Spark       sparkView
	Drift       *scan.Drift
	Findings    []store.ResultRow
	Unknowns    []store.ResultRow
	Collections []model.Collection
	Severities  []model.Severity
	Titles      map[string]string
}

func (s *Server) connectionPage(w http.ResponseWriter, r *http.Request) {
	d, err := s.svc.ConnectionDetail(r.Context(), r.PathValue("id"), "")
	if errors.Is(err, scan.ErrUnknownConnection) || errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, http.StatusNotFound, "Unknown connection.")
		return
	}
	if err != nil {
		s.internalPage(w, err)
		return
	}
	v := connectionPageView{
		Card: newCardView(d.ConnectionSummary), Spark: newSparkView(d.History), Drift: d.Drift,
		Findings: d.Findings, Unknowns: d.Unknowns, Collections: d.Collections,
		Severities: model.Severities, Titles: s.titles(),
	}
	s.renderPage(w, http.StatusOK, "connection", d.Connection.DisplayName, v)
}

// findingPageView is the data for /f/{id}.
type findingPageView struct {
	scan.FindingDetail
	ConnDomID string
}

func (s *Server) findingPage(w http.ResponseWriter, r *http.Request) {
	f, err := s.svc.Finding(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, http.StatusNotFound, "Unknown finding. Finding links point at one scan; it may be from a database that was reset.")
		return
	}
	if err != nil {
		s.internalPage(w, err)
		return
	}
	s.renderPage(w, http.StatusOK, "finding", f.Rule.Title, findingPageView{FindingDetail: f, ConnDomID: domID(f.Connection.ID)})
}

func (s *Server) aboutPage(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, http.StatusOK, "about", "About", struct {
		Permissions any
		Rules       []model.Rule
	}{permissionsTable(), s.svc.Rules()})
}

// ---- htmx fragments ------------------------------------------------------------------

// view returns "page" or "card": what the status poller should become when
// the scan finishes (a refreshed card, or a full page reload).
func viewParam(r *http.Request) string {
	if r.URL.Query().Get("view") == "page" {
		return "page"
	}
	return "card"
}

// uiCreateScan answers the "Run scan" button. 409 and 429 return fragments
// too: the htmx-config meta tag in the layout tells htmx to swap them.
func (s *Server) uiCreateScan(w http.ResponseWriter, r *http.Request) {
	outcome, sc, activeID := s.createScan(r)
	view := viewParam(r)
	switch outcome {
	case created:
		s.renderFragment(w, http.StatusAccepted, "scan_status",
			statusView{ScanID: sc.ID, View: view, Message: "Scan queued…", Class: "info"})
	case conflict:
		s.renderFragment(w, http.StatusConflict, "scan_status",
			statusView{ScanID: activeID, View: view, Message: "Scan already running", Class: "warn"})
	case tooMany:
		w.Header().Set("Retry-After", "60")
		s.renderFragment(w, http.StatusTooManyRequests, "slow_down", nil)
	case notFound:
		http.Error(w, "unknown connection", http.StatusNotFound)
	case unavailable:
		http.Error(w, "not accepting scans right now", http.StatusServiceUnavailable)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// uiScanStatus is polled every second by the status fragment. While the scan
// is active it returns the fragment again (which keeps polling). Once done it
// returns the refreshed card and retargets the swap onto the card (no more
// polling), or asks the page to reload.
func (s *Server) uiScanStatus(w http.ResponseWriter, r *http.Request) {
	sc, err := s.svc.GetScan(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "unknown scan", http.StatusNotFound)
		return
	}
	if err != nil {
		s.internalFragment(w, err)
		return
	}
	view := viewParam(r)
	if sc.Status.Active() {
		msg := "Scan queued…"
		if sc.Status == model.ScanRunning {
			msg = "Scan running…"
		}
		s.renderFragment(w, http.StatusOK, "scan_status", statusView{ScanID: sc.ID, View: view, Message: msg, Class: "info"})
		return
	}
	if view == "page" {
		w.Header().Set("HX-Refresh", "true") // htmx reloads the whole page
		w.WriteHeader(http.StatusOK)
		return
	}
	sum, err := s.svc.Connection(r.Context(), sc.ConnectionID)
	if err != nil {
		s.internalFragment(w, err)
		return
	}
	card := newCardView(sum)
	w.Header().Set("HX-Retarget", "#card-"+card.DomID)
	w.Header().Set("HX-Reswap", "outerHTML")
	s.renderFragment(w, http.StatusOK, "card", card)
}

func (s *Server) uiCard(w http.ResponseWriter, r *http.Request) {
	sum, err := s.svc.Connection(r.Context(), r.PathValue("id"))
	if errors.Is(err, scan.ErrUnknownConnection) {
		http.Error(w, "unknown connection", http.StatusNotFound)
		return
	}
	if err != nil {
		s.internalFragment(w, err)
		return
	}
	s.renderFragment(w, http.StatusOK, "card", newCardView(sum))
}

// uiFindings returns just the <tbody> rows for a severity filter change.
func (s *Server) uiFindings(w http.ResponseWriter, r *http.Request) {
	sev, err := parseSeverity(r.URL.Query().Get("severity"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sum, err := s.svc.Connection(r.Context(), r.PathValue("id"))
	if errors.Is(err, scan.ErrUnknownConnection) {
		http.Error(w, "unknown connection", http.StatusNotFound)
		return
	}
	if err != nil {
		s.internalFragment(w, err)
		return
	}
	var rows []store.ResultRow
	if sum.Latest != nil {
		if rows, err = s.svc.Findings(r.Context(), sum.Latest.ID, sev); err != nil {
			s.internalFragment(w, err)
			return
		}
	}
	s.renderFragment(w, http.StatusOK, "findings_rows", struct {
		Findings []store.ResultRow
		Titles   map[string]string
	}{rows, s.titles()})
}

func (s *Server) titles() map[string]string {
	m := map[string]string{}
	for _, r := range s.svc.Rules() {
		m[r.ID] = r.Title
	}
	return m
}

func (s *Server) internalPage(w http.ResponseWriter, err error) {
	s.log.Error("page error", "error", err)
	s.errorPage(w, http.StatusInternalServerError, "Something went wrong.")
}

func (s *Server) internalFragment(w http.ResponseWriter, err error) {
	s.log.Error("fragment error", "error", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}
