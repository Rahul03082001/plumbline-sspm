// Package web serves the HTML pages, the htmx fragment endpoints (/ui/...),
// the JSON API (/api/...), health checks and metrics. Handlers only parse
// input, call the scan service, and render; there is no business logic here.
package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/connector/github"
	"github.com/Rahul03082001/plumbline-sspm/internal/model"
	"github.com/Rahul03082001/plumbline-sspm/internal/scan"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// scanRateLimit is how many scans one IP may start per minute.
const scanRateLimit = 5

// Options configures the web server.
type Options struct {
	Service          *scan.Service
	Logger           *slog.Logger
	MetricsHandler   http.Handler // nil = no /metrics route
	TrustedProxyHops int
	LiveOrg          string // shown in the banner; "" when no live connection
}

// Server holds parsed templates and dependencies.
type Server struct {
	svc      *scan.Service
	log      *slog.Logger
	pages    map[string]*template.Template
	partials *template.Template
	limiter  *ipLimiter
	liveOrg  string
}

// New builds the full HTTP handler, middleware included.
func New(o Options) (http.Handler, error) {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{svc: o.Service, log: o.Logger, limiter: newIPLimiter(scanRateLimit, o.TrustedProxyHops), liveOrg: o.LiveOrg}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	// Go 1.22+ patterns: "METHOD /path/{wildcard}". {$} means "exactly /".
	mux.HandleFunc("GET /{$}", s.dashboard)
	mux.HandleFunc("GET /c/{id}", s.connectionPage)
	mux.HandleFunc("GET /f/{id}", s.findingPage)
	mux.HandleFunc("GET /about", s.aboutPage)

	mux.HandleFunc("POST /ui/connections/{id}/scans", s.uiCreateScan)
	mux.HandleFunc("GET /ui/scans/{id}/status", s.uiScanStatus)
	mux.HandleFunc("GET /ui/connections/{id}/card", s.uiCard)
	mux.HandleFunc("GET /ui/connections/{id}/findings", s.uiFindings)

	mux.HandleFunc("GET /api/connections", s.apiConnections)
	mux.HandleFunc("POST /api/connections/{id}/scans", s.apiCreateScan)
	mux.HandleFunc("GET /api/scans/{id}", s.apiScan)
	mux.HandleFunc("GET /api/scans/{id}/results", s.apiResults)
	mux.HandleFunc("GET /api/scans/{id}/drift", s.apiDrift)
	mux.HandleFunc("GET /api/rules", s.apiRules)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", s.readyz)
	if o.MetricsHandler != nil {
		mux.Handle("GET /metrics", o.MetricsHandler)
	}
	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	// Catch-all for unknown GET paths. Being GET-only lets the mux answer a
	// wrong method on a known path with 405 Method Not Allowed instead.
	mux.HandleFunc("GET /", s.notFound)

	// Middleware wraps from the inside out: recover is closest to handlers.
	var h http.Handler = mux
	h = recoverPanics(o.Logger, h)
	h = securityHeaders(h)
	h = logRequests(o.Logger, h)
	return h, nil
}

// ---- templates ------------------------------------------------------------------

var templateFuncs = template.FuncMap{
	"sevClass":   severityClass,
	"reasonText": reasonText,
	"pathEscape": url.PathEscape,
	"short":      shortID,
	"absInt":     func(n int) int { return max(n, -n) },
	// iso / human / clock accept time.Time or *time.Time (nil = never).
	"iso": func(v any) string {
		if t, ok := asTime(v); ok {
			return t.UTC().Format(time.RFC3339)
		}
		return ""
	},
	"human": func(v any) string {
		if t, ok := asTime(v); ok {
			return t.UTC().Format("2 Jan 2006 15:04 UTC")
		}
		return "never"
	},
	"clock": func(v any) string {
		if t, ok := asTime(v); ok {
			return t.UTC().Format("3:04 PM UTC")
		}
		return ""
	},
	// poll builds the self-polling status fragment for an active scan.
	"poll": func(scanID, view string) statusView {
		return statusView{ScanID: scanID, View: view, Message: "Scan in progress…", Class: "info"}
	},
}

func asTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t, !t.IsZero()
	case *time.Time:
		if t != nil {
			return *t, true
		}
	}
	return time.Time{}, false
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func (s *Server) parseTemplates() error {
	base, err := template.New("").Funcs(templateFuncs).ParseFS(templateFS, "templates/layout.html", "templates/partials.html")
	if err != nil {
		return err
	}
	s.partials = base
	s.pages = map[string]*template.Template{}
	for _, name := range []string{"dashboard", "connection", "finding", "about", "error"} {
		clone, err := base.Clone()
		if err != nil {
			return err
		}
		if s.pages[name], err = clone.ParseFS(templateFS, "templates/"+name+".html"); err != nil {
			return fmt.Errorf("template %s: %w", name, err)
		}
	}
	return nil
}

// pageData is what every full page receives.
type pageData struct {
	Title   string
	Nav     string
	LiveOrg string
	Content any
}

// renderPage executes into a buffer first, so a template error becomes a
// clean 500 instead of half a page.
func (s *Server) renderPage(w http.ResponseWriter, status int, name, title string, content any) {
	var buf bytes.Buffer
	data := pageData{Title: title, Nav: name, LiveOrg: s.liveOrg, Content: content}
	if err := s.pages[name].ExecuteTemplate(&buf, "layout", data); err != nil {
		s.log.Error("render page", "page", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// renderFragment executes one named partial (an htmx response).
func (s *Server) renderFragment(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.partials.ExecuteTemplate(&buf, name, data); err != nil {
		s.log.Error("render fragment", "fragment", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (s *Server) errorPage(w http.ResponseWriter, status int, msg string) {
	s.renderPage(w, status, "error", http.StatusText(status), struct {
		Status  int
		Message string
	}{status, msg})
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Path) >= 5 && r.URL.Path[:5] == "/api/" {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	s.errorPage(w, http.StatusNotFound, "There is nothing at this address.")
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Ready(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// ---- JSON helpers ---------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// permissionsTable is shown on /about; it is the same data as docs/permissions.md.
func permissionsTable() []github.EndpointPermission { return github.Endpoints }

// parseSeverity validates a ?severity= value ("" = all).
func parseSeverity(v string) (model.Severity, error) {
	if v == "" {
		return "", nil
	}
	for _, s := range model.Severities {
		if string(s) == v {
			return s, nil
		}
	}
	return "", errors.New("severity must be one of critical, high, medium, low")
}

// parseResult validates a ?result= value ("" = all).
func parseResult(v string) (model.Result, error) {
	switch model.Result(v) {
	case "", model.Pass, model.Fail, model.Unknown:
		return model.Result(v), nil
	}
	return "", errors.New("result must be one of pass, fail, unknown")
}
