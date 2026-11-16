package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/connector"
	"github.com/Rahul03082001/plumbline-sspm/internal/connector/simulated"
	"github.com/Rahul03082001/plumbline-sspm/internal/model"
	"github.com/Rahul03082001/plumbline-sspm/internal/rules"
	"github.com/Rahul03082001/plumbline-sspm/internal/scan"
	"github.com/Rahul03082001/plumbline-sspm/internal/store"
)

const simID = simulated.ConnectionID

// gate wraps a connector and blocks every Collect until released, so a scan
// stays "running" for as long as a test needs (to provoke a 409).
type gate struct {
	inner   connector.Connector
	release chan struct{}
}

func (g *gate) Collect(ctx context.Context) (connector.Snapshot, error) {
	select {
	case <-g.release:
	case <-ctx.Done():
		return connector.Snapshot{}, ctx.Err()
	}
	return g.inner.Collect(ctx)
}

// evilConnector returns assets whose names contain HTML, to prove the UI
// escapes API-derived data.
type evilConnector struct{}

func (evilConnector) Collect(context.Context) (connector.Snapshot, error) {
	cols := map[model.AssetKind]model.Collection{}
	for _, k := range model.AllKinds {
		cols[k] = model.Collection{Kind: k, Status: model.CollectionComplete}
	}
	return connector.Snapshot{Collections: cols, Assets: []model.Asset{{
		Kind: model.KindRepo, ExternalID: "1", Name: `<script>alert("x")</script>`,
		Attributes: model.Attributes{"visibility": "public", "default_branch_protected": false, "secret_scanning": false},
	}}}, nil
}

type testEnv struct {
	srv  *httptest.Server
	svc  *scan.Service
	gate *gate
}

// newEnv starts a real Service (with workers) and the full handler. The
// simulated connector sits behind a gate that tests open when they want
// scans to finish.
func newEnv(t *testing.T, hops int) *testEnv {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	svc := scan.New(st, ruleset, scan.Options{})
	g := &gate{inner: simulated.New(0, 0), release: make(chan struct{})}
	if err := svc.Register(ctx, model.Connection{ID: simID, Provider: "github", DisplayName: "Acme", Mode: model.ModeSimulated}, g); err != nil {
		t.Fatal(err)
	}
	if err := svc.Register(ctx, model.Connection{ID: "github:evil", Provider: "github", DisplayName: "Evil", Mode: model.ModeLive}, evilConnector{}); err != nil {
		t.Fatal(err)
	}
	svc.Start()
	h, err := New(Options{Service: svc, TrustedProxyHops: hops})
	if err != nil {
		t.Fatal(err)
	}
	env := &testEnv{srv: httptest.NewServer(h), svc: svc, gate: g}
	t.Cleanup(func() {
		env.srv.Close()
		env.openGate()
		sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		svc.Shutdown(sctx)
		st.Close()
	})
	return env
}

func (e *testEnv) openGate() {
	select {
	case <-e.gate.release:
	default:
		close(e.gate.release)
	}
}

func (e *testEnv) do(t *testing.T, method, path string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// waitDone waits until the connection has no active scan.
func (e *testEnv) waitDone(t *testing.T, connID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sum, err := e.svc.Connection(context.Background(), connID)
		if err == nil && sum.Active == nil && sum.Latest != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scan did not finish")
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	e := newEnv(t, 0)
	for _, p := range []string{"/", "/api/connections", "/ui/connections/" + simID + "/card", "/nope"} {
		resp, _ := e.do(t, "GET", p, nil)
		h := resp.Header
		csp := h.Get("Content-Security-Policy")
		for _, want := range []string{"frame-ancestors 'none'", "script-src 'self' https://cdn.jsdelivr.net", "default-src 'self'", "style-src 'self'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP missing %q: %s", p, want, csp)
			}
		}
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: CSP must not allow inline/eval", p)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: missing nosniff/no-referrer", p)
		}
	}
}

func TestContentTypesAndStatusCodes(t *testing.T) {
	e := newEnv(t, 0)
	cases := []struct {
		method, path string
		status       int
		ctype        string
	}{
		{"GET", "/", 200, "text/html"},
		{"GET", "/about", 200, "text/html"},
		{"GET", "/c/" + simID, 200, "text/html"},
		{"GET", "/c/github:nope", 404, "text/html"},
		{"GET", "/f/does-not-exist", 404, "text/html"},
		{"GET", "/nope", 404, "text/html"},
		{"GET", "/ui/connections/" + simID + "/card", 200, "text/html"},
		{"GET", "/ui/connections/" + simID + "/findings?severity=high", 200, "text/html"},
		{"GET", "/ui/connections/" + simID + "/findings?severity=bogus", 400, "text/plain"},
		{"GET", "/api/connections", 200, "application/json"},
		{"GET", "/api/rules", 200, "application/json"},
		{"GET", "/api/scans/does-not-exist", 404, "application/json"},
		{"GET", "/api/nope", 404, "application/json"},
		{"POST", "/api/connections/github:nope/scans", 404, "application/json"},
		{"GET", "/healthz", 200, "application/json"},
		{"GET", "/readyz", 200, "application/json"},
		{"GET", "/static/app.css", 200, "text/css"},
		{"DELETE", "/api/connections", 405, ""},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			resp, _ := e.do(t, tc.method, tc.path, nil)
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if tc.ctype != "" && !strings.HasPrefix(resp.Header.Get("Content-Type"), tc.ctype) {
				t.Fatalf("content-type = %q, want %s", resp.Header.Get("Content-Type"), tc.ctype)
			}
		})
	}
}

func TestAPICreateScan202Then409(t *testing.T) {
	e := newEnv(t, 0)
	resp, body := e.do(t, "POST", "/api/connections/"+simID+"/scans", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("first POST = %d %s", resp.StatusCode, body)
	}
	var first struct{ ID, Status string }
	_ = json.Unmarshal([]byte(body), &first)
	if first.ID == "" || first.Status != "queued" {
		t.Fatalf("got %s", body)
	}
	resp, body = e.do(t, "POST", "/api/connections/"+simID+"/scans", nil)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, first.ID) {
		t.Fatalf("second POST = %d %s (must name the active scan)", resp.StatusCode, body)
	}
}

func TestUIFragmentsFor202And409And429(t *testing.T) {
	e := newEnv(t, 0)
	path := "/ui/connections/" + simID + "/scans?view=card"

	resp, body := e.do(t, "POST", path, nil)
	if resp.StatusCode != http.StatusAccepted || !strings.Contains(body, "Scan queued") ||
		!strings.Contains(body, `hx-trigger="every 1s"`) {
		t.Fatalf("202 fragment: %d %s", resp.StatusCode, body)
	}
	resp, body = e.do(t, "POST", path, nil)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "Scan already running") ||
		!strings.Contains(body, `hx-trigger="every 1s"`) {
		t.Fatalf("409 fragment must say 'Scan already running' and keep polling: %d %s", resp.StatusCode, body)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatal("409 /ui response must be HTML")
	}
	// Burst is 5 per minute per IP; 2 used above.
	for i := 0; i < 3; i++ {
		e.do(t, "POST", path, nil)
	}
	resp, body = e.do(t, "POST", path, nil)
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(body, "Slow down") ||
		!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("429 fragment: %d %s", resp.StatusCode, body)
	}
	// The API shares the same limiter and answers JSON.
	resp, _ = e.do(t, "POST", "/api/connections/"+simID+"/scans", nil)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("api 429: %d", resp.StatusCode)
	}
}

func TestRateLimitIsPerIPAndSpoofProof(t *testing.T) {
	e := newEnv(t, 1) // behind one trusted proxy (Cloud Run)
	post := func(xff string) int {
		resp, _ := e.do(t, "POST", "/api/connections/github:nope/scans", map[string]string{"X-Forwarded-For": xff})
		return resp.StatusCode
	}
	for i := 0; i < 5; i++ {
		if code := post("203.0.113.7"); code == http.StatusTooManyRequests {
			t.Fatalf("request %d limited too early", i+1)
		}
	}
	if post("203.0.113.7") != http.StatusTooManyRequests {
		t.Fatal("6th request from the same IP must get 429")
	}
	// A client faking a new left-most address is still the same client:
	// the proxy appended the real address on the right.
	if post("198.51.100.99, 203.0.113.7") != http.StatusTooManyRequests {
		t.Fatal("spoofed X-Forwarded-For must not bypass the limiter")
	}
	if post("192.0.2.50") == http.StatusTooManyRequests {
		t.Fatal("a different client must have its own bucket")
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		xff    string
		hops   int
		want   string
	}{
		{"direct, header ignored", "10.0.0.1:5555", "1.2.3.4", 0, "10.0.0.1"},
		{"one proxy", "169.254.1.1:80", "1.2.3.4", 1, "1.2.3.4"},
		{"one proxy, spoofed prefix", "169.254.1.1:80", "6.6.6.6, 1.2.3.4", 1, "1.2.3.4"},
		{"two proxies", "169.254.1.1:80", "6.6.6.6, 1.2.3.4, 35.1.1.1", 2, "1.2.3.4"},
		{"header too short", "10.0.0.9:1", "", 1, "10.0.0.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remote
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := clientIP(r, tc.hops); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestStatusFragmentPollsThenReturnsCard(t *testing.T) {
	e := newEnv(t, 0)
	_, body := e.do(t, "POST", "/api/connections/"+simID+"/scans", nil)
	var sc struct{ ID string }
	_ = json.Unmarshal([]byte(body), &sc)

	resp, body := e.do(t, "GET", "/ui/scans/"+sc.ID+"/status?view=card", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `hx-trigger="every 1s"`) {
		t.Fatalf("active scan must keep polling: %s", body)
	}
	e.openGate()
	e.waitDone(t, simID)

	resp, body = e.do(t, "GET", "/ui/scans/"+sc.ID+"/status?view=card", nil)
	if strings.Contains(body, "hx-trigger") {
		t.Fatal("a finished scan must stop polling")
	}
	if resp.Header.Get("HX-Retarget") != "#card-github-acme-demo" || resp.Header.Get("HX-Reswap") != "outerHTML" {
		t.Fatalf("finished scan must swap in the refreshed card, headers: %v", resp.Header)
	}
	if !strings.Contains(body, `id="card-github-acme-demo"`) || !strings.Contains(body, "Score 28") {
		t.Fatalf("refreshed card expected: %s", body)
	}
	resp, _ = e.do(t, "GET", "/ui/scans/"+sc.ID+"/status?view=page", nil)
	if resp.Header.Get("HX-Refresh") != "true" {
		t.Fatal("page view should reload when done")
	}
}

func TestAPIResultsDriftAndFilters(t *testing.T) {
	e := newEnv(t, 0)
	e.openGate()
	_, body := e.do(t, "POST", "/api/connections/"+simID+"/scans", nil)
	var sc struct{ ID string }
	_ = json.Unmarshal([]byte(body), &sc)
	e.waitDone(t, simID)

	resp, body := e.do(t, "GET", "/api/scans/"+sc.ID+"/results?result=fail&severity=critical", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	var res struct {
		Results []struct{ Result, Severity, RuleID string } `json:"results"`
	}
	_ = json.Unmarshal([]byte(body), &res)
	if len(res.Results) != 2 {
		t.Fatalf("want 2 critical failures (SL-ORG-001, SL-USER-001), got %d", len(res.Results))
	}
	for _, r := range res.Results {
		if r.Result != "fail" || r.Severity != "critical" {
			t.Fatalf("filter leaked %+v", r)
		}
	}
	if resp, _ := e.do(t, "GET", "/api/scans/"+sc.ID+"/results?severity=urgent", nil); resp.StatusCode != 400 {
		t.Fatal("bad severity must be 400")
	}

	_, body = e.do(t, "GET", "/api/scans/"+sc.ID+"/drift", nil)
	var d map[string]json.RawMessage
	_ = json.Unmarshal([]byte(body), &d)
	for _, k := range []string{"new", "resolved", "resolved_asset_removed", "unverifiable", "persisting_count"} {
		if _, ok := d[k]; !ok {
			t.Errorf("drift JSON missing %q: %s", k, body)
		}
	}
}

func TestAPIHidesScoreWhenCoverageInsufficient(t *testing.T) {
	low := toScanJSON(model.Scan{Status: model.ScanSucceeded, Score: 100, ChecksTotal: 10, ChecksAssessed: 5})
	if low.Score != nil || low.CoveragePct == nil || *low.CoveragePct != 50 {
		t.Fatalf("score must be null under 60%% coverage: %+v", low)
	}
	queued := toScanJSON(model.Scan{Status: model.ScanQueued})
	if queued.Score != nil || queued.CoveragePct != nil {
		t.Fatal("unfinished scans have no numbers")
	}
}

func TestAPIDerivedDataIsEscaped(t *testing.T) {
	e := newEnv(t, 0)
	e.do(t, "POST", "/api/connections/github:evil/scans", nil)
	e.waitDone(t, "github:evil")
	_, body := e.do(t, "GET", "/c/github:evil", nil)
	if strings.Contains(body, `<script>alert("x")</script>`) {
		t.Fatal("asset name was rendered as raw HTML")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("expected the escaped asset name on the page")
	}
}

// TestNoTemplateHTMLInWebPackage enforces "never wrap API-derived data in
// template.HTML" the simple way: the conversion doesn't appear at all.
func TestNoTemplateHTMLInWebPackage(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "template.HTML(") {
			t.Errorf("%s uses template.HTML(...), which disables escaping", f)
		}
	}
}

func TestSparklineGapsForNonComparableScans(t *testing.T) {
	hist := []model.Scan{
		{Status: model.ScanSucceeded, Score: 30, ChecksTotal: 10, ChecksAssessed: 10, Comparable: true},
		{Status: model.ScanSucceeded, Score: 50, ChecksTotal: 10, ChecksAssessed: 7, Comparable: false}, // gap
		{Status: model.ScanSucceeded, Score: 50, ChecksTotal: 10, ChecksAssessed: 7, Comparable: true},
		{Status: model.ScanSucceeded, Score: 40, ChecksTotal: 10, ChecksAssessed: 10, Comparable: true},
	}
	v := newSparkView(hist)
	if len(v.GapDots) != 1 || len(v.ScoreDots) != 3 {
		t.Fatalf("gaps=%d dots=%d", len(v.GapDots), len(v.ScoreDots))
	}
	// Scan 1 alone (no segment), then scans 3-4 joined: exactly one segment.
	if len(v.ScoreSegments) != 1 {
		t.Fatalf("segments = %v", v.ScoreSegments)
	}
}
