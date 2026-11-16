package metrics

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

func TestMetricsExposeSpecNames(t *testing.T) {
	m := New()
	m.RegisterQueueDepth(func() int { return 3 })
	m.ScanFinished("live", "succeeded", 1500*time.Millisecond)
	m.GitHubRequest("GET /orgs/{org}/hooks", 200)
	m.GitHubRequest("GET /orgs/{org}/hooks", 0)
	m.RateLimitWait("secondary")
	m.CheckResults("github:x", map[model.Result]int{model.Pass: 5, model.Fail: 2})

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	out := string(body)
	for _, want := range []string{
		`plumbline_scans_total{mode="live",status="succeeded"} 1`,
		`plumbline_scan_duration_seconds_count{mode="live"} 1`,
		`plumbline_github_requests_total{endpoint="GET /orgs/{org}/hooks",status_class="2xx"} 1`,
		`plumbline_github_requests_total{endpoint="GET /orgs/{org}/hooks",status_class="network_error"} 1`,
		`plumbline_github_rate_limit_waits_total{kind="secondary"} 1`,
		`plumbline_check_results{connection="github:x",result="fail"} 2`,
		`plumbline_check_results{connection="github:x",result="unknown"} 0`,
		`plumbline_queue_depth 3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
}
