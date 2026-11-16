// Package metrics defines Plumbline's Prometheus metrics (spec section 10)
// and implements the small observer interfaces the scan service and the
// GitHub client call. Those packages don't import Prometheus at all.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

// Metrics holds every collector on a private registry (no global state, so
// tests can create as many as they like).
type Metrics struct {
	reg            *prometheus.Registry
	scansTotal     *prometheus.CounterVec
	scanDuration   *prometheus.HistogramVec
	githubRequests *prometheus.CounterVec
	rateLimitWaits *prometheus.CounterVec
	checkResults   *prometheus.GaugeVec
}

// New creates and registers all metrics.
func New() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		scansTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "plumbline_scans_total", Help: "Finished scans by mode and final status.",
		}, []string{"mode", "status"}),
		scanDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "plumbline_scan_duration_seconds",
			Help:    "Wall-clock duration of finished scans.",
			Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 120},
		}, []string{"mode"}),
		githubRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "plumbline_github_requests_total",
			Help: "GitHub API requests by endpoint pattern and status class.",
		}, []string{"endpoint", "status_class"}),
		rateLimitWaits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "plumbline_github_rate_limit_waits_total",
			Help: "Times we waited for a GitHub rate limit, by kind (primary|secondary).",
		}, []string{"kind"}),
		checkResults: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "plumbline_check_results",
			Help: "Check results of the latest succeeded scan, by connection and result.",
		}, []string{"connection", "result"}),
	}
	m.reg.MustRegister(m.scansTotal, m.scanDuration, m.githubRequests, m.rateLimitWaits, m.checkResults,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// RegisterQueueDepth exposes plumbline_queue_depth, read live from fn.
func (m *Metrics) RegisterQueueDepth(fn func() int) {
	m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "plumbline_queue_depth", Help: "Scans waiting for a worker.",
	}, func() float64 { return float64(fn()) }))
}

// Handler serves the metrics in Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// ScanFinished implements scan.Metrics.
func (m *Metrics) ScanFinished(mode, status string, d time.Duration) {
	m.scansTotal.WithLabelValues(mode, status).Inc()
	m.scanDuration.WithLabelValues(mode).Observe(d.Seconds())
}

// CheckResults implements scan.Metrics. All three results are set so a
// result that dropped to zero doesn't keep its old value.
func (m *Metrics) CheckResults(connectionID string, counts map[model.Result]int) {
	for _, r := range []model.Result{model.Pass, model.Fail, model.Unknown} {
		m.checkResults.WithLabelValues(connectionID, string(r)).Set(float64(counts[r]))
	}
}

// GitHubRequest implements github.Observer. endpoint is a pattern such as
// "GET /orgs/{org}/hooks", never a full URL, so label cardinality stays small.
func (m *Metrics) GitHubRequest(endpoint string, status int) {
	m.githubRequests.WithLabelValues(endpoint, statusClass(status)).Inc()
}

// RateLimitWait implements github.Observer.
func (m *Metrics) RateLimitWait(kind string) {
	m.rateLimitWaits.WithLabelValues(kind).Inc()
}

func statusClass(status int) string {
	if status == 0 {
		return "network_error"
	}
	return strconv.Itoa(status/100) + "xx"
}
