package scan

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
	"github.com/Rahul03082001/plumbline-sspm/internal/store"
)

// ErrNotSucceeded is returned when drift is requested for a scan that has no
// published results.
var ErrNotSucceeded = errors.New("scan has not succeeded")

// historyLength is how many scans the trend line shows.
const historyLength = 10

// SeverityCount is the number of failing checks of one severity.
type SeverityCount struct {
	Severity model.Severity `json:"severity"`
	Count    int            `json:"count"`
}

// ReasonCount groups unknown checks by why they are unknown.
type ReasonCount struct {
	Reason   string `json:"reason"`
	Endpoint string `json:"endpoint,omitempty"`
	Count    int    `json:"count"`
}

// ConnectionSummary is everything a dashboard card shows.
type ConnectionSummary struct {
	Connection     model.Connection
	Latest         *model.Scan // current (newest succeeded) scan; nil if none
	Previous       *model.Scan // the succeeded scan before Latest
	LastAttempt    *model.Scan // newest scan of any status
	Active         *model.Scan // queued/running scan, if any
	FailBySeverity []SeverityCount
	Unverifiable   int
	UnknownReasons []ReasonCount
}

// ScoreDelta returns the change since the previous scan, and whether it
// may be shown at all. It is hidden when the scores are not comparable or
// either score is hidden for insufficient coverage: we never draw a green
// "improved" arrow that might just mean "we can see less".
func (c ConnectionSummary) ScoreDelta() (int, bool) {
	if c.Latest == nil || c.Previous == nil || !c.Latest.Comparable ||
		!c.Latest.ScoreVisible() || !c.Previous.ScoreVisible() {
		return 0, false
	}
	return c.Latest.Score - c.Previous.Score, true
}

// LastFailure returns the newest scan if it failed after the current one
// (e.g. "Rate limited; try again after 3:42 PM"), else nil.
func (c ConnectionSummary) LastFailure() *model.Scan {
	if c.LastAttempt == nil || c.LastAttempt.Status != model.ScanFailed {
		return nil
	}
	if c.Latest != nil && c.LastAttempt.CreatedAt.Before(c.Latest.CreatedAt) {
		return nil
	}
	return c.LastAttempt
}

// Connections returns a summary for every registered connection.
func (s *Service) Connections(ctx context.Context) ([]ConnectionSummary, error) {
	conns, err := s.store.ListConnections(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ConnectionSummary, 0, len(conns))
	for _, c := range conns {
		if _, ok := s.conns[c.ID]; !ok {
			continue // e.g. live connection no longer configured
		}
		sum, err := s.summary(ctx, c)
		if err != nil {
			return nil, err
		}
		out = append(out, sum)
	}
	return out, nil
}

// Connection returns one connection's summary.
func (s *Service) Connection(ctx context.Context, id string) (ConnectionSummary, error) {
	if _, ok := s.conns[id]; !ok {
		return ConnectionSummary{}, ErrUnknownConnection
	}
	c, err := s.store.GetConnection(ctx, id)
	if err != nil {
		return ConnectionSummary{}, err
	}
	return s.summary(ctx, c)
}

func (s *Service) summary(ctx context.Context, c model.Connection) (ConnectionSummary, error) {
	sum := ConnectionSummary{Connection: c}
	var err error
	if sum.Latest, err = optional(s.store.LatestSucceeded(ctx, c.ID)); err != nil {
		return sum, err
	}
	if sum.LastAttempt, err = optional(s.store.LatestScan(ctx, c.ID)); err != nil {
		return sum, err
	}
	if sum.Active, err = optional(s.store.ActiveScan(ctx, c.ID)); err != nil {
		return sum, err
	}
	if sum.Latest == nil {
		return sum, nil
	}
	if sum.Previous, err = optional(s.store.PreviousSucceeded(ctx, *sum.Latest)); err != nil {
		return sum, err
	}
	results, err := s.store.Results(ctx, sum.Latest.ID, store.ResultFilter{})
	if err != nil {
		return sum, err
	}
	sum.FailBySeverity, sum.Unverifiable, sum.UnknownReasons = tally(results)
	return sum, nil
}

// tally counts failures by severity, unverifiable findings, and unknown reasons.
func tally(results []store.ResultRow) ([]SeverityCount, int, []ReasonCount) {
	bySev := map[model.Severity]int{}
	unverifiable := 0
	type key struct{ reason, endpoint string }
	reasons := map[key]int{}
	for _, r := range results {
		switch r.Result {
		case model.Fail:
			bySev[r.Severity]++
		case model.Unknown:
			if r.LastDefinitive == model.Fail {
				unverifiable++
			}
			reasons[key{r.Evidence.Reason, r.Evidence.Endpoint}]++
		}
	}
	sev := make([]SeverityCount, 0, len(model.Severities))
	for _, s := range model.Severities {
		sev = append(sev, SeverityCount{Severity: s, Count: bySev[s]})
	}
	rc := make([]ReasonCount, 0, len(reasons))
	for k, n := range reasons {
		rc = append(rc, ReasonCount{Reason: k.reason, Endpoint: k.endpoint, Count: n})
	}
	sort.Slice(rc, func(i, j int) bool {
		if rc[i].Count != rc[j].Count {
			return rc[i].Count > rc[j].Count
		}
		return rc[i].Reason+rc[i].Endpoint < rc[j].Reason+rc[j].Endpoint
	})
	return sev, unverifiable, rc
}

// ConnectionDetail is everything the connection page shows.
type ConnectionDetail struct {
	ConnectionSummary
	History     []model.Scan // last 10 succeeded scans, oldest first
	Drift       *Drift
	Findings    []store.ResultRow // failing checks of the current scan
	Unknowns    []store.ResultRow // unknown checks of the current scan
	Collections []model.Collection
}

// ConnectionDetail loads the connection page. severity filters the findings.
func (s *Service) ConnectionDetail(ctx context.Context, id string, severity model.Severity) (ConnectionDetail, error) {
	sum, err := s.Connection(ctx, id)
	if err != nil {
		return ConnectionDetail{}, err
	}
	d := ConnectionDetail{ConnectionSummary: sum}
	if d.History, err = s.store.SucceededHistory(ctx, id, historyLength); err != nil {
		return d, err
	}
	if sum.Latest == nil {
		return d, nil
	}
	drift, err := s.Drift(ctx, sum.Latest.ID)
	if err != nil {
		return d, err
	}
	d.Drift = &drift
	if d.Findings, err = s.Findings(ctx, sum.Latest.ID, severity); err != nil {
		return d, err
	}
	if d.Unknowns, err = s.store.Results(ctx, sum.Latest.ID, store.ResultFilter{Result: model.Unknown}); err != nil {
		return d, err
	}
	d.Collections, err = s.store.Collections(ctx, sum.Latest.ID)
	return d, err
}

// Findings returns the failing checks of a scan, optionally by severity.
func (s *Service) Findings(ctx context.Context, scanID string, severity model.Severity) ([]store.ResultRow, error) {
	return s.store.Results(ctx, scanID, store.ResultFilter{Result: model.Fail, Severity: severity})
}

// Results returns a scan's check results with optional filters.
func (s *Service) Results(ctx context.Context, scanID string, f store.ResultFilter) ([]store.ResultRow, error) {
	if _, err := s.store.GetScan(ctx, scanID); err != nil {
		return nil, err
	}
	return s.store.Results(ctx, scanID, f)
}

// GetScan returns one scan.
func (s *Service) GetScan(ctx context.Context, id string) (model.Scan, error) {
	return s.store.GetScan(ctx, id)
}

// Drift compares a succeeded scan with the previous succeeded scan of the
// same connection.
func (s *Service) Drift(ctx context.Context, scanID string) (Drift, error) {
	sc, err := s.store.GetScan(ctx, scanID)
	if err != nil {
		return Drift{}, err
	}
	if sc.Status != model.ScanSucceeded {
		return Drift{}, ErrNotSucceeded
	}
	cur, err := s.store.Results(ctx, sc.ID, store.ResultFilter{})
	if err != nil {
		return Drift{}, err
	}
	var prev []store.ResultRow
	prevID := ""
	if p, err := s.store.PreviousSucceeded(ctx, sc); err == nil {
		prevID = p.ID
		if prev, err = s.store.Results(ctx, p.ID, store.ResultFilter{}); err != nil {
			return Drift{}, err
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return Drift{}, err
	}
	return computeDrift(sc.ID, prevID, cur, prev, s.titles), nil
}

// FindingDetail is everything the finding page shows.
type FindingDetail struct {
	Result            store.ResultRow
	Rule              model.Rule
	Scan              model.Scan
	Connection        model.Connection
	FirstSeen         *model.Scan // start of the current run of failures
	LastConfirmed     *model.Scan // where the last pass/fail was observed
	UnverifiableSince *model.Scan // first scan after LastConfirmed, if now unknown
	IsCurrent         bool        // belongs to the connection's current scan
}

// Finding loads one check result with its history.
func (s *Service) Finding(ctx context.Context, resultID string) (FindingDetail, error) {
	r, err := s.store.GetResult(ctx, resultID)
	if err != nil {
		return FindingDetail{}, err
	}
	d := FindingDetail{Result: r}
	if d.Scan, err = s.store.GetScan(ctx, r.ScanID); err != nil {
		return d, err
	}
	if d.Connection, err = s.store.GetConnection(ctx, d.Scan.ConnectionID); err != nil {
		return d, err
	}
	rule, ok := s.Rule(r.RuleID)
	if !ok {
		return d, fmt.Errorf("rule %s not loaded", r.RuleID)
	}
	d.Rule = rule
	if r.FirstFailedScanID != "" {
		if d.FirstSeen, err = optional(s.store.GetScan(ctx, r.FirstFailedScanID)); err != nil {
			return d, err
		}
	}
	if r.LastDefinitiveScanID != "" {
		if d.LastConfirmed, err = optional(s.store.GetScan(ctx, r.LastDefinitiveScanID)); err != nil {
			return d, err
		}
		if r.Result == model.Unknown {
			if d.UnverifiableSince, err = optional(s.store.NextSucceededAfter(ctx, d.Scan.ConnectionID, r.LastDefinitiveScanID)); err != nil {
				return d, err
			}
		}
	}
	if latest, err := s.store.LatestSucceeded(ctx, d.Scan.ConnectionID); err == nil {
		d.IsCurrent = latest.ID == d.Scan.ID
	}
	return d, nil
}

// Rules returns the loaded rules.
func (s *Service) Rules() []model.Rule { return s.rules }

// Rule returns one rule by ID.
func (s *Service) Rule(id string) (model.Rule, bool) {
	for _, r := range s.rules {
		if r.ID == id {
			return r, true
		}
	}
	return model.Rule{}, false
}

// Ready reports whether the service can serve traffic: DB reachable and
// rules loaded. Used by /readyz.
func (s *Service) Ready(ctx context.Context) error {
	if len(s.rules) == 0 {
		return errors.New("no rules loaded")
	}
	return s.store.Ping(ctx)
}

// optional turns store.ErrNotFound into (nil, nil), for "may not exist".
// It is generic: T is filled in by the compiler from the argument.
func optional[T any](v T, err error) (*T, error) {
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}
