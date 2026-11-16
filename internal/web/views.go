package web

import (
	"fmt"
	"strings"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
	"github.com/Rahul03082001/plumbline-sspm/internal/scan"
)

// View models: plain structs with everything a template needs, already
// decided in Go. Templates only print fields and loop; they never compute.

// cardView is one dashboard card (also the "refreshed card" htmx fragment).
type cardView struct {
	ID           string
	DomID        string // safe for an HTML id / CSS selector
	Name         string
	Simulated    bool
	HasScan      bool
	Score        scoreView
	FailCounts   []scan.SeverityCount
	TotalFails   int
	Unverifiable int
	LastScanAt   *time.Time
	Failure      *failureView
	ActiveScanID string
}

// scoreView renders "Score 74 · 11 of 14 checks assessed (79%)" and all the
// honesty rules around it (spec section 5).
type scoreView struct {
	Visible         bool // false -> "Insufficient coverage"
	Score           int
	Assessed, Total int
	CoveragePct     int
	NotComparable   bool
	HasPrevious     bool
	PrevCoveragePct int
	Delta           int
	ShowDelta       bool // never true when not comparable
	UnknownReasons  []scan.ReasonCount
}

type failureView struct {
	Code       string
	Message    string
	RetryAfter *time.Time
}

func newScoreView(sum scan.ConnectionSummary) scoreView {
	l := sum.Latest
	if l == nil {
		return scoreView{}
	}
	v := scoreView{
		Visible: l.ScoreVisible(), Score: l.Score, Assessed: l.ChecksAssessed, Total: l.ChecksTotal,
		CoveragePct: l.CoveragePct(), NotComparable: !l.Comparable, UnknownReasons: sum.UnknownReasons,
	}
	if sum.Previous != nil {
		v.HasPrevious = true
		v.PrevCoveragePct = sum.Previous.CoveragePct()
	}
	v.Delta, v.ShowDelta = sum.ScoreDelta()
	return v
}

func newCardView(sum scan.ConnectionSummary) cardView {
	c := cardView{
		ID: sum.Connection.ID, DomID: domID(sum.Connection.ID), Name: sum.Connection.DisplayName,
		Simulated: sum.Connection.Mode == model.ModeSimulated, HasScan: sum.Latest != nil,
		Score: newScoreView(sum), FailCounts: sum.FailBySeverity, Unverifiable: sum.Unverifiable,
	}
	for _, f := range sum.FailBySeverity {
		c.TotalFails += f.Count
	}
	if sum.Latest != nil {
		c.LastScanAt = sum.Latest.FinishedAt
	}
	if f := sum.LastFailure(); f != nil {
		c.Failure = newFailureView(*f)
	}
	if sum.Active != nil {
		c.ActiveScanID = sum.Active.ID
	}
	return c
}

func newFailureView(s model.Scan) *failureView {
	f := &failureView{Code: s.Error, RetryAfter: s.RetryAfter}
	switch s.Error {
	case scan.FailRateLimited:
		f.Message = "Rate limited by GitHub; try again after"
	case scan.FailUnauthorized:
		f.Message = "GitHub rejected the token (401). It may have expired."
	case scan.FailTimeout:
		f.Message = "The last scan timed out. Previous results are still shown."
	case scan.FailInterrupted:
		f.Message = "The last scan was interrupted by a restart."
	default:
		f.Message = fmt.Sprintf("The last scan failed (%s). Previous results are still shown.", s.Error)
	}
	return f
}

// domID turns "github:acme-demo" into "github-acme-demo". A ':' in an id
// would be read as a CSS pseudo-class by htmx's "#id" selectors.
func domID(id string) string {
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

// statusView is the self-polling "scan status" fragment.
type statusView struct {
	ScanID  string
	View    string // "card" or "page": what to return once the scan finishes
	Message string
	Class   string
}

// ---- sparkline ---------------------------------------------------------------

const (
	sparkW = 300
	sparkH = 64
	sparkP = 6 // padding so dots at 0/100 aren't clipped
)

// sparkView is an inline-SVG trend of the last 10 scans.
type sparkView struct {
	W, H          int
	ThresholdY    int      // the 60% line: below it no score is shown
	ScoreSegments []string // each is a polyline "x,y x,y"; gaps split segments
	CoverageLine  string
	ScoreDots     []dot
	GapDots       []dot // scans whose score is left out of the line
	Count         int
}

type dot struct{ X, Y int }

// newSparkView draws score (with gaps) and coverage. A scan's score point is
// left out (a gap) when it isn't comparable with the scan before it, or its
// coverage was too low to show a score. Otherwise a rise caused by lost
// visibility would look like progress.
func newSparkView(history []model.Scan) sparkView {
	v := sparkView{W: sparkW, H: sparkH, Count: len(history)}
	minCov := model.MinCoverage // a variable, so the float-to-int conversion happens at run time
	v.ThresholdY = sparkP + int((1-minCov)*float64(sparkH-2*sparkP)+0.5)
	if len(history) == 0 {
		return v
	}
	x := func(i int) int {
		if len(history) == 1 {
			return sparkW / 2
		}
		return sparkP + i*(sparkW-2*sparkP)/(len(history)-1)
	}
	y := func(pct float64) int { return sparkP + int((1-pct/100)*float64(sparkH-2*sparkP)+0.5) }

	var cov []string
	var seg []string
	flush := func() {
		if len(seg) > 1 {
			v.ScoreSegments = append(v.ScoreSegments, strings.Join(seg, " "))
		}
		seg = nil
	}
	for i, s := range history {
		cov = append(cov, fmt.Sprintf("%d,%d", x(i), y(s.Coverage()*100)))
		gap := !s.ScoreVisible() || (i > 0 && !s.Comparable)
		if gap {
			flush()
			v.GapDots = append(v.GapDots, dot{x(i), y(s.Coverage() * 100)})
			continue
		}
		p := dot{x(i), y(float64(s.Score))}
		seg = append(seg, fmt.Sprintf("%d,%d", p.X, p.Y))
		v.ScoreDots = append(v.ScoreDots, p)
	}
	flush()
	if len(cov) > 1 {
		v.CoverageLine = strings.Join(cov, " ")
	}
	return v
}

// ---- small helpers used by templates -------------------------------------------

func severityClass(s model.Severity) string { return "sev-" + string(s) }

func reasonText(reason string) string {
	switch reason {
	case model.ReasonPermissionDenied:
		return "permission denied"
	case model.ReasonNotFoundOrNoAccess:
		return "not found or no access"
	case model.ReasonNotAvailableReadOnly:
		return "not available to a read-only token"
	case model.ReasonFieldNotReturned:
		return "field not returned"
	case model.ReasonCollectionIncomplete:
		return "asset not listed (incomplete collection)"
	case model.ReasonServerError:
		return "GitHub server error"
	case model.ReasonMissing:
		return "value missing"
	case "unprocessable":
		return "request rejected (422)"
	case "":
		return "unknown"
	}
	return strings.ReplaceAll(reason, "_", " ")
}
