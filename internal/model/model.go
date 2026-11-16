// Package model holds the provider-agnostic types shared by every other
// package: connectors produce Assets, the rule engine turns Assets into
// CheckResults, and the scan package stores them.
//
// Keeping these types in one small package with no dependencies means the
// compiler checks the "contract" between connectors and the rule engine.
package model

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// AssetKind is a named string type. Using a distinct type (instead of plain
// string) lets the compiler stop us from passing, say, a rule ID where a kind
// is expected.
type AssetKind string

const (
	KindOrg     AssetKind = "org"
	KindUser    AssetKind = "user"
	KindRepo    AssetKind = "repo"
	KindWebhook AssetKind = "webhook"
)

// AllKinds lists every kind a GitHub connector enumerates. Order is the
// display order in the UI.
var AllKinds = []AssetKind{KindOrg, KindUser, KindRepo, KindWebhook}

// Mode says whether a connection talks to a real API or to demo data.
type Mode string

const (
	ModeLive      Mode = "live"
	ModeSimulated Mode = "simulated"
)

// Connection is one SaaS tenant we scan, e.g. "github:acme-demo".
type Connection struct {
	ID          string
	Provider    string
	DisplayName string
	Mode        Mode
	CreatedAt   time.Time
}

// ScanStatus is the lifecycle of a scan: queued -> running -> succeeded|failed.
type ScanStatus string

const (
	ScanQueued    ScanStatus = "queued"
	ScanRunning   ScanStatus = "running"
	ScanSucceeded ScanStatus = "succeeded"
	ScanFailed    ScanStatus = "failed"
)

// Active reports whether the scan still occupies the connection's single
// "active scan" slot.
func (s ScanStatus) Active() bool { return s == ScanQueued || s == ScanRunning }

// Scan is one run of a connector plus rule evaluation.
// Score/Checks*/Comparable are only meaningful when Status == ScanSucceeded.
type Scan struct {
	ID             string
	ConnectionID   string
	Status         ScanStatus
	Error          string
	RetryAfter     *time.Time // pointer = optional value (nil means "not set")
	Score          int
	ChecksTotal    int
	ChecksAssessed int
	ChecksUnknown  int
	Comparable     bool
	// CollectionIncomplete means at least one asset listing was partial,
	// failed, or missing. Check counts then describe only the known inventory.
	CollectionIncomplete bool
	CreatedAt            time.Time
	StartedAt            *time.Time
	FinishedAt           *time.Time
}

// MinCoverage is the threshold below which we refuse to show a score.
const MinCoverage = 0.60

// Coverage = assessed / total for known assets. It is not overall coverage
// when CollectionIncomplete is true. A scan with zero applicable checks has zero
// coverage (we assessed nothing), not 100%.
func (s Scan) Coverage() float64 {
	if s.ChecksTotal == 0 {
		return 0
	}
	return float64(s.ChecksAssessed) / float64(s.ChecksTotal)
}

// CoveragePct is Coverage rounded to a whole percent for display.
func (s Scan) CoveragePct() int {
	return int(s.Coverage()*100 + 0.5)
}

// ScoreVisible is false when too little was assessed for the score to mean
// anything. The UI then shows "Insufficient coverage" instead of a number.
func (s Scan) ScoreVisible() bool {
	return s.Status == ScanSucceeded && !s.CollectionIncomplete && s.Coverage() >= MinCoverage
}

// CollectionStatus records whether listing an asset kind fully succeeded.
type CollectionStatus string

const (
	CollectionComplete CollectionStatus = "complete" // every page returned 2xx
	CollectionPartial  CollectionStatus = "partial"  // an error after page 1
	CollectionFailed   CollectionStatus = "failed"   // the listing call itself failed
)

// Collection is the per-kind enumeration outcome of one scan.
type Collection struct {
	Kind   AssetKind
	Status CollectionStatus
	Reason string // e.g. "permission_denied"; empty when complete
}

// Unknown-reason codes. Using constants avoids typos in string literals.
const (
	ReasonPermissionDenied     = "permission_denied"
	ReasonNotFoundOrNoAccess   = "not_found_or_no_access"
	ReasonNotAvailableReadOnly = "not_available_read_only"
	ReasonFieldNotReturned     = "field_not_returned"
	ReasonServerError          = "server_error"
	ReasonCollectionIncomplete = "collection_incomplete"
	ReasonMissing              = "missing"
	ReasonUnprocessable        = "unprocessable"
)

// UnknownReason explains why an attribute could not be read.
type UnknownReason struct {
	Reason   string `json:"reason"`
	Endpoint string `json:"endpoint,omitempty"` // endpoint *pattern*, never a full URL
}

// Asset is one normalized resource: an org, a user, a repo, or a webhook.
type Asset struct {
	ID         string
	ScanID     string
	Kind       AssetKind
	ExternalID string // the provider's own stable ID
	Name       string
	Attributes Attributes               // known values only; absent key = unknown
	Unknown    map[string]UnknownReason // why some attributes are absent
	// CarriedForward is true when the asset was not seen this scan because
	// its kind's listing was incomplete. It is copied from the previous scan
	// with empty attributes, so every check on it is "unknown".
	CarriedForward bool
}

// Key identifies an asset across scans of the same connection.
func (a Asset) Key() string { return string(a.Kind) + "/" + a.ExternalID }

// Result is the three-valued outcome of one rule on one asset.
type Result string

const (
	Pass    Result = "pass"
	Fail    Result = "fail"
	Unknown Result = "unknown"
)

// Severity of a rule. Weight is how many points a failing check costs.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Weight returns the score penalty for one failing check of this severity.
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 15
	case SeverityHigh:
		return 8
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 1
	}
	return 0
}

// Rank orders severities for sorting (critical first).
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	}
	return 4
}

// Severities lists valid severities in display order.
var Severities = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}

// CheckResult is the outcome of one rule evaluated against one asset in one
// scan. A "finding" is simply a CheckResult whose Result is Fail.
type CheckResult struct {
	ID          string
	ScanID      string
	RuleID      string
	AssetID     string
	Fingerprint string
	Result      Result
	Severity    Severity
	Evidence    Evidence

	// History fields (see DECISIONS.md, "last_definitive"):
	LastDefinitive       Result // "" (never known), Pass, or Fail
	LastDefinitiveScanID string
	FirstFailedScanID    string
}

// Evidence explains a result: the values used, or why it is unknown.
// It is stored as JSON in the evidence column.
type Evidence struct {
	Values           map[string]any `json:"values,omitempty"`
	Reason           string         `json:"reason,omitempty"`
	Endpoint         string         `json:"endpoint,omitempty"`
	UnknownFields    []string       `json:"unknown_fields,omitempty"`
	CollectionStatus string         `json:"collection_status,omitempty"`
}

// Fingerprint identifies "this rule on this asset" across scans.
// sha256(connection_id | rule_id | asset_kind | external_id), hex encoded.
// Including connection and kind means two different tenants (or a user and a
// repo that happen to share a numeric ID) can never share a fingerprint.
func Fingerprint(connectionID, ruleID string, kind AssetKind, externalID string) string {
	sum := sha256.Sum256([]byte(connectionID + "|" + ruleID + "|" + string(kind) + "|" + externalID))
	return hex.EncodeToString(sum[:])
}

// NewID returns a random UUID v4 string. Ten lines here save a third-party
// dependency (see DECISIONS.md, "Few dependencies").
func NewID() string {
	var b [16]byte
	// crypto/rand.Read never returns an error on supported platforms
	// (documented since Go 1.24), so we can ignore the return values.
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
