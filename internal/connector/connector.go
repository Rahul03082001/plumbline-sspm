// Package connector defines the boundary between "talking to a SaaS API" and
// "evaluating posture". A connector only collects and normalizes; it never
// evaluates rules and never writes to the database.
package connector

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

// Snapshot is everything one collection produced.
type Snapshot struct {
	// Assets have no ID/ScanID yet; the scan publisher assigns them.
	Assets []model.Asset
	// Collections says, per asset kind, whether the listing was complete.
	// A kind missing from this map is treated as "failed".
	Collections map[model.AssetKind]model.Collection
}

// Connector collects a read-only snapshot of one tenant.
type Connector interface {
	// Collect returns an error only for problems that make the WHOLE scan
	// untrustworthy (bad token, rate limited past the deadline, timeout).
	// Per-endpoint problems (one 403) become "unknown" attributes instead.
	Collect(ctx context.Context) (Snapshot, error)
}

// ErrUnauthorized means the token is missing, bad, or expired (HTTP 401).
var ErrUnauthorized = errors.New("unauthorized")

// RateLimitError means the provider asked us to wait longer than the scan
// deadline allows (or we hit the retry limit). RetryAt is when to try again.
type RateLimitError struct {
	RetryAt time.Time
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limited until %s", e.RetryAt.UTC().Format(time.RFC3339))
}
