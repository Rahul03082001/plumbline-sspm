// Package simulated is a fake GitHub tenant ("github:acme-demo") whose data
// changes between scans, so visitors to the demo can see drift.
//
// It does NOT have its own collector or normalizer. Instead it pretends to be
// GitHub's REST API at the HTTP level (an http.RoundTripper serving embedded
// JSON in GitHub's real response shapes), and plugs that into the same
// github.Connector the live scan uses. So the demo exercises the real client,
// pagination, error classification and normalizer. See DECISIONS.md.
package simulated

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/connector"
	"github.com/Rahul03082001/plumbline-sspm/internal/connector/github"
)

//go:embed fixtures
var fixtures embed.FS

const (
	// Org is the simulated organization's login.
	Org = "acme-demo"
	// ConnectionID is the simulated connection's ID.
	ConnectionID = "github:" + Org
	// baseURL uses the reserved .invalid TLD, which can never resolve, so
	// even a bug could not send a simulated request to a real host.
	baseURL = "https://api.simulated.invalid"
)

// Cycle is the order of fixture versions: v1 -> v2 -> v2 -> v1, repeating.
// That sequence shows, in four clicks: a fix (resolved), lost access
// (unverifiable), still lost (still unverifiable), access back (persisting,
// NOT new), and a regression.
var Cycle = []string{"v1", "v2", "v2", "v1"}

// Connector is the simulated tenant. It is safe for concurrent use.
type Connector struct {
	mu    sync.Mutex // guards next
	next  int        // index into Cycle for the next scan
	delay time.Duration
}

// New returns a simulated connector. startAt is how many scans have already
// succeeded (from the database), so the cycle continues after a restart.
// delay makes each scan take a little time so the UI can show progress.
func New(startAt int, delay time.Duration) *Connector {
	return &Connector{next: startAt, delay: delay}
}

var _ connector.Connector = (*Connector)(nil)

// Collect serves the next fixture version through the real GitHub connector.
func (c *Connector) Collect(ctx context.Context) (connector.Snapshot, error) {
	c.mu.Lock()
	version := Cycle[c.next%len(Cycle)]
	c.next++
	c.mu.Unlock()

	if c.delay > 0 {
		t := time.NewTimer(c.delay)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			return connector.Snapshot{}, ctx.Err()
		}
	}

	client, err := github.NewClient(github.ClientOptions{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Transport: &Transport{Version: version}},
		// No token and no Observer: nothing secret here, and demo traffic
		// must not show up in the GitHub request metrics.
	})
	if err != nil {
		return connector.Snapshot{}, err
	}
	return github.New(client, Org).Collect(ctx)
}

// Transport answers GitHub API requests from the embedded fixtures.
type Transport struct {
	Version string // "v1" or "v2"
}

// RoundTrip implements http.RoundTripper: the one method http.Client calls
// to turn a request into a response.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet {
		return nil, fmt.Errorf("simulated GitHub: only GET is supported, got %s", req.Method)
	}
	path := req.URL.Path
	q := req.URL.Query()
	prefix := "/orgs/" + Org

	var file string
	switch {
	case path == prefix:
		file = "org"
	case path == prefix+"/members" && q.Get("role") == "admin":
		file = "members_admin"
	case path == prefix+"/members" && q.Get("filter") == "2fa_disabled":
		file = "members_2fa_disabled"
	case path == prefix+"/members":
		file = "members"
	case path == prefix+"/outside_collaborators" && q.Get("filter") == "2fa_disabled":
		file = "outside_collaborators_2fa_disabled"
	case path == prefix+"/outside_collaborators":
		file = "outside_collaborators"
	case path == prefix+"/repos":
		file = "repos"
	case path == prefix+"/hooks":
		file = "hooks"
	case strings.HasPrefix(path, "/repos/"+Org+"/") && strings.HasSuffix(path, "/branches/main/protection"):
		repo := strings.TrimSuffix(strings.TrimPrefix(path, "/repos/"+Org+"/"), "/branches/main/protection")
		return t.protection(req, repo)
	default:
		return reply(req, http.StatusNotFound, `{"message":"Not Found"}`), nil
	}

	if t.forbidden(file) {
		// What GitHub returns when the token lacks the needed permission.
		return reply(req, http.StatusForbidden, `{"message":"Resource not accessible by personal access token"}`), nil
	}
	body, err := t.read(file + ".json")
	if err != nil {
		return nil, err
	}
	return reply(req, http.StatusOK, string(body)), nil
}

func (t *Transport) protection(req *http.Request, repo string) (*http.Response, error) {
	body, err := t.read("branch_protection.json")
	if err != nil {
		return nil, err
	}
	var protected map[string]bool
	if err := json.Unmarshal(body, &protected); err != nil {
		return nil, err
	}
	p, ok := protected[repo]
	switch {
	case !ok:
		return reply(req, http.StatusNotFound, `{"message":"Branch not found"}`), nil
	case !p:
		return reply(req, http.StatusNotFound, `{"message":"Branch not protected"}`), nil
	}
	return reply(req, http.StatusOK, `{"url":"https://api.simulated.invalid/protection","required_pull_request_reviews":{"required_approving_review_count":1}}`), nil
}

// read returns this version's file, falling back to v1: v2 only contains
// the files that changed.
func (t *Transport) read(name string) ([]byte, error) {
	b, err := fixtures.ReadFile("fixtures/" + t.Version + "/" + name)
	if errors.Is(err, fs.ErrNotExist) && t.Version != "v1" {
		return fixtures.ReadFile("fixtures/v1/" + name)
	}
	return b, err
}

// forbidden reports whether this version simulates a 403 for file.
func (t *Transport) forbidden(file string) bool {
	b, err := fixtures.ReadFile("fixtures/" + t.Version + "/forbidden.json")
	if err != nil {
		return false
	}
	var list []string
	if json.Unmarshal(b, &list) != nil {
		return false
	}
	for _, f := range list {
		if f == file {
			return true
		}
	}
	return false
}

func reply(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    req,
	}
}
