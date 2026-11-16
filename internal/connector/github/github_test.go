package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/connector"
	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

const org = "plumbline-demo-org"

// ---- test helpers -----------------------------------------------------------

// fakeSleeper records requested waits and returns immediately.
type fakeSleeper struct {
	mu    sync.Mutex
	slept []time.Duration
}

func (f *fakeSleeper) Sleep(ctx context.Context, d time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.slept = append(f.slept, d)
	return ctx.Err()
}

func (f *fakeSleeper) waits() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.slept...)
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "github", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fakeGitHub is an httptest server that answers like a healthy GitHub org.
// Tests override individual routes with `override`, which returns true if it
// handled the request.
type fakeGitHub struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	methods  map[string]int
	hits     map[string]int
	auth     map[string]bool
	override func(w http.ResponseWriter, r *http.Request) bool
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{t: t, methods: map[string]int{}, hits: map[string]int{}, auth: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.methods[r.Method]++
	f.hits[r.URL.Path+"?"+r.URL.RawQuery]++
	f.auth[r.Header.Get("Authorization")] = true
	override := f.override
	f.mu.Unlock()

	if override != nil && override(w, r) {
		return
	}
	q := r.URL.Query()
	p := r.URL.Path
	send := func(status int, name string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, fixture(f.t, name))
	}
	switch {
	case p == "/orgs/"+org:
		send(200, "org.json")
	case p == "/orgs/"+org+"/members" && q.Get("role") == "admin":
		send(200, "members_admin.json")
	case p == "/orgs/"+org+"/members" && q.Get("filter") == "2fa_disabled":
		send(200, "members_2fa_disabled.json")
	case p == "/orgs/"+org+"/members":
		send(200, "members.json")
	case p == "/orgs/"+org+"/outside_collaborators":
		w.Write([]byte("[]"))
	case p == "/orgs/"+org+"/repos":
		send(200, "repos.json")
	case p == "/repos/"+org+"/api-service/branches/main/protection":
		send(200, "protection_200.json")
	case p == "/repos/"+org+"/legacy-scripts/branches/main/protection":
		send(404, "protection_404_not_protected.json")
	case p == "/orgs/"+org+"/hooks":
		send(200, "hooks.json")
	default:
		w.WriteHeader(404)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	}
}

func (f *fakeGitHub) hitCount(pathAndQuery string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[pathAndQuery]
}

// newTestClient returns a client pointed at the fake, with a fake sleeper,
// a fixed clock, and zero jitter so timing assertions are exact.
func newTestClient(t *testing.T, f *fakeGitHub, now time.Time) (*Client, *fakeSleeper) {
	t.Helper()
	sl := &fakeSleeper{}
	c, err := NewClient(ClientOptions{
		BaseURL: f.srv.URL, Token: "test-token", Sleeper: sl,
		Now: func() time.Time { return now }, Jitter: func(time.Duration) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, sl
}

func collect(t *testing.T, f *fakeGitHub) (connector.Snapshot, *fakeSleeper, error) {
	t.Helper()
	c, sl := newTestClient(t, f, time.Now())
	snap, err := New(c, org).Collect(context.Background())
	return snap, sl, err
}

func asset(snap connector.Snapshot, kind model.AssetKind, name string) model.Asset {
	for _, a := range snap.Assets {
		if a.Kind == kind && a.Name == name {
			return a
		}
	}
	return model.Asset{}
}

// ---- happy path + normalizer --------------------------------------------------

func TestCollectFindsPlantedIssues(t *testing.T) {
	f := newFakeGitHub(t)
	snap, _, err := collect(t, f)
	if err != nil {
		t.Fatal(err)
	}
	o := asset(snap, model.KindOrg, org)
	if v, ok := model.GetBool(o.Attributes, "two_factor_required"); !ok || v {
		t.Error("2FA should be known and off")
	}
	if v, _ := model.GetString(o.Attributes, "default_repo_permission"); v != "write" {
		t.Errorf("default permission = %q", v)
	}
	legacy := asset(snap, model.KindRepo, "legacy-scripts")
	if v, ok := model.GetBool(legacy.Attributes, "default_branch_protected"); !ok || v {
		t.Error(`404 "Branch not protected" must mean protected=false`)
	}
	if v, ok := model.GetBool(legacy.Attributes, "secret_scanning"); !ok || v {
		t.Error("secret scanning should be known and off")
	}
	if v, _ := model.GetBool(asset(snap, model.KindRepo, "api-service").Attributes, "default_branch_protected"); !v {
		t.Error("api-service should be protected")
	}
	owner := asset(snap, model.KindUser, "octo-owner")
	if a, _ := model.GetBool(owner.Attributes, "is_admin"); !a {
		t.Error("octo-owner should be admin")
	}
	if m, ok := model.GetBool(owner.Attributes, "mfa_enabled"); !ok || m {
		t.Error("octo-owner should be known to lack MFA")
	}
	for _, k := range model.AllKinds {
		if snap.Collections[k].Status != model.CollectionComplete {
			t.Errorf("%s: %+v", k, snap.Collections[k])
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.auth["Bearer test-token"] || len(f.auth) != 1 {
		t.Errorf("every request must carry the token: %v", f.auth)
	}
}

func TestNormalizeHooksFromRecordedJSON(t *testing.T) {
	f := newFakeGitHub(t)
	snap, _, err := collect(t, f)
	if err != nil {
		t.Fatal(err)
	}
	plain := asset(snap, model.KindWebhook, "http://example.com")
	cases := []struct {
		a      model.Asset
		field  string
		want   any
		reason string
	}{
		{plain, "url_scheme", "http", "plain-HTTP URL"},
		{plain, "insecure_ssl", true, `insecure_ssl: "1"`},
		{plain, "has_secret", false, "no secret key"},
	}
	masked := asset(snap, model.KindWebhook, "https://hooks.example.net")
	cases = append(cases,
		struct {
			a      model.Asset
			field  string
			want   any
			reason string
		}{masked, "has_secret", true, `masked "********" secret`},
		struct {
			a      model.Asset
			field  string
			want   any
			reason string
		}{masked, "insecure_ssl", false, `insecure_ssl: "0"`})
	for _, tc := range cases {
		if got := tc.a.Attributes[tc.field]; got != tc.want {
			t.Errorf("%s: %s = %v, want %v", tc.reason, tc.field, got, tc.want)
		}
	}
	// The URL's path/query (here a fake token) must never be stored.
	enc, _ := model.EncodeAttributes(masked.Attributes, masked.Unknown)
	if strings.Contains(enc+masked.Name, "SHOULD-NOT-BE-STORED") {
		t.Fatal("webhook URL query leaked into the asset")
	}
}

func TestNormalizeOrgNonOwnerFieldsAreUnknown(t *testing.T) {
	a, err := normalizeOrg([]byte(fixture(t, "org_non_owner.json")))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"two_factor_required", "default_repo_permission", "members_can_create_public_repos"} {
		if _, present := a.Attributes[k]; present {
			t.Errorf("%s must be unknown, not a default value", k)
		}
		if a.Unknown[k].Reason != model.ReasonFieldNotReturned {
			t.Errorf("%s reason = %+v", k, a.Unknown[k])
		}
	}
}

func TestParseInsecureSSL(t *testing.T) {
	cases := []struct {
		in       any
		want, ok bool
	}{{"1", true, true}, {"0", false, true}, {1.0, true, true}, {0.0, false, true}, {"yes", false, false}, {nil, false, false}}
	for _, tc := range cases {
		if got, ok := parseInsecureSSL(tc.in); got != tc.want || ok != tc.ok {
			t.Errorf("parseInsecureSSL(%v) = %v,%v", tc.in, got, ok)
		}
	}
}

// ---- pagination ---------------------------------------------------------------

func TestPaginationFollowsLinkHeaderAcrossThreePages(t *testing.T) {
	f := newFakeGitHub(t)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/orgs/"+org+"/members" || r.URL.Query().Get("role") != "" || r.URL.Query().Get("filter") != "" {
			return false
		}
		page := r.URL.Query().Get("page")
		next := map[string]string{"": "2", "2": "3"}[page]
		if next != "" {
			w.Header().Set("Link", fmt.Sprintf(`<%s/orgs/%s/members?per_page=100&page=%s>; rel="next", <%s/orgs/%s/members?page=3>; rel="last"`,
				f.srv.URL, org, next, f.srv.URL, org))
		}
		id := map[string]int{"": 1, "2": 2, "3": 3}[page]
		fmt.Fprintf(w, `[{"login":"user-%d","id":%d}]`, id, 4000+id)
		return true
	}
	snap, _, err := collect(t, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"user-1", "user-2", "user-3"} {
		if asset(snap, model.KindUser, l).ExternalID == "" {
			t.Errorf("%s missing: pagination stopped early", l)
		}
	}
	if snap.Collections[model.KindUser].Status != model.CollectionComplete {
		t.Fatalf("got %+v", snap.Collections[model.KindUser])
	}
}

func TestPaginationRefusesForeignHost(t *testing.T) {
	f := newFakeGitHub(t)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/orgs/"+org+"/repos" {
			return false
		}
		w.Header().Set("Link", `<https://evil.example/steal?page=2>; rel="next"`)
		w.Write([]byte(`[]`))
		return true
	}
	snap, _, err := collect(t, f)
	if err != nil {
		t.Fatal(err)
	}
	c := snap.Collections[model.KindRepo]
	if c.Status != model.CollectionPartial || c.Reason != "untrusted_next_link" {
		t.Fatalf("got %+v", c)
	}
}

func TestForbiddenOnPage2MakesRepoCollectionPartial(t *testing.T) {
	f := newFakeGitHub(t)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/orgs/"+org+"/repos" {
			return false
		}
		if r.URL.Query().Get("page") == "2" {
			w.WriteHeader(403)
			w.Write([]byte(`{"message":"Resource not accessible by personal access token"}`))
			return true
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s/orgs/%s/repos?page=2>; rel="next"`, f.srv.URL, org))
		w.Write([]byte(fixture(t, "repos.json")))
		return true
	}
	snap, _, err := collect(t, f)
	if err != nil {
		t.Fatal(err)
	}
	c := snap.Collections[model.KindRepo]
	if c.Status != model.CollectionPartial || c.Reason != model.ReasonPermissionDenied {
		t.Fatalf("got %+v", c)
	}
	if asset(snap, model.KindRepo, "api-service").ExternalID == "" {
		t.Fatal("page 1 repos must still be returned")
	}
}

// ---- 404 handling for branch protection ------------------------------------------

func TestBranchProtection404s(t *testing.T) {
	cases := []struct {
		name       string
		file       string
		wantKnown  bool
		wantReason string
	}{
		{"branch not protected", "protection_404_not_protected.json", true, ""},
		{"other 404", "protection_404_not_found.json", false, model.ReasonNotFoundOrNoAccess},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeGitHub(t)
			f.override = func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.HasSuffix(r.URL.Path, "/legacy-scripts/branches/main/protection") {
					return false
				}
				w.WriteHeader(404)
				w.Write([]byte(fixture(t, tc.file)))
				return true
			}
			snap, _, err := collect(t, f)
			if err != nil {
				t.Fatal(err)
			}
			a := asset(snap, model.KindRepo, "legacy-scripts")
			v, known := model.GetBool(a.Attributes, "default_branch_protected")
			if known != tc.wantKnown || (known && v) {
				t.Fatalf("got (%v,%v)", v, known)
			}
			if !known && a.Unknown["default_branch_protected"].Reason != tc.wantReason {
				t.Fatalf("reason = %+v", a.Unknown["default_branch_protected"])
			}
		})
	}
}

// ---- rate limits ------------------------------------------------------------------

func TestPrimaryRateLimitWaitsUntilResetThenRetries(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	reset := now.Add(90 * time.Second)
	f := newFakeGitHub(t)
	var calls int
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/orgs/"+org+"/hooks" {
			return false
		}
		calls++
		if calls == 1 {
			w.Header().Set("X-Ratelimit-Remaining", "0")
			w.Header().Set("X-Ratelimit-Reset", fmt.Sprint(reset.Unix()))
			w.WriteHeader(403)
			w.Write([]byte(`{"message":"API rate limit exceeded"}`))
			return true
		}
		return false // second call: normal response
	}
	c, sl := newTestClient(t, f, now)
	snap, err := New(c, org).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waits := sl.waits()
	if len(waits) != 1 || waits[0] < 90*time.Second {
		t.Fatalf("must wait the FULL time until reset (>=90s), got %v", waits)
	}
	if snap.Collections[model.KindWebhook].Status != model.CollectionComplete {
		t.Fatal("the retry should have succeeded")
	}
}

func TestRetryAfterWaitsExactlyThatLong(t *testing.T) {
	f := newFakeGitHub(t)
	var calls int
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/orgs/"+org {
			return false
		}
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(429)
			return true
		}
		return false
	}
	_, sl, err := collect(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if w := sl.waits(); len(w) != 1 || w[0] != 30*time.Second {
		t.Fatalf("want exactly one 30s wait, got %v", w)
	}
}

func TestSecondaryRateLimitWithoutHeaderWaits60s(t *testing.T) {
	f := newFakeGitHub(t)
	var calls int
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/orgs/"+org {
			return false
		}
		calls++
		if calls <= 2 {
			w.WriteHeader(403)
			w.Write([]byte(`{"message":"You have exceeded a secondary rate limit."}`))
			return true
		}
		return false
	}
	_, sl, err := collect(t, f)
	if err != nil {
		t.Fatal(err)
	}
	// 60s, then exponential backoff on the repeat: 120s.
	if w := sl.waits(); len(w) != 2 || w[0] != 60*time.Second || w[1] != 120*time.Second {
		t.Fatalf("got %v", w)
	}
}

func TestRetryAfterLongerThanDeadlineFailsImmediately(t *testing.T) {
	f := newFakeGitHub(t)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Retry-After", "3600") // an hour; scan deadline is 2 minutes
		w.WriteHeader(429)
		return true
	}
	c, sl := newTestClient(t, f, time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, err := New(c, org).Collect(ctx)
	var rl *connector.RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("want RateLimitError, got %v", err)
	}
	if len(sl.waits()) != 0 {
		t.Fatal("must not wait at all when the wait cannot fit the deadline")
	}
	if time.Until(rl.RetryAt) < 59*time.Minute {
		t.Fatalf("RetryAt should be ~1h from now, got %v", rl.RetryAt)
	}
}

func TestRateLimitGivesUpAfterTwoRetries(t *testing.T) {
	f := newFakeGitHub(t)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(429)
		return true
	}
	_, sl, err := collect(t, f)
	var rl *connector.RateLimitError
	if !errors.As(err, &rl) || len(sl.waits()) != 2 {
		t.Fatalf("want RateLimitError after 2 waits, got %v / %v", err, sl.waits())
	}
}

// ---- permission errors, 401, 5xx -------------------------------------------------------

func TestPlain403IsUnknownWithoutRetry(t *testing.T) {
	f := newFakeGitHub(t)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/orgs/"+org+"/members" && r.URL.Query().Get("filter") == "2fa_disabled" {
			w.WriteHeader(403)
			w.Write([]byte(`{"message":"Must be an organization owner."}`))
			return true
		}
		return false
	}
	snap, sl, err := collect(t, f)
	if err != nil {
		t.Fatalf("a permission 403 must not fail the scan: %v", err)
	}
	if len(sl.waits()) != 0 {
		t.Fatal("a permission 403 must not be retried")
	}
	if n := f.hitCount("/orgs/" + org + "/members?filter=2fa_disabled&per_page=100"); n != 1 {
		t.Fatalf("2fa_disabled called %d times, want 1", n)
	}
	owner := asset(snap, model.KindUser, "octo-owner")
	if _, known := model.GetBool(owner.Attributes, "mfa_enabled"); known {
		t.Fatal("mfa_enabled must be unknown")
	}
	if r := owner.Unknown["mfa_enabled"]; r.Reason != model.ReasonPermissionDenied || r.Endpoint != epMembersNoMFA {
		t.Fatalf("got %+v", r)
	}
	if a, _ := model.GetBool(owner.Attributes, "is_admin"); !a {
		t.Fatal("other attributes still collected (the scan continued)")
	}
}

func TestForbiddenHooksListingIsFailedCollection(t *testing.T) {
	f := newFakeGitHub(t)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/orgs/"+org+"/hooks" {
			w.WriteHeader(403)
			return true
		}
		return false
	}
	snap, _, err := collect(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if c := snap.Collections[model.KindWebhook]; c.Status != model.CollectionFailed || c.Reason != model.ReasonPermissionDenied {
		t.Fatalf("got %+v", c)
	}
}

func Test401FailsScanWithoutRetry(t *testing.T) {
	f := newFakeGitHub(t)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(401)
		w.Write([]byte(`{"message":"Bad credentials"}`))
		return true
	}
	_, sl, err := collect(t, f)
	if !errors.Is(err, connector.ErrUnauthorized) {
		t.Fatalf("got %v", err)
	}
	if len(sl.waits()) != 0 || f.hitCount("/orgs/"+org+"?") != 1 {
		t.Fatal("401 must not be retried")
	}
}

func Test5xxTwiceThen200Succeeds(t *testing.T) {
	f := newFakeGitHub(t)
	var calls int
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/orgs/"+org {
			return false
		}
		calls++
		if calls <= 2 {
			w.WriteHeader(502)
			return true
		}
		return false
	}
	snap, sl, err := collect(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Collections[model.KindOrg].Status != model.CollectionComplete {
		t.Fatal("org should be collected after retries")
	}
	if w := sl.waits(); len(w) != 2 || w[0] != 500*time.Millisecond || w[1] != time.Second {
		t.Fatalf("want backoff 0.5s, 1s; got %v", w)
	}
}

func Test5xxExhaustedMarksCollectionFailed(t *testing.T) {
	f := newFakeGitHub(t)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/orgs/"+org+"/repos" {
			w.WriteHeader(503)
			return true
		}
		return false
	}
	snap, sl, err := collect(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if c := snap.Collections[model.KindRepo]; c.Status != model.CollectionFailed || c.Reason != model.ReasonServerError {
		t.Fatalf("got %+v", c)
	}
	if len(sl.waits()) != 3 {
		t.Fatalf("want 3 retries, got %v", sl.waits())
	}
}

// ---- GET only ------------------------------------------------------------------------------

func TestOnlyGETRequestsAreEverSent(t *testing.T) {
	f := newFakeGitHub(t)
	if _, _, err := collect(t, f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for method, n := range f.methods {
		if method != http.MethodGet {
			t.Fatalf("sent %d %s request(s); the connector must be read-only", n, method)
		}
	}
	if f.methods[http.MethodGet] < 9 {
		t.Fatalf("expected the full set of GETs, got %d", f.methods[http.MethodGet])
	}
}

func TestBranchProtectionConcurrencyIsBounded(t *testing.T) {
	f := newFakeGitHub(t)
	var mu sync.Mutex
	inFlight, maxInFlight := 0, 0
	const n = 12
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.URL.Path == "/orgs/"+org+"/repos":
			var b strings.Builder
			b.WriteString("[")
			for i := 0; i < n; i++ {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `{"id":%d,"name":"r%d","visibility":"public","default_branch":"main","owner":{"login":"%s"}}`, 9000+i, i, org)
			}
			b.WriteString("]")
			w.Write([]byte(b.String()))
			return true
		case strings.HasSuffix(r.URL.Path, "/protection"):
			mu.Lock()
			inFlight++
			if inFlight > maxInFlight {
				maxInFlight = inFlight
			}
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
			mu.Lock()
			inFlight--
			mu.Unlock()
			w.Write([]byte(`{}`))
			return true
		}
		return false
	}
	if _, _, err := collect(t, f); err != nil {
		t.Fatal(err)
	}
	if maxInFlight > protectionConcurrency || maxInFlight < 2 {
		t.Fatalf("max concurrent protection calls = %d, want 2..%d", maxInFlight, protectionConcurrency)
	}
}

func TestNextLink(t *testing.T) {
	h := `<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"`
	if got := nextLink(h); got != "https://api.github.com/x?page=2" {
		t.Fatalf("got %q", got)
	}
	if nextLink(`<https://api.github.com/x?page=1>; rel="prev"`) != "" || nextLink("") != "" {
		t.Fatal("no next link expected")
	}
}
