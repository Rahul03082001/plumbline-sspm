// Package github is the live GitHub connector: a GET-only REST client with
// pagination, retries and rate-limit handling, plus the normalizer that turns
// GitHub's JSON into provider-agnostic model.Assets.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/connector"
)

const (
	defaultRequestTimeout = 10 * time.Second
	maxRateLimitRetries   = 2                // spec 7.4: "Retry up to 2 times"
	maxServerRetries      = 3                // spec 7.4: 5xx/network, 3 times
	secondaryDefaultWait  = 60 * time.Second // secondary limit with no retry-after
	maxBodyBytes          = 10 << 20         // 10 MiB; protects memory from huge bodies
)

// Sleeper waits for d or until ctx is done. Tests inject a fake that records
// the duration and returns instantly, so "wait 60s" tests run in microseconds.
type Sleeper interface {
	Sleep(ctx context.Context, d time.Duration) error
}

// realSleeper is the production Sleeper.
type realSleeper struct{}

func (realSleeper) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select { // whichever happens first: timer fires, or the scan is cancelled
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Observer receives metrics events. nil means "don't record" (the simulated
// tenant passes nil so demo traffic doesn't pollute GitHub request metrics).
type Observer interface {
	GitHubRequest(endpoint string, status int)
	RateLimitWait(kind string)
}

// ClientOptions configures a Client. Zero values get sensible defaults.
type ClientOptions struct {
	BaseURL        string // https://api.github.com
	Token          string // empty = no Authorization header (simulated tenant)
	HTTPClient     *http.Client
	Sleeper        Sleeper
	Now            func() time.Time
	Jitter         func(base time.Duration) time.Duration
	Observer       Observer
	Logger         *slog.Logger
	RequestTimeout time.Duration
}

// Client is a GET-only GitHub REST client. It has no method that can send
// anything other than GET; a test asserts that, too.
type Client struct {
	base    *url.URL
	token   string
	http    *http.Client
	sleeper Sleeper
	now     func() time.Time
	jitter  func(time.Duration) time.Duration
	obs     Observer
	log     *slog.Logger
	timeout time.Duration
}

// NewClient builds a Client.
func NewClient(o ClientOptions) (*Client, error) {
	base, err := url.Parse(strings.TrimSuffix(o.BaseURL, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("invalid GitHub base URL %q", o.BaseURL)
	}
	c := &Client{base: base, token: o.Token, http: o.HTTPClient, sleeper: o.Sleeper,
		now: o.Now, jitter: o.Jitter, obs: o.Observer, log: o.Logger, timeout: o.RequestTimeout}
	if c.http == nil {
		c.http = &http.Client{}
	}
	if c.sleeper == nil {
		c.sleeper = realSleeper{}
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.jitter == nil {
		// Full jitter in [0, base/2): spreads out retries from many clients.
		c.jitter = func(b time.Duration) time.Duration { return time.Duration(rand.Int64N(int64(b/2) + 1)) }
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.timeout == 0 {
		c.timeout = defaultRequestTimeout
	}
	return c, nil
}

// APIError is a non-retryable (or retries-exhausted) HTTP error for one call.
// Message is GitHub's "message" field, used ONLY to recognise
// "Branch not protected"; it is never logged or stored.
type APIError struct {
	Status   int // 0 = network error
	Endpoint string
	Message  string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: HTTP %d", e.Endpoint, e.Status)
}

// response is a successful (2xx) reply.
type response struct {
	header http.Header
	body   []byte
}

// get performs one logical GET (with retries) of an absolute URL.
// endpoint is the *pattern* (e.g. "GET /orgs/{org}/hooks") used for metrics,
// logs and evidence, so no org/repo names or query strings end up there.
func (c *Client) get(ctx context.Context, endpoint, rawURL string) (*response, error) {
	var rateLimitRetries, serverRetries, secondaryRepeats int
	for {
		if err := ctx.Err(); err != nil {
			return nil, err // scan deadline hit or cancelled
		}
		status, header, body, err := c.once(ctx, rawURL)
		if c.obs != nil {
			c.obs.GitHubRequest(endpoint, status)
		}

		// Network error or timeout of this single request.
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if serverRetries >= maxServerRetries {
				return nil, &APIError{Status: 0, Endpoint: endpoint}
			}
			if err := c.backoff(ctx, serverRetries); err != nil {
				return nil, err
			}
			serverRetries++
			continue
		}

		switch {
		case status >= 200 && status < 300:
			return &response{header: header, body: body}, nil

		case status == http.StatusUnauthorized:
			// Bad/expired token: retrying can't help, and nothing we collect
			// is trustworthy. Fail the whole scan.
			return nil, connector.ErrUnauthorized

		case status == http.StatusForbidden || status == http.StatusTooManyRequests:
			kind, wait, limited := classifyRateLimit(status, header, body, c.now(), secondaryRepeats)
			if !limited {
				// A plain 403 is a permission problem. It will never succeed,
				// so don't retry: the caller marks attributes unknown.
				return nil, &APIError{Status: status, Endpoint: endpoint, Message: githubMessage(body)}
			}
			retryAt := c.now().Add(wait)
			if rateLimitRetries >= maxRateLimitRetries || !fitsDeadline(ctx, c.now(), wait) {
				// Never retry earlier than GitHub asked. If we can't wait the
				// full time inside the scan deadline, fail the scan cleanly.
				return nil, &connector.RateLimitError{RetryAt: retryAt}
			}
			c.log.Warn("github rate limited; waiting", "endpoint", endpoint, "kind", kind, "wait_ms", wait.Milliseconds())
			if c.obs != nil {
				c.obs.RateLimitWait(kind)
			}
			if err := c.sleeper.Sleep(ctx, wait); err != nil {
				return nil, err
			}
			rateLimitRetries++
			if kind == "secondary" {
				secondaryRepeats++
			}
			continue

		case status >= 500:
			if serverRetries >= maxServerRetries {
				return nil, &APIError{Status: status, Endpoint: endpoint}
			}
			if err := c.backoff(ctx, serverRetries); err != nil {
				return nil, err
			}
			serverRetries++
			continue

		default: // 404, 422, other 4xx: not retryable
			return nil, &APIError{Status: status, Endpoint: endpoint, Message: githubMessage(body)}
		}
	}
}

// once sends exactly one GET with its own 10s timeout.
func (c *Client) once(ctx context.Context, rawURL string) (int, http.Header, []byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	// http.MethodGet is hard-coded: this client cannot send anything else.
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "plumbline-sspm")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, resp.Header, body, nil
}

// backoff sleeps 0.5s, 1s, 2s (+ jitter) for retry 0, 1, 2.
func (c *Client) backoff(ctx context.Context, retry int) error {
	base := 500 * time.Millisecond << retry // << is a bit shift: 500ms * 2^retry
	return c.sleeper.Sleep(ctx, base+c.jitter(base))
}

// classifyRateLimit decides whether a 403/429 is a rate limit, which kind,
// and how long GitHub told us to wait. Order matters (spec 7.4):
//  1. x-ratelimit-remaining: 0  -> primary limit, wait until x-ratelimit-reset
//  2. retry-after header        -> secondary limit, wait that many seconds
//  3. body says "secondary rate limit" -> secondary, 60s, doubling on repeats
//  4. a bare 429                -> treated like (3): 429 always means "slow down"
//  5. anything else             -> not a rate limit (a permission 403)
func classifyRateLimit(status int, h http.Header, body []byte, now time.Time, secondaryRepeats int) (kind string, wait time.Duration, limited bool) {
	if h.Get("X-Ratelimit-Remaining") == "0" {
		wait = secondaryDefaultWait
		if reset, err := strconv.ParseInt(h.Get("X-Ratelimit-Reset"), 10, 64); err == nil {
			// reset is a Unix time in whole seconds. +1s so we retry strictly
			// AFTER it, never a fraction of a second early.
			wait = time.Unix(reset, 0).Sub(now) + time.Second
			if wait < time.Second {
				wait = time.Second
			}
		}
		return "primary", wait, true
	}
	if ra := h.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs >= 0 {
			return "secondary", time.Duration(secs) * time.Second, true
		}
	}
	if strings.Contains(strings.ToLower(string(body)), "secondary rate limit") || status == http.StatusTooManyRequests {
		return "secondary", secondaryDefaultWait << secondaryRepeats, true
	}
	return "", 0, false
}

// fitsDeadline reports whether waiting d still leaves us inside ctx's deadline.
func fitsDeadline(ctx context.Context, now time.Time, d time.Duration) bool {
	deadline, ok := ctx.Deadline()
	return !ok || !now.Add(d).After(deadline)
}

// githubMessage extracts the "message" field of an error body, if any.
func githubMessage(body []byte) string {
	var m struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &m)
	return m.Message
}

// nextLink returns the rel="next" URL from a Link header, or "".
// Example: <https://api.github.com/orgs/x/repos?page=2>; rel="next", <...>; rel="last"
func nextLink(h string) string {
	for _, part := range strings.Split(h, ",") {
		segs := strings.Split(strings.TrimSpace(part), ";")
		if len(segs) < 2 {
			continue
		}
		u := strings.Trim(strings.TrimSpace(segs[0]), "<>")
		for _, p := range segs[1:] {
			if strings.TrimSpace(p) == `rel="next"` {
				return u
			}
		}
	}
	return ""
}

// listing is the outcome of a paginated list call.
type listing struct {
	items    []json.RawMessage
	status   string // "complete" | "partial" | "failed"
	reason   string
	endpoint string
}

// getAll follows Link rel="next" pages. Non-fatal errors become a partial
// (error after page 1) or failed (error on page 1) listing; fatal errors
// (401, rate limit, timeout) are returned as err and fail the scan.
func (c *Client) getAll(ctx context.Context, endpoint, path string) (listing, error) {
	l := listing{endpoint: endpoint, status: "complete"}
	next := c.base.String() + path
	for page := 0; next != ""; page++ {
		resp, err := c.get(ctx, endpoint, next)
		if err != nil {
			if isFatal(err) {
				return l, err
			}
			l.reason = reasonFor(err)
			l.status = "partial"
			if page == 0 {
				l.status = "failed"
			}
			return l, nil
		}
		var items []json.RawMessage
		if err := json.Unmarshal(resp.body, &items); err != nil {
			l.status, l.reason = "partial", "unexpected_response"
			if page == 0 {
				l.status = "failed"
			}
			return l, nil
		}
		l.items = append(l.items, items...)

		next = nextLink(resp.header.Get("Link"))
		if next != "" && !c.sameOrigin(next) {
			// Never follow a pagination link to another host: it would
			// receive our token. Treat the listing as incomplete instead.
			l.status, l.reason = "partial", "untrusted_next_link"
			return l, nil
		}
	}
	return l, nil
}

func (c *Client) sameOrigin(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == c.base.Scheme && u.Host == c.base.Host
}

// isFatal reports whether an error must fail the whole scan.
func isFatal(err error) bool {
	var rl *connector.RateLimitError
	return errors.Is(err, connector.ErrUnauthorized) || errors.As(err, &rl) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// reasonFor maps a non-fatal error to an unknown-reason code.
func reasonFor(err error) string {
	var api *APIError
	if !errors.As(err, &api) {
		return "server_error"
	}
	switch {
	case api.Status == http.StatusForbidden:
		return "permission_denied"
	case api.Status == http.StatusNotFound:
		return "not_found_or_no_access"
	case api.Status == http.StatusUnprocessableEntity:
		return "unprocessable"
	default:
		return "server_error"
	}
}
