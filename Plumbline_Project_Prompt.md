# Plumbline: Mini SaaS Security Posture Manager (SSPM), v3.1

> **How to use this file:** Paste the **Master Context** (section 2) into your AI coding tool at the start of every session. Then work through the **Build Phases** (section 12) one at a time, checking each phase's "done when" criteria before moving on. Don't ask the AI to build everything at once: you must be able to explain every part in an interview.

> **What changed in v3.1 (final; scope is frozen):** findings keep their history through any number of unknown scans (`last_definitive` tracking, carry-forward of all previously known assets); htmx configured to show 409/429 fragments, with Playwright checks; two wording fixes.
>
> **What changed in v3:** a missing asset only counts as removed after a *complete* listing; scores are flagged "not comparable" when visibility drops; Retry-After waits are honored in full; crash-recovery claims are narrowed for Cloud Run; htmx gets HTML fragment endpoints; current Go version; size and cold-start claims are now things to measure; separate rule for plain-HTTP webhooks.
>
> **What changed in v2:** correct Cloud Run setup (CPU, single instance), a truly read-only fine-grained GitHub token, coverage-aware scoring, an "unverifiable" drift state, correct 403/404/429 handling, scan consistency (one active scan, atomic publish, crash recovery), honest "simulated provider" wording, GitHub-first scope, and a section on why Go was chosen over Python.

---

## 0. Project in one paragraph

- **Name:** Plumbline (a plumb line checks whether a wall is truly straight, not just whether it looks straight)
- **Repository:** `plumbline-sspm` · Go module: `github.com/<your-username>/plumbline-sspm` · binary: `plumbline`
- **Tagline:** "Measure SaaS security posture. Detect drift. Never mistake lost access for a fix."

Plumbline connects to a GitHub organization through its REST API using a **read-only** token, collects security-relevant configuration, normalizes it into a provider-agnostic asset model, and evaluates it against posture rules. For every rule and asset it records **pass, fail, or unknown**, then shows a posture score **together with assessment coverage**, findings with evidence and remediation, and **drift** since the last scan (new, resolved, and unverifiable). It ships with **one live integration (GitHub)** and **one simulated GitHub tenant** whose data changes between scans, so visitors to the live link can see drift. Simulated Google Workspace and Slack tenants are optional stretch goals that show the design is extensible; they are **not** real integrations.

---

## 1. Why Go and not Python (read this before building, and use it in interviews)

You're stronger in Python, so this choice needs a real reason. Here's the honest case.

**Why Go fits this workload:**
1. **Concurrent I/O is central to it.** A scanner makes many API calls, fans out over repos, runs a worker pool, and must respect timeouts and cancellation. Goroutines, channels, and `context.Context` are built into the language and standard library, and every outbound call naturally carries a deadline. In Python I'd be choosing between asyncio, threads, and Celery, and mixing sync and async libraries.
2. **A single static binary.** With `CGO_ENABLED=0` and a pure-Go SQLite driver, the app ships as one file in a minimal distroless image, with no language runtime to install and far fewer OS packages to patch than a typical Python image. **Measure** the image size and cold-start time after you deploy and use your real numbers; don't quote estimates.
3. **A smaller dependency surface.** The standard library covers the HTTP server and client, JSON, HTML templates, embedded files, crypto, and testing. A security product should have few third-party dependencies. **Count** your direct dependencies in `go.mod` once you're done and quote that number.
4. **Static types for the core model.** Assets, check results, and rules are shared contracts between connectors and the rule engine. The compiler catches mismatches that Python would only surface at runtime or through extra tooling.
5. **The race detector.** `go test -race` checks the worker pool and queue for data races, which is hard to do as cheaply in Python.
6. **Career fit.** The posting lists Go alongside Java and Python. My resume already shows Python and Java in production; Go fills the gap and is common in cloud and cloud-security backends.

**Tradeoffs I accepted (say these out loud; it shows judgment):**
- Python would have been faster for me to write, and its SaaS SDKs are more mature.
- Go's JSON handling for loosely structured data (`map[string]any` attributes) is more verbose. I contained that in one helper package.
- For heavy data analysis (pandas-style work), I'd pick Python. This project is I/O and concurrency-heavy, not analysis-heavy.

**30-second interview answer:**
> "I'm strongest in Python, but I picked Go on purpose. The scanner is mostly concurrent API calls that need timeouts, bounded parallelism, and cancellation, and goroutines, errgroup, and context handle that natively. Interfaces made the connector boundary clean, and the standard library covered almost everything, so I ended up with only [N] direct dependencies, which matters in a security tool. The cost was slower development while learning, and more verbose JSON handling, which I contained in one package."

**Plan for learning Go (Day 0, about 3 hours, before Phase 1):**
- A Tour of Go (go.dev/tour): basics, methods and interfaces, generics (skim), concurrency
- Read: "Effective Go" sections on errors, interfaces, and goroutines
- Practice: write a tiny program that fetches 3 URLs concurrently with `context.WithTimeout` and `errgroup`
- Skim: `database/sql` and table-driven tests (go.dev/doc/tutorial/add-a-test)

Realistic timeline: **3 days is an ambitious prototype target** while learning Go; plan for 4. If time runs short, cut UI polish and the stretch goals, **not** the failure-handling tests. Trustworthy results under failure (lost permissions, incomplete collection, throttling) are this project's best interview story.

---

## 2. Master Context (paste this into your AI tool first)

```
You are helping me build "Plumbline" (repo: plumbline-sspm), a small SaaS Security Posture Management
(SSPM) service in Go. I am new to Go and must explain every line in a job
interview, so write simple, idiomatic, well-commented code. Explain any Go
idiom I may not know in a short comment. Do not add features I didn't ask for.

TECH STACK (do not change without asking):
- Go: the current stable release (check go.dev/dl); standard library first
  (net/http with method + path routing patterns, available since Go 1.22)
- SQLite via modernc.org/sqlite (pure Go, CGO_ENABLED=0) using database/sql,
  WAL mode, foreign keys ON, a single *sql.DB with SetMaxOpenConns(1) for writes
- Migrations: plain .sql files embedded with go:embed, applied at startup
- Rules: YAML embedded with go:embed, parsed with gopkg.in/yaml.v3
- UI: Go html/template + htmx 2.x (pinned version, CDN with SRI hash) + one
  hand-written CSS file + one small static JS file. No React. htmx must be
  configured to swap 409/429 fragments (see section 9).
  htmx swaps HTML, so the UI calls dedicated /ui/... endpoints that return
  HTML fragments. The /api/... endpoints return JSON only. Both call the same
  service layer; no business logic in handlers.
- Logging: log/slog (JSON). Metrics: prometheus/client_golang at /metrics
- Rate limiting: golang.org/x/time/rate. Concurrency helpers: golang.org/x/sync/errgroup
- Tests: testing package, table-driven tests, net/http/httptest fake APIs, run with -race
- Container: multi-stage Dockerfile -> gcr.io/distroless/static:nonroot
- Deploy: Cloud Run, single instance (see DEPLOYMENT CONSTRAINTS)

ARCHITECTURE:
  connector (GitHub live | GitHub simulated)
    -> collect raw config (read-only API calls), recording for EACH asset kind
       whether enumeration was complete, partial, or failed
    -> normalize into Assets (provider-agnostic schema)
    -> carry forward: EVERY asset present in the previous succeeded scan
       (including assets that were themselves carried forward or unknown) that is
       missing now, and whose kind was NOT completely enumerated, is kept with
       "unknown" results (reason: "collection_incomplete"). It stays until a
       COMPLETE listing confirms it is gone.
    -> each check result also stores last_definitive (the most recent pass/fail
       for that fingerprint), copied forward through unknown scans. Drift
       compares against last_definitive, not just the previous scan's result.
    -> rule engine produces a CheckResult for EVERY applicable (rule, asset):
       pass | fail | unknown   (unknown = data missing or not permitted)
    -> publish atomically: assets + check results + scan status/score/coverage
       in ONE database transaction
    -> drift: compare against the previous SUCCEEDED scan of the same connection
    -> UI + JSON API

SCANNING:
- POST creates a scan row (status=queued) and sends the job to a buffered
  channel; 2 workers process jobs. Statuses: queued -> running -> succeeded | failed.
- At most ONE queued/running scan per connection (enforced by a partial unique
  index; a second request returns 409 Conflict with the active scan's id).
- On startup, any scan left queued/running is marked failed with
  error="interrupted". This only helps when the DB survives a restart (local
  runs, or a persistent disk later). On Cloud Run a stopped instance loses its
  DB, so the demo resets on restart; document it that way and don't claim more.
- A failed scan publishes NOTHING; the previous succeeded scan stays current.

DEPLOYMENT CONSTRAINTS (Cloud Run):
- Background work continues after the HTTP response, so the service MUST run with
  instance-based billing (--no-cpu-throttling) or CPU is restricted after the response.
- --max-instances=1 because the queue and SQLite live inside the instance.
  --min-instances=0 (scale to zero). This is a documented single-instance demo.
  max-instances is a scaling limit, not a distributed lock (e.g. old and new
  revisions can overlap during a deploy). Real coordination would need a shared
  database and a durable task queue; say so in the README.
- SQLite is on the instance's in-memory filesystem: data resets on restart.
  On startup, seed the simulated tenant and run its first scans so the
  dashboard is never empty.

SECURITY REQUIREMENTS FOR THE APP ITSELF:
- GitHub token only from env (mounted from Secret Manager). Never accept tokens
  from visitors. Never log tokens, Authorization headers, or raw API bodies.
- The token is a fine-grained PAT with READ-ONLY permissions. The connector
  only issues GET requests; add a test that fails if any non-GET is sent.
- Scan creation is rate limited per IP (5/minute) -> 429.
- Security headers: CSP (allow only self + the htmx CDN), X-Content-Type-Options,
  Referrer-Policy: no-referrer, frame-ancestors 'none'.
- Never wrap API-derived data in template.HTML.
- Every outbound request uses a context with a timeout.

PROJECT LAYOUT:
  cmd/plumbline/main.go             wiring, config, startup recovery, graceful shutdown
  internal/config/
  internal/store/                  DB, migrations (store/migrations/*.sql), transactions
  internal/model/                  Asset, Rule, CheckResult, Scan, attribute helpers
  internal/connector/              Connector interface
  internal/connector/github/       live connector (client, pagination, retries, normalize)
  internal/connector/simulated/    simulated GitHub tenant (go:embed JSON, v1/v2)
  internal/rules/                  YAML loader, validator, evaluator (rules/*.yaml)
  internal/scan/                   queue, workers, publish, drift, score, coverage
  internal/web/                    handlers, middleware, templates, static
  testdata/                        recorded GitHub responses
```

---

## 3. Scope

**Core (must ship):**
- Live GitHub organization connector, read-only.
- One simulated GitHub tenant (`github:acme-demo`, labeled "Simulated") with v1/v2 data for drift.
- 9 core rules (section 5); drop SL-ORG-003 if short on time.
- Pass/fail/unknown check results, score plus coverage, drift with new, resolved, and unverifiable states.
- Dashboard, connection page, finding detail, about page, JSON API, health checks, metrics.
- Live on Cloud Run.

**Stretch (only after the core works and is deployed):**
- Simulated Google Workspace and Slack tenants plus their rules (`SL-ORG-004`, `SL-APP-001`, `SL-USER-004`).
- More GitHub checks (Dependabot alerts, stale admins).

**Out of scope:** user accounts, OAuth app installation, auto-remediation, Kafka/Pub/Sub, Postgres, Kubernetes, React. These go in the README's "Next steps".

---

## 4. Data model

```sql
CREATE TABLE connections (
  id           TEXT PRIMARY KEY,           -- "github:plumbline-demo-org", "github:acme-demo"
  provider     TEXT NOT NULL,              -- github (stretch: google_workspace, slack)
  display_name TEXT NOT NULL,
  mode         TEXT NOT NULL CHECK (mode IN ('live','simulated')),
  created_at   TIMESTAMP NOT NULL
);

CREATE TABLE scans (
  id                TEXT PRIMARY KEY,      -- UUID
  connection_id     TEXT NOT NULL REFERENCES connections(id),
  status            TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','failed')),
  error             TEXT,
  score             INTEGER,               -- 0..100, from ASSESSED checks only
  checks_total      INTEGER,               -- applicable (rule, asset) pairs
  checks_assessed   INTEGER,               -- pass + fail
  checks_unknown    INTEGER,
  comparable        INTEGER,               -- 1 if score is comparable to previous scan (section 5)
  created_at        TIMESTAMP NOT NULL,
  started_at        TIMESTAMP,
  finished_at       TIMESTAMP
);
-- At most one active scan per connection (SQLite partial unique index)
CREATE UNIQUE INDEX one_active_scan ON scans(connection_id)
  WHERE status IN ('queued','running');

-- Did we successfully list every asset of this kind?
CREATE TABLE collections (
  scan_id     TEXT NOT NULL REFERENCES scans(id),
  asset_kind  TEXT NOT NULL,               -- org | user | repo | webhook
  status      TEXT NOT NULL CHECK (status IN ('complete','partial','failed')),
  reason      TEXT,                        -- e.g. "permission_denied", "rate_limited"
  PRIMARY KEY (scan_id, asset_kind)
);
-- "complete" means every page of the listing endpoint returned 2xx.
-- Any error mid-pagination => "partial". Listing call itself denied => "failed".

CREATE TABLE assets (
  id          TEXT PRIMARY KEY,
  scan_id     TEXT NOT NULL REFERENCES scans(id),
  kind        TEXT NOT NULL,               -- org | user | repo | webhook
  external_id TEXT NOT NULL,
  name        TEXT NOT NULL,
  attributes  TEXT NOT NULL,               -- JSON; absent key = unknown
  carried_forward INTEGER NOT NULL DEFAULT 0  -- 1 = not seen this scan because its
                                              -- listing was incomplete; copied from the
                                              -- previous scan with attributes = {}
);

CREATE TABLE check_results (
  id           TEXT PRIMARY KEY,
  scan_id      TEXT NOT NULL REFERENCES scans(id),
  rule_id      TEXT NOT NULL,
  asset_id     TEXT NOT NULL REFERENCES assets(id),
  fingerprint  TEXT NOT NULL,              -- see below
  result       TEXT NOT NULL CHECK (result IN ('pass','fail','unknown')),
  severity     TEXT NOT NULL,
  evidence     TEXT NOT NULL,              -- JSON: values used, or reason for unknown
  last_definitive        TEXT CHECK (last_definitive IN ('pass','fail')),
                                           -- = result if pass/fail; if unknown, copied
                                           --   from the previous scan's row (NULL if never known)
  last_definitive_scan_id TEXT,            -- scan where last_definitive was observed
  first_failed_scan_id    TEXT,            -- start of the current unresolved run of failures;
                                           --   kept through unknown scans, reset on pass/removal
  UNIQUE (scan_id, fingerprint)
);
CREATE INDEX idx_results_scan ON check_results(scan_id, result);
CREATE INDEX idx_results_fp   ON check_results(fingerprint);
```

**Fingerprint** = `sha256(connection_id | rule_id | asset_kind | external_id)`. It's stable across scans of the same connection and can't collide across connections or asset types.

**A finding** is simply a check result with `result = 'fail'`.

**Unknown is explicit.** If an attribute is missing (null, endpoint returned 403/404 for permissions, or the feature isn't supported), the check result is `unknown` and its evidence records the reason, for example `{"reason":"permission_denied","endpoint":"GET /orgs/{org}/hooks"}`.

**Normalized attributes (GitHub core):**
- `org`: `two_factor_required` (bool), `default_repo_permission` (string), `members_can_create_public_repos` (bool)
- `user`: `login`, `is_admin` (bool), `mfa_enabled` (bool), `is_outside_collaborator` (bool)
- `repo`: `visibility`, `default_branch`, `default_branch_protected` (bool), `secret_scanning` (bool)
- `webhook`: `url_scheme` (http|https), `insecure_ssl` (bool), `has_secret` (bool). These are independent: an `https` URL can still have SSL verification turned off, and an `http` URL is unencrypted no matter what `insecure_ssl` says.

Write one small helper package (`model/attr.go`) with typed getters such as `GetBool(attrs, "mfa_enabled") (value bool, known bool)` so the rule engine never deals with `any` directly.

---

## 5. Rules

Format:
```yaml
- id: SL-USER-001
  title: Admin account without MFA
  severity: critical
  providers: [github]
  asset_kind: user
  fail_when:                        # ALL conditions true -> fail
    - { field: is_admin,    op: eq, value: true }
    - { field: mfa_enabled, op: eq, value: false }
  remediation: >
    Require two-factor authentication for the organization:
    Settings > Authentication security > Require two-factor authentication.
```
Operators: `eq`, `neq`, `in`, `contains`. Evaluation is three-valued: if any referenced field is unknown, the result is `unknown` (never pass, never fail). Validate rules at startup; an unknown operator or field is a startup error.

**Core rules (9):**

| ID | Kind | Fails when | Severity |
|---|---|---|---|
| SL-ORG-001 | org | `two_factor_required == false` | critical |
| SL-ORG-002 | org | `default_repo_permission in [write, admin]` | high |
| SL-ORG-003 | org | `members_can_create_public_repos == true` | medium |
| SL-USER-001 | user | `is_admin == true` AND `mfa_enabled == false` | critical |
| SL-REPO-001 | repo | `visibility == public` AND `default_branch_protected == false` | medium |
| SL-REPO-002 | repo | `visibility == public` AND `secret_scanning == false` | high |
| SL-HOOK-001 | webhook | `insecure_ssl == true` (SSL verification disabled) | high |
| SL-HOOK-002 | webhook | `has_secret == false` | medium |
| SL-HOOK-003 | webhook | `url_scheme == http` (payloads sent unencrypted) | high |

(Short on time? Drop SL-ORG-003.)

**Score and coverage:**
- `coverage = checks_assessed / checks_total`
- Score: start at 100 and subtract per failing check (critical 15, high 8, medium 3, low 1), floor 0. Count only assessed checks.
- If coverage is under 60%, **don't show the score number**. Show "Insufficient coverage" with the coverage percent and a list of the unknown reasons. A perfect score with little data checked is misleading.
- Always show the two together: **"Score 74 · 11 of 14 checks assessed (79%)"**.
- **Comparability.** Because unknown checks are excluded, a score can *rise* just because failing checks became unknown. Set `comparable = 0` when, compared with the previous succeeded scan, either (a) any check went from fail to unknown, or (b) coverage dropped by more than 5 percentage points. When it's not comparable:
  - show a **"Not comparable: visibility dropped"** badge next to the score,
  - show the coverage change (e.g. "Coverage 92% → 71%") and the number of unverifiable findings prominently,
  - never show a green "score improved" arrow, and leave that point out of the trend line (draw a gap) so it doesn't look like progress.

---

## 6. Drift (compare with the previous succeeded scan of the same connection)

For each fingerprint, compare the **current result** with the **last definitive state** (`last_definitive` from the previous succeeded scan, i.e. the most recent pass or fail, looking through any unknown scans in between):

| Last definitive | Current | Drift state |
|---|---|---|
| (none) or pass | fail | **new** (if last definitive was pass, label it "regressed") |
| fail | fail | persisting (even if there were unknown scans in between) |
| fail | pass | **resolved** |
| fail | unknown | **unverifiable**: shown in amber, NOT counted as resolved, and stays unverifiable on every following unknown scan |
| fail | asset missing, and that kind's collection is **complete** | **resolved (asset removed)**: shown separately |
| any | asset missing, and that kind's collection is **partial/failed** | carried forward as unknown; if last definitive was fail → **unverifiable** |
| pass or (none) | unknown | not a finding; only lowers coverage |

**Worked example (must be a test):** `fail → unknown → unknown → fail` is **persisting**, with "first seen" still pointing at the first fail. It must not become "new" again. If the next scan is `pass`, it's **resolved**. A fourth variant: `fail → missing (partial listing) → missing (partial) → missing (complete)` gives unverifiable, unverifiable, then resolved (asset removed).

Three rules keep drift trustworthy:
1. **Losing access is not fixing.** If the token loses a permission, a security problem must not look fixed.
2. **Missing is not removed.** An asset only counts as removed after a successful, complete listing of that asset kind. Until then it's carried forward, **however many incomplete scans happen in a row**, which also keeps it in the coverage denominator so coverage can't look better just because inaccessible assets disappeared.
3. **Unknown doesn't reset history.** Drift and "first seen" use the last definitive state, so a finding that was briefly unreadable keeps its history.

Explain these in interviews; this is the kind of detail SSPM teams care about.

---

## 7. GitHub live connector

### 7.1 Test organization setup (do this yourself, ~20 min)
1. Create a **free** GitHub organization (e.g. `plumbline-demo-org`).
2. Create **public** repos only (branch protection on private repos needs a paid plan):
   - `api-service`: protect `main` (require PR reviews)
   - `legacy-scripts`: no branch protection, secret scanning off if the toggle exists
3. Add an org webhook to `http://example.com/hook` with SSL verification **disabled** and **no secret**.
4. Leave "Require two-factor authentication" **off** for the org (a planted finding).
5. Set default repository permission to **Write** (a planted finding).

### 7.2 Token: fine-grained, read-only
1. Org Settings > Personal access tokens > allow fine-grained tokens (you're the owner).
2. Create a **fine-grained PAT** with **Resource owner = your org**, access to **all repositories**, expiration of 90 days, and **read-only** permissions:
   - Organization: **Members: Read**, **Administration: Read**, **Webhooks: Read**
   - Repository: **Metadata: Read**, **Administration: Read**
3. Approve the token request in the org if prompted.
4. **Before coding,** check each endpoint in section 7.3 against its "Fine-grained access tokens" box in the GitHub REST docs and record the result in `docs/permissions.md`: endpoint, permission needed, supported (yes/no). If an endpoint doesn't support fine-grained tokens or needs write access, **don't widen the token**. Mark the attribute unknown with `reason: "not_available_read_only"`. Put this table in the README; it shows least-privilege thinking.

### 7.3 Endpoints (GET only)
Headers: `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, `User-Agent: plumbline-sspm`.
- `GET /orgs/{org}` → org attributes (some fields are owner-only; null means unknown)
- `GET /orgs/{org}/members?role=admin` → admins
- `GET /orgs/{org}/members?filter=2fa_disabled` → users without 2FA (owner-only; on 403/422 mark `mfa_enabled` unknown for all users)
- `GET /orgs/{org}/outside_collaborators`
- `GET /orgs/{org}/repos?type=all` → repos, `visibility`, `security_and_analysis`
- `GET /repos/{owner}/{repo}/branches/{branch}/protection`
- `GET /orgs/{org}/hooks` → `config.insecure_ssl` ("0"/"1"), `config.url`, `config.secret` (present when set, masked)

### 7.4 Response handling (be precise)

**404 on branch protection:**
- If the body message is `"Branch not protected"` → `default_branch_protected = false`.
- Any other 404 (no access, repo or branch missing) → unknown, `reason: "not_found_or_no_access"`.
- Add `testdata/` fixtures for both cases.

**403 and 429 (classify before deciding):**
- **Primary rate limit:** 403 or 429 with `x-ratelimit-remaining: 0`. Required wait = until `x-ratelimit-reset`.
- **Secondary rate limit:** 403 or 429 with a `retry-after` header → required wait = `retry-after` seconds. With no header but a body mentioning "secondary rate limit" → required wait = 60s, then exponential backoff on repeats. Retry up to 2 times.
- **Never retry earlier than GitHub asked.** If the required wait fits inside the scan's remaining deadline, wait the *full* time and retry. If it doesn't, stop and fail the scan with `error="rate_limited"` and `retry_after=<timestamp>` (shown in the UI as "Rate limited; try again after 3:42 PM"). Nothing is published, so the previous scan stays current.
- **Any other 403** → permission problem: don't retry, mark the affected attributes unknown with `reason: "permission_denied"`, and continue the scan.
- **401** → bad or expired token: fail the whole scan with `error="unauthorized"`. Don't retry.

**5xx or network errors:** retry up to 3 times with exponential backoff + jitter (0.5s, 1s, 2s base).

**Other rules:**
- Paginate with the `Link` header (`rel="next"`), `per_page=100`.
- 10s timeout per request; 2-minute timeout for the whole scan.
- Fetch branch protection for repos concurrently with `errgroup`, limited to 4 at a time.
- Connector tests assert that only GET requests are ever sent.

---

## 8. Simulated tenant (demo data)

- `github:acme-demo`, shown everywhere with a **"Simulated"** badge.
- JSON fixtures in GitHub's own response shapes (so they go through the **same normalizer** as live data), embedded with go:embed:
  - **v1:** 20 users (3 admins, 1 admin without 2FA), 10 public repos (4 unprotected, 2 without secret scanning), 3 webhooks (1 insecure, 1 without a secret)
  - **v2:** fixes the insecure webhook; adds one new unprotected repo; **removes the `filter=2fa_disabled` response (simulates a 403)**, so the admin-without-2FA finding becomes **unverifiable**. This shows off section 6.
- Scans cycle through **v1 → v2 → v2 → v1** (then repeat). This shows on the live demo exactly the sequence that matters: admin MFA goes fail → unverifiable → still unverifiable → **persisting** (not "new"), and the fixed webhook comes back as **regressed**.
- **Stretch:** simulated `google_workspace:acme.com` and `slack:acme` tenants with their own simple JSON shapes and normalizers. Label them "Simulated" too.

---

## 9. API and pages

**JSON API**
| Method | Path | Notes |
|---|---|---|
| GET | `/api/connections` | latest score, coverage, counts per connection |
| POST | `/api/connections/{id}/scans` | 202 + scan id; 409 if a scan is active; 429 if rate limited |
| GET | `/api/scans/{id}` | status, score, coverage, counts, error |
| GET | `/api/scans/{id}/results?result=fail&severity=` | check results |
| GET | `/api/scans/{id}/drift` | `{new, resolved, resolved_asset_removed, unverifiable, persisting_count}` |
| GET | `/api/rules` | loaded rules |
| GET | `/healthz`, `/readyz`, `/metrics` | `readyz` = DB OK + rules loaded |

**HTML fragment endpoints (for htmx; return HTML, never JSON)**
| Method | Path | Returns |
|---|---|---|
| POST | `/ui/connections/{id}/scans` | a "scan status" fragment (queued) that polls itself; on 409, a fragment saying "Scan already running" that polls the active scan; on 429, a "Slow down" fragment |
| GET | `/ui/scans/{id}/status` | the status fragment; while queued/running it includes `hx-trigger="every 1s"`; once finished it returns the refreshed connection card (no more polling) |
| GET | `/ui/connections/{id}/card` | one dashboard card |
| GET | `/ui/connections/{id}/findings?severity=` | the findings table body (for filter changes) |

Both `/api/...` and `/ui/...` handlers call the same service functions; only the rendering differs.

**htmx and error status codes.** By default htmx does **not** swap 4xx/5xx responses, so the 409 and 429 fragments would silently never appear. Pin htmx **2.x** and configure response handling in the page `<head>` so those two codes swap and other errors don't:

```html
<meta name="htmx-config" content='{
  "responseHandling": [
    {"code": "204", "swap": false},
    {"code": "[23]..", "swap": true},
    {"code": "409", "swap": true, "error": false},
    {"code": "429", "swap": true, "error": false},
    {"code": "[45]..", "swap": false, "error": true}
  ]
}'>
```
Order matters: the first matching entry wins, so 409 and 429 must come before the general `[45]..` rule. Other errors show a small generic "Something went wrong" toast via an `htmx:responseError` listener in your one static JS file (not inline JS, so CSP stays strict). Check the exact `responseHandling` format against the htmx 2 docs for the version you pin.

**Pages (htmx)**
1. **Dashboard `/`**: one card per connection with a Live/Simulated badge, "Score 74 · 79% coverage" (or "Insufficient coverage"), a "Not comparable" badge when applicable, counts by severity, last scan time, and a "Run scan" button (htmx POST to `/ui/connections/{id}/scans`).
2. **Connection `/c/{id}`**: score and coverage trend (inline SVG sparkline, last 10 scans), drift panel (new / resolved / unverifiable / asset removed), findings table filterable by severity, and an "Unknown checks" table with reasons.
3. **Finding `/f/{id}`**: rule, severity, asset, evidence, remediation, first seen (`first_failed_scan_id`, kept through unknown scans), last confirmed (`last_definitive_scan_id`), and an "unverifiable since…" note when the current result is unknown.
4. **About `/about`**: architecture diagram, the permissions table from `docs/permissions.md`, the single-instance demo note, and the "1 live + simulated" disclaimer.

Top banner: *"Live: one GitHub organization scanned read-only. Simulated: demo data to show drift."*

---

## 10. Observability

- `slog` JSON with `scan_id`, `connection_id`, `mode`, `duration_ms`, `checks_assessed`, `checks_unknown`. Never log tokens, headers, or bodies.
- Metrics:
  - `plumbline_scans_total{mode,status}`
  - `plumbline_scan_duration_seconds{mode}`
  - `plumbline_github_requests_total{endpoint,status_class}` (use the endpoint *pattern*, not the full URL)
  - `plumbline_github_rate_limit_waits_total{kind}` (primary|secondary)
  - `plumbline_check_results{connection,result}` (latest scan)
  - `plumbline_queue_depth`
- Graceful shutdown on SIGTERM: stop accepting jobs, wait up to 8s for running jobs. When the database survives the restart (local runs or a persistent disk), startup recovery marks anything left running as failed. On Cloud Run the database is lost with the instance, so the demo simply resets.

---

## 11. Tests (~50; put the real number on your resume)

- **Rule engine:** every operator × pass/fail/unknown; every rule with fixtures.
- **Attribute helpers:** missing key, wrong type, and null all count as unknown.
- **Normalizer:** recorded GitHub JSON → expected assets, including masked webhook secrets and `insecure_ssl: "1"`.
- **GitHub client (httptest fake):**
  - Link-header pagination across 3 pages
  - 404 "Branch not protected" → false; other 404 → unknown
  - 403 with `x-ratelimit-remaining: 0` → waits the full time until reset, then retries (use an injectable clock/sleeper so the test is fast)
  - 429 with `retry-after: 30` → waits exactly 30s (never less), then retries
  - `retry-after` longer than the remaining scan deadline → scan fails `rate_limited` immediately, nothing published
  - 403 on page 2 of `/orgs/{org}/repos` → repo collection is `partial`
  - plain 403 → unknown, no retry, scan continues
  - 401 → scan fails, no retry
  - 5xx twice then 200 → success
  - only GET requests are ever sent
- **Scan pipeline:**
  - second POST while one is active → 409
  - an error during publish → transaction rolled back, scan failed, previous scan still current
  - startup recovery marks queued/running scans as failed
  - worker panic → recovered, scan failed
- **Drift:** v1 → v2 gives exactly the expected new / resolved / unverifiable sets.
- **Missing vs removed:** a failing repo missing from a *complete* listing → resolved (asset removed); missing from a *partial* listing → carried forward as unknown → unverifiable, and still counted in `checks_total`.
- **Multi-scan sequences** (table-driven, one row per sequence; assert drift state and first-seen scan at every step):
  - `fail → unknown → unknown → fail` → new, unverifiable, unverifiable, **persisting** (first seen = scan 1)
  - `fail → unknown → unknown → pass` → …, **resolved**
  - `pass → unknown → fail` → …, **regressed**
  - `fail → missing(partial) → missing(partial) → missing(partial)` → asset still present at scan 4, unverifiable, still in `checks_total`
  - `fail → missing(partial) → missing(complete)` → …, **resolved (asset removed)**
  - `fail → pass → fail` → new first-seen scan (scan 3), labeled regressed
- **Score/coverage:** known inputs give a known score; coverage under 60% gives "insufficient"; a fail → unknown change gives `comparable = 0` even if the score went up.
- **HTTP:** status codes, 429 limiter, security headers present; `/ui/...` endpoints return `text/html` and `/api/...` return `application/json`; the 409 and 429 `/ui` responses contain the "already running" and "slow down" fragments.
- **Browser check (Playwright, 2 tests; you've used it before):** clicking "Run scan" twice quickly shows "Scan already running" on screen; clicking past the rate limit shows "Slow down". These prove htmx actually swaps the error fragments, which server-side tests can't.

**Priority if time is short:** the failure-handling tests (rate limits, permission loss, incomplete collection, drift states) matter more than anything else in this list, and more than extra providers.
- CI runs `go vet`, `staticcheck`, `go test -race ./...`.

---

## 12. Build Phases

### Day 0 (about 3 hours): Go basics. See section 1.

### Day 1: Core engine, no network

**Phase 1: Skeleton**
```
Create the project per PROJECT LAYOUT. main.go loads config from env (PORT=8080,
DB_PATH=./plumbline.db, GITHUB_TOKEN and GITHUB_ORG optional), opens SQLite
(WAL, foreign keys on), applies embedded migrations from section 4, runs startup
recovery (queued/running scans -> failed "interrupted"), serves /healthz and
/readyz, and shuts down gracefully on SIGTERM. Add a Makefile: run, test, lint.
Explain each Go idiom you use in a short comment.
```
✅ Done when: `make run` works; `/healthz` returns 200; inserting two queued scans for one connection fails on the unique index; restarting with a leftover `running` scan marks it failed.

**Phase 2: Model, attribute helpers, rules**
```
Implement internal/model (Asset, Rule, CheckResult, Scan) and model/attr.go typed
getters returning (value, known). Implement internal/rules: load and validate the
YAML rules from section 5 and evaluate assets into CheckResults with three-valued
logic (pass/fail/unknown) and JSON evidence, including the unknown reason.
Compute fingerprints per section 4. Table-driven tests for every operator and rule.
```
✅ Done when: all rules load; `go test ./internal/rules/... ./internal/model/...` passes.

**Phase 3: Simulated tenant, queue, atomic publish, drift, score**
```
Implement the Connector interface and the simulated GitHub tenant per section 8:
JSON fixtures in GitHub's response shapes, cycling v1 → v2 → v2 → v1. Route them through
a shared normalizer package that the live connector will also use. The connector
returns assets AND a per-kind collection status (complete/partial/failed).
Implement internal/scan: buffered-channel queue, 2 workers with panic recovery,
409 on a duplicate active scan, carry-forward of ALL previously known missing
assets from incomplete collections, last_definitive / first_failed_scan_id
tracking (sections 4 and 6), publishing collections + assets + check results + scan
score/coverage/comparable/status in ONE transaction, drift states from section 6,
and score/coverage/comparability from section 5. Seed the simulated connection
and run its first scan on an empty DB. Tests for drift, missing-vs-removed,
score, coverage, comparability, rollback, and recovery.
```
✅ Done when: on startup, the simulated tenant has a succeeded scan; a second scan shows the webhook as resolved, a new unprotected repo, admin MFA as **unverifiable**, and the score marked **not comparable**; the third scan keeps admin MFA unverifiable; the fourth shows it as **persisting** with its original first-seen scan, and the webhook as **regressed**.

> **Checkpoint: don't start Day 2 until this passes.** Prove the multi-scan failure behavior with tests (section 11, "Multi-scan sequences") *before* building the connector or the dashboard. It's the core of the project's interview story.

### Day 2: Live connector and UI

**Phase 4: GitHub connector**
```
Implement internal/connector/github per section 7: GET-only client with required
headers, Link pagination, per-request and per-scan timeouts, the exact 401/403/404/
429/5xx classification in 7.4 with an injectable sleeper for tests, bounded
concurrency (errgroup, limit 4) for branch protection, and normalization through
the shared normalizer. Register it only when GITHUB_TOKEN and GITHUB_ORG are set.
Write every httptest case from section 11. Never log the token or bodies.
```
✅ Done when: a live scan of your test org finds the planted issues: 2FA not required, default permission write, unprotected `legacy-scripts`, insecure webhook without a secret. Anything the token can't read shows as unknown with a reason.

**Phase 5: API and UI**
```
Implement the JSON API, the /ui HTML fragment endpoints, and the 4 pages in
section 9 with html/template, htmx,
one CSS file (severity chips: critical red, high orange, medium amber, low gray;
unverifiable amber outline), and an inline SVG sparkline. Add the per-IP rate
limiter and security headers middleware. Handler tests.
```
✅ Done when: you can run a scan, watch the status change, see score + coverage, and see all four drift states on the simulated tenant.

**Phase 6: Observability**
```
Add slog request logging (method, route pattern, status, duration; never query
strings or headers) and the Prometheus metrics from section 10.
```
✅ Done when: `/metrics` shows scan and GitHub request counters after a live scan.

### Day 3: Ship it

**Phase 7: Container, CI, deploy**
```
Multi-stage Dockerfile: golang:<current stable, matching go.mod> build with
CGO_ENABLED=0 -> 
gcr.io/distroless/static:nonroot. GitHub Actions CI: go vet, staticcheck,
go test -race, docker build. A deploy workflow to Cloud Run on push to main using
Workload Identity Federation (no JSON keys). Deploy flags:
--no-cpu-throttling --max-instances=1 --min-instances=0 --memory=256Mi,
GITHUB_TOKEN from Secret Manager via --set-secrets, GITHUB_ORG as an env var.
Give me the exact gcloud commands for: enabling APIs, Artifact Registry repo,
secret creation, runtime service account with secretAccessor on that one secret,
deployer service account, and the WIF pool/provider bound to my repo only.
```
✅ Done when: the public URL works in incognito; the live and simulated cards both load; a scan from the live page completes.

> **Cost note:** instance-based billing charges while the instance is up. With `min-instances=0` it scales to zero when idle, and a demo should stay within or near the free tier. Set a **$5 budget alert** anyway, but know that a budget alert only **emails you; it does not stop spending**. Your real cost limits are `--max-instances=1`, `min-instances=0`, and the per-IP rate limit. Check the billing page after the first few days.
>
> **Measure after deploy** (for your README and interviews): image size (`docker images`), cold-start time (first request after idle), p50 scan duration (from `/metrics`), and direct dependency count (`go.mod`).

**Phase 8: README and polish**
```
README (under 250 lines): pitch; live demo link; screenshots; ASCII architecture;
"1 live GitHub integration + simulated tenants" stated plainly; how normalization
makes rules provider-agnostic; rule table; pass/fail/unknown and coverage; drift
states including unverifiable; permissions table (least privilege); response
handling for 401/403/404/429; Design decisions & tradeoffs: Go vs Python
(section 1), SQLite + in-process queue vs Postgres + Cloud Tasks/Pub/Sub,
single-instance Cloud Run and why --no-cpu-throttling (and that max-instances
isn't a lock), ephemeral demo data that resets on restart, atomic publish,
missing-vs-removed, comparability. Measured numbers. Run locally. Test count.
Next steps.
```
✅ Done when: someone who's never seen the code understands it in 3 minutes.

---

## 13. Before you call it done

- [ ] Live URL works in incognito; the Live/Simulated badges are visible
- [ ] Token is fine-grained, read-only, and expires; `docs/permissions.md` is filled in
- [ ] `git log -p | grep -iE "github_pat_|ghp_"` returns nothing
- [ ] CI green with `-race`; you know the exact test count
- [ ] Budget alert set
- [ ] You can explain without notes: three-valued rules, coverage, the drift states (incl. missing-vs-removed and comparability), fingerprinting, the 403-vs-rate-limit logic, why one active scan per connection, the atomic publish, why `--no-cpu-throttling` and `--max-instances=1`, and why Go
- [ ] Repo pinned on your GitHub profile

---

## 14. Resume entry (replace N and X with real numbers)

**Plumbline: SaaS Security Posture Management Scanner** · Live Demo · GitHub
*Go, SQLite, htmx, GitHub REST API, Prometheus, Docker, GCP Cloud Run, GitHub Actions*
- Built a Go SSPM scanner that collects GitHub organization configuration through a least-privilege, read-only token, normalizes it into a provider-agnostic asset model, and evaluates **N** posture rules with pass/fail/unknown results and coverage-aware scoring.
- Implemented drift detection across scans with fingerprinted results, separating resolved issues from checks that became unverifiable due to lost access, so permission loss can't mask open findings.
- Hardened the API client with Link-header pagination, primary/secondary rate-limit handling, and retry with backoff and jitter; covered failure modes with **N** table-driven and httptest-based tests run under the race detector in CI.
- Ensured results stay trustworthy under failure: assets missing from incomplete listings are carried forward as unverifiable instead of resolved, and scores are flagged non-comparable when visibility drops.
- Deployed to Cloud Run with Workload Identity Federation, Secret Manager, atomic scan publishing, and Prometheus metrics.

Don't list Google Workspace or Slack as integrations. If you build the stretch tenants, say "extensible to other providers (simulated Google Workspace and Slack tenants)".

---

## 15. Interview talking points

1. **"Walk me through a scan."** POST → 409/429 checks → queued → worker → connector (GET-only, paginated, rate-limit aware) → normalize → three-valued rules → one transaction → drift vs last succeeded scan.
2. **"Why Go?"** Use the 30-second answer in section 1, including the tradeoffs.
3. **"How would this scale to 10,000 tenants?"** Postgres; Cloud Tasks or Pub/Sub per provider for durable dispatch; per-tenant rate-limit budgets; GitHub App installation tokens instead of PATs; incremental collection from audit logs and webhooks instead of full scans; partitioned results tables.
4. **"Your token loses a permission halfway. What does the user see?"** Affected checks become unknown; assets missing from incomplete listings are carried forward rather than dropped; those findings show as unverifiable, not resolved; the score is flagged "not comparable" even if it went up; and it's hidden entirely if coverage falls under 60%.
5. **"Why not just retry every 403?"** Because most 403s are permission errors that will never succeed. Only rate-limit 403s/429s (identified by headers) are retried, and never earlier than GitHub asked. If the wait doesn't fit the scan deadline, the scan fails cleanly and the previous results stay current.
6. **"How do you add Salesforce?"** Write a new connector and normalizer; most rules carry over because they target normalized attributes, and missing capabilities show up as unknown instead of fake passes.
