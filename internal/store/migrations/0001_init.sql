-- 0001_init.sql: the schema from section 4 of the project spec.
-- Timestamps are stored as fixed-width UTC text (see store.go, formatTime),
-- so ORDER BY on them is always chronological.

CREATE TABLE connections (
  id           TEXT PRIMARY KEY,           -- "github:plumbline-demo-org", "github:acme-demo"
  provider     TEXT NOT NULL,              -- github
  display_name TEXT NOT NULL,
  mode         TEXT NOT NULL CHECK (mode IN ('live','simulated')),
  created_at   TIMESTAMP NOT NULL
);

CREATE TABLE scans (
  id                TEXT PRIMARY KEY,      -- UUID
  connection_id     TEXT NOT NULL REFERENCES connections(id),
  status            TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','failed')),
  error             TEXT,
  retry_after       TIMESTAMP,             -- set only when error = 'rate_limited'
  score             INTEGER,               -- 0..100, from ASSESSED checks only
  checks_total      INTEGER,               -- applicable (rule, asset) pairs
  checks_assessed   INTEGER,               -- pass + fail
  checks_unknown    INTEGER,
  comparable        INTEGER,               -- 1 if score is comparable to previous scan
  created_at        TIMESTAMP NOT NULL,
  started_at        TIMESTAMP,
  finished_at       TIMESTAMP
);
-- At most one active scan per connection (SQLite partial unique index).
-- The database itself refuses a second queued/running scan, so two racing
-- HTTP requests can never both start a scan.
CREATE UNIQUE INDEX one_active_scan ON scans(connection_id)
  WHERE status IN ('queued','running');
CREATE INDEX idx_scans_conn ON scans(connection_id, status, created_at);

-- Did we successfully list every asset of this kind?
CREATE TABLE collections (
  scan_id     TEXT NOT NULL REFERENCES scans(id),
  asset_kind  TEXT NOT NULL,               -- org | user | repo | webhook
  status      TEXT NOT NULL CHECK (status IN ('complete','partial','failed')),
  reason      TEXT,                        -- e.g. "permission_denied", "rate_limited"
  PRIMARY KEY (scan_id, asset_kind)
);

CREATE TABLE assets (
  id          TEXT PRIMARY KEY,
  scan_id     TEXT NOT NULL REFERENCES scans(id),
  kind        TEXT NOT NULL,               -- org | user | repo | webhook
  external_id TEXT NOT NULL,
  name        TEXT NOT NULL,
  attributes  TEXT NOT NULL,               -- JSON; absent key = unknown
  carried_forward INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_assets_scan ON assets(scan_id);

CREATE TABLE check_results (
  id           TEXT PRIMARY KEY,
  scan_id      TEXT NOT NULL REFERENCES scans(id),
  rule_id      TEXT NOT NULL,
  asset_id     TEXT NOT NULL REFERENCES assets(id),
  fingerprint  TEXT NOT NULL,
  result       TEXT NOT NULL CHECK (result IN ('pass','fail','unknown')),
  severity     TEXT NOT NULL,
  evidence     TEXT NOT NULL,
  last_definitive         TEXT CHECK (last_definitive IN ('pass','fail')),
  last_definitive_scan_id TEXT,
  first_failed_scan_id    TEXT,
  UNIQUE (scan_id, fingerprint)
);
CREATE INDEX idx_results_scan ON check_results(scan_id, result);
CREATE INDEX idx_results_fp   ON check_results(fingerprint);
