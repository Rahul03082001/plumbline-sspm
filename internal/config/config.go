// Package config reads all settings from environment variables.
//
// Twelve-factor style: no config files, no flags. Cloud Run injects env vars,
// and the GitHub token arrives as an env var mounted from Secret Manager.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds every setting the app needs. It is built once in main and
// passed down explicitly (no global variables).
type Config struct {
	Port   string // HTTP port, Cloud Run sets PORT=8080
	DBPath string // SQLite file path

	// Live GitHub connector. Both must be set, or neither.
	GitHubToken  string
	GitHubOrg    string
	GitHubAPIURL string // overridable for tests; defaults to https://api.github.com

	// SimulatedScanDelay makes the simulated scan take a little time, so a
	// visitor can watch "queued -> running -> succeeded" and a quick second
	// click shows "Scan already running". See DECISIONS.md.
	SimulatedScanDelay time.Duration

	// TrustedProxyHops: how many proxies in front of us append to
	// X-Forwarded-For. 0 = use the TCP peer address (local runs).
	// Cloud Run = 1. Used only for the per-IP rate limiter.
	TrustedProxyHops int

	LogLevel string // debug | info | warn | error
}

// Load reads the environment and validates it.
func Load() (Config, error) {
	return load(os.Getenv)
}

// load takes the lookup function as a parameter so tests can pass a fake
// environment instead of calling os.Setenv (which is global state).
func load(getenv func(string) string) (Config, error) {
	cfg := Config{
		Port:         withDefault(getenv("PORT"), "8080"),
		DBPath:       withDefault(getenv("DB_PATH"), "./plumbline.db"),
		GitHubToken:  getenv("GITHUB_TOKEN"),
		GitHubOrg:    getenv("GITHUB_ORG"),
		GitHubAPIURL: withDefault(getenv("GITHUB_API_URL"), "https://api.github.com"),
		LogLevel:     withDefault(getenv("LOG_LEVEL"), "info"),
	}

	delay, err := time.ParseDuration(withDefault(getenv("SIMULATED_SCAN_DELAY"), "2s"))
	if err != nil || delay < 0 {
		return Config{}, fmt.Errorf("SIMULATED_SCAN_DELAY: must be a duration like 2s, got %q", getenv("SIMULATED_SCAN_DELAY"))
	}
	cfg.SimulatedScanDelay = delay

	hops, err := strconv.Atoi(withDefault(getenv("TRUSTED_PROXY_HOPS"), "0"))
	if err != nil || hops < 0 {
		return Config{}, fmt.Errorf("TRUSTED_PROXY_HOPS: must be a non-negative integer, got %q", getenv("TRUSTED_PROXY_HOPS"))
	}
	cfg.TrustedProxyHops = hops

	// Half-configured live connector is almost always a deploy mistake, so we
	// fail loudly at startup instead of silently skipping the live scan.
	if (cfg.GitHubToken == "") != (cfg.GitHubOrg == "") {
		return Config{}, errors.New("GITHUB_TOKEN and GITHUB_ORG must be set together (or both left empty)")
	}
	return cfg, nil
}

// LiveEnabled reports whether the live GitHub connector should be registered.
func (c Config) LiveEnabled() bool {
	return c.GitHubToken != "" && c.GitHubOrg != ""
}

func withDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
