package config

import (
	"testing"
	"time"
)

// fakeEnv turns a map into a getenv-style function.
func fakeEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := load(fakeEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "8080" || cfg.DBPath != "./plumbline.db" || cfg.SimulatedScanDelay != 2*time.Second {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.LiveEnabled() {
		t.Fatal("live connector must be off without a token")
	}
}

func TestLoadRejectsHalfConfiguredGitHub(t *testing.T) {
	// Table-driven test: each row is one case. This is the standard Go style.
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"token only", map[string]string{"GITHUB_TOKEN": "x"}},
		{"org only", map[string]string{"GITHUB_ORG": "acme"}},
		{"bad delay", map[string]string{"SIMULATED_SCAN_DELAY": "soon"}},
		{"bad hops", map[string]string{"TRUSTED_PROXY_HOPS": "-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := load(fakeEnv(tc.env)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
