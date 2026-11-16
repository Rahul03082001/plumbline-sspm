package github

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPermissionsDocListsEveryEndpoint keeps docs/permissions.md honest: if
// the connector starts calling a new endpoint, this fails until the doc says
// which permission it needs.
func TestPermissionsDocListsEveryEndpoint(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "permissions.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for _, e := range Endpoints {
		if !strings.Contains(doc, "`"+e.Endpoint+"`") {
			t.Errorf("docs/permissions.md does not list %s", e.Endpoint)
		}
		if !strings.HasPrefix(e.Endpoint, "GET ") {
			t.Errorf("%s: every endpoint must be a GET", e.Endpoint)
		}
	}
}
