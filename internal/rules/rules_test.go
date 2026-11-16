package rules

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

func TestBuiltinRulesLoad(t *testing.T) {
	rs, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"SL-HOOK-001", "SL-HOOK-002", "SL-HOOK-003", "SL-ORG-001", "SL-ORG-002",
		"SL-ORG-003", "SL-REPO-001", "SL-REPO-002", "SL-USER-001"}
	if len(rs) != len(want) {
		t.Fatalf("got %d rules, want %d", len(rs), len(want))
	}
	for i, r := range rs {
		if r.ID != want[i] {
			t.Errorf("rule %d = %s, want %s", i, r.ID, want[i])
		}
	}
}

// TestOperators covers every operator x pass/fail/unknown on a one-condition rule.
func TestOperators(t *testing.T) {
	cases := []struct {
		name  string
		field string
		op    model.Op
		value any
		attrs model.Attributes
		want  model.Result
	}{
		{"eq bool fail", "is_admin", model.OpEq, true, model.Attributes{"is_admin": true}, model.Fail},
		{"eq bool pass", "is_admin", model.OpEq, true, model.Attributes{"is_admin": false}, model.Pass},
		{"eq bool unknown", "is_admin", model.OpEq, true, model.Attributes{}, model.Unknown},
		{"eq string fail", "login", model.OpEq, "root", model.Attributes{"login": "root"}, model.Fail},
		{"neq fail", "login", model.OpNeq, "root", model.Attributes{"login": "octo"}, model.Fail},
		{"neq pass", "login", model.OpNeq, "root", model.Attributes{"login": "root"}, model.Pass},
		{"neq unknown", "login", model.OpNeq, "root", model.Attributes{"login": nil}, model.Unknown},
		{"in fail", "login", model.OpIn, []any{"a", "b"}, model.Attributes{"login": "b"}, model.Fail},
		{"in pass", "login", model.OpIn, []any{"a", "b"}, model.Attributes{"login": "c"}, model.Pass},
		{"in unknown", "login", model.OpIn, []any{"a"}, model.Attributes{}, model.Unknown},
		{"contains fail", "login", model.OpContains, "bot", model.Attributes{"login": "ci-bot-1"}, model.Fail},
		{"contains pass", "login", model.OpContains, "bot", model.Attributes{"login": "alice"}, model.Pass},
		{"contains unknown", "login", model.OpContains, "bot", model.Attributes{"login": 7.0}, model.Unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := model.Rule{ID: "SL-TEST-001", AssetKind: model.KindUser,
				FailWhen: []model.Condition{{Field: tc.field, Op: tc.op, Value: tc.value}}}
			got, _ := Evaluate(r, model.Asset{Kind: model.KindUser, Attributes: tc.attrs})
			if got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// TestEveryRule gives each built-in rule a failing, a passing and an unknown asset.
func TestEveryRule(t *testing.T) {
	rs, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]model.Rule{}
	for _, r := range rs {
		byID[r.ID] = r
	}
	type fixture struct {
		attrs model.Attributes
		want  model.Result
	}
	cases := map[string][]fixture{
		"SL-ORG-001": {
			{model.Attributes{"two_factor_required": false}, model.Fail},
			{model.Attributes{"two_factor_required": true}, model.Pass},
			{model.Attributes{"two_factor_required": nil}, model.Unknown}, // owner-only field returned null
		},
		"SL-ORG-002": {
			{model.Attributes{"default_repo_permission": "write"}, model.Fail},
			{model.Attributes{"default_repo_permission": "admin"}, model.Fail},
			{model.Attributes{"default_repo_permission": "read"}, model.Pass},
			{model.Attributes{}, model.Unknown},
		},
		"SL-ORG-003": {
			{model.Attributes{"members_can_create_public_repos": true}, model.Fail},
			{model.Attributes{"members_can_create_public_repos": false}, model.Pass},
			{model.Attributes{}, model.Unknown},
		},
		"SL-USER-001": {
			{model.Attributes{"is_admin": true, "mfa_enabled": false}, model.Fail},
			{model.Attributes{"is_admin": true, "mfa_enabled": true}, model.Pass},
			{model.Attributes{"is_admin": false, "mfa_enabled": false}, model.Pass},
			// Spec: ANY referenced field unknown -> unknown, even if the other is false.
			{model.Attributes{"is_admin": false}, model.Unknown},
			{model.Attributes{"is_admin": true}, model.Unknown},
		},
		"SL-REPO-001": {
			{model.Attributes{"visibility": "public", "default_branch_protected": false}, model.Fail},
			{model.Attributes{"visibility": "public", "default_branch_protected": true}, model.Pass},
			{model.Attributes{"visibility": "private", "default_branch_protected": false}, model.Pass},
			{model.Attributes{"visibility": "public"}, model.Unknown},
		},
		"SL-REPO-002": {
			{model.Attributes{"visibility": "public", "secret_scanning": false}, model.Fail},
			{model.Attributes{"visibility": "public", "secret_scanning": true}, model.Pass},
			{model.Attributes{"visibility": "public"}, model.Unknown},
		},
		"SL-HOOK-001": {
			{model.Attributes{"insecure_ssl": true}, model.Fail},
			{model.Attributes{"insecure_ssl": false}, model.Pass},
			{model.Attributes{}, model.Unknown},
		},
		"SL-HOOK-002": {
			{model.Attributes{"has_secret": false}, model.Fail},
			{model.Attributes{"has_secret": true}, model.Pass},
			{model.Attributes{}, model.Unknown},
		},
		"SL-HOOK-003": {
			{model.Attributes{"url_scheme": "http"}, model.Fail},
			{model.Attributes{"url_scheme": "https"}, model.Pass},
			{model.Attributes{}, model.Unknown},
		},
	}
	if len(cases) != len(rs) {
		t.Fatalf("every rule needs fixtures: have %d, rules %d", len(cases), len(rs))
	}
	for id, fixtures := range cases {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("rule %s not loaded", id)
		}
		for i, f := range fixtures {
			got, _ := Evaluate(r, model.Asset{Kind: r.AssetKind, Attributes: f.attrs})
			if got != f.want {
				t.Errorf("%s fixture %d (%v): got %s, want %s", id, i, f.attrs, got, f.want)
			}
		}
	}
}

func TestUnknownEvidenceCarriesReason(t *testing.T) {
	rs, _ := LoadBuiltin()
	var userRule model.Rule
	for _, r := range rs {
		if r.ID == "SL-USER-001" {
			userRule = r
		}
	}
	a := model.Asset{Kind: model.KindUser, Attributes: model.Attributes{"is_admin": true},
		Unknown: map[string]model.UnknownReason{"mfa_enabled": {
			Reason: model.ReasonPermissionDenied, Endpoint: "GET /orgs/{org}/members?filter=2fa_disabled"}}}
	res, ev := Evaluate(userRule, a)
	if res != model.Unknown || ev.Reason != model.ReasonPermissionDenied || ev.Endpoint == "" {
		t.Fatalf("got %s %+v", res, ev)
	}
	if ev.Values["is_admin"] != true || len(ev.UnknownFields) != 1 {
		t.Fatalf("evidence should keep known values and list unknown fields: %+v", ev)
	}
	// No recorded reason -> "missing".
	_, ev = Evaluate(userRule, model.Asset{Kind: model.KindUser, Attributes: model.Attributes{"is_admin": true}})
	if ev.Reason != model.ReasonMissing {
		t.Fatalf("got reason %q", ev.Reason)
	}
}

func TestCarriedForwardAssetIsAlwaysUnknown(t *testing.T) {
	rs, _ := LoadBuiltin()
	for _, r := range rs {
		res, ev := Evaluate(r, model.Asset{Kind: r.AssetKind, CarriedForward: true,
			// Even attributes that would fail are ignored: we did not see it this scan.
			Attributes: model.Attributes{"insecure_ssl": true}})
		if res != model.Unknown || ev.Reason != model.ReasonCollectionIncomplete {
			t.Fatalf("%s: got %s %q", r.ID, res, ev.Reason)
		}
	}
}

func TestValidatorRejectsBadRules(t *testing.T) {
	base := `- id: SL-TEST-001
  title: t
  severity: high
  providers: [github]
  asset_kind: user
  remediation: r
`
	cases := map[string]string{
		"unknown operator": base + "  fail_when:\n    - { field: is_admin, op: gt, value: true }\n",
		"unknown field":    base + "  fail_when:\n    - { field: is_root, op: eq, value: true }\n",
		"type mismatch":    base + "  fail_when:\n    - { field: is_admin, op: eq, value: \"yes\" }\n",
		"in needs list":    base + "  fail_when:\n    - { field: login, op: in, value: root }\n",
		"contains on bool": base + "  fail_when:\n    - { field: is_admin, op: contains, value: \"x\" }\n",
		"no conditions":    base + "  fail_when: []\n",
		"misspelled key":   base + "  fail_whn:\n    - { field: is_admin, op: eq, value: true }\n",
		"bad severity":     strings.Replace(base, "high", "urgent", 1) + "  fail_when:\n    - { field: is_admin, op: eq, value: true }\n",
		"bad kind":         strings.Replace(base, "asset_kind: user", "asset_kind: printer", 1) + "  fail_when:\n    - { field: is_admin, op: eq, value: true }\n",
		"bad provider":     strings.Replace(base, "[github]", "[myspace]", 1) + "  fail_when:\n    - { field: is_admin, op: eq, value: true }\n",
		"duplicate id":     base + "  fail_when:\n    - { field: is_admin, op: eq, value: true }\n" + base + "  fail_when:\n    - { field: is_admin, op: eq, value: true }\n",
	}
	for name, yml := range cases {
		t.Run(name, func(t *testing.T) {
			fsys := fstest.MapFS{"r.yaml": {Data: []byte(yml)}}
			if _, err := Load(fsys, "*.yaml"); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestEvaluateAllCoversEveryApplicablePair(t *testing.T) {
	rs, _ := LoadBuiltin()
	assets := []model.Asset{
		{ID: "a1", Kind: model.KindOrg, ExternalID: "1"},
		{ID: "a2", Kind: model.KindUser, ExternalID: "2"},
		{ID: "a3", Kind: model.KindRepo, ExternalID: "3"},
		{ID: "a4", Kind: model.KindWebhook, ExternalID: "4"},
	}
	got := EvaluateAll(rs, "github", "github:x", "scan1", assets)
	if len(got) != 3+1+2+3 {
		t.Fatalf("got %d results, want 9", len(got))
	}
	if len(EvaluateAll(rs, "slack", "slack:x", "scan1", assets)) != 0 {
		t.Fatal("rules must not apply to other providers")
	}
}
