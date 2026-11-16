package model

import (
	"regexp"
	"testing"
)

func TestGetBoolUnknownCases(t *testing.T) {
	attrs := Attributes{"yes": true, "no": false, "null": nil, "str": "true", "num": 1.0}
	cases := []struct {
		key       string
		wantVal   bool
		wantKnown bool
	}{
		{"yes", true, true},
		{"no", false, true},
		{"missing", false, false}, // missing key -> unknown
		{"null", false, false},    // JSON null -> unknown
		{"str", false, false},     // wrong type -> unknown (never coerced)
		{"num", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			v, known := GetBool(attrs, tc.key)
			if v != tc.wantVal || known != tc.wantKnown {
				t.Fatalf("GetBool(%q) = (%v,%v), want (%v,%v)", tc.key, v, known, tc.wantVal, tc.wantKnown)
			}
		})
	}
}

func TestGetStringUnknownCases(t *testing.T) {
	attrs := Attributes{"s": "public", "null": nil, "b": true}
	if v, ok := GetString(attrs, "s"); !ok || v != "public" {
		t.Fatalf("got (%q,%v)", v, ok)
	}
	for _, k := range []string{"missing", "null", "b"} {
		if _, ok := GetString(attrs, k); ok {
			t.Fatalf("%q should be unknown", k)
		}
	}
}

func TestAttributesRoundTrip(t *testing.T) {
	in := Attributes{"is_admin": true, "login": "octo"}
	unk := map[string]UnknownReason{"mfa_enabled": {Reason: ReasonPermissionDenied, Endpoint: "GET /orgs/{org}/members?filter=2fa_disabled"}}
	s, err := EncodeAttributes(in, unk)
	if err != nil {
		t.Fatal(err)
	}
	out, gotUnk, err := DecodeAttributes(s)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := GetBool(out, "is_admin"); !v {
		t.Fatal("is_admin lost")
	}
	if _, known := GetBool(out, "mfa_enabled"); known {
		t.Fatal("mfa_enabled must stay unknown")
	}
	if _, present := out["_unknown"]; present {
		t.Fatal("reserved key leaked into attributes")
	}
	if gotUnk["mfa_enabled"].Reason != ReasonPermissionDenied {
		t.Fatalf("reason lost: %+v", gotUnk)
	}
}

func TestFingerprintStableAndDistinct(t *testing.T) {
	a := Fingerprint("github:acme", "SL-USER-001", KindUser, "42")
	if a != Fingerprint("github:acme", "SL-USER-001", KindUser, "42") {
		t.Fatal("fingerprint must be stable")
	}
	others := []string{
		Fingerprint("github:other", "SL-USER-001", KindUser, "42"), // other connection
		Fingerprint("github:acme", "SL-USER-001", KindRepo, "42"),  // same id, other kind
		Fingerprint("github:acme", "SL-ORG-001", KindUser, "42"),   // other rule
	}
	for _, o := range others {
		if o == a {
			t.Fatal("fingerprints must differ")
		}
	}
}

func TestNewIDIsUUIDv4(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if id := NewID(); !re.MatchString(id) {
		t.Fatalf("not a v4 UUID: %s", id)
	}
	if a, b := NewID(), NewID(); a == b {
		t.Fatal("ids must be random")
	}
}

func TestCoverageAndScoreVisibility(t *testing.T) {
	s := Scan{Status: ScanSucceeded, ChecksTotal: 14, ChecksAssessed: 11}
	if s.CoveragePct() != 79 || !s.ScoreVisible() {
		t.Fatalf("got %d%% visible=%v", s.CoveragePct(), s.ScoreVisible())
	}
	low := Scan{Status: ScanSucceeded, ChecksTotal: 10, ChecksAssessed: 5}
	if low.ScoreVisible() {
		t.Fatal("50% coverage must hide the score")
	}
	if (Scan{Status: ScanSucceeded}).Coverage() != 0 {
		t.Fatal("zero checks = zero coverage")
	}
}
