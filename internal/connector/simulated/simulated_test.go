package simulated

import (
	"context"
	"net/http"
	"testing"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

func count(snap []model.Asset, kind model.AssetKind) int {
	n := 0
	for _, a := range snap {
		if a.Kind == kind {
			n++
		}
	}
	return n
}

func find(assets []model.Asset, kind model.AssetKind, name string) model.Asset {
	for _, a := range assets {
		if a.Kind == kind && a.Name == name {
			return a
		}
	}
	return model.Asset{}
}

func TestV1Snapshot(t *testing.T) {
	snap, err := New(0, 0).Collect(context.Background()) // index 0 = v1
	if err != nil {
		t.Fatal(err)
	}
	if count(snap.Assets, model.KindOrg) != 1 || count(snap.Assets, model.KindUser) != 20 ||
		count(snap.Assets, model.KindRepo) != 10 || count(snap.Assets, model.KindWebhook) != 3 {
		t.Fatalf("unexpected asset counts")
	}
	for _, k := range model.AllKinds {
		if snap.Collections[k].Status != model.CollectionComplete {
			t.Fatalf("%s collection = %+v", k, snap.Collections[k])
		}
	}
	bob := find(snap.Assets, model.KindUser, "bob-owner")
	if admin, _ := model.GetBool(bob.Attributes, "is_admin"); !admin {
		t.Fatal("bob-owner should be an admin")
	}
	if mfa, known := model.GetBool(bob.Attributes, "mfa_enabled"); !known || mfa {
		t.Fatal("bob-owner should be known to have no MFA in v1")
	}
	// Only scheme://host is kept from the webhook URL (path may hold secrets).
	if find(snap.Assets, model.KindWebhook, "https://chat.acme.example").ExternalID == "" {
		t.Fatal("webhook name should be scheme://host only")
	}
}

func TestV2SimulatesLostMFAPermission(t *testing.T) {
	c := New(1, 0) // index 1 = v2
	snap, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count(snap.Assets, model.KindRepo) != 11 {
		t.Fatal("v2 adds one repo")
	}
	bob := find(snap.Assets, model.KindUser, "bob-owner")
	if _, known := model.GetBool(bob.Attributes, "mfa_enabled"); known {
		t.Fatal("mfa_enabled must be unknown in v2")
	}
	if r := bob.Unknown["mfa_enabled"]; r.Reason != model.ReasonPermissionDenied {
		t.Fatalf("reason = %+v", r)
	}
	hook := find(snap.Assets, model.KindWebhook, "https://ci.acme.example")
	if insecure, _ := model.GetBool(hook.Attributes, "insecure_ssl"); insecure {
		t.Fatal("v2 fixes the insecure webhook")
	}
}

func TestCycleOrder(t *testing.T) {
	want := []string{"v1", "v2", "v2", "v1", "v1", "v2"}
	for i, w := range want {
		if got := Cycle[i%len(Cycle)]; got != w {
			t.Fatalf("scan %d: got %s want %s", i, got, w)
		}
	}
}

func TestTransportRejectsNonGET(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/orgs/"+Org, nil)
	if _, err := (&Transport{Version: "v1"}).RoundTrip(req); err == nil {
		t.Fatal("POST must be rejected")
	}
}
