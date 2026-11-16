package scan

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/connector"
	"github.com/Rahul03082001/plumbline-sspm/internal/connector/simulated"
	"github.com/Rahul03082001/plumbline-sspm/internal/model"
	"github.com/Rahul03082001/plumbline-sspm/internal/store"
)

func names(items []DriftItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.RuleID+" "+it.AssetName)
	}
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSimulatedDemoStory is the Phase 3 "done when": the v1 -> v2 -> v2 -> v1
// cycle through the REAL GitHub connector code (simulated at the HTTP level).
func TestSimulatedDemoStory(t *testing.T) {
	ctx := context.Background()
	svc, _ := newHarness(t, builtinRules(t), simulated.New(0, 0))
	// Re-register under the simulated connection ID (fingerprints use it).
	sim := model.Connection{ID: simulated.ConnectionID, Provider: "github", DisplayName: "Acme", Mode: model.ModeSimulated}
	if err := svc.Register(ctx, sim, simulated.New(0, 0)); err != nil {
		t.Fatal(err)
	}

	s1 := runScan(t, svc, sim.ID)
	if s1.Status != model.ScanSucceeded || s1.ChecksTotal != 52 || s1.ChecksAssessed != 52 {
		t.Fatalf("scan 1: %+v", s1)
	}
	if s1.Score != 28 {
		t.Errorf("scan 1 score = %d, want 28", s1.Score)
	}

	// Scan 2 (v2): webhook fixed, new unprotected repo, MFA filter now 403.
	s2 := runScan(t, svc, sim.ID)
	d2, _ := svc.Drift(ctx, s2.ID)
	if got := names(d2.Resolved); !equal(got, []string{"SL-HOOK-001 https://ci.acme.example"}) {
		t.Errorf("scan 2 resolved = %v", got)
	}
	if got := names(d2.New); !equal(got, []string{"SL-REPO-001 payments-v2"}) {
		t.Errorf("scan 2 new = %v", got)
	}
	if got := names(d2.Unverifiable); !equal(got, []string{"SL-USER-001 bob-owner"}) {
		t.Errorf("scan 2 unverifiable = %v", got)
	}
	if s2.Comparable {
		t.Error("scan 2 must be NOT comparable (a failing check became unknown)")
	}
	if s2.Score <= s1.Score {
		t.Errorf("the score rose (%d -> %d) only because of lost visibility; that's the point", s1.Score, s2.Score)
	}
	if s2.CoveragePct() != 63 || !s2.ScoreVisible() {
		t.Errorf("scan 2 coverage = %d%% (visible %v), want 63%%", s2.CoveragePct(), s2.ScoreVisible())
	}

	// Scan 3 (v2 again): still unverifiable, nothing else changes.
	s3 := runScan(t, svc, sim.ID)
	d3, _ := svc.Drift(ctx, s3.ID)
	if got := names(d3.Unverifiable); !equal(got, []string{"SL-USER-001 bob-owner"}) {
		t.Errorf("scan 3 unverifiable = %v", got)
	}
	if len(d3.New)+len(d3.Resolved)+len(d3.ResolvedAssetRemoved) != 0 {
		t.Errorf("scan 3 should have no other drift: %+v", d3)
	}
	if !s3.Comparable {
		t.Error("scan 3 has the same visibility as scan 2, so it is comparable")
	}

	// Scan 4 (v1): MFA visible again -> persisting (NOT new), webhook regressed,
	// payments-v2 gone after a complete listing -> resolved (asset removed).
	s4 := runScan(t, svc, sim.ID)
	d4, _ := svc.Drift(ctx, s4.ID)
	if len(d4.Unverifiable) != 0 {
		t.Errorf("scan 4 unverifiable = %v", names(d4.Unverifiable))
	}
	if got := names(d4.New); !equal(got, []string{"SL-HOOK-001 https://ci.acme.example"}) || !d4.New[0].Regressed {
		t.Errorf("scan 4 new = %v (must be regressed)", got)
	}
	if got := names(d4.ResolvedAssetRemoved); !equal(got, []string{"SL-REPO-001 payments-v2"}) {
		t.Errorf("scan 4 resolved_asset_removed = %v", got)
	}
	findings, _ := svc.Findings(ctx, s4.ID, model.SeverityCritical)
	for _, f := range findings {
		if f.RuleID == "SL-USER-001" && f.FirstFailedScanID != s1.ID {
			t.Errorf("admin MFA finding first seen = %s, want scan 1 %s", f.FirstFailedScanID, s1.ID)
		}
	}
	if d4.PersistingCount == 0 {
		t.Error("admin MFA must count as persisting")
	}
}

func TestSecondRequestWhileActiveIs409(t *testing.T) {
	svc, _ := newHarness(t, builtinRules(t), &scripted{steps: []connector.Snapshot{step("fail")}})
	first, err := svc.RequestScan(context.Background(), testConn)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.RequestScan(context.Background(), testConn)
	var active *store.ActiveScanError
	if !errors.As(err, &active) || active.ScanID != first.ID {
		t.Fatalf("want ActiveScanError(%s), got %v", first.ID, err)
	}
}

func TestPublishErrorRollsBackAndKeepsPreviousScan(t *testing.T) {
	ctx := context.Background()
	svc, st := newHarness(t, builtinRules(t, "SL-REPO-001"),
		&scripted{steps: []connector.Snapshot{step("fail"), step("pass")}})
	good := runScan(t, svc, testConn)

	svc.beforeCommit = func() error { return errors.New("disk full") }
	bad := runScan(t, svc, testConn)
	if bad.Status != model.ScanFailed || bad.Error != FailPublish {
		t.Fatalf("got %s/%q", bad.Status, bad.Error)
	}
	cur, _ := st.LatestSucceeded(ctx, testConn)
	if cur.ID != good.ID {
		t.Fatal("the previous succeeded scan must stay current")
	}
	if rs, _ := st.Results(ctx, bad.ID, store.ResultFilter{}); len(rs) != 0 {
		t.Fatal("a failed publish must leave no results behind")
	}
	if cols, _ := st.Collections(ctx, bad.ID); len(cols) != 0 {
		t.Fatal("a failed publish must leave no collections behind")
	}
}

func TestWorkerPanicIsRecovered(t *testing.T) {
	conn := &scripted{steps: []connector.Snapshot{step("fail")}, panicAt: 1}
	svc, _ := newHarness(t, builtinRules(t), conn)
	sc := runScan(t, svc, testConn) // must not crash the test binary
	if sc.Status != model.ScanFailed || sc.Error != FailPanic {
		t.Fatalf("got %s/%q", sc.Status, sc.Error)
	}
	// The next scan works normally.
	if next := runScan(t, svc, testConn); next.Status != model.ScanSucceeded {
		t.Fatalf("next scan: %s", next.Status)
	}
}

func TestRateLimitedScanPublishesNothing(t *testing.T) {
	ctx := context.Background()
	retryAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	conn := &scripted{steps: []connector.Snapshot{step("fail")},
		errs: map[int]error{2: &connector.RateLimitError{RetryAt: retryAt}, 3: connector.ErrUnauthorized}}
	svc, st := newHarness(t, builtinRules(t), conn)
	good := runScan(t, svc, testConn)

	rl := runScan(t, svc, testConn)
	if rl.Status != model.ScanFailed || rl.Error != FailRateLimited || rl.RetryAfter == nil || !rl.RetryAfter.Equal(retryAt) {
		t.Fatalf("got %+v", rl)
	}
	unauth := runScan(t, svc, testConn)
	if unauth.Error != FailUnauthorized {
		t.Fatalf("got %q", unauth.Error)
	}
	if cur, _ := st.LatestSucceeded(ctx, testConn); cur.ID != good.ID {
		t.Fatal("previous scan must stay current")
	}
}

func TestShutdownInterruptsQueuedScans(t *testing.T) {
	ctx := context.Background()
	svc, st := newHarness(t, builtinRules(t), &scripted{steps: []connector.Snapshot{step("fail")}})
	sc, err := svc.RequestScan(ctx, testConn) // queued, no workers running
	if err != nil {
		t.Fatal(err)
	}
	sctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	svc.Shutdown(sctx)
	got, _ := st.GetScan(ctx, sc.ID)
	if got.Status != model.ScanFailed || got.Error != FailInterrupted {
		t.Fatalf("got %s/%q", got.Status, got.Error)
	}
	if _, err := svc.RequestScan(ctx, testConn); !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("after shutdown: %v", err)
	}
}

// TestWorkersUnderRace runs real worker goroutines on two connections at
// once; `go test -race` checks the queue and workers for data races.
func TestWorkersUnderRace(t *testing.T) {
	ctx := context.Background()
	svc, st := newHarness(t, builtinRules(t), &scripted{steps: []connector.Snapshot{step("fail"), step("pass")}})
	sim := model.Connection{ID: simulated.ConnectionID, Provider: "github", DisplayName: "Acme", Mode: model.ModeSimulated}
	if err := svc.Register(ctx, sim, simulated.New(0, 0)); err != nil {
		t.Fatal(err)
	}
	svc.Start()
	for i := 0; i < 3; i++ {
		for _, id := range []string{testConn, sim.ID} {
			if _, err := svc.RequestScan(ctx, id); err != nil {
				t.Fatal(err)
			}
		}
		// Wait for both to finish before the next round (one active per connection).
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			a, _ := st.ActiveScan(ctx, testConn)
			b, _ := st.ActiveScan(ctx, sim.ID)
			if a.ID == "" && b.ID == "" {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	svc.Shutdown(sctx)
	for _, id := range []string{testConn, sim.ID} {
		if n, _ := st.CountSucceeded(ctx, id); n != 3 {
			t.Fatalf("%s: %d succeeded scans, want 3", id, n)
		}
	}
}
