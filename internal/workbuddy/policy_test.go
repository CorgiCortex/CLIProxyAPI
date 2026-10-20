package workbuddy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWorkBuddyPromptDegradeEndsAtCSTMidnight(t *testing.T) {
	now := time.Date(2026, 10, 21, 15, 59, 0, 0, time.UTC)
	p := NewPolicyState(func() time.Time { return now })
	p.Degrade()
	if !p.Degraded() {
		t.Fatal("missing degradation")
	}
	now = now.Add(30 * time.Second)
	p.Degrade()
	now = now.Add(30 * time.Second)
	if p.Degraded() {
		t.Fatal("repeated rejection extended midnight window")
	}
}
func TestWorkBuddyExitBackoffScopeDecayAndRequestWaitBudget(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	p := NewPolicyState(func() time.Time { return now })
	p.jitter = func() float64 { return 1 }
	var waits []time.Duration
	p.sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	ctx, _ := WithRequestState(context.Background(), 2)
	s := State(ctx)
	for i := 0; i < 8; i++ {
		if err := p.Backoff(ctx, s, "https://upstream.test/path", "http://user:secret@proxy.test"); err != nil {
			t.Fatal(err)
		}
	}
	var total time.Duration
	for _, d := range waits {
		total += d
	}
	if total != 5*time.Second {
		t.Fatalf("logical request wait = %v", total)
	}
	key := ExitKey("https://upstream.test/another", "http://user:secret@proxy.test")
	if p.exits[key].count != 1 {
		t.Fatal("same request charged exit repeatedly")
	}
	second, _ := WithRequestState(context.Background(), 2)
	if err := p.Backoff(second, State(second), "https://upstream.test", "http://user:secret@proxy.test"); err != nil {
		t.Fatal(err)
	}
	if waits[len(waits)-1] != 2*time.Second {
		t.Fatal("new request did not advance exit streak")
	}
	if key == ExitKey("https://different.test", "http://user:secret@proxy.test") {
		t.Fatal("different origins shared failure scope")
	}
	now = now.Add(61 * time.Second)
	third, _ := WithRequestState(context.Background(), 2)
	_ = p.Backoff(third, State(third), "https://upstream.test", "http://user:secret@proxy.test")
	if waits[len(waits)-1] != time.Second {
		t.Fatal("exit streak did not decay")
	}
	p.ExitSuccess("https://upstream.test", "http://user:secret@proxy.test")
	if _, ok := p.exits[key]; ok {
		t.Fatal("success did not clear exit streak")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitBeforeConnect(canceled, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel = %v", err)
	}
}
func TestWorkBuddyProductSwitchBudgetAndCNDeviceGate(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	p := NewPolicyState(func() time.Time { return now })
	c := testCredential()
	expected := []Product{VSCode, CLI, Desktop, VSCode}
	for _, want := range expected {
		got, ok := p.NextProduct(c, "model", nil)
		if !ok || got != want {
			t.Fatalf("next=%s/%v want %s", got, ok, want)
		}
		c.Product = got
	}
	if _, ok := p.NextProduct(c, "model", nil); ok {
		t.Fatal("fifth switch allowed")
	}
	now = now.Add(61 * time.Second)
	if _, ok := p.NextProduct(c, "model", nil); !ok {
		t.Fatal("switch window did not expire")
	}
	c.Realm = China
	c.Product = Desktop
	c.DeviceToken = ""
	c.EnterpriseID = ""
	if got, ok := p.NextProduct(c, "model", nil); !ok || got != CLI {
		t.Fatal("CN personal VSCode identity fabricated device token")
	}
	if _, ok := p.NextProduct(c, "only-current", []Product{Desktop}); ok {
		t.Fatal("single allowed identity switched")
	}
}
func TestWorkBuddyIdentityChangeCannotClearCapOrRestriction(t *testing.T) {
	g, now, _ := governorFixture(t, Limits{})
	c := testCredential()
	if _, err := g.RecordFailure(c, "free", Fault{Kind: FaultModelCap, ResetAt: now.Add(time.Hour)}, FailureOptions{FreeModel: true}); err != nil {
		t.Fatal(err)
	}
	if g.ClearIdentityModelCooldown(c, "free") {
		t.Fatal("identity change cleared durable cap")
	}
	if _, err := g.RecordFailure(c, "ordinary", Fault{Kind: FaultModelRate}, FailureOptions{}); err != nil {
		t.Fatal(err)
	}
	if !g.ClearIdentityModelCooldown(c, "ordinary") {
		t.Fatal("ordinary model cooldown not cleared")
	}
	if _, err := g.RecordFailure(c, "ordinary", Fault{Kind: FaultRestricted}, FailureOptions{}); err != nil {
		t.Fatal(err)
	}
	if g.ClearIdentityModelCooldown(c, "ordinary") {
		t.Fatal("identity change cleared restriction")
	}
}
