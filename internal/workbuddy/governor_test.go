package workbuddy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func governorFixture(t *testing.T, limits Limits) (*Governor, *time.Time, string) {
	t.Helper()
	now := time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "risk.json")
	g, err := OpenGovernor(path, GovernorOptions{Now: func() time.Time { return now }, Location: time.FixedZone("CST", 8*3600), Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	return g, &now, path
}

func TestWorkBuddyBalanceReadRespectsControlCooldown(t *testing.T) {
	g, _, _ := governorFixture(t, Limits{ReserveCredits: 10})
	c := testCredential()
	if gate, _ := g.Check(c, "balance", false, true); !gate.Allowed() {
		t.Fatal("unknown balance prevented a balance read")
	}
	if _, err := g.RecordFailure(c, "balance", Fault{Kind: FaultModelRate, Soft: true}, FailureOptions{}); err != nil {
		t.Fatal(err)
	}
	if gate, _ := g.Check(c, "balance", false, true); gate.Reason != "model_cooldown" {
		t.Fatal("balance read bypassed endpoint cooldown")
	}
}

func TestGovernorRestrictionWaveAndStaleSuccessSurviveRestart(t *testing.T) {
	g, now, path := governorFixture(t, Limits{})
	first := testCredential()
	second := first
	second.UID = "second-user"
	_, oldAttempt := g.Check(first, "model", false, false)
	fault := Fault{Kind: FaultRestricted, Status: 403, Code: 11140}
	result, err := g.RecordFailure(first, "model", fault, FailureOptions{})
	if err != nil || !result.Stop || result.Until.Sub(*now) != 2*time.Hour {
		t.Fatalf("restriction result=%+v err=%v", result, err)
	}
	if err := g.Complete(first, oldAttempt, 10, nil, true); err != nil {
		t.Fatal(err)
	}
	if gate, _ := g.Check(first, "model", false, false); gate.Reason != "account_restricted" {
		t.Fatal("stale success cleared restriction")
	}
	// The same UID in another product cannot create a second regional event.
	first.Product = VSCode
	if _, err := g.RecordFailure(first, "model", fault, FailureOptions{}); err != nil {
		t.Fatal(err)
	}
	if gate, _ := g.Check(second, "model", false, false); !gate.Allowed() {
		t.Fatal("same account was counted twice")
	}
	if _, err := g.RecordFailure(second, "model", fault, FailureOptions{}); err != nil {
		t.Fatal(err)
	}
	third := first
	third.UID = "third-user"
	if gate, _ := g.Check(third, "model", false, true); gate.Reason != "region_restricted" || !gate.Stop {
		t.Fatal("background balance request bypassed region hold")
	}
	restarted, errOpen := OpenGovernor(path, g.options)
	if errOpen != nil {
		t.Fatal(errOpen)
	}
	third.AccessToken = "fresh-token"
	if gate, _ := restarted.Check(third, "model", false, false); gate.Reason != "region_restricted" {
		t.Fatal("restart cleared region hold")
	}
	*now = now.Add(31 * time.Minute)
	if gate, _ := restarted.Check(third, "model", false, false); !gate.Allowed() {
		t.Fatal("regional hold did not expire")
	}
	if gate, _ := restarted.Check(first, "model", false, false); gate.Reason != "account_restricted" {
		t.Fatal("identity switch cleared account restriction")
	}
	*now = now.Add(90 * time.Minute)
	if gate, _ := restarted.Check(first, "model", false, false); !gate.Allowed() {
		t.Fatal("account restriction did not expire")
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	if strings.Contains(string(raw), "fixture-user") || strings.Contains(string(raw), "old-refresh") {
		t.Fatal("risk state contains raw identity or credentials")
	}
}

func TestGovernor429ScopesCountersDecayAndPersistentCaps(t *testing.T) {
	g, now, path := governorFixture(t, Limits{})
	c := testCredential()
	for index := 0; index < 3; index++ {
		gate, err := g.RecordFailure(c, "limited", Fault{Kind: FaultModelRate, Soft: true}, FailureOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if want := time.Minute * time.Duration(1<<index); gate.Until.Sub(*now) != want {
			t.Fatalf("model cooldown=%s want %s", gate.Until.Sub(*now), want)
		}
	}
	if gate, _ := g.Check(c, "sibling", false, false); !gate.Allowed() {
		t.Fatal("model 429 parked sibling models")
	}
	account, errAccount := g.RecordFailure(c, "limited", Fault{Kind: FaultAccountRate}, FailureOptions{})
	if errAccount != nil || account.Until.Sub(*now) != 10*time.Minute {
		t.Fatalf("account streak contaminated by model errors: %+v %v", account, errAccount)
	}
	*now = now.Add(11 * time.Minute)
	model, errModel := g.RecordFailure(c, "limited", Fault{Kind: FaultModelRate, Soft: true}, FailureOptions{})
	if errModel != nil || model.Until.Sub(*now) != time.Minute {
		t.Fatal("soft streak failed to decay")
	}
	until := now.Add(2 * time.Hour)
	for _, entry := range []struct {
		model string
		free  bool
		kind  FaultKind
	}{
		{"free", true, FaultModelCap}, {"paid", false, FaultModelCap}, {"clock_only", true, FaultModelRate},
	} {
		if _, err := g.RecordFailure(c, entry.model, Fault{Kind: entry.kind, ResetAt: until}, FailureOptions{FreeModel: entry.free}); err != nil {
			t.Fatal(err)
		}
	}
	restarted, errOpen := OpenGovernor(path, g.options)
	if errOpen != nil {
		t.Fatal(errOpen)
	}
	c.Product = CLI
	c.AccessToken = "rotated-fixture"
	if gate, _ := restarted.Check(c, "free", false, false); gate.Allowed() {
		t.Fatal("token refresh or product switch cleared free cap")
	}
	for _, model := range []string{"paid", "clock_only", "limited"} {
		if gate, _ := restarted.Check(c, model, true, false); !gate.Allowed() {
			t.Fatalf("runtime-only window persisted for %s", model)
		}
	}
}

func TestGovernorBreakersSharedUnknownCounterAndLocalErrors(t *testing.T) {
	g, now, _ := governorFixture(t, Limits{})
	c := testCredential()
	for _, kind := range []FaultKind{FaultLocalNetwork, FaultTLS, FaultContent, FaultModelRetired, FaultEntitlement} {
		if _, err := g.RecordFailure(c, "model", Fault{Kind: kind}, FailureOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if gate, _ := g.Check(c, "model", false, false); !gate.Allowed() {
		t.Fatal("request/model/local error penalized account")
	}
	for index := 1; index <= 5; index++ {
		result, err := g.RecordFailure(c, "model", Fault{Kind: FaultConnection}, FailureOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if index < 3 && !result.Until.IsZero() {
			t.Fatal("breaker opened before threshold")
		}
		if index == 3 && result.Until.Sub(*now) != 30*time.Minute {
			t.Fatal("unknown failures did not feed shared breaker")
		}
	}
	state := g.state.Accounts[RiskAccountKey(c)]
	if state.UnknownFailures != 5 || state.DegradeUntil.Sub(*now) != 10*time.Minute || state.BreakerUntil.Sub(*now) != 2*time.Hour {
		t.Fatal("unknown and shared failure ladders disagree")
	}
	*now = now.Add(3 * time.Hour)
	if _, err := g.RecordFailure(c, "model", Fault{Kind: FaultHard}, FailureOptions{}); err != nil {
		t.Fatal(err)
	}
	if state.Failures != 1 || state.UnknownFailures != 0 {
		t.Fatal("hard streak did not decay")
	}
}

func TestGovernorBalanceBudgetsAndDayRollover(t *testing.T) {
	g, now, _ := governorFixture(t, Limits{ReserveCredits: 2, DailyTokens: 100, DailyCredits: 5, ModelTokens: map[string]int64{"model": 50}})
	c := testCredential()
	if gate, _ := g.Check(c, "model", false, false); gate.Reason != "balance_unknown" {
		t.Fatal("reserve ignored unknown balance")
	}
	balanceGate, balanceAttempt := g.Check(c, "", false, true)
	if !balanceGate.Allowed() {
		t.Fatal("balance observation cannot fill unknown balance")
	}
	if err := g.ObserveBalance(c, balanceAttempt, 10); err != nil {
		t.Fatal(err)
	}
	_, attempt := g.Check(c, "model", false, false)
	credits := 5.0
	if err := g.Complete(c, attempt, 50, &credits, true); err != nil {
		t.Fatal(err)
	}
	if gate, _ := g.Check(c, "model", false, false); gate.Reason != "model_daily_tokens" {
		t.Fatal("model budget not enforced")
	}
	if gate, _ := g.Check(c, "sibling", false, false); !gate.Allowed() {
		t.Fatal("paid credit budget blocked free sibling")
	}
	if gate, _ := g.Check(c, "sibling", true, false); gate.Reason != "daily_credits" {
		t.Fatal("credit budget not enforced for paid model")
	}
	_, oldBalance := g.Check(c, "", false, true)
	if _, err := g.RecordFailure(c, "model", Fault{Kind: FaultBalance}, FailureOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := g.ObserveBalance(c, oldBalance, 100); err != nil {
		t.Fatal(err)
	}
	if gate, _ := g.Check(c, "sibling", false, false); gate.Reason != "balance_empty" {
		t.Fatal("stale balance cleared newer 402")
	}
	_, freshBalance := g.Check(c, "", false, true)
	if err := g.ObserveBalance(c, freshBalance, 10); err != nil {
		t.Fatal(err)
	}
	if gate, _ := g.Check(c, "sibling", false, false); !gate.Allowed() {
		t.Fatal("positive balance did not revive 402")
	}
	*now = time.Date(2026, 10, 21, 16, 0, 0, 0, time.UTC)
	if gate, _ := g.Check(c, "model", true, false); !gate.Allowed() {
		t.Fatal("local midnight did not reset budgets")
	}
}

func TestGovernorInvalidStateAndPersistenceFailureStopDispatch(t *testing.T) {
	g, _, path := governorFixture(t, Limits{})
	c := testCredential()
	g.path = filepath.Join(path, "not-a-directory", "risk.json")
	if _, err := g.RecordFailure(c, "model", Fault{Kind: FaultRestricted}, FailureOptions{}); err == nil {
		t.Fatal("persistence failure was hidden")
	}
	if gate, _ := g.Check(c, "model", false, true); gate.Reason != "state_persistence_failed" || !gate.Stop {
		t.Fatal("dispatch continued after persistence failure")
	}
	g.path = path
	if err := g.Flush(); err != nil {
		t.Fatal(err)
	}
	if gate, _ := g.Check(c, "model", false, false); gate.Reason != "account_restricted" {
		t.Fatal("flush recovery cleared restriction")
	}
	if err := os.WriteFile(path, []byte(`{"version":9,"accounts":{},"realms":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenGovernor(path, g.options); err == nil {
		t.Fatal("unknown risk schema accepted")
	}
}

func TestGovernorEntitlementEvidenceIsScopedAndExpires(t *testing.T) {
	g, now, path := governorFixture(t, Limits{})
	free := testCredential()
	paid := free
	paid.UID = "paid-fixture-user"
	paid.EnterpriseID = "fixture-enterprise"
	_, older := g.Check(paid, "model", true, false)
	*now = now.Add(time.Second)
	fault := ClassifyHTTP(500, []byte(`{"code":11158,"message":"model is not allowed for user type [personal_free_user]"}`))
	if gate, err := g.RecordFailure(free, "model", fault, FailureOptions{}); err != nil || !gate.Stop {
		t.Fatalf("record: %+v %v", gate, err)
	}
	restarted, err := OpenGovernor(path, g.options)
	if err != nil {
		t.Fatal(err)
	}
	mark, ok := restarted.Entitlement(International, "model")
	if !ok || mark.UserType != "personal_free_user" {
		t.Fatalf("mark = %+v %v", mark, ok)
	}
	if gate, _ := restarted.Check(paid, "model", true, false); !gate.Allowed() {
		t.Fatal("free refusal blocked paid account")
	}
	if gate, _ := restarted.Check(free, "sibling", true, false); !gate.Allowed() {
		t.Fatal("model refusal penalized sibling model")
	}
	if err := restarted.Complete(paid, older, 0, nil, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := restarted.Entitlement(International, "model"); !ok {
		t.Fatal("stale completion erased newer refusal evidence")
	}
	_, fresh := restarted.Check(paid, "model", true, false)
	if err := restarted.Complete(paid, fresh, 0, nil, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := restarted.Entitlement(International, "model"); ok {
		t.Fatal("successful recheck did not clear mark")
	}
	if _, err := restarted.RecordFailure(free, "model", fault, FailureOptions{}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(24 * time.Hour)
	if _, ok := restarted.Entitlement(International, "model"); ok {
		t.Fatal("entitlement mark did not expire")
	}
}
func TestGovernorModelConfigurationFailuresDoNotPoisonAccount(t *testing.T) {
	g, _, _ := governorFixture(t, Limits{})
	c := testCredential()
	for _, code := range []string{"11129", "11150"} {
		fault := ClassifyHTTP(550, []byte(`{"code":`+code+`}`))
		if fault.Kind != FaultModelParameter || !ErrorForFault(fault).Stop {
			t.Fatalf("code %s classified %+v", code, fault)
		}
		for i := 0; i < 8; i++ {
			if _, err := g.RecordFailure(c, "model", fault, FailureOptions{}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if gate, _ := g.Check(c, "sibling", true, false); !gate.Allowed() {
		t.Fatalf("configuration failure poisoned account: %+v", gate)
	}
}

func TestWorkBuddyObservedCreditChargesProtectReserveBetweenBalanceReads(t *testing.T) {
	g, _, _ := governorFixture(t, Limits{ReserveCredits: 5})
	c := testCredential()
	_, balance := g.Check(c, "balance", false, true)
	if err := g.ObserveBalance(c, balance, 20); err != nil {
		t.Fatal(err)
	}
	_, attempt := g.Check(c, "paid", true, false)
	_, staleBalance := g.Check(c, "balance", false, true)
	credit := 16.0
	if err := g.Complete(c, attempt, 1, &credit, false); err != nil {
		t.Fatal(err)
	}
	if err := g.ObserveBalance(c, staleBalance, 20); err != nil {
		t.Fatal(err)
	}
	if gate, _ := g.Check(c, "paid", true, false); gate.Reason != "credit_reserve" {
		t.Fatal("observed spend did not protect reserve")
	}
	_, fresh := g.Check(c, "balance", false, true)
	if err := g.ObserveBalance(c, fresh, 30); err != nil {
		t.Fatal(err)
	}
	if gate, _ := g.Check(c, "paid", true, false); !gate.Allowed() {
		t.Fatal("fresh balance did not replace local debits")
	}
}
