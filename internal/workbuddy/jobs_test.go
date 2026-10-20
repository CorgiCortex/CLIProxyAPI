package workbuddy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorkBuddyJobIntentPersistsBeforeActionAndSurvivesRestart(t *testing.T) {
	now := time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "jobs.json")
	ledger, err := OpenJobLedger(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	c := testCredential()
	calls := 0
	run := func(context.Context) (JobReceipt, error) {
		calls++
		raw, errRead := os.ReadFile(path)
		if errRead != nil || !strings.Contains(string(raw), `"pending"`) {
			t.Fatal("action ran without durable intent")
		}
		if strings.Contains(string(raw), c.UID) || strings.Contains(string(raw), c.AccessToken) {
			t.Fatal("receipt leaked credential")
		}
		return JobReceipt{AlreadyDone: true}, nil
	}
	receipt, ran, err := ledger.Run(context.Background(), c, "checkin", "2026-10-21", run)
	if err != nil || !ran || receipt.Status != "success" {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	restarted, err := OpenJobLedger(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, ran, err = restarted.Run(context.Background(), c, "checkin", "2026-10-21", run); err != nil || ran || calls != 1 {
		t.Fatal("restart repeated completed work")
	}
}
func TestWorkBuddyJobCooldownAndRetryBudget(t *testing.T) {
	now := time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC)
	ledger, err := OpenJobLedger(filepath.Join(t.TempDir(), "jobs.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	c := testCredential()
	calls := 0
	run := func(context.Context) (JobReceipt, error) {
		calls++
		return JobReceipt{}, &DispatchError{Reason: "region_restricted", Until: now.Add(time.Hour)}
	}
	for i := 0; i < 6; i++ {
		receipt, ran, errRun := ledger.Run(context.Background(), c, "balance", "slot", run)
		if errRun == nil || !ran || receipt.Status != "failed" || receipt.Reason != "region_restricted" {
			t.Fatal("failed job reported success")
		}
		if _, ran, _ = ledger.Run(context.Background(), c, "balance", "slot", run); ran {
			t.Fatal("job ignored cooldown")
		}
		now = now.Add(time.Hour)
	}
	if _, ran, _ := ledger.Run(context.Background(), c, "balance", "slot", run); ran || calls != 6 {
		t.Fatal("retry budget exceeded")
	}
}
func TestWorkBuddyJobCannotRunWhenIntentPersistenceFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts")
	ledger, err := OpenJobLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	ranAction := false
	_, _, err = ledger.Run(context.Background(), testCredential(), "checkin", "day", func(context.Context) (JobReceipt, error) { ranAction = true; return JobReceipt{}, nil })
	if err == nil || ranAction {
		t.Fatal("failed persistence allowed action")
	}
}
func TestWorkBuddyJobSlotAndUnknownReward(t *testing.T) {
	before := time.Date(2026, 10, 21, 0, 59, 0, 0, time.UTC)
	if _, due := JobSlot(before, "checkin"); due {
		t.Fatal("checkin before 9 CST")
	}
	morning, _ := JobSlot(before.Add(time.Minute), "growth")
	night, _ := JobSlot(before.Add(13*time.Hour), "growth")
	if morning == night {
		t.Fatal("evening growth reconciliation missing")
	}
	receipt, err := RewardReceipt(ControlResult{Data: json.RawMessage(`{}`)})
	if err != nil || receipt.Credit != nil || receipt.Energy != nil {
		t.Fatal("missing reward replaced with zero")
	}
}
func TestWorkBuddyGrowthClaimsOnlyObservedCompletion(t *testing.T) {
	var paths []string
	a, c, now := controlFixture(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/v2/activity/growth/tasks":
			fmt.Fprint(w, `{"code":0,"data":{"tasks":[{"task_code":"chat_5","accept_status":"completed","task_type":"single"},{"task_code":"needs_real_action","accept_status":"accepted","task_type":"single","progress":{"current":0,"target":1}},{"task_code":"missing_progress","accept_status":"accepted","task_type":"single"}]}}`)
		case "/activity/growth/tasks/chat_5/claim":
			fmt.Fprint(w, `{"code":0,"data":{"credit":100}}`)
		default:
			t.Error("unexpected operation", r.URL.Path)
			w.WriteHeader(500)
		}
	})
	path := filepath.Join(t.TempDir(), "jobs.json")
	ledger, err := OpenJobLedger(path, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	pending, err := a.ReconcileGrowth(context.Background(), ledger)
	if err != nil || pending != 2 || len(paths) != 2 {
		t.Fatalf("pending=%d paths=%v err=%v", pending, paths, err)
	}
	// The same stale vendor list must not cause a second payout request.
	pending, err = a.ReconcileGrowth(context.Background(), ledger)
	if err != nil || pending != 2 || len(paths) != 3 {
		t.Fatal("reconciliation replayed an already recorded claim")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted jobState
	if err = json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	rewardObserved := false
	for _, receipt := range persisted.Receipts {
		if receipt.Job == "growth_claim:chat_5" && receipt.Credit != nil && *receipt.Credit == 100 {
			rewardObserved = true
		}
	}
	if !rewardObserved || strings.Contains(string(raw), c.AccessToken) {
		t.Fatal("invalid reward receipt")
	}
}
func TestWorkBuddyGrowthAcceptanceRequiresPerTaskAck(t *testing.T) {
	a, _, _ := controlFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":0,"data":{"results":[{"task_code":"one","status":"accepted"}]}}`)
	})
	if err := a.AcceptGrowthTasks(context.Background(), []string{"one", "two"}); err == nil {
		t.Fatal("missing acceptance acknowledged")
	}
	a, _, _ = controlFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":0,"data":{"tasks":[{"task_code":"one"}]}}`)
	})
	if _, err := a.GrowthTasks(context.Background()); err == nil {
		t.Fatal("missing status inferred")
	}
}
func TestWorkBuddyJobSameLaneDoesNotOverlap(t *testing.T) {
	ledger, err := OpenJobLedger(filepath.Join(t.TempDir(), "jobs.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	started, finish := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, _, errRun := ledger.Run(context.Background(), testCredential(), "balance", "slot1", func(context.Context) (JobReceipt, error) {
			close(started)
			<-finish
			return JobReceipt{}, errors.New("fixture error")
		})
		result <- errRun
	}()
	<-started
	_, ran, err := ledger.Run(context.Background(), testCredential(), "balance", "slot2", func(context.Context) (JobReceipt, error) { t.Error("overlapping lane"); return JobReceipt{}, nil })
	close(finish)
	if err != nil || ran || <-result == nil {
		t.Fatal("lane or failure result incorrect")
	}
}

func TestWorkBuddyResetProbeUsesShortRetryAndTwentyAttemptBudget(t *testing.T) {
	now := time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC)
	ledger, err := OpenJobLedger(filepath.Join(t.TempDir(), "jobs.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	run := func(context.Context) (JobReceipt, error) {
		calls++
		return JobReceipt{}, errors.New("fixture connection error")
	}
	for i := 0; i < 20; i++ {
		if _, ran, errRun := ledger.Run(context.Background(), testCredential(), "reset_probe:hy3", "reset-window", run); !ran || errRun == nil {
			t.Fatal("reset attempt skipped")
		}
		now = now.Add(15 * time.Second)
	}
	if _, ran, _ := ledger.Run(context.Background(), testCredential(), "reset_probe:hy3", "reset-window", run); ran || calls != 20 {
		t.Fatal("reset retry budget exceeded")
	}
}

func TestWorkBuddyQuotaScheduleSurvivesRestartAndSlotBoundary(t *testing.T) {
	now := time.Date(2026, 10, 21, 21, 59, 59, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "jobs.json")
	ledger, err := OpenJobLedger(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first := testCredential()
	second := first
	second.UID = "second-quota-fixture"
	slot, _ := JobSlot(now, "quota")
	if err = ledger.PrepareQuota(first, "hy3", slot); err != nil {
		t.Fatal(err)
	}
	if err = ledger.PrepareQuota(second, "hy3", slot); err != nil {
		t.Fatal(err)
	}
	firstKey := RiskAccountKey(first) + ":quota_scan:hy3:" + slot
	secondKey := RiskAccountKey(second) + ":quota_scan:hy3:" + slot
	if ledger.state.Receipts[firstKey].NextAttempt.Sub(now) != 5*time.Second || ledger.state.Receipts[secondKey].NextAttempt.Sub(now) != 20*time.Second {
		t.Fatal("first scans were not staggered")
	}
	ledger, err = OpenJobLedger(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	run := func(context.Context) (JobReceipt, error) { calls++; return JobReceipt{}, nil }
	now = now.Add(4 * time.Second)
	nextSlot, _ := JobSlot(now, "quota")
	if nextSlot == slot {
		t.Fatal("fixture did not cross a six-hour boundary")
	}
	if _, ran, _ := ledger.Run(context.Background(), first, "quota_scan:hy3", nextSlot, run); ran {
		t.Fatal("slot rollover bypassed persisted initial delay")
	}
	now = now.Add(time.Second)
	if _, ran, errRun := ledger.Run(context.Background(), first, "quota_scan:hy3", nextSlot, run); !ran || errRun != nil {
		t.Fatal("due scan did not run")
	}
	now = now.Add(6*time.Hour - time.Second)
	thirdSlot, _ := JobSlot(now, "quota")
	if _, ran, _ := ledger.Run(context.Background(), first, "quota_scan:hy3", thirdSlot, run); ran {
		t.Fatal("slot rollover shortened the six-hour scan interval")
	}
	now = now.Add(time.Second)
	if _, ran, errRun := ledger.Run(context.Background(), first, "quota_scan:hy3", thirdSlot, run); !ran || errRun != nil || calls != 2 {
		t.Fatal("six-hour scan did not resume")
	}
}

func TestWorkBuddyQuotaRetryBudgetDoesNotResetAtSlotBoundary(t *testing.T) {
	now := time.Date(2026, 10, 21, 21, 59, 0, 0, time.UTC)
	ledger, err := OpenJobLedger(filepath.Join(t.TempDir(), "jobs.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	c := testCredential()
	calls := 0
	run := func(context.Context) (JobReceipt, error) {
		calls++
		return JobReceipt{}, errors.New("fixture quota failure")
	}
	var last time.Time
	for i := 1; i <= 6; i++ {
		slot, _ := JobSlot(now, "quota")
		receipt, ran, errRun := ledger.Run(context.Background(), c, "quota_scan:hy3", slot, run)
		if !ran || errRun == nil || receipt.Attempts != i {
			t.Fatalf("attempt %d: receipt=%+v ran=%v err=%v", i, receipt, ran, errRun)
		}
		last = now
		now = now.Add(15 * time.Minute)
	}
	now = last.Add(6*time.Hour - time.Second)
	slot, _ := JobSlot(now, "quota")
	if _, ran, _ := ledger.Run(context.Background(), c, "quota_scan:hy3", slot, run); ran {
		t.Fatal("slot rollover restarted exhausted retry budget early")
	}
	now = now.Add(time.Second)
	slot, _ = JobSlot(now, "quota")
	receipt, ran, errRun := ledger.Run(context.Background(), c, "quota_scan:hy3", slot, run)
	if !ran || errRun == nil || receipt.Attempts != 1 || calls != 7 {
		t.Fatal("new quota period did not reset attempt budget")
	}
}
