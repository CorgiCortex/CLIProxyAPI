package workbuddy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestWorkBuddyBalancePreservesUnknownZeroAndPrecision(t *testing.T) {
	p, err := decodeCreditPackage(json.RawMessage(`{"CapacitySize":"100","CapacityUsedPrecise":"0","CapacityRemainPrecise":"0.125","CapacityRemain":0}`))
	if err != nil || p.Capacity == nil || *p.Capacity != 100 || p.Used == nil || *p.Used != 0 || p.Remaining == nil || *p.Remaining != .125 {
		t.Fatalf("package=%+v err=%v", p, err)
	}
	p, err = decodeCreditPackage(json.RawMessage(`{"CapacitySize":100,"CapacityUsed":20}`))
	if err != nil || p.Remaining != nil {
		t.Fatal("missing remainder was derived")
	}
	for _, raw := range []string{`{"CapacityRemain":"NaN"}`, `{"CapacityRemain":-1}`, `{"CapacityRemain":true}`} {
		if _, err = decodeCreditPackage(json.RawMessage(raw)); err == nil {
			t.Fatal("invalid number accepted")
		}
	}
}
func TestWorkBuddyBalanceAggregatesAllPagesBeforeCreditRecovery(t *testing.T) {
	var calls atomic.Int32
	a, c, _ := controlFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request struct{ PageNumber int }
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		fmt.Fprintf(w, `{"code":0,"data":{"Response":{"Data":{"TotalCount":2,"Accounts":[{"AccountId":"p%d","CapacityRemainPrecise":"12.5","CapacityUsed":2,"CapacitySize":14.5}]}}}}`, request.PageNumber)
	})
	if _, err := a.Governor.RecordFailure(*c, "chat", Fault{Kind: FaultBalance, Status: 402}, FailureOptions{}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.FetchBalance(context.Background())
	if err != nil || snapshot.Remaining == nil || *snapshot.Remaining != 25 || len(snapshot.Packages) != 2 || calls.Load() != 2 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	if gate, _ := a.Governor.Check(*c, "chat", false, false); !gate.Allowed() {
		t.Fatal("positive balance did not clear credit parking")
	}
}
func TestWorkBuddyBalanceMissingFieldClearsOldObservedRemainder(t *testing.T) {
	a, c, _ := controlFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":0,"data":{"Response":{"Data":{"Accounts":[{"CapacityUsed":2,"CapacitySize":10}]}}}}`)
	})
	_, attempt := a.Governor.Check(*c, "balance", false, true)
	if err := a.Governor.ObserveBalance(*c, attempt, 50); err != nil {
		t.Fatal(err)
	}
	if err := a.Governor.UpdateLimits(Limits{ReserveCredits: 5}, nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.FetchBalance(context.Background())
	if err != nil || snapshot.Remaining != nil {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	if gate, _ := a.Governor.Check(*c, "chat", false, false); gate.Reason != "balance_unknown" {
		t.Fatal("old balance carried forward")
	}
}
func TestWorkBuddyBalanceRejectsIncompleteAndDuplicatePages(t *testing.T) {
	for _, accounts := range []string{`[]`, `[{"AccountId":"duplicate","CapacityRemain":10}]`} {
		t.Run(accounts, func(t *testing.T) {
			a, _, _ := controlFixture(t, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `{"code":0,"data":{"Response":{"Data":{"TotalCount":2,"Accounts":%s}}}}`, accounts)
			})
			if _, err := a.FetchBalance(context.Background()); err == nil {
				t.Fatal("partial total accepted")
			}
		})
	}
}
func TestWorkBuddyEnterpriseBalanceDoesNotInventRemainder(t *testing.T) {
	a, c, _ := controlFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/billing/meter/get-enterprise-user-usage" {
			t.Error("personal endpoint used for enterprise")
		}
		fmt.Fprint(w, `{"code":0,"data":{"credit":"30.5","limitNum":100,"cycleStartTime":"2026-10-01"}}`)
	})
	c.EnterpriseID = "fixture-enterprise"
	result, err := a.FetchBalance(context.Background())
	if err != nil || !result.Enterprise || result.Remaining != nil || result.Used == nil || *result.Used != 30.5 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
