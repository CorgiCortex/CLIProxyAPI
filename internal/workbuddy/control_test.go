package workbuddy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func controlFixture(t *testing.T, handler http.HandlerFunc) (*ControlClient, *Credential, *time.Time) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	g, now, _ := governorFixture(t, Limits{})
	c := testCredential()
	c.Realm = China
	limiter, err := NewLimiter(4, 1)
	if err != nil {
		t.Fatal(err)
	}
	a := &ControlClient{Governor: g, Transports: NewTransports(32, nil), Limiter: limiter, Versions: DefaultVersions(), BaseURL: server.URL, Now: func() time.Time { return *now }, Load: func() (Credential, error) { return c, nil }}
	return a, &c, now
}

func TestWorkBuddyControlRestrictionBlocksRefreshAndAllOperations(t *testing.T) {
	var calls, refreshes atomic.Int32
	a, c, now := controlFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, `{"code":0,"data":{}}`) })
	a.Refresh = func(context.Context) (Credential, error) { refreshes.Add(1); return *c, nil }
	c.ExpiresAt = now.Add(-time.Minute).Unix()
	if _, err := a.Governor.RecordFailure(*c, "chat", Fault{Kind: FaultRestricted, Status: 403, Code: 11140}, FailureOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, op := range []ControlOperation{ControlModels, ControlResources, ControlCheckin, ControlGrowthTasks} {
		_, err := a.Call(context.Background(), ControlRequest{Operation: op})
		var dispatch *DispatchError
		if !errors.As(err, &dispatch) || dispatch.Reason != "account_restricted" {
			t.Fatalf("%s: %v", op, err)
		}
	}
	if calls.Load() != 0 || refreshes.Load() != 0 {
		t.Fatal("restricted credential contacted upstream")
	}
}

func TestWorkBuddyControl429IsSharedAndBalanceCannotBypassIt(t *testing.T) {
	var calls atomic.Int32
	a, _, _ := controlFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(429)
		fmt.Fprint(w, `{"code":14003,"msg":"too many requests"}`)
	})
	for i := 0; i < 2; i++ {
		if _, err := a.Call(context.Background(), ControlRequest{Operation: ControlResources}); err == nil {
			t.Fatal("429 accepted")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("balance bypassed cooldown")
	}
}

func TestWorkBuddyControlRefreshOnceAndPersistBeforeReplay(t *testing.T) {
	var calls atomic.Int32
	var saved atomic.Bool
	a, c, _ := controlFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer rotated" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"code":401}`)
			return
		}
		if !saved.Load() {
			t.Error("rotation replayed before persistence")
		}
		if r.URL.Path != "/v2/billing/meter/daily-checkin" {
			t.Error("wrong path")
		}
		fmt.Fprint(w, `{"code":0,"data":{"credit":25}}`)
	})
	a.Refresh = func(context.Context) (Credential, error) {
		c.AccessToken = "rotated"
		saved.Store(true)
		return *c, nil
	}
	result, err := a.Call(context.Background(), ControlRequest{Operation: ControlCheckin})
	if err != nil || calls.Load() != 2 || result.AlreadyDone || string(result.Data) != `{"credit":25}` {
		t.Fatalf("result=%+v calls=%d err=%v", result, calls.Load(), err)
	}
}

func TestWorkBuddyControlCheckinAlreadyDoneHasNoInventedReward(t *testing.T) {
	a, _, _ := controlFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"code":10001,"data":null}`)
	})
	result, err := a.Call(context.Background(), ControlRequest{Operation: ControlCheckin})
	if err != nil || !result.AlreadyDone || string(result.Data) != "null" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestWorkBuddyControlUncertainMutationIsNeverReplayed(t *testing.T) {
	var calls atomic.Int32
	a, _, _ := controlFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		if err = conn.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := a.Call(context.Background(), ControlRequest{Operation: ControlGrowthClaim, TaskCode: "chat_5"}); err == nil {
		t.Fatal("uncertain claim reported success")
	}
	if calls.Load() != 1 {
		t.Fatal("uncertain mutation replayed")
	}
}

func TestWorkBuddyControlRejectsUnknownEnvelopesAndInjectedPaths(t *testing.T) {
	for _, body := range []string{`{}`, `{"data":{}}`, `{"code":0`, strings.Repeat("x", 4<<20+1)} {
		t.Run(fmt.Sprint(len(body)), func(t *testing.T) {
			a, _, _ := controlFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if _, err := a.Call(context.Background(), ControlRequest{Operation: ControlResources}); err == nil {
				t.Fatal("malformed envelope accepted")
			}
		})
	}
	var calls atomic.Int32
	a, _, _ := controlFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
	for _, r := range []ControlRequest{{Operation: "https://other.test"}, {Operation: ControlGrowthClaim, TaskCode: "../../auth"}, {Operation: ControlGrowthAccept, TaskCodes: []string{"bad/code"}}} {
		if _, err := a.Call(context.Background(), r); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached network")
	}
}

func TestWorkBuddyControlBodyAndContext(t *testing.T) {
	a, _, _ := controlFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("X-Client-Platform") != "web" {
			t.Error("wrong billing request")
		}
		var body struct {
			PageNumber int
			PageSize   int
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.PageNumber != 2 || body.PageSize != 100 {
			t.Error("pagination lost")
		}
		fmt.Fprint(w, `{"code":0,"data":{"Response":{"Data":{"Accounts":[]}}}}`)
	})
	if _, err := a.Call(context.Background(), ControlRequest{Operation: ControlResources, Page: 2}); err != nil {
		t.Fatal(err)
	}
	c, _ := a.Load()
	client, err := a.Transports.Client(c, a.BaseURL, "", nil)
	if err != nil || client.Timeout != 0 {
		t.Fatal("background upstream has a deadline")
	}
}

func TestWorkBuddyRewardAndMetadataReadsCanRecoverCreditParking(t *testing.T) {
	var calls atomic.Int32
	a, c, _ := controlFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, `{"code":0,"data":{}}`) })
	if err := a.Governor.UpdateLimits(Limits{ReserveCredits: 10}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Governor.RecordFailure(*c, "chat", Fault{Kind: FaultBalance, Status: 402}, FailureOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, request := range []ControlRequest{{Operation: ControlModels}, {Operation: ControlGrowthTasks}, {Operation: ControlGrowthAccept, TaskCodes: []string{"chat_5"}}, {Operation: ControlGrowthClaim, TaskCode: "chat_5"}} {
		if _, err := a.Call(context.Background(), request); err != nil {
			t.Fatalf("non-billable recovery operation %s blocked: %v", request.Operation, err)
		}
	}
	if gate, _ := a.Governor.Check(*c, "chat", true, false); gate.Reason != "balance_empty" {
		t.Fatal("metadata/reward response cleared credit parking without a balance observation")
	}
	if calls.Load() != 4 {
		t.Fatal("recovery operations missing")
	}
	if _, err := a.Governor.RecordFailure(*c, "chat", Fault{Kind: FaultRestricted, Status: 403, Code: 11140}, FailureOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Call(context.Background(), ControlRequest{Operation: ControlGrowthClaim, TaskCode: "chat_5"}); err == nil || calls.Load() != 4 {
		t.Fatal("reward operation bypassed account restriction")
	}
}
