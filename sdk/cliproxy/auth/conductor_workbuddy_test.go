package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/workbuddy"
	execution "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type workBuddyContextExecutor struct {
	mockCustomErrorExecutor
	preparations int
}

func (e *workBuddyContextExecutor) PrepareExecutionContext(ctx context.Context, _ execution.Request, _ execution.Options) (context.Context, error) {
	e.preparations++
	return workbuddy.WithRequestState(ctx, 2)
}
func TestWorkBuddyNativeFailureScopeInManager(t *testing.T) {
	for _, stop := range []bool{true, false} {
		t.Run(map[bool]string{true: "restriction_stops_rotation", false: "model_cap_rotates_without_generic_penalty"}[stop], func(t *testing.T) {
			manager := NewManager(nil, nil, nil)
			ids := []string{t.Name() + "-a", t.Name() + "-b"}
			for _, id := range ids {
				a := &Auth{ID: id, Provider: "workbuddy", Status: StatusActive}
				if _, err := manager.Register(context.Background(), a); err != nil {
					t.Fatal(err)
				}
				registry.GetGlobalRegistry().RegisterClient(id, "workbuddy", []*registry.ModelInfo{{ID: "fixture-model"}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
			}
			calls := 0
			var firstState *workbuddy.RequestState
			e := &workBuddyContextExecutor{mockCustomErrorExecutor: mockCustomErrorExecutor{identifier: "workbuddy"}}
			e.executeFn = func(ctx context.Context, a *Auth, _ execution.Request, _ execution.Options) (execution.Response, error) {
				calls++
				execution.MarkUpstreamAttempt(ctx)
				state := workbuddy.State(ctx)
				if state == nil {
					t.Error("request context not prepared")
				}
				if firstState == nil {
					firstState = state
				} else if state != firstState {
					t.Error("rotation replaced logical request")
				}
				if calls == 1 {
					return execution.Response{}, &workbuddy.DispatchError{Reason: "fixture", Status: 429, Stop: stop}
				}
				return execution.Response{Payload: []byte(`{"ok":true}`)}, nil
			}
			manager.RegisterExecutor(e)
			_, err := manager.Execute(context.Background(), []string{"workbuddy"}, execution.Request{Model: "fixture-model"}, execution.Options{})
			if stop {
				var native *workbuddy.DispatchError
				if !errors.As(err, &native) || calls != 1 {
					t.Fatalf("stop: calls=%d err=%v", calls, err)
				}
			} else if err != nil || calls != 2 {
				t.Fatalf("continue: calls=%d err=%v", calls, err)
			}
			if e.preparations != 1 {
				t.Fatalf("context preparations = %d", e.preparations)
			}
			for _, id := range ids {
				a, ok := manager.GetByID(id)
				if !ok {
					t.Fatal("auth disappeared")
				}
				if a.Unavailable || !a.NextRetryAfter.IsZero() {
					t.Fatal("generic account cooldown replaced native scope")
				}
			}
		})
	}
}

func TestWorkBuddyNativeAuthFailureDoesNotRefreshAgain(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	a := &Auth{ID: "wb-refresh-once", Provider: "workbuddy", Status: StatusActive, Metadata: map[string]any{"access_token": "fixture", "refresh_token": "fixture-refresh"}}
	if _, err := manager.Register(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	executor := &workBuddyRefreshTrap{mockCustomErrorExecutor: mockCustomErrorExecutor{identifier: "workbuddy"}}
	manager.RegisterExecutor(executor)
	_, refreshed := manager.tryRefreshAfterUnauthorized(context.Background(), a, &workbuddy.DispatchError{Reason: "authentication", Status: 401}, false)
	if refreshed || executor.calls != 0 {
		t.Fatal("SDK repeated provider-owned refresh")
	}
}

type workBuddyRefreshTrap struct {
	mockCustomErrorExecutor
	calls int
}

func (e *workBuddyRefreshTrap) Refresh(context.Context, *Auth) (*Auth, error) {
	e.calls++
	return nil, errors.New("unexpected refresh")
}
