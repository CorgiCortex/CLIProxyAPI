package workbuddy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWorkBuddyLogicalRequestBudgetAndIdentity(t *testing.T) {
	ctx, err := WithRequestState(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := WithRequestState(ctx, 200)
	if err != nil {
		t.Fatal(err)
	}
	s := State(second)
	if s != State(ctx) {
		t.Fatal("retry replaced request state")
	}
	for i := 0; i < 3; i++ {
		if err := s.Begin(); err != nil {
			t.Fatal(err)
		}
	}
	var dispatch *DispatchError
	if err := s.Begin(); !errors.As(err, &dispatch) || !dispatch.Stop {
		t.Fatalf("budget error = %v", err)
	}
	c := testCredential()
	if !s.Charge(c) || s.Charge(c) {
		t.Fatal("failure count repeated")
	}
	c.Product = CLI
	if s.Charge(c) {
		t.Fatal("product bypassed UID failure scope")
	}
	if !s.Refresh(c) || s.Refresh(c) {
		t.Fatal("refresh not bounded")
	}
}
func TestWorkBuddyConcurrencyAdmissionAndCancellation(t *testing.T) {
	limiter, err := NewLimiter(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	releaseA, err := limiter.Acquire(ctx, "a", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	releaseB, err := limiter.Acquire(ctx, "b", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	releaseB()
	releaseB()
	if _, err := limiter.Acquire(ctx, "a", 0); err == nil {
		t.Fatal("caller cap bypassed")
	}
	releaseA()
	release, err := limiter.Acquire(ctx, "a", 0)
	if err != nil {
		t.Fatal(err)
	}
	release()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := limiter.Acquire(canceled, "c", time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel = %v", err)
	}
	if limiter.active != 0 || len(limiter.callers) != 0 {
		t.Fatal("admission leaked")
	}
}
func TestWorkBuddyConcurrencyWakeup(t *testing.T) {
	limiter, _ := NewLimiter(1, 0)
	release, _ := limiter.Acquire(context.Background(), "a", time.Second)
	admitted := make(chan func(), 1)
	go func() {
		r, err := limiter.Acquire(context.Background(), "b", time.Minute)
		if err != nil {
			admitted <- nil
			return
		}
		admitted <- r
	}()
	release()
	select {
	case r := <-admitted:
		if r == nil {
			t.Fatal("wait failed")
		}
		r()
	case <-time.After(5 * time.Second):
		t.Fatal("waiter not released")
	}
}
