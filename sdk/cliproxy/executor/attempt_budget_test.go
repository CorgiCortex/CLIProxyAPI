package executor

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

func TestProviderAttemptBudgetSurvivesNestedAttempts(t *testing.T) {
	ctx := WithProviderAttemptBudget(context.Background(), "zcode", 3)
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Go(func() {
			nested := WithProviderAttemptBudget(ctx, "zcode", 3)
			if TakeProviderAttempt(nested, "zcode") {
				accepted.Add(1)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 3 {
		t.Fatalf("accepted %d, want 3", accepted.Load())
	}
	if !TakeProviderAttempt(ctx, "claude") {
		t.Fatal("ZCode budget changed another provider")
	}
	if !TakeProviderAttempt(WithProviderAttemptBudget(context.Background(), "zcode", 3), "zcode") {
		t.Fatal("budget leaked to another request")
	}
}
