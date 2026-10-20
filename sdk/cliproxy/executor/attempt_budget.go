package executor

import (
	"context"
	"sync/atomic"
)

type attemptBudgetKey string

// WithProviderAttemptBudget shares a provider's wire-send budget across auth retries.
// Calling it again preserves the existing budget, including nested continuations.
func WithProviderAttemptBudget(ctx context.Context, provider string, limit int32) context.Context {
	key := attemptBudgetKey(provider)
	if _, ok := ctx.Value(key).(*atomic.Int32); ok {
		return ctx
	}
	remaining := &atomic.Int32{}
	remaining.Store(limit)
	return context.WithValue(ctx, key, remaining)
}

// TakeProviderAttempt consumes one actual inference send, not a credential handshake.
func TakeProviderAttempt(ctx context.Context, provider string) bool {
	remaining, ok := ctx.Value(attemptBudgetKey(provider)).(*atomic.Int32)
	return !ok || remaining.Add(-1) >= 0
}
