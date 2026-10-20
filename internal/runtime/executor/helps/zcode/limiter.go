package zcode

import (
	"fmt"
	"sync"
	"time"
)

// BusyError describes local admission pressure, not an upstream account failure.
type BusyError struct{ After time.Duration }

func (e *BusyError) Error() string              { return "zcode: account request budget is busy" }
func (e *BusyError) StatusCode() int            { return 429 }
func (e *BusyError) RetryAfter() *time.Duration { d := e.After; return &d }
func (e *BusyError) IsRequestScoped() bool      { return true }

// RetryOtherCredential permits rotation without marking this account unhealthy.
func (e *BusyError) RetryOtherCredential() bool { return true }

type accountBudget struct {
	active int
	next   time.Time
}

// Limiter survives executor replacement and holds permits through response EOF.
type Limiter struct {
	mu       sync.Mutex
	accounts map[string]*accountBudget
	now      func() time.Time
}

func NewLimiter() *Limiter {
	return &Limiter{accounts: make(map[string]*accountBudget), now: time.Now}
}

func (l *Limiter) Acquire(id string, max int, interval time.Duration) (func(), error) {
	if id == "" {
		return nil, fmt.Errorf("zcode: account ID is required")
	}
	if max <= 0 {
		max = 1
	}
	if interval <= 0 {
		interval = time.Second
	}
	l.mu.Lock()
	now := l.now()
	// Bound idle account state without expiring active permits.
	for key, state := range l.accounts {
		if state.active == 0 && !state.next.After(now) {
			delete(l.accounts, key)
		}
	}
	s := l.accounts[id]
	if s == nil {
		s = &accountBudget{}
		l.accounts[id] = s
	}
	if s.active >= max || s.next.After(now) {
		after := s.next.Sub(now)
		if after <= 0 {
			after = interval
		}
		l.mu.Unlock()
		return nil, &BusyError{After: after}
	}
	s.active++
	s.next = now.Add(interval)
	l.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { l.mu.Lock(); s.active--; l.mu.Unlock() }) }, nil
}
