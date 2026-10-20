package workbuddy

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// DispatchError declares provider-owned retry policy. The SDK must not convert
// model-only caps into generic credential cooldowns or rotate after restriction.
type DispatchError struct {
	Reason string
	Status int
	Stop   bool
	Until  time.Time
}

func (e *DispatchError) Error() string { return "workbuddy: " + e.Reason }
func (e *DispatchError) StatusCode() int {
	if e.Status > 0 {
		return e.Status
	}
	return http.StatusServiceUnavailable
}
func (e *DispatchError) RetryAfter() *time.Duration {
	if e.Until.IsZero() {
		return nil
	}
	wait := time.Until(e.Until)
	if wait < 0 {
		wait = 0
	}
	return &wait
}

func (e *DispatchError) NativeExecutionErrorAction() string {
	if e.Stop {
		return "stop"
	}
	return "continue"
}

func ErrorForFault(f Fault) *DispatchError {
	stop := false
	switch f.Kind {
	case FaultRestricted, FaultContent, FaultModelRetired, FaultProviderUnavailable, FaultEntitlement, FaultModelParameter, FaultTLS, FaultCanceled, FaultRequest:
		stop = true
	}
	status := f.Status
	if status == 0 {
		status = http.StatusBadGateway
	}
	return &DispatchError{Reason: string(f.Kind), Status: status, Stop: stop, Until: f.ResetAt}
}

type requestStateKey struct{}
type RequestState struct {
	Route          SessionRoute
	mu             sync.Mutex
	Turn           string
	attempts, max  int
	charged        map[string]bool
	refreshed      map[string]bool
	exits          map[string]bool
	degraded, paid bool
	delay          time.Duration
}

func WithRequestState(ctx context.Context, accounts int, extra ...int) (context.Context, error) {
	if _, ok := ctx.Value(requestStateKey{}).(*RequestState); ok {
		return ctx, nil
	}
	turn, err := NewTurnID()
	if err != nil {
		return ctx, err
	}
	if accounts < 2 {
		accounts = 2
	}
	additional := 0
	if len(extra) > 0 && extra[0] > 0 {
		additional = extra[0]
	}
	state := &RequestState{Turn: turn, max: accounts + 1 + additional, exits: make(map[string]bool), charged: make(map[string]bool), refreshed: make(map[string]bool)}
	return context.WithValue(ctx, requestStateKey{}, state), nil
}
func State(ctx context.Context) *RequestState {
	state, _ := ctx.Value(requestStateKey{}).(*RequestState)
	return state
}
func (s *RequestState) Begin() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attempts >= s.max {
		return &DispatchError{Reason: "request_attempt_limit", Status: 503, Stop: true}
	}
	s.attempts++
	return nil
}
func (s *RequestState) Charge(c Credential) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := RiskAccountKey(c)
	if s.charged[key] {
		return false
	}
	s.charged[key] = true
	return true
}
func (s *RequestState) Refresh(c Credential) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := RiskAccountKey(c)
	if s.refreshed[key] {
		return false
	}
	s.refreshed[key] = true
	return true
}

// Limiter bounds both total upstream concurrency and individual caller usage.
// Queue deadlines only govern admission; they never become network deadlines.
type Limiter struct {
	mu             sync.Mutex
	global, perKey int
	active         int
	callers        map[string]int
	changed        chan struct{}
}

func NewLimiter(global, perKey int) (*Limiter, error) {
	if global == 0 {
		global = 32
	}
	if global < 1 || perKey < 0 {
		return nil, fmt.Errorf("workbuddy: invalid concurrency limits")
	}
	return &Limiter{global: global, perKey: perKey, callers: make(map[string]int), changed: make(chan struct{})}, nil
}
func (l *Limiter) Acquire(ctx context.Context, key string, wait time.Duration) (func(), error) {
	queueCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		l.mu.Lock()
		if l.active < l.global && (l.perKey == 0 || l.callers[key] < l.perKey) {
			l.active++
			l.callers[key]++
			l.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					l.mu.Lock()
					defer l.mu.Unlock()
					l.active--
					l.callers[key]--
					if l.callers[key] == 0 {
						delete(l.callers, key)
					}
					close(l.changed)
					l.changed = make(chan struct{})
				})
			}, nil
		}
		changed := l.changed
		l.mu.Unlock()
		select {
		case <-changed:
		case <-queueCtx.Done():
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, &DispatchError{Reason: "concurrency_queue_full", Status: 503, Stop: true}
		}
	}
}

func (l *Limiter) Configure(global, perKey int) error {
	if global == 0 {
		global = 32
	}
	if global < 1 || perKey < 0 {
		return fmt.Errorf("workbuddy: invalid concurrency limits")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.global, l.perKey = global, perKey
	close(l.changed)
	l.changed = make(chan struct{})
	return nil
}

func (s *RequestState) TryDegrade() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded {
		return false
	}
	s.degraded = true
	return true
}
func (s *RequestState) TryPaidFallback() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.paid {
		return false
	}
	s.paid = true
	return true
}
func (s *RequestState) ChargeExit(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exits[key] {
		return false
	}
	s.exits[key] = true
	return true
}
func (s *RequestState) ReserveDelay(requested time.Duration) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	remaining := 5*time.Second - s.delay
	if requested > remaining {
		requested = remaining
	}
	if requested < 0 {
		requested = 0
	}
	s.delay += requested
	return requested
}
