package workbuddy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type JobReceipt struct {
	Account      string    `json:"account"`
	Job          string    `json:"job"`
	Slot         string    `json:"slot"`
	Status       string    `json:"status"`
	Attempts     int       `json:"attempts"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at,omitempty"`
	NextAttempt  time.Time `json:"next_attempt"`
	Reason       string    `json:"reason,omitempty"`
	AlreadyDone  bool      `json:"already_done,omitempty"`
	Credit       *float64  `json:"credit,omitempty"`
	Energy       *float64  `json:"energy,omitempty"`
	PendingTasks int       `json:"pending_tasks,omitempty"`
}
type jobState struct {
	Version  int                   `json:"version"`
	Receipts map[string]JobReceipt `json:"receipts"`
}
type JobLedger struct {
	mu      sync.Mutex
	path    string
	now     func() time.Time
	state   jobState
	active  map[string]bool
	saveErr error
}

func OpenJobLedger(path string, now func() time.Time) (*JobLedger, error) {
	if now == nil {
		now = time.Now
	}
	l := &JobLedger{path: path, now: now, state: jobState{Version: 1, Receipts: make(map[string]JobReceipt)}, active: make(map[string]bool)}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, fmt.Errorf("workbuddy: read job receipts: %w", err)
	}
	if err = json.Unmarshal(raw, &l.state); err != nil {
		return nil, fmt.Errorf("workbuddy: decode job receipts: %w", err)
	}
	if l.state.Version != 1 || l.state.Receipts == nil {
		return nil, fmt.Errorf("workbuddy: unsupported job receipt version")
	}
	return l, nil
}
func (l *JobLedger) persistLocked() error {
	l.saveErr = WriteJSON(l.path, l.state)
	if l.saveErr != nil {
		return fmt.Errorf("workbuddy: persist job receipt: %w", l.saveErr)
	}
	return nil
}

// Run persists intent before the action. A process restart retains retry limits
// and success receipts; an uncertain outcome is never recorded as completion.
// run must reconcile upstream state before retrying non-idempotent actions.
func (l *JobLedger) Run(ctx context.Context, c Credential, job, slot string, run func(context.Context) (JobReceipt, error)) (JobReceipt, bool, error) {
	account := RiskAccountKey(c)
	key := account + ":" + job + ":" + slot
	lane := account + ":" + job
	l.mu.Lock()
	receipt := l.state.Receipts[key]
	if l.saveErr != nil {
		err := l.saveErr
		l.mu.Unlock()
		return receipt, false, err
	}
	now := l.now()
	if strings.HasPrefix(job, "quota_scan:") {
		var latest JobReceipt
		for previousKey, previous := range l.state.Receipts {
			if previous.Account == account && previous.Job == job && previous.StartedAt.After(latest.StartedAt) {
				latest = previous
			}
			if previous.Account == account && previous.Job == job && previous.Status == "scheduled" {
				if now.Before(previous.NextAttempt) {
					l.mu.Unlock()
					return previous, false, nil
				}
				if previousKey != key {
					delete(l.state.Receipts, previousKey)
				}
			}
			if previous.Account == account && previous.Job == job && previous.Status == "success" && now.Before(previous.FinishedAt.Add(6*time.Hour)) {
				l.mu.Unlock()
				return previous, false, nil
			}
		}
		if latest.Slot != slot && (latest.Status == "failed" || latest.Status == "pending") {
			until := latest.NextAttempt
			lastAttempt := latest.FinishedAt
			if lastAttempt.IsZero() {
				lastAttempt = latest.StartedAt
			}
			if latest.Attempts >= 6 && lastAttempt.Add(6*time.Hour).After(until) {
				until = lastAttempt.Add(6 * time.Hour)
			}
			if now.Before(until) {
				l.mu.Unlock()
				return latest, false, nil
			}
			if latest.Attempts < 6 {
				receipt.Attempts = latest.Attempts
			}
		}
	}
	maxAttempts, retryDelay := 6, 15*time.Minute
	if strings.HasPrefix(job, "reset_probe:") {
		maxAttempts, retryDelay = 20, 15*time.Second
	}
	if receipt.Status == "success" || receipt.Attempts >= maxAttempts || now.Before(receipt.NextAttempt) || l.active[lane] {
		l.mu.Unlock()
		return receipt, false, nil
	}
	// Keep seven days of receipts. Pending/uncertain outcomes remain available
	// for reconciliation instead of silently becoming new work.
	for k, r := range l.state.Receipts {
		if r.Status == "success" && now.Sub(r.FinishedAt) > 7*24*time.Hour {
			delete(l.state.Receipts, k)
		}
	}
	if _, exists := l.state.Receipts[key]; !exists && len(l.state.Receipts) >= 10000 {
		l.mu.Unlock()
		return receipt, false, fmt.Errorf("workbuddy: job receipt limit reached")
	}
	receipt.Account, receipt.Job, receipt.Slot = account, job, slot
	receipt.Status, receipt.Reason = "pending", ""
	receipt.StartedAt, receipt.FinishedAt = now, time.Time{}
	receipt.Attempts++
	receipt.NextAttempt = now.Add(retryDelay)
	l.state.Receipts[key] = receipt
	if err := l.persistLocked(); err != nil {
		l.mu.Unlock()
		return receipt, false, err
	}
	l.active[lane] = true
	l.mu.Unlock()
	outcome, err := run(ctx)
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.active, lane)
	receipt.FinishedAt = l.now()
	receipt.Status = "success"
	receipt.AlreadyDone, receipt.Credit, receipt.Energy = outcome.AlreadyDone, outcome.Credit, outcome.Energy
	receipt.PendingTasks = outcome.PendingTasks
	if err != nil {
		receipt.Status, receipt.Reason = "failed", "operation_failed"
		if errors.Is(err, context.Canceled) {
			receipt.Reason = "canceled"
		}
		var dispatch *DispatchError
		if errors.As(err, &dispatch) {
			receipt.Reason = dispatch.Reason
			if dispatch.Until.After(receipt.NextAttempt) {
				receipt.NextAttempt = dispatch.Until
			}
		}
	}
	l.state.Receipts[key] = receipt
	if errSave := l.persistLocked(); errSave != nil {
		return receipt, true, errSave
	}
	return receipt, true, err
}

// PrepareQuota spreads newly observed account/model pairs over the initial
// hour. Persisting the schedule prevents a restart from bursting the whole pool.
func (l *JobLedger) PrepareQuota(c Credential, model, slot string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.saveErr != nil {
		return l.saveErr
	}
	account, job := RiskAccountKey(c), "quota_scan:"+model
	for _, receipt := range l.state.Receipts {
		if receipt.Account == account && receipt.Job == job {
			return nil
		}
	}
	if len(l.state.Receipts) >= 10000 {
		return fmt.Errorf("workbuddy: job receipt limit reached")
	}
	now := l.now()
	next := now.Add(5 * time.Second)
	var latest time.Time
	for _, receipt := range l.state.Receipts {
		if strings.HasPrefix(receipt.Job, "quota_scan:") && receipt.Status == "scheduled" && receipt.NextAttempt.After(latest) {
			latest = receipt.NextAttempt
		}
	}
	if spaced := latest.Add(15 * time.Second); spaced.After(next) {
		next = spaced
	}
	if limit := now.Add(time.Hour); next.After(limit) {
		next = limit
	}
	key := account + ":" + job + ":" + slot
	l.state.Receipts[key] = JobReceipt{Account: account, Job: job, Slot: slot, Status: "scheduled", NextAttempt: next}
	return l.persistLocked()
}

func RewardReceipt(result ControlResult) (JobReceipt, error) {
	receipt := JobReceipt{AlreadyDone: result.AlreadyDone}
	if len(result.Data) == 0 || string(result.Data) == "null" {
		return receipt, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(result.Data, &fields); err != nil {
		return receipt, fmt.Errorf("workbuddy: invalid activity receipt")
	}
	var err error
	receipt.Credit, err = observedNumber(fields, "credit")
	if err != nil {
		return receipt, err
	}
	receipt.Energy, err = observedNumber(fields, "energy")
	return receipt, err
}

// JobSlot separates recurring observations from daily benefits. No timer or
// scheduler touches an account until the corresponding policy is enabled.
func JobSlot(now time.Time, job string) (string, bool) {
	local := now.In(time.FixedZone("CST", 8*3600))
	switch job {
	case "models", "balance", "quota":
		return fmt.Sprintf("%s/%d", local.Format("2006-01-02"), local.Hour()/6), true
	case "checkin", "growth":
		if local.Hour() < 9 {
			return "", false
		}
		if job == "growth" {
			hour := 9
			if local.Hour() >= 21 {
				hour = 21
			}
			return fmt.Sprintf("%s/%d", local.Format("2006-01-02"), hour), true
		}
		return local.Format("2006-01-02"), true
	default:
		return "", false
	}
}
