package workbuddy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"time"
)

// Limits are enforced on observed usage. Concurrent requests can finish beyond
// a configured budget; no estimated token or credit amount is stored as fact.
type Limits struct {
	ReserveCredits float64
	DailyTokens    int64
	DailyCredits   float64
	ModelTokens    map[string]int64
}

type GovernorOptions struct {
	Now      func() time.Time
	Location *time.Location
	Limits   Limits
	Realms   map[Realm]Limits
}

type modelRisk struct {
	CooldownUntil time.Time `json:"-"`
	CapUntil      time.Time `json:"cap_until,omitempty"`
}

type accountRisk struct {
	Version          uint64                `json:"-"`
	RestrictedUntil  time.Time             `json:"restricted_until,omitempty"`
	BalanceUntil     time.Time             `json:"balance_until,omitempty"`
	CooldownUntil    time.Time             `json:"-"`
	BreakerUntil     time.Time             `json:"-"`
	DegradeUntil     time.Time             `json:"-"`
	LastFailure      time.Time             `json:"-"`
	LastSoft         time.Time             `json:"-"`
	Failures         int                   `json:"-"`
	UnknownFailures  int                   `json:"-"`
	SoftStreak       int                   `json:"-"`
	UnscopedStreak   int                   `json:"-"`
	Models           map[string]*modelRisk `json:"models"`
	Day              string                `json:"day"`
	Tokens           int64                 `json:"tokens"`
	CreditsSpent     float64               `json:"credits_spent"`
	ModelTokens      map[string]int64      `json:"model_tokens"`
	CreditsRemain    *float64              `json:"credits_remain,omitempty"`
	BalanceStartedAt time.Time             `json:"balance_started_at,omitempty"`
}

type realmRisk struct {
	HoldUntil time.Time            `json:"hold_until,omitempty"`
	Events    map[string]time.Time `json:"events"`
}

// EntitlementMark records a refusal observed for a region/model and reported
// user tier. It is evidence, not a region-wide permission decision: one free
// account's refusal must not block paid accounts in the same region.
type EntitlementMark struct {
	CheckedAt time.Time `json:"checked_at"`
	Until     time.Time `json:"until"`
	UserType  string    `json:"user_type,omitempty"`
}

type governorState struct {
	Version      int                                  `json:"version"`
	Entitlements map[Realm]map[string]EntitlementMark `json:"entitlements,omitempty"`
	Accounts     map[string]*accountRisk              `json:"accounts"`
	Realms       map[Realm]*realmRisk                 `json:"realms"`
}

type Governor struct {
	mu      sync.Mutex
	path    string
	options GovernorOptions
	state   governorState
	saveErr error
}

type Gate struct {
	Reason  string
	Until   time.Time
	Stop    bool
	Version uint64
}

func (g Gate) Allowed() bool { return g.Reason == "" }

// Attempt records one credential's state at dispatch. A later success may not
// clear restrictions or cooldowns raised by a different in-flight request.
type Attempt struct {
	Account   string
	Model     string
	Version   uint64
	StartedAt time.Time
}

func OpenGovernor(path string, options GovernorOptions) (*Governor, error) {
	if path == "" {
		return nil, fmt.Errorf("workbuddy: risk state path is required")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Location == nil {
		location, errLocation := time.LoadLocation("Asia/Shanghai")
		if errLocation != nil {
			return nil, errLocation
		}
		options.Location = location
	}
	validateLimits := func(limits Limits) error {
		if !validCredit(limits.ReserveCredits) || limits.DailyTokens < 0 || !validCredit(limits.DailyCredits) {
			return fmt.Errorf("workbuddy: limits must be finite and nonnegative")
		}
		for _, limit := range limits.ModelTokens {
			if limit < 0 {
				return fmt.Errorf("workbuddy: model limits cannot be negative")
			}
		}
		return nil
	}
	if err := validateLimits(options.Limits); err != nil {
		return nil, err
	}
	for realm, limits := range options.Realms {
		if realm != China && realm != International {
			return nil, fmt.Errorf("workbuddy: invalid limit region")
		}
		if err := validateLimits(limits); err != nil {
			return nil, err
		}
	}
	g := &Governor{path: path, options: options, state: governorState{Version: 1, Accounts: make(map[string]*accountRisk), Realms: make(map[Realm]*realmRisk)}}
	raw, errRead := os.ReadFile(path)
	if errRead == nil {
		if errDecode := json.Unmarshal(raw, &g.state); errDecode != nil || g.state.Version != 1 || g.state.Accounts == nil || g.state.Realms == nil {
			return nil, fmt.Errorf("workbuddy: invalid risk state; dispatch remains disabled")
		}
		for _, state := range g.state.Accounts {
			if state == nil || state.Models == nil || state.ModelTokens == nil {
				return nil, fmt.Errorf("workbuddy: incomplete account risk state")
			}
			if state.Tokens < 0 || !validCredit(state.CreditsSpent) || (state.CreditsRemain != nil && !validCredit(*state.CreditsRemain)) {
				return nil, fmt.Errorf("workbuddy: invalid persisted usage")
			}
			for _, tokens := range state.ModelTokens {
				if tokens < 0 {
					return nil, fmt.Errorf("workbuddy: invalid persisted model usage")
				}
			}
			for _, model := range state.Models {
				if model == nil {
					return nil, fmt.Errorf("workbuddy: incomplete model risk state")
				}
			}
		}
		for realm, state := range g.state.Realms {
			if (realm != China && realm != International) || state == nil || state.Events == nil {
				return nil, fmt.Errorf("workbuddy: incomplete region risk state")
			}
		}
	} else if !errors.Is(errRead, os.ErrNotExist) {
		return nil, fmt.Errorf("workbuddy: read risk state: %w", errRead)
	}
	if g.state.Entitlements == nil {
		g.state.Entitlements = make(map[Realm]map[string]EntitlementMark)
	}
	for realm, models := range g.state.Entitlements {
		if realm != China && realm != International {
			return nil, fmt.Errorf("workbuddy: invalid entitlement region")
		}
		for model, mark := range models {
			if model == "" || mark.CheckedAt.IsZero() || mark.Until.Before(mark.CheckedAt) {
				return nil, fmt.Errorf("workbuddy: invalid entitlement evidence")
			}
		}
	}
	if err := g.persistLocked(); err != nil {
		return nil, err
	}
	return g, nil
}

func RiskAccountKey(c Credential) string {
	sum := sha256.Sum256([]byte(string(c.Realm) + "\x00" + c.UID))
	return hex.EncodeToString(sum[:])
}

func (g *Governor) accountLocked(c Credential) *accountRisk {
	key := RiskAccountKey(c)
	state := g.state.Accounts[key]
	if state == nil {
		state = &accountRisk{Models: make(map[string]*modelRisk), ModelTokens: make(map[string]int64)}
		g.state.Accounts[key] = state
	}
	day := g.options.Now().In(g.options.Location).Format("2006-01-02")
	if state.Day != day {
		state.Day = day
		state.Tokens, state.CreditsSpent = 0, 0
		clear(state.ModelTokens)
	}
	return state
}

func (g *Governor) persistLocked() error {
	if err := WriteJSON(g.path, g.state); err != nil {
		g.saveErr = err
		return fmt.Errorf("workbuddy: persist risk state; dispatch suspended: %w", err)
	}
	g.saveErr = nil
	return nil
}

func (g *Governor) Flush() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.persistLocked()
}

// Check is shared by chat, probes and activity jobs. A balance-only request may
// bypass balance/budget gates to observe recovery, but never account or region
// restrictions, ordinary cooldowns or circuit breakers.
func (g *Governor) Check(c Credential, model string, paid, balanceOnly bool) (Gate, Attempt) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.options.Now()
	if err := c.Validate(); err != nil {
		return Gate{Reason: "invalid_credential", Stop: true}, Attempt{}
	}
	state := g.accountLocked(c)
	attempt := Attempt{Account: RiskAccountKey(c), Model: model, Version: state.Version, StartedAt: now}
	gate := Gate{Version: state.Version}
	if g.saveErr != nil {
		gate.Reason, gate.Stop = "state_persistence_failed", true
		return gate, attempt
	}
	if c.Disabled || c.AccessToken == "" {
		gate.Reason = "credential_disabled"
		return gate, attempt
	}
	if c.ExpiresAt > 0 && c.ExpiresAt <= now.Unix() {
		gate.Reason = "credential_expired"
		return gate, attempt
	}
	if region := g.state.Realms[c.Realm]; region != nil && now.Before(region.HoldUntil) {
		gate.Reason, gate.Until, gate.Stop = "region_restricted", region.HoldUntil, true
		return gate, attempt
	}
	for _, blocked := range []struct {
		reason string
		until  time.Time
	}{
		{"account_restricted", state.RestrictedUntil}, {"account_cooldown", state.CooldownUntil},
		{"account_breaker", state.BreakerUntil}, {"account_degraded", state.DegradeUntil},
	} {
		if now.Before(blocked.until) && blocked.until.After(gate.Until) {
			gate.Reason, gate.Until = blocked.reason, blocked.until
		}
	}
	if gate.Reason != "" {
		return gate, attempt
	}
	if !balanceOnly && now.Before(state.BalanceUntil) {
		gate.Reason, gate.Until = "balance_empty", state.BalanceUntil
		return gate, attempt
	}
	if modelState := state.Models[model]; modelState != nil {
		until := later(modelState.CapUntil, modelState.CooldownUntil)
		if now.Before(until) {
			gate.Reason, gate.Until = "model_cooldown", until
			return gate, attempt
		}
	}
	if balanceOnly {
		return gate, attempt
	}
	limits := g.options.Limits
	if override, exists := g.options.Realms[c.Realm]; exists {
		limits = override
	}
	if limits.ReserveCredits > 0 {
		if state.CreditsRemain == nil {
			gate.Reason = "balance_unknown"
			return gate, attempt
		}
		if *state.CreditsRemain <= limits.ReserveCredits {
			gate.Reason = "credit_reserve"
			return gate, attempt
		}
	}
	switch {
	case limits.DailyTokens > 0 && state.Tokens >= limits.DailyTokens:
		gate.Reason = "daily_tokens"
	case paid && limits.DailyCredits > 0 && state.CreditsSpent >= limits.DailyCredits:
		gate.Reason = "daily_credits"
	case limits.ModelTokens[model] > 0 && state.ModelTokens[model] >= limits.ModelTokens[model]:
		gate.Reason = "model_daily_tokens"
	}
	if gate.Reason != "" {
		gate.Until = nextLocalHour(now, g.options.Location, 0)
	}
	return gate, attempt
}

func nextLocalHour(now time.Time, location *time.Location, hour int) time.Time {
	local := now.In(location)
	next := time.Date(local.Year(), local.Month(), local.Day(), hour, 0, 0, 0, location)
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func backoff(count, threshold int, base, maximum time.Duration) time.Duration {
	steps := min(max(count-threshold, 0), 20)
	return min(base*time.Duration(1<<steps), maximum)
}

// RecordFailure is called once per credential per logical request for hard and
// unknown failures. The executor owns that request-local deduplication set.
type FailureOptions struct {
	FreeModel     bool
	SingleAccount bool
}

func (g *Governor) RecordFailure(c Credential, model string, fault Fault, options FailureOptions) (Gate, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := c.Validate(); err != nil {
		return Gate{Reason: "invalid_credential", Stop: true}, err
	}
	state := g.accountLocked(c)
	now := g.options.Now()
	gate := Gate{Reason: string(fault.Kind)}
	changed := true
	switch fault.Kind {
	case FaultRestricted:
		if !now.Before(state.RestrictedUntil) {
			state.RestrictedUntil = now.Add(2 * time.Hour)
		}
		gate.Until, gate.Stop = state.RestrictedUntil, true
		region := g.state.Realms[c.Realm]
		if region == nil {
			region = &realmRisk{Events: make(map[string]time.Time)}
			g.state.Realms[c.Realm] = region
		}
		for uid, when := range region.Events {
			if now.Sub(when) > 15*time.Minute {
				delete(region.Events, uid)
			}
		}
		region.Events[RiskAccountKey(c)] = now
		if len(region.Events) >= 2 {
			region.HoldUntil = later(region.HoldUntil, now.Add(30*time.Minute))
		}
	case FaultBalance:
		state.BalanceUntil = later(state.BalanceUntil, nextLocalHour(now, g.options.Location, 4))
		gate.Until = state.BalanceUntil
	case FaultAccountRate:
		g.decaySoftLocked(state, now)
		state.SoftStreak++
		state.CooldownUntil = later(state.CooldownUntil, now.Add(backoff(state.SoftStreak, 1, 10*time.Minute, 2*time.Hour)))
		gate.Until = state.CooldownUntil
	case FaultModelRate, FaultModelCap:
		wait := time.Minute
		if fault.ResetAt.IsZero() && fault.Soft {
			g.decaySoftLocked(state, now)
			state.UnscopedStreak++
			wait = backoff(state.UnscopedStreak, 1, time.Minute, 10*time.Minute)
		}
		until := now.Add(wait)
		if !fault.ResetAt.IsZero() {
			until = later(now.Add(time.Second), fault.ResetAt)
		}
		modelState := state.Models[model]
		if modelState == nil {
			modelState = &modelRisk{}
			state.Models[model] = modelState
		}
		modelState.CooldownUntil = later(modelState.CooldownUntil, until)
		if fault.Kind == FaultModelCap && options.FreeModel {
			modelState.CapUntil = later(modelState.CapUntil, until)
		}
		gate.Until = until
	case FaultHard, FaultGateway, FaultUnknown, FaultConnection:
		if !state.LastFailure.IsZero() && now.Sub(state.LastFailure) > 10*time.Minute {
			state.Failures, state.UnknownFailures = 0, 0
		}
		state.LastFailure = now
		state.Failures++
		if fault.Kind == FaultUnknown || fault.Kind == FaultConnection {
			state.UnknownFailures++
		}
		if state.Failures >= 3 {
			state.BreakerUntil = later(state.BreakerUntil, now.Add(backoff(state.Failures, 3, 30*time.Minute, 6*time.Hour)))
		}
		if state.UnknownFailures >= 5 {
			state.DegradeUntil = later(state.DegradeUntil, now.Add(backoff(state.UnknownFailures, 5, 10*time.Minute, 2*time.Hour)))
		}
		gate.Until = later(state.BreakerUntil, state.DegradeUntil)
		if fault.Kind == FaultUnknown {
			wait := time.Minute
			if options.SingleAccount {
				wait = 3 * time.Second
			}
			state.CooldownUntil = later(state.CooldownUntil, now.Add(wait))
			gate.Until = later(gate.Until, state.CooldownUntil)
		}
	case FaultEntitlement:
		models := g.state.Entitlements[c.Realm]
		if models == nil {
			models = make(map[string]EntitlementMark)
			g.state.Entitlements[c.Realm] = models
		}
		models[model] = EntitlementMark{CheckedAt: now, Until: now.Add(24 * time.Hour), UserType: fault.UserType}
		gate.Stop = true
	case FaultAuth:
		// Called only after the request's one refresh attempt has failed.
		wait := time.Minute
		if options.SingleAccount {
			wait = 3 * time.Second
		}
		state.CooldownUntil = later(state.CooldownUntil, now.Add(wait))
		gate.Until = state.CooldownUntil
	default:
		changed = false
		gate.Stop = fault.Kind != FaultLocalNetwork
	}
	if changed {
		state.Version++
		if err := g.persistLocked(); err != nil {
			return Gate{Reason: "state_persistence_failed", Stop: true}, err
		}
	}
	gate.Version = state.Version
	return gate, nil
}

func (g *Governor) decaySoftLocked(state *accountRisk, now time.Time) {
	if !state.LastSoft.IsZero() && now.Sub(state.LastSoft) > 10*time.Minute {
		state.SoftStreak, state.UnscopedStreak = 0, 0
	}
	state.LastSoft = now
}

// Complete records supplied observed usage even if another request raised a
// newer penalty. A success clears penalties only when its dispatch version
// still matches. A cap survives success until its own reset time.
func (g *Governor) Complete(c Credential, attempt Attempt, tokens int64, credits *float64, success bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if attempt.Account != RiskAccountKey(c) || tokens < 0 || (credits != nil && !validCredit(*credits)) {
		return fmt.Errorf("workbuddy: invalid completion accounting")
	}
	state := g.accountLocked(c)
	if tokens > math.MaxInt64-state.Tokens || tokens > math.MaxInt64-state.ModelTokens[attempt.Model] ||
		(credits != nil && !validCredit(state.CreditsSpent+*credits)) {
		return fmt.Errorf("workbuddy: usage counter overflow")
	}
	state.Tokens += tokens
	state.ModelTokens[attempt.Model] += tokens
	if credits != nil {
		state.CreditsSpent += *credits
	}
	if success {
		if mark, ok := g.state.Entitlements[c.Realm][attempt.Model]; ok && !attempt.StartedAt.Before(mark.CheckedAt) {
			delete(g.state.Entitlements[c.Realm], attempt.Model)
		}
	}
	if success && attempt.Version == state.Version {
		state.RestrictedUntil, state.CooldownUntil, state.BreakerUntil, state.DegradeUntil = time.Time{}, time.Time{}, time.Time{}, time.Time{}
		state.LastFailure, state.LastSoft = time.Time{}, time.Time{}
		state.Failures, state.UnknownFailures, state.SoftStreak, state.UnscopedStreak = 0, 0, 0, 0
		if model := state.Models[attempt.Model]; model != nil {
			model.CooldownUntil = time.Time{}
		}
		state.Version++
	}
	return g.persistLocked()
}

func (g *Governor) ObserveBalance(c Credential, attempt Attempt, remain float64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if attempt.Account != RiskAccountKey(c) || !validCredit(remain) {
		return fmt.Errorf("workbuddy: invalid balance observation")
	}
	state := g.accountLocked(c)
	if attempt.Version != state.Version || attempt.StartedAt.Before(state.BalanceStartedAt) {
		return nil
	}
	state.CreditsRemain = &remain
	state.BalanceStartedAt = attempt.StartedAt
	if remain > 0 && attempt.Version == state.Version {
		state.BalanceUntil = time.Time{}
	}
	return g.persistLocked()
}

func validCredit(value float64) bool {
	return value >= 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

// UpdateLimits applies hot-reloaded budgets without rebuilding cooldown state.
func (g *Governor) UpdateLimits(limits Limits, realms map[Realm]Limits) error {
	validate := func(l Limits) bool {
		if !validCredit(l.ReserveCredits) || !validCredit(l.DailyCredits) || l.DailyTokens < 0 {
			return false
		}
		for _, n := range l.ModelTokens {
			if n < 0 {
				return false
			}
		}
		return true
	}
	clone := func(l Limits) Limits {
		m := make(map[string]int64, len(l.ModelTokens))
		for k, v := range l.ModelTokens {
			m[k] = v
		}
		l.ModelTokens = m
		return l
	}
	if !validate(limits) {
		return fmt.Errorf("workbuddy: invalid budgets")
	}
	copyRealms := make(map[Realm]Limits, len(realms))
	for realm, l := range realms {
		if (realm != International && realm != China) || !validate(l) {
			return fmt.Errorf("workbuddy: invalid regional budgets")
		}
		copyRealms[realm] = clone(l)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.options.Limits = clone(limits)
	g.options.Realms = copyRealms
	return nil
}

// Entitlement returns fresh refusal evidence without changing dispatch policy.
func (g *Governor) Entitlement(realm Realm, model string) (EntitlementMark, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	mark, ok := g.state.Entitlements[realm][model]
	return mark, ok && g.options.Now().Before(mark.Until)
}

func (g *Governor) Capped(c Credential, model string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	state := g.state.Accounts[RiskAccountKey(c)]
	if state == nil {
		return false
	}
	cap := state.Models[model]
	return cap != nil && g.options.Now().Before(cap.CapUntil)
}

// ClearIdentityModelCooldown clears only the ordinary model cooldown after a
// successful product change. Durable caps and account/region restrictions stay.
func (g *Governor) ClearIdentityModelCooldown(c Credential, model string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.options.Now()
	state := g.accountLocked(c)
	if g.saveErr != nil || c.Disabled {
		return false
	}
	if realm := g.state.Realms[c.Realm]; realm != nil && now.Before(realm.HoldUntil) {
		return false
	}
	for _, until := range []time.Time{state.RestrictedUntil, state.BalanceUntil, state.CooldownUntil, state.BreakerUntil, state.DegradeUntil} {
		if now.Before(until) {
			return false
		}
	}
	current := state.Models[model]
	if current == nil {
		return true
	}
	if now.Before(current.CapUntil) {
		return false
	}
	current.CooldownUntil = time.Time{}
	state.Version++
	return true
}
