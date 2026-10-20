package workbuddy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math/rand/v2"
	"net/url"
	"sync"
	"time"
)

const DegradedPrompt = "You are a helpful assistant. Respond in the user's language, follow the user's instructions, and be direct and concise."

type exitFailure struct {
	count int
	last  time.Time
	wait  time.Duration
}
type productSwitch struct {
	count int
	last  time.Time
}

// PolicyState contains deliberately process-local recovery state. Restrictions,
// model caps and usage remain in Governor and cannot be cleared by this object.
type PolicyState struct {
	mu            sync.Mutex
	now           func() time.Time
	jitter        func() float64
	sleep         func(context.Context, time.Duration) error
	degradedUntil time.Time
	exits         map[string]exitFailure
	switches      map[string]productSwitch
}

func NewPolicyState(now func() time.Time) *PolicyState {
	if now == nil {
		now = time.Now
	}
	return &PolicyState{now: now, jitter: func() float64 { return .75 + rand.Float64()*.5 }, sleep: waitBeforeConnect, exits: make(map[string]exitFailure), switches: make(map[string]productSwitch)}
}
func waitBeforeConnect(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (p *PolicyState) Degraded() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.now().Before(p.degradedUntil)
}
func (p *PolicyState) Degrade() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if now.Before(p.degradedUntil) {
		return
	}
	cst := time.FixedZone("CST", 8*3600)
	local := now.In(cst)
	p.degradedUntil = time.Date(local.Year(), local.Month(), local.Day()+1, 0, 0, 0, 0, cst)
}
func ExitKey(base, proxy string) string {
	u, err := url.Parse(base)
	target := base
	if err == nil {
		target = u.Scheme + "://" + u.Host
	}
	sum := sha256.Sum256([]byte(target + "\x00" + proxy))
	return hex.EncodeToString(sum[:])
}

// Backoff charges each exit once per logical request and caps total waiting at
// five seconds. Call only after closing the failed connection/response body.
func (p *PolicyState) Backoff(ctx context.Context, state *RequestState, base, proxy string) error {
	key := ExitKey(base, proxy)
	charge := state.ChargeExit(key)
	p.mu.Lock()
	now := p.now()
	entry := p.exits[key]
	if now.Sub(entry.last) > time.Minute {
		entry = exitFailure{}
	}
	if charge {
		entry.count++
		entry.last = now
		step := entry.count - 1
		if step > 4 {
			step = 4
		}
		seconds := 1 << step
		if seconds > 15 {
			seconds = 15
		}
		entry.wait = time.Duration(float64(time.Duration(seconds)*time.Second) * p.jitter())
		if len(p.exits) >= 1024 {
			for k, v := range p.exits {
				if now.Sub(v.last) > time.Minute {
					delete(p.exits, k)
				}
			}
		}
		if _, exists := p.exits[key]; exists || len(p.exits) < 1024 {
			p.exits[key] = entry
		}
	}
	p.mu.Unlock()
	return p.sleep(ctx, state.ReserveDelay(entry.wait))
}
func (p *PolicyState) ExitSuccess(base, proxy string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.exits, ExitKey(base, proxy))
}

func (p *PolicyState) NextProduct(c Credential, model string, allowed []Product) (Product, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	key := RiskAccountKey(c) + "\x00" + model
	entry := p.switches[key]
	if now.Sub(entry.last) > time.Minute {
		entry = productSwitch{}
	}
	if entry.count >= 4 {
		return "", false
	}
	sequence := []Product{Desktop, VSCode, CLI}
	start := 0
	for i, product := range sequence {
		if product == c.Product {
			start = i
			break
		}
	}
	permitted := func(product Product) bool {
		if len(allowed) == 0 {
			return true
		}
		for _, item := range allowed {
			if item == product {
				return true
			}
		}
		return false
	}
	for i := 1; i < len(sequence); i++ {
		next := sequence[(start+i)%len(sequence)]
		if !permitted(next) {
			continue
		}
		// CN VSCode personal accounts require a real device token. Do not invent one.
		if next == VSCode && c.Realm == China && c.EnterpriseID == "" && c.DeviceToken == "" {
			continue
		}
		if len(p.switches) >= 500 {
			for k, v := range p.switches {
				if now.Sub(v.last) > time.Minute {
					delete(p.switches, k)
				}
			}
		}
		if _, exists := p.switches[key]; !exists && len(p.switches) >= 500 {
			return "", false
		}
		entry.count++
		entry.last = now
		p.switches[key] = entry
		return next, true
	}
	return "", false
}
func (p *PolicyState) ProductSuccess(c Credential, model string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.switches, RiskAccountKey(c)+"\x00"+model)
}
