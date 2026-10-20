package helps

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/workbuddy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// WorkBuddyRuntime is shared by executor replacements and all products/accounts.
// There must be one owner per state directory in a server process.
type WorkBuddyRuntime struct {
	Governor   *workbuddy.Governor
	Transports *workbuddy.Transports
	Limiter    *workbuddy.Limiter
	// BaseURL is an injection seam for offline tests, never populated from auth files.
	BaseURL     string
	StateDir    string
	RefreshGate workbuddy.RefreshGate
	mu          sync.Mutex
	auths       map[string]*coreauth.Auth
	manager     *coreauth.Manager
	Save        func(context.Context, *coreauth.Auth, *coreauth.Auth) error
}

func NewWorkBuddyRuntime(cfg config.WorkBuddyConfig) (*WorkBuddyRuntime, error) {
	if cfg.StateDir == "" {
		return nil, fmt.Errorf("workbuddy: state-dir is required")
	}
	r := &WorkBuddyRuntime{Transports: workbuddy.NewTransports(256, nil), StateDir: filepath.Clean(cfg.StateDir), auths: make(map[string]*coreauth.Auth)}
	var err error
	r.Governor, err = workbuddy.OpenGovernor(filepath.Join(r.StateDir, "risk.json"), workbuddy.GovernorOptions{})
	if err != nil {
		return nil, err
	}
	r.Limiter, err = workbuddy.NewLimiter(cfg.MaxConcurrency, cfg.PerCallerConcurrency)
	if err != nil {
		return nil, err
	}
	r.Save = func(context.Context, *coreauth.Auth, *coreauth.Auth) error {
		return fmt.Errorf("workbuddy: credential persistence is not configured")
	}
	if err = r.Configure(cfg); err != nil {
		return nil, err
	}
	return r, nil
}

// BindManager uses the configured manager store and its concurrency fences.
// It never falls back to a process-global token directory.
func (r *WorkBuddyRuntime) BindManager(manager *coreauth.Manager) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manager = manager
	r.Save = func(ctx context.Context, original, updated *coreauth.Auth) error {
		base, ok := manager.GetByID(updated.ID)
		if !ok || base.Disabled {
			return fmt.Errorf("workbuddy: credential removed or disabled during refresh")
		}
		// The manager validates registration/credential versions before persistence.
		committed, err := manager.UpdateRefreshedAuth(ctx, original, updated)
		if err != nil {
			return err
		}
		if committed == nil || committed.Metadata["access_token"] != updated.Metadata["access_token"] {
			return fmt.Errorf("workbuddy: credential changed during refresh")
		}
		r.Track(committed)
		return nil
	}
}

func (r *WorkBuddyRuntime) Configure(cfg config.WorkBuddyConfig) error {
	if filepath.Clean(cfg.StateDir) != r.StateDir {
		return fmt.Errorf("workbuddy: changing state-dir requires a process restart")
	}
	if cfg.QueueSeconds < 0 {
		return fmt.Errorf("workbuddy: queue-seconds cannot be negative")
	}
	convert := func(l config.WorkBuddyLimits) workbuddy.Limits {
		return workbuddy.Limits{ReserveCredits: l.ReserveCredits, DailyTokens: l.DailyTokens, DailyCredits: l.DailyCredits, ModelTokens: l.ModelTokens}
	}
	realms := make(map[workbuddy.Realm]workbuddy.Limits)
	for k, v := range cfg.RealmLimits {
		realms[workbuddy.Realm(k)] = convert(v)
	}
	if err := r.Governor.UpdateLimits(convert(cfg.Limits), realms); err != nil {
		return err
	}
	return r.Limiter.Configure(cfg.MaxConcurrency, cfg.PerCallerConcurrency)
}
func WorkBuddyCredential(a *coreauth.Auth) (workbuddy.Credential, error) {
	if a == nil || a.Provider != "workbuddy" {
		return workbuddy.Credential{}, fmt.Errorf("workbuddy: missing credential")
	}
	raw, err := json.Marshal(a.Metadata)
	if err != nil {
		return workbuddy.Credential{}, fmt.Errorf("workbuddy: invalid credential metadata")
	}
	c, err := workbuddy.DecodeCredential(raw)
	if err != nil {
		return c, err
	}
	c.Disabled = c.Disabled || a.Disabled
	if a.ProxyURL != "" {
		c.ProxyURL = a.ProxyURL
	}
	return c, nil
}
func (r *WorkBuddyRuntime) Track(a *coreauth.Auth) {
	if a == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev := r.auths[a.ID]; prev != nil {
		if prev.RegistrationEpoch > a.RegistrationEpoch ||
			(prev.RegistrationEpoch == a.RegistrationEpoch && prev.Generation > a.Generation) ||
			(prev.RegistrationEpoch == a.RegistrationEpoch && prev.Generation == a.Generation && prev.UpdatedAt.After(a.UpdatedAt)) {
			return
		}
	}
	r.auths[a.ID] = a.Clone()
}
func (r *WorkBuddyRuntime) Current(a *coreauth.Auth) *coreauth.Auth {
	r.mu.Lock()
	manager := r.manager
	r.mu.Unlock()
	if manager != nil && a != nil {
		current, ok := manager.GetByID(a.ID)
		if !ok {
			return nil
		}
		r.Track(current)
	}
	r.Track(a)
	r.mu.Lock()
	defer r.mu.Unlock()
	if a != nil && r.auths[a.ID] != nil {
		return r.auths[a.ID].Clone()
	}
	return a
}
func (r *WorkBuddyRuntime) Accounts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	unique := make(map[string]bool)
	for _, a := range r.auths {
		c, err := WorkBuddyCredential(a)
		if err == nil && !c.Disabled {
			unique[workbuddy.RiskAccountKey(c)] = true
		}
	}
	return len(unique)
}
func (r *WorkBuddyRuntime) Refresh(ctx context.Context, a *coreauth.Auth, proxy string) (*coreauth.Auth, error) {
	a = r.Current(a)
	c, err := WorkBuddyCredential(a)
	if err != nil {
		return nil, err
	}
	client := &workbuddy.AuthClient{Transports: r.Transports, Versions: workbuddy.DefaultVersions(), ProxyURL: proxy, BaseURL: r.BaseURL}
	var saved, loaded *coreauth.Auth
	refreshed, err := r.RefreshGate.Run(ctx, workbuddy.RiskAccountKey(c), c.AccessToken,
		func() (workbuddy.Credential, error) {
			loaded = r.Current(a)
			return WorkBuddyCredential(loaded)
		},
		func(next workbuddy.Credential) error {
			original := loaded.Clone()
			updated := original.Clone()
			raw, errMarshal := json.Marshal(next)
			if errMarshal != nil {
				return errMarshal
			}
			if errDecode := json.Unmarshal(raw, &updated.Metadata); errDecode != nil {
				return errDecode
			}
			// Zero means no reported expiration; do not retain an older value.
			updated.Metadata["expires_at"] = next.ExpiresAt
			updated.LastRefreshedAt = time.Now()
			updated.UpdatedAt = updated.LastRefreshedAt
			r.mu.Lock()
			save := r.Save
			r.mu.Unlock()
			if errSave := save(ctx, original, updated); errSave != nil {
				return errSave
			}
			r.Track(updated)
			saved = r.Current(updated)
			return nil
		}, client)
	if err != nil {
		return nil, &workbuddy.DispatchError{Reason: "credential_refresh_failed", Status: 401, Stop: true}
	}
	if saved != nil {
		return saved, nil
	}
	current := r.Current(a)
	if current == nil {
		return nil, fmt.Errorf("workbuddy: credential removed during refresh")
	}
	if current.Metadata["access_token"] != refreshed.AccessToken {
		return nil, fmt.Errorf("workbuddy: refreshed credential not installed")
	}
	return current, nil
}
