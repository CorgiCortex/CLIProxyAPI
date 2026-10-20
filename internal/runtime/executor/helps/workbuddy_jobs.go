package helps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/workbuddy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

type workBuddyCatalogCache struct {
	ObservedAt time.Time         `json:"observed_at"`
	Models     []workbuddy.Model `json:"models"`
}

func (r *WorkBuddyRuntime) Models(c workbuddy.Credential) ([]workbuddy.Model, error) {
	raw, err := os.ReadFile(filepath.Join(r.StateDir, "catalog-"+workbuddy.RiskAccountKey(c)+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return workbuddy.Catalog(c.Realm), nil
	}
	if err != nil {
		return nil, fmt.Errorf("workbuddy: read model catalog: %w", err)
	}
	var cached workBuddyCatalogCache
	if err = json.Unmarshal(raw, &cached); err != nil || len(cached.Models) == 0 {
		return nil, fmt.Errorf("workbuddy: invalid cached model catalog")
	}
	return cached.Models, nil
}

// Maintenance is a single process-wide lane. Reload cancels an active cycle;
// every control request also reloads the authoritative credential before dispatch.
func (r *WorkBuddyRuntime) Maintenance(ctx context.Context, cfg *config.Config, epoch uint64, probe ...func(context.Context, *coreauth.Auth, string) error) ([]string, error) {
	if cfg == nil || !cfg.WorkBuddy.Enabled || !cfg.WorkBuddy.Jobs.Enabled {
		return nil, nil
	}
	if !r.jobMu.TryLock() {
		return nil, nil
	}
	defer r.jobMu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	r.mu.Lock()
	if epoch != r.jobEpoch {
		r.mu.Unlock()
		return nil, nil
	}
	r.jobCancel = cancel
	manager := r.manager
	var records []*coreauth.Auth
	if manager == nil {
		for _, a := range r.auths {
			records = append(records, a.Clone())
		}
	}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		if r.jobEpoch == epoch {
			r.jobCancel = nil
		}
		r.mu.Unlock()
	}()
	if manager != nil {
		records = manager.List()
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	seen := make(map[string]bool)
	var changed []string
	var failures []error
	policy := cfg.WorkBuddy.Jobs
	probeCount := 0
	scanCount := 0
	for _, auth := range records {
		if err := ctx.Err(); err != nil {
			return changed, err
		}
		c, err := WorkBuddyCredential(r.Current(auth))
		if err != nil || c.Disabled {
			continue
		}
		key := workbuddy.RiskAccountKey(c)
		if seen[key] {
			continue
		}
		seen[key] = true
		load := func() (workbuddy.Credential, error) {
			r.mu.Lock()
			current := r.jobEpoch == epoch
			r.mu.Unlock()
			if !current {
				return workbuddy.Credential{}, context.Canceled
			}
			credential, errLoad := WorkBuddyCredential(r.Current(auth))
			if errLoad == nil && workbuddy.RiskAccountKey(credential) != key {
				return credential, fmt.Errorf("workbuddy: account changed during background work")
			}
			return credential, errLoad
		}
		client := &workbuddy.ControlClient{Governor: r.Governor, Transports: r.Transports, Limiter: r.Limiter, Versions: workbuddy.DefaultVersions(), ProxyURL: cfg.ProxyURL, BaseURL: r.BaseURL, QueueWait: time.Duration(cfg.WorkBuddy.QueueSeconds) * time.Second, MinimumInterval: time.Second, Load: load}
		client.Refresh = func(ctx context.Context) (workbuddy.Credential, error) {
			if _, errLoad := load(); errLoad != nil {
				return workbuddy.Credential{}, errLoad
			}
			updated, errRefresh := r.Refresh(ctx, auth, cfg.ProxyURL)
			if errRefresh != nil {
				return workbuddy.Credential{}, errRefresh
			}
			return WorkBuddyCredential(updated)
		}
		jobs := []struct {
			name    string
			enabled bool
		}{{"models", policy.ModelDiscovery}, {"balance", policy.BalanceRefresh}, {"checkin", policy.Checkin && c.Realm == workbuddy.China && c.EnterpriseID == ""}, {"growth", policy.Growth && c.Realm == workbuddy.China && c.EnterpriseID == ""}}
		for _, job := range jobs {
			if !job.enabled {
				continue
			}
			slot, due := workbuddy.JobSlot(time.Now(), job.name)
			if !due {
				continue
			}
			_, ran, errRun := r.Jobs.Run(ctx, c, job.name, slot, func(ctx context.Context) (workbuddy.JobReceipt, error) {
				switch job.name {
				case "models":
					models, errModels := client.DiscoverModels(ctx)
					if errModels != nil {
						return workbuddy.JobReceipt{}, errModels
					}
					errWrite := workbuddy.WriteJSON(filepath.Join(r.StateDir, "catalog-"+key+".json"), workBuddyCatalogCache{ObservedAt: time.Now(), Models: models})
					if errWrite == nil {
						changed = append(changed, auth.ID)
					}
					return workbuddy.JobReceipt{}, errWrite
				case "balance":
					balance, errBalance := client.FetchBalance(ctx)
					if errBalance != nil {
						return workbuddy.JobReceipt{}, errBalance
					}
					return workbuddy.JobReceipt{}, workbuddy.WriteJSON(filepath.Join(r.StateDir, "balance-"+key+".json"), balance)
				case "checkin":
					result, errCheckin := client.Call(ctx, workbuddy.ControlRequest{Operation: workbuddy.ControlCheckin})
					if errCheckin != nil {
						return workbuddy.JobReceipt{}, errCheckin
					}
					return workbuddy.RewardReceipt(result)
				case "growth":
					pending, errGrowth := client.ReconcileGrowth(ctx, r.Jobs)
					return workbuddy.JobReceipt{PendingTasks: pending}, errGrowth
				default:
					return workbuddy.JobReceipt{}, fmt.Errorf("workbuddy: unsupported maintenance task")
				}
			})
			if errRun != nil {
				reason := "operation_failed"
				var dispatch *workbuddy.DispatchError
				if errors.As(errRun, &dispatch) {
					reason = dispatch.Reason
				}
				log.WithFields(log.Fields{"provider": "workbuddy", "account_key": key, "job": job.name, "reason": reason}).Warn("background task incomplete")
				failures = append(failures, fmt.Errorf("workbuddy: %s: %w", job.name, errRun))
			} else if ran {
				log.WithFields(log.Fields{"provider": "workbuddy", "account_key": key, "job": job.name}).Debug("background task recorded")
			}
		}
		if len(probe) > 0 && (policy.QuotaScan || policy.ResetProbes) {
			allowed := func(a *coreauth.Auth, model string) bool {
				credential, errCredential := WorkBuddyCredential(a)
				if errCredential != nil || credential.Disabled || len(credential.Models) > 0 && !slices.Contains(credential.Models, model) {
					return false
				}
				if manager == nil {
					return true
				}
				models := registry.GetGlobalRegistry()
				return models.ClientSupportsModel(a.ID, model) || a.Prefix != "" && models.ClientSupportsModel(a.ID, a.Prefix+"/"+model)
			}
			plans := r.Governor.DueResetProbes(c)
			pendingReset := make(map[string]bool, len(plans))
			for _, plan := range plans {
				pendingReset[plan.Model] = true
			}
			if !policy.ResetProbes {
				plans = nil
			}
			if policy.QuotaScan {
				for _, model := range workbuddy.FreeProbeModels(c.Realm) {
					if !pendingReset[model] && !r.Governor.Capped(c, model) {
						plans = append(plans, workbuddy.ResetProbe{Model: model})
					}
				}
			}
			for _, plan := range plans {
				if !allowed(r.Current(auth), plan.Model) {
					continue
				}
				if probeCount >= 16 {
					return changed, errors.Join(failures...)
				}
				job, slot := "reset_probe:"+plan.Model, plan.ResetAt.UTC().Format(time.RFC3339Nano)
				if plan.ResetAt.IsZero() {
					job = "quota_scan:" + plan.Model
					slot, _ = workbuddy.JobSlot(time.Now(), "quota")
					if errSchedule := r.Jobs.PrepareQuota(c, plan.Model, slot); errSchedule != nil {
						return changed, errSchedule
					}
					if scanCount >= 6 {
						continue
					}
				}
				_, _, errProbe := r.Jobs.Run(ctx, c, job, slot, func(ctx context.Context) (workbuddy.JobReceipt, error) {
					if _, errLoad := load(); errLoad != nil {
						return workbuddy.JobReceipt{}, errLoad
					}
					current := r.Current(auth)
					if !allowed(current, plan.Model) {
						return workbuddy.JobReceipt{}, &workbuddy.DispatchError{Reason: "model_not_allowed_for_probe", Status: 400, Stop: true}
					}
					if probeCount > 0 {
						timer := time.NewTimer(400 * time.Millisecond)
						select {
						case <-ctx.Done():
							timer.Stop()
							return workbuddy.JobReceipt{}, ctx.Err()
						case <-timer.C:
						}
					}
					probeCount++
					if plan.ResetAt.IsZero() {
						scanCount++
					}
					current = r.Current(auth)
					if !allowed(current, plan.Model) {
						return workbuddy.JobReceipt{}, &workbuddy.DispatchError{Reason: "model_not_allowed_for_probe", Status: 400, Stop: true}
					}
					return workbuddy.JobReceipt{}, probe[0](ctx, current, plan.Model)
				})
				if errProbe != nil {
					failures = append(failures, fmt.Errorf("workbuddy: quota probe: %w", errProbe))
				}
			}
		}
	}
	return changed, errors.Join(failures...)
}
