package cliproxy

import (
	"context"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	log "github.com/sirupsen/logrus"
)

func (s *Service) runWorkBuddyMaintenance(ctx context.Context) {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.workBuddyMaintenanceCycle(ctx)
		timer.Reset(15 * time.Second)
	}
}

func (s *Service) workBuddyMaintenanceCycle(ctx context.Context) {
	cfg := s.currentConfig()
	if cfg == nil || !cfg.WorkBuddy.Enabled || !cfg.WorkBuddy.Jobs.Enabled || s.coreManager == nil {
		return
	}
	provider, ok := s.coreManager.Executor("workbuddy")
	if !ok {
		return
	}
	native, ok := provider.(*executor.WorkBuddyExecutor)
	if !ok || !native.UsesConfig(cfg) {
		return
	}
	changed, err := native.RunMaintenance(ctx)
	if err != nil && ctx.Err() == nil {
		log.WithField("provider", "workbuddy").Warn("maintenance cycle has incomplete tasks; inspect durable receipts")
	}
	if ctx.Err() != nil || !native.UsesConfig(s.currentConfig()) {
		return
	}
	for _, id := range changed {
		if current, exists := s.coreManager.GetByID(id); exists && !current.Disabled {
			s.registerModelsForAuth(ctx, current)
		}
	}
}
