package workbuddy

import (
	"sort"
	"time"
)

type ResetProbe struct {
	Model   string
	ResetAt time.Time
}

func (g *Governor) DueResetProbes(c Credential) []ResetProbe {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.options.Now()
	var probes []ResetProbe
	for model, state := range g.accountLocked(c).Models {
		if IsFreeCapModel(c.Realm, model) && !state.CapUntil.IsZero() && !now.Before(state.CapUntil) {
			probes = append(probes, ResetProbe{Model: model, ResetAt: state.CapUntil})
		}
	}
	sort.Slice(probes, func(i, j int) bool {
		if probes[i].ResetAt.Equal(probes[j].ResetAt) {
			return probes[i].Model < probes[j].Model
		}
		return probes[i].ResetAt.Before(probes[j].ResetAt)
	})
	return probes
}
func FreeProbeModels(realm Realm) []string {
	models := []string{"hy3", "hy4-preview-f"}
	if realm == International {
		models = append(models, "deepseek-v4.1-flash")
	}
	return models
}
