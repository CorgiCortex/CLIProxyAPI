package config

import "testing"

func TestWorkBuddyV8Configuration(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`version: 8
oauth:
  auth-dir: /private/workbuddy-auth
  providers:
    workbuddy:
      enabled: true
      state-dir: /private/workbuddy-state
      max-concurrency: 8
      per-caller-concurrency: 2
      queue-seconds: 15
      limits:
        reserve-credits: 10
        daily-tokens: 10000
        model-tokens:
          fixture-model: 5000
      realm-limits:
        cn:
          daily-tokens: 2000
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.WorkBuddy.Enabled || cfg.WorkBuddy.StateDir != "/private/workbuddy-state" || cfg.WorkBuddy.PerCallerConcurrency != 2 || cfg.WorkBuddy.Limits.ModelTokens["fixture-model"] != 5000 || cfg.WorkBuddy.RealmLimits["cn"].DailyTokens != 2000 {
		t.Fatalf("configuration not mapped: %+v", cfg.WorkBuddy)
	}
	defaultCfg, err := ParseConfigBytes([]byte("version: 8\n"))
	if err != nil {
		t.Fatal(err)
	}
	if defaultCfg.WorkBuddy.Enabled {
		t.Fatal("provider enabled implicitly")
	}
}
