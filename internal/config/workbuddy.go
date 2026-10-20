package config

// WorkBuddyConfig is opt-in. State belongs to a dedicated provider volume and
// must never be shared between independent server processes.
type WorkBuddyConfig struct {
	AffinityByPrefix     *bool                      `yaml:"affinity-by-prefix" json:"affinity-by-prefix"`
	AffinityMaxMessages  *int                       `yaml:"affinity-max-messages" json:"affinity-max-messages"`
	AffinityPageSize     *int                       `yaml:"affinity-page-size" json:"affinity-page-size"`
	EgressBackoff        bool                       `yaml:"egress-backoff" json:"egress-backoff"`
	AutoSwitchProduct    bool                       `yaml:"auto-switch-product" json:"auto-switch-product"`
	AutoSwitchProducts   []string                   `yaml:"auto-switch-products" json:"auto-switch-products"`
	PaidFallback         bool                       `yaml:"paid-fallback" json:"paid-fallback"`
	Prompt               WorkBuddyPrompt            `yaml:"prompt" json:"prompt"`
	Enabled              bool                       `yaml:"enabled" json:"enabled"`
	StateDir             string                     `yaml:"state-dir" json:"state-dir"`
	MaxConcurrency       int                        `yaml:"max-concurrency" json:"max-concurrency"`
	PerCallerConcurrency int                        `yaml:"per-caller-concurrency" json:"per-caller-concurrency"`
	QueueSeconds         int                        `yaml:"queue-seconds" json:"queue-seconds"`
	Limits               WorkBuddyLimits            `yaml:"limits" json:"limits"`
	RealmLimits          map[string]WorkBuddyLimits `yaml:"realm-limits" json:"realm-limits"`
}

type WorkBuddyLimits struct {
	ReserveCredits float64          `yaml:"reserve-credits" json:"reserve-credits"`
	DailyTokens    int64            `yaml:"daily-tokens" json:"daily-tokens"`
	DailyCredits   float64          `yaml:"daily-credits" json:"daily-credits"`
	ModelTokens    map[string]int64 `yaml:"model-tokens" json:"model-tokens"`
}

type WorkBuddyPrompt struct {
	Mode string `yaml:"mode" json:"mode"`
	Text string `yaml:"text" json:"text"`
	File string `yaml:"file" json:"file"`
}
