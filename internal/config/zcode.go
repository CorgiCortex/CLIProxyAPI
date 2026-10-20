package config

import (
	"fmt"
	"net/url"
)

// ZCodeConfig configures the native ZCode transport. Credentials live in auth files.
type ZCodeConfig struct {
	AppVersion    string `yaml:"app-version" json:"app-version"`
	CaptchaURL    string `yaml:"captcha-url" json:"captcha-url"`
	MaxConcurrent int    `yaml:"max-concurrent" json:"max-concurrent"`
	MinIntervalMS int    `yaml:"min-interval-ms" json:"min-interval-ms"`
	// StartPlanSystem is an operator-supplied gateway system prefix. It is applied
	// before payload rules and never replaces the caller's system instructions.
	StartPlanSystem string `yaml:"start-plan-system" json:"start-plan-system"`
}

func (c ZCodeConfig) Validate() error {
	if c.MaxConcurrent < 0 || c.MinIntervalMS < 0 {
		return fmt.Errorf("zcode: limits must be non-negative")
	}
	if c.CaptchaURL != "" {
		u, err := url.Parse(c.CaptchaURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("zcode: captcha-url must be an HTTP(S) origin without credentials, query or fragment")
		}
	}
	return nil
}
