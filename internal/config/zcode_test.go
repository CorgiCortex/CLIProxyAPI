package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestZCodeV8ConfigurationRoundTrip(t *testing.T) {
	input := []byte("upstream:\n  zcode:\n    app-version: 3.16.2\n    captcha-url: http://127.0.0.1:8318\n    max-concurrent: 2\n    min-interval-ms: 1500\n")
	var cfg Config
	if err := yaml.Unmarshal(input, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ZCode.MaxConcurrent != 2 || cfg.ZCode.MinIntervalMS != 1500 {
		t.Fatalf("lost v8 fields: %+v", cfg.ZCode)
	}
	output, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip Config
	if err = yaml.Unmarshal(output, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if roundtrip.ZCode != cfg.ZCode || !strings.Contains(string(output), "zcode:") {
		t.Fatal("configuration failed round-trip")
	}
	for _, invalid := range []ZCodeConfig{{MaxConcurrent: -1}, {MinIntervalMS: -1}, {CaptchaURL: "https://user:password@example.test"}, {CaptchaURL: "file:///tmp/token"}} {
		if err = invalid.Validate(); err == nil {
			t.Fatalf("accepted unsafe config: %+v", invalid)
		}
	}
}
