package cliproxy

import (
	"context"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/workbuddy"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
)

func TestWorkBuddyModelsRequireOptInAndRespectRealm(t *testing.T) {
	c := workbuddy.Credential{Type: "workbuddy", UID: "fixture-model-user", AccessToken: "fixture-only", Realm: workbuddy.China, Product: workbuddy.Desktop}
	a, err := sdkauth.WorkBuddyAuthRecord(c)
	if err != nil {
		t.Fatal(err)
	}
	registry := GlobalModelRegistry()
	t.Cleanup(func() { registry.UnregisterClient(a.ID) })
	cfg := &internalconfig.Config{}
	service := &Service{cfg: cfg}
	service.registerModelsForAuth(context.Background(), a)
	if len(registry.GetModelsForClient(a.ID)) != 0 {
		t.Fatal("disabled provider advertised models")
	}
	cfg.WorkBuddy.Enabled = true
	service.registerModelsForAuth(context.Background(), a)
	models := registry.GetModelsForClient(a.ID)
	if len(models) == 0 {
		t.Fatal("no CN fallback catalog")
	}
	for _, m := range models {
		if m.ID == "hy3" && (m.Thinking == nil || len(m.Thinking.Levels) == 0) {
			t.Fatal("catalog reasoning capabilities were lost")
		}
		if m.ID == "gpt-6-astra" {
			t.Fatal("CN catalog leaked intl model")
		}
	}
	a.Metadata["models"] = []string{"fixture-model"}
	service.registerModelsForAuth(context.Background(), a)
	models = registry.GetModelsForClient(a.ID)
	if len(models) != 1 || models[0].ID != "fixture-model" {
		t.Fatalf("explicit models = %+v", models)
	}
}
