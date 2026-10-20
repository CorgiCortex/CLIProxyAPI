package cliproxy

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestZCodeRegistersNativeExecutorAndOnlyConfiguredModels(t *testing.T) {
	cfg := &config.Config{}
	manager := coreauth.NewManager(nil, nil, nil)
	service := &Service{cfg: cfg, coreManager: manager}
	auth := &coreauth.Auth{ID: "zcode-" + uuid.NewString(), Provider: "zcode", Metadata: map[string]any{
		"family": "zai", "plan": "start-plan", "jwt": "test-only",
		"models": []map[string]string{{"name": "EXACT-MODEL", "alias": "zcode-test"}},
	}}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { GlobalModelRegistry().UnregisterClient(auth.ID) })
	service.ensureExecutorsForAuth(auth)
	registered, ok := manager.Executor("zcode")
	if !ok {
		t.Fatal("missing zcode executor")
	}
	if _, ok = registered.(*executor.ZCodeExecutor); !ok {
		t.Fatalf("not native: %T", registered)
	}
	service.ensureExecutorsForAuth(auth)
	again, _ := manager.Executor("zcode")
	if again != registered {
		t.Fatal("registering another account replaced live transport state")
	}
	if !service.registerModelsForAuth(context.Background(), auth) {
		t.Fatal("model registration rejected")
	}
	models := GlobalModelRegistry().GetModelsForClient(auth.ID)
	if len(models) != 1 || models[0].ID != "zcode-test" {
		t.Fatalf("unexpected models: %+v", models)
	}
	auth.Metadata["models"] = []any{}
	service.registerModelsForAuth(context.Background(), auth)
	if len(GlobalModelRegistry().GetModelsForClient(auth.ID)) != 0 {
		t.Fatal("empty configuration retained phantom models")
	}
}
