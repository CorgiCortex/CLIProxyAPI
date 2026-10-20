package auth_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/workbuddy"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
)

func TestWorkBuddyCredentialRoundtripAndRejectedReplacement(t *testing.T) {
	c := workbuddy.Credential{Type: "workbuddy", UID: "fixture-user", Realm: workbuddy.International, Product: workbuddy.CLI,
		AccessToken: "fixture-token", RefreshToken: "fixture-refresh", ProxyURL: "direct", ExpiresAt: 4102444800, Models: []string{"fixture-model"}}
	record, errRecord := sdkAuth.WorkBuddyAuthRecord(c)
	if errRecord != nil {
		t.Fatal(errRecord)
	}
	record.Metadata["note"] = "retained metadata"
	store := sdkAuth.NewFileTokenStore()
	dir := t.TempDir()
	store.SetBaseDir(dir)
	path, errSave := store.Save(context.Background(), record)
	if errSave != nil {
		t.Fatal(errSave)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	entries, errSynth := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{AuthDir: dir, Now: time.Now(), StrictFileParsing: true}, path, raw)
	if errSynth != nil || len(entries) != 1 {
		t.Fatalf("synthesis failed: %v count=%d", errSynth, len(entries))
	}
	loaded := entries[0]
	if loaded.Provider != "workbuddy" || loaded.ProxyURL != "direct" || loaded.Metadata["refresh_token"] != "fixture-refresh" ||
		loaded.Metadata["note"] != "retained metadata" || loaded.ID != filepath.Base(path) {
		t.Fatal("credential metadata was lost")
	}
	loaded.Metadata["access_token"] = "rotated-fixture"
	if _, err := store.Save(context.Background(), loaded); err != nil {
		t.Fatal(err)
	}
	validRaw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	delete(loaded.Metadata, "uid")
	if _, err := store.Save(context.Background(), loaded); err == nil {
		t.Fatal("malformed credential overwrote valid file")
	}
	after, errRead := os.ReadFile(path)
	if errRead != nil || string(after) != string(validRaw) {
		t.Fatal("failed save damaged valid credential")
	}
	var saved map[string]any
	if err := json.Unmarshal(after, &saved); err != nil {
		t.Fatal(err)
	}
	if saved["access_token"] != "rotated-fixture" {
		t.Fatal("rotation did not persist")
	}
	if _, err := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{AuthDir: dir, StrictFileParsing: true}, path, []byte(`{"type":"workbuddy","uid":"u","realm":"wrong","product":"cli","access_token":"x"}`)); err == nil {
		t.Fatal("watcher accepted invalid credential")
	}
}
