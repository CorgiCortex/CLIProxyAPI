package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/workbuddy"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

func DoWorkBuddyLogin(cfg *config.Config, options *LoginOptions, realm, product string) {
	if options == nil {
		options = &LoginOptions{}
	}
	manager := newAuthManager()
	_, savedPath, errLogin := manager.Login(context.Background(), "workbuddy", cfg, &sdkAuth.LoginOptions{
		NoBrowser: options.NoBrowser,
		Metadata:  map[string]string{"realm": realm, "product": product},
	})
	if errLogin != nil {
		log.WithError(errLogin).Error("WorkBuddy authentication failed")
		return
	}
	fmt.Printf("WorkBuddy authentication saved to %s\n", savedPath)
}

// DoWorkBuddyImport reads only the explicitly supplied file. It never discovers
// desktop credentials or other providers' account directories.
func DoWorkBuddyImport(cfg *config.Config, path string) error {
	if cfg == nil || cfg.AuthDir == "" {
		return fmt.Errorf("workbuddy: auth directory is required")
	}
	file, errOpen := os.Open(path)
	if errOpen != nil {
		return fmt.Errorf("workbuddy: open import: %w", errOpen)
	}
	raw, errRead := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	errClose := file.Close()
	if errRead != nil || errClose != nil {
		return errors.Join(errRead, errClose)
	}
	if len(raw) > 1<<20 {
		return fmt.Errorf("workbuddy: credential import exceeds 1 MiB")
	}
	var kind struct {
		Type string `json:"type"`
	}
	if errDecode := json.Unmarshal(raw, &kind); errDecode != nil {
		return fmt.Errorf("workbuddy: invalid import JSON")
	}
	var credential workbuddy.Credential
	var errImport error
	switch kind.Type {
	case "workbuddy":
		credential, errImport = workbuddy.DecodeCredential(raw)
	case "":
		credential, errImport = workbuddy.ImportHubCredential(raw)
	default:
		return fmt.Errorf("workbuddy: import contains another provider's credential")
	}
	if errImport != nil {
		return errImport
	}
	record, errRecord := sdkAuth.WorkBuddyAuthRecord(credential)
	if errRecord != nil {
		return errRecord
	}
	store := sdkAuth.GetTokenStore()
	if setter, ok := store.(interface{ SetBaseDir(string) }); ok {
		setter.SetBaseDir(cfg.AuthDir)
	}
	savedPath, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record)
	if errSave != nil {
		return errSave
	}
	fmt.Printf("WorkBuddy credential imported to %s\n", savedPath)
	return nil
}
