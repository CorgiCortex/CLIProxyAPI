package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/workbuddy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

type WorkBuddyAuthenticator struct {
	Client *workbuddy.AuthClient
}

func NewWorkBuddyAuthenticator() *WorkBuddyAuthenticator { return &WorkBuddyAuthenticator{} }
func (*WorkBuddyAuthenticator) Provider() string         { return "workbuddy" }
func (*WorkBuddyAuthenticator) RefreshLead() *time.Duration {
	lead := 2 * time.Minute
	return &lead
}

func (a *WorkBuddyAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("workbuddy: configuration is required")
	}
	if opts == nil {
		opts = &LoginOptions{}
	}
	realm, product := workbuddy.International, workbuddy.Desktop
	if value := opts.Metadata["realm"]; value != "" {
		realm = workbuddy.Realm(value)
	}
	if value := opts.Metadata["product"]; value != "" {
		product = workbuddy.Product(value)
	}
	client := a.Client
	if client == nil {
		pools := workbuddy.NewTransports(4, nil)
		defer pools.CloseIdleConnections()
		client = &workbuddy.AuthClient{Transports: pools, Versions: workbuddy.DefaultVersions(), ProxyURL: cfg.ProxyURL}
	}
	acquisitionCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	session, errStart := client.Start(acquisitionCtx, realm, product)
	if errStart != nil {
		return nil, errStart
	}
	fmt.Printf("Open this URL to authorize WorkBuddy:\n%s\n", session.AuthURL)
	if !opts.NoBrowser && browser.IsAvailable() {
		if errOpen := browser.OpenURL(session.AuthURL); errOpen != nil {
			log.Warn("WorkBuddy browser could not be opened; use the printed authorization URL")
		}
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-acquisitionCtx.Done():
			return nil, acquisitionCtx.Err()
		case <-ticker.C:
			credential, errPoll := client.Poll(acquisitionCtx, session)
			if errors.Is(errPoll, workbuddy.ErrLoginPending) {
				continue
			}
			if errPoll != nil {
				return nil, errPoll
			}
			return WorkBuddyAuthRecord(credential)
		}
	}
}

func WorkBuddyAuthRecord(credential workbuddy.Credential) (*coreauth.Auth, error) {
	if err := credential.Validate(); err != nil {
		return nil, err
	}
	raw, errMarshal := json.Marshal(credential)
	if errMarshal != nil {
		return nil, fmt.Errorf("workbuddy: encode credential: %w", errMarshal)
	}
	var metadata map[string]any
	if errDecode := json.Unmarshal(raw, &metadata); errDecode != nil {
		return nil, errDecode
	}
	sum := sha256.Sum256([]byte(credential.UID + "\x00" + credential.EnterpriseID))
	filename := "workbuddy-" + string(credential.Realm) + "-" + hex.EncodeToString(sum[:16]) + ".json"
	status := coreauth.StatusActive
	if credential.Disabled {
		status = coreauth.StatusDisabled
	}
	now := time.Now()
	return &coreauth.Auth{
		ID: filename, FileName: filename, Provider: "workbuddy", Label: "WorkBuddy " + string(credential.Realm),
		Metadata: metadata, ProxyURL: credential.ProxyURL, Prefix: credential.Prefix,
		Disabled: credential.Disabled, Status: status, CreatedAt: now, UpdatedAt: now, LastRefreshedAt: now,
	}, nil
}
