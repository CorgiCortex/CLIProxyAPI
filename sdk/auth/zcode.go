package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	zcodeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/zcode"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

type ZCodeAuthenticator struct{}

func NewZCodeAuthenticator() *ZCodeAuthenticator        { return &ZCodeAuthenticator{} }
func (*ZCodeAuthenticator) Provider() string            { return "zcode" }
func (*ZCodeAuthenticator) RefreshLead() *time.Duration { return nil }

func (*ZCodeAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil || opts == nil {
		return nil, fmt.Errorf("zcode: config and login options are required")
	}
	family, plan := opts.Metadata["family"], opts.Metadata["plan"]
	if family == "" {
		family = "zai"
	}
	if plan == "" {
		plan = "start-plan"
	}
	if (family != "zai" && family != "bigmodel") || (plan != "start-plan" && plan != "coding-plan") {
		return nil, fmt.Errorf("zcode: invalid family or plan")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	pollToken := hex.EncodeToString(random)
	client := &zcodeauth.Client{Origin: "https://zcode.z.ai", HTTP: util.SetProxy(&cfg.SDKConfig, &http.Client{Timeout: 30 * time.Second})}
	flow, err := client.Init(ctx, family, pollToken)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Open this URL to authorize ZCode:\n%s\n", flow.AuthorizeURL)
	if !opts.NoBrowser {
		if errOpen := browser.OpenURL(flow.AuthorizeURL); errOpen != nil {
			log.WithError(errOpen).Warn("zcode: open the printed authorization URL manually")
		}
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(flow.ExpiresAt, 0))
	defer cancel()
	interval := time.Duration(flow.PollInterval) * time.Second
	if interval < time.Second {
		interval = time.Second
	}
	for {
		result, errPoll := client.Poll(ctx, flow.ID, pollToken)
		if errPoll != nil {
			return nil, errPoll
		}
		switch result.Status {
		case "pending":
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
			continue
		case "ready":
			if result.Token == "" {
				return nil, fmt.Errorf("zcode: login returned no ZCode JWT")
			}
			oauthToken := result.ZAI.AccessToken
			if family == "bigmodel" {
				oauthToken = result.BigModel.AccessToken
			}
			metadata := map[string]any{"type": "zcode", "family": family, "plan": plan, "jwt": result.Token, "device_id": uuid.NewString(), "user_id": result.User.ID, "models": []config.CodexModel{}}
			if plan == "coding-plan" {
				if oauthToken == "" {
					return nil, fmt.Errorf("zcode: login returned no provider OAuth token")
				}
				key, errKey := client.ResolveKey(ctx, family, oauthToken)
				if errKey != nil {
					return nil, errKey
				}
				metadata["api_key"] = key
				if family == "bigmodel" {
					metadata["oauth_access_token"] = oauthToken
				}
			}
			name := "zcode-" + family + "-" + plan + "-" + strings.ReplaceAll(uuid.NewString(), "-", "") + ".json"
			return &coreauth.Auth{ID: name, FileName: name, Provider: "zcode", Label: "ZCode " + family + " " + plan, Metadata: metadata, Status: coreauth.StatusActive}, nil
		case "failed":
			return nil, fmt.Errorf("zcode: authorization failed")
		default:
			return nil, fmt.Errorf("zcode: unexpected authorization status")
		}
	}
}
