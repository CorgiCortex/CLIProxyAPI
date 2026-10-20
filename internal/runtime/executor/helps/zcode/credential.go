// Package zcode implements ZCode transport support without owning account selection.
package zcode

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// Credential is the explicit on-disk ZCode account contract.
type Credential struct {
	Family           string              `json:"family"`
	Plan             string              `json:"plan"`
	JWT              string              `json:"jwt"`
	APIKey           string              `json:"api_key"`
	OAuthAccessToken string              `json:"oauth_access_token,omitempty"`
	DeviceID         string              `json:"device_id"`
	Models           []config.CodexModel `json:"models"`
}

func ReadCredential(auth *coreauth.Auth) (Credential, error) {
	var c Credential
	if auth == nil {
		return c, fmt.Errorf("zcode: missing account")
	}
	data, err := json.Marshal(auth.Metadata)
	if err != nil {
		return c, fmt.Errorf("zcode: encode account metadata: %w", err)
	}
	if err = json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("zcode: decode account metadata: %w", err)
	}
	if c.Family != "zai" && c.Family != "bigmodel" {
		return c, fmt.Errorf("zcode: family must be zai or bigmodel")
	}
	switch c.Plan {
	case "start-plan":
		if strings.TrimSpace(c.JWT) == "" {
			return c, fmt.Errorf("zcode: start-plan requires jwt")
		}
	case "coding-plan":
		if strings.TrimSpace(c.APIKey) == "" {
			return c, fmt.Errorf("zcode: coding-plan requires api_key")
		}
	default:
		return c, fmt.Errorf("zcode: plan must be start-plan or coding-plan")
	}
	return c, nil
}

func (c Credential) Endpoint() string {
	if c.Plan == "start-plan" {
		return "https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages"
	}
	if c.Family == "bigmodel" {
		return "https://open.bigmodel.cn/api/anthropic/v1/messages"
	}
	return "https://api.z.ai/api/anthropic/v1/messages"
}

// AllowedTarget prevents credential forwarding to arbitrary URLs or redirects.
func AllowedTarget(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	switch u.Hostname() {
	case "zcode.z.ai", "api.z.ai", "open.bigmodel.cn", "bigmodel.cn":
		return true
	}
	return false
}
