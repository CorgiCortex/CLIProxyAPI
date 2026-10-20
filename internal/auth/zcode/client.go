// Package zcode implements the server-mediated ZCode CLI login protocol.
package zcode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
)

type Client struct {
	HTTP   *http.Client
	Origin string
}

type Flow struct {
	ID           string `json:"flow_id"`
	AuthorizeURL string `json:"authorize_url"`
	ExpiresAt    int64  `json:"expires_at"`
	PollInterval int    `json:"poll_interval_sec"`
}

type PollResult struct {
	Status string `json:"status"`
	Token  string `json:"token"`
	ZAI    struct {
		AccessToken string `json:"access_token"`
	} `json:"zai"`
	BigModel struct {
		AccessToken string `json:"access_token"`
	} `json:"bigmodel"`
	User struct {
		ID string `json:"user_id"`
	} `json:"user"`
}

// Request rejects malformed business responses without logging their credential-bearing bodies.
func (c *Client) Request(ctx context.Context, method, target, authorization string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	client := *c.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("zcode: credential request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.WithError(errClose).Warn("zcode: close credential response")
		}
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("zcode: credential request HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		Code json.RawMessage `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&envelope); err != nil {
		return fmt.Errorf("zcode: invalid credential response: %w", err)
	}
	code := strings.Trim(string(envelope.Code), `"`)
	if code != "0" && code != "200" {
		return fmt.Errorf("zcode: credential request rejected")
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return fmt.Errorf("zcode: credential response missing data")
	}
	if err = json.Unmarshal(envelope.Data, output); err != nil {
		return fmt.Errorf("zcode: credential response data: %w", err)
	}
	return nil
}

func (c *Client) Init(ctx context.Context, family, pollToken string) (Flow, error) {
	var flow Flow
	if family != "zai" && family != "bigmodel" {
		return flow, fmt.Errorf("zcode: invalid login family")
	}
	err := c.Request(ctx, "POST", c.Origin+"/api/v1/oauth/cli/init", "Bearer "+pollToken, map[string]string{"provider": family}, &flow)
	if err != nil {
		return flow, err
	}
	u, err := url.Parse(flow.AuthorizeURL)
	if err != nil || u.Scheme != "https" || u.User != nil || flow.ID == "" || flow.ExpiresAt <= 0 || flow.PollInterval <= 0 {
		return flow, fmt.Errorf("zcode: invalid login flow")
	}
	switch u.Hostname() {
	case "zcode.z.ai", "z.ai", "api.z.ai", "bigmodel.cn", "open.bigmodel.cn":
	default:
		return flow, fmt.Errorf("zcode: untrusted authorization origin")
	}
	return flow, nil
}

func (c *Client) Poll(ctx context.Context, flowID, token string) (PollResult, error) {
	var out PollResult
	err := c.Request(ctx, "GET", c.Origin+"/api/v1/oauth/cli/poll/"+url.PathEscape(flowID), "Bearer "+token, nil, &out)
	return out, err
}

type customerInfo struct {
	Organizations []struct {
		ID       string `json:"organizationId"`
		Name     string `json:"organizationName"`
		Projects []struct {
			ID   string          `json:"projectId"`
			Name string          `json:"projectName"`
			Type json.RawMessage `json:"projectType"`
		} `json:"projects"`
	} `json:"organizations"`
}

func (c *Client) project(ctx context.Context, host, authorization string) (string, string, error) {
	var info customerInfo
	if err := c.Request(ctx, "GET", host+"/api/biz/customer/getCustomerInfo", authorization, nil, &info); err != nil {
		return "", "", err
	}
	var orgID, projectID string
	for _, org := range info.Organizations {
		if org.ID == "" {
			continue
		}
		var selected string
		for _, p := range org.Projects {
			if p.ID == "" || strings.Trim(string(p.Type), `"`) == "2" {
				continue
			}
			if selected == "" || strings.Contains(p.Name, "\u9ed8\u8ba4\u9879\u76ee") {
				selected = p.ID
			}
		}
		if selected != "" && (orgID == "" || strings.Contains(org.Name, "\u9ed8\u8ba4\u673a\u6784")) {
			orgID, projectID = org.ID, selected
		}
	}
	if orgID == "" || projectID == "" {
		return "", "", fmt.Errorf("zcode: no eligible organization/project")
	}
	return orgID, projectID, nil
}

// ResolveKey explicitly provisions or reuses the dedicated ZCode API key during login.
func (c *Client) ResolveKey(ctx context.Context, family, token string) (string, error) {
	host, authorization := "https://bigmodel.cn", token
	if family == "zai" {
		host = "https://api.z.ai"
		var login struct {
			AccessToken      string `json:"access_token"`
			AccessTokenCamel string `json:"accessToken"`
		}
		if err := c.Request(ctx, "POST", host+"/api/auth/z/login", "", map[string]string{"token": token}, &login); err != nil {
			return "", err
		}
		biz := login.AccessToken
		if biz == "" {
			biz = login.AccessTokenCamel
		}
		if biz == "" {
			return "", fmt.Errorf("zcode: missing business token")
		}
		authorization = "Bearer " + biz
	}
	orgID, projectID, err := c.project(ctx, host, authorization)
	if err != nil {
		return "", err
	}
	endpoint := host + "/api/biz/v1/organization/" + url.PathEscape(orgID) + "/projects/" + url.PathEscape(projectID) + "/api_keys"
	type apiKey struct {
		Key  string `json:"apiKey"`
		Name string `json:"name"`
	}
	var keys []apiKey
	if err = c.Request(ctx, "GET", endpoint, authorization, nil, &keys); err != nil {
		return "", err
	}
	var key string
	for _, candidate := range keys {
		if candidate.Name == "zcode-api-key" && candidate.Key != "" {
			key = candidate.Key
			break
		}
	}
	if key == "" {
		var created apiKey
		if err = c.Request(ctx, "POST", endpoint, authorization, map[string]string{"name": "zcode-api-key"}, &created); err != nil {
			return "", err
		}
		key = created.Key
	}
	if key == "" {
		return "", fmt.Errorf("zcode: missing API key")
	}
	var copied struct {
		Secret string `json:"secretKey"`
	}
	if err = c.Request(ctx, "GET", endpoint+"/copy/"+url.PathEscape(key), authorization, nil, &copied); err != nil {
		return "", err
	}
	if copied.Secret == "" {
		return "", fmt.Errorf("zcode: missing API key secret")
	}
	return key + "." + copied.Secret, nil
}

func (c *Client) ProjectToken(ctx context.Context, oauthToken, apiKeyID, version string) (string, error) {
	const host = "https://bigmodel.cn"
	token := strings.TrimPrefix(oauthToken, "Bearer ")
	orgID, projectID, err := c.project(ctx, host, token)
	if err != nil {
		return "", err
	}
	var result struct {
		AccessToken string `json:"accessToken"`
	}
	endpoint := host + "/api/biz/v1/organization/" + url.PathEscape(orgID) + "/projects/" + url.PathEscape(projectID) + "/api_keys/" + url.PathEscape(apiKeyID) + "/access_tokens"
	err = c.Request(ctx, "POST", endpoint, "Bearer "+token, map[string]string{"clientType": "zcode", "clientVersion": version}, &result)
	if err != nil {
		return "", err
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("zcode: missing project access token")
	}
	return result.AccessToken, nil
}
