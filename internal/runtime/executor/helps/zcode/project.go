package zcode

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	zcodeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/zcode"
	"golang.org/x/sync/singleflight"
)

type projectToken struct {
	value   string
	expires time.Time
}
type ProjectTokens struct {
	mu     sync.Mutex
	values map[string]projectToken
	group  singleflight.Group
}

func NewProjectTokens() *ProjectTokens { return &ProjectTokens{values: make(map[string]projectToken)} }

func (p *ProjectTokens) Resolve(ctx context.Context, client *http.Client, account string, c Credential, version string) (string, error) {
	if c.Family != "bigmodel" || c.OAuthAccessToken == "" {
		return c.APIKey, nil
	}
	key := signingCacheKey(account, c.Family, c.APIKey+"\n"+c.OAuthAccessToken)
	result := p.group.DoChan(key, func() (any, error) {
		p.mu.Lock()
		now := time.Now()
		for k, cached := range p.values {
			if !cached.expires.After(now.Add(5 * time.Minute)) {
				delete(p.values, k)
			}
		}
		cached, ok := p.values[key]
		p.mu.Unlock()
		if ok {
			return cached.value, nil
		}
		ctxMint, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		apiKeyID, _, found := strings.Cut(c.APIKey, ".")
		if !found {
			return nil, fmt.Errorf("zcode: BigModel API key has no secret")
		}
		authClient := &zcodeauth.Client{HTTP: client}
		token, err := authClient.ProjectToken(ctxMint, c.OAuthAccessToken, apiKeyID, version)
		if err != nil {
			return nil, err
		}
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			return nil, fmt.Errorf("zcode: invalid project token")
		}
		data, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("zcode: invalid project token encoding")
		}
		var claims struct {
			Exp int64  `json:"exp"`
			Key string `json:"api_key"`
			Use string `json:"token_use"`
		}
		if json.Unmarshal(data, &claims) != nil || claims.Exp <= now.Add(5*time.Minute).Unix() || claims.Key != apiKeyID || claims.Use != "project_access" {
			return nil, fmt.Errorf("zcode: invalid project token claims")
		}
		p.mu.Lock()
		p.values[key] = projectToken{value: token, expires: time.Unix(claims.Exp, 0)}
		p.mu.Unlock()
		return token, nil
	})
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case value := <-result:
		if value.Err != nil {
			return "", value.Err
		}
		return value.Val.(string), nil
	}
}
