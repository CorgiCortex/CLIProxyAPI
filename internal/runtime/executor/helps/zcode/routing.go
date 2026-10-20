package zcode

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type routeEntry struct {
	From      string `json:"from"`
	To        string `json:"to"`
	JWTHeader string `json:"zcodeAuthorizationHeader"`
}
type routeSnapshot struct {
	entries []routeEntry
	expires time.Time
}
type Routes struct {
	mu    sync.Mutex
	cache map[string]routeSnapshot
	group singleflight.Group
}

func NewRoutes() *Routes { return &Routes{cache: make(map[string]routeSnapshot)} }

func validateRoute(entry routeEntry) error {
	for _, raw := range []string{entry.From, entry.To} {
		u, err := url.Parse(raw)
		if err != nil || !AllowedTarget(u) || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || path.Clean(u.Path) != strings.TrimRight(u.Path, "/") {
			return fmt.Errorf("zcode: unsafe endpoint mapping")
		}
	}
	if entry.JWTHeader != "" {
		u, _ := url.Parse(entry.To)
		allowed := u.Hostname() == "zcode.z.ai" && (strings.HasPrefix(u.Path, "/api/v1/ultra/") || strings.HasPrefix(u.Path, "/api/v1/ultra-zai/"))
		if !strings.EqualFold(entry.JWTHeader, "X-ZCode-Authorization") || !allowed {
			return fmt.Errorf("zcode: unsafe JWT endpoint mapping")
		}
	}
	return nil
}

func (r *Routes) Resolve(ctx context.Context, client *http.Client, account string, c Credential, version string) (string, bool, error) {
	if c.Plan != "coding-plan" {
		return c.Endpoint(), false, nil
	}
	key := signingCacheKey(account, version, c.APIKey)
	result := r.group.DoChan(key, func() (any, error) {
		r.mu.Lock()
		now := time.Now()
		for k, value := range r.cache {
			if !value.expires.After(now) {
				delete(r.cache, k)
			}
		}
		cached, ok := r.cache[key]
		r.mu.Unlock()
		if ok {
			return cached, nil
		}
		req, err := http.NewRequestWithContext(ctx, "GET", "https://zcode.z.ai/api/v1/agent/configs", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Api-Key", c.APIKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "ZCode/"+version)
		req.Header.Set("X-ZCode-App-Version", version)
		if c.DeviceID != "" {
			req.Header.Set("X-Device-Mid", c.DeviceID)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("zcode: endpoint configuration unavailable: %w", err)
		}
		defer closeBody(resp.Body)
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("zcode: endpoint configuration HTTP %d", resp.StatusCode)
		}
		var envelope struct {
			Code *int `json:"code"`
			Data struct {
				ProxyEndpoint struct {
					Mapping []routeEntry `json:"mapping"`
				} `json:"proxyEndpoint"`
			} `json:"data"`
		}
		if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&envelope); err != nil {
			return nil, fmt.Errorf("zcode: invalid endpoint configuration: %w", err)
		}
		if envelope.Code == nil || *envelope.Code != 0 || len(envelope.Data.ProxyEndpoint.Mapping) > 256 {
			return nil, fmt.Errorf("zcode: rejected endpoint configuration")
		}
		seen := make(map[string]bool)
		for _, entry := range envelope.Data.ProxyEndpoint.Mapping {
			if err = validateRoute(entry); err != nil {
				return nil, err
			}
			from := strings.TrimRight(entry.From, "/")
			if seen[from] {
				return nil, fmt.Errorf("zcode: duplicate endpoint mapping")
			}
			seen[from] = true
		}
		snapshot := routeSnapshot{entries: envelope.Data.ProxyEndpoint.Mapping, expires: now.Add(5 * time.Minute)}
		r.mu.Lock()
		r.cache[key] = snapshot
		r.mu.Unlock()
		return snapshot, nil
	})
	select {
	case <-ctx.Done():
		return "", false, ctx.Err()
	case value := <-result:
		if value.Err != nil {
			return "", false, value.Err
		}
		for _, entry := range value.Val.(routeSnapshot).entries {
			if strings.TrimRight(entry.From, "/") == c.Endpoint() {
				if entry.JWTHeader != "" && c.JWT == "" {
					return "", false, fmt.Errorf("zcode: routed endpoint requires ZCode JWT; re-authenticate")
				}
				return entry.To, entry.JWTHeader != "", nil
			}
		}
		return c.Endpoint(), false, nil
	}
}
