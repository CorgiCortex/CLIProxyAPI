package workbuddy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	authStatePath = "/v2/plugin/auth/state"
	authTokenPath = "/v2/plugin/auth/token"
	refreshPath   = "/v2/plugin/auth/token/refresh"
	maxAuthBody   = 1 << 20
)

var ErrLoginPending = errors.New("workbuddy: browser authorization pending")

// AuthClient handles credential acquisition only. Chat and background tasks
// use separate transports and contexts without acquisition deadlines.
type AuthClient struct {
	Transports *Transports
	Versions   IdentityVersions
	ProxyURL   string
	// BaseURL is an explicit upstream override, primarily for offline fixtures.
	BaseURL string
	Now     func() time.Time
}

type LoginSession struct {
	State     string
	AuthURL   string
	Realm     Realm
	Product   Product
	CreatedAt time.Time
}

type authEnvelope struct {
	Code *int            `json:"code"`
	Data json.RawMessage `json:"data"`
}

type tokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    int64  `json:"expiresAt"`
	Domain       string `json:"domain"`
	EnterpriseID string `json:"enterpriseId"`
}

func (a *AuthClient) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *AuthClient) base(realm Realm) (string, error) {
	base, _, errEndpoint := Endpoint(realm, Desktop)
	if errEndpoint != nil {
		return "", errEndpoint
	}
	if a.BaseURL != "" {
		if err := validateBaseURL(a.BaseURL); err != nil {
			return "", err
		}
		base = a.BaseURL
	}
	return base, nil
}

func (a *AuthClient) headers(realm Realm) http.Header {
	origin, version := "https://www.workbuddy.ai", a.Versions.DesktopIntl
	if realm == China {
		origin, version = "https://www.codebuddy.cn", a.Versions.DesktopCN
	}
	return http.Header{
		"Content-Type":     {"application/json"},
		"Accept":           {"application/json, text/plain, */*"},
		"X-Requested-With": {"XMLHttpRequest"},
		"User-Agent":       {"WorkBuddy/" + version},
		"Origin":           {origin},
		"Referer":          {origin + "/"},
	}
}

func (a *AuthClient) call(ctx context.Context, c Credential, method, path string, headers http.Header) (authEnvelope, error) {
	base, errBase := a.base(c.Realm)
	if errBase != nil {
		return authEnvelope{}, errBase
	}
	if a.Transports == nil {
		return authEnvelope{}, fmt.Errorf("workbuddy: auth transports not configured")
	}
	proxyURL := a.ProxyURL
	if c.ProxyURL != "" {
		proxyURL = c.ProxyURL
	}
	client, errClient := a.Transports.Client(c, base, proxyURL, nil)
	if errClient != nil {
		return authEnvelope{}, errClient
	}
	acquisitionCtx, cancelAcquisition := context.WithTimeout(ctx, 30*time.Second)
	defer cancelAcquisition()
	var body io.Reader
	if method == http.MethodPost {
		body = bytes.NewReader([]byte("{}"))
	}
	req, errRequest := http.NewRequestWithContext(acquisitionCtx, method, base+path, body)
	if errRequest != nil {
		return authEnvelope{}, fmt.Errorf("workbuddy: create auth request")
	}
	req.Header = headers
	resp, errDo := client.Do(req)
	if errDo != nil {
		// url.Error includes the OAuth state query. Return its cause only.
		var urlError *url.Error
		if errors.As(errDo, &urlError) {
			errDo = urlError.Err
		}
		return authEnvelope{}, fmt.Errorf("workbuddy: auth transport: %w", errDo)
	}
	raw, errRead := io.ReadAll(io.LimitReader(resp.Body, maxAuthBody+1))
	errClose := resp.Body.Close()
	if errRead != nil || errClose != nil {
		return authEnvelope{}, fmt.Errorf("workbuddy: read auth response: %w", errors.Join(errRead, errClose))
	}
	if resp.StatusCode != http.StatusOK {
		return authEnvelope{}, fmt.Errorf("workbuddy: auth HTTP status %d", resp.StatusCode)
	}
	if len(raw) > maxAuthBody {
		return authEnvelope{}, fmt.Errorf("workbuddy: auth response too large")
	}
	var payload authEnvelope
	if err := json.Unmarshal(raw, &payload); err != nil || payload.Code == nil {
		return authEnvelope{}, fmt.Errorf("workbuddy: invalid auth response")
	}
	return payload, nil
}

func (a *AuthClient) Start(ctx context.Context, realm Realm, product Product) (LoginSession, error) {
	if _, _, err := Endpoint(realm, product); err != nil {
		return LoginSession{}, err
	}
	c := Credential{Realm: realm, Product: product}
	payload, errCall := a.call(ctx, c, http.MethodPost, authStatePath+"?platform=CLI", a.headers(realm))
	if errCall != nil {
		return LoginSession{}, errCall
	}
	var data struct {
		State   string `json:"state"`
		AuthURL string `json:"authUrl"`
	}
	if *payload.Code != 0 || json.Unmarshal(payload.Data, &data) != nil || data.State == "" || data.AuthURL == "" {
		return LoginSession{}, fmt.Errorf("workbuddy: auth state response missing state or authorization URL (code %d)", *payload.Code)
	}
	authURL, errURL := url.Parse(data.AuthURL)
	if errURL != nil || authURL.Scheme != "https" || authURL.Hostname() == "" || authURL.User != nil {
		return LoginSession{}, fmt.Errorf("workbuddy: invalid authorization URL")
	}
	return LoginSession{State: data.State, AuthURL: data.AuthURL, Realm: realm, Product: product, CreatedAt: a.now()}, nil
}

func (a *AuthClient) Poll(ctx context.Context, session LoginSession) (Credential, error) {
	if session.State == "" || session.CreatedAt.IsZero() || !a.now().Before(session.CreatedAt.Add(10*time.Minute)) {
		return Credential{}, fmt.Errorf("workbuddy: login session expired or invalid")
	}
	c := Credential{Type: "workbuddy", Realm: session.Realm, Product: session.Product, ProxyURL: a.ProxyURL}
	payload, errCall := a.call(ctx, c, http.MethodGet, authTokenPath+"?state="+url.QueryEscape(session.State), a.headers(session.Realm))
	if errCall != nil {
		return Credential{}, errCall
	}
	if *payload.Code == 11217 {
		return Credential{}, ErrLoginPending
	}
	if *payload.Code != 0 {
		return Credential{}, fmt.Errorf("workbuddy: login rejected (code %d)", *payload.Code)
	}
	return decodeTokenResponse(c, payload.Data)
}

func decodeTokenResponse(c Credential, raw json.RawMessage) (Credential, error) {
	var data tokenResponse
	if err := json.Unmarshal(raw, &data); err != nil {
		return Credential{}, fmt.Errorf("workbuddy: invalid token response")
	}
	if data.AccessToken == "" {
		return Credential{}, fmt.Errorf("workbuddy: token response missing access token")
	}
	claims, errClaims := ParseTokenClaims(data.AccessToken)
	if errClaims != nil {
		return Credential{}, errClaims
	}
	if c.UID != "" && claims.Subject != c.UID {
		return Credential{}, fmt.Errorf("workbuddy: refreshed token subject changed")
	}
	c.UID, c.AccessToken, c.ExpiresAt = claims.Subject, data.AccessToken, claims.Expires
	if data.ExpiresAt > 0 {
		c.ExpiresAt = data.ExpiresAt
		if c.ExpiresAt > 1e11 {
			c.ExpiresAt /= 1000
		}
	}
	if data.RefreshToken != "" {
		c.RefreshToken = data.RefreshToken
	}
	if data.Domain != "" {
		c.Domain = data.Domain
	}
	if data.EnterpriseID != "" {
		c.EnterpriseID = data.EnterpriseID
	} else if claims.EnterpriseID != "" {
		c.EnterpriseID = claims.EnterpriseID
	}
	return c, c.Validate()
}

func (a *AuthClient) Refresh(ctx context.Context, c Credential) (Credential, error) {
	if err := c.Validate(); err != nil {
		return Credential{}, err
	}
	if c.RefreshToken == "" {
		return Credential{}, fmt.Errorf("workbuddy: no refresh token; sign in again")
	}
	headers := a.headers(c.Realm)
	headers.Set("X-Refresh-Token", c.RefreshToken)
	source, language := "plugin", "en-US"
	if c.Realm == China {
		source, language = "workbuddy", "zh-CN"
	}
	headers.Set("X-Auth-Refresh-Source", source)
	headers.Set("X-User-Id", c.UID)
	_, domain, errEndpoint := Endpoint(c.Realm, Desktop)
	if errEndpoint != nil {
		return Credential{}, errEndpoint
	}
	if c.Domain != "" {
		domain = c.Domain
	}
	headers.Set("X-Domain", domain)
	headers.Set("X-CodeBuddy-Request", "1")
	headers.Set("Accept-Language", language)
	if c.EnterpriseID != "" {
		headers.Set("X-Enterprise-Id", c.EnterpriseID)
	}
	payload, errCall := a.call(ctx, c, http.MethodPost, refreshPath, headers)
	if errCall != nil {
		return Credential{}, errCall
	}
	if *payload.Code != 0 {
		return Credential{}, fmt.Errorf("workbuddy: refresh rejected (code %d)", *payload.Code)
	}
	// Both response envelopes are observed at this endpoint.
	var nested struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(payload.Data, &nested); err != nil {
		return Credential{}, fmt.Errorf("workbuddy: invalid refresh response")
	}
	raw := payload.Data
	if len(nested.Data) > 0 && string(nested.Data) != "null" {
		raw = nested.Data
	}
	return decodeTokenResponse(c, raw)
}

// RefreshGate serializes rotating refresh tokens per credential. A waiting
// request re-reads the credential after the winner has durably saved it.
type RefreshGate struct {
	mu    sync.Mutex
	locks map[string]*refreshLock
}

type refreshLock struct {
	ch         chan struct{}
	refs       int
	pending    *Credential
	oldAccess  string
	oldRefresh string
}

func (g *RefreshGate) Run(ctx context.Context, key, observedToken string, load func() (Credential, error), save func(Credential) error, client *AuthClient) (Credential, error) {
	g.mu.Lock()
	if g.locks == nil {
		g.locks = make(map[string]*refreshLock)
	}
	lock := g.locks[key]
	if lock == nil {
		lock = &refreshLock{ch: make(chan struct{}, 1)}
		g.locks[key] = lock
	}
	lock.refs++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		lock.refs--
		if lock.refs == 0 && lock.pending == nil {
			delete(g.locks, key)
		}
	}()
	select {
	case lock.ch <- struct{}{}:
		defer func() { <-lock.ch }()
	case <-ctx.Done():
		return Credential{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	current, errLoad := load()
	if errLoad != nil {
		return Credential{}, errLoad
	}
	if lock.pending != nil {
		if current.AccessToken == lock.oldAccess && current.RefreshToken == lock.oldRefresh {
			if errSave := save(*lock.pending); errSave != nil {
				return Credential{}, fmt.Errorf("workbuddy: persist pending token rotation: %w", errSave)
			}
			current = *lock.pending
		}
		g.mu.Lock()
		lock.pending = nil
		g.mu.Unlock()
		lock.oldAccess, lock.oldRefresh = "", ""
	}
	if current.AccessToken != observedToken && !current.Expiring(client.now()) {
		return current, nil
	}
	refreshed, errRefresh := client.Refresh(ctx, current)
	if errRefresh != nil {
		return Credential{}, errRefresh
	}
	if errSave := save(refreshed); errSave != nil {
		// A rotating token may already have been consumed upstream. Preserve the
		// new pair for a later persistence attempt instead of replaying the old
		// refresh token. Process crashes still require explicit reauthorization.
		g.mu.Lock()
		lock.pending = &refreshed
		g.mu.Unlock()
		lock.oldAccess, lock.oldRefresh = current.AccessToken, current.RefreshToken
		return Credential{}, fmt.Errorf("workbuddy: persist refreshed credential: %w", errSave)
	}
	return refreshed, nil
}
