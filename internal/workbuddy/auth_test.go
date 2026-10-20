package workbuddy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testJWT(subject string, expires int64, nonce string) string {
	raw, _ := json.Marshal(map[string]any{"sub": subject, "exp": expires, "nonce": nonce})
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(raw) + ".fixture"
}

func testCredential() Credential {
	return Credential{Type: "workbuddy", UID: "fixture-user", Realm: International, Product: Desktop,
		AccessToken: testJWT("fixture-user", 4102444800, "old"), RefreshToken: "old-refresh", ExpiresAt: 4102444800}
}

func TestOAuthPendingSuccessExpiryAndRedaction(t *testing.T) {
	now := time.Unix(1800000000, 0)
	token := testJWT("fixture-user", now.Add(time.Hour).Unix(), "login")
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case authStatePath:
			if r.Method != http.MethodPost || r.URL.Query().Get("platform") != "CLI" {
				t.Error("wrong login state request")
			}
			fmt.Fprint(w, `{"code":0,"data":{"state":"private/state","authUrl":"https://www.workbuddy.ai/login?state=private"}}`)
		case authTokenPath:
			if r.URL.Query().Get("state") != "private/state" {
				t.Error("state was not encoded correctly")
			}
			if polls.Add(1) == 1 {
				fmt.Fprint(w, `{"code":11217,"msg":"private-token-must-not-leak"}`)
			} else {
				json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{
					"accessToken": token, "refreshToken": "new-refresh", "expiresAt": now.Add(time.Hour).UnixMilli(),
				}})
			}
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	transports := NewTransports(8, nil)
	defer transports.CloseIdleConnections()
	client := &AuthClient{Transports: transports, Versions: DefaultVersions(), BaseURL: server.URL, Now: func() time.Time { return now }}
	session, errStart := client.Start(context.Background(), International, CLI)
	if errStart != nil {
		t.Fatal(errStart)
	}
	if _, err := client.Poll(context.Background(), session); !errors.Is(err, ErrLoginPending) {
		t.Fatalf("pending result: %v", err)
	}
	credential, errPoll := client.Poll(context.Background(), session)
	if errPoll != nil {
		t.Fatal(errPoll)
	}
	if credential.UID != "fixture-user" || credential.AccessToken != token || credential.ExpiresAt != now.Add(time.Hour).Unix() || credential.Product != CLI {
		t.Fatal("login credential does not match response")
	}
	now = now.Add(10 * time.Minute)
	if _, err := client.Poll(context.Background(), session); err == nil || polls.Load() != 2 {
		t.Fatal("expired login performed a network request")
	}
}

func TestRefreshRotatesOnceAcrossConcurrentRequests(t *testing.T) {
	now := time.Unix(1800000000, 0)
	current := testCredential()
	current.ExpiresAt = now.Unix()
	oldToken := current.AccessToken
	rotatedToken := testJWT(current.UID, now.Add(time.Hour).Unix(), "rotated")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != refreshPath || r.Header.Get("X-Refresh-Token") != "old-refresh" ||
			r.Header.Get("X-Auth-Refresh-Source") != "plugin" || r.Header.Get("Authorization") != "" {
			t.Error("invalid refresh request")
		}
		json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{"data": map[string]any{
			"accessToken": rotatedToken, "refreshToken": "rotated-refresh",
		}}})
	}))
	defer server.Close()
	transports := NewTransports(8, nil)
	defer transports.CloseIdleConnections()
	client := &AuthClient{Transports: transports, Versions: DefaultVersions(), BaseURL: server.URL, Now: func() time.Time { return now }}
	path := filepath.Join(t.TempDir(), "credential.json")
	if err := WriteJSON(path, current); err != nil {
		t.Fatal(err)
	}
	var gate RefreshGate
	var saves atomic.Int32
	load := func() (Credential, error) {
		raw, errRead := os.ReadFile(path)
		if errRead != nil {
			return Credential{}, errRead
		}
		return DecodeCredential(raw)
	}
	save := func(c Credential) error {
		saves.Add(1)
		return WriteJSON(path, c)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			c, err := gate.Run(context.Background(), "account-id", oldToken, load, save, client)
			if err != nil {
				t.Error(err)
			} else if c.AccessToken != rotatedToken || c.RefreshToken != "rotated-refresh" {
				t.Error("waiter did not receive rotated tokens")
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 || saves.Load() != 1 {
		t.Fatalf("refreshes=%d saves=%d, want 1 each", calls.Load(), saves.Load())
	}
	info, errStat := os.Stat(path)
	if errStat != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credential permissions are not private")
	}
	if len(gate.locks) != 0 {
		t.Fatal("refresh lock leaked")
	}
}

func TestAuthRejectsRedirectsAndUntrustedResponses(t *testing.T) {
	for _, fixture := range []struct {
		name   string
		status int
		body   string
	}{
		{"redirect", 302, ""},
		{"unauthorized", 401, "private-refresh-secret"},
		{"invalid_json", 200, `{"accessToken":"private-refresh-secret"`},
		{"missing_code", 200, `{"data":{"accessToken":"private-refresh-secret"}}`},
		{"wrong_subject", 200, fmt.Sprintf(`{"code":0,"data":{"accessToken":%q}}`, testJWT("other-user", 4102444800, ""))},
		{"oversize", 200, strings.Repeat("private-refresh-secret", maxAuthBody)},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/must-not-follow")
				w.WriteHeader(fixture.status)
				fmt.Fprint(w, fixture.body)
			}))
			defer server.Close()
			transports := NewTransports(8, nil)
			defer transports.CloseIdleConnections()
			client := &AuthClient{Transports: transports, Versions: DefaultVersions(), BaseURL: server.URL}
			_, err := client.Refresh(context.Background(), testCredential())
			if err == nil || strings.Contains(err.Error(), "private-refresh-secret") {
				t.Fatalf("expected sanitized error, got %v", err)
			}
			if calls.Load() != 1 {
				t.Fatal("auth request followed redirect or retried")
			}
		})
	}
}

func TestRefreshGateCanceledWaiterDoesNotRefresh(t *testing.T) {
	var gate RefreshGate
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := gate.Run(ctx, "account-id", "", func() (Credential, error) {
		t.Error("canceled caller loaded credentials")
		return Credential{}, nil
	}, nil, nil)
	if !errors.Is(err, context.Canceled) || len(gate.locks) != 0 {
		t.Fatalf("cancellation did not release lock: %v", err)
	}
}

func TestRefreshPersistenceFailureDoesNotReplayConsumedToken(t *testing.T) {
	current := testCredential()
	observedToken := current.AccessToken
	rotated := testJWT(current.UID, 4102444800, "recovered")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{"accessToken": rotated, "refreshToken": "consumed-once"}})
	}))
	defer server.Close()
	pools := NewTransports(4, nil)
	defer pools.CloseIdleConnections()
	client := &AuthClient{Transports: pools, Versions: DefaultVersions(), BaseURL: server.URL}
	var gate RefreshGate
	failSave := true
	load := func() (Credential, error) { return current, nil }
	save := func(c Credential) error {
		if failSave {
			return errors.New("fixture disk failure")
		}
		current = c
		return nil
	}
	if _, err := gate.Run(context.Background(), "account", observedToken, load, save, client); err == nil {
		t.Fatal("persistence failure was hidden")
	}
	failSave = false
	result, err := gate.Run(context.Background(), "account", observedToken, load, save, client)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || result.AccessToken != rotated || current.RefreshToken != "consumed-once" || len(gate.locks) != 0 {
		t.Fatal("rotation recovery replayed a token or lost the pending credential")
	}
}
