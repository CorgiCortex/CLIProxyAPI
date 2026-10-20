package zcode

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLoginFlowBothFamilies(t *testing.T) {
	for _, family := range []string{"zai", "bigmodel"} {
		t.Run(family, func(t *testing.T) {
			calls := 0
			client := &Client{Origin: "https://zcode.z.ai", HTTP: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("Authorization") != "Bearer poll-token" {
					t.Fatal("poll credential not preserved")
				}
				body := `{"code":0,"data":{"status":"ready","token":"zcode-jwt","zai":{"access_token":"zai-token"},"bigmodel":{"access_token":"bigmodel-token"},"user":{"user_id":"u"}}}`
				if calls == 1 {
					if r.Method != "POST" {
						t.Fatal("init must POST")
					}
					var input map[string]string
					if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
						t.Fatal(err)
					}
					if input["provider"] != family {
						t.Fatal("family mismatch")
					}
					body = `{"code":0,"data":{"flow_id":"flow","authorize_url":"https://zcode.z.ai/auth","expires_at":9999999999,"poll_interval_sec":2}}`
				} else if r.URL.Path != "/api/v1/oauth/cli/poll/flow" {
					t.Fatal("unexpected poll route")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			flow, err := client.Init(context.Background(), family, "poll-token")
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Poll(context.Background(), flow.ID, "poll-token")
			if err != nil || result.Status != "ready" || result.Token != "zcode-jwt" {
				t.Fatalf("bad poll: %+v %v", result, err)
			}
		})
	}
}

func TestCredentialResponseErrorsNeverExposeSecrets(t *testing.T) {
	client := &Client{HTTP: &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"token":"secret"}`))}, nil
	})}}
	var result map[string]any
	err := client.Request(context.Background(), "GET", "https://api.z.ai/test", "Bearer secret", nil, &result)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe error: %v", err)
	}
}
