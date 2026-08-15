package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestFreebuffRequestLifecycle(t *testing.T) {
	var finished bool
	var chatBody struct {
		Messages         []map[string]any  `json:"messages"`
		CodebuffMetadata map[string]string `json:"codebuff_metadata"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/api/v1/freebuff/session":
			if r.Method == http.MethodGet {
				http.NotFound(w, r)
				return
			}
			if r.Header.Get("x-freebuff-model") != freebuffModel {
				t.Fatalf("x-freebuff-model = %q", r.Header.Get("x-freebuff-model"))
			}
			json.NewEncoder(w).Encode(freebuffSession{Status: "active", Model: freebuffModel, InstanceID: "instance-1"})
		case "/api/v1/agent-runs":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["action"] == "FINISH" {
				finished = true
				return
			}
			json.NewEncoder(w).Encode(freebuffRun{RunID: "run-1"})
		case "/api/v1/chat/completions":
			if err := json.NewDecoder(r.Body).Decode(&chatBody); err != nil {
				t.Fatal(err)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"id": "chat-1", "model": freebuffModel,
				"choices": []any{map[string]any{"index": 0, "message": map[string]string{"role": "assistant", "content": "pong"}, "finish_reason": "stop"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	executor := NewOpenAICompatExecutor(freebuffProvider, &config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"base_url": server.URL + "/api/v1", "api_key": "token"}}
	response, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   freebuffModel,
		Payload: []byte(`{"model":"deepseek/deepseek-v4-flash","messages":[{"role":"user","content":"ping"}]}`),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Payload) == 0 {
		t.Fatal("empty response")
	}
	if chatBody.Messages[0]["content"] != freebuffPrompt || chatBody.CodebuffMetadata["freebuff_instance_id"] != "instance-1" || chatBody.CodebuffMetadata["cost_mode"] != "free" {
		t.Fatalf("prepared body = %+v", chatBody)
	}
	if !finished {
		t.Fatal("run was not finished")
	}
}
