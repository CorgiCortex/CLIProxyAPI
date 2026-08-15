package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestFreebuffRequestLifecycle(t *testing.T) {
	wantAgents := map[string]string{
		"deepseek/deepseek-v4-pro":   "base3-free-deepseek",
		"deepseek/deepseek-v4-flash": "base3-free-deepseek-flash",
		"openai/gpt-5.6-luna":        "base3-free-luna",
		"minimax/minimax-m3":         "base3-free-minimax-m3",
		"mimo/mimo-v2.5":             "base3-free-mimo",
	}
	if !reflect.DeepEqual(freebuffAgentByModel, wantAgents) {
		t.Fatalf("freebuff agents = %#v", freebuffAgentByModel)
	}

	var session freebuffSession
	var deleted, finished int
	var startedAgents []string
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
			switch r.Method {
			case http.MethodGet:
				if session.Status == "" {
					http.NotFound(w, r)
					return
				}
				json.NewEncoder(w).Encode(session)
			case http.MethodDelete:
				deleted++
				session = freebuffSession{}
				w.WriteHeader(http.StatusNoContent)
			case http.MethodPost:
				model := r.Header.Get("x-freebuff-model")
				session = freebuffSession{Status: "active", Model: model, InstanceID: "instance-1"}
				json.NewEncoder(w).Encode(session)
			}
		case "/api/v1/agent-runs":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["action"] == "FINISH" {
				finished++
				return
			}
			startedAgents = append(startedAgents, body["agentId"].(string))
			json.NewEncoder(w).Encode(freebuffRun{RunID: "run-1"})
		case "/api/v1/chat/completions":
			if err := json.NewDecoder(r.Body).Decode(&chatBody); err != nil {
				t.Fatal(err)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"id": "chat-1", "model": session.Model,
				"choices": []any{map[string]any{"index": 0, "message": map[string]string{"role": "assistant", "content": "pong"}, "finish_reason": "stop"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	executor := NewOpenAICompatExecutor(util.OpenAICompatibleProviderKey(freebuffProvider), &config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"base_url": server.URL + "/api/v1", "api_key": "token"}}
	for _, model := range []string{freebuffDeepSeekV4FlashModel, freebuffDeepSeekV4ProModel} {
		payload, err := json.Marshal(map[string]any{"model": model, "messages": []map[string]string{{"role": "user", "content": "ping"}}})
		if err != nil {
			t.Fatal(err)
		}
		response, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{Model: model, Payload: payload}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI})
		if err != nil {
			t.Fatal(err)
		}
		if len(response.Payload) == 0 {
			t.Fatal("empty response")
		}
	}
	if chatBody.Messages[0]["content"] != freebuffPrompt || chatBody.CodebuffMetadata["freebuff_instance_id"] != "instance-1" || chatBody.CodebuffMetadata["cost_mode"] != "free" {
		t.Fatalf("prepared body = %+v", chatBody)
	}
	if !reflect.DeepEqual(startedAgents, []string{"base3-free-deepseek-flash", "base3-free-deepseek"}) || deleted != 1 || finished != 2 {
		t.Fatalf("started agents = %v, deleted = %d, finished = %d", startedAgents, deleted, finished)
	}
}
