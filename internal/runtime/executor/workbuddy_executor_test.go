package executor

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/workbuddy"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	execution "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const wbSuccess = "data: {\"id\":\"chat-test\",\"model\":\"fixture-model\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hello\"}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":2,\"total_tokens\":10}}\n\ndata: [DONE]\n\n"

func wbFixture(t *testing.T, handler http.HandlerFunc) (*WorkBuddyExecutor, *coreauth.Auth) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cfg := &config.Config{WorkBuddy: config.WorkBuddyConfig{Enabled: true, StateDir: t.TempDir()}}
	e := NewWorkBuddyExecutor(cfg, nil)
	if e.initErr != nil {
		t.Fatal(e.initErr)
	}
	e.runtime.BaseURL = server.URL
	t.Cleanup(e.runtime.Transports.CloseIdleConnections)
	a, err := sdkauth.WorkBuddyAuthRecord(workbuddy.Credential{Type: "workbuddy", UID: "offline-user", Realm: workbuddy.International, Product: workbuddy.Desktop, AccessToken: "fixture-only-token", Models: []string{"fixture-model"}})
	if err != nil {
		t.Fatal(err)
	}
	e.TrackAuth(a)
	return e, a
}
func wbRequest() (execution.Request, execution.Options) {
	return execution.Request{Model: "fixture-model", Payload: []byte(`{"model":"fixture-model","messages":[{"role":"user","content":"test"}]}`)}, execution.Options{SourceFormat: sdktranslator.FromString("openai")}
}
func TestWorkBuddyExecutorNonStreamAndStream(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "aggregate", true: "stream"}[stream], func(t *testing.T) {
			var requests atomic.Int32
			e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/v2/chat/completions" {
					t.Errorf("path = %s", r.URL.Path)
				}
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if !gjson.GetBytes(raw, "stream").Bool() {
					t.Error("upstream was not streaming")
				}
				if r.Header.Get("X-IDE-Type") != "WorkBuddy" {
					t.Error("missing identity")
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, wbSuccess)
			})
			req, opts := wbRequest()
			if stream {
				opts.Stream = true
				result, err := e.ExecuteStream(context.Background(), a, req, opts)
				if err != nil {
					t.Fatal(err)
				}
				var output strings.Builder
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
					output.Write(chunk.Payload)
				}
				if !strings.Contains(output.String(), "hello") || !strings.Contains(output.String(), `"finish_reason":"stop"`) {
					t.Fatalf("output = %s", output.String())
				}
			} else {
				result, err := e.Execute(context.Background(), a, req, opts)
				if err != nil {
					t.Fatal(err)
				}
				if gjson.GetBytes(result.Payload, "choices.0.message.content").String() != "hello" || gjson.GetBytes(result.Payload, "usage.total_tokens").Int() != 10 {
					t.Fatalf("response = %s", result.Payload)
				}
			}
			if requests.Load() != 1 {
				t.Fatalf("requests = %d", requests.Load())
			}
			raw, err := json.Marshal(a.Metadata)
			if err != nil {
				t.Fatal(err)
			}
			c, err := workbuddy.DecodeCredential(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.runtime.Governor.UpdateLimits(workbuddy.Limits{DailyTokens: 10}, nil); err != nil {
				t.Fatal(err)
			}
			if gate, _ := e.runtime.Governor.Check(c, "fixture-model", true, false); gate.Allowed() {
				t.Fatal("observed usage was not charged")
			}
		})
	}
}
func TestWorkBuddyExecutorPayloadBarrierOnBothPaths(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "aggregate", true: "stream"}[stream], func(t *testing.T) {
			e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
				reader, err := gzip.NewReader(r.Body)
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				defer func() { _ = reader.Close() }()
				body, err := io.ReadAll(reader)
				if err != nil {
					t.Error(err)
				}
				for path, want := range map[string]string{"max_tokens": "7", "cache_retention": "short", "metadata.user": "configured", "barrier": "first"} {
					if got := gjson.GetBytes(body, path).String(); got != want {
						t.Errorf("%s=%q want %q", path, got, want)
					}
				}
				if gjson.GetBytes(body, "stream_options").Exists() {
					t.Error("filtered field restored")
				}
				_, _ = io.WriteString(w, wbSuccess)
			})
			a.Metadata["product"] = "cli"
			e.cfg.Payload = config.PayloadConfig{
				Override: []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"max_tokens": 7, "cache_retention": "short", "metadata.user": "configured", "barrier": "first"}}},
				Filter:   []config.PayloadFilterRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: []string{"stream_options"}}},
			}
			req, opts := wbRequest()
			if stream {
				opts.Stream = true
				result, err := e.ExecuteStream(context.Background(), a, req, opts)
				if err != nil {
					t.Fatal(err)
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
				}
			} else {
				if _, err := e.Execute(context.Background(), a, req, opts); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
func TestWorkBuddyRestrictionSurvivesExecutorReload(t *testing.T) {
	var requests atomic.Int32
	e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `{"code":11140,"message":"sensitive-content"}`)
	})
	req, opts := wbRequest()
	_, err := e.Execute(context.Background(), a, req, opts)
	var failure *workbuddy.DispatchError
	if !errors.As(err, &failure) || !failure.Stop || strings.Contains(err.Error(), "sensitive-content") {
		t.Fatalf("restriction = %v", err)
	}
	cfg := *e.cfg
	cfg.WorkBuddy.MaxConcurrency = 2
	next := NewWorkBuddyExecutor(&cfg, e)
	if next.runtime != e.runtime {
		t.Fatal("reload lost runtime")
	}
	_, err = next.Execute(context.Background(), a, req, opts)
	if !errors.As(err, &failure) || !strings.Contains(failure.Reason, "restricted") {
		t.Fatalf("gate = %v", err)
	}
	if requests.Load() != 1 {
		t.Fatal("restriction allowed new upstream request")
	}
}
func TestWorkBuddyMidStreamFailureDoesNotReplayOrFakeDone(t *testing.T) {
	var requests atomic.Int32
	e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\n")
	})
	req, opts := wbRequest()
	opts.Stream = true
	result, err := e.ExecuteStream(context.Background(), a, req, opts)
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	var terminal error
	for chunk := range result.Chunks {
		text.Write(chunk.Payload)
		if chunk.Err != nil {
			terminal = chunk.Err
		}
	}
	var failure *workbuddy.DispatchError
	if !errors.As(terminal, &failure) || !failure.Stop {
		t.Fatalf("terminal = %v", terminal)
	}
	if !strings.Contains(text.String(), "partial") || strings.Contains(text.String(), "[DONE]") {
		t.Fatalf("output = %s", text.String())
	}
	if requests.Load() != 1 {
		t.Fatal("replayed visible output")
	}
}
func TestWorkBuddyEmptyStreamRetriesOnlyOnce(t *testing.T) {
	var requests atomic.Int32
	e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			return
		}
		_, _ = io.WriteString(w, wbSuccess)
	})
	req, opts := wbRequest()
	if _, err := e.Execute(context.Background(), a, req, opts); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatalf("attempts = %d", requests.Load())
	}
}
func TestWorkBuddyRefreshBeforeRetryPersistsPair(t *testing.T) {
	var chats atomic.Int32
	var refreshes atomic.Int32
	var saved atomic.Int32
	e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/plugin/auth/token/refresh" {
			refreshes.Add(1)
			_, _ = io.WriteString(w, `{"code":0,"data":{"accessToken":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJvZmZsaW5lLXVzZXIifQ.sig","refreshToken":"rotated-refresh","expiresAt":4102444800000}}`)
			return
		}
		if chats.Add(1) == 1 {
			w.WriteHeader(401)
			return
		}
		if saved.Load() != 1 {
			t.Error("chat resumed before durable credential save")
		}
		_, _ = io.WriteString(w, wbSuccess)
	})
	a.Metadata["refresh_token"] = "fixture-refresh"
	var mu sync.Mutex
	var persisted *coreauth.Auth
	e.runtime.Save = func(_ context.Context, _ *coreauth.Auth, next *coreauth.Auth) error {
		mu.Lock()
		defer mu.Unlock()
		persisted = next.Clone()
		saved.Add(1)
		return nil
	}
	req, opts := wbRequest()
	if _, err := e.Execute(context.Background(), a, req, opts); err != nil {
		t.Fatal(err)
	}
	if refreshes.Load() != 1 || chats.Load() != 2 {
		t.Fatalf("refreshes=%d chats=%d", refreshes.Load(), chats.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if persisted == nil || persisted.Metadata["refresh_token"] != "rotated-refresh" {
		t.Fatal("rotated refresh token missing")
	}
}
func TestWorkBuddyDisabledExecutorAndArbitraryHTTP(t *testing.T) {
	e := NewWorkBuddyExecutor(&config.Config{}, nil)
	req, opts := wbRequest()
	if _, err := e.Execute(context.Background(), nil, req, opts); err == nil {
		t.Fatal("disabled provider executed")
	}
	if _, err := e.HttpRequest(context.Background(), nil, nil); err == nil {
		t.Fatal("ungoverned HTTP supported")
	}
}
func TestWorkBuddyCredentialUsesLatestRotation(t *testing.T) {
	e, a := wbFixture(t, func(http.ResponseWriter, *http.Request) {})
	old := a.Clone()
	newer := a.Clone()
	newer.UpdatedAt = newer.UpdatedAt.Add(1)
	newer.Metadata["access_token"] = "new-token"
	e.TrackAuth(newer)
	c, err := helps.WorkBuddyCredential(e.runtime.Current(old))
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessToken != "new-token" {
		t.Fatal("stale SDK credential restored consumed token")
	}
}

func TestWorkBuddyDownstreamProtocols(t *testing.T) {
	cases := []struct{ format, body, contentPath, streamMarker string }{
		{"claude", `{"model":"fixture-model","max_tokens":100,"messages":[{"role":"user","content":"test"}]}`, "content.0.text", "content_block_delta"},
		{"openai-response", `{"model":"fixture-model","input":"test"}`, "output.0.content.0.text", "response.output_text.delta"},
		{"gemini", `{"contents":[{"role":"user","parts":[{"text":"test"}]}]}`, "candidates.0.content.parts.0.text", "hello"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if gjson.GetBytes(body, "messages.#").Int() < 2 {
					t.Errorf("untranslated request: %s", body)
				}
				_, _ = io.WriteString(w, wbSuccess)
			})
			req := execution.Request{Model: "fixture-model", Payload: []byte(tc.body)}
			opts := execution.Options{SourceFormat: sdktranslator.FromString(tc.format)}
			response, err := e.Execute(context.Background(), a, req, opts)
			if err != nil {
				t.Fatal(err)
			}
			if gjson.GetBytes(response.Payload, tc.contentPath).String() != "hello" {
				t.Fatalf("nonstream response = %s", response.Payload)
			}
			opts.Stream = true
			req.Payload, _ = sjson.SetBytes(req.Payload, "stream", true)
			result, err := e.ExecuteStream(context.Background(), a, req, opts)
			if err != nil {
				t.Fatal(err)
			}
			var text strings.Builder
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					t.Fatal(chunk.Err)
				}
				text.Write(chunk.Payload)
			}
			if !strings.Contains(text.String(), tc.streamMarker) {
				t.Fatalf("untranslated stream = %s", text.String())
			}
		})
	}
}

func TestWorkBuddyStreamEnvelopeRestrictionStopsAndPersists(t *testing.T) {
	var requests atomic.Int32
	e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, "data: {\"error\":{\"code\":11140,\"message\":\"private upstream detail\"}}\n\n")
	})
	req, opts := wbRequest()
	_, err := e.Execute(context.Background(), a, req, opts)
	var failure *workbuddy.DispatchError
	if !errors.As(err, &failure) || !failure.Stop || failure.Reason != string(workbuddy.FaultRestricted) {
		t.Fatalf("SSE fault = %v", err)
	}
	if strings.Contains(err.Error(), "private") {
		t.Fatal("error body exposed")
	}
	if _, err = e.Execute(context.Background(), a, req, opts); err == nil {
		t.Fatal("restriction lost")
	}
	if requests.Load() != 1 {
		t.Fatal("stream error bypassed restriction gate")
	}
}

func TestWorkBuddyRefreshUsesConfiguredManagerStore(t *testing.T) {
	var chats atomic.Int32
	e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/plugin/auth/token/refresh" {
			_, _ = io.WriteString(w, `{"code":0,"data":{"accessToken":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJvZmZsaW5lLXVzZXIifQ.sig","refreshToken":"manager-rotated","expiresAt":4102444800000}}`)
			return
		}
		if chats.Add(1) == 1 {
			w.WriteHeader(401)
			return
		}
		_, _ = io.WriteString(w, wbSuccess)
	})
	a.Metadata["refresh_token"] = "fixture-refresh"
	store := sdkauth.NewFileTokenStore()
	dir := t.TempDir()
	store.SetBaseDir(dir)
	manager := coreauth.NewManager(store, nil, nil)
	registered, err := manager.Register(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	e.BindCredentialManager(manager)
	e.TrackAuth(registered)
	manager.RegisterExecutor(e)
	req, opts := wbRequest()
	if _, err := e.Execute(context.Background(), registered, req, opts); err != nil {
		t.Fatal(err)
	}
	current, ok := manager.GetByID(registered.ID)
	if !ok || current.Metadata["refresh_token"] != "manager-rotated" {
		t.Fatal("manager not updated")
	}
	loaded, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Metadata["refresh_token"] != "manager-rotated" {
		t.Fatal("configured store did not receive rotation")
	}
	// A later SDK refresh takes the same provider path and preserves manager fences.
	if _, err := manager.ForceRefreshAuth(context.Background(), registered.ID); err != nil {
		t.Fatal(err)
	}
}

func TestWorkBuddyInflightRefreshCannotOverwriteExternalRotation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, `{"code":0,"data":{"accessToken":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJvZmZsaW5lLXVzZXIifQ.sig","refreshToken":"stale-rotation","expiresAt":4102444800000}}`)
	})
	a.Metadata["refresh_token"] = "fixture-refresh"
	store := sdkauth.NewFileTokenStore()
	store.SetBaseDir(t.TempDir())
	manager := coreauth.NewManager(store, nil, nil)
	registered, err := manager.Register(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	e.BindCredentialManager(manager)
	e.TrackAuth(registered)
	done := make(chan error, 1)
	go func() { _, errRefresh := e.Refresh(context.Background(), registered); done <- errRefresh }()
	<-started
	replacement := registered.Clone()
	replacement.Metadata["access_token"] = "newer-external-token"
	replacement.Metadata["refresh_token"] = "newer-external-refresh"
	if _, err := manager.Update(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("stale refresh was accepted")
	}
	current, ok := manager.GetByID(registered.ID)
	if !ok || current.Metadata["access_token"] != "newer-external-token" {
		t.Fatal("external rotation overwritten")
	}
	loaded, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Metadata["access_token"] != "newer-external-token" {
		t.Fatal("external persisted rotation overwritten")
	}
}

func TestWorkBuddyContentDegradationRebuildsBeforeFinalBarrier(t *testing.T) {
	var calls atomic.Int32
	e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if gjson.GetBytes(body, "configured").String() != "yes" {
			t.Error("payload rules missing on rebuilt attempt")
		}
		if calls.Add(1) == 1 {
			if gjson.GetBytes(body, "messages.0.content").String() != "caller-system" {
				t.Error("initial prompt rewritten")
			}
			w.WriteHeader(403)
			_, _ = io.WriteString(w, `{"message":"content review"}`)
			return
		}
		if gjson.GetBytes(body, "messages.0.content").String() != workbuddy.DegradedPrompt {
			t.Error("retry did not degrade system prompt")
		}
		if gjson.GetBytes(body, "messages.1.content").String() != "user-content" {
			t.Error("degradation altered user content")
		}
		_, _ = io.WriteString(w, wbSuccess)
	})
	e.cfg.Payload = config.PayloadConfig{Override: []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"configured": "yes"}}}}
	req, opts := wbRequest()
	req.Payload = []byte(`{"model":"fixture-model","messages":[{"role":"system","content":"caller-system"},{"role":"user","content":"user-content"}]}`)
	if _, err := e.Execute(context.Background(), a, req, opts); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("attempts=%d", calls.Load())
	}
}
func TestWorkBuddyCustomPromptNeverDegradesOrRetries(t *testing.T) {
	var calls atomic.Int32
	e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if gjson.GetBytes(body, "messages.0.content").String() != "custom-prompt" {
			t.Error("custom prompt not applied")
		}
		w.WriteHeader(403)
	})
	e.cfg.WorkBuddy.Prompt = config.WorkBuddyPrompt{Mode: "custom", Text: "custom-prompt"}
	req, opts := wbRequest()
	if _, err := e.Execute(context.Background(), a, req, opts); err == nil {
		t.Fatal("content rejection lost")
	}
	if calls.Load() != 1 || e.runtime.Policy.Degraded() {
		t.Fatal("custom prompt opted into degradation")
	}
}
func TestWorkBuddyProductSwitchPersistsBeforeRetry(t *testing.T) {
	var calls atomic.Int32
	var saved atomic.Int32
	e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(429)
			_, _ = io.WriteString(w, `{"code":14003,"message":"too many requests"}`)
			return
		}
		if r.Header.Get("X-IDE-Type") != "CLI" || saved.Load() != 1 {
			t.Error("identity did not persist before retry")
		}
		_, _ = io.WriteString(w, wbSuccess)
	})
	e.cfg.WorkBuddy.AutoSwitchProduct = true
	e.cfg.WorkBuddy.AutoSwitchProducts = []string{"workbuddy", "cli"}
	e.runtime.Save = func(_ context.Context, _ *coreauth.Auth, next *coreauth.Auth) error {
		if next.Metadata["product"] != "cli" {
			t.Error("unexpected saved product")
		}
		saved.Add(1)
		return nil
	}
	req, opts := wbRequest()
	if _, err := e.Execute(context.Background(), a, req, opts); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("requests=%d", calls.Load())
	}
}
func TestWorkBuddyPaidFallbackRequiresOptInAndEveryFreeAccountCapped(t *testing.T) {
	for _, tc := range []struct {
		name           string
		enabled, other bool
		want           int
	}{{"disabled", false, false, 1}, {"other-free-account", true, true, 1}, {"all-capped", true, false, 2}} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				model := gjson.GetBytes(body, "model").String()
				calls.Add(1)
				if model == "deepseek-v4.1-flash" {
					w.WriteHeader(429)
					_, _ = io.WriteString(w, `{"code":6004,"message":"reset at 2099-10-22 00:00:00 UTC+8"}`)
					return
				}
				if model != "deepseek-v4.1-flash-sg" {
					t.Errorf("unexpected billed model %s", model)
				}
				_, _ = io.WriteString(w, wbSuccess)
			})
			e.cfg.WorkBuddy.PaidFallback = tc.enabled
			if tc.other {
				second := a.Clone()
				second.ID = "second-fixture"
				second.Metadata["uid"] = "second-fixture-user"
				e.TrackAuth(second)
			}
			req, opts := wbRequest()
			req.Model = "deepseek-v4.1-flash"
			_, err := e.Execute(context.Background(), a, req, opts)
			if tc.want == 2 && err != nil {
				t.Fatal(err)
			}
			if tc.want == 1 && err == nil {
				t.Fatal("cap ignored")
			}
			if calls.Load() != int32(tc.want) {
				t.Fatalf("requests=%d want %d", calls.Load(), tc.want)
			}
			c, _ := helps.WorkBuddyCredential(a)
			if !e.runtime.Governor.Capped(c, "deepseek-v4.1-flash") {
				t.Fatal("paid fallback cleared free cap")
			}
		})
	}
}

func TestWorkBuddyNativeSelectionUsesWarmHistoryAndRiskGates(t *testing.T) {
	e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, wbSuccess) })
	b := a.Clone()
	b.ID = "workbuddy-fixture-b"
	b.Metadata["uid"] = "fixture-b"
	e.TrackAuth(b)
	req, opts := wbRequest()
	ctx, err := e.PrepareExecutionContext(context.Background(), req, opts)
	if err != nil {
		t.Fatal(err)
	}
	first, err := e.SelectAuth(ctx, "fixture-model", opts, []*coreauth.Auth{a, b})
	if err != nil {
		t.Fatal(err)
	}
	again, err := e.SelectAuth(ctx, "fixture-model", opts, []*coreauth.Auth{b, a})
	if err != nil || again.ID != first.ID {
		t.Fatal("affinity followed candidate ordering")
	}
	c, _ := helps.WorkBuddyCredential(first)
	if _, err := e.runtime.Governor.RecordFailure(c, "fixture-model", workbuddy.Fault{Kind: workbuddy.FaultModelRate}, workbuddy.FailureOptions{}); err != nil {
		t.Fatal(err)
	}
	switched, err := e.SelectAuth(ctx, "fixture-model", opts, []*coreauth.Auth{a, b})
	if err != nil || switched.ID == first.ID {
		t.Fatal("affinity bypassed model cooldown")
	}
	sibling, err := e.SelectAuth(ctx, "another-model", opts, []*coreauth.Auth{first})
	if err != nil || sibling.ID != first.ID {
		t.Fatal("model cooldown poisoned account")
	}
}

func TestWorkBuddyMaintenanceDefaultsOffAndCachesDiscoveredModels(t *testing.T) {
	var calls atomic.Int32
	e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v3/config" {
			t.Error("unexpected background endpoint")
		}
		_, _ = io.WriteString(w, `{"code":0,"data":{"agents":{"cli":{"models":["fixture-discovered"]}},"models":[{"id":"fixture-discovered","maxInputTokens":2048}]}}`)
	})
	if _, err := e.RunMaintenance(context.Background()); err != nil || calls.Load() != 0 {
		t.Fatal("disabled background jobs ran")
	}
	e.cfg.WorkBuddy.Jobs = config.WorkBuddyJobs{Enabled: true, ModelDiscovery: true}
	changed, err := e.RunMaintenance(context.Background())
	if err != nil || len(changed) != 1 || changed[0] != a.ID || calls.Load() != 1 {
		t.Fatalf("changed=%v calls=%d err=%v", changed, calls.Load(), err)
	}
	if _, err = e.RunMaintenance(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatal("completed slot repeated")
	}
	restarted := NewWorkBuddyExecutor(e.cfg, nil)
	restarted.runtime.BaseURL = e.runtime.BaseURL
	restarted.TrackAuth(a)
	t.Cleanup(restarted.runtime.Transports.CloseIdleConnections)
	if _, err = restarted.RunMaintenance(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatal("restart repeated completed discovery")
	}
	models, err := restarted.ModelCatalog(a)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, model := range models {
		if model.ID == "fixture-discovered" && model.Input == 2048 {
			found = true
		}
	}
	if !found {
		t.Fatal("discovered catalog did not survive restart")
	}
}

func TestWorkBuddyDisableReloadCancelsBackgroundConnection(t *testing.T) {
	started := make(chan struct{})
	e, _ := wbFixture(t, func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() })
	e.cfg.WorkBuddy.Jobs = config.WorkBuddyJobs{Enabled: true, ModelDiscovery: true}
	done := make(chan error, 1)
	go func() { _, err := e.RunMaintenance(context.Background()); done <- err }()
	<-started
	nextCfg := *e.cfg
	nextCfg.WorkBuddy.Enabled = false
	disabled := NewWorkBuddyExecutor(&nextCfg, e)
	if disabled.initErr == nil {
		t.Fatal("disabled provider remained available")
	}
	if err := <-done; err == nil {
		t.Fatal("canceled background connection reported success")
	}
}

func TestWorkBuddyUpstreamCreditUsageEnforcesPaidDailyBudget(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "aggregate", true: "stream"}[stream], func(t *testing.T) {
			var calls atomic.Int32
			e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.WriteString(w, strings.Replace(wbSuccess, `"total_tokens":10`, `"total_tokens":10,"credit":2.5`, 1))
			})
			e.cfg.WorkBuddy.Limits.DailyCredits = 2
			if err := e.runtime.Configure(e.cfg.WorkBuddy); err != nil {
				t.Fatal(err)
			}
			req, opts := wbRequest()
			if stream {
				opts.Stream = true
				result, err := e.ExecuteStream(context.Background(), a, req, opts)
				if err != nil {
					t.Fatal(err)
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
				}
			} else if _, err := e.Execute(context.Background(), a, req, opts); err != nil {
				t.Fatal(err)
			}
			_, err := e.Execute(context.Background(), a, req, opts)
			if err == nil || !strings.Contains(err.Error(), "daily_credits") || calls.Load() != 1 {
				t.Fatalf("calls=%d err=%v", calls.Load(), err)
			}
		})
	}
}

func TestWorkBuddyResetProbeReusesGovernorAndStopsAfterObservedRecovery(t *testing.T) {
	var calls atomic.Int32
	e, a := wbFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = io.WriteString(w, wbSuccess) })
	now := time.Now().Add(-2 * time.Minute)
	governor, err := workbuddy.OpenGovernor(filepath.Join(t.TempDir(), "risk.json"), workbuddy.GovernorOptions{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	e.runtime.Governor = governor
	e.cfg.WorkBuddy.Jobs = config.WorkBuddyJobs{Enabled: true, ResetProbes: true}
	c, err := helps.WorkBuddyCredential(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = governor.RecordFailure(c, "hy3", workbuddy.Fault{Kind: workbuddy.FaultModelCap, ResetAt: now.Add(time.Minute)}, workbuddy.FailureOptions{FreeModel: true}); err != nil {
		t.Fatal(err)
	}
	if _, err = e.RunMaintenance(context.Background()); err != nil || calls.Load() != 0 {
		t.Fatal("probe ran before reset")
	}
	now = now.Add(2 * time.Minute)
	if _, err = e.RunMaintenance(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatalf("calls=%d err=%v", calls.Load(), err)
	}
	if len(governor.DueResetProbes(c)) != 0 {
		t.Fatal("confirmed recovery retained pending reset")
	}
	if _, err = e.RunMaintenance(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatal("recovered model was probed again")
	}
}

func TestWorkBuddyStaleExecutorCannotStartMaintenanceAfterDisable(t *testing.T) {
	var calls atomic.Int32
	e, _ := wbFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, `{"code":0,"data":{}}`)
	})
	e.cfg.WorkBuddy.Jobs = config.WorkBuddyJobs{Enabled: true, ModelDiscovery: true}
	disabledConfig := *e.cfg
	disabledConfig.WorkBuddy.Enabled = false
	_ = NewWorkBuddyExecutor(&disabledConfig, e)
	if changed, err := e.RunMaintenance(context.Background()); err != nil || len(changed) != 0 || calls.Load() != 0 {
		t.Fatal("old executor started maintenance after disable")
	}
}
