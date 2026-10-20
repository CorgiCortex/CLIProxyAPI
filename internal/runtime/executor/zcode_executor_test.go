package executor

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/translator"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	exec "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/hkdf"
)

type zcodeTestTransport func(*http.Request) (*http.Response, error)

func (f zcodeTestTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func zcodeTestAccount() *coreauth.Auth {
	return &coreauth.Auth{ID: "zcode-test", Provider: "zcode", Metadata: map[string]any{"family": "zai", "plan": "start-plan", "jwt": "test-jwt"}}
}

func zcodeTestHandshake(t *testing.T) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, []byte("secret"), []byte("WD_CLIENT_SIGN_KDF_SALT"), []byte("ed25519_priv")), key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, gcm.NonceSize())
	encrypted := gcm.Seal(iv, iv, []byte(base64.StdEncoding.EncodeToString(der)), []byte("key"))
	return `{"code":200,"data":{"privateCipher":"` + base64.StdEncoding.EncodeToString(encrypted) + `"}}`
}

func TestZCodeFourAccountModesAndToolTranslation(t *testing.T) {
	for _, family := range []string{"zai", "bigmodel"} {
		for _, plan := range []string{"start-plan", "coding-plan"} {
			for _, format := range []translator.Format{translator.FormatClaude, translator.FormatOpenAI, translator.FormatOpenAIResponse} {
				t.Run(family+"/"+plan+"/"+format.String(), func(t *testing.T) {
					cfg := &config.Config{ZCode: config.ZCodeConfig{CaptchaURL: zcodeTestWorker(t)}}
					auth := zcodeTestAccount()
					auth.Metadata["family"], auth.Metadata["plan"], auth.Metadata["api_key"] = family, plan, "key.secret"
					handshake := zcodeTestHandshake(t)
					inference := 0
					ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", zcodeTestTransport(func(r *http.Request) (*http.Response, error) {
						body := handshake
						switch r.URL.Path {
						case "/api/v1/agent/configs":
							body = `{"code":0,"data":{"proxyEndpoint":{"mapping":[]}}}`
						case "/api/paas/c1f3a7e2/v2/client":
							if r.Header.Get("Authorization") != "key.secret" {
								t.Fatal("bad handshake auth")
							}
						default:
							inference++
							if plan == "coding-plan" {
								host := "api.z.ai"
								if family == "bigmodel" {
									host = "open.bigmodel.cn"
								}
								if r.URL.Host != host || r.Header.Get("X-Client-Sig") == "" || r.Header.Get("X-Api-Key") != "key.secret" {
									t.Fatal("incorrect signed route")
								}
							} else if r.URL.Host != "zcode.z.ai" || r.Header.Get("X-Client-Sig") != "" {
								t.Fatal("incorrect start-plan route")
							}
							body = `{"id":"m1","type":"message","role":"assistant","model":"model","content":[{"type":"tool_use","id":"call1","name":"lookup","input":{"query":"hello"}}],"stop_reason":"tool_use","usage":{"input_tokens":4,"output_tokens":6}}`
						}
						return &http.Response{StatusCode: 200, Header: http.Header{"Authorization": {"must-not-leak"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					}))
					payload := []byte(`{"model":"model","messages":[{"role":"user","content":"hi"}],"max_tokens":32}`)
					if format == translator.FormatOpenAIResponse {
						payload = []byte(`{"model":"model","input":"hi"}`)
					}
					result, err := NewZCodeExecutor(cfg).Execute(ctx, auth, exec.Request{Model: "model", Payload: payload}, exec.Options{SourceFormat: format})
					if err != nil {
						t.Fatal(err)
					}
					if inference != 1 || !strings.Contains(string(result.Payload), "lookup") || !strings.Contains(string(result.Payload), "hello") {
						t.Fatalf("tool translation failed: %s", result.Payload)
					}
					if result.Headers.Get("Authorization") != "" {
						t.Fatal("credential echo leaked")
					}
				})
			}
		}
	}
}

func zcodeTestWorker(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/token" {
			t.Error("unexpected worker route", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("account leaked to worker")
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"verify_param": "test-verify", "region": "cn", "expires_at": time.Now().Add(time.Minute).UnixMilli()}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestZCodePayloadBarrierSurvivesCaptchaRetry(t *testing.T) {
	cfg := &config.Config{ZCode: config.ZCodeConfig{CaptchaURL: zcodeTestWorker(t), StartPlanSystem: "built-in prefix"}}
	cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"model": "configured-model", "max_tokens": 17}}}
	cfg.Payload.Filter = []config.PayloadFilterRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: []string{"system", "metadata"}}}
	executor := NewZCodeExecutor(cfg)
	calls := 0
	var previous []byte
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", zcodeTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		if calls > 1 && !bytes.Equal(body, previous) {
			t.Fatal("retry changed finalized payload")
		}
		previous = body
		if gjson.GetBytes(body, "system").Exists() || gjson.GetBytes(body, "metadata").Exists() || gjson.GetBytes(body, "model").String() != "configured-model" || gjson.GetBytes(body, "max_tokens").Int() != 17 {
			t.Fatalf("payload barrier violated: %s", body)
		}
		if r.Header.Get("Authorization") != "Bearer test-jwt" || r.Header.Get("X-Api-Key") != "" {
			t.Fatal("wrong start-plan auth")
		}
		if calls == 1 {
			return &http.Response{StatusCode: 403, Header: http.Header{"X-Aliyun-Captcha-Verify-Param": {"challenge"}}, Body: io.NopCloser(strings.NewReader(`{"code":3007}`))}, nil
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":"m1","type":"message","role":"assistant","model":"configured-model","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":4,"output_tokens":1}}`))}, nil
	}))
	result, err := executor.Execute(ctx, zcodeTestAccount(), exec.Request{Model: "model", Payload: []byte(`{"model":"model","messages":[{"role":"user","content":"hello"}],"system":"caller","max_tokens":32}`)}, exec.Options{SourceFormat: translator.FormatClaude})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || gjson.GetBytes(result.Payload, "content.0.text").String() != "ok" {
		t.Fatalf("unexpected result: %d %s", calls, result.Payload)
	}
}

func TestZCodeStreamingProtocolsAndTruncation(t *testing.T) {
	events := []string{
		`{"type":"message_start","message":{"id":"msg_test","type":"message","role":"assistant","model":"model","content":[],"usage":{"input_tokens":4,"output_tokens":0}}}`,
		`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}`,
		`{"type":"content_block_stop","index":0}`,
		`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}`,
		`{"type":"message_stop"}`,
	}
	for _, format := range []translator.Format{translator.FormatClaude, translator.FormatOpenAI, translator.FormatOpenAIResponse} {
		for _, truncated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/truncated=%v", format, truncated), func(t *testing.T) {
				cfg := &config.Config{ZCode: config.ZCodeConfig{CaptchaURL: zcodeTestWorker(t)}}
				executor := NewZCodeExecutor(cfg)
				var wire strings.Builder
				for i, event := range events {
					if truncated && i == len(events)-1 {
						break
					}
					fmt.Fprintf(&wire, "event: %s\ndata: %s\n\n", gjson.Get(event, "type").String(), event)
				}
				ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", zcodeTestTransport(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(wire.String()))}, nil
				}))
				payload := []byte(`{"model":"model","messages":[{"role":"user","content":"hi"}],"max_tokens":32}`)
				if format == translator.FormatOpenAIResponse {
					payload = []byte(`{"model":"model","input":"hi"}`)
				}
				result, err := executor.ExecuteStream(ctx, zcodeTestAccount(), exec.Request{Model: "model", Payload: payload}, exec.Options{SourceFormat: format})
				if err != nil {
					t.Fatal(err)
				}
				var all strings.Builder
				var streamErr error
				for chunk := range result.Chunks {
					all.Write(chunk.Payload)
					if chunk.Err != nil {
						streamErr = chunk.Err
					}
				}
				if truncated != (streamErr != nil) {
					t.Fatalf("incorrect completion: %v", streamErr)
				}
				if !strings.Contains(all.String(), "hello") {
					t.Fatalf("translation lost text: %s", all.String())
				}
				if !truncated && format == translator.FormatOpenAIResponse && !strings.Contains(all.String(), "response.completed") {
					t.Fatalf("missing Responses terminal event: %s", all.String())
				}
			})
		}
	}
}
