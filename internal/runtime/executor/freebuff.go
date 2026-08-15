package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const (
	freebuffProvider = "freebuff"
	freebuffModel    = "deepseek/deepseek-v4-flash"
	freebuffAgent    = "base3-free-deepseek-flash"
	freebuffPrompt   = "You are Buffy, the coding agent behind Codebuff."
)

type freebuffSession struct {
	Status     string `json:"status"`
	Model      string `json:"model"`
	InstanceID string `json:"instanceId"`
}

type freebuffRun struct {
	RunID string `json:"runId"`
}

func (e *OpenAICompatExecutor) isFreebuff() bool {
	return strings.EqualFold(strings.TrimSpace(e.provider), freebuffProvider)
}

func (e *OpenAICompatExecutor) prepareFreebuffRequest(ctx context.Context, client *http.Client, auth *cliproxyauth.Auth, baseURL, apiKey, model string, payload []byte) ([]byte, string, error) {
	if model != freebuffModel {
		return nil, "", fmt.Errorf("freebuff: unsupported model %q", model)
	}

	var body map[string]json.RawMessage
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, "", err
	}
	var messages []json.RawMessage
	if err := json.Unmarshal(body["messages"], &messages); err != nil {
		return nil, "", err
	}
	marker, err := json.Marshal(map[string]string{"role": "system", "content": freebuffPrompt})
	if err != nil {
		return nil, "", err
	}
	body["messages"], err = json.Marshal(append([]json.RawMessage{marker}, messages...))
	if err != nil {
		return nil, "", err
	}

	instanceID, err := e.freebuffInstance(ctx, client, auth, baseURL, apiKey, model)
	if err != nil {
		return nil, "", err
	}
	runID, err := e.startFreebuffRun(ctx, client, auth, baseURL, apiKey)
	if err != nil {
		return nil, "", err
	}
	body["codebuff_metadata"], err = json.Marshal(map[string]string{
		"run_id":               runID,
		"client_id":            uuid.NewString(),
		"cost_mode":            "free",
		"freebuff_instance_id": instanceID,
	})
	if err != nil {
		return nil, "", err
	}
	payload, err = json.Marshal(body)
	return payload, runID, err
}

func (e *OpenAICompatExecutor) freebuffInstance(ctx context.Context, client *http.Client, auth *cliproxyauth.Auth, baseURL, apiKey, model string) (string, error) {
	// ponytail: one account owns one session; shard locks by credential only if acquisition latency matters.
	e.freebuffMu.Lock()
	defer e.freebuffMu.Unlock()
	var session freebuffSession
	if err := e.freebuffJSON(ctx, client, auth, http.MethodGet, strings.TrimSuffix(baseURL, "/")+"/freebuff/session", apiKey, nil, nil, &session); err != nil {
		var statusError statusErr
		if !errors.As(err, &statusError) || statusError.StatusCode() != http.StatusNotFound {
			return "", err
		}
		session.Status = "none"
	}
	if session.Status == "none" {
		headers := http.Header{"x-freebuff-model": []string{model}}
		if err := e.freebuffJSON(ctx, client, auth, http.MethodPost, strings.TrimSuffix(baseURL, "/")+"/freebuff/session", apiKey, headers, nil, &session); err != nil {
			return "", err
		}
	}
	if session.Status != "active" || session.Model != model || session.InstanceID == "" {
		return "", fmt.Errorf("freebuff: session status=%q model=%q", session.Status, session.Model)
	}
	return session.InstanceID, nil
}

func (e *OpenAICompatExecutor) startFreebuffRun(ctx context.Context, client *http.Client, auth *cliproxyauth.Auth, baseURL, apiKey string) (string, error) {
	body, err := json.Marshal(map[string]any{"action": "START", "agentId": freebuffAgent, "ancestorRunIds": []string{}})
	if err != nil {
		return "", err
	}
	var run freebuffRun
	if err = e.freebuffJSON(ctx, client, auth, http.MethodPost, strings.TrimSuffix(baseURL, "/")+"/agent-runs", apiKey, nil, body, &run); err != nil {
		return "", err
	}
	if run.RunID == "" {
		return "", fmt.Errorf("freebuff: start run returned no runId")
	}
	return run.RunID, nil
}

func (e *OpenAICompatExecutor) finishFreebuffRun(ctx context.Context, client *http.Client, auth *cliproxyauth.Auth, baseURL, apiKey, runID, status string) error {
	ctx = context.WithoutCancel(ctx)
	body, err := json.Marshal(map[string]any{
		"action":        "FINISH",
		"runId":         runID,
		"status":        status,
		"totalSteps":    1,
		"directCredits": 0,
		"totalCredits":  0,
		"steps":         []any{},
	})
	if err != nil {
		return err
	}
	return e.freebuffJSON(ctx, client, auth, http.MethodPost, strings.TrimSuffix(baseURL, "/")+"/agent-runs", apiKey, nil, body, nil)
}

func (e *OpenAICompatExecutor) freebuffJSON(ctx context.Context, client *http.Client, auth *cliproxyauth.Auth, method, url, apiKey string, headers http.Header, body []byte, dst any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("User-Agent", "ai-sdk/openai-compatible/codebuff")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(req, attrs)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return fmt.Errorf("freebuff: read response: %w; close response: %v", err, closeErr)
		}
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return statusErr{code: resp.StatusCode, msg: string(responseBody)}
	}
	if dst == nil || len(responseBody) == 0 {
		return nil
	}
	return json.Unmarshal(responseBody, dst)
}
