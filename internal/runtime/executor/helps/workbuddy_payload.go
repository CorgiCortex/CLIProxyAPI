package helps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/workbuddy"
)

const workBuddySystemPrompt = "You are a helpful coding assistant."

// NormalizeWorkBuddyPayload runs before the payload finalizer. It intentionally
// preserves caller text, tool schemas and unknown public fields.
func NormalizeWorkBuddyPayload(raw []byte, c workbuddy.Credential, model string) ([]byte, error) {
	if len(raw) > 16<<20 {
		return nil, &workbuddy.DispatchError{Reason: "request_body_too_large", Status: 413, Stop: true}
	}
	var body map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil || body == nil {
		return nil, fmt.Errorf("workbuddy: invalid chat payload")
	}
	messages, ok := body["messages"].([]any)
	if !ok {
		return nil, fmt.Errorf("workbuddy: messages must be an array")
	}
	deepseek := strings.HasPrefix(strings.ToLower(model), "deepseek")
	thinking, _ := body["thinking"].(map[string]any)
	effort, _ := body["reasoning_effort"].(string)
	if effort == "" {
		effort, _ = body["reasoningEffort"].(string)
	}
	enabled := deepseek && thinking["type"] != "disabled" && effort != "none"
	for _, item := range messages {
		message, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("workbuddy: invalid message")
		}
		if message["role"] == "developer" {
			message["role"] = "system"
		}
		if enabled && message["role"] == "assistant" {
			if _, ok := message["reasoning_content"]; !ok {
				message["reasoning_content"] = ""
			}
		}
	}
	if len(messages) == 0 || messages[0].(map[string]any)["role"] != "system" {
		messages = append([]any{map[string]any{"role": "system", "content": workBuddySystemPrompt}}, messages...)
	}
	body["messages"] = repairWorkBuddyTools(messages)
	body["model"] = model
	for key := range body {
		if strings.HasPrefix(key, "_") {
			delete(body, key)
		}
	}
	if value, ok := body["max_completion_tokens"]; ok {
		if _, exists := body["max_tokens"]; !exists {
			body["max_tokens"] = value
		}
		delete(body, "max_completion_tokens")
	}
	if value, ok := body["max_tokens"].(json.Number); ok && strings.HasPrefix(model, "gpt-") {
		if n, err := value.Int64(); err == nil && n < 16 {
			body["max_tokens"] = 16
		}
	}
	if _, ok := body["max_tokens"]; !ok {
		if meta, found := workbuddy.ModelFor(c.Realm, model); found && meta.Output > 0 {
			body["max_tokens"] = meta.Output
		}
	}
	if enabled {
		if _, ok := body["thinking"]; !ok {
			body["thinking"] = map[string]any{"type": "enabled"}
		}
		if effort == "" {
			body["reasoning_effort"] = "high"
		}
	}
	if stop, ok := body["stop"].(string); ok {
		body["stop"] = []string{stop}
	}
	body["stream"] = true
	if _, ok := body["stream_options"]; !ok {
		body["stream_options"] = map[string]any{"include_usage": true}
	}
	if c.Product == workbuddy.CLI {
		for _, key := range []string{"metadata", "conversation_id", "previous_response_id"} {
			delete(body, key)
		}
		body["cache_retention"] = "long"
	}
	var compact bytes.Buffer
	encoder := json.NewEncoder(&compact)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(body); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(compact.Bytes(), []byte("\n")), nil
}

// repairWorkBuddyTools joins split adjacent call declarations, moves available
// results next to their declarations, and removes incomplete call/result pairs.
// Intervening ordinary messages retain their relative order and text.
func repairWorkBuddyTools(messages []any) []any {
	merged := make([]map[string]any, 0, len(messages))
	for _, item := range messages {
		m := item.(map[string]any)
		calls, _ := m["tool_calls"].([]any)
		if len(merged) > 0 && m["role"] == "assistant" && len(calls) > 0 {
			prev := merged[len(merged)-1]
			previous, _ := prev["tool_calls"].([]any)
			// Content-bearing assistant turns remain independent.
			if prev["role"] == "assistant" && len(previous) > 0 && (m["content"] == nil || m["content"] == "") {
				prev["tool_calls"] = append(previous, calls...)
				continue
			}
		}
		merged = append(merged, m)
	}
	consumed := make(map[int]bool)
	out := make([]any, 0, len(merged))
	for i, m := range merged {
		if consumed[i] || m["role"] == "tool" {
			continue
		}
		calls, _ := m["tool_calls"].([]any)
		if len(calls) == 0 {
			out = append(out, m)
			continue
		}
		kept := make([]any, 0, len(calls))
		results := make([]any, 0, len(calls))
		usedIDs := make(map[string]bool)
		for _, raw := range calls {
			call, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			id, _ := call["id"].(string)
			if id == "" || usedIDs[id] {
				continue
			}
			usedIDs[id] = true
			for j := i + 1; j < len(merged); j++ {
				candidate := merged[j]
				// A new declaration for the same ID bounds this call's result scope.
				if nextCalls, ok := candidate["tool_calls"].([]any); ok {
					repeated := false
					for _, next := range nextCalls {
						if nextMap, ok := next.(map[string]any); ok && nextMap["id"] == id {
							repeated = true
							break
						}
					}
					if repeated {
						break
					}
				}
				if !consumed[j] && candidate["role"] == "tool" && candidate["tool_call_id"] == id {
					kept = append(kept, call)
					results = append(results, candidate)
					consumed[j] = true
					break
				}
			}
		}
		if len(kept) > 0 {
			m["tool_calls"] = kept
		} else {
			delete(m, "tool_calls")
		}
		if len(kept) > 0 || m["content"] != nil && m["content"] != "" {
			out = append(out, m)
			out = append(out, results...)
		}
	}
	return out
}
