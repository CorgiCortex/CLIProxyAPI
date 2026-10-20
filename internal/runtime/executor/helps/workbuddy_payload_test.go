package helps

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/workbuddy"
	"github.com/tidwall/gjson"
)

func TestWorkBuddyToolRepairAndThinking(t *testing.T) {
	raw := []byte(`{"messages":[{"role":"developer","content":"keep client instructions"},{"role":"assistant","tool_calls":[{"id":"a","type":"function","function":{"name":"one","arguments":"{}"}}]},{"role":"assistant","tool_calls":[{"id":"b","type":"function","function":{"name":"two","arguments":"{}"}},{"id":"missing","type":"function","function":{"name":"three","arguments":"{}"}}]},{"role":"user","content":"intervening"},{"role":"tool","tool_call_id":"b","content":"B"},{"role":"tool","tool_call_id":"a","content":"A"},{"role":"tool","tool_call_id":"orphan","content":"drop"}],"_private_marker":true,"max_completion_tokens":50}`)
	body, err := NormalizeWorkBuddyPayload(raw, workbuddy.Credential{Realm: workbuddy.International, Product: workbuddy.CLI}, "deepseek-v4.1-flash")
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"messages.#": "5", "messages.0.role": "system", "messages.0.content": "keep client instructions", "messages.1.tool_calls.#": "2", "messages.2.tool_call_id": "a", "messages.3.tool_call_id": "b", "messages.4.content": "intervening", "thinking.type": "enabled", "reasoning_effort": "high", "max_tokens": "50", "cache_retention": "long"} {
		if got := gjson.GetBytes(body, path).String(); got != want {
			t.Errorf("%s=%q want %q; body=%s", path, got, want, body)
		}
	}
	if !gjson.GetBytes(body, "messages.1.reasoning_content").Exists() {
		t.Error("missing reasoning backfill")
	}
	for _, path := range []string{"_private_marker", "max_completion_tokens"} {
		if gjson.GetBytes(body, path).Exists() {
			t.Errorf("unexpected %s", path)
		}
	}
}
func TestWorkBuddyPayloadKeepsExplicitReasoningOptOut(t *testing.T) {
	raw := []byte(`{"messages":[{"role":"assistant","content":"prior"},{"role":"user","content":"next"}],"thinking":{"type":"disabled"},"tools":[{"type":"function","function":{"name":"tool","parameters":{"type":"object","properties":{"n":{"type":"integer"}}}}}]}`)
	body, err := NormalizeWorkBuddyPayload(raw, workbuddy.Credential{Realm: workbuddy.International, Product: workbuddy.Desktop}, "deepseek-v4.1-flash")
	if err != nil {
		t.Fatal(err)
	}
	if gjson.GetBytes(body, "reasoning_effort").Exists() || gjson.GetBytes(body, "messages.1.reasoning_content").Exists() {
		t.Fatal("thinking opt out overwritten")
	}
	if gjson.GetBytes(body, "tools.0.function.parameters.properties.n.type").String() != "integer" {
		t.Fatal("tool schema modified")
	}
}
