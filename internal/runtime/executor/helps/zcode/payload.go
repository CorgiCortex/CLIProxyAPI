package zcode

import (
	"encoding/json"
	"fmt"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// AdaptPayload applies gateway metadata and cache hints before the user's rules.
// The default prefix is independently authored; no third-party prompt asset is embedded.
func AdaptPayload(body []byte, c Credential, session, prefix string) ([]byte, error) {
	if !gjson.ValidBytes(body) {
		return nil, fmt.Errorf("zcode: invalid translated payload")
	}
	identity, err := json.Marshal(map[string]string{"device_id": c.DeviceID, "account_uuid": "", "session_id": session})
	if err != nil {
		return nil, err
	}
	body, err = sjson.SetBytes(body, "metadata.user_id", string(identity))
	if err != nil {
		return nil, err
	}
	if c.Plan == "start-plan" {
		if prefix == "" {
			prefix = "You are ZCode, an AI coding assistant. Follow the user's instructions and use only the tools supplied in this request."
		}
		var blocks []json.RawMessage
		block, errMarshal := json.Marshal(map[string]any{"type": "text", "text": prefix, "cache_control": map[string]string{"type": "ephemeral"}})
		if errMarshal != nil {
			return nil, errMarshal
		}
		blocks = append(blocks, block)
		system := gjson.GetBytes(body, "system")
		switch {
		case system.Type == gjson.String:
			caller, errMarshal := json.Marshal(map[string]string{"type": "text", "text": system.String()})
			if errMarshal != nil {
				return nil, errMarshal
			}
			blocks = append(blocks, caller)
		case system.IsArray():
			for _, caller := range system.Array() {
				blocks = append(blocks, json.RawMessage(caller.Raw))
			}
		case system.Exists() && system.Type != gjson.Null:
			return nil, fmt.Errorf("zcode: system must be text or content blocks")
		}
		body, err = sjson.SetBytes(body, "system", blocks)
		if err != nil {
			return nil, err
		}
	}
	// Keep at most one message-level cache breakpoint. System/tool rules remain
	// caller-owned, except for the optional gateway prefix above.
	messages := gjson.GetBytes(body, "messages").Array()
	for i, message := range messages {
		content := message.Get("content")
		if content.Type == gjson.String {
			body, err = sjson.SetBytes(body, fmt.Sprintf("messages.%d.content", i), []map[string]string{{"type": "text", "text": content.String()}})
			if err != nil {
				return nil, err
			}
		} else {
			for j := range content.Array() {
				body, err = sjson.DeleteBytes(body, fmt.Sprintf("messages.%d.content.%d.cache_control", i, j))
				if err != nil {
					return nil, err
				}
			}
		}
	}
	if len(messages) > 0 {
		last := len(messages) - 1
		content := gjson.GetBytes(body, fmt.Sprintf("messages.%d.content", last)).Array()
		if len(content) > 0 {
			body, err = sjson.SetBytes(body, fmt.Sprintf("messages.%d.content.%d.cache_control", last, len(content)-1), map[string]string{"type": "ephemeral"})
			if err != nil {
				return nil, err
			}
		}
	}
	return body, nil
}
