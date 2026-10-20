package workbuddy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

const maxStreamEvent = 16 << 20
const maxCollectedResponse = 64 << 20

// StreamError intentionally excludes upstream payloads and partial user text.
type StreamError struct{ Reason string }

func (e *StreamError) Error() string { return "workbuddy: " + e.Reason }

// ReadEvents implements SSE framing, including CRLF, comments and multiline
// data. An EOF without the upstream terminator is never a successful completion.
func ReadEvents(r io.Reader, consume func([]byte) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), maxStreamEvent)
	var data []byte
	dispatch := func() (bool, error) {
		if len(data) == 0 {
			return false, nil
		}
		event := bytes.TrimSuffix(data, []byte("\n"))
		if bytes.Equal(bytes.TrimSpace(event), []byte("[DONE]")) {
			return true, nil
		}
		if !json.Valid(event) {
			return false, &StreamError{"invalid upstream event"}
		}
		if err := consume(event); err != nil {
			return false, err
		}
		data = data[:0]
		return false, nil
	}
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			done, err := dispatch()
			if err != nil {
				return err
			}
			if done {
				return nil
			}
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			value := line[5:]
			if len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
			if len(data)+len(value)+1 > maxStreamEvent {
				return &StreamError{"upstream event exceeds limit"}
			}
			data = append(data, value...)
			data = append(data, '\n')
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	// A final data line need not be followed by an empty line.
	done, err := dispatch()
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	return &StreamError{"upstream stream ended before completion"}
}

// StreamFault retains risk classification without retaining the error body.
type StreamFault struct{ Fault Fault }

func (e *StreamFault) Error() string { return "workbuddy: upstream stream " + string(e.Fault.Kind) }

type chatDelta struct {
	Role      string  `json:"role,omitempty"`
	Content   *string `json:"content,omitempty"`
	Reasoning *string `json:"reasoning_content,omitempty"`
	Refusal   *string `json:"refusal,omitempty"`
	ToolCalls []struct {
		Index    int    `json:"index"`
		ID       string `json:"id,omitempty"`
		Type     string `json:"type,omitempty"`
		Function struct {
			Name      string `json:"name,omitempty"`
			Arguments string `json:"arguments,omitempty"`
		} `json:"function"`
	} `json:"tool_calls,omitempty"`
}

type ChatEvent struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Created int64  `json:"created"`
	Choices []struct {
		Index        int             `json:"index"`
		Delta        chatDelta       `json:"delta"`
		FinishReason *string         `json:"finish_reason"`
		Logprobs     json.RawMessage `json:"logprobs,omitempty"`
	} `json:"choices"`
	Usage json.RawMessage `json:"usage,omitempty"`
	Error json.RawMessage `json:"error,omitempty"`
}

// DecodeEvent refuses SSE error envelopes even when the HTTP status was 200.
func DecodeEvent(raw []byte) (ChatEvent, error) {
	var event ChatEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		return event, &StreamError{"invalid upstream chat event"}
	}
	if len(event.Error) > 0 && string(event.Error) != "null" {
		var detail map[string]any
		_ = json.Unmarshal(event.Error, &detail)
		status := 502
		for _, key := range []string{"status", "status_code", "http_status"} {
			if value, ok := detail[key].(float64); ok && value >= 400 && value <= 599 {
				status = int(value)
				break
			}
		}
		if match := codePattern.FindSubmatch(raw); len(match) == 2 {
			code, _ := strconv.Atoi(string(match[1]))
			switch code {
			case 11140:
				status = 403
			case 6004, 14003:
				status = 429
			}
		}
		return event, &StreamFault{Fault: ClassifyHTTP(status, raw)}
	}
	if event.Choices == nil && len(event.Usage) == 0 {
		return event, &StreamError{"unrecognized upstream chat event"}
	}
	for _, choice := range event.Choices {
		if choice.Index < 0 || choice.Index > 127 {
			return event, &StreamError{"invalid upstream choice index"}
		}
		for _, tool := range choice.Delta.ToolCalls {
			if tool.Index < 0 || tool.Index > 1023 {
				return event, &StreamError{"invalid upstream tool index"}
			}
		}
	}
	return event, nil
}

// ObservedTokens returns only vendor-reported usage. Missing usage is distinct
// from an explicit zero and must not be replaced by an estimate.
func ObservedTokens(raw json.RawMessage) (int64, bool) {
	var u struct {
		Total      *int64 `json:"total_tokens"`
		Prompt     *int64 `json:"prompt_tokens"`
		Completion *int64 `json:"completion_tokens"`
	}
	if json.Unmarshal(raw, &u) != nil {
		return 0, false
	}
	if u.Total != nil && *u.Total >= 0 {
		return *u.Total, true
	}
	if u.Prompt != nil && u.Completion != nil && *u.Prompt >= 0 && *u.Completion >= 0 && *u.Prompt <= int64(^uint64(0)>>1)-*u.Completion {
		return *u.Prompt + *u.Completion, true
	}
	return 0, false
}

type collectedTool struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}
type collectedChoice struct {
	role      string
	content   strings.Builder
	reasoning strings.Builder
	refusal   strings.Builder
	tools     map[int]*collectedTool
	finish    *string
	logprobs  []json.RawMessage
}

// Collector retains independent choice/tool indices instead of concatenating
// parallel tool calls into one invalid function invocation.
type Collector struct {
	id, model string
	created   int64
	choices   map[int]*collectedChoice
	usage     json.RawMessage
	size      int
}

func (c *Collector) Add(raw []byte) error {
	if len(raw) > maxCollectedResponse-c.size {
		return &StreamError{"collected response exceeds limit"}
	}
	c.size += len(raw)
	event, err := DecodeEvent(raw)
	if err != nil {
		return err
	}
	if event.ID != "" {
		c.id = event.ID
	}
	if event.Model != "" {
		c.model = event.Model
	}
	if event.Created != 0 {
		c.created = event.Created
	}
	if len(event.Usage) > 0 && string(event.Usage) != "null" {
		c.usage = append(c.usage[:0], event.Usage...)
	}
	if c.choices == nil {
		c.choices = make(map[int]*collectedChoice)
	}
	for _, delta := range event.Choices {
		choice := c.choices[delta.Index]
		if choice == nil {
			choice = &collectedChoice{role: "assistant", tools: make(map[int]*collectedTool)}
			c.choices[delta.Index] = choice
		}
		if delta.Delta.Role != "" {
			choice.role = delta.Delta.Role
		}
		if delta.Delta.Content != nil {
			choice.content.WriteString(*delta.Delta.Content)
		}
		if delta.Delta.Reasoning != nil {
			choice.reasoning.WriteString(*delta.Delta.Reasoning)
		}
		if delta.Delta.Refusal != nil {
			choice.refusal.WriteString(*delta.Delta.Refusal)
		}
		if delta.FinishReason != nil {
			finish := *delta.FinishReason
			choice.finish = &finish
		}
		for _, td := range delta.Delta.ToolCalls {
			tool := choice.tools[td.Index]
			if tool == nil {
				tool = &collectedTool{Type: "function"}
				choice.tools[td.Index] = tool
			}
			if td.ID != "" {
				tool.ID = td.ID
			}
			if td.Type != "" {
				tool.Type = td.Type
			}
			tool.Function.Name += td.Function.Name
			tool.Function.Arguments += td.Function.Arguments
		}
		if len(delta.Logprobs) > 0 && string(delta.Logprobs) != "null" {
			choice.logprobs = append(choice.logprobs, append(json.RawMessage(nil), delta.Logprobs...))
		}
	}
	return nil
}
func (c *Collector) Usage() json.RawMessage { return c.usage }
func (c *Collector) Response() ([]byte, error) {
	if len(c.choices) == 0 {
		return nil, &StreamError{"upstream completed without a choice"}
	}
	indexes := make([]int, 0, len(c.choices))
	for i := range c.choices {
		indexes = append(indexes, i)
	}
	sort.Ints(indexes)
	choices := make([]any, 0, len(indexes))
	for _, i := range indexes {
		choice := c.choices[i]
		if choice.finish == nil {
			return nil, &StreamError{"upstream completed without a finish reason"}
		}
		message := map[string]any{"role": choice.role, "content": choice.content.String()}
		if choice.reasoning.Len() > 0 {
			message["reasoning_content"] = choice.reasoning.String()
		}
		if choice.refusal.Len() > 0 {
			message["refusal"] = choice.refusal.String()
		}
		if len(choice.tools) > 0 {
			ids := make([]int, 0, len(choice.tools))
			for id := range choice.tools {
				ids = append(ids, id)
			}
			sort.Ints(ids)
			tools := make([]*collectedTool, 0, len(ids))
			for _, id := range ids {
				tools = append(tools, choice.tools[id])
			}
			message["tool_calls"] = tools
			if choice.content.Len() == 0 {
				message["content"] = nil
			}
		}
		out := map[string]any{"index": i, "message": message, "finish_reason": choice.finish}
		if len(choice.logprobs) > 0 {
			merged := map[string][]json.RawMessage{}
			for _, raw := range choice.logprobs {
				var part map[string][]json.RawMessage
				if err := json.Unmarshal(raw, &part); err != nil {
					return nil, fmt.Errorf("workbuddy: invalid logprobs")
				}
				for key, items := range part {
					merged[key] = append(merged[key], items...)
				}
			}
			out["logprobs"] = merged
		}
		choices = append(choices, out)
	}
	result := map[string]any{"id": c.id, "object": "chat.completion", "created": c.created, "model": c.model, "choices": choices}
	if len(c.usage) > 0 {
		result["usage"] = c.usage
	}
	return json.Marshal(result)
}
