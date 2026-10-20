package workbuddy

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestWorkBuddySSEFramingAndCollection(t *testing.T) {
	input := ": heartbeat\r\ndata: {\r\ndata: \"id\":\"chat-1\",\"model\":\"test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"reasoning_content\":\"think\",\"tool_calls\":[{\"index\":1,\"id\":\"b\",\"function\":{\"name\":\"second\",\"arguments\":\"{\"}},{\"index\":0,\"id\":\"a\",\"function\":{\"name\":\"first\",\"arguments\":\"{}\"}}]}}]}\r\n\r\n" +
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"}"}}]},"finish_reason":"tool_calls"}]}` + "\n\n" +
		`data: {"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":3,"total_tokens":15}}` + "\n\n" + "data: [DONE]"
	var collector Collector
	if err := ReadEvents(strings.NewReader(input), collector.Add); err != nil {
		t.Fatal(err)
	}
	raw, err := collector.Response()
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"choices.0.message.tool_calls.0.id": "a", "choices.0.message.tool_calls.1.id": "b", "choices.0.message.tool_calls.1.function.arguments": "{}", "choices.0.message.reasoning_content": "think", "usage.total_tokens": "15", "choices.0.finish_reason": "tool_calls"} {
		if got := gjson.GetBytes(raw, path).String(); got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
	if n, ok := ObservedTokens(collector.Usage()); !ok || n != 15 {
		t.Fatalf("usage = %d %v", n, ok)
	}
}
func TestWorkBuddyStreamFailuresAreNotCompleted(t *testing.T) {
	for _, input := range []string{
		"", `data: {"choices":[{"index":0,"delta":{"content":"partial"}}]}` + "\n\n",
		"data: not-json\n\n", `data: {"error":{"message":"secret-token"}}` + "\n\ndata: [DONE]\n\n",
		`data: {"choices":[{"index":-1,"delta":{}}]}` + "\n\ndata: [DONE]\n\n",
	} {
		var c Collector
		err := ReadEvents(strings.NewReader(input), c.Add)
		if err == nil {
			t.Fatalf("accepted malformed stream %q", input)
		}
		if strings.Contains(err.Error(), "secret-token") {
			t.Fatal("error leaked upstream body")
		}
	}
	var c Collector
	if err := ReadEvents(strings.NewReader(`data: {"choices":[{"index":0,"delta":{"content":"partial"}}]}`+"\n\ndata: [DONE]\n\n"), c.Add); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Response(); err == nil {
		t.Fatal("accepted missing finish reason")
	}
}
func TestWorkBuddySSEConsumerErrorStopsImmediately(t *testing.T) {
	want := errors.New("downstream canceled")
	calls := 0
	err := ReadEvents(strings.NewReader("data: {}\n\ndata: {}\n\n"), func([]byte) error { calls++; return want })
	if !errors.Is(err, want) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
func TestWorkBuddySSEReadErrorPreserved(t *testing.T) {
	err := ReadEvents(errorReader{}, func([]byte) error { return nil })
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestWorkBuddyObservedTokensMissingAndOverflow(t *testing.T) {
	for _, raw := range []string{`{}`, `{"total_tokens":-1}`, `{"prompt_tokens":9223372036854775807,"completion_tokens":1}`, `null`} {
		if n, ok := ObservedTokens([]byte(raw)); ok {
			t.Fatalf("invented usage %d for %s", n, raw)
		}
	}
}
