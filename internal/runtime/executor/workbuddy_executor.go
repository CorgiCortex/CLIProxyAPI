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
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/workbuddy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	execution "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

var _ coreauth.ProviderExecutor = (*WorkBuddyExecutor)(nil)
var _ coreauth.RequestAuthPreparer = (*WorkBuddyExecutor)(nil)

// WorkBuddyExecutor owns no account-specific transport or risk state. Those
// belong to the shared runtime so rotations and reloads cannot bypass gates.
type WorkBuddyExecutor struct {
	cfg     *config.Config
	runtime *helps.WorkBuddyRuntime
	initErr error
}

func NewWorkBuddyExecutor(cfg *config.Config, previous *WorkBuddyExecutor) *WorkBuddyExecutor {
	e := &WorkBuddyExecutor{cfg: cfg}
	if previous != nil {
		e.runtime = previous.runtime
	}
	if cfg == nil || !cfg.WorkBuddy.Enabled {
		e.initErr = fmt.Errorf("workbuddy: provider is disabled")
		return e
	}
	if e.runtime == nil {
		e.runtime, e.initErr = helps.NewWorkBuddyRuntime(cfg.WorkBuddy)
	} else {
		e.initErr = e.runtime.Configure(cfg.WorkBuddy)
	}
	return e
}
func (e *WorkBuddyExecutor) Identifier() string                 { return "workbuddy" }
func (e *WorkBuddyExecutor) UsesConfig(cfg *config.Config) bool { return e.cfg == cfg }
func (e *WorkBuddyExecutor) BindCredentialManager(manager *coreauth.Manager) {
	if e.runtime != nil {
		e.runtime.BindManager(manager)
	}
}
func (e *WorkBuddyExecutor) TrackAuth(a *coreauth.Auth) {
	if e.runtime != nil {
		e.runtime.Track(a)
	}
}
func (e *WorkBuddyExecutor) PrepareExecutionContext(ctx context.Context, _ execution.Request, _ execution.Options) (context.Context, error) {
	if e.initErr != nil {
		return ctx, &workbuddy.DispatchError{Reason: "provider_unavailable", Status: 503, Stop: true}
	}
	return workbuddy.WithRequestState(ctx, e.runtime.Accounts())
}
func (e *WorkBuddyExecutor) ShouldPrepareRequestAuth(a *coreauth.Auth) bool {
	c, err := helps.WorkBuddyCredential(a)
	return err == nil && c.RefreshToken != "" && c.Expiring(time.Now())
}
func (e *WorkBuddyExecutor) PrepareRequestAuth(ctx context.Context, a *coreauth.Auth) (*coreauth.Auth, error) {
	return e.Refresh(ctx, a)
}
func (e *WorkBuddyExecutor) Refresh(ctx context.Context, a *coreauth.Auth) (*coreauth.Auth, error) {
	if e.initErr != nil {
		return nil, e.initErr
	}
	c, err := helps.WorkBuddyCredential(a)
	if err != nil {
		return nil, err
	}
	proxy := c.ProxyURL
	if proxy == "" && e.cfg != nil {
		proxy = e.cfg.ProxyURL
	}
	return e.runtime.Refresh(ctx, a, proxy)
}

// Arbitrary management HTTP requests cannot bypass the provider governor or
// send WorkBuddy credentials to a caller-specified destination.
func (e *WorkBuddyExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, &workbuddy.DispatchError{Reason: "arbitrary_http_requests_are_not_supported", Status: 400, Stop: true}
}

func (e *WorkBuddyExecutor) build(ctx context.Context, c workbuddy.Credential, req execution.Request, opts execution.Options) ([]byte, error) {
	if opts.Alt != "" {
		return nil, &workbuddy.DispatchError{Reason: "unsupported_endpoint", Status: 400, Stop: true}
	}
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	from, to := opts.SourceFormat, sdktranslator.FromString("openai")
	original := req.Payload
	if len(opts.OriginalRequest) > 0 {
		original = opts.OriginalRequest
	}
	originalTranslated, body, changed, err := helps.TranslateRequestPairWithAPIKeyModelCompatibilityAndUpdateIntent(ctx, opts.Headers, e.cfg, from, to, baseModel, original, req.Payload, opts.Stream, helps.APIKeyModelIsCompat(req))
	if err != nil {
		return nil, err
	}
	body = helps.SetStringIfDifferent(body, "model", baseModel)
	body, err = helps.ApplyRequestThinking(body, req, opts, from.String(), to.String(), e.Identifier(), changed)
	if err != nil {
		return nil, err
	}
	body, err = helps.NormalizeWorkBuddyPayload(body, c, baseModel)
	if err != nil {
		return nil, err
	}
	return helps.NewPayloadFinalizer(e.cfg, e.Identifier(), baseModel, to.String(), "", originalTranslated, req, opts)(body), nil
}

func (e *WorkBuddyExecutor) execute(ctx context.Context, a *coreauth.Auth, req execution.Request, opts execution.Options, consume func([]byte, []byte) error) (errResult error) {
	if e.initErr != nil {
		return &workbuddy.DispatchError{Reason: "provider_unavailable", Status: 503, Stop: true}
	}
	ctx, errResult = e.PrepareExecutionContext(ctx, req, opts)
	if errResult != nil {
		return errResult
	}
	state := workbuddy.State(ctx)
	a = e.runtime.Current(a)
	c, err := helps.WorkBuddyCredential(a)
	if err != nil {
		return &workbuddy.DispatchError{Reason: "invalid_credential", Status: 401, Stop: true}
	}
	if c.Expiring(time.Now()) && c.RefreshToken != "" {
		a, err = e.Refresh(ctx, a)
		if err != nil {
			return err
		}
		c, err = helps.WorkBuddyCredential(a)
		if err != nil {
			return err
		}
	}
	caller, _ := opts.Metadata[execution.CallerScopeMetadataKey].(string)
	queue := time.Duration(e.cfg.WorkBuddy.QueueSeconds) * time.Second
	if queue == 0 {
		queue = 30 * time.Second
	}
	release, err := e.runtime.Limiter.Acquire(ctx, caller, queue)
	if err != nil {
		return err
	}
	defer release()
	reporter := helps.NewExecutorUsageReporter(ctx, e, req.Model, a)
	var reportedUsage json.RawMessage
	defer func() {
		detail := helps.ParseOpenAIUsage(append(append([]byte(`{"usage":`), reportedUsage...), '}'))
		if errResult != nil {
			reporter.PublishFailureWithDetail(ctx, detail, errResult)
		} else {
			reporter.Publish(ctx, detail)
		}
	}()
	preOutputRetry := false
	for {
		body, errBuild := e.build(ctx, c, req, opts)
		if errBuild != nil {
			return errBuild
		}
		// Validation after the final barrier is read-only. Explicit conflicting user
		// rules are rejected rather than silently overwritten by provider defaults.
		if len(body) > 16<<20 {
			return &workbuddy.DispatchError{Reason: "request_body_too_large", Status: 413, Stop: true}
		}
		model := gjson.GetBytes(body, "model").String()
		if !gjson.ValidBytes(body) || model == "" || !gjson.GetBytes(body, "stream").Bool() {
			return &workbuddy.DispatchError{Reason: "final_payload_requires_model_and_stream", Status: 400, Stop: true}
		}
		gate, attempt := e.runtime.Governor.Check(c, model, workbuddy.IsPaidModel(c.Realm, model), false)
		if !gate.Allowed() {
			return &workbuddy.DispatchError{Reason: gate.Reason, Status: 429, Stop: gate.Stop, Until: gate.Until}
		}
		if errBegin := state.Begin(); errBegin != nil {
			return errBegin
		}
		session := helps.DerivedSessionID(opts.Metadata, req.Metadata)
		if c.Product == workbuddy.VSCode {
			session = state.Turn
		}
		headers, order, errHeaders := workbuddy.IdentityHeaders(c, workbuddy.DefaultVersions(), session, state.Turn, model, time.Now())
		if errHeaders != nil {
			return errHeaders
		}
		framed, encoding, errFrame := workbuddy.Frame(c.Product, body)
		if errFrame != nil {
			return errFrame
		}
		if encoding != "" {
			headers.Set("Content-Encoding", encoding)
		}
		base, _, errBase := workbuddy.Endpoint(c.Realm, c.Product)
		if errBase != nil {
			return errBase
		}
		if e.runtime.BaseURL != "" {
			base = e.runtime.BaseURL
		}
		proxy := c.ProxyURL
		if proxy == "" {
			proxy = e.cfg.ProxyURL
		}
		if override := execution.RequestProxyURL(ctx); override != "" {
			proxy = override
		}
		client, errClient := e.runtime.Transports.Client(c, base, proxy, order)
		if errClient != nil {
			return errClient
		}
		httpReq, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(base, "/")+"/v2/chat/completions", bytes.NewReader(framed))
		if errRequest != nil {
			return errRequest
		}
		httpReq.Header = headers
		client = reporter.TrackHTTPClient(client)
		reporter.SetTranslatedReasoningEffort(body, "openai")
		execution.MarkUpstreamAttempt(ctx)
		response, errDo := client.Do(httpReq)
		if errDo != nil {
			return e.recordFailure(c, model, state, workbuddy.ClassifyTransport(errDo))
		}
		reporter.ObserveResponse(response)
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			raw, errRead := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			closeWorkBuddyBody(response.Body)
			if errRead != nil {
				return e.recordFailure(c, model, state, workbuddy.ClassifyTransport(errRead))
			}
			fault := workbuddy.ClassifyHTTP(response.StatusCode, raw)
			if fault.Kind == workbuddy.FaultAuth && c.RefreshToken != "" && state.Refresh(c) {
				updated, errRefresh := e.runtime.Refresh(ctx, a, proxy)
				if errRefresh == nil {
					a = updated
					c, err = helps.WorkBuddyCredential(a)
					if err != nil {
						return err
					}
					continue
				}
			}
			return e.recordFailure(c, model, state, fault)
		}
		emitted := false
		var usage json.RawMessage
		var tokens int64
		finished := make(map[int]bool)
		errStream := workbuddy.ReadEvents(response.Body, func(raw []byte) error {
			event, errEvent := workbuddy.DecodeEvent(raw)
			if errEvent != nil {
				return errEvent
			}
			if len(event.Usage) > 0 && string(event.Usage) != "null" {
				usage = append(usage[:0], event.Usage...)
				if observed, ok := workbuddy.ObservedTokens(usage); ok {
					tokens = observed
				}
			}
			reporter.ObserveResponseModel(raw)
			reporter.ObserveTokenEvent(gjson.GetBytes(raw, "choices.0.delta.content").String() != "" || gjson.GetBytes(raw, "choices.0.delta.reasoning_content").String() != "" || gjson.GetBytes(raw, "choices.0.delta.tool_calls.#").Int() > 0)
			for _, choice := range event.Choices {
				if choice.FinishReason != nil {
					finished[choice.Index] = true
				} else if _, ok := finished[choice.Index]; !ok {
					finished[choice.Index] = false
				}
			}
			if errConsume := consume(raw, body); errConsume != nil {
				return errConsume
			}
			emitted = true
			return nil
		})
		closeWorkBuddyBody(response.Body)
		if errStream == nil {
			if len(finished) == 0 {
				errStream = &workbuddy.StreamError{Reason: "upstream completed without a choice"}
			}
			for _, done := range finished {
				if !done {
					errStream = &workbuddy.StreamError{Reason: "upstream completed without a finish reason"}
					break
				}
			}
		}
		if len(usage) > 0 {
			reportedUsage = usage
		}
		if errComplete := e.runtime.Governor.Complete(c, attempt, tokens, nil, errStream == nil); errComplete != nil {
			return &workbuddy.DispatchError{Reason: "usage_persistence_failed", Status: 503, Stop: true}
		}
		if errStream == nil {
			return consume([]byte("[DONE]"), body)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var upstreamFault *workbuddy.StreamFault
		if errors.As(errStream, &upstreamFault) {
			failure := e.recordFailure(c, model, state, upstreamFault.Fault)
			var dispatch *workbuddy.DispatchError
			if emitted && errors.As(failure, &dispatch) {
				dispatch.Stop = true
			}
			return failure
		}
		if !emitted && !preOutputRetry {
			var streamError *workbuddy.StreamError
			fault := workbuddy.ClassifyTransport(errStream)
			if errors.As(errStream, &streamError) {
				fault.Kind = workbuddy.FaultConnection
			}
			if fault.Kind == workbuddy.FaultConnection {
				preOutputRetry = true
				continue
			}
		}
		failure := e.recordFailure(c, model, state, workbuddy.Fault{Kind: workbuddy.FaultUnknown, Status: 502})
		// Once output escaped, no SDK credential rotation may replay the prompt.
		var dispatch *workbuddy.DispatchError
		if errors.As(failure, &dispatch) {
			dispatch.Stop = true
		}
		return failure
	}
}
func (e *WorkBuddyExecutor) recordFailure(c workbuddy.Credential, model string, state *workbuddy.RequestState, fault workbuddy.Fault) error {
	// Hard/unknown failures count once per UID per logical request. Explicit
	// scopes and caps always apply, including new evidence after refresh.
	charge := true
	if fault.Kind == workbuddy.FaultHard || fault.Kind == workbuddy.FaultUnknown {
		charge = state.Charge(c)
	}
	failure := workbuddy.ErrorForFault(fault)
	if charge {
		gate, err := e.runtime.Governor.RecordFailure(c, model, fault, workbuddy.FailureOptions{FreeModel: workbuddy.IsFreeCapModel(c.Realm, model), SingleAccount: e.runtime.Accounts() <= 1})
		if err != nil {
			return &workbuddy.DispatchError{Reason: "risk_persistence_failed", Status: 503, Stop: true}
		}
		failure.Until = gate.Until
		failure.Stop = failure.Stop || gate.Stop
	}
	return failure
}
func closeWorkBuddyBody(body io.Closer) {
	if err := body.Close(); err != nil {
		log.WithField("provider", "workbuddy").Debug("upstream body close failed")
	}
}

func (e *WorkBuddyExecutor) Execute(ctx context.Context, a *coreauth.Auth, req execution.Request, opts execution.Options) (execution.Response, error) {
	var collector workbuddy.Collector
	var finalBody []byte
	err := e.execute(ctx, a, req, opts, func(raw, body []byte) error {
		finalBody = body
		if bytes.Equal(raw, []byte("[DONE]")) {
			return nil
		}
		return collector.Add(raw)
	})
	if err != nil {
		return execution.Response{}, err
	}
	body, err := collector.Response()
	if err != nil {
		return execution.Response{}, err
	}
	var param any
	out := sdktranslator.TranslateNonStream(ctx, sdktranslator.FromString("openai"), execution.ResponseFormatOrSource(opts), req.Model, helps.ApplyPatchOriginalRequest(req, opts), finalBody, body, &param)
	return execution.Response{Payload: out}, nil
}
func (e *WorkBuddyExecutor) ExecuteStream(ctx context.Context, a *coreauth.Auth, req execution.Request, opts execution.Options) (*execution.StreamResult, error) {
	if e.initErr != nil {
		return nil, &workbuddy.DispatchError{Reason: "provider_unavailable", Status: 503, Stop: true}
	}
	out := make(chan execution.StreamChunk)
	go func() {
		defer close(out)
		var param any
		err := e.execute(ctx, a, req, opts, func(raw, body []byte) error {
			line := append([]byte("data: "), raw...)
			chunks := sdktranslator.TranslateStream(ctx, sdktranslator.FromString("openai"), execution.ResponseFormatOrSource(opts), req.Model, helps.ApplyPatchOriginalRequest(req, opts), body, line, &param)
			for _, chunk := range chunks {
				select {
				case out <- execution.StreamChunk{Payload: chunk}:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
		if err != nil {
			select {
			case out <- execution.StreamChunk{Err: err}:
			case <-ctx.Done():
			}
		}
	}()
	return &execution.StreamResult{Chunks: out}, nil
}
func (e *WorkBuddyExecutor) CountTokens(ctx context.Context, a *coreauth.Auth, req execution.Request, opts execution.Options) (execution.Response, error) {
	if e.initErr != nil {
		return execution.Response{}, e.initErr
	}
	c, err := helps.WorkBuddyCredential(a)
	if err != nil {
		return execution.Response{}, err
	}
	body, err := e.build(ctx, c, req, opts)
	if err != nil {
		return execution.Response{}, err
	}
	enc, err := helps.TokenizerForModel(thinking.ParseSuffix(req.Model).ModelName)
	if err != nil {
		return execution.Response{}, err
	}
	count, err := helps.CountOpenAIChatTokens(enc, body)
	if err != nil {
		return execution.Response{}, err
	}
	result := sdktranslator.TranslateTokenCount(ctx, sdktranslator.FromString("openai"), execution.ResponseFormatOrSource(opts), count, helps.BuildOpenAIUsageJSON(count))
	return execution.Response{Payload: result}, nil
}
