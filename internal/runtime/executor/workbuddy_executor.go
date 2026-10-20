package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
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
	cfg          *config.Config
	runtime      *helps.WorkBuddyRuntime
	initErr      error
	runtimeEpoch uint64
}

func NewWorkBuddyExecutor(cfg *config.Config, previous *WorkBuddyExecutor) *WorkBuddyExecutor {
	e := &WorkBuddyExecutor{cfg: cfg}
	if previous != nil {
		e.runtime = previous.runtime
	}
	if cfg == nil || !cfg.WorkBuddy.Enabled {
		if e.runtime != nil {
			e.runtime.CancelMaintenance()
		}
		e.initErr = fmt.Errorf("workbuddy: provider is disabled")
		return e
	}
	if e.runtime == nil {
		e.runtime, e.initErr = helps.NewWorkBuddyRuntime(cfg.WorkBuddy)
	} else {
		e.initErr = e.runtime.Configure(cfg.WorkBuddy)
	}
	if e.runtime != nil {
		e.runtimeEpoch = e.runtime.MaintenanceEpoch()
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

func (e *WorkBuddyExecutor) ModelCatalog(a *coreauth.Auth) ([]workbuddy.Model, error) {
	if e.initErr != nil {
		return nil, e.initErr
	}
	c, err := helps.WorkBuddyCredential(a)
	if err != nil {
		return nil, err
	}
	return e.runtime.Models(c)
}

func (e *WorkBuddyExecutor) RunMaintenance(ctx context.Context) ([]string, error) {
	if e.initErr != nil {
		return nil, e.initErr
	}
	return e.runtime.Maintenance(ctx, e.cfg, e.runtimeEpoch, func(ctx context.Context, auth *coreauth.Auth, model string) error {
		probeExecutor := *e
		probeConfig := *e.cfg
		probeConfig.WorkBuddy.PaidFallback = false
		probeConfig.WorkBuddy.AutoSwitchProduct = false
		probeConfig.WorkBuddy.Prompt = config.WorkBuddyPrompt{Mode: "custom", Text: workbuddy.DegradedPrompt}
		probeExecutor.cfg = &probeConfig
		payload, err := json.Marshal(map[string]any{
			"model":      model,
			"messages":   []map[string]string{{"role": "user", "content": "Reply with OK."}},
			"max_tokens": 16,
		})
		if err != nil {
			return err
		}
		opts := execution.Options{SourceFormat: sdktranslator.FromString("openai"), Metadata: map[string]any{
			execution.ExecutionSessionMetadataKey: "workbuddy-quota-probe:" + model,
		}}
		_, err = probeExecutor.Execute(ctx, auth, execution.Request{Model: model, Payload: payload}, opts)
		return err
	})
}
func (e *WorkBuddyExecutor) PrepareExecutionContext(ctx context.Context, req execution.Request, opts execution.Options) (context.Context, error) {
	if e.initErr != nil {
		return ctx, &workbuddy.DispatchError{Reason: "provider_unavailable", Status: 503, Stop: true}
	}
	if workbuddy.State(ctx) != nil {
		return ctx, nil
	}
	extra := 0
	if e.cfg.WorkBuddy.AutoSwitchProduct {
		extra = 4
	}
	next, err := workbuddy.WithRequestState(ctx, e.runtime.Accounts(), extra)
	if err != nil {
		return ctx, err
	}
	prefix, maxMessages, pageSize := true, 400, 3
	if e.cfg.WorkBuddy.AffinityByPrefix != nil {
		prefix = *e.cfg.WorkBuddy.AffinityByPrefix
	}
	if e.cfg.WorkBuddy.AffinityMaxMessages != nil {
		maxMessages = *e.cfg.WorkBuddy.AffinityMaxMessages
	}
	if e.cfg.WorkBuddy.AffinityPageSize != nil {
		pageSize = *e.cfg.WorkBuddy.AffinityPageSize
	}
	caller, _ := opts.Metadata[execution.CallerScopeMetadataKey].(string)
	explicit, _ := opts.Metadata[execution.ExecutionSessionMetadataKey].(string)
	if explicit == "" {
		for _, key := range []string{"X-Conversation-Id", "X-Session-Id", "Session_id", "X-Codex-Session-Id"} {
			if value := opts.Headers.Get(key); value != "" {
				explicit = value
				break
			}
		}
	}
	if explicit == "" {
		for _, key := range []string{"conversation_id", "session_id", "metadata.session_id"} {
			if value := gjson.GetBytes(req.Payload, key).String(); value != "" {
				explicit = value
				break
			}
		}
	}
	payload := sdktranslator.TranslateRequest(opts.SourceFormat, sdktranslator.FromString("openai"), req.Model, req.Payload, opts.Stream)
	workbuddy.State(next).Route = workbuddy.SessionRouting(caller, explicit, payload, prefix, maxMessages, pageSize)
	return next, nil
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

func (e *WorkBuddyExecutor) build(ctx context.Context, c workbuddy.Credential, req execution.Request, opts execution.Options, override ...string) ([]byte, error) {
	if opts.Alt != "" {
		return nil, &workbuddy.DispatchError{Reason: "unsupported_endpoint", Status: 400, Stop: true}
	}
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	if len(override) > 0 && override[0] != "" {
		baseModel = override[0]
	}
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
	body, err = helps.NormalizeWorkBuddyPayload(body, c, baseModel, helps.WorkBuddyPrompt(e.cfg.WorkBuddy.Prompt, e.runtime.Policy.Degraded()))
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
	paidModel := ""
	for {
		body, errBuild := e.build(ctx, c, req, opts, paidModel)
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
			if !gate.Stop && gate.Reason == "model_cooldown" && e.paidFallback(c, model, state, paidModel) {
				paidModel = "deepseek-v4.1-flash-sg"
				continue
			}
			return &workbuddy.DispatchError{Reason: gate.Reason, Status: 429, Stop: gate.Stop, Until: gate.Until}
		}
		if errBegin := state.Begin(); errBegin != nil {
			return errBegin
		}
		session := helps.DerivedSessionID(opts.Metadata, req.Metadata)
		if state.Route.Key != "" {
			session = state.Route.Key
		}
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
			return e.connectionFailure(ctx, c, model, state, workbuddy.ClassifyTransport(errDo), base, proxy)
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
			updated, failure, retry := e.recoverFailure(ctx, a, c, model, state, fault, base, proxy, paidModel == "")
			if retry {
				if updated != nil {
					a = updated
					c, err = helps.WorkBuddyCredential(a)
					if err != nil {
						return err
					}
				}
				continue
			}
			if fault.Kind == workbuddy.FaultModelCap && e.paidFallback(c, model, state, paidModel) {
				paidModel = "deepseek-v4.1-flash-sg"
				continue
			}
			return failure
		}
		emitted := false
		var usage json.RawMessage
		var tokens int64
		var credits *float64
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
				if observed := workbuddy.ObservedCredits(usage); observed != nil {
					credits = observed
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
		if errComplete := e.runtime.Governor.Complete(c, attempt, tokens, credits, errStream == nil); errComplete != nil {
			return &workbuddy.DispatchError{Reason: "usage_persistence_failed", Status: 503, Stop: true}
		}
		if errStream == nil {
			e.runtime.Policy.ProductSuccess(c, model)
			if e.cfg.WorkBuddy.EgressBackoff {
				e.runtime.Policy.ExitSuccess(base, proxy)
			}
			return consume([]byte("[DONE]"), body)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var upstreamFault *workbuddy.StreamFault
		if errors.As(errStream, &upstreamFault) {
			if !emitted {
				updated, failure, retry := e.recoverFailure(ctx, a, c, model, state, upstreamFault.Fault, base, proxy, paidModel == "")
				if retry {
					if updated != nil {
						a = updated
						c, err = helps.WorkBuddyCredential(a)
						if err != nil {
							return err
						}
					}
					continue
				}
				if upstreamFault.Fault.Kind == workbuddy.FaultModelCap && e.paidFallback(c, model, state, paidModel) {
					paidModel = "deepseek-v4.1-flash-sg"
					continue
				}
				return failure
			}
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
				if e.cfg.WorkBuddy.EgressBackoff {
					if errWait := e.runtime.Policy.Backoff(ctx, state, base, proxy); errWait != nil {
						return errWait
					}
				}
				continue
			}
		}
		var failure error
		if e.cfg.WorkBuddy.EgressBackoff {
			failure = e.connectionFailure(ctx, c, model, state, workbuddy.Fault{Kind: workbuddy.FaultConnection, Status: 502}, base, proxy)
		} else {
			failure = e.recordFailure(c, model, state, workbuddy.Fault{Kind: workbuddy.FaultUnknown, Status: 502})
		}
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
	e.runtime.Affinity.Demote(c.Realm, state.Route, c.UID)
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

// recoverFailure runs only before downstream output. Each retry rebuilds from
// the original request and crosses the payload finalizer once again.
func (e *WorkBuddyExecutor) recoverFailure(ctx context.Context, a *coreauth.Auth, c workbuddy.Credential, model string, state *workbuddy.RequestState, fault workbuddy.Fault, base, proxy string, allowSwitch bool) (*coreauth.Auth, error, bool) {
	if fault.Kind == workbuddy.FaultContent && e.cfg.WorkBuddy.Prompt.Mode != "custom" && state.TryDegrade() {
		e.runtime.Policy.Degrade()
		return nil, nil, true
	}
	if fault.Kind == workbuddy.FaultGateway && e.cfg.WorkBuddy.EgressBackoff {
		return nil, e.connectionFailure(ctx, c, model, state, fault, base, proxy), false
	}
	failure := e.recordFailure(c, model, state, fault)
	var dispatch *workbuddy.DispatchError
	if !errors.As(failure, &dispatch) || dispatch.Stop {
		return nil, failure, false
	}
	if allowSwitch && e.cfg.WorkBuddy.AutoSwitchProduct && (fault.Kind == workbuddy.FaultModelRate || fault.Kind == workbuddy.FaultModelCap) && !e.runtime.Governor.Capped(c, model) {
		allowed := make([]workbuddy.Product, 0, len(e.cfg.WorkBuddy.AutoSwitchProducts))
		for _, p := range e.cfg.WorkBuddy.AutoSwitchProducts {
			allowed = append(allowed, workbuddy.Product(p))
		}
		if next, ok := e.runtime.Policy.NextProduct(c, model, allowed); ok {
			updated, err := e.runtime.SwitchProduct(ctx, a, next)
			if err == nil && e.runtime.Governor.ClearIdentityModelCooldown(c, model) {
				return updated, nil, true
			}
		}
	}
	return nil, failure, false
}
func (e *WorkBuddyExecutor) connectionFailure(ctx context.Context, c workbuddy.Credential, model string, state *workbuddy.RequestState, fault workbuddy.Fault, base, proxy string) error {
	if e.cfg.WorkBuddy.EgressBackoff && (fault.Kind == workbuddy.FaultGateway || fault.Kind == workbuddy.FaultConnection) {
		if err := e.runtime.Policy.Backoff(ctx, state, base, proxy); err != nil {
			return err
		}
		return workbuddy.ErrorForFault(fault)
	}
	return e.recordFailure(c, model, state, fault)
}
func (e *WorkBuddyExecutor) paidFallback(c workbuddy.Credential, model string, state *workbuddy.RequestState, current string) bool {
	return current == "" && e.cfg.WorkBuddy.PaidFallback && c.Realm == workbuddy.International && model == "deepseek-v4.1-flash" && e.runtime.AllFreeCapped(c.Realm, model) && state.TryPaidFallback()
}

// SelectAuth runs after SDK model, pin, caller eligibility and priority checks.
// It never introduces a credential outside the candidate set supplied by SDK.
func (e *WorkBuddyExecutor) SelectAuth(ctx context.Context, model string, opts execution.Options, candidates []*coreauth.Auth) (*coreauth.Auth, error) {
	if len(candidates) == 0 {
		return nil, &workbuddy.DispatchError{Reason: "no_eligible_credentials", Status: 503, Stop: true}
	}
	state := workbuddy.State(ctx)
	if state == nil {
		return candidates[0], nil
	}
	baseModel := thinking.ParseSuffix(model).ModelName
	byRealm := make(map[workbuddy.Realm]map[string]*coreauth.Auth)
	for _, candidate := range candidates {
		c, err := helps.WorkBuddyCredential(candidate)
		if err != nil {
			continue
		}
		gate, _ := e.runtime.Governor.Check(c, baseModel, workbuddy.IsPaidModel(c.Realm, baseModel), false)
		eligible := gate.Allowed() || gate.Reason == "credential_expired" && c.RefreshToken != ""
		if !eligible && gate.Reason == "model_cooldown" && e.cfg.WorkBuddy.PaidFallback && baseModel == "deepseek-v4.1-flash" && c.Realm == workbuddy.International && e.runtime.AllFreeCapped(c.Realm, baseModel) {
			paidGate, _ := e.runtime.Governor.Check(c, "deepseek-v4.1-flash-sg", true, false)
			eligible = paidGate.Allowed()
		}
		if !eligible {
			continue
		}
		if byRealm[c.Realm] == nil {
			byRealm[c.Realm] = make(map[string]*coreauth.Auth)
		}
		previous := byRealm[c.Realm][c.UID]
		if previous == nil || candidate.ID < previous.ID {
			byRealm[c.Realm][c.UID] = candidate
		}
	}
	// Shared model names prefer the international realm. Explicit auth prefixes
	// and pins are already narrowed by SDK and preserve China-only routes.
	for _, realm := range []workbuddy.Realm{workbuddy.International, workbuddy.China} {
		group := byRealm[realm]
		if len(group) == 0 {
			continue
		}
		eligible := make([]string, 0, len(group))
		for uid := range group {
			eligible = append(eligible, uid)
		}
		allSet := make(map[string]bool)
		for _, c := range e.runtime.Credentials() {
			if c.Realm == realm {
				allSet[c.UID] = true
			}
		}
		all := make([]string, 0, len(allSet))
		for uid := range allSet {
			all = append(all, uid)
		}
		uid := e.runtime.Affinity.Pick(realm, state.Route, eligible, all)
		return group[uid], nil
	}
	// Let the executor report the precise gate and the SDK's normal retry loop
	// handle exhausted tiers. Selection itself must not bypass a restriction.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	return candidates[0], nil
}
