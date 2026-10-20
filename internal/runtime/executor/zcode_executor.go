package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps/zcode"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	exec "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

var _ coreauth.ProviderExecutor = (*ZCodeExecutor)(nil)

// ZCodeExecutor implements both ZCode plans using the existing protocol pipeline.
type ZCodeExecutor struct {
	cfg      *config.Config
	limiter  *zcode.Limiter
	signer   *zcode.Signer
	projects *zcode.ProjectTokens
	routes   *zcode.Routes
}

func NewZCodeExecutor(cfg *config.Config) *ZCodeExecutor {
	if cfg == nil {
		cfg = &config.Config{}
	}
	return &ZCodeExecutor{cfg: cfg, limiter: zcode.NewLimiter(), signer: zcode.NewSigner(), projects: zcode.NewProjectTokens(), routes: zcode.NewRoutes()}
}

// WithConfig preserves in-flight permits and signing state across config reloads.
func (e *ZCodeExecutor) WithConfig(cfg *config.Config) *ZCodeExecutor {
	return &ZCodeExecutor{cfg: cfg, limiter: e.limiter, signer: e.signer, projects: e.projects, routes: e.routes}
}

func (e *ZCodeExecutor) Identifier() string { return "zcode" }

func (e *ZCodeExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	if _, err := zcode.ReadCredential(auth); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("zcode: automatic login refresh is unavailable; re-authenticate this account")
}

func (e *ZCodeExecutor) CountTokens(context.Context, *coreauth.Auth, exec.Request, exec.Options) (exec.Response, error) {
	return exec.Response{}, statusErr{code: http.StatusNotImplemented, msg: "zcode: token counting is not supported"}
}

// HttpRequest rejects raw calls so they cannot bypass admission, signing or the
// final payload barrier. Inference uses Execute/ExecuteStream exclusively.
func (e *ZCodeExecutor) HttpRequest(ctx context.Context, auth *coreauth.Auth, req *http.Request) (*http.Response, error) {
	return nil, &zcode.RequestError{Code: 501, Message: "zcode: raw authenticated HTTP calls are not supported"}
}

func (e *ZCodeExecutor) client(ctx context.Context, auth *coreauth.Auth) *http.Client {
	client := *helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}

func (e *ZCodeExecutor) prepare(ctx context.Context, req exec.Request, opts exec.Options, stream bool, c zcode.Credential, session string) ([]byte, error) {
	if opts.Alt != "" {
		return nil, statusErr{code: 501, msg: "zcode: alternate operations are not supported"}
	}
	if !gjson.ValidBytes(req.Payload) {
		return nil, statusErr{code: 400, msg: "zcode: invalid JSON request"}
	}
	if gjson.GetBytes(req.Payload, "background").Bool() {
		return nil, statusErr{code: 400, msg: "zcode: background responses are not supported"}
	}
	model := thinking.ParseSuffix(req.Model).ModelName
	original := req.Payload
	if len(opts.OriginalRequest) > 0 {
		original = opts.OriginalRequest
	}
	originalTranslated := translator.TranslateRequest(opts.SourceFormat, translator.FormatClaude, model, bytes.Clone(original), stream)
	body, err := helps.TranslateRequestReturningError(ctx, opts.Headers, e.cfg, opts.SourceFormat, translator.FormatClaude, model, bytes.Clone(req.Payload), stream, false)
	if err != nil {
		return nil, err
	}
	body = helps.SetStringIfDifferent(body, "model", model)
	body = helps.SetBoolIfDifferent(body, "stream", stream)
	body, err = helps.ApplyRequestThinking(body, req, opts, opts.SourceFormat.String(), "claude", e.Identifier())
	if err != nil {
		return nil, err
	}
	body, err = zcode.AdaptPayload(body, c, session, e.cfg.ZCode.StartPlanSystem)
	if err != nil {
		return nil, err
	}
	// No business payload mutation is allowed beyond this barrier, including retries.
	finalize := helps.NewPayloadFinalizer(e.cfg, e.Identifier(), model, "claude", "", originalTranslated, req, opts)
	return finalize(body), nil
}

func (e *ZCodeExecutor) dispatch(ctx context.Context, auth *coreauth.Auth, req exec.Request, opts exec.Options, stream bool) (*http.Response, []byte, func(), error) {
	ctx = exec.WithProviderAttemptBudget(ctx, e.Identifier(), 3)
	c, err := zcode.ReadCredential(auth)
	if err != nil {
		return nil, nil, nil, statusErr{code: 401, msg: err.Error()}
	}
	session, _ := opts.Metadata[exec.CanonicalSessionIDMetadataKey].(string)
	if session == "" {
		session = uuid.NewString()
	}
	scope := sha256.Sum256([]byte(auth.ID + "\n" + session))
	session = hex.EncodeToString(scope[:16])
	if c.DeviceID == "" {
		c.DeviceID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(auth.ID)).String()
	}
	body, err := e.prepare(ctx, req, opts, stream, c, session)
	if err != nil {
		return nil, nil, nil, err
	}
	release, err := e.limiter.Acquire(auth.ID, e.cfg.ZCode.MaxConcurrent, time.Duration(e.cfg.ZCode.MinIntervalMS)*time.Millisecond)
	if err != nil {
		return nil, nil, nil, err
	}
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	client := e.client(ctx, auth)
	version := e.cfg.ZCode.AppVersion
	if version == "" {
		version = "3.16.2"
	}
	target, includeJWT, err := e.routes.Resolve(ctx, client, auth.ID, c, version)
	if err != nil {
		return nil, nil, nil, &zcode.RequestError{Code: 503, Message: err.Error()}
	}
	for attempt := 0; attempt < 2; attempt++ {
		signingCredential := c.APIKey
		out, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
		if errRequest != nil {
			return nil, nil, nil, errRequest
		}
		out.Header.Set("Content-Type", "application/json")
		out.Header.Set("Anthropic-Version", "2023-06-01")
		out.Header.Set("User-Agent", "ZCode/"+version)
		out.Header.Set("X-ZCode-App-Version", version)
		out.Header.Set("X-ZCode-Agent", "glm")
		out.Header.Set("HTTP-Referer", "https://zcode.z.ai/")
		out.Header.Set("X-Request-Id", uuid.NewString())
		out.Header.Set("X-Session-Id", session)
		if includeJWT {
			out.Header.Set("X-ZCode-Authorization", "Bearer "+c.JWT)
		}
		if c.Plan == "start-plan" {
			// The loopback worker is a separate trust boundary and never sees credentials.
			local := &http.Client{CheckRedirect: client.CheckRedirect}
			token, errCaptcha := zcode.TakeCaptcha(ctx, local, e.cfg.ZCode.CaptchaURL, version)
			if errCaptcha != nil {
				return nil, nil, nil, &zcode.RequestError{Code: 503, Message: errCaptcha.Error()}
			}
			out.Header.Set("Authorization", "Bearer "+c.JWT)
			out.Header.Set("X-Aliyun-Captcha-Verify-Param", token.VerifyParam)
			if token.Region != "" {
				out.Header.Set("X-Aliyun-Captcha-Verify-Region", token.Region)
			}
		} else {
			out.Header.Set("Authorization", "Bearer "+c.APIKey)
			out.Header.Set("X-Api-Key", c.APIKey)
			var errProject error
			signingCredential, errProject = e.projects.Resolve(ctx, client, auth.ID, c, version)
			if errProject != nil {
				return nil, nil, nil, statusErr{code: 503, msg: errProject.Error()}
			}
			if errSign := e.signer.Sign(ctx, client, out, auth.ID, signingCredential, version, session); errSign != nil {
				return nil, nil, nil, statusErr{code: 503, msg: errSign.Error()}
			}
		}
		if !exec.TakeProviderAttempt(ctx, e.Identifier()) {
			return nil, nil, nil, &zcode.RequestError{Code: 429, Message: "zcode: inference attempt budget exhausted"}
		}
		started := time.Now()
		resp, errDo := client.Do(out)
		if errDo != nil {
			return nil, nil, nil, errDo
		}
		log.WithFields(log.Fields{"provider": "zcode", "family": c.Family, "plan": c.Plan, "model": req.Model, "status": resp.StatusCode, "attempt": attempt + 1, "headers_ms": time.Since(started).Milliseconds()}).Debug("zcode upstream response")
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			success = true
			return resp, body, release, nil
		}
		errorBody, errRead := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if errClose := resp.Body.Close(); errClose != nil {
			log.WithError(errClose).Warn("zcode: close rejected response")
		}
		if errRead != nil {
			return nil, nil, nil, errRead
		}
		challenge := c.Plan == "start-plan" && (resp.Header.Get("X-Aliyun-Captcha-Verify-Param") != "" || gjson.GetBytes(errorBody, "code").Int() == 3007)
		signature := c.Plan == "coding-plan" && resp.StatusCode == 401 && (bytes.Contains(errorBody, []byte("VERIFY_SIGNATURE_INVALID")) || bytes.Contains(errorBody, []byte("VERIFY_APIKEY_EXPIRED")))
		if attempt == 0 && (challenge || signature) {
			if signature {
				e.signer.Invalidate(auth.ID, out.URL.Scheme+"://"+out.URL.Host, signingCredential)
			}
			continue
		}
		if challenge || signature {
			return nil, nil, nil, &zcode.RequestError{Code: 503, Message: "zcode: verification rejected after renewal"}
		}
		// Error bodies may contain credential echoes. Return only status and a stable category.
		return nil, nil, nil, statusErr{code: resp.StatusCode, msg: fmt.Sprintf("zcode: upstream request rejected (HTTP %d)", resp.StatusCode), retryAfter: helps.ParseClaudeRateLimitResetForError(resp.Header, errorBody, time.Now())}
	}
	return nil, nil, nil, statusErr{code: 502, msg: "zcode: verification retry exhausted"}
}

func (e *ZCodeExecutor) Execute(ctx context.Context, auth *coreauth.Auth, req exec.Request, opts exec.Options) (result exec.Response, err error) {
	reporter := helps.NewUsageReporter(ctx, e.Identifier(), req.Model, auth)
	defer reporter.TrackFailure(ctx, &err)
	resp, body, release, err := e.dispatch(ctx, auth, req, opts, false)
	if err != nil {
		return result, err
	}
	defer release()
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.WithError(errClose).Warn("zcode: close response")
		}
	}()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}
	if !gjson.ValidBytes(data) || gjson.GetBytes(data, "type").String() != "message" {
		return result, statusErr{code: 502, msg: "zcode: invalid upstream message"}
	}
	reporter.Publish(ctx, helps.ParseClaudeUsage(data))
	original := opts.OriginalRequest
	if len(original) == 0 {
		original = req.Payload
	}
	var param any
	result.Payload = translator.TranslateNonStream(ctx, translator.FormatClaude, exec.ResponseFormatOrSource(opts), req.Model, original, body, data, &param)
	result.Headers = zcode.ResponseHeaders(resp.Header)
	return result, nil
}

func (e *ZCodeExecutor) ExecuteStream(ctx context.Context, auth *coreauth.Auth, req exec.Request, opts exec.Options) (_ *exec.StreamResult, err error) {
	reporter := helps.NewUsageReporter(ctx, e.Identifier(), req.Model, auth)
	defer reporter.TrackFailure(ctx, &err)
	resp, body, release, err := e.dispatch(ctx, auth, req, opts, true)
	if err != nil {
		return nil, err
	}
	out := make(chan exec.StreamChunk)
	go func() {
		defer close(out)
		defer release()
		defer func() {
			if errClose := resp.Body.Close(); errClose != nil {
				log.WithError(errClose).Warn("zcode: close stream")
			}
		}()
		original := opts.OriginalRequest
		if len(original) == 0 {
			original = req.Payload
		}
		var param any
		var usage helps.StreamUsageBuffer
		terminal := false
		send := func(chunk exec.StreamChunk) bool {
			select {
			case out <- chunk:
				return true
			case <-ctx.Done():
				return false
			}
		}
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 4096), 16<<20)
		for scanner.Scan() {
			line := bytes.Clone(scanner.Bytes())
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
			if !gjson.ValidBytes(data) {
				streamErr := statusErr{code: 502, msg: "zcode: invalid SSE data"}
				usage.PublishFailure(ctx, reporter, streamErr)
				send(exec.StreamChunk{Err: streamErr})
				return
			}
			event := gjson.GetBytes(data, "type").String()
			if event == "error" {
				streamErr := statusErr{code: 502, msg: "zcode: upstream stream error"}
				usage.PublishFailure(ctx, reporter, streamErr)
				send(exec.StreamChunk{Err: streamErr})
				return
			}
			usage.ObserveClaudeStream(line)
			if event == "message_stop" {
				terminal = true
			}
			// Preserve complete SSE frames for native Messages clients.
			frame := append([]byte("event: "+event+"\n"), line...)
			frame = append(frame, '\n', '\n')
			wire := line
			if exec.ResponseFormatOrSource(opts) == translator.FormatClaude {
				wire = frame
			}
			for _, translated := range translator.TranslateStream(ctx, translator.FormatClaude, exec.ResponseFormatOrSource(opts), req.Model, original, body, wire, &param) {
				if !send(exec.StreamChunk{Payload: translated}) {
					usage.PublishFailure(ctx, reporter, ctx.Err())
					return
				}
			}
		}
		errStream := scanner.Err()
		if errStream == nil && !terminal {
			errStream = io.ErrUnexpectedEOF
		}
		if errStream != nil {
			usage.PublishFailure(ctx, reporter, errStream)
			send(exec.StreamChunk{Err: errStream})
			return
		}
		usage.Publish(ctx, reporter)
		reporter.EnsurePublished(ctx)
	}()
	return &exec.StreamResult{Headers: zcode.ResponseHeaders(resp.Header), Chunks: out}, nil
}
