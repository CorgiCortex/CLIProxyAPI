# Native ZCode provider

ZCode uses the existing Messages, Chat Completions and Responses HTTP APIs.
Accounts use provider `zcode`, with explicit `family` (`zai` or `bigmodel`) and
`plan` (`start-plan` or `coding-plan`). Both inference modes use an Anthropic
Messages upstream. This implementation is independent of the reference projects.

## Login and import

```sh
./CLIProxyAPI --config config.yaml --zcode-login --zcode-family zai --zcode-plan start-plan --no-browser
./CLIProxyAPI --config config.yaml --zcode-login --zcode-family bigmodel --zcode-plan coding-plan --no-browser
```

Coding Plan login provisions or reuses the provider's dedicated `zcode-api-key`.
Login does not claim plans or make purchases. ZCode JWT expiration requires
re-login; this provider does not invent a refresh-token exchange.

Alternatively, place an account JSON file in the configured `oauth.auth-dir`.
Use a private directory and restrict file permissions to the service owner.
For example (all values below are placeholders):

```json
{
  "type": "zcode",
  "family": "zai",
  "plan": "start-plan",
  "jwt": "REPLACE_WITH_ZCODE_JWT",
  "device_id": "REPLACE_WITH_PERSISTENT_UUID",
  "models": [{"name": "EXACT_UPSTREAM_MODEL", "alias": "zcode-model"}]
}
```

Coding Plan accounts additionally require `api_key` in `id.secret` form.
BigModel OAuth accounts retain `oauth_access_token` for project signing-token
acquisition. Their ZCode JWT is also required when the server's endpoint map
requests the additional ZCode authorization header. Credentials must not be
passed in command-line flags, committed, or shared with the verification worker.

Models are intentionally explicit, including upstream capitalization. Login
creates an empty model list; configure only models the account can actually use.
An empty account directory exposes no ZCode models.

## Configuration and verification worker

```yaml
upstream:
  zcode:
    app-version: "3.16.2"
    captcha-url: "http://127.0.0.1:8318"
    max-concurrent: 1
    min-interval-ms: 1000
    start-plan-system: ""
```

The version is a configurable protocol baseline, not a statement about the
currently installed official client. Start Plan gateway prompt requirements may
change: `start-plan-system` overrides the independently authored gateway prefix
inserted before caller instructions. It does not embed the official client's
proprietary system-prompt asset; acceptance of this prefix needs real-account
validation.
All built-in adaptation runs before user payload rules; a filtered field is
never restored by retries.

Build `tools/zcode-captcha/Dockerfile` using `tools/zcode-captcha` as context.
The worker uses Node and an isolated Chromium runtime to run the public
verification SDK. It binds only `127.0.0.1:8318`; run it alongside the proxy in
the same network namespace. It accepts only `app_version`, never account tokens
or prompts. `/healthz` checks worker readiness without contacting an upstream.
It limits solves to one at a time with four pending acquisitions, rejects reused
verification identifiers, and cools down on failures. Generation is on demand.
No verification traffic is generated until a Start Plan request arrives.

The worker supports a deployment-owned `ZCODE_CAPTCHA_PROXY` for matching the
inference egress. Accounts requiring different proxy exits need separately
configured instances/workers; do not mix their verification state. The initial
deployment uses direct egress for both containers.

## Request control

- Per-account admission covers all models and lasts through stream completion.
  Defaults are concurrency one and at least one second between request starts.
- A logical request has at most three ZCode inference sends across account
  rotation and verification retries. Each attempt may renew failed verification
  or signature material once. Credential/control requests do not consume this
  inference budget.
- Coding Plan signing uses a scoped handshake cache and Ed25519 proof headers.
  A signature failure never permanently disables signing.
- Explicit verification rejection is distinct from invalid credentials.
  Local worker failures leave account health unchanged.
- Redirects never forward credentials. Endpoint mappings are restricted to
  known HTTPS origins and approved paths for ZCode JWT injection.
- Client cancellation closes streams. Missing `message_stop`, malformed SSE and
  upstream stream errors are failures, not successful completions.
- Credential acquisition has bounded timeouts. Established inference/control
  connections use caller cancellation, not internal read/write deadlines.

Limits are process-local. Run one replica per account set until a distributed
admission mechanism is provided. Count-tokens, Responses compact/background,
off-peak queues, automatic plan claims, Highspeed cards and MCP are not included
in this initial provider.

## Validation boundary

Offline tests cover protocol translation, payload-rule ordering, retry bounds,
signing, account admission and verification-worker cancellation. Real account
acceptance remains a separate gate: check every enabled family/plan, exact
model access, text/tools/reasoning, upstream signing and captcha acceptance,
usage, and terminal SSE events. A Ready pod without credentials proves only
deployment readiness.
