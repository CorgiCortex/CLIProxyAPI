# WorkBuddy native provider

This implementation is being built for the isolated `cliproxyapi-wb` test
service. The existing `cliproxy` deployment and its accounts are outside its
scope. No real WorkBuddy account has been used for validation.

Protocol reference: [workbuddy2api-hub](https://github.com/ardeyouxipianyi/workbuddy2api-hub),
revision `af706fc31e4a22cb2dea7442361b2b15185c3cee` (MIT).
The attribution is in `internal/workbuddy/NOTICE`.

## Delivery stages

1. Credential and transport foundation:
   - Explicit JSON import, browser authorization, serialized rotating refresh.
   - Native file-store and watcher integration, atomic private credential writes.
   - China/international routing and Desktop/VSCode/CLI identity profiles.
   - Separate connection pools for each account, identity, credential, origin
     and proxy. HTTP CONNECT/SOCKS support, certificate verification,
     cancellation, HTTP/1.1 header order and casing, gzip framing.
   - Offline tests for the above. Refresh and chat execution integration belongs
     to stage 2; registering an authenticator alone does not enable inference.
2. Core reverse proxy:
   - Provider executor, model discovery/registration, all supported downstream
     protocol translations, streaming and nonstream aggregation.
   - Shared risk governor: persisted model caps and reset times, differentiated
     account/model 429 backoff, hard/unknown circuit breakers, 11140 account and
     regional holds, 402 credit parking, token/credit/reserve limits, local day
     rollover, auth failures and model entitlement failures.
   - Bounded retries, pre-output stream retry rules, affinity, conversation
     paging, exit backoff, queue/concurrency limits, payload size limits.
     Optional identity switching and paid fallback stay disabled by default.
   - Preserve tool contracts; apply user payload rules once, after all built-in
     transformations. Only transport framing follows that semantic boundary.
3. Quota and activity jobs:
   - Balance refresh, quota scans, reset-window probes, sign-in, daily web
     activity and growth tasks.
   - All background jobs use the same risk governor as chat, including account
     restrictions and regional holds. They require an explicit enabled policy.
   - Deploy a distinct image and GitOps application, namespace, PVC, Secret and
     API key. Start with an empty auth directory and jobs disabled.

Dashboard functionality is excluded. Mock coverage cannot establish real
upstream acceptance, current account entitlement, award amounts or actual
anti-abuse behavior. Those checks remain pending until a test account is
provided.

## Implementation status

The credential/transport foundation is merged. Core execution is being developed
in `feat/workbuddy-proxy`; deployment is still pending. Offline coverage now
includes the native executor, OpenAI Chat/Responses, Claude and Gemini response
translation, SSE/nonstream collection, parallel tool calls, usage accounting,
401 refresh with persistence before replay, and SDK-scoped retry decisions.
HTTP errors and error envelopes inside HTTP 200 streams share the risk classifier.
A truncated stream is an error; once a chunk was emitted it cannot be replayed
on another credential. Only a pre-output connection failure gets one retry.

The static model catalog is an offline snapshot. Opt-in discovery reads
`/v3/config`, prefers the CLI agent's model list and merges observed metadata
with the snapshot. Empty responses cannot erase the catalog. Discovery persists
per-account results and republishes model registrations with the existing SDK
publication fences. Neither source establishes entitlement to run a model.
Native credential `models` explicitly restrict the published models.

The governor and transport pools are shared across executor replacements.
Configuration reloads preserve cooldowns, restrictions and usage. Changing the
state directory requires a restart; the old directory must be migrated explicitly.
Only one process may own a state directory. The isolated deployment will use a
single replica and its own PVC.

Model entitlement error `11158` is retained as region/model evidence for 24 hours,
including the reported user tier when known. As in the reference, this is not a
blanket dispatch ban: a free account's refusal cannot establish whether a paid
account may use the model. A later successful check clears the mark; older
in-flight completions cannot erase newer evidence. Model configuration errors
`11129` and `11150` also stop rotation without penalizing the account.

Conversation affinity keeps three recent eligible accounts per caller/session
for two hours. Conversations beyond 400 messages use stable account pages
(default size three); cooldowns do not change page membership. Native selection
still honors SDK pins, exclusions, priority and the final governor check.

Content rejection can replace the built-in prompt with a neutral prompt until
CST midnight, with one retry per request. Custom prompts are excluded. Optional
exit backoff shares failures by origin/proxy and caps waiting at five seconds
per logical request. Optional product switching persists the new identity before
retrying and permits at most four switches per account/model per minute.
Restrictions and durable free-model caps survive identity changes. Optional paid
fallback applies only to international DeepSeek Flash when every enabled account
in that region has an active free-model cap; paid budgets are checked again.
All rebuilt requests pass through the final payload-rule barrier exactly once.

Background operations now share chat's governor, connection pools and limiter:

- Model discovery and balance observations run in six-hour slots. Resource
  pagination must complete before publishing totals. Missing numeric fields
  remain unknown, including the enterprise endpoint's unreported remainder.
- CN personal sign-in runs after 09:00 CST. An explicit already-checked-in
  response is completion evidence, with no invented reward amount.
- Growth reconciliation runs after 09:00 and 21:00 CST. It verifies individual
  acceptance results and claims only vendor-observed completion. Desktop,
  subscription, donation and other real actions are not fabricated as telemetry.
- Optional quota scans use the three known free-cap models as applicable to the
  realm. Reset probes wait for the recorded reset time; both execute through the
  native chat path with paid fallback and product switching disabled. Each cycle
  admits at most 16 probes, including at most six quota scans, with 400 ms spacing.
  New quota pairs start after five seconds and are staggered by 15 seconds up to
  one hour; the schedule survives restart. Successful scans remain at least six
  hours apart even across a scheduling-slot boundary. Registered cap windows are
  handled only by reset probes until recovery is observed.
- Atomic job receipts precede actions. Completed slots survive restart; ordinary
  failures retry after 15 minutes, at most six times per slot. Reset failures
  retry after at least 15 seconds, at most 20 times per reset window, subject to
  any longer governor cooldown. Reload and shutdown cancel active maintenance.

Background jobs default to disabled. They record only observed credits and
rewards. Inference `usage.credit` feeds the paid daily budget and local debits
against the last observed balance, protecting the reserve between refreshes.
The persisted balance snapshot retains the vendor's original observation.

Automated international web activity and actual task-specific growth actions
remain follow-up work. The isolated deployment and real-account validation are
still pending; this implementation must not be described as fully validated
upstream parity.

An explicit v8 configuration enables the provider:

```yaml
oauth:
  auth-dir: /data/workbuddy-auth
  providers:
    workbuddy:
      enabled: true
      state-dir: /data/workbuddy-state
      max-concurrency: 32
      per-caller-concurrency: 2
      queue-seconds: 30
      jobs:
        enabled: false
        model-discovery: false
        balance-refresh: false
        checkin: false
        growth: false
        quota-scan: false
        reset-probes: false
      limits:
        daily-tokens: 0
        daily-credits: 0
        reserve-credits: 0
```

Zero budgets disable that local limit. Regional limit blocks replace the global
budget block for that region. A positive credit reserve requires an observed
balance, so requests remain gated while balance is unknown. Tokens and credits
are recorded from upstream observations only; credits are never inferred from
token counts. Concurrent requests can complete beyond a configured budget.
Queue deadlines end at admission and never become upstream network deadlines.
The general management HTTP tunnel is unsupported for this provider; arbitrary
requests must not bypass its risk governor or export credentials to another host.

The `WorkBuddy isolated image` workflow publishes only
`ghcr.io/corgicortex/cliproxyapi-wb:sha-<full-commit>` after offline race checks.
It never updates the existing DockerHub image or deploys a workload. Deployment
requires a separately reviewed GitOps pin.

## Credential setup

Use a separate configuration and auth directory for this test service. Never
point it at the production auth directory, mounted Secret or PVC.

Browser authorization:

```sh
cli-proxy-api --config wb-config.yaml --workbuddy-login \
  --workbuddy-realm intl --workbuddy-product workbuddy --no-browser
```

The printed URL is opened by the account owner. The proxy polls the authorization
state for at most ten minutes and saves the resulting credential through its
configured token store.

Explicit import:

```sh
cli-proxy-api --config wb-config.yaml --workbuddy-import /private/wb-account.json
```

The file can be a single hub account record (camelCase token fields, explicit
`realm`) or a native credential with `type: workbuddy`, `uid`, `realm`,
`product`, `access_token`, optional `refresh_token` and `expires_at` in epoch
seconds. `product` is `workbuddy`, `vscode` or `cli`; `realm` is `intl` or `cn`.
Enterprise accounts also retain `enterprise_id`. Optional native fields include
`proxy_url`, `device_token`, `private_data`, `models`, `prefix` and `disabled`.
`private_data` accepts `auto`, `true` or `false`.

Provide credentials later as a private file or mounted secret, then provide its
path. Tokens, passwords and full account exports do not belong in chat, command
arguments, PRs or test fixtures. The import command does not scan desktop
profiles or discover other providers' credentials.

## Offline validation

Tests use generated fixture JWTs and loopback HTTP/TLS servers. They do not
contact WorkBuddy or inspect any existing account files.

```sh
go test ./internal/workbuddy ./sdk/auth ./internal/watcher/synthesizer \
  ./internal/cmd ./cmd/server
go test ./internal/runtime/executor ./internal/runtime/executor/helps \
  ./sdk/cliproxy/auth ./sdk/cliproxy ./internal/config -run TestWorkBuddy
go build -o test-output ./cmd/server
rm test-output
```

The local host currently has no C compiler, so `-race` requires a separate
runner with CGO enabled. Run the race detector there before merging provider
implementation.
