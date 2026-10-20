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
go build -o test-output ./cmd/server
rm test-output
```

The local host currently has no C compiler, so `-race` requires a separate
runner with CGO enabled. Run the race detector there before merging provider
implementation.
