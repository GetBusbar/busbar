# Configuration reference

Busbar reads **two YAML files** at startup:

| File | Default path | Override | Purpose |
|---|---|---|---|
| Provider catalog | `providers.yaml` next to config.yaml | `--providers <path>` flag, or `providers_file:` in config.yaml | Shipped map of provider names → protocol, base URL, error map. Operators rarely edit this. |
| Deployment config | `/etc/busbar/config.yaml` | `-c`/`--config <path>` flag, or `BUSBAR_CONFIG` env | Your site's providers (with secret references for credentials), models, pools, auth, groups, pricing, store, and telemetry export. |

**Flag-first (1.6.0).** The config path resolves **`-c`/`--config` flag > `BUSBAR_CONFIG` env >
`/etc/busbar/config.yaml`**; the provider-catalog path resolves **`--providers` flag > `providers_file:`
in config.yaml > `providers.yaml` next to the resolved config.yaml**.

Both files support `${VAR}` environment interpolation before YAML is parsed. A missing or malformed env var reference is a fatal startup error, Busbar refuses to boot rather than run with an incomplete config.

> Looking for a one-page map of every key? See [Config at a glance](https://getbusbar.com/docs/config-at-a-glance/).
>
> All defaults below are sourced from the config structs in `crates/busbar-kernel/src/config/` and the runtime constants they feed. Where a serde field default differs from a runtime constant, both are noted.

---

## Table of contents

- [Environment variables](#environment-variables)
- [Environment interpolation](#environment-interpolation)
- [`config`, `config_version`, `telemetry`](#config)
- [`providers.yaml`](#providersyaml)
  - [Catalog fields](#catalog-fields)
  - [Health probing](#health-probing)
- [`config.yaml`](#configyaml)
  - [`listen`](#listen)
  - [`tls`](#tls)
  - [`auth`](#auth)
  - [`groups`](#groups)
  - [`rate_card` and `per_request_fee`](#rate_card-and-per_request_fee)
  - [`store`](#store)
  - [`providers`](#providers)
  - [`models`](#models)
  - [`pools`](#pools)
    - [Members and weights](#members-and-weights)
    - [Pool `hooks`: ordering and gates](#pool-hooks-ordering-and-gates)
    - [`breaker`](#breaker)
    - [`failover`](#failover)
    - [`on_exhausted`](#on_exhausted)
    - [`affinity`](#affinity)
    - [Context-length failover](#context-length-failover)
  - [`limits`](#limits)
  - [`export`](#export)
  - [Virtual keys and enforcement](#virtual-keys-and-enforcement)
  - [`plugins`](#plugins)
  - [`secrets`](#secrets)
  - [`security`](#security)
  - [`advanced`](#advanced)
  - [Advanced settings reference](#advanced-settings-reference)
  - [Login attempt limits](#login-attempt-limits)
  - [`advanced.tls`](#advancedtls)
  - [`providers_file`](#providers_file)
- [Migrating a 1.4.x config](#migrating-a-14x-config)
- [Reserved names](#reserved-names)
- [Minimal working example](#minimal-working-example)
- [Full annotated example](#full-annotated-example)
- [Startup validation summary](#startup-validation-summary)

---

## Environment variables

The environment variables Busbar reads by design (excluding test-only `BUSBAR_T_*` / `BUSBAR_SENTINEL_*` names):

| Variable | Where read | Purpose / default |
|---|---|---|
| `BUSBAR_CONFIG` | boot (config path) | Path to `config.yaml`. Default: `/etc/busbar/config.yaml`. **The one bootstrap env var**: it locates config.yaml itself. Overridden by the `-c`/`--config` flag. |
| `RUST_LOG` | logging init | Console log filter; logs always go to stderr. A bare level (`error`, `warn`, `info`, `debug`, `trace`, or `off`) or comma-separated per-target directives over a default level, e.g. `busbar=debug,hyper=warn` or `info,busbar::request=debug` (the per-request `request finished` summary alone). Default: `info`. A value that is not a filter stops boot with `BUSBAR-9007`. See [Observability](observability.md). |
| *(each provider's `api_key: { env: VAR }` reference)* | secret resolution at boot | The env var **named by** the secret reference holds that provider's upstream credential. Resolved once at boot per provider; unset is a fatal boot error (use `api_key: none` for a keyless upstream). |
| *(any `${VAR}` in `config.yaml`)* | config load | Expanded before YAML is parsed. Unset → fatal boot error. |

`BUSBAR_ADMIN_TOKEN` is not special-cased in the code. It appears in the shipped `config.yaml` only because the file references `{ env: BUSBAR_ADMIN_TOKEN }` as the `token:` of the `admin-tokens` identity provider (`identity-providers.admin-tokens.token`). Any variable name works.

**CLI flags for the input files (1.6.0).** `-c`/`--config <path>` (also `--config=<path>`) points
Busbar at config.yaml, taking precedence over `BUSBAR_CONFIG`; `--providers <path>` (also
`--providers=<path>`) points it at the provider catalog, taking precedence over `providers_file:`.
See [Operations → Process configuration](operations.md#process-configuration).

**Operational environment overrides are retired in 1.6.0.** Serving reads `providers_file:`
(or `--providers`) and the corresponding `advanced` keys instead of `BUSBAR_PROVIDERS`,
`BUSBAR_WORKER_THREADS`, `BUSBAR_UPSTREAM_HTTP1_ONLY` and `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE`.
Boot and `--validate` refuse a set retired launch variable with `BUSBAR-3029`, naming its
replacement without echoing the value. Write the intended values into configuration using
[the environment-input mappings](migration-1.6.md#environment-inputs), then remove the variables
from the launcher before validating or starting Busbar. An empty `BUSBAR_PROVIDERS` selects
nothing and counts as unset; the other retired variables refuse even when empty.

`BUSBAR_CONFIG_OVERLAY` is a separate one-time selector for the old overlay, whose contents are
folded into `config.yaml` on upgrade; runtime configuration is persisted through the Store.
`BUSBAR_CONFIG` (bootstrap), explicit secret `{ env: NAME }` references, `RUST_LOG`, and the
`TOKIO_WORKER_THREADS` fallback remain supported.

### `config`

The top-level `config:` block is config-**management** policy: whether the admin API may mutate config at runtime. Runtime mutations persist exclusively through the operator's base `store:`, which anchors overlay recovery. A durable Store preserves them across restart; the memory Store is ephemeral. There is no independent overlay file.

```yaml
config:
  locked: false                 # false = mutable (admin API may change config); true = immutable/GitOps
```

- **`locked: true`**: admin-API config mutations are refused at runtime; change config by editing `config.yaml` + `POST /config/reload`. The overlay is ignored.
- Mutable management requires the Store's atomic conditional-record capability. Persistence must succeed before a new config generation is published; failure refuses the mutation.
- A read-only config directory has no effect on Store persistence. `config.overlay` (including file and boolean selectors) is not part of the current grammar and is refused. One-time migration removes that selector while preserving `config.locked` and imports old file state separately. Serving does not read `BUSBAR_CONFIG_OVERLAY`.
- Boot recovers the complete overlay from the base Store before opening effective application plugins. An unavailable, incomplete, corrupt or newer overlay refuses recovery. `--ignore-overlay` explicitly ignores it (left untouched) without deleting its Store records. `--validate` does not open a Store or recover its overlay. See [Operations](operations.md#config-mutability-locked--overlay) for recovery and anchor changes.

### `config_version`

`config_version: 1` is the config stamp, `config.yaml`'s first key. The first 1.6.0 boot of a 1.5.5
config (one with no stamp) upgrades it in place, writes the stamp, and keeps the original beside it as
`config.yaml.1.5.5` (see [the 1.6 upgrade instructions](migration-1.6.md)). A config that already
carries the stamp is read as written; a value other than the current one is refused at boot. Do not
add or edit it by hand.

### `telemetry`

The in-process metric registry. On by default, whatever the `export:` instances are; an export recorder
only raises the retention.

```yaml
telemetry:
  enabled: true            # default true. `false` is the one way to turn it off; /metrics then answers 503 telemetry_disabled
  retention_seconds: 300   # default 300
  max_lane_series: 1024    # default 1024: lanes that get their own request-duration series before the rest fold into target="other"
```

### Plane sections and `oauth_as`

A plane owns its own top-level section (`tools:`, `agents:`, `streams:`, `decisions:`, `mcp:`, and
any other registered plane), parsed by that plane and documented in that plane's own documentation:
[MCP](mcp.md), [A2A](a2a.md) and
[voice.md](voice.md). Core reserves only the words listed under [Reserved names](#reserved-names) inside
a plane section. `oauth_as:` is likewise an opaque section owned by the OAuth authorization-server
plane (the MCP protected-resource metadata and its authorization servers); see that plane's
documentation. Both are judged by their owners, not by this reference.

---

## Environment interpolation

### Syntax

Only the **brace form** `${NAME}` is expanded. Bare `$NAME` is passed through unchanged.

```yaml
providers:
  internal:
    base_url: "https://${LLM_GATEWAY_HOST}/v1"   # expanded: the env var's value is substituted
    api_key: { env: INTERNAL_KEY }               # NOT interpolation: a secret REFERENCE, resolved at boot
```

Most secrets never need `${VAR}` interpolation at all: credential fields are secret references
(`{ env: VAR }` / `{ file: /path }` / `{ module: <secret-plugin> }`) resolved by the secret
subsystem at boot. Interpolation remains for non-secret values (hosts, paths, names).

### Error cases

| Situation | Behavior |
|---|---|
| `${NAME}` where `NAME` is unset | Fatal boot error: `unset environment variable: NAME` |
| `${NAME` with no closing `}` | Fatal boot error: `unclosed variable reference...` |
| `${}` (empty name) | Fatal boot error: `empty variable name in ${}` |
| Value contains a control character (`\n`, `\r`, `\t`, NUL, DEL, U+0085, U+2028, U+2029) | Fatal boot error, prevents newline-based YAML-structure injection via env vars |
| Value would change the config's YAML STRUCTURE when substituted (see below) | Fatal boot error, names the offending variable(s) where identifiable |

Ordinary punctuation (`: / @ . - # " , { } [ ] &` etc.) in env var values is allowed. There is no fixed forbidden-character list. Interpolation scans the entire raw file, including commented-out lines, so a `${VAR}` in a comment must still resolve.

### Structural-equivalence check

Beyond the control-character check above, every interpolated document is verified to keep the same
YAML *shape* the template declares. Concretely: the raw template is interpolated twice (once with
real values, once with an inert placeholder standing in for each `${VAR}`), both results are parsed,
and the two parse trees must have the same map keys, the same sequence lengths, and the same node
kind (map / sequence / scalar) at every position. A substituted value may change what a scalar leaf
*contains* (that's the entire point of interpolation), but it may never change how many keys a map
has, how long a sequence is, or what kind of node sits at a given position.

This closes a class of injection the control-character check alone cannot see: inside a YAML flow
collection (`{ }` / `[ ]`, used by this project's own examples, e.g. `client_tokens: [ "${VAR}" ]`),
a value containing a bare `,`, `"`, or `'` can splice in extra structure on a single line, with no
newline involved at all. Because the check is about *shape*, not content, it has no forbidden-character
list to maintain and no false positives on legitimate values that happen to contain YAML-"special"
characters but do not actually change the parsed shape. An LDAP DN with mandatory commas, a Windows
path with backslashes, a URL with a query string, or a value that changes a scalar's *inferred type*
(e.g. `port: ${PORT}`, where a real `8080` infers as a number, but the check does not compare scalar
values or types, only shape) all interpolate normally. Only a value that actually widens/narrows the parsed
structure is rejected.

A value containing an unescaped `"` still breaks a double-quoted scalar exactly as YAML's own grammar
says it does (that is not this check's job to prevent: it is the control-character check's cousin
concern, and an ordinary YAML parse error results either way, not a silent injection). A JSON blob
therefore does NOT interpolate cleanly if it is spliced into a double-quoted scalar: use a `{ file: ...
}` secret reference for that case instead of `${VAR}`.

---

## `providers.yaml`

A map of provider name → `ProviderDef`. The shipped catalog is a curated set of verified providers across the six supported protocols. You can add an entry for any OpenAI-compatible endpoint not already in the catalog.

### Provider options

A provider entry in `config.yaml` may also set any request header or query parameter its dialect's
API accepts, under the provider's own name, beside busbar's keys:

```yaml
providers:
  openai:
    api_key: { env: OPENAI_API_KEY }
    OpenAI-Organization: org-abc
    OpenAI-Project: proj_1
  vertex:
    api_key: { env: GOOGLE_SA }
    x-goog-user-project: my-gcp-project
  azure:
    api_key: { env: AZURE_KEY }
    api-version: 2024-10-21
```

| Dialect | Names (header unless noted) |
|---|---|
| `anthropic` | `anthropic-version` (`2023-06-01`, `2023-01-01`), `anthropic-beta` (a list or comma-separated) |
| `openai`, `responses` | `OpenAI-Organization`\*, `OpenAI-Project`\*, `api-version` (query; Azure OpenAI) |
| `gemini` | `X-Goog-User-Project`\*, `X-Goog-Quota-User`, `X-Goog-Request-Reason`, `X-Server-Timeout` (whole seconds) |
| `bedrock` | `X-Amzn-Bedrock-Trace`, `X-Amzn-Bedrock-GuardrailIdentifier`, `X-Amzn-Bedrock-GuardrailVersion`, `X-Amzn-Bedrock-PerformanceConfig-Latency`, `X-Amzn-Bedrock-Service-Tier` (sent to `bedrock-invoke` models) |
| `cohere` | `X-Client-Name` |

- Header names match without regard to case. Query names match exactly.
- Any other key that is not one of busbar's provider keys fails startup and `--validate`. The one catalog-level exception is `model_capabilities`, a list of per-model capability rules judged by the LLM plane (see [Providers: lane capabilities](providers.md#lane-capabilities)). The
  error names the key and lists the names the provider's dialect accepts.
- Credential and auth fields (`Authorization`, `x-api-key`, `api-key`, `x-goog-api-key`, `key`,
  `X-Amz-*`, ...) can't be set this way. Use `api_key` and `auth`. Hop-by-hop fields
  (`Connection`, `Transfer-Encoding`, `Host`, ...) are refused too.
- **Precedence.** A static option is a default. When a caller speaks the provider's own dialect and
  sends the same header or query parameter, the caller's value is used. Names marked \* are forced:
  they select the account that is billed, so the configured value always goes out and a caller's
  value never does.
- A `providers.yaml` catalog entry follows the same rule: it may set options, and any other key
  fails startup, naming the file and the key. This applies to every entry, deployed or not.
  the first-boot migration reports stray catalog keys.

### Catalog fields

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `protocol` | string | **yes** (catalog) | n/a | The wire protocol (dialect) the provider speaks, for example `anthropic`, `openai`, `gemini`, `bedrock`, `responses` or `cohere`. Required in the catalog; there is no default. In a `config.yaml` provider entry an omitted `protocol` falls back to the catalog's value. An unknown protocol is a startup error. |
| `base_url` | string | **yes** | n/a | Scheme + host (+ optional path prefix). Must start with `https://` for external endpoints. An `http://` URL in the catalog is not blocked at parse time but will be rejected by the SSRF guard on deployment use. Trailing slash is trimmed. |
| `error_map` | map<string, string> | no | `{}` | Maps a provider-specific error **code string** (from the JSON error body) to a canonical disposition class. Valid values: `rate_limit`, `overloaded`, `server_error`, `timeout`, `network`, `auth`, `billing`, `client_error`, `context_length`. An unrecognized class value is a startup error. HTTP-status classification (401→auth, 429→rate_limit, 5xx→server_error, etc.) applies automatically without an `error_map`; this field is only for provider-specific JSON codes. |
| `path` | string | no | Protocol's standard path | Overrides the upstream request path appended to `base_url`. Must begin with `/`. Static, ignores the per-request model. Use when the API version is in `base_url` and the endpoint path differs from the protocol default (e.g. `/chat/completions` without `/v1`). |
| `path_base` | string | no | Protocol's default base | For URL-model protocols: overrides the hardcoded base segment while the per-request suffix is still appended. Must begin with `/`. On **Gemini** it replaces `/v1beta/models` (suffix `/{model}:verb`) to reach Google Vertex AI's `/v1/projects/{project}/locations/{location}/publishers/google/models` layout; on **Anthropic** it enables Claude-on-Vertex (the model moves into a `:rawPredict`/`:streamRawPredict` suffix and the body carries `anthropic_version` in place of `model`). Config-only, no code. |
| `auth` | string | no | Protocol's native auth | The egress auth style: any style word declared by an admitted `kind: auth` plugin, or a `module:` instance name. Core keeps no style-to-plugin table; a word no admitted auth plugin implements is refused with "no admitted auth plugin implements the outbound style `X`; write `module:`". The styles in the shipped catalog are `bearer` (sends `Authorization: Bearer <key>`), `api-key` (sends `api-key: <key>`, for Azure OpenAI), `jwt-bearer` (OAuth 2.0 JWT-bearer, RFC 7523, from a service-account key resolved via `api_key`) and `oauth-client-credentials` (OAuth 2.0 client-credentials, RFC 6749 §4.4; the `api_key` reference resolves to `client_id:client_secret`, exchanged at `token_url` for a bearer); each needs the auth plugin that implements it to be admitted. When unset, each protocol uses its native scheme: bearer for anthropic/openai/responses/cohere, `x-goog-api-key` for gemini, AWS SigV4 for bedrock. |
| `token_url` | string | no | none | OAuth token endpoint for `auth: oauth-client-credentials`, where Busbar POSTs the client credentials for a bearer. Required for that auth; must be https for a public host. |
| `scope` | string | no | none | OAuth scope for `auth: oauth-client-credentials`. Required for that auth. |
| `subject` | string | no | none | JWT-bearer assertion `sub` claim (RFC 7523 §3) for `auth: jwt-bearer`. **Opt-in only**: leave unset for a plain (non-delegated) service account, e.g. the default Vertex AI setup; setting it (to any value) switches a Google service-account grant into domain-wide-delegation/impersonation semantics, so only set it when impersonating a specific principal or when a non-Google IdP's jwt-bearer profile requires `sub`. Ignored for every other auth style. |
| `health` | object | no | none | Active health-probe config. See [Health probing](#health-probing). |

Example entries:

```yaml
anthropic:
  protocol: anthropic
  base_url: https://api.anthropic.com

azure-openai:
  protocol: openai
  base_url: https://myaccount.openai.azure.com/openai/deployments/gpt-4o
  path: /chat/completions?api-version=2024-02-01
  auth: api-key    # sends api-key: <key> instead of Authorization: Bearer

zai-api:
  protocol: openai
  base_url: https://api.z.ai/api/paas/v4
  path: /chat/completions
  error_map:
    "1113": billing
    "1302": rate_limit
```

### Per-provider deployment overrides

In `config.yaml`, a provider entry may selectively override the catalog's `protocol`, `base_url`, `error_map` (merged: deployment entries win per code), `path`, `path_base`, `auth`, `token_url`, `scope`, `subject`, and `health`. The only always-required field in the deployment entry is `api_key` (a secret reference).

### Health probing

Health probing sends one minimal token request per interval per lane. It runs on a background task; probe outcomes run through the same disposition pipeline as organic traffic (2xx recovers the lane, transient failures increment the breaker, hard errors set the lane dead for 30 min).

| Field | Type | Default | Notes |
|---|---|---|---|
| `mode` | string | `none` | `none` (passive only, breaker updates on organic traffic), `dead` (re-probe only tripped lanes), `active` (probe all lanes at every interval). `active` sends one billable request per lane per interval. |
| `interval_secs` | integer | `30` | Seconds between probes. Floored at 1. |
| `timeout_secs` | integer | `5` | Per-probe request timeout. Floored at 1. |

```yaml
anthropic:
  protocol: anthropic
  base_url: https://api.anthropic.com
  health:
    mode: dead
    interval_secs: 30
    timeout_secs: 5
```

A provider declaring `api_key: none` (a keyless local upstream) is not probed regardless of the `health` block: the probe would go out unauthenticated, which says nothing about a lane that never authenticates.

---

## `config.yaml`

### `listen`

```yaml
listen: "0.0.0.0:8080"
```

| Field | Type | Default |
|---|---|---|
| `listen` | string (`host:port`) | `0.0.0.0:8080` |

The value is passed directly to `tokio::net::TcpListener::bind`. An invalid or already-bound address is a fatal startup error.

---

### `tls`

Optional. When present, Busbar terminates inbound TLS natively (and, with
`client_ca`, requires mutual TLS). When **absent**, Busbar serves plain HTTP,
the historical default, unchanged.

```yaml
tls:
  cert: { file: /etc/busbar/tls/fullchain.pem }  # PEM cert chain, leaf first (secret reference)
  key:  { file: /etc/busbar/tls/privkey.pem }    # PEM private key (PKCS#8 / PKCS#1 / SEC1)
  client_ca: { file: /etc/busbar/tls/ca.pem }    # optional: present = mTLS required
```

| Field | Type | Default |
|---|---|---|
| `cert` | secret reference | (required when `tls` is set) |
| `key` | secret reference | (required when `tls` is set) |
| `client_ca` | secret reference | unset (no client-cert requirement) |

Each value is a secret REFERENCE (the canonical `{ module: <secret-plugin>, settings: {...} }`, or a
shorthand such as `{ file: ... }` that an admitted secret module declares)
resolving to PEM bytes. The same shape configures the admin listener under `admin_tls:` (with
`client_ca` gating admin mTLS; a network-exposed `admin_listen` without `admin_tls.client_ca`
refuses to boot unless `admin_require_mtls: false` is set deliberately).

Certs/keys are loaded once at startup; any missing or unparseable file is a fatal
startup error naming the file. ALPN offers `h2, http/1.1`: a client that offers h2 speaks
HTTP/2, one that offers only http/1.1 is served HTTP/1.1. Rotate certs by replacing
the files and restarting. Full operational guide:
[`operations.md`](operations.md#inbound-tls--mutual-tls-mtls).

---

### `auth`

Front-door identity for the data plane plus the admin chain and role policy.

**Define once, reference by name.** Every identity provider is DEFINED once in the top-level
`identity-providers:` map (`name -> {module, settings, max_admin_scope, token, browser_login}`) and
REFERENCED BY BARE NAME from `auth.chain:`, `auth.admin_auth:` and `auth.role_bindings:`. One IdP that
serves both planes is therefore configured ONCE. Under the retired grammar it had to be written
inline in both chains, and nothing stopped the two copies from drifting. The built-ins `keys` (the
signed-key verifier) and `admin-tokens` (the operator credential) are referenced bare and need a
definition only when they carry config.

Static token allowlists do not exist: every caller carries either a minted signed key or an IdP
credential a chain provider verifies.

Giving a provider definition a `browser_login:` block also lets developers **self-serve** their own
budgeted key by signing in. Busbar exposes a `GET`/`POST /auth/token` exchange automatically. (A client id/secret
belongs to ONE IdP registration, so it lives on that provider.) See
[Token exchange (self-serve keys)](token-exchange.md). A sign-in never undoes an administrator's
action on a self-serve key: a disabled key stays disabled, a revoked key is permanent, and an admin
regroup or rotation stands ([Admin actions and self-service](token-exchange.md#admin-actions-and-self-service)).

```yaml
identity-providers:
  <operator-auth>: { module: <operator-auth-module>, token: { env: BUSBAR_ADMIN_TOKEN } }
  ad:
    module: ad                                            # a `kind: auth` plugin
    settings: { server: "ldaps://corp", base_dn: "dc=corp" }
    # max_admin_scope:                                    # PER-PROVIDER admin ceiling:
    #                                                     # `read-only` | `full` ONLY.
    #                                                     # OMITTED = read-only (most restrictive)

auth:
  signing_key: { file: /run/secrets/busbar-signing.key }  # REQUIRED with `keys`; busbar --generate-signing-key
  chain: [keys, ad]                                       # bare PROVIDER NAMES
  admin_auth: [<operator-auth>, ad]
  role_bindings:
    ad:
      growth-eng: { allowed_pools: [fast], group: growth }
      platform:   { group: acme, admin_scope: full }      # allowed_pools omitted = ALL pools
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `signing_key` | secret reference | **when `keys` is in the chain** | none | The ed25519 key Busbar signs + verifies virtual-key tokens with, as a secret reference (the canonical `{ module: <secret-plugin>, settings: {…} }` form, or a shorthand an admitted secret module declares; never an inline literal). Fleet-shared (every node verifying the same tokens resolves the same key). **Required whenever the data-plane chain names the built-in `keys` verifier**; its absence there fails `--validate`/boot. Busbar does **not** auto-generate one. Generate a key with `busbar --generate-signing-key`. Rotating it revokes every outstanding key. |
| `chain` | list of provider NAMES | no | `[]` | The ordered DATA-PLANE authentication chain: the **sole** authority over whether a data-plane request needs a credential (the admin token never gates the data plane; see the axis note below). Each entry is a bare NAME: either a built-in (`keys`) or a key of the top-level `identity-providers:` map. A name that is neither is a **hard startup error** (fail-closed: never a silently-skipped identity provider). `[]` (default) is the open front door: development only, loud startup warning (the admin API stays gated by `admin_auth`). When the chain names `keys`, a **usable admin mint path** must exist (an `admin-tokens` provider with a `token:`, or an admin provider granting `full`). Otherwise no virtual key could ever be minted and the data plane would reject every request, so it is a **hard startup error**. A configured auth plugin that cannot be loaded (missing/untrusted tarball, wrong kind, `plugins.enabled: false`, or an ABI failure) is likewise a **hard startup error**. |
| `admin_auth` | list of provider NAMES | no | `[admin-tokens]` | The chain gating `/api/v1/admin/*`, same bare-name references as `chain`. The built-in `admin-tokens` provider carries the operator credential as a secret reference (`token:`) on its definition. `[]` is refused at boot: there is no open admin posture. |
| `role_bindings` | map | no | `{}` | Role policy, NESTED BY PROVIDER NAME: `role_bindings.<provider>.<role> -> { allowed_pools?, group?, admin_scope?, verbs? }`. Keying by NAME (not by the backing plugin's own name) is what lets two named providers share one module and still hold independent grants. See below. |
| `key_ttl` | duration string | no | `90d` | The lifetime of a key minted by the self-serve token exchange (`POST /auth/token`): the key expires `key_ttl` after it is minted. Read at every apply/reload. |
| `require_if_match` | bool | no | `false` | When `true`, a guarded config mutation through the admin API that carries no `If-Match` header is refused `428` (`invalid_request` / `if_match_required`). Absent or `false` accepts a missing `If-Match`. `auth.policy.require_if_match` is not a key: it is refused as an unknown field. |

**The `identity-providers:` definition map.** `name -> { module, settings?, max_admin_scope?, token?, browser_login? }`.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `module` | string | **yes** | n/a | Which `kind: auth` plugin (or built-in) backs this provider: the built-in `keys` / `admin-tokens`, or a `kind: auth` plugin name/alias. The SAME module may back SEVERAL named providers (different issuers, different ceilings). The NAME is the instance. |
| `settings` | map | no | `{}` | The module's own opaque config, pushed verbatim (SecretRef-typed values resolve first). |
| `max_admin_scope` | string | no | `read-only` | This provider's ADMIN ceiling, regardless of what `role_bindings` grants. The accepted tokens are exactly `read-only` \| `full`; any other value (including `none`) is an unknown scope token and fails `--validate`/boot. OMIT the key to get the MOST RESTRICTIVE default (`read-only`). There is no lower ceiling to write. The built-in `admin-tokens` operator credential is exempt (full by definition). `full` from an external IdP is always an explicit opt-in. To give a provider NO admin authority at all, leave this omitted and grant no `admin_scope` under its `role_bindings`. |
| `token` | secret reference | no | none | The operator ADMIN credential, only meaningful on a provider whose `module` is the built-in `admin-tokens`; anywhere else it is a boot error. |
| `browser_login` | map | no | none | `{ client_id?, client_secret? }`. PRESENCE puts a button on the hosted login page; a provider without it is headless-only (still usable via `POST /auth/token`). Failed credential sign-ins are limited by fixed engine constants (see [Login attempt limits](#login-attempt-limits)). <!-- docs-truth: depends on !2696 (unmerged; deletes `browser_login.failure_window`, `auth.login_limits.*`) and the owner ruling fixing `browser_login.max_failures` at 3 (no MR yet) --> |

**Where did `auth.upstream_credentials` go?** To `pools.upstream_credentials`: whose credential reaches the provider is a ROUTING property, not an inbound-auth one. See [`pools`](#pools).

**Token extraction order (data plane):** `Authorization: Bearer`, then `x-api-key`, then
`x-goog-api-key`. Blank values are treated as absent.

**Three orthogonal axes.** Data-plane admission, admin-API access, and governance
enforcement are independent, each with one local source of truth:

- **Data-plane admission** is decided **solely** by `auth.chain`: `[]` = open/anonymous, `[keys]` =
  a virtual key is required and resolved, an IdP/plugin chain requires that IdP. Nothing else, in
  particular **not** the admin token, decides whether a data-plane request needs a credential.
- **Admin-API access** is decided **solely** by `auth.admin_auth`; it gates `/api/v1/admin/*` and
  never touches the data plane. Minting lives behind it simply because mint is an admin endpoint.
- **Governance enforcement** is automatic: it applies to whatever principal-with-group the chain
  resolved. An open chain resolves no principal, so there is nothing to enforce.

This makes **"protected admin API + open (anonymous) relay for users"** expressible: set
`chain: []` with an `admin_auth` operator credential.

**Bedrock ingress.** Native Bedrock SDK clients authenticate with AWS SigV4. Mint a key with
`"issue_aws_credential": true`; the response includes `aws_access_key_id` +
`aws_secret_access_key` (shown once). Busbar verifies the inbound SigV4 signature natively
(including body-hash integrity), then applies the key's group limits and pool ACL.

#### `auth.role_bindings`: provider-scoped role policy

A role asserted by an identity provider earns exactly what the binding under THAT provider NAME
grants, nothing else: `ad.platform` and `sso.platform` are distinct grants, and a provider can never
ride another provider's binding. An unbound role grants nothing (fail closed). Because the nesting key
is the provider NAME (not the backing module's name), two named providers may share one `module:` and
still hold independent grants.

| Field | Notes |
|---|---|
| `allowed_pools` | DATA-PLANE grant: pools this role may target. OMITTED = ALL pools; an explicit `[]` = NO pools (an empty list is the empty set, everywhere in the config). Pool lists union across a principal's granting roles; any omitted grant widens the union to all pools. |
| `allowed_<kind>s` | PLANE grant: the names of a plane kind's items this role may use, for example the servers or tools of a tool plane or the agents of an agent plane (the key is `allowed_` plus the plane's kind plus `s`). Three-state exactly as `allowed_pools`: omitted = all, an explicit `[]` = none, and the lists union across a principal's granting roles. The plane's own documentation names its kinds. |
| `group` | The `groups:` bucket this role's principals charge through. Absent = no group (authed + unlimited). With several bound groups the first in role order wins. |
| `admin_scope` | The admin authority this role grants: `read-only` \| `full` (see [admin-api.md](admin-api.md#authentication--scopes)). Absent = none. A principal holds the highest scope its bound roles grant, then the asserting provider's `max_admin_scope` ceiling caps it (a `read-only` ceiling, which is the default and the recommended posture for an external IdP, reduces a `full` grant to `read-only`). Omitting `admin_scope` here is how a role gets no admin authority at all. |
| *the role `"*"`* | 1.6.0. Binds the principals 1.5.5 admitted with no grant: a principal that asserts no roles, and, when the provider's table binds no other role, every principal the provider identifies. It grants what its fields state, like any role. A principal whose roles a named binding grants is judged by those alone; one asserting only roles the table does not name is still refused. 1.6.0 refuses a signed-in principal no binding grants (401), so the 1.6.0 upgrade writes `"*": {}` (every pool, no budget) for each data-plane provider whose users 1.5.5 admitted that way, with a warning: it keeps 1.5.5's access and is yours to tighten or remove. |
| `verbs` | 1.6.0. The PER-VERB admin allow-list this role grants: `"*"` (every verb, exactly `admin_scope: full`) or a list of admin operation names from the closed verb table, e.g. `[get_keys, post_keys, get_ledger_totals]` (the snake-case operation names of the [admin API](admin-api.md), the 1.6.0 verbs by their own names). A named verb is admitted whatever scope it needs; any verb the list does not name is `403 forbidden`, the same answer a missing scope gets. `admin_scope` stays the 1.5.5 shorthand beside it (`read-only` = every read, `full` = every verb), and a principal holds the UNION of both across its bound roles. The provider's `max_admin_scope` caps a named verb as it caps `admin_scope`. Absent = only what `admin_scope` grants, as in 1.5.5. Any other shape, or a name the table does not declare, fails `--validate`/boot. |

Admin access is therefore EITHER a role's `admin_scope` (through an identity provider named in `admin_auth`)
OR the `admin-tokens` operator token. The admin chain is live-mutable over the API
(`PUT /api/v1/admin/auth`) with an anti-lockout guard; see the [Admin API guide](./admin-api.md).

#### identity-provider plugins

Any `identity-providers:` definition whose `module:` is not a built-in (`keys` / `admin-tokens`) is a
**`kind: auth` plugin**: an identity provider loaded in-process at boot over the signed plugin ABI,
the same trust and loader path as store and secret plugins (see
[plugins.md](plugins.md#auth-plugins-kind-auth)). Install it like any other plugin: set
`plugins.enabled: true`, drop the signed tarball in the plugins directory, define the provider under
`identity-providers:`, then name that provider in `auth.chain:` / `auth.admin_auth:`. Its `settings:`
map is passed to the plugin verbatim as its config.

Role policy is nested under the **provider NAME you chose** in `identity-providers:`, the definition
key, not the plugin's own runtime `name()`. That is what lets the same plugin back two providers with
independent bindings and independent `max_admin_scope` ceilings.

A verified caller presents its IdP-issued token as `Authorization: Bearer <token>`; the auth plugin
validates it and asserts the token's claims as roles, which Busbar maps through `role_bindings.<provider>`
to pools, limits, and (optionally) an admin scope capped by that provider's `max_admin_scope`.

Each auth plugin defines its own `settings:` (issuer, audience, claim mapping, and so on) and ships its
own setup guide. Provider-specific setup, such as an SSO provider's portal walkthrough or a claim-to-role
mapping, belongs to that plugin's own documentation, not to this reference. What core owns is the
contract: the `module:` and `settings:` of the definition, the `role_bindings.<provider>` keyed by the
**provider NAME**, and the `max_admin_scope` ceiling. A role a plugin asserts binds only when the
`role_bindings` key matches the role string exactly as the plugin asserts it; an unmatched role is a
silent no-match, not an error.

```yaml
public_url: "https://busbar.example.com"
plugins: { enabled: true }                      # the auth plugin's tarball is in plugins.dir
identity-providers:
  <operator-auth>: { module: <operator-auth-module>, token: { env: BUSBAR_ADMIN_TOKEN } }   # mints the keys
  sso:                                          # the provider NAME
    module: <auth-plugin>                       # the `kind: auth` plugin
    settings: { }                               # the plugin's own settings
    browser_login:
      client_secret: { env: SSO_CLIENT_SECRET }
    # max_admin_scope omitted ⇒ read-only, the most restrictive ceiling; with no
    # `admin_scope` in the role_bindings below, SSO grants no admin authority at all.
auth:
  signing_key: { file: /run/secrets/busbar-signing.key }
  chain: [keys, sso]                            # bare provider NAMES
  role_bindings:
    sso:                                        # keyed by PROVIDER NAME
      "<role-the-plugin-asserts>": { group: engineering }
groups:
  engineering:
    limits:
      - { budget: 200000, per: month }
```

---

### `groups`

The ONE limit tree. A group is a named enforcement bucket: an ordered list of generic limits plus
an optional `parent` forming an acyclic chain (any depth). Keys are pure auth and carry no limits;
a key binds to at most one group at mint, and every request walks the chain UP through `parent`,
enforcing EVERY limit of EVERY group (AND, atomically, all-or-nothing charging).

```yaml
groups:
  acme:
    limits:
      - { requests: 500, per: minute }
      - { budget: 1000000, per: month }
  growth:
    parent: acme
    limits:
      - { requests: 50, per: minute }
      - { budget: 200000, per: month }
  bob:
    parent: growth
    enabled: true                    # false = freeze this group (and every descendant's traffic)
    limits:
      - { requests: 10,   per: minute }
      - { requests: 1000, per: day }
      - { concurrent: 5 }            # no `per` = instantaneous in-flight cap
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `parent` | string | none | The parent group; must exist; the chain must be acyclic (validated with paste-ready fixes). Any depth. |
| `enabled` | bool | `true` | `false` FREEZES the group: every request charging through it (its own keys and every descendant's) is rejected with a 403 naming the group, while its usage history is kept. |
| `limits` | list | `[]` | Each entry has exactly ONE metric key: `requests`, `tokens`, or `budget` with a required `per:` window (`minute` \| `hour` \| `day` \| `month` \| `total`), or `concurrent` with NO `per:` (instantaneous). An optional `pool: <name>` on a windowed metric scopes the limit to that pool's traffic (see below); the pool must exist. A metric repeated for the same window + pool scope keeps the most restrictive amount. |
| `child_default` | `{ limits: [...] }` | none | The limit template stamped onto any CHILD group auto-provisioned under this one (see below). Provisioning-time only: it never affects THIS group's own enforcement. |

**Metric semantics:**

- **`requests`** is precise: the counter increments synchronously at admission. Rejection: 429
  naming the bucket (e.g. `group 'bob': requests per minute`) with `Retry-After` to the window
  roll (`total` never rolls, so no header).
- **`tokens`** is best-effort post-paid: tokens land after each response, so the cap blocks the
  NEXT request once the ledgered total crosses it. Rejection: 429 + `Retry-After`.
- **`budget`** derives at admission from the bucket's exact class ledger and dated rate-card history,
  including fee units. The `budget` amount is in MINOR units: hundredths of the abstract cost unit
  the card is priced in (cents when you price in dollars), so `budget: 5000` is 50 cost units. Rejection: the vendor's native
  quota status (429 for most protocols; Bedrock's quota shape is 400-class), naming the bucket.
- **`concurrent`** is an in-flight gauge: incremented at admission, released when the response
  stream completes. Rejection: 429, no `Retry-After`. Takes no `pool:` (the gauge is per group).

**Pool-scoped limits (`pool:`).** A windowed limit may carry `pool: <name>`, making it account and
enforce per `(group, pool)` instead of group-wide, the per-tier budget split:

```yaml
groups:
  dev-team:
    limits:
      - { budget: 5000, per: month, pool: frontier }   # expensive tier: its own bucket
      - { budget: 5000, per: month, pool: value }      # cheap tier: its own bucket
```

Each pool-qualified limit gets its own ledger bucket (`group:<name>@<window>#<pool>`): exhausting
the `frontier` budget blocks only requests dispatched through `frontier` (the rejection names the
pool), while `value` traffic still admits against its untouched bucket. Group-wide limits (no
`pool:`) still count ALL traffic, and everything ANDs across the chain as usual. Token accrual and
non-2xx refunds mirror the admission exactly: they touch only the buckets the request's pool
charged. The named pool must exist in `pools:`. A dangling qualifier fails validation (it would
be an unenforced budget).

**Budgets that teach (`on_exhaust: downgrade`).** A pool-scoped `budget` limit may declare what
its exhaustion does instead of refusing:

```yaml
groups:
  dev-team:
    limits:
      - { budget: 5000, per: month, pool: frontier,
          on_exhaust: downgrade, downgrade_to: value }   # exhausted → reroute, don't refuse
      - { budget: 5000, per: month, pool: value }
```

When the frontier budget runs dry, a frontier request is **re-admitted and dispatched through
`value`**. The caller's expensive calls get cheaper, not blocked. The charge lands on the
effective pool's buckets (accounting follows the traffic), the key's pool ACL is re-checked on
every hop (a downgrade can never route a key into a pool it may not use: a denied hop falls back
to the plain quota rejection), and cascades are cycle-bounded. Absent (or `on_exhaust: block`),
exhaustion rejects with the vendor's quota status, today's default. `downgrade` requires
`downgrade_to:` naming a different existing pool, a `pool:` scope, and the `budget` metric (all
validated at the door).

**Auto-provisioned children (`child_default`).** A group may carry a limit template for children
created under it at runtime (e.g. a per-user `user:<sub>` leaf provisioned on first self-mint):

```yaml
groups:
  org:
    child_default: { limits: [ { budget: 500, per: month } ] }   # the org-wide default
  engineering:
    parent: org
    child_default: { limits: [ { budget: 2000, per: month } ] }  # overrides the org's for ITS children
  accounting:
    parent: org                                                  # no template of its own
```

The template's `limits:` use the same shape as any group's `limits:`. Resolution is
**nearest-ancestor-wins**: provisioning walks up from the immediate parent and copies the first
`child_default` it finds: a leaf under `engineering` gets the 2000 budget, one under `accounting`
inherits the org's 500. No template anywhere on the chain means the new child is **inherit-only**:
no limits of its own, capped solely by the parent chain. `child_default` never changes what the
declaring group itself enforces, and pool qualifiers inside a template are validated like any
other limit's.

---

### `rate_card` and `per_request_fee`

Host-owned rate cards are the cost source.
Every billable class a plane declares is the ledger (the four reserved LLM
token tiers, plus any OPEN class a plane counts — a rerank's `search_units`, an A2A hop's `bytes`).
Every count a provider reports is a ledger line under its class (owner ruling LEDGER-100): beside
its tokens the LLM plane ledgers `search_units` (rerank search units, Anthropic web searches),
`classifications` (Cohere `billed_units.classifications`), `web_fetch_requests` (Anthropic),
`unitemized_tokens` (the tokens a provider's stated total counts above its itemized buckets),
`images` (per-image answers: dall-e, Imagen, Titan, SDXL), `audio_ms` (a transcription's reported
duration, in whole milliseconds) and one class per Bedrock guardrail policy-unit count
(`guardrail_*`). None of these counts toward a `tokens:` cap;
every spend figure is DERIVED at read time from exact class counts and the applicable dated rates,
including fee units. A new card prices subsequent arrivals without repricing earlier usage.
An attributed backdated amendment corrects only its declared window; `as_of` selects a reproducible
history point. No derived money or rewritten booked row is stored. Card history and activation
confirmation belong to the configured Store: a new card activates only after the Store confirms it
was saved, and boot refuses if it cannot confirm its card.

```yaml
rate_card:
  sonnet-anthropic: { input_utok: 3.0, output_utok: 15.0, cache_read_utok: 0.3, cache_write_utok: 3.75,
                       units: { search_units: 0, classifications: 0, web_fetch_requests: 0,
                               unitemized_tokens: 0, images: 0, audio_ms: 0,
                               guardrail_automated_reasoning_policies: 0,
                               guardrail_automated_reasoning_policy_units: 0,
                               guardrail_content_policy_image_units: 0, guardrail_content_policy_units: 0,
                               guardrail_contextual_grounding_policy_units: 0,
                               guardrail_sensitive_information_policy_free_units: 0,
                               guardrail_sensitive_information_policy_units: 0,
                               guardrail_topic_policy_units: 0, guardrail_word_policy_units: 0 } }   # open classes: free, but explicitly configured
  sonnet-bedrock:   { input_utok: 2.8, output_utok: 14.0, cache_write_utok: 3.5 }
per_request_fee: 0
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `rate_card` | map | absent (usage-based pricing off) | Rates keyed by configured model and plugin-declared unit. A present card must name every configured model: otherwise startup, `--validate` and `PUT /config/settings` refuse with a paste-ready zeroed stub of exactly the missing models (the card is AUTHORITATIVE and COMPLETE). A named model missing an open-unit rate only warns; quantities are still recorded and that unit is unpriced, not free. Configure an explicit `0` for a free unit. An omitted `input_utok`, `output_utok` or `cache_read_utok` prices at 0; an omitted `cache_write_utok` prices at `input_utok` (no separate write tariff, never 0). Invalid rates, unknown model names and undeclared unit names remain errors. Rates use MICRO-units (1e-6 abstract cost unit); `*_utok` values must be exactly representable in whole nano-units, with at most three decimal places. |
| `units` | map, per entry | `{}` | Rates for OPEN (non-reserved) billable classes, alongside a model's four `*_utok` tiers: `{ <class>: <rate> }`, same MICRO-units-per-unit scale. The wire form is a non-negative integer, or an exact decimal STRING (`"0.5"`); a bare YAML/JSON float is refused — it has already lost precision through a binary double by the time serde sees it. A rate finer than 0.001 micro-units per unit, negative, or past ~1.8e16 is refused at parse ("finer than one nano-unit, the finest rate the card holds; round it to three decimal places"). A reserved class name (`input`, `output`, `cache_read`, `cache_write`) under `units:` is refused — it already has its own `*_utok` field. An unpriced class under a card that IS configured for the model REFUSES at the point it is hit, rather than silently billing `0` (see [Virtual keys and enforcement](#virtual-keys-and-enforcement)). |
| `per_request_fee` | integer | `0` | Flat charge per request in MINOR units (hundredths of the abstract cost unit, the same unit as a `budget` limit), charged at admission into every chain bucket's request count (refunded on a non-2xx outcome). |

Plugins report measurements, not prices. The host records each report under the current work's
identity and computes cost from the ledger and applicable rate card. Unit names are plugin data:
adding a new measured unit does not require a provider-specific pricing branch in core.
A missing measurement is unknown; it must not be replaced with zero or a different unit.

The rate numbers are **abstract cost units**: Busbar does pure integer math and never knows what
currency they represent. Currency, symbols, and FX are display concerns owned by your dashboard.
Routing's `cheapest` strategy derives its per-member scalar from the card as
`(input_utok + output_utok) / 2`; pool members carry no cost fields.

A configured rate the card cannot hold is a BOOT refusal, not a silent unpriced cell: a `*_utok`
tier below half a nano-unit (e.g. `0.0004`) or past ~1.8e16 fails validation naming the model, the
tier and the rate —

```text
rate_card['<model>'].<tier> = <rate> micro-units per token is a rate the card cannot hold
(non-zero rates run from 0.0005 to about 1.8e16), so the class would bill as unpriced;
configure 0 to make it free, or a rate in range
```

— rather than booting and refusing on the first hit. Configure an explicit `0`, or a rate inside
the representable range.

<!-- docs-truth: `plugin_rate_cards` is not a configuration key: the config file and `PUT /config/settings` refuse it as an unknown field (`DeployCfg` and `RootSettings` deny unknown fields and have no such member). Plugin measurement rates are set only by a signed rate-history amendment of a measurement lane (`POST /ledger/amend-rate-history`), and the stored card keeps what it set. -->

#### Per-plane rate cards (`tools.rate_card`, `agents.rate_card`, `streams.rate_card`, `decisions.rate_card`)

The reserved `rate_card` key is also accepted, core-owned, under every non-LLM plane's own section —
`tools:`, `agents:`, `streams:`, `decisions:` — one card per plane, resolved independently of the
flat/`pools` card above and of every other plane's card. Each entry is the same `{ *_utok fields,
units: {...} }` shape (a non-LLM plane's classes are all OPEN, so only `units:` is meaningful for
it); the field-by-field grammar for each is documented in
[MCP](mcp.md) (`tools.rate_card`, keyed by tool name — prices `tool_calls` and `bytes`),
[A2A](a2a.md) (`agents.rate_card`, keyed `agent:<id>` — prices `bytes`, the request + response
body bytes an A2A hop relayed both ways), and
[voice.md](voice.md) (`streams.rate_card`). The same rule applies to every plane:
its plugin declares the units it measures, and the host checks its configured lanes against
those declarations. A present card must carry an entry for every configured
lane (for example every agent under `agents:`); one silent about a lane fails boot and every apply
with a paste-ready stub. Missing unit rates on a named lane produce warnings naming the lane and
units. A missing card disables usage-based pricing for that plane; a named lane missing a unit
rate leaves that unit unpriced. Neither case discards recorded quantities. An explicit zero rate makes a unit
free. Spend-budget admission and complete cost calculations still require the relevant rates;
a warning does not authorize treating an unknown cost as zero. `GET /usage`, `/groups/{name}/usage` and `/keys/{id}/usage` surface that refusal as
`409 unpriced_class` (`{"error":{"code":"unpriced_class","message":"usage cannot be priced: the
rate card in force names no price for class \`<class>\` of \`<lane>\`"}}`) instead of a bare `500
internal`; no figure moves, only the status and code the caller sees change.

> **Upgrading from 1.5.5.** A 1.5.5 `rate_card:` that names every configured model still boots, but
> each class its plane declares and the card does not price is left unpriced, with a warning naming
> the lane and classes. To keep 1.5.5's billing, add the `units:` map above (every LLM open class
> at `0`) to any one entry of the flat/`pools` card, and price the ones you bill. The
> declared classes per plane are: `pools` (LLM) = `input`, `output`, `cache_read`, `cache_write`,
> `search_units`, `classifications`, `web_fetch_requests`, `unitemized_tokens`, `images`, `audio_ms`, `guardrail_automated_reasoning_policies`, `guardrail_automated_reasoning_policy_units`, `guardrail_content_policy_image_units`, `guardrail_content_policy_units`, `guardrail_contextual_grounding_policy_units`, `guardrail_sensitive_information_policy_free_units`, `guardrail_sensitive_information_policy_units`, `guardrail_topic_policy_units`, `guardrail_word_policy_units`; `tools`
> (MCP) = `tool_calls`, `bytes`; `agents` (A2A) = `bytes`; `decisions` = `decision`, `input_tokens`,
> `output_tokens`; `streams` (voice) = `audio_tokens_in`, `audio_tokens_out`, `text_tokens_in`,
> `text_tokens_out`, `audio_seconds_in`, `tool_calls`, `image_tokens_in`, `video_tokens_in`. (`cached_tokens` is reported by both duplex dialects but is
> a SUBSET of the input token classes above, not a class beside them — pricing it too would
> double-bill the same cached input, so it is not a declared billable class; it is carried,
> unbilled, as attribution only.) A plane with no `rate_card` of its own is unaffected (absent =
> billing off, no refusal).

---

### `store`

The store as a plugin instance: `{ module, settings }`. **Required in 1.6.0**: a config without a `store:` block is refused (BUSBAR-3120), and the first 1.6.0 boot of a 1.5.5 config inserts `store: {module: memory}`. There is no default store. `memory` is the one store compiled into the binary (keys, usage, and the audit log reset on restart); every durable backend is a `kind: store` plugin, a signed tarball released and documented on its own.

```yaml
store:
  module: <store-plugin>        # the alias of an admitted `kind: store` plugin
  settings: { }                 # that plugin's own configuration
```

| `module` | Source | `settings` |
|---|---|---|
| `memory` | compiled in, no plugin | none |
| a `kind: store` plugin alias | signed plugin tarball in `plugins.dir` | the plugin's own keys; see the plugin's documentation |

`settings` is the store module's OWN opaque configuration, passed through verbatim. A non-`memory` store requires `plugins.enabled: true` and the store's tarball in `plugins.dir`, or Busbar refuses to boot naming the flag/plugin. Which durable stores exist, what each one's `settings` take, and whether a store is single-node or cluster-shared are the store plugin's own documentation, not core's.

**Fleet semantics (honest):** with a cluster-shared store behind N Busbar nodes,
virtual keys, accumulated usage, the audit log, and the revocation denylist are genuinely shared.
The limit hard caps are enforced PER NODE from each node's in-memory counters and reconciled
durably through ADDITIVE flushes, so the shared store converges on the true fleet total, but
between flushes N nodes splitting traffic can admit up to ~N times a configured cap. The caps are
not a synchronous cluster-wide gate.

**Metering retention (all backends):** `usage_metering` rows are one per (key,
metering-bucket day, model, provider), accumulated forever. Busbar has no prune path on any store
backend, because metering is observability only,
never consulted for enforcement. Row
CARDINALITY is bounded by your config (keys × buckets × models × providers), but the TIME dimension
is not, so the table grows without bound unless you retain it yourself. `list_metering(bucket)` reads
exactly one day, so deleting rows for buckets older than N days is safe and cannot affect admission,
billing, or any other enforcement path. It is a plain `DELETE` against your store's own schema, on
your own retention horizon; Busbar does not choose one for you.

**Backend caveats:** transport security for a store's network connection follows the
[plaintext rule](#advancedtls): the connection goes through the host connector, which verifies TLS
against `advanced.tls` and refuses opportunistic or plaintext modes unless the instance carries an
explicit `insecure_transport` acceptance. Retention, TTLs and TLS options beyond that are the store
plugin's own documentation.

---

### `providers`

Declares which catalog providers this deployment uses and supplies the env var holding each one's credential.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `api_key` | secret reference | **yes** | n/a | The upstream credential as a secret reference: `{ env: VAR }`, `{ file: /path }`, `{ module: <secret-plugin>, settings: {...} }`, or the bare scalar `none`. Resolved once at boot, **fail-closed**: a reference that does not resolve (unset variable, missing or empty file, unknown module, secret-plugin error) **refuses boot** under `BUSBAR-8020` and fails `--validate` — it never degrades to an empty credential. `api_key: none` declares an upstream that takes NO credential (a local ollama or vLLM, reached under the [destination guard](#advanced)): the lane starts, no auth header is sent, and the health prober skips it. `none` is rejected with `auth: jwt-bearer` and `auth: oauth-client-credentials`, which mint their token FROM the credential. Omitting `api_key` is still an error. |
| `protocol` | string | no | Catalog value | Override the catalog protocol. Rarely needed. An omitted value takes the catalog entry's `protocol`, which is required there. |
| `base_url` | string | no | Catalog value | Override the upstream base URL. Must use `https://` for public/external hosts. The scheme check admits plain `http://` for a private or loopback host (e.g. a local Ollama or vLLM instance); the connection itself is still judged by the [destination guard](#advanced). <!-- docs-truth: whether a configured provider host on a private address is dialed depends on the unbuilt guard change described under the destination guard (owner ruling 23:15Z) --> Cloud-metadata hosts are blocked regardless of scheme (see SSRF guard). |
| `error_map` | map<string, string> | no | `{}` merged onto catalog | Merged with the catalog's `error_map`; deployment entries win per code. |
| `path` | string | no | Catalog value | Override the upstream path. Must begin with `/`. |
| `path_base` | string | no | Catalog value | Override the URL-model base segment (Gemini or Anthropic), keeping the per-request verb suffix. Must begin with `/`. For Gemini-on-Vertex and Claude-on-Vertex. |
| *provider options* | per name | no | none | Any value the provider's own API accepts in a request header or query parameter, written under the provider's own name directly in the entry (see [Provider options](#provider-options)). |
| `auth` | string | no | Catalog value | The egress auth style: a word declared by an admitted `kind: auth` plugin, or a `module:` instance name (see the catalog `auth` field above). |
| `token_url` | string | no | Catalog value | OAuth token endpoint for `oauth-client-credentials`. |
| `scope` | string | no | Catalog value | OAuth scope for `oauth-client-credentials`. |
| `subject` | string | no | Catalog value | JWT-bearer assertion `sub` claim (RFC 7523 §3) for `jwt-bearer`. Opt-in. See the catalog `subject` row above; unset means no `sub` claim, the correct default for a plain Vertex AI service account. |
| `health` | object | no | Catalog value | Override the catalog's health probe config. |
| `allow_metadata_hosts` | list<string> | no | — | **Retired in 1.6.0 and refused** (BUSBAR-3136): cloud metadata is refused for every outbound connection and no configuration admits it. the first-boot migration removes it (BUSBAR-3411). |

**Credential format by protocol** (the VALUE the `api_key` reference resolves to):

| Protocol | Resolved credential format | How it's sent |
|---|---|---|
| `anthropic` | API key (`sk-ant-api…`) or OAuth token (`sk-ant-oat…`) | `x-api-key: <key>` for API keys; `Authorization: Bearer <key>` for OAuth tokens. Mode is inferred from the key prefix; both headers are sent if the prefix is unrecognized. `anthropic-version` header is always added. |
| `openai` / `responses` / `cohere` | API key | `Authorization: Bearer <key>` |
| `openai` + `auth: api-key` (Azure) | API key | `api-key: <key>` |
| `gemini` | API key | `x-goog-api-key: <key>` |
| `bedrock` | `ACCESS_KEY_ID:SECRET_ACCESS_KEY` or `ACCESS_KEY_ID:SECRET_ACCESS_KEY:SESSION_TOKEN` | AWS SigV4: signed per request. Region is parsed from the host in `base_url` (e.g. `bedrock-runtime.us-east-1.amazonaws.com`). |

```yaml
providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }
  openai:
    api_key: { env: OPENAI_KEY }
  gemini:
    api_key: { file: /run/secrets/gemini-key }
    health:
      mode: dead
      interval_secs: 60
  bedrock-us-east-1:
    api_key: { env: AWS_BEDROCK_CREDS }   # ACCESS:SECRET or ACCESS:SECRET:SESSION
```

**Reserved name:** a provider named `admin` (or any name beginning with `admin/`) is a startup error.

---

### `models`

A model is a **lane**: one model at one provider, with its own concurrency semaphore, lifetime budget, and breaker cell. Models must be defined here before they can be used as pool members or targeted directly.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `provider` | string | **yes** | n/a | Must name a key in this file's `providers` map. |
| `max_concurrent` | integer | no | unset (unbounded) | Optional per-lane concurrency limiter: the max simultaneous in-flight requests for this lane (semaphore size). **Omit it for no cap** (unbounded): a limiter you opt into, mirroring `max_requests`. Set a positive integer to cap. Must be ≥ 1 when set (`0` = a lane that never admits a request = startup error). |
| `max_requests` | integer | no | `-1` | Lifetime request budget. `-1` (default) = unlimited. When the counter reaches `0` the lane is unusable. Must not be `0` (zero budget = permanently unusable = startup error). |
| `default_max_tokens` | integer | no | `4096` | Injected **only** on a cross-protocol hop to a backend that requires `max_tokens` (Anthropic protocol) when the caller omitted it. Has no effect on same-protocol passthrough. Must be > 0 when set. |
| `upstream_model` | string | no | the config key | The model id sent to the provider on the wire (request body for body-model protocols; URL path for path-model protocols like Bedrock/Gemini; and health probes). Defaults to the config key. Set it when the key can't be the wire id: most commonly to run the **same model behind two providers** (the keys must differ, but each needs its own provider-specific model string). Must be non-empty when set. Metrics, breaker cells, and logs still key off the config key, not this. |
| `attempt_timeout_ms` | integer | no | unset (no cap) | Per-attempt cap, in milliseconds, on time to **response headers** (the hang detector). If the provider has not started answering within the cap, the attempt is treated exactly like a transport timeout: the breaker records a transient failure and the request fails over to the next pool member within the same request. Because the cap covers only connect + headers, a healthy long **stream body** is never cut off by it. A pool member's own `attempt_timeout_ms` overrides this per pool. Must be ≥ 1 when set (0 is a startup error); always floored by the request's remaining `failover.timeout_secs` budget. |
| `reasoning` | bool | no | `false` | Operator declaration that this model accepts reasoning/thinking request parameters (Anthropic `thinking`, Gemini `thinkingConfig`, OpenAI `reasoning_effort`). Gates the [cross-protocol reasoning carry](#cross-protocol-reasoning-reasoning): without the flag, a translated reasoning ask is dropped at the seam (warned) and never sent, so a non-reasoning model can never 400 from translation. Capability is per-model, not per-provider (Sonnet takes `thinking`; Haiku rejects it). You declare what you deployed, like `context_max`. A pool member's `reasoning` overrides this per pool. Same-protocol passthrough ignores it. |
| `prompt_caching` | bool | no | `false` | Operator declaration that this model accepts prompt-cache markers on dialects where the marker is **model-gated**: Bedrock Converse's `cachePoint`, which Claude accepts but Amazon Nova hard-rejects with a 400 ("extraneous key"). The cache twin of `reasoning`: without the flag, cross-protocol `cache_control` breakpoints headed to such a dialect are dropped at the seam (warned) and the request proceeds uncached, fail-safe, never a translation-induced 400. Set it on Claude-on-Bedrock models to keep their prompt caching across the Anthropic→Bedrock translation. Dialects whose cache form is universally accepted (the Anthropic API's `cache_control`) ignore the flag, as does same-protocol passthrough (byte-exact). |

```yaml
models:
  claude-sonnet-4-5:
    provider: anthropic
    max_concurrent: 20
    max_requests: -1
    default_max_tokens: 8192

  gpt-4o:
    provider: openai
    max_concurrent: 20

  gemini-1.5-pro:
    provider: gemini
    max_concurrent: 15

  nova-pro:
    provider: bedrock-us-east-1
    max_concurrent: 10
```

**Direct routing:** a model named `my-model` is reachable at `POST /my-model/v1/messages` (Anthropic ingress). The ad-hoc route `POST /{provider}/{model}/v1/messages` bypasses the model map entirely: it routes to the named provider with the named model string, using no pool.

**Reserved name:** a model named `admin` is a startup error.

#### Same model, two providers (`upstream_model`)

To run one real model: say Claude 3.5 Sonnet, behind **both** Anthropic and Bedrock in a single failover pool, the two model keys must differ (keys are unique), but each provider expects its own model string. `upstream_model` carries the provider-specific wire id while the key stays a stable operator alias:

```yaml
models:
  sonnet-anthropic:
    provider: anthropic
    max_concurrent: 20
    upstream_model: claude-3-5-sonnet-20241022             # what Anthropic expects on the wire
  sonnet-bedrock:
    provider: bedrock-us-east-1
    max_concurrent: 10
    upstream_model: anthropic.claude-3-5-sonnet-20241022-v2:0   # Bedrock's modelId

pools:
  sonnet:                                  # clients call ONE name: POST /sonnet/v1/messages
    members:
      - model: sonnet-anthropic
        weight: 3                          # primary
      - model: sonnet-bedrock
        weight: 1                          # cross-provider failover lane
```

Clients always address `sonnet`; when Anthropic rate-limits or trips its breaker, Busbar fails over in-flight to the **same model** on Bedrock. Health probes use `upstream_model` too, so a lane can't report healthy on the alias while real traffic fails on the wrong upstream id. Models without a collision (e.g. `gpt-4o`) need no `upstream_model`: the key already is the wire id.

---

### `pools`

A pool is a named, weighted group of model lanes with shared failover, breaker, and affinity config. Pools are optional, a deployment can route directly to models without any pools.

**Target a pool** with `POST /smart/v1/messages` (Anthropic ingress), or by setting `"model": "smart"` in `POST /v1/chat/completions` (OpenAI ingress), `POST /v2/chat` (Cohere), etc.

**Reserved name:** a pool named `admin` is a startup error. A pool name must not collide with any provider or model name.

#### Members and weights

```yaml
pools:
  smart:
    members:
      - model: claude-sonnet-4-5
        weight: 8
      - model: gpt-4o
        weight: 2
      - model: gemini-1.5-pro
        weight: 1
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `model` | string | **yes** | n/a | Name of a model in `models`. Must be a configured model; a missing model is a startup error. |
| `weight` | integer | no | `1` | Relative selection share under smooth weighted round-robin (SWRR), computed over the currently healthy/usable members. Must be ≥ 1. `0` is a startup error. |
| `context_max` | integer | no | none | This member's maximum context window (tokens). Used for [context-length failover](#context-length-failover). |
| `attempt_timeout_ms` | integer | no | the model's value | Per-attempt time-to-response-headers cap for this member **in this pool**, overriding the model-level `attempt_timeout_ms`. Lets the same model carry different hang tolerances per pool (e.g. `10000` in a batch pool, `50` in a latency-critical one). Must be ≥ 1 when set (0 is a startup error). See [Per-attempt timeouts](#per-attempt-timeouts-attempt_timeout_ms). |
| `reasoning` | bool | no | the model's value | Per-pool override of the model-level `reasoning` capability flag (member wins), so the same lane can allow thinking in a research pool and refuse it in a latency-critical one. See [Cross-protocol reasoning](#cross-protocol-reasoning-reasoning). |
| `tier` | string | no | none | Operator-declared routing tier label (e.g. `"primary"`, `"overflow"`, `"large"`, `"small"`). Inert for plain weighted pools (no hooks). Exposed to gate hooks as the `tier` field on each candidate. See [Pool `hooks`](#pool-hooks-ordering-and-gates). |
| `tags` | list<string> | no | `[]` | Free-form string labels (e.g. `["opus", "large-context"]`). The `restrict` gate verb intersects the candidate set against these tags (compliance pinning). Exposed to gate hooks for tag-based candidate selection. Inert for plain weighted pools. |

The member object above is the canonical form and the one the 1.6.0 upgrade preserves as written. A pool whose members carry nothing but a weight may instead list them as bare model names with a pool-level `weights: { <model>: <n> }` map; the two spellings are equivalent, may be mixed, and an inline `weight:` wins over the map for that member. A pool-level `tier:` and `attempt_timeout_ms:` likewise apply to every member that does not state its own. With `weights:` absent and bare names only, the pool is an ordered failover list with the first member as primary.

Selection uses Nginx-style smooth weighted round-robin (SWRR) across the healthy subset. A tripped, dead, or capacity-exhausted member is skipped and its share redistributes to the remaining members automatically. Selection state is isolated per-pool (separate SWRR shard), so unrelated pools that share a lane select independently.

**Empty `members` list is a startup error.**

A pool spanning members that use different underlying protocols produces a startup **warning** (not an error). Cross-protocol requests are translated via the IR (intermediate representation), which carries every field it models into the target's native shape. Source-only fields (e.g. OpenAI `logit_bias`) are dropped before reaching a foreign backend, and so are the few standard ones with no representation on the target at all; the list is in [Fields the target protocol cannot express](https://getbusbar.com/docs/protocols/#fields-the-target-protocol-cannot-express), and every drop emits a `warn!` naming the field. Attachments (documents, audio, video) cross. Same-protocol members are unaffected: those requests are forwarded byte-for-byte.

---

#### Per-attempt timeouts (`attempt_timeout_ms`)

Some providers fail by **hanging**: the connection opens, then nothing comes back for minutes. The ordinary transport timeout is sized for a full response and is far too long to catch this. `attempt_timeout_ms` caps how long a single attempt may wait for **response headers**; when it expires, the attempt is recorded as a transient failure on that member's breaker cell and the request fails over to the next member, all within the same request.

Two layers, member wins over model:

```yaml
models:
  gemini-pro:
    provider: gemini
    max_concurrent: 20
    attempt_timeout_ms: 10000     # model-level default: give it 10s anywhere

pools:
  batch:
    members:
      - model: gemini-pro         # inherits the model's 10000ms
      - model: gpt-4o
  realtime:
    members:
      - model: gemini-pro
        attempt_timeout_ms: 50    # THIS pool can't wait: hop after 50ms
      - model: gpt-4o
```

Details:

- The cap covers **connect + time to response headers only**. A healthy stream that has started answering is never cut off mid-body by it.
- Expiry is classified like a network timeout: it counts toward the breaker's transient streak (repeated hangs trip the lane) and shows up in metrics as `disposition="attempt_timeout"` on `busbar_upstream_failures_total` and `reason="attempt_timeout"` on `busbar_failovers_total`.
- The cap is always floored by the request's remaining [`failover.timeout_secs`](#failover) budget; it can never extend a request past that.
- Unset means no per-attempt cap (the transport timeout still applies). `0` is a startup error; disable by omitting the field.

---

#### Cross-protocol reasoning (`reasoning`)

The reasoning/thinking ask translates between the three protocols that model it: OpenAI `reasoning_effort` and Responses `reasoning.effort` (words), Anthropic `thinking.budget_tokens` and Gemini `thinkingConfig.thinkingBudget` (token budgets). Number to number is a straight copy; words and numbers convert through the effort table below. The response-side thinking content (thinking blocks, thought parts) already translates losslessly and needs no configuration.

The ask is **gated per lane** because thinking support is per-model, not per-protocol, and Busbar keeps no model database. `reasoning: true` on a model (or a pool member, which wins) declares "this backend accepts thinking params":

```yaml
models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 20
    reasoning: true       # this model accepts thinking params
  claude-haiku:
    provider: anthropic
    max_concurrent: 40    # no flag: a translated reasoning ask is dropped (warned), never sent
```

With the flag set, an OpenAI client's `reasoning_effort: "high"` reaches this Claude lane as `thinking: {type: enabled, budget_tokens: 16384}`; a Gemini client's `thinkingBudget: 6000` reaches it as `budget_tokens: 6000`. Without the flag the request still succeeds, thinking at the backend's default level.

The effort table (word ↔ number conversion, both directions) is operator-tunable:

```yaml
limits:
  reasoning_effort_budgets:   # defaults shown; must be ascending, all > 0
    minimal: 1024
    low: 4096
    medium: 8192
    high: 16384
```

Guard rails, applied automatically: the budget is clamped to leave at least 1024 answer tokens under `max_tokens` (Anthropic requires `budget_tokens < max_tokens`), and when `max_tokens` is too small to fit any thinking the ask is dropped with a warn. Anthropic rejects `temperature`/`top_k` alongside thinking, so those knobs are omitted (warned) when a thinking ask is emitted to an Anthropic backend. Gemini's dynamic `-1` round-trips to Gemini verbatim and projects elsewhere as `medium`.

---

#### Pool `hooks`: ordering and gates

**Hooks are DEFINED once, at the top level, and REFERENCED by bare name.** The top-level
`hooks:` map is the definition surface: `<instance-name>: { module, settings, … }`. Every ATTACH
point (the reserved all-pools `pools.hooks:` list and each pool's own `hooks:` list) carries BARE
NAMES only. Inline hook instances are gone, and so is the removed top-level `global_hooks:` list.
The SAME module may back several named hooks: a different scope or different settings is a new NAME,
and the name is the instance.

A pool's `hooks:` list therefore holds two kinds of bare name:

- a **built-in ordering strategy**: `weighted` \| `cheapest` \| `fastest` \| `least_busy` \| `usage`
  (at most one per pool: it sets the base ranking; the default is `weighted`, the zero-cost SWRR
  baseline);
- a **defined hook name**: a key of the top-level `hooks:` map. Its `module:` names a loaded
  `kind: hook` plugin by signed-manifest name/alias (there are no built-in `socket`/`webhook`
  transports; a hook is always a signed plugin), so it requires `plugins.enabled: true` and the
  tarball installed in `plugins.dir`. An unresolvable `module:`, or a
  reference to a name that no `hooks:` entry defines, is a fail-closed boot error.

```yaml
plugins: { enabled: true, dir: /etc/busbar/plugins }

hooks:                                                 # the DEFINITION map (define once)
  audit:
    module: <hook-plugin>                              # a `kind: hook` plugin alias
    kind: tap
    phase: [request, response]                         # a LIST of stages; omit = all four
    on_error: nothing
  pii:
    module: <hook-plugin>                              # a `kind: hook` plugin
    settings: { }                                      # the plugin's own settings
    groups: [engineering]                              # SCOPE: omit or [] = every caller
    kind: gate
    timeout_ms: 5
    prompt: ro
    on_error: reject
  rank:
    module: <hook-plugin>                              # the SAME module, a second named hook
    settings: { }
    kind: gate
    timeout_ms: 5
    on_error: nothing

pools:
  hooks: [audit]                                       # RESERVED: attaches to EVERY pool
  upstream_credentials: own                            # RESERVED: the all-pools default
  smart:
    hooks: [cheapest, pii, rank]                       # base strategy + two gates, BY NAME
    members:
      - model: claude-sonnet-4-5
        weight: 2
        context_max: 200000
        tier: primary
        tags: ["sonnet", "fast"]
      - model: gpt-4o
        weight: 1
        context_max: 128000
        tier: primary
        tags: ["gpt4"]
      - model: gpt-4o-mini
        weight: 1
        tier: overflow
        tags: ["cheap"]
```

**The two reserved keys at the `pools:` level.** `hooks` and `upstream_credentials` are RESERVED: a
pool may not be named either (a startup error). They carry the all-pools default, and they combine
with a pool's own value differently, by TYPE:

| Reserved key | Type | Combine rule |
|---|---|---|
| `pools.hooks` | LIST | **ADDITIVE**: a pool fires `pools.hooks` ∪ its own `hooks:`. Deduped by name: a hook named in BOTH lists fires exactly ONCE, at its first position. |
| `pools.upstream_credentials` | SCALAR (`own` \| `passthrough`) | **OVERRIDE**: a pool's own `upstream_credentials:` replaces the all-pools default outright. `own` (the default) sends the configured provider credential upstream; `passthrough` forwards the caller's own. This is where the retired `auth.upstream_credentials` went: whose credential reaches the provider is a ROUTING property. |

**Semantics:**

- The `cheapest` strategy derives each member's cost scalar from the top-level `rate_card`
  (members carry no cost fields).
- All decision gates (the pool's own and every all-pools attach) fire **concurrently** per request
  and reconcile deterministically: any `reject` wins (the lowest-`priority` gate's status/message
  surfaces), `restrict`s intersect (an empty intersection applies that gate's `on_empty`,
  fail-closed by default), and with multiple `order`s the last in the chain wins. A restriction
  persists across every failover hop.

**Hook definition fields** (`hooks.<name>`, alongside the module's opaque `settings`; full model in
[Hooks](hooks.md)):

| Field | Type | Default | Description |
|---|---|---|---|
| `module` | string | **required** | The `kind: hook` plugin backing this named instance, by signed-manifest name/alias. The same module may back several named hooks. |
| `settings` | map | `{}` | The plugin's own opaque config, pushed to it via the `configure` wire message. Its keys are the plugin's own documentation; any outbound call it makes goes through the [destination guard](#advanced). |
| `groups` | list<string> | `[]` (every caller) | SCOPE: the caller groups this hook fires for. A USER is a leaf group (e.g. `user:bob`); membership walks the [`groups:`](#groups) tree, matching the caller's own group or any ancestor. |
| `phase` | list<string> | all four stages | The pipeline stages this hook fires at: `request` \| `candidate` \| `routing` \| `response`. A **LIST**. Omitting `phase:` means exactly those four core stages. |
| `kind` | `tap` \| `gate` | `gate` | `gate` = fire-and-wait (may rank/reject/restrict/rewrite); `tap` = fire-and-forget observation. |
| `timeout_ms` | integer | `1` | Hard wall-clock deadline for a gate decision. Raise it when the hook does I/O. On timeout the decision is coerced to `on_error`. |
| `on_error` | keyword or ref | `nothing` | Fallback when a gate times out / errors / saturates: a bare terminal (`nothing` \| `weighted` \| `reject` \| `first`) or a structured hook reference `{ hook: <name> }` (a chain, proven terminating at boot). A gate's deliberate `reject` reply is a decision, not a failure. |
| `on_empty` | string | `reject` | A restrict gate's empty-intersection behavior: `reject` (fail closed, 503) or `weighted` (advisory escape). |
| `prompt` | `no` \| `ro` \| `rw` | `no` | Prompt-content grant: `ro` sends the prompt read-only; `rw` additionally allows a `rewrite` reply. `rw` on a tap is a startup error. |
| `user` | `no` \| `ro` | `no` | Caller-identity grant: governance key id/name (never the secret) + the body's end-user field. |
| `priority` | integer | `0` | Chain ordering key: orders the rewrite transform chain and tie-breaks the reconcile. |
| `signals` | list<string> | `[]` | Typed signals this hook requests from the signal catalog (names are the catalog's; an unknown name fails parse). Omission grants no additional signal. Declaring a signal here is what makes the engine compute and project it. <!-- docs-truth: owner KEEP 23:15Z; CONFIG-DELTA lists `hooks.<h>.signals` as DC-7 (kept, W2g !2688 left it). -->|

The per-member `tier` and `tags` fields documented in [Members and weights](#members-and-weights)
feed the ordering strategies and gate candidates. The deciding policy and the answering member
are on the unit record (`GET /api/v1/admin/records`) and in the request log's `route_policy` field;
no response header names them.

---

#### `breaker`

Circuit-breaker tuning for one target. On the LLM plane a target is a `(pool, lane)` cell, and the state is independent per pool: a lane open in pool A can be closed in pool B. Lane-global state (hard-down, lifetime budget, concurrency semaphore) is shared across all pools.

**This block is accepted on a pool, and only on a pool.** On the LLM plane that is an entry of the top-level `pools:` map. MCP and A2A failover pools are NOT in the top-level `pools:` map: each plane's pools live under the reserved `pools` sub-key of that plane's own section (`tools.pools.<name>`, `agents.pools.<name>`), and the section a pool is written in is its plane. Such a pool takes `members:` (bare registration names from the same section; a member from another section, or one the section does not define, fails boot), `repeatable:` (the operations that may be performed twice; default none) and the same `breaker:` block with the same keys, validation and defaults as below. A plane pool written in the top-level `pools:` is read as an LLM pool, so its members are refused as unknown models; the first-boot migration moves such pools under their section. A `breaker:` on a registration itself (`tools.<server>.breaker:`, `agents.<agent>.breaker:`) is not accepted: `tools:` and `agents:` entries reject unknown keys, so it fails at boot rather than running with the block ignored. The complete MCP and A2A grammar, with every boot refusal, is in [MCP](mcp.md) and [A2A](a2a.md). The fourth plane noun, `streams:` (live voice), is a singular section rather than a named-definition registry, so it has no pools and no `breaker:` block of its own; its complete grammar is in [voice.md](voice.md). The same is true of `tools.<server>.sampling_bounds`, the per-upstream bounds on a server-initiated `sampling/createMessage` ask (`max_messages`, `max_prompt_bytes`, `max_stop_sequences`, `max_stop_sequence_bytes`, `temperature_min_milli`/`temperature_max_milli`, `max_input_response_bytes`): each defaults to a shipped ceiling and an ask past a bound is refused by name, never relayed; the full grammar is in [MCP](mcp.md).

```yaml
tools:
  search-eu: { url: "https://eu.example/mcp", pin: { mechanism: unpinned } }
  search-us: { url: "https://us.example/mcp", pin: { mechanism: unpinned } }
  pools:                                   # the MCP plane's failover pools
    search:
      members: [search-eu, search-us]      # first = primary
      breaker:
        trip: { mode: consecutive, consecutive_n: 3 }
```

```yaml
pools:
  primary:
    members:
      - model: claude-sonnet-4-5
      - model: gpt-4o
    breaker:
      trip:
        mode: error_rate
        window_secs: 30
        threshold: 0.5
        min_requests: 5
      base_cooldown_secs: 15
      max_cooldown_secs: 120
```

| Field | Type | Default | Validation | Notes |
|---|---|---|---|---|
| `trip.mode` | string | `error_rate` | Must be `error_rate` or `consecutive` | **`error_rate`**: trips when `errors/total ≥ threshold` over `window_secs` seconds, with at least `min_requests` outcomes in the window. **`consecutive`**: trips after `consecutive_n` consecutive failures regardless of window. |
| `trip.window_secs` | integer | `30` | Must be ≥ 1 | Sliding outcome window for `error_rate` mode. Outcomes older than `window_secs` are evicted. (`window_secs` is the ONLY spelling; `window_s` fails boot.) |
| `trip.threshold` | float | `0.5` | Must be in `(0.0, 1.0]` | Error fraction threshold for `error_rate` mode. `0.5` means more than half of outcomes in the window must be errors to trip. |
| `trip.min_requests` | integer | `5` | Must be ≥ 1 | `error_rate` mode: minimum outcomes required in the window before the threshold is evaluated. Prevents tripping on a single failure with no baseline. |
| `trip.consecutive_n` | integer | `3` | Must be ≥ 1 | `consecutive` mode: number of consecutive failures that trip the breaker. (`consecutive_n` is the ONLY spelling; `n` fails boot.) |
| `base_cooldown_secs` | integer | `15` | Must be ≥ 1 | Initial cooldown duration after a trip. Subsequent trips without a successful recovery double the cooldown (exponential backoff). |
| `max_cooldown_secs` | integer | `120` | Must be ≥ `base_cooldown_secs` | Maximum cooldown regardless of backoff. |

**Cooldown details.** Cooldown is exponential: `base * 2^streak`, clamped to `max_cooldown_secs`, with ±10% random jitter (seeded from time, cell address, and streak) to decorrelate simultaneous failures. A provider `Retry-After` header is always honored as a **floor** on the computed cooldown (no config knob; always enabled), hard-capped at 24 hours to prevent overflow.

**Recovery.** When a cooldown expires the breaker transitions to HalfOpen. Exactly one request becomes the recovery probe (via a single CAS); `/healthz` and SWRR selection reads never steal the probe. If the probe succeeds, the breaker closes; if it fails, the cooldown doubles and the cycle repeats.

**Disposition by error class:**

| Class | Breaker effect | Lane penalty |
|---|---|---|
| `rate_limit`, `overloaded`, `server_error`, `timeout`, `network` | Transient: increments error counter / streak, may trip | Yes |
| `auth`, `billing` | Hard-down, 30-minute sticky cooldown (`HARD_DOWN_COOLDOWN_SECS = 1800`); recovers only via successful health probe | Yes (hard) |
| `client_error` | Client fault, relayed verbatim | None |
| `context_length` | Context failover, fails over to larger-context member | None |

A `context_length` classification is suppressed on any 5xx response, it cannot mask an upstream outage.

**Omitting the `breaker` block** uses all defaults above. The defaults match ADR-0002.

---

#### `failover`

Bounds how long Busbar will retry across members for a single request.

```yaml
pools:
  resilient:
    members:
      - model: claude-sonnet-4-5
        weight: 3
      - model: gpt-4o
        weight: 2
      - model: gemini-1.5-pro
        weight: 1
    failover:
      timeout_secs: 30
      max_hops: 3
      exclusions:
        - gemini-1.5-pro   # never used as a failover destination; still receives primary traffic
```

| Field | Type | Default | Validation | Notes |
|---|---|---|---|---|
| `timeout_secs` | integer | `120` | Must be ≥ 1 | Wall-clock budget for the entire request across all hops. Exceeded → 503 immediately. (`timeout_secs` is the ONLY spelling; the `deadline_secs` alias is gone and fails boot.) |
| `max_hops` | integer | `3` | n/a | Maximum number of failover hops for one request. A hop is one upstream attempt that fails before the first response byte. (`max_hops` is the ONLY spelling; the `cap` alias is gone and fails boot.) |
| `exclusions` | list<string> | none | Each entry must name a member of **this** pool | Model names that are **never** selected as a failover destination, primary or otherwise. Use to reserve a member for affinity-only use or to permanently exclude a degraded lane. |

**Failover boundary: the first upstream byte.** Failover is only possible before the first byte of the upstream response reaches the client. Once streaming has begun (any SSE or event-stream byte sent to the client), an upstream failure cannot fail over. Busbar instead records the breaker penalty and emits an in-band SSE error event. The client is responsible for retrying at the application level.

**Budget refund.** The lifetime `max_requests` counter is decremented optimistically when a 2xx header is received. If the response body then fails to deliver (transport error after headers), the decrement is reversed, so a partial-body transport failure does not permanently consume a budget slot.

---

#### `on_exhausted`

What to do when every member of the pool is tripped, dead, or concurrency-exhausted.

```yaml
pools:
  primary:
    members:
      - model: claude-sonnet-4-5
      - model: gpt-4o
    on_exhausted: { fallback_pool: overflow }

  overflow:
    members:
      - model: claude-sonnet-4-5
      - model: gpt-4o-mini
    on_exhausted: least_bad
```

A keyword stays bare; a reference is structured (the `on_X` convention):

| Value | Behavior |
|---|---|
| `reject` | Return `503 Service Unavailable` with a `Retry-After` header. When a member is in breaker cooldown, `Retry-After` is the soonest genuine cooldown expiry; when exhaustion is pure saturation (every member at its `max_concurrent` limit, breakers closed), it is a small saturation floor instead of `1`. This is the default when `on_exhausted` is omitted. No alias spellings. |
| `least_bad` | Route to the member whose cooldown expires soonest **that still has a free concurrency permit**, even though it is Open. A soonest member that is itself at capacity is skipped in favour of a servable sibling (rather than a hard 503); only when no admissible member has a free permit does it fall through to `reject`. The request is likely to fail, but degraded service is preferred over a hard 503. This is logged as a degraded dispatch. No alias spellings. |
| `{ fallback_pool: <name> }` | Route the request to another named pool and run its full selection logic. Cycles (`primary` to `overflow` back to `primary`) and self-references are detected at startup and are errors. |
| `{ queue: { max_ms: <ms> } }` | Wait a **bounded** time for a concurrency permit to free on an at-capacity member, then dispatch on the freed lane. The waiter acquires directly on the candidate lanes' own FIFO semaphores, so a freed permit wakes **exactly one** waiter (no lost wakeup, no thundering herd). The wait is bounded by `min(max_ms, remaining failover budget)` and can never block past `failover.timeout_secs`; on winning a permit the lane's breaker is **re-checked** (a lane that tripped Open while queued is dropped and the wait continues on the rest). On deadline, a closed semaphore, or no remaining candidates it falls through to `reject`. Queueing only helps **saturation** (at-capacity) exhaustion. If every excluded member is dead / budget-exhausted / breaker-open it sheds immediately without waiting. `max_ms` is a required inner key. No alias spellings. Live park depth: `busbar_pool_queued{pool}`. |

`reject` and `least_bad` are matched as exact bare strings with no alias spellings (a typo or any other spelling is an unknown-keyword boot error). `fallback_pool` and `queue` are structured mappings with no alias spellings either, and take exactly one of `fallback_pool` / `queue` (both present is an error). **Unknown keywords or a malformed structure are a fatal startup error** (not a runtime 503).

`queue.max_ms` is validated at `--validate`/boot: it must be `> 0` (a `0` wait never queues: that is just `reject` with extra machinery) and `<=` the resolved failover budget (`failover.timeout_secs × 1000`, else the global default `120000` ms). A `max_ms` larger than the whole failover budget is clamped to it at runtime and would never reach its ceiling, so it is rejected at boot with an actionable message rather than shipped as a silent dead-letter. Exactly `max_ms == budget` is accepted (only a value strictly greater is rejected).

---

#### `affinity`

Pin a session to one pool member while that member remains healthy. Useful to keep provider-side prompt caches warm or to maintain conversational state.

```yaml
pools:
  smart:
    members:
      - model: claude-sonnet-4-5
      - model: gpt-4o
    affinity:
      mode: session
      header_name: x-session-id
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `mode` | string | `session` | `session` is the only supported value. Any other value is a startup error. |
| `header_name` | string | `x-session-id` | Request header whose value identifies the session. |

Affinity is a **preference, not a hard pin**. If the sticky member is tripped, dead, or at capacity, Busbar falls back to normal SWRR selection without failing the request.

---

#### Context-length failover

Declare each member's `context_max` so an oversized request fails over to a larger-context member instead of returning an error: and without penalizing the smaller lane, since a context-length overflow is not an upstream fault.

```yaml
pools:
  long-context:
    members:
      - model: claude-sonnet-4-5
        context_max: 200000
      - model: gemini-1.5-pro
        context_max: 1000000
```

When a member returns a context-length error, Busbar:
1. Excludes from the **current request** any candidate whose known `context_max` is ≤ the failed lane's.
2. Fails over to a member with a larger (or unknown) `context_max`.
3. Records no breaker penalty against the smaller lane.

Members without `context_max` set are always eligible for context-length failover (their capacity is unknown; Busbar treats unknown as potentially unlimited).

---

### `limits`

Optional. Exposes the operational limits below (plus `reasoning_effort_budgets`, see [Cross-protocol reasoning](#cross-protocol-reasoning-reasoning)) so operators can tune them without rebuilding. All fields default to their historical values, so omitting this block is a no-op.

```yaml
limits:
  max_inbound_concurrent: 8192    # 0 = unlimited; > 0 caps in-flight inbound and sheds excess (503)
  request_body_max_bytes: 33554432  # 32 MiB
  upstream_request_timeout_secs: 300
  tls_handshake_timeout_secs: 10
  request_body_read_timeout_secs: 30  # max gap between inbound body frames (slow-loris body defense)
  pool_max_idle_per_host: 8192   # = max_inbound_concurrent's default, by design
  pool_idle_timeout_secs: 300     # 5 min
  hard_down_cooldown_secs: 1800   # 30 min
  upstream_error_body_max_bytes: 262144  # 256 KiB
  max_honored_retry_after_secs: 86400 # 24 h
  default_max_tokens: 4096
  max_keys_per_principal: 0       # 0 = unlimited; >0 caps LIVE keys bound to one group (per-user anti-sprawl)
  max_auto_provisioned_groups: 0  # 0 = unlimited; >0 caps how many groups a mint may auto-provision
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `max_inbound_concurrent` | integer | `8192` | Global inbound concurrency cap, applied outermost (before request bodies are buffered), so it is the global bound on peak request memory: worst case is this limit times `request_body_max_bytes`. A request that arrives while the cap is full is **shed**, returned a `503` with `Retry-After` immediately, rather than queued behind the cap (the layer is a `tower::limit::GlobalConcurrencyLimitLayer` wrapped in `tower::load_shed`). `0` = unlimited (no cap layer installed). **Restart-to-apply**: it is captured once in `main()` and baked into the router at process start; a config apply swaps only the `App`, never the router, so the semaphore's permit count cannot change live. `reload_to_apply` flags `limits.max_inbound_concurrent` when set. |
| `request_body_max_bytes` | integer | `33554432` | Maximum inbound request body size (bytes). Exceeding this returns a protocol-native 413. **Partially restart-to-apply, not flagged by `reload_to_apply` (a known limitation):** the inbound 413 threshold (`axum::extract::DefaultBodyLimit`) is boot-frozen the same way as `max_inbound_concurrent` above, but the coupled egress translate/buffer cap (`limits::translate_body_max_bytes()`) reads a live snapshot re-installed on every apply. A live `PUT` therefore only half-applies: **lowering** this value moves the egress cap down immediately while the inbound 413 threshold stays at the boot value, so a request body can land in the gap between the two: accepted inbound, but no longer buffer-translatable on a cross-protocol hop, breaking the "accepted implies translatable" invariant. `reload_to_apply` does not flag this field: flagging it dotted would mis-state that the whole field is stored-not-live when three of its four consumers are in fact live. The fix (make the inbound limit read the live snapshot, or otherwise pin the coupling) is not made because it touches the request path and the router layer stack. |
| `upstream_request_timeout_secs` | integer | `300` | Per-upstream-request wall-clock timeout. Applies to both the connect and the full response. **Restart-to-apply**: the upstream `reqwest::Client` is built once at boot and reused across config applies (warm connection pools are kept deliberately), so a live `PUT` changes the stored value but not the running client. `reload_to_apply` flags `limits.upstream_request_timeout_secs` when set. |
| `tls_handshake_timeout_secs` | integer | `10` | Wall-clock cap on each inbound TLS handshake; prevents slowloris / handshake-flood. Ignored when `tls:` is absent. |
| `request_body_read_timeout_secs` | integer | `30` | Maximum time allowed between inbound request-body frames before the connection is dropped. Closes the slow-loris body gap the header-read timeout does not cover. |
| `pool_max_idle_per_host` | integer | `8192` | HTTP connection pool idle connection limit per upstream host. The default equals `max_inbound_concurrent`'s default by design (each in-flight request holds at most one upstream connection); lower it if you front many distinct upstream hosts. **Restart-to-apply** (same boot-scoped `UpstreamClients` reuse as above; `reload_to_apply` flags `limits.pool_max_idle_per_host`). |
| `pool_idle_timeout_secs` | integer | `300` | How long an idle keep-alive connection stays in the upstream pool before being closed. The 300s default keeps the warm working set alive across inter-burst gaps (TCP keepalive validates idle sockets in the meantime); lower it to shed idle sockets sooner. **Restart-to-apply** (same boot-scoped `UpstreamClients` reuse; `reload_to_apply` flags `limits.pool_idle_timeout_secs`). The connect timeout (10s) and TCP keepalive (60s) baked into the same client builder are not configurable at all. |
| `hard_down_cooldown_secs` | integer | `1800` | Sticky cooldown for `auth`/`billing` breaker dispositions (hard-down). Recovering these lanes requires a successful health probe. |
| `upstream_error_body_max_bytes` | integer | `262144` | Maximum bytes buffered from a non-2xx upstream response body for error classification. |
| `max_honored_retry_after_secs` | integer | `86400` | Maximum value honored from an upstream `Retry-After` header (to prevent overflow). |
| `default_max_tokens` | integer | `4096` | Gateway-wide default injected on cross-protocol hops to Anthropic when the caller omitted `max_tokens`. Overridden by a per-model `default_max_tokens` when set. |
| `max_keys_per_principal` | integer | `0` | Anti-sprawl cap: the maximum number of **live** keys (enabled and not revoked) that may be bound to one group, the unbound bucket included. `0` = unlimited. Enforced on `POST /keys` **and** on a `PATCH /keys/{id}` rebind; over cap is a terminal `409 conflict`. |
| `max_auto_provisioned_groups` | integer | `0` | Anti-sprawl cap on the SHAPE of the limit tree: the maximum size of the runtime group set that `POST /keys` may grow by auto-provisioning (`parent:`). `0` = unlimited. Over ceiling is a terminal `409 conflict`; binding to an existing group is unaffected. |

<!-- docs-truth: `limits.datagram_line_memory_bytes` is deleted by !2658 (unmerged; the limit becomes unlimited, its former default); its row and the datagram LINE memory-credit paragraphs are removed. Dev still accepts the key until that MR lands. -->

---

### `export`

**`export:` is the single telemetry-egress surface.**
It is a NAMED map (`<instance-name>: { module, settings }`), so the SAME module can back SEVERAL
instances, which the retired type-keyed block could not express at all (two request-log webhooks to
two URLs is a real deployment: app logs plus SIEM). Presence is the switch; an absent/empty block
leaves collection inert.

```yaml
store: { module: memory }
export:
  <instance-name>: { module: <export-plugin>, settings: { } }   # a `kind: export` plugin and its own settings
  <second-name>:   { module: <export-plugin>, settings: { } }   # the SAME module may back several instances
```

Each `module:` names a `kind: export` plugin (an admitted signed plugin, or one linked into the
binary) and `settings:` is that plugin's own opaque configuration, passed through verbatim. Which
modules exist, the streams each carries (metrics, logs, traces), their `settings` keys, defaults
and limits (whether an instance is singleton, whether a route is mounted, delivery bounds, credential
handling) are each plugin's own documentation, not core's. What core owns:

- the named-map shape and `module` / `settings` contract above;
- every outbound connection an export instance makes goes through the [destination guard](#advanced)
  and the [outbound TLS trust store](#advancedtls); a metadata host is always refused;
- the restart and admin-API behavior below.

Export instance membership, `module`, `streams` and `fields` are **restart-to-apply** for push
delivery: the process keeps its boot-opened sinks and their projections. Removing a definition
therefore does not guarantee that its push delivery has stopped until restart. Settings of an
existing instance of the same module are refreshed live; a refused refresh retains its prior
settings and logs a warning.

The named-map admin API reports boot-bound changes through `reload_to_apply` and `note`, with
`export.<name>` identifying the instance. A pending export deletion returns `200` with those fields;
a fully live deletion returns `204`. Route mounting has its separate restart requirement: a route
absent at boot remains unavailable until restart. Export definitions are not part of the single-value
`PUT /config/settings` overlay.

**Response headers moved.** `Server-Timing: busbar;dur=<ms>` (formerly `observability.emit_server_timing`) is now an `advanced.response_headers` toggle, default `false`. The 1.5.5 `x-busbar-route-policy` / `x-busbar-route-target` headers and their `route_policy` toggle are removed (see [migration-1.6.md](migration-1.6.md)). See [`advanced`](#advanced) below and [observability.md#response-headers](observability.md#response-headers) for the full catalogue. the first-boot migration moves an old `observability.emit_server_timing` key for you; the old key is otherwise an `unknown field` boot error.

---

### Virtual keys and enforcement

The identity/enforcement model in one page. (The config pieces live in the sections above:
[`auth`](#auth) for the chain and role bindings, [`groups`](#groups) for the limit tree,
[`rate_card`](#rate_card-and-per_request_fee) for pricing, [`store`](#store) for durability.)

**A minted key is a busbar-SIGNED, EXPIRING token** `{sub, exp, kid}` (ed25519, signed with
`auth.signing_key`). Verification is stateless: signature + expiry + a small revocation denylist.
Policy (the bound `group`, `allowed_pools`) is resolved from the store by `sub`, so an operator
can rebind or freeze a key without re-issuing the credential. Keys are PURE AUTH: they carry NO
limits; every cap lives on the bound group's chain, and a key with no group is authed +
unlimited (access only).

**Mint** (`POST /api/v1/admin/keys`, guarded by `auth.admin_auth`):

```json
{ "name": "bob-laptop", "group": "bob", "allowed_pools": ["fast"],
  "labels": { "team": "growth" }, "expires_in": "7d" }
```

- `group` must name a configured `groups:` entry (`400` otherwise). Omitted = unlimited key. **Auto-provision**: when `group` names a leaf that does NOT yet exist and `parent` names an existing group, the leaf is created automatically (limits stamped from the nearest-ancestor `child_default`; inherit-only when none), bound to the key, and live in the enforcement chain immediately. If the group already exists, `parent` must match its actual parent (`409` otherwise: a mint never re-homes). Requires `full` scope.
- `allowed_pools` omitted = ALL pools; an explicit `[]` = NO pools (C6: an empty list is the
  empty set). The intent is stored exactly as given.
- `expires_in` / `expires_at` are mutually exclusive; the default lifetime is 90 days.
- `"issue_aws_credential": true` additionally returns `aws_access_key_id` +
  `aws_secret_access_key` for Bedrock-SDK (SigV4) clients: both shown once.
- The signed token is returned ONCE and never stored (the store holds the binding, ledger, and
  denylist, not the token).
- `limits.max_keys_per_principal`: when set to a positive integer, caps how many keys may be
  bound to one group (a group = one principal in the self-service model). An over-cap mint is a
  `409 conflict`. Absent or `0` = unlimited.

**Enforcement** walks the bound group's chain at admission and ANDs every limit (see
[`groups`](#groups) for per-metric semantics). Spend derives at check time from exact ledger
quantities and dated rate history. Forward card changes preserve earlier prices; attributed
backdated corrections apply only to their declared windows. A key bound to a group missing from the
running config fails CLOSED (the rejection names the unconfigured bucket); minting validates the
group exists, and boot re-checks every stored key.

**Admin API routes** (guarded by `auth.admin_auth`, served on `admin_listen`):

| Route | Method | Description |
|---|---|---|
| `/api/v1/admin/keys` | `POST` | Mint a key. Returns the signed token once (`"issue_aws_credential": true` adds the AWS pair, also shown once). |
| `/api/v1/admin/keys` | `GET` | List key metadata: `{id, name, allowed_pools, group, enabled, created_at, labels}` (never a secret). |
| `/api/v1/admin/keys/{id}` | `PATCH` | `{enabled?, group??}`: freeze/unfreeze the binding, or rebind/unbind the group (three-state: absent = unchanged, `null` = unbind, value = rebind to an existing group). `enabled: true` on a revoked key is refused `409` with `BUSBAR-4044`: revoked is permanent. |
| `/api/v1/admin/keys/{id}/usage` | `GET` | The key's all-time attribution counters (derived spend, tokens, requests) plus chain-derived `rate_headroom`. |
| `/api/v1/admin/keys/{id}` | `DELETE` | Revoke: adds the subject to the durable denylist (enforced immediately, survives restart). Returns 404 if not found. |

See [operations.md](operations.md) for worked payloads and [admin-api.md](admin-api.md) for the
full admin contract (which carries its own version, independent of the binary's SemVer).

---

### `plugins`

The dynamic plugin subsystem: signed plugin tarballs (the seven kinds, store, secret, auth, hook, export, plane and transport, share the same machinery) that Busbar verifies and loads at boot. **Off by default**: with `plugins.enabled: false` (or the whole block absent) no plugin is ever discovered or loaded, and a tarball dropped into the directory is inert. See [plugins.md](plugins.md) for the plugin author guide, the artifact format, and the full trust model.

```yaml
plugins:
  enabled: true                 # MASTER SWITCH, default false. Off = no plugin ever loads.
  dir: plugins                  # where the signed .tar.gz plugin tarballs live (default: plugins)
  trust:
    # busbar's own release key is EMBEDDED in the binary: busbar-signed plugins verify with
    # zero configuration. This block is for THIRD-PARTY publishers and explicit opt-ins.
    publishers:                 # third-party ed25519 signing keys (allowlist)
      - name: acme
        plugins: [acme-store-dynamo]
        keys:
          - { public_key: "<64-hex ed25519 public key>", revoked: false }
    allow_untrusted: false      # default false: unsigned/unknown publisher code is refused
  min_versions:                 # anti-downgrade floors, keyed by manifest name (third-party;
    acme-store-dynamo: "2.0.0"  # first-party tracks its own accepted version high-water mark)
  fetch:                        # tarballs Busbar downloads into `dir` before preflight
    - { github: "org/repo@v1.2.3", sha256: "<64-hex>" }
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `enabled` | bool | no | `false` | Master switch. `false`/absent = NO plugin loads (drop-is-inert). A non-`memory` `store.module` with plugins disabled is a boot error naming this flag. |
| `dir` | string | no | `plugins` | Directory holding the signed plugin tarballs (`*.tar.gz`), relative to the working directory. Filenames are irrelevant: identity comes from each tarball's signed manifest. |
| `trust.publishers` | list | no | empty | Entries contain `name`, a nonempty `plugins` list of exact canonical names, and nonempty `keys` records (`public_key`: hex Ed25519, `revoked`: default false). Valid active keys admit only those names automatically. Multiple keys allow rotation overlap; revoked keys refuse. Duplicate identities/keys, weak keys, empty scopes and the reserved `busbar` identity refuse. |
| `trust.allow_untrusted` | bool | no | `false` | Explicit opt-in for unsigned or unknown-publisher code, always labelled unverified. Invalid known-publisher signatures, altered bytes, scope failures, revocations, incompatible ABI and trusted floors remain hard refusals. |
| `fetch` | list | no | empty | Tarballs Busbar downloads into `dir` before the plugin preflight: at boot (a miss is fatal) and on `POST /plugins/reload` (a miss warns, BUSBAR-6001, and keeps the current artifact). Each entry is exactly one of `{ github: "org/repo@tag", sha256? }`, `{ url: "https://…/plugin.tar.gz", sha256? }` or `{ env: VAR }` (the variable holds a URL, optionally `url@sha256`); a complete-archive pin is required before dropped native bootstrap/check/migration code executes (see [Plugins](plugins.md#how-plugins-are-secured)); a URL must end in a tarball filename, and an unknown key fails the parse. `sha256` is an integrity pin and the download-skip cache key (a file in `dir` already hashing to it means no network); signature verification remains the trust gate. `--validate` does no network, so it does not fetch. |
| `min_versions` | map | no | empty | Anti-downgrade floors: manifest `name` -> minimum `version`. A floored plugin must prove (trusted signature at/above the floor) that it meets it; no opt-in flag can bypass a floor. First-party plugins are automatically floored at the highest accepted version of each plugin on this host. |

**Fail-closed guarantees:** with plugins enabled, ANY invalid tarball or manifest in `dir` (unparseable, missing/malformed fields, sha256 mismatch, unsupported `abi_version`) aborts boot naming the file and reason; any name/alias conflict between loadable plugins aborts boot naming both. `busbar --validate` checks operator inputs and local artifacts without network access, Store opening or overlay recovery. Authorized native grammar/check callbacks may execute; they require the bootstrap archive authorization described in [Plugins](plugins.md#how-plugins-are-secured). Validation does not prove plugin opening, readiness or backend reachability. `busbar --list-plugins` remains manifest-only.

### `secrets`

Module-level `open()` configuration for `kind: secret` plugins, keyed by module name or alias: `secrets.<module>.settings` is delivered to the plugin's `open()` (any secret-reference value in it, such as `token: { env: VAULT_TOKEN }` where an admitted secret module declares the `env` shorthand, is resolved through that module before it crosses the ABI). Absent, every secret plugin opens with `{}`. A secret module linked into the build takes no module-level config and must not appear here. The entry rejects unknown keys. See [plugins.md](plugins.md) for the Vault example.

### `security`

Optional. Extends the hardcoded cloud-metadata SSRF denylist. When absent, only the built-in denylist applies. Cloud metadata is refused for every outbound connection, in every egress class, and no configuration admits it. See [Security: Provider upstreams & SSRF](https://getbusbar.com/docs/security/) for the full threat model, the complete denylist, and worked examples.

```yaml
security:
  blocked_metadata_hosts:
    - "169.254.100.1"
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `blocked_metadata_hosts` | list<string> | `[]` | Additional hosts/IPs appended to the hardcoded denylist. Entries may be IP literals or DNS hostnames. Matched with the same obfuscation-aware canonicalization as the built-in list. |
| `allow_metadata_hosts` | list<string> | — | **Retired in 1.6.0 and refused** (BUSBAR-3136). the first-boot migration removes it, naming each removed entry (BUSBAR-3411). |
| `allow_all_metadata` | bool | — | **Retired in 1.6.0 and refused** when `true` (BUSBAR-3136). the first-boot migration removes it. |

A workload that needs cloud credentials uses workload-identity federation (IRSA, AKS workload identity, GKE workload identity federation) through a projected token file, never the instance metadata endpoint.

---

## Reserved names

Inside a plane section (`pools:`, `tools:`, `agents:`, `streams:`, `decisions:` and any other section
that registers named entries), a few words belong to Busbar, not to you. A registration named with one
of them is refused at startup with this message, which names the offending word:

```text
BUSBAR-3101: a pool may not be named `hooks` (reserved in `pools:`). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3101
```

Rename the registration; any other name works.

### Reserved at the top of every plane section

| Name | What it is for |
|---|---|
| `hooks` | The all-section hook attach list: hooks listed here run for every registration in the section, in addition to each registration's own `hooks:`. |
| `upstream_credentials` | The all-section default credential mode (`own` or `passthrough`) for upstream calls; a registration may override it. |
| `usage_observations` | Durable usage accounting policy keyed by configured member (accounting namespace, usage classes, reservation). Host-owned; never a registration. |

### Reserved settings Busbar owns

These words configure behavior of the section or of its pools. A registration is refused when it takes one
of these names and its body is shaped like a registration instead of the setting.

| Name | What it is for |
|---|---|
| `pools` | The named pools of a plane's section. |
| `breaker` | A pool's circuit-breaker ladder (`base_cooldown_secs`, `max_cooldown_secs`, `trip`). See [`breaker`](#breaker). |
| `on_exhausted` | What a pool does when every member is unavailable (`fallback_pool`, `queue`, or `reject`). See [`on_exhausted`](#on_exhausted). |
| `affinity` | A pool's session affinity (`mode`, `header_name`). See [`affinity`](#affinity). |
| `gates` | The ordered list of gating hooks on a pool. See [Pool `hooks`](#pool-hooks-ordering-and-gates). |
| `tier` | A pool member's tier, written in a member object (`{name, tier}`). |
| `repeatable` | The operations a pool may perform twice. |
| `work` | Bounds on asynchronous work handles: `max_live` and `retain_s`. |
| `timeout` | A registration's wall-clock bound on one attempt to reach it. |
| `rate_card` | The plane's rate card, one lane per entry. See [Per-plane rate cards](#per-plane-rate-cards-toolsrate_card-agentsrate_card-streamsrate_card-decisionsrate_card). |
| `fees` | The plane's `per_request` and `per_session` fees. |

---

## Minimal working example

The smallest config that parses and resolves. `providers`, `models` and `store` are the only required top-level sections.

**`config.yaml`:**

<!-- doc-check: config -->
```yaml
store: { module: memory }

providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }

models:
  claude:
    provider: anthropic
    max_concurrent: 10
```

**Required environment variable:** `ANTHROPIC_KEY` must be set.

**Routes available:**
- `POST /claude/v1/messages`: Anthropic ingress, directly to the `claude` model.
- `GET /healthz`, readiness check.

No `/metrics`: Prometheus is opt-in through an `export:` instance (see [`export`](#export)).

`listen` defaults to `0.0.0.0:8080`. No auth gate. No pools.

---

## Full annotated example

This example requires: `BUSBAR_ADMIN_TOKEN`, `ANTHROPIC_KEY`, `OPENAI_KEY`, `GEMINI_KEY`, a signing key at `/run/secrets/busbar-signing.key` (`busbar --generate-signing-key`), and a signed `kind: store` plugin tarball in `/etc/busbar/plugins`.

```yaml
listen: "0.0.0.0:8080"
admin_listen: "127.0.0.1:8081"      # the admin API always runs on its own listener

# ---------------------------------------------------------------------------
# Auth: data-plane callers present minted signed keys (the built-in `keys`
# verifier); the admin API is gated by the operator credential provider.
# ---------------------------------------------------------------------------
identity-providers:
  <operator-auth>: { module: <operator-auth-module>, token: { env: BUSBAR_ADMIN_TOKEN } }

auth:
  signing_key: { file: /run/secrets/busbar-signing.key }  # REQUIRED with `keys`; no auto-gen
  #                                                        # (`busbar --generate-signing-key`)
  chain:
    - keys
  admin_auth: [<operator-auth>]           # a bare PROVIDER NAME (defined above)

# ---------------------------------------------------------------------------
# Groups: the ONE limit tree. Keys bind to a group at mint; enforcement walks
# the chain and ANDs every limit.
# ---------------------------------------------------------------------------
groups:
  growth:
    limits:
      - { requests: 600, per: minute }
      - { budget: 2000000, per: month }
      - { concurrent: 64 }

# ---------------------------------------------------------------------------
# Pricing: the ONE cost source (abstract micro-units per token, per model).
# ---------------------------------------------------------------------------
rate_card:
  claude-sonnet: { input_utok: 3.0, output_utok: 15.0, cache_read_utok: 0.3, cache_write_utok: 3.75,
                   # a present card configures EVERY class the LLM plane declares, on some entry;
                   # the open classes ride `units:` (0 = free)
                   units: { search_units: 0, classifications: 0, web_fetch_requests: 0,
                            unitemized_tokens: 0, images: 0, audio_ms: 0,
                            guardrail_automated_reasoning_policies: 0,
                            guardrail_automated_reasoning_policy_units: 0,
                            guardrail_content_policy_image_units: 0, guardrail_content_policy_units: 0,
                            guardrail_contextual_grounding_policy_units: 0,
                            guardrail_sensitive_information_policy_free_units: 0,
                            guardrail_sensitive_information_policy_units: 0,
                            guardrail_topic_policy_units: 0, guardrail_word_policy_units: 0 } }
  gpt-4o:        { input_utok: 2.5, output_utok: 10.0 }
  gpt-4o-mini:   { input_utok: 0.15, output_utok: 0.6 }
  gemini-1.5-pro: { input_utok: 1.25, output_utok: 5.0 }
per_request_fee: 1

# ---------------------------------------------------------------------------
# Store: keys/usage/audit/denylist (a plugin; REQUIRED in 1.6.0, no default; `module: memory`
# is the ephemeral RAM store, and the first 1.6.0 boot of a 1.5.5 config inserts it).
# ---------------------------------------------------------------------------
store:
  module: <store-plugin>            # the alias of an admitted `kind: store` plugin
  settings: { }                     # that plugin's own settings

# A non-`memory` store is a signed plugin: the plugin subsystem must be on and
# its tarball installed in `plugins.dir`.
plugins:
  enabled: true
  dir: /etc/busbar/plugins

# ---------------------------------------------------------------------------
# Providers: secret references name where each credential lives.
# ---------------------------------------------------------------------------
providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }
    health:
      mode: dead           # re-probe only tripped lanes, every 30s
      interval_secs: 30
      timeout_secs: 5

  openai:
    api_key: { env: OPENAI_KEY }

  gemini:
    api_key: { env: GEMINI_KEY }

# ---------------------------------------------------------------------------
# Models: one lane per model. Each lane has its own semaphore and breaker.
# ---------------------------------------------------------------------------
models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 20
    max_requests: -1          # unlimited lifetime budget
    default_max_tokens: 4096  # injected on cross-protocol hops to Anthropic only

  gpt-4o:
    provider: openai
    max_concurrent: 20

  gemini-1.5-pro:
    provider: gemini
    max_concurrent: 15

  gpt-4o-mini:
    provider: openai
    max_concurrent: 30        # high capacity overflow lane

# ---------------------------------------------------------------------------
# Pools: named groups of weighted lanes with failover and breaker config.
# ---------------------------------------------------------------------------
pools:
  # Primary pool, weighted SWRR with session affinity and a tight breaker.
  smart:
    members:
      - model: claude-sonnet
        weight: 2
        context_max: 200000
      - model: gpt-4o
        weight: 2
        context_max: 128000
      - model: gemini-1.5-pro
        weight: 1
        context_max: 1000000

    affinity:
      mode: session
      header_name: x-session-id

    breaker:
      trip:
        mode: consecutive     # trip fast on a short streak
        consecutive_n: 2
      base_cooldown_secs: 5
      max_cooldown_secs: 60

    failover:
      timeout_secs: 30        # total wall-clock budget across all hops
      max_hops: 3             # at most 3 failover attempts

    on_exhausted: { fallback_pool: overflow }

  # Overflow pool, used when every smart member is tripped.
  overflow:
    members:
      - model: claude-sonnet
        weight: 3
      - model: gpt-4o-mini
        weight: 1
    on_exhausted: least_bad   # serve degraded rather than hard 503

  # Cost-optimized pool: the cheapest strategy derives each member's cost
  # from the rate_card above (members carry no cost fields).
  batch:
    hooks: [cheapest]
    members:
      - model: gpt-4o-mini
        weight: 1
        tags: ["cheap"]
      - model: claude-sonnet
        weight: 1
    failover:
      timeout_secs: 120
      max_hops: 3
    on_exhausted: reject

# ---------------------------------------------------------------------------
# Export: the single telemetry-egress surface. Metrics, traces and per-request
# logging are all NAMED instances here (there is no `observability:` or
# top-level `metrics:` block). Each instance names a `kind: export` plugin and
# gives it that plugin's own settings. Omit the block and collection is inert.
# ---------------------------------------------------------------------------
export:
  <instance-name>: { module: <export-plugin>, settings: { } }

# ---------------------------------------------------------------------------
# Response headers: every busbar-injected header is opt-in, default OFF (see
# observability.md#response-headers). This example opts into it.
# ---------------------------------------------------------------------------
advanced:
  response_headers:
    server_timing: true
```

Then mint a key for each caller (shown once; bind it to a group):

```bash
curl -s -X POST http://127.0.0.1:8081/api/v1/admin/keys \
  -H "authorization: Bearer $BUSBAR_ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"name":"team-growth","group":"growth","expires_in":"30d"}'
```

---

## Startup validation summary

Busbar validates the merged config before accepting any traffic. Fatal errors abort startup; warnings are logged and startup continues.

**Errors (fatal):**

| Rule | Condition |
|---|---|
| Provider name reserved | Any provider named `admin` or beginning with `admin/` |
| Protocol unknown | `protocol` not in `{anthropic, openai, gemini, bedrock, responses, cohere}` |
| `base_url` SSRF | `base_url` resolves to a cloud-metadata/IMDS host (e.g. `169.254.169.254`, `metadata.google.internal`) or uses an alternate IP encoding (decimal-int, hex, octal, IPv4-mapped IPv6) that decodes to a metadata address |
| `base_url` plaintext | `base_url` uses `http://` with a public (non-private, non-loopback) host: plain HTTP to a public host would expose the API key on the wire |
| `error_map` value unknown | A value in `error_map` is not one of the nine canonical disposition classes |
| `auth` value unknown | `auth` names a style no admitted `kind: auth` plugin implements (and is not a `module:` instance name) |
| `affinity.mode` value unknown | `affinity.mode` not `session` (the only supported value) |
| 1.x config detected | A 1.x structural marker is present (a `governance:` block, `auth.group_map:`, `auth.mode:`, a top-level `hooks:` **REGISTRY** block (one with `socket:`/`webhook:` entries, or any entry lacking `module:`; the 1.5.3 `hooks:` DEFINITION map is valid and passes straight through), `api_key_env`, `target:` in a pool member): an unstamped 1.x config is migrated by the first boot, and a stamped config holding one is refused by the strict parse (`unknown field`) |
| Retired key present | A retired grammar key is present (`global_hooks:`, `observability:`, a top-level `metrics:` block, `admin_insecure:`, `auth.upstream_credentials:`, `auth.methods:`, `otlp_url`/`otlp_endpoint`): the first boot of an unstamped config migrates it; a stamped config holding one is refused by the strict parse (`unknown field`) |
| Provider `api_key` unresolvable | A provider's `api_key` reference does not resolve (unset variable, missing or empty file, unknown module, secret-plugin error). `BUSBAR-8020` names the provider and the reference (`env:VAR`, `file:/path`), never the value. Declare `api_key: none` for an upstream that takes no credential |
| `api_key: none` where a credential is required | `none` on any secret other than a provider `api_key`, or on a provider using `auth: jwt-bearer` / `auth: oauth-client-credentials` (both mint their token FROM the credential) |
| `path` malformed | `path` does not begin with `/` |
| Model name reserved | Model named `admin` |
| `provider` reference missing | `models.<name>.provider` does not name a configured provider |
| Unknown top-level key | Any unrecognized top-level key in `config.yaml` (typo fail-closed; every nested block already rejects unknown keys) |
| Plugin store without plugins | `store.module` names a plugin (anything but `memory`) while `plugins.enabled` is `false`/absent; the error names the flag |
| Invalid plugin artifact | With plugins enabled: any tarball in `plugins.dir` that fails structural validation (unreadable/hostile archive, malformed or incomplete manifest, `sha256` mismatch, unsupported `abi_version`); the error names the file and reason |
| Plugin conflict | Two loadable plugins share a `name` or `alias`, or an alias collides with another plugin's name; the error names both |
| Plugin store unresolved | `store.module` does not resolve to a loadable `kind: store` plugin (missing, skipped by trust with the reason attached, or the wrong kind) |
| `max_concurrent: 0` | A concurrency semaphore of 0 never grants a permit (omit the field for unbounded; `0` is the only rejected value) |
| `max_requests: 0` | Zero lifetime budget = permanently unusable lane |
| `default_max_tokens: 0` | Would be injected upstream and rejected |
| Pool name reserved | Pool named `admin` |
| Pool name collision | Pool name matches a provider or model name |
| Empty `members` | A pool with no members is un-routable |
| `weight: 0` | Pool member weight of 0 is invalid |
| `model` reference missing | A pool member's `model` does not name a configured model |
| `failover.timeout_secs: 0` | Zero failover deadline |
| `failover.timeout_secs` too large | Greater than the maximum of `86400` s (24 h); a per-request failover budget over a day is a fat-finger typo |
| `failover.exclusions` dangling | An exclusion names a model not in the pool |
| Fallback pool cycle | `on_exhausted: fallback_pool:<X>` where following the chain creates a cycle |
| Fallback pool self-reference | `on_exhausted: fallback_pool:<self>` |
| Fallback pool unknown | `on_exhausted: fallback_pool:<name>` where `name` is not a configured pool |
| `on_exhausted` malformed | Not `reject`, `least_bad`, `{ fallback_pool: <pool> }`, or `{ queue: { max_ms: <ms> } }` (or a mapping naming both `fallback_pool` and `queue`) |
| `on_exhausted.queue.max_ms: 0` | A `0` wait never queues (it is just `reject` with extra machinery) |
| `on_exhausted.queue.max_ms` too large | Greater than the resolved failover budget (`failover.timeout_secs × 1000` ms); a queue longer than the whole budget never reaches its ceiling |
| `affinity.mode` unknown | Any value other than `session` |
| Pool `hooks:` names more than one ordering strategy | A pool has one base ordering |
| Pool `hooks:` name undefined | A bare name in `pools.hooks:` or a pool's `hooks:` that is neither a built-in strategy (`weighted`/`cheapest`/`fastest`/`least_busy`/`usage`) nor a key of the top-level `hooks:` map |
| Unknown hook module | A `hooks.<name>.module` does not resolve to a loaded `kind: hook` plugin (by manifest name/alias) |
| Hook plugin subsystem disabled | A `hooks.<name>.module` names a plugin while `plugins.enabled` is false, or the tarball is not installed in `plugins.dir` |
| Hook outbound destination refused | A hook plugin's outbound call to a destination the [destination guard](#advanced) refuses (a metadata host always; request-derived private addresses) |
| `prompt: rw` on a `kind: tap` hook | A tap observes; it can never rewrite |
| Groups tree faults | A `parent` that does not exist (paste-ready stub) or a cycle (the path is printed); any acyclic depth is accepted |
| Malformed group limit | A limit without exactly one metric key, a windowed metric without `per:`, or `concurrent` with a `per:` |
| Breaker `max_cooldown < base_cooldown` | Cooldown ceiling below the base |
| Rate card incomplete | rate_card (or a plane's rate_card) present but missing an entry for a configured model or lane (a paste-ready zeroed stub of the missing entries is printed) |
| Rate card names an unknown model or class | A `rate_card` key that is not a configured model, or a `units:` key the plane does not declare |
| `auth.chain` names an unknown module | Every chain entry must be the built-in `keys` or a loaded `kind: auth` plugin |
| `role_bindings` faults | A binding under a module not in any chain, or a bound `group` that does not exist in `groups:` |
| Admin token blank | The `admin-tokens` `token` secret reference resolves to a blank/whitespace-only value |
| Exposed admin without mTLS | A non-loopback `admin_listen` without `admin_tls.client_ca`, unless `admin_require_mtls: false` is set deliberately |
| `${VAR}` unset in config | Unresolvable interpolation reference |
| `${}` or unclosed `${` | Malformed interpolation syntax |

**Warnings (non-fatal):**

| Condition |
|---|
| `chain: []` (open front door): no client authentication, development only |
| `pools.upstream_credentials: passthrough` (or a pool override) with a provider whose credential reference resolves non-empty (credential-leak risk) |
| Heterogeneous pool (members span more than one backend protocol, cross-protocol translation applies) |
| `allowed_pools` on a virtual key (admin API) names a pool not currently configured |
| The ephemeral `memory` store with minted keys: keys, usage, and the revocation denylist reset on restart (choose a durable `store.module` for persistence) |

---

### Login attempt limits

Hosted credential sign-in (`POST /auth/token` from the login form: any `Credential` login plugin) is
limited before the plugin is called, so busbar never forwards more guesses to the directory than it
allows. The limits are fixed engine constants and are not configurable:

<!-- docs-truth: depends on !2696 (unmerged): deletes `auth.login_limits.*` and `browser_login.failure_window`; the owner ruling fixes `browser_login.max_failures` at 3 (no MR yet). Until it merges, dev still accepts the `auth.login_limits` block. -->

| Limiter | Fixed value |
|---|---|
| Per account, across every credential method | 3 failures per 15 minutes |
| Per source | 20 failures per 15 minutes, and 30 submissions per minute |
| Global | 600 failures per minute (an alarm that tightens per-source limits, never a refusal) |
| Admin API, refused admin credentials per source | 50 failures per 5 minutes |

- **Per account.** The account is the plugin's first declared text field, normalised (Unicode
  NFKC_Casefold, whitespace collapsed, one `DOMAIN\` prefix and one `@suffix` stripped), keyed by an
  HMAC derived from `auth.signing_key` and counted in the core store, so the budget is fleet-wide.
  Without a signing key, or while the store is unreachable, credential sign-in answers 503 without
  calling the plugin (BUSBAR-4039, BUSBAR-4035). Two names the normaliser cannot fold (a
  sAMAccountName and a UPN with a different prefix) are two budgets; `CORP\alice` and `EMEA\alice`
  share one (only stricter).
- **Per source.** An IPv4 address, or an IPv6 /64 with /48 (100) and /32 (500) aggregates. See
  `advanced.trusted_proxies`. Unknown sources skip this limiter only.
- **Answer.** 429 "Too many sign-in attempts" with `Retry-After` = the method's window in whole
  minutes (60..=900), identical whichever limiter tripped and whether the account exists. A wrong
  password stays 401. A method whose provider answered five outages in a minute is held 30 s (503).
- **Plugins** may add the reply extension `reject_hint: account_locked` (or `throttled`) to a
  declined credential; busbar then stops forwarding for that account for its window.
- Rotating `auth.signing_key` resets every account's count (a rolling rotation briefly doubles it).

### `advanced`

Internal tuning knobs, normally omitted; each field defaults to its historical value.

```yaml
advanced:
  rate_sweep_interval: 256          # budget-table sweep: every Nth admission drops entries no longer needed
  usage_flush_interval_ms: 100      # write-behind flush cadence for in-memory usage/budget counters
  worker_threads: 4                 # data-plane worker count — one pinned runtime + listener each; omit ⇒ one per core
  upstream_http1_only: false        # pin the upstream client to HTTP/1.1
  upstream_h2_prior_knowledge: false # force h2c prior-knowledge to cleartext upstreams
  response_headers:                 # every busbar-injected response header, opt-in, default OFF
    server_timing: false            # `Server-Timing: busbar;dur=<ms>` (formerly observability.emit_server_timing)
  trusted_proxies: []               # ingresses/load balancers whose forwarded client address is believed (IPs, CIDRs)
  forwarded_header: x-forwarded-for # header read from a trusted proxy: x-forwarded-for or forwarded
  block_private_addresses: true     # refuse outbound dials to private/loopback addresses (destination guard)
  proxy_resolution: local           # local (engine resolves and judges) or proxy (proxy resolves)
```

Every key is tabled and explained in the [advanced settings reference](#advanced-settings-reference) below.

`trusted_proxies` decides **who sent a request** for the login attempt limiter and the admin door.
`X-Forwarded-For` is read only when the socket peer is inside `trusted_proxies`, right to left past
trusted hops; an unreadable hop makes the client unknown, never the proxy. A private or loopback
peer that sends `X-Forwarded-For` while `trusted_proxies` is empty is unknown too, and warns
BUSBAR-4036: **set `trusted_proxies` when an ingress fronts busbar**, or every user shares the
ingress's budget. IPv4-mapped IPv6 peers are their IPv4 address. It is a **boot-time** knob.
<!-- docs-truth: depends on !2676 (unmerged), which deletes `advanced.forwarded_header` (fixed `x-forwarded-for`) -->

The shutdown drain budget (20 s, starting when listener draining begins) and the cap on finished governed requests
awaiting settlement (20,000) are fixed engine constants, not configuration. A quarter of the drain
is a reserve: requests are cut at three quarters, then spend is settled, the audit tail sealed, the
journal flushed and the writer retired inside the reserve. A second signal ends the drain at once.
The exit is `0` when the writer retired, `75` when every completed request's spend is durable but
running requests were cut (each listed on stderr as `open_at_exit`), and `70` when some completed
spend is not durable (listed on stderr as evidence). At the pending cap, a new governed request is
refused with `503 durability_unavailable` and `Retry-After: 1` until the backlog falls
(`busbar_unit_checkpoints_terminal`); running requests never count.

`advanced.shutdown.deregister_delay` is the readiness propagation allowance before that drain:

```yaml
advanced:
  shutdown:
    deregister_delay: 5s
```

It defaults to `5s` and accepts duration strings from `0s` through `300s` inclusive (`5m` is also
300 seconds). Invalid values are refused, never clamped. `0s` begins listener draining immediately.
The value is captured at boot. Edit it through the configuration document; a stored change is
reported under `/advanced/shutdown/deregister_delay` as pending restart and leaves the running
process's allowance unchanged. `PUT /config/settings` does not expose this field.

An operator signal or released admin restart first marks `/readyz` unready while listeners and
credential refresh continue through the allowance, then begins the full fixed 20-second drain.
Persistence safety shutdown bypasses the allowance; a second signal also expires the drain.
Repeated operator requests cannot extend either interval. Reserve at least
`deregister_delay + 20s + 6s + operator margin` in the process supervisor: with the default, at
least 31 seconds before margin. The six seconds covers the existing bounded exit handover.

`worker_threads`, `upstream_http1_only`, and `upstream_h2_prior_knowledge` are **boot-time** knobs (read
once at process/client construction), so unlike `rate_sweep_interval` and `usage_flush_interval_ms`
they are not live-mutable via `PUT /config/settings`. A change takes effect on the next restart.
(The usage writer reads `usage_flush_interval_ms` before each wait, so an applied change is used
from the next wait on.) The
`BUSBAR_*` env vars that used to back these knobs are retired in 1.6.0 and never read at serve time;
see the [development migration limitation](#environment-variables) before upgrading a launcher
that sets them. `TOKIO_WORKER_THREADS` remains a fallback for `worker_threads`.

`response_headers` is likewise **restart-to-apply**: `server_timing` is baked into router middleware
composition at boot, so a live `PUT` stores the new value
durably (`reload_to_apply` flags `advanced.response_headers`) but only takes effect on the next
restart. Full catalogue, rationale for defaulting off, and exactly when each header fires:
[observability.md#response-headers](observability.md#response-headers).

**The destination guard.** One check applies to every outbound connection busbar makes (provider
upstreams, token endpoints, health probes, export sinks, plugin fetches, plane and plugin dials). It
applies the default private-address refusal to a destination that comes from request data or the network (a
target a caller or a plane names) is refused when it is, or resolves to, a private (RFC 1918),
loopback, link-local, CGNAT, IPv6 unique-local (`fc00::/7`) or IPv6 site-local (`fec0::/10`)
address. A core-selected provider route may reach its own configured base/token origins.
Declared operator-infrastructure Needs, such as a database, secret service or directory, retain
their declared-target policy. Neither grants arbitrary requests permission to the same hostname.
A cloud-metadata address is refused for every destination, configured ones included (a configured
name that later resolves to one is refused). The check runs after name resolution, and the
connection is made to the address that was checked; an IP address written in a URL is checked as
that address. Through an HTTP(S)/ALL_PROXY CONNECT proxy, the target is still checked by address:
busbar resolves the target, judges every address it answers, and the CONNECT names the judged
address, so the proxy dials exactly what was checked (a name that does not resolve locally is
refused). BUSBAR-3149 states the posture at boot (proxy endpoints without credentials, `NO_PROXY`,
the mode) and writes a `config.egress_proxy` audit record. Cloud metadata (the built-in metadata
names and addresses, IPv4 and IPv6 link-local, and `security.blocked_metadata_hosts`) is refused in
every egress class and nothing admits it. Of the 1.5.5 keys, `security.blocked_metadata_hosts`
still loads and extends the same check; `security.allow_metadata_hosts`,
`security.allow_all_metadata` and `providers.<p>.allow_metadata_hosts` are retired and refused
(BUSBAR-3136).

**One guard governs every outbound connection, plugins included.** No plugin and no transport
dials on its own: a plugin declares what it needs (a transport and an egress class), and busbar's
connector resolves the name, applies this check to every answered address, and lets the transport
open only the address it checked. So the guard governs an export sink, a hook's outbound call, an
identity provider fetch, a plane's upstream (an MCP server, an A2A agent) and every other plugin
dial alike. There is no global hostname allowlist: a plane registration that must reach a
private target carries its own core-owned `allow_private` on its declared registration. The
connector restricts this grant to that selected route's origin. Configured providers retain
private reach only on their own base/token origins; other requests, strict JUDGE/OPEN_WEB checks,
redirects to other origins and callbacks cannot borrow it. `advanced.allow_destinations` is
removed: a configuration that still carries it loads, the key is ignored (it grants nothing and is
never written back) and one warning line says so. The scheme a
destination may use is part of the same check: an export sink or hook on the `loopback-allowed`
class takes `https://`, or plaintext `http://` only to loopback; an `open-web` destination (a
webhook sink, an identity provider's documents) takes `https://` only.

### Advanced settings reference

Every key an operator can write under `advanced:`, in one place. The whole block is optional;
leaving a key out gives the default shown. `advanced` refuses keys it does not know (a typo is a
boot error, never ignored), except the removed `allow_destinations`, which is ignored with one
warning so that an old configuration still loads. "Applies" says when a change takes effect: **on apply** means a
configuration apply (the next published configuration generation) is enough; **restart** means the
running process keeps the old value until it is restarted (a stored change is saved, but does not
act yet).

| Key | Type and unit | Default | Allowed range | What it does | Applies |
|---|---|---|---|---|---|
| `advanced.wait_for_commit` | boolean | `false` | `true` / `false` | Whether a metered response's last byte waits until its audit line is committed. Administrative changes always wait. | on apply (next generation) |
| `advanced.usage_flush_interval_ms` | integer, milliseconds | `100` | 1 to 946,080,000,000 (30 years); `0` is raised to 1 with one warning | How often in-memory usage and budget counters are written out. | on apply |
| `advanced.rate_sweep_interval` | integer, count of admissions | `256` | 1 to 4,294,967,295; `0` is refused | How often a budget table drops entries that are no longer needed. | on apply |
| `advanced.worker_threads` | integer, threads | one per CPU core | 1 to 65,535; `0` means the default, and above 65,535 is lowered to 65,535, each with one warning (`BUSBAR-9008`) | Number of data-plane worker threads. | restart |
| `advanced.upstream_http1_only` | boolean | `false` | `true` / `false` | Pin the upstream HTTP client to HTTP/1.1. | restart |
| `advanced.upstream_h2_prior_knowledge` | boolean | `false` | `true` / `false` | Speak HTTP/2 without negotiation to cleartext upstreams. | restart |
| `advanced.response_headers.server_timing` | boolean | `false` | `true` / `false` | Add `Server-Timing: busbar;dur=<ms>` to responses. | restart |
| `advanced.shutdown.deregister_delay` | duration string | `5s` | `0s` to `300s` inclusive | Time the engine reports itself not ready before it starts draining. | restart |
| `advanced.block_private_addresses` | boolean | `true` | `true` / `false` | Refuse outbound connections to private, loopback and similar addresses. | restart |
| `advanced.trusted_proxies` | list of IP addresses or CIDR ranges | empty list | each entry an IP or CIDR with no stray host bits | Load balancers whose forwarded client address is believed. | restart |
| `advanced.forwarded_header` | text | `x-forwarded-for` | `x-forwarded-for` or `forwarded` | Which forwarding header to read from a trusted proxy. | restart |
| `advanced.proxy_resolution` | text | `local` | `local` or `proxy` | Who resolves a destination's name when an outbound proxy is used. | restart |
| `advanced.tls.roots` | text | `bundled` | `bundled`, `system` or `none` | Base set of certificate authorities for outbound TLS. | restart |
| `advanced.tls.trust_anchors` | list of certificate sources | empty list | `{ file: }`, `{ env: }` or inline PEM | Extra certificate authorities trusted for every destination. | restart |
| `advanced.tls.destinations` | list of entries | empty list | see [`advanced.tls`](#advancedtls) | Per-destination authorities, key pins and client certificate. | restart |

"Restart" for the keys above is what the code does today: `advanced.rate_sweep_interval` is read
again on every admission, `advanced.usage_flush_interval_ms` before each wait of the background
writer, and the configuration apply republishes both; every other key is read once at boot. Every
one of those restart keys is reported by the pending-restart list in the admin API
(`reload_to_apply`) when an edit changes it: `worker_threads`, `response_headers`,
`shutdown.deregister_delay`, `upstream_http1_only`, `upstream_h2_prior_knowledge`,
`trusted_proxies`, `forwarded_header`, `block_private_addresses`, `proxy_resolution` and `tls`.
`trusted_proxies` and `block_private_addresses` are security settings: an edit to them is stored
but does not act until the engine restarts, and the list now says so.

#### `advanced.wait_for_commit`

Decides whether a metered response's last byte is released before or after a record of that
response is committed.

- `false` (the default): the response is released as soon as the transport has it. Nothing on the
  request signs, hashes, takes a lock another core holds, or waits for the store. The request's
  audit line goes to its own core's outbox, and one background flusher writes every core's lines
  in a single group commit every `advanced.usage_flush_interval_ms`. A refused request that names
  nobody (bad credential, no route) writes no line of its own. Each core counts such refusals by
  (listener, step, reason, status), and each flush writes one line per count that is not zero:
  "N requests refused for reason R on listener L between T1 and T2".
- `true`: a metered response puts one line in its core's outbox, asks the flusher to flush at
  once, and releases its last byte only after the group commit that holds that line. If the
  response's deadline passes first, the response is not released.

Administrative changes (configuration edits, key changes, every operator action through the admin
API) are acknowledged only after their record is committed, whatever this is set to.

The value belongs to the configuration generation a request was admitted under. A changed value
applies on a configuration apply, with no restart, and only requests admitted under the new
generation see it. A request never sees it change while it runs.

When to change it: set `true` when you must be able to prove that every answer a client received
has a committed record, for example under an audit obligation. Leave it `false` for the lowest
latency.

Cost: with `true`, every request is slower by the time the commit takes, and that time is added to
every answer. With `false` there is no added wait.

**What can be lost with `false`:** if the engine crashes (kill, power loss), audit lines still in a
core's outbox can be lost even though their clients already received answers. That covers lines
handed over since the last group commit, at most one flush interval (100 ms by default; for audit
lines the flusher clamps the interval to 1 to 1,000 ms), and the refusal counts of that interval.
This setting does not decide how money is recorded. Spend and request counts follow
`advanced.usage_flush_interval_ms` below in both modes. A request's charge is keyed by its unit
identity, so a recovery replay never counts it twice. A normal shutdown flushes everything first.

**When the flusher cannot commit** (store down, disk full) for longer than 2 seconds, new
billable requests are refused with the "durability unavailable" refusal, and `BUSBAR-2060` is
logged once. Service resumes by itself after the next good commit. See
[operations.md](operations.md#audit-flusher-stall).

```yaml
advanced:
  wait_for_commit: true
```

#### `advanced.usage_flush_interval_ms`

How often the engine writes its in-memory usage and budget counters to the store, in milliseconds.
Between writes the counters live only in memory. The writer reads this before each wait
(`crates/busbar-kernel/src/governance/mod.rs`, `run_budget_flusher`), so a value changed through
`PUT /config/settings` or the configuration document is used from the next wait on: the wait
already in progress when the change is applied is the last one on the old value. It applies on a
configuration apply, with no restart.

When to change it: lower it to shrink the window of lost spend after a crash; raise it to write
to a slow store less often. Cost: a lower value means more writes to the store; a higher value
widens the loss window.

**What can be lost:** on a crash (kill -9, power loss) up to this many milliseconds of accrued
spend and request counts. A graceful shutdown flushes fully. The code refuses values above
946,080,000,000 ms (30 years). The shortest interval is 1 ms: the writer waits on the runtime's
timer, which has a resolution of one millisecond, and a wait of `0` would make the writer loop with
no pause. A configured `0` is therefore converted to 1, with one warning line (`BUSBAR-3117`) at boot
and on every configuration apply; nothing is refused. The store has no commit period of its own that
would set a higher floor.

```yaml
advanced:
  usage_flush_interval_ms: 50
```

#### `advanced.rate_sweep_interval`

Budget counters are kept in memory in tables. Every Nth admission that touches a table also
removes entries that are no longer needed (idle for more than 31 days with nothing owed).
`rate_sweep_interval` is N. It is a count of admissions, not a time.

When to change it: rarely. Raise it if the sweep shows up in latency measurements on a table with
very many keys; lower it to reclaim memory sooner. Cost: a low value spends a pass over the table
more often; a high value lets unused entries stay in memory longer. A table that receives no
admissions is not swept at all. `0` is refused at boot (`BUSBAR-3117`, configuration setting out of range).
Applies on a configuration apply.

```yaml
advanced:
  rate_sweep_interval: 1024
```

#### `advanced.worker_threads`

The number of data-plane worker threads; each runs its own runtime and listener. Left out, the
engine uses one per available CPU core. `TOKIO_WORKER_THREADS` is read as a fallback when the key
is absent. The engine never starts more than 65,535, which is the most the Tokio scheduler can
run (it keeps its count of searching workers in 16 bits); a larger value is lowered to 65,535.

When to change it: on a container with a CPU limit far below the host's core count, set it to the
limit; on a shared host, to the cores you want to give the engine. Cost: too few threads cap
throughput; too many on a limited CPU quota add scheduling overhead.

`0` is not a valid count. One rule applies wherever the value is read (the boot read of
`config.yaml`, the runtime built after recovery, and the admin document edit): `0` is converted to
the default, a count above 65,535 to 65,535, and each conversion writes one warning line
(`BUSBAR-9008`). Nothing is refused: an edit carrying `0` or a larger count is accepted and stored as
written.

```yaml
advanced:
  worker_threads: 4
```

#### `advanced.upstream_http1_only`

Pins the client that talks to providers and other upstreams to HTTP/1.1. By default the client
negotiates HTTP/2 where the far end offers it. When to change it: an upstream or middlebox that
handles HTTP/2 badly. Cost: no HTTP/2 multiplexing, so more connections for the same traffic. The
value is passed to the HTTP transport, which declares this key in its settings and reads it (a
transport reaches it only if its settings name this path). If `upstream_h2_prior_knowledge` is
also `true`, this setting wins.

```yaml
advanced:
  upstream_http1_only: true
```

#### `advanced.upstream_h2_prior_knowledge`

Speaks HTTP/2 directly (no HTTP/1.1 upgrade or negotiation) to cleartext (`http://`) upstreams.
When to change it: an h2c-only upstream. Cost: a far end that does not speak HTTP/2 fails; the
source records that this measurably lowered throughput in performance testing, which is why it is
off. Setting it together with `upstream_http1_only` is not refused, and the rule is fixed:
`upstream_http1_only` wins. Over TLS the HTTP transport then offers `http/1.1` alone, and to a
cleartext upstream it speaks HTTP/1.1, not h2c. The engine passes both values to the transport
unchanged; the rule lives in the transport (`door::offer_for`) and is tested there.

```yaml
advanced:
  upstream_h2_prior_knowledge: true
```

#### `advanced.response_headers.server_timing`

Adds `Server-Timing: busbar;dur=<ms>` to every response: the engine's own added latency in
milliseconds (request time minus the upstream round trip). When to change it: to measure the
engine's overhead. Cost: it tells any client, authenticated or not, that the response came through
Busbar, so it is off by default. Details in [observability.md](observability.md#response-headers).

```yaml
advanced:
  response_headers:
    server_timing: true
```

#### `advanced.shutdown.deregister_delay`

When the engine is told to stop, it first reports itself not ready (`/readyz`) for this long, so a
load balancer can stop sending traffic, and only then starts draining. Accepts duration strings
such as `5s` or `2m`, from `0s` to `300s`; anything else (a number without a unit, `301s`) is
refused at boot, never clamped. `0s` starts draining at once. Safety shutdowns skip the delay.

When to change it: set it to at least your load balancer's health-check interval times its
failure threshold. Cost: every planned stop takes this long longer; leave room for it in the
supervisor's stop timeout (see above).

```yaml
advanced:
  shutdown:
    deregister_delay: 10s
```

#### `advanced.block_private_addresses`

When `true` (the default) the destination guard refuses outbound connections to a destination that
is, or resolves to, a private, loopback, link-local or similar address (see above), for the
connection classes the guard lists. Cloud-metadata addresses stay refused whatever this says.
When to change it: a deployment whose providers and tools all live on private addresses and that
accepts the exposure. **Risk:** with `false`, a request that can name a destination can make the
engine connect to services inside your network. Prefer a per-registration `allow_private` where
your plane supports it.

```yaml
advanced:
  block_private_addresses: true
```

#### `advanced.trusted_proxies` and `advanced.forwarded_header`

`trusted_proxies` lists the load balancers or ingresses (an IP address or a CIDR each) whose
forwarded client address is believed; the login attempt limiter and the admin door use the result.
`forwarded_header` chooses the one header read from them, `x-forwarded-for` (default) or
`forwarded`. Without `trusted_proxies`, the socket peer is the client, and a private peer that
sends a forwarding header is treated as unknown and warned about. When to change them: whenever an
ingress sits in front of the engine. Cost of a wrong list: listing an address you do not control
lets its sender claim any client address and so avoid the per-source limit; leaving the ingress
out makes all users share one budget. A bad entry, or a header other than the two, is refused at
boot. Detail: [`advanced`](#advanced) above.

```yaml
advanced:
  trusted_proxies: [10.0.0.0/8, 192.0.2.10]
  forwarded_header: x-forwarded-for
```

#### `advanced.proxy_resolution`

When outbound connections go through `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`: `local` (default)
has the engine resolve the name, judge every address, and tell the proxy the judged address;
`proxy` sends the name and, when the name does not resolve on the engine host, leaves the address
check to the proxy. When to change it: split-horizon DNS where names resolve only at the proxy.
**Risk with `proxy`:** the destination guard cannot judge an address it never sees.

```yaml
advanced:
  proxy_resolution: local
```

#### `advanced.tls.roots`, `advanced.tls.trust_anchors`, `advanced.tls.destinations`

The outbound TLS trust store. `roots` picks the base authorities (`bundled`: the Mozilla set
Busbar ships; `system`: the operating system's bundle; `none`: only the ones you list).
`trust_anchors` adds authorities for every destination; `destinations` adds authorities, key pins
(`pin_spki_sha256`) and a client certificate for matching hosts. There is no way to turn
verification off. When to change it: a private certificate authority or a pinned partner. Cost:
`none` refuses every TLS dial no anchor covers. Full rules, validation and rotation in
[`advanced.tls`](#advancedtls) below.

```yaml
advanced:
  tls:
    roots: system
    trust_anchors:
      - { file: /etc/busbar/ca/corp-root.pem }
```

### `advanced.tls`

The **outbound TLS trust store**: one place that decides which certificate authorities, key pins
and client identity every outbound TLS connection busbar makes uses (providers, token endpoints,
export sinks, plugin needs, plane members, stores that upgrade to TLS). Plugins no longer carry
their own CA settings. There is no setting that disables certificate or host-name verification,
and none is reserved for one.

```yaml
advanced:
  tls:
    roots: bundled                  # bundled (default, 1.5.5's Mozilla set) | system | none
    trust_anchors:                  # CAs trusted for every destination, on top of roots
      - { file: /etc/busbar/ca/corp-root.pem }
    destinations:
      - match: ldap.corp.internal   # exact host, *.domain, IP or CIDR
        trust_anchors: [ { env: LDAP_CA_PEM } ]
        include_roots: false        # default: these anchors REPLACE roots + trust_anchors for this host
      - match: ccp.corp.example.com
        pin_spki_sha256: sha256/4Bm1...=        # held on top of verification, never instead of it
        client_identity: { cert: { file: /etc/busbar/ccp.crt }, key: { file: /etc/busbar/ccp.key } }
```

* **`roots`**: `bundled` is the Mozilla root set busbar ships (1.5.5 parity). `system` reads the
  operating system's CA bundle once at boot (`SSL_CERT_FILE` / `SSL_CERT_DIR` when set, else the
  distribution's bundle file); expired, non-CA and unreadable entries are dropped with one
  BUSBAR-3147 warning carrying the count, and an empty bundle refuses the boot (BUSBAR-3140).
  `none` trusts only what `trust_anchors` and matching `destinations` list; a TLS dial no anchor
  applies to is refused (BUSBAR-3140), a pinned one included (never a panic).
* **Selection** is by the host the destination guard judged for the dial: never by a name a
  plugin offers for SNI, never by a proxy hop. Name entries match name dials; IP and CIDR entries
  match only IP-literal dials. A dial matching several entries trusts the union of their anchors.
  A matching entry that lists anchors **replaces** `roots` and `trust_anchors` for that dial unless
  `include_roots: true`. An entry that lists only a pin or a client identity keeps the base set.
* **Sources** are `{ file: <path> }`, `{ env: <NAME> }` or inline PEM. This is core's own TLS
  source grammar, not secret shorthand: it needs no secret module. A secret-store reference is
  refused: the store is built before any secret plugin is reachable, and a CA is public. Client
  identity keys are read by core and never handed to a plugin.
* **Validation at boot** (every operator anchor): the PEM parses and holds only certificates; each
  is an X.509 v3 CA (`basicConstraints CA:TRUE`, and `keyCertSign` when `keyUsage` is present);
  `notBefore` (five minutes' tolerance) `<= now < notAfter`; rustls accepts it. A failure refuses
  the boot with BUSBAR-3137 naming the key, the index, the source and the destination it scopes.
  A self-signed server certificate (`CA:FALSE`) is not an anchor: list the CA that issued it.
  Malformed entries are BUSBAR-3148; a wildcard over a single label (`*.internal`) is BUSBAR-3145.
* **Fingerprints and audit**: every accepted anchor logs one BUSBAR-3138 line (SHA-256 of the DER,
  subject, issuer, notAfter, scope) and writes one `config.tls_trust_anchor` audit record; the base
  set logs its count and a SHA-256 over the sorted set.
* **Runtime**: the store is boot-time (restart to apply). An hourly sweep withdraws an anchor past
  its notAfter from new connections (BUSBAR-5048, audited; a dial whose matching entry has no anchor
  left is refused), repeats the 30-day expiry warning daily (BUSBAR-3139), and warns once per change
  when an anchor file's contents differ from what was loaded (BUSBAR-5049, audited).
* **Revocation**: no CRL or OCSP checking in 1.6.x.

**Rotation runbook.** List the new CA beside the old one (two `trust_anchors` items, or two
anchors on the entry), validate (`busbar --validate`), restart, confirm the new BUSBAR-3138
fingerprint, move the servers to certificates from the new CA, then remove the old anchor and
restart again.

**The plaintext rule** (every transport, carriers that upgrade later included: postgres,
valkey/redis, mysql, ldap, vault over `http://`): a connection without TLS is admitted only to an
instance whose own block carries `insecure_transport: { accept: plaintext, reason: "..." }` (BUSBAR-3141). No loopback address or name is exempt (SEC-2): a local server without TLS needs the same acceptance. There is no `plaintext` entry under `advanced.tls.destinations`. A
carrier that negotiates TLS in-protocol (a postgres SSLRequest, LDAP StartTLS, a MySQL SSLRequest)
may make one cleartext write of at most 64 bytes before its upgrade; anything else in clear to a
non-admitted host is refused. Credentials are never sent in clear to a host that is not loopback,
whatever an entry says (BUSBAR-3146). Postgres `sslmode=prefer`, `sslmode=allow` and a missing
sslmode are refused (BUSBAR-3142, owner sign-off 2026-11-13: encryption required); valkey
`#insecure` is refused (BUSBAR-3143). The upgrade rewrites none of this: it refuses with the line to add (see
[transport security](migration-1.6.md#transport-security)).
<!-- docs-truth: depends on !2676 (unmerged), which deletes `advanced.tls.destinations[].plaintext` -->

Every refused dial writes one rate-limited BUSBAR-5046 line and one `egress.dial_refused` audit
record; every TLS verification failure writes one BUSBAR-5047 line and one
`egress.tls_verification_failed` record naming the host, the matching entries and the anchor
fingerprints in force (never certificate bodies).

### `providers_file`

Top-level pointer to the provider catalog. Relative paths resolve against the config.yaml directory;
absent ⇒ `providers.yaml` next to config.yaml; if that default file does not exist the catalog is empty (logged at info, naming the path), which suits an admin-only deployment that configures no provider. Boot never creates that file; a first 1.6.0 boot's configuration upgrade records the absence, and a providers.yaml that appears while that upgrade is still in progress is refused as a changed document. A file named by `providers_file:` or `--providers` must exist, or boot is refused. The `--providers <path>` CLI flag (1.6.0) overrides this
key. The two-file model is unchanged. This just names the catalog that config.yaml's `providers:` map
references.

```yaml
providers_file: providers.yaml
```

---

## Migrating a 1.4.x config

The config format is an operator artifact outside the SemVer freeze; it changed shape in 1.5.0
WITH tooling:

1. Upgrade to 1.5.5 first, then start 1.6.0 on the result: the first boot mechanically converts every
   deterministic change and reports where a human must decide. The loudest warning: every `allowed_pools: []` occurrence, whose meaning FLIPPED
   (it used to mean all pools, it now means NO pools).
2. Review the TODO/WARNING items, then `busbar --validate` the result.
3. Re-mint every virtual key (`POST /api/v1/admin/keys`): 1.4.x bearer secrets and static
   `client_tokens` no longer authenticate. Keys are signed tokens that expire (default 90
   days).

Booting a 1.x config directly REFUSES with a named error that says to go through 1.5.5 first; nothing from
1.x can boot-and-silently-flip semantics.
## Fixed engine resource budgets

These limits are engine constants, not configuration keys. All framed listeners
share a **256 MiB** budget for admitted request-body payload. Each incoming body
piece is charged before it is queued; the charge remains until the request ends,
including while its body is assembled and dispatched. Exhaustion refuses the
stream with **503**; the configured per-request body limit still uses **413**.
The budget measures payload bytes, not total process memory or allocator overhead.

Datagram claim doors share a process-wide maximum of **1,024 associations** and
allow at most **64 associations per claim door**. Capacity is reserved before an
association is installed and released on failed installation or close. An
association expires after **300 seconds**, even when its transport supplies no
deadline. Exhaustion refuses association admission. Expiry closes the association;
clients must establish a new one.

Root data and admin stream listeners retain the connector's **1,024 concurrent
connection** limit. Framed request-body collection uses the same read bounds as
the admin HTTP listener: at least **1 KiB/s** averaged over the read after a
**10-second** grace period, plus a total read deadline derived from the current
translation-body byte cap divided by 1 KiB/s. The inter-piece timeout still
applies. Periodic small pieces cannot reset the total deadline or bypass the
throughput floor; a violation refuses the request as deadline exceeded.

The Hyper HTTP listener requires the first complete request headers within
**30 seconds** of plaintext IO becoming available, after any TLS handshake.
Silent sockets, partial protocol prefaces, HTTP/2 control frames and incomplete
headers do not extend that deadline. The first HTTP/1 request shares this one
window with protocol detection; subsequent HTTP/1 header-read behavior is unchanged.

After its first request, an HTTP/2 connection closes after **30 seconds with no
active requests**. A request remains active while its handler runs or either its
request or response body remains unfinished. Complete request admission before
expiry starts fresh activity; control frames do not. Healthy long streaming
responses remain supported. Hyper also sends keepalive PINGs after **30 seconds**
of receive inactivity with a **10-second** acknowledgement timeout.

First-header and HTTP/2 idle expiry close the transport immediately, without a
drain task. Ordinary connection close allows shutdown and read-drain to share a
**30-second total** budget, with a **5-second** read-idle bound inside it. The
connection admission slot remains held until the actual transport is released,
including normal draining. These fixed policies add no configuration keys and do
not govern plugin-framed upgrades or datagrams.

**Active output stall:** the native listener bounds every write. Each batch of
output for a connection has one absolute deadline of
`limits.upstream_request_timeout_secs`; partial progress does not extend it. A
peer that stops reading, or reads one byte at a time, loses the connection when
the deadline passes: the transport is dropped directly (no protocol shutdown a
stalled peer could block) and its connection slot is released. A drain close by
core is bounded by the shorter of that deadline and the drain grace.
