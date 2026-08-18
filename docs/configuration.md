# Configuration reference

Busbar reads **two YAML files** at startup:

| File | Default path | Env override | Purpose |
|---|---|---|---|
| Provider catalog | `/etc/busbar/providers.yaml` | `BUSBAR_PROVIDERS` | Shipped map of provider names → protocol, base URL, error map. Operators rarely edit this. |
| Deployment config | `/etc/busbar/config.yaml` | `BUSBAR_CONFIG` | Your site's providers (with secret references for credentials), models, pools, auth, groups, pricing, store, and telemetry export. |

Both files support `${VAR}` environment interpolation before YAML is parsed. A missing or malformed env var reference is a fatal startup error, Busbar refuses to boot rather than run with an incomplete config.

> Looking for a one-page map of every key? See [Config at a glance](config-at-a-glance.md).
>
> All defaults below are sourced from `crates/busbar/src/config/mod.rs`, `crates/busbar/src/breaker.rs`, `crates/busbar/src/health.rs`, and `crates/busbar/src/proto/mod.rs`. Where a serde field default differs from a runtime constant, both are noted.

---

## Table of contents

- [Environment variables](#environment-variables)
- [Environment interpolation](#environment-interpolation)
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
  - [`security`](#security)
  - [`advanced`](#advanced)
- [Migrating a 1.4.x config](#migrating-a-14x-config)
- [Minimal working example](#minimal-working-example)
- [Full annotated example](#full-annotated-example)
- [Startup validation summary](#startup-validation-summary)

---

## Environment variables

These are the only environment variables read by Busbar (excluding test-only `BUSBAR_T_*` / `BUSBAR_SENTINEL_*` names):

| Variable | Where read | Purpose / default |
|---|---|---|
| `BUSBAR_CONFIG` | `main.rs` | Path to `config.yaml`. Default: `/etc/busbar/config.yaml`. **The one bootstrap env var**: it locates config.yaml itself. |
| `BUSBAR_PROVIDERS` | `main.rs` | **Deprecated (1.5.3)**. Use the top-level `providers_file:` key. Path to `providers.yaml`; still honored (with a warning) for one release. Default: `providers.yaml` next to `config.yaml`. |
| `RUST_LOG` | `observability.rs` | Log level: `error`, `warn`, `info`, `debug`, or `trace`. Default: `info`. |
| *(each provider's `api_key: { env: VAR }` reference)* | `main.rs` | The env var **named by** the secret reference holds that provider's upstream credential. Resolved once at boot per provider. |
| *(any `${VAR}` in `config.yaml`)* | `config.rs` | Expanded before YAML is parsed. Unset → fatal boot error. |

`BUSBAR_ADMIN_TOKEN` is not special-cased in the code. It appears in the shipped `config.yaml` only because the file references `{ env: BUSBAR_ADMIN_TOKEN }` under `auth.admin_auth`. Any variable name works.

**Operational env vars moved into `config.yaml` (1.5.3).** `BUSBAR_PROVIDERS` → `providers_file:`, `BUSBAR_CONFIG_OVERLAY` → `config.overlay.file`, `BUSBAR_WORKER_THREADS` → `advanced.worker_threads`, `BUSBAR_UPSTREAM_HTTP1_ONLY` → `advanced.upstream_http1_only`, and `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` → `advanced.upstream_h2_prior_knowledge`. Each old env var still works for one release (with a deprecation warning). Only `BUSBAR_CONFIG` (bootstrap), secret `{ env: NAME }` references, and `RUST_LOG` remain env-native. See the [`config`](#config) and [`advanced`](#advanced) sections and the [upgrade note](migration-1.5.md#153-config-consolidation).

### `config`

The top-level `config:` block is config-**management** policy: whether the admin API may mutate config at runtime, and where those mutations persist. It is distinct from `store:` (the data-plane store). Absent ⇒ **durable-by-default**: mutable, with an overlay file next to `config.yaml`, so admin-API mutations survive a restart.

```yaml
config:
  locked: false                 # false = mutable (admin API may change config); true = immutable/GitOps
  overlay:
    file: busbar-overlay.json    # where mutations persist; relative paths resolve next to config.yaml
    # `overlay: false` disables persistence entirely. Valid ONLY with `locked: true`.
```

- **`locked: true`**: admin-API config mutations are refused at runtime; change config by editing `config.yaml` + `POST /config/reload`. The overlay is ignored.
- **Boot invariant: `locked` XOR a writable overlay.** A mutable config with no writable overlay (you set `overlay: false`, or the config dir is read-only) **refuses to boot**, with a message naming the two fixes (a writable `config.overlay.file`, or `config.locked: true`). This makes a silently-non-durable mutation unreachable.
- The `overlay:` map names its backend by key (`file:` today), mirroring `store: { module, settings }`, so a future durable-store overlay backend is additive.

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

### Catalog fields

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `protocol` | string | no | `anthropic` | One of the six supported wire protocols: `anthropic`, `openai`, `gemini`, `bedrock`, `responses`, `cohere`. An unknown protocol is a startup error. |
| `base_url` | string | **yes** | n/a | Scheme + host (+ optional path prefix). Must start with `https://` for external endpoints. An `http://` URL in the catalog is not blocked at parse time but will be rejected by the SSRF guard on deployment use. Trailing slash is trimmed. |
| `error_map` | map<string, string> | no | `{}` | Maps a provider-specific error **code string** (from the JSON error body) to a canonical disposition class. Valid values: `rate_limit`, `overloaded`, `server_error`, `timeout`, `network`, `auth`, `billing`, `client_error`, `context_length`. An unrecognized class value is a startup error. HTTP-status classification (401→auth, 429→rate_limit, 5xx→server_error, etc.) applies automatically without an `error_map`; this field is only for provider-specific JSON codes. |
| `path` | string | no | Protocol's standard path | Overrides the upstream request path appended to `base_url`. Must begin with `/`. Static, ignores the per-request model. Use when the API version is in `base_url` and the endpoint path differs from the protocol default (e.g. `/chat/completions` without `/v1`). |
| `path_base` | string | no | Protocol's default base | For URL-model protocols: overrides the hardcoded base segment while the per-request suffix is still appended. Must begin with `/`. On **Gemini** it replaces `/v1beta/models` (suffix `/{model}:verb`) to reach Google Vertex AI's `/v1/projects/{project}/locations/{location}/publishers/google/models` layout; on **Anthropic** it enables Claude-on-Vertex (the model moves into a `:rawPredict`/`:streamRawPredict` suffix and the body carries `anthropic_version` in place of `model`). Config-only, no code. |
| `auth` | string | no | Protocol's native auth | The egress auth mechanism. `bearer` (sends `Authorization: Bearer <key>`) · `api-key` (sends `api-key: <key>`, for Azure OpenAI) · `jwt-bearer` (OAuth 2.0 JWT-bearer, RFC 7523: mints + auto-refreshes a bearer from a service-account key resolved via `api_key`; e.g. Google Vertex AI) · `oauth-client-credentials` (OAuth 2.0 client-credentials, RFC 6749 §4.4: the `api_key` reference resolves to `client_id:client_secret`, exchanged at `token_url` for a bearer; e.g. Azure OpenAI via Entra ID). When unset, each protocol uses its native scheme: bearer for anthropic/openai/responses/cohere, `x-goog-api-key` for gemini, AWS SigV4 for bedrock. |
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

A provider whose `api_key` reference resolves to an empty value will not be probed regardless of the `health` block.

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

Each value is a secret REFERENCE (`{ file: ... }` / `{ env: VAR }` / `{ module: <secret-plugin> }`)
resolving to PEM bytes. The same shape configures the admin listener under `admin_tls:` (with
`client_ca` gating admin mTLS; a network-exposed `admin_listen` without `admin_tls.client_ca`
refuses to boot unless `admin_require_mtls: false` is set deliberately).

Certs/keys are loaded once at startup; any missing or unparseable file is a fatal
startup error naming the file. ALPN advertises http/1.1. Rotate certs by replacing
the files and restarting. Full operational guide:
[`operations.md`](operations.md#inbound-tls--mutual-tls-mtls).

---

### `auth`

Front-door identity for the data plane plus the admin chain and role policy.

**1.5.3: define once, reference by name.** Every identity provider is DEFINED once in the top-level
`identity-providers:` map (`name -> {module, settings, max_admin_scope, token, browser_login}`) and
REFERENCED BY BARE NAME from `auth.chain:`, `auth.admin_auth:` and `auth.role_bindings:`. One IdP that
serves both planes is therefore configured ONCE. Under the retired grammar it had to be written
inline in both chains, and nothing stopped the two copies from drifting. The built-ins `keys` (the
signed-key verifier) and `admin-tokens` (the operator credential) are referenced bare and need a
definition only when they carry config.

Static token allowlists are GONE in 1.5.0: every caller carries either a minted signed key or an IdP
credential a chain provider verifies.

Giving a provider definition a `browser_login:` block also lets developers **self-serve** their own
budgeted key by signing in. Busbar exposes a `GET`/`POST /auth/token` exchange automatically. (1.5.3
folded the retired parallel `auth.methods:` map into the provider definition: a client id/secret
belongs to ONE IdP registration, so it belongs on that provider.) See
[Token exchange (self-serve keys)](token-exchange.md).

```yaml
identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }
  ad:
    module: ad                                            # a `kind: auth` plugin
    settings: { server: "ldaps://corp", base_dn: "dc=corp" }
    # max_admin_scope:                                    # PER-PROVIDER admin ceiling:
    #                                                     # `read-only` | `full` ONLY.
    #                                                     # OMITTED = read-only (most restrictive)

auth:
  signing_key: { file: /run/secrets/busbar-signing.key }  # REQUIRED with `keys`; busbar --generate-signing-key
  chain: [keys, ad]                                       # bare PROVIDER NAMES
  admin_auth: [admin-tokens, ad]
  role_bindings:
    ad:
      growth-eng: { allowed_pools: [fast], group: growth }
      platform:   { group: acme, admin_scope: full }      # allowed_pools omitted = ALL pools
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `signing_key` | secret reference | **when `keys` is in the chain** | none | The ed25519 key Busbar signs + verifies virtual-key tokens with, as a secret reference (`{ file: … }` / `{ env: … }` / a secret plugin, never an inline literal). Fleet-shared (every node verifying the same tokens resolves the same key). **Required whenever the data-plane chain names the built-in `keys` verifier**; its absence there fails `--validate`/boot. Busbar does **not** auto-generate one (1.5.1: the earlier generate-and-persist-beside-config behavior boot-looped read-only config mounts). Generate a key with `busbar --generate-signing-key`. Rotating it revokes every outstanding key. |
| `chain` | list of provider NAMES | no | `[]` | The ordered DATA-PLANE authentication chain: the **sole** authority over whether a data-plane request needs a credential (the admin token never gates the data plane; see the axis note below). Each entry is a bare NAME: either a built-in (`keys`) or a key of the top-level `identity-providers:` map. A name that is neither is a **hard startup error** (fail-closed: never a silently-skipped identity provider). `[]` (default) is the open front door: development only, loud startup warning (the admin API stays gated by `admin_auth`). When the chain names `keys`, a **usable admin mint path** must exist (an `admin-tokens` provider with a `token:`, an admin provider granting `full`, or an explicit open `admin_auth: []`). Otherwise no virtual key could ever be minted and the data plane would reject every request, so it is a **hard startup error**. A configured auth plugin that cannot be loaded (missing/untrusted tarball, wrong kind, `plugins.enabled: false`, or an ABI failure) is likewise a **hard startup error**. |
| `admin_auth` | list of provider NAMES | no | `[admin-tokens]` | The chain gating `/api/v1/admin/*`, same bare-name references as `chain`. The built-in `admin-tokens` provider carries the operator credential as a secret reference (`token:`) on its definition. `[]` = OPEN admin (dev only; loud warning). |
| `role_bindings` | map | no | `{}` | Role policy, NESTED BY PROVIDER NAME: `role_bindings.<provider>.<role> -> { allowed_pools?, group?, admin_scope? }`. Keying by NAME (not by the backing plugin's own name) is what lets two named providers share one module and still hold independent grants. See below. |

**The `identity-providers:` definition map.** `name -> { module, settings?, max_admin_scope?, token?, browser_login? }`.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `module` | string | **yes** | n/a | Which `kind: auth` plugin (or built-in) backs this provider: the built-in `keys` / `admin-tokens`, or a `kind: auth` plugin name/alias. The SAME module may back SEVERAL named providers (different issuers, different ceilings). The NAME is the instance. |
| `settings` | map | no | `{}` | The module's own opaque config, pushed verbatim (SecretRef-typed values resolve first). |
| `max_admin_scope` | string | no | `read-only` | This provider's ADMIN ceiling, regardless of what `role_bindings` grants. The accepted tokens are exactly `read-only` \| `full`; any other value (including `none`) is an unknown scope token and fails `--validate`/boot. OMIT the key to get the MOST RESTRICTIVE default (`read-only`). There is no lower ceiling to write. The built-in `admin-tokens` operator credential is exempt (full by definition). `full` from an external IdP is always an explicit opt-in. To give a provider NO admin authority at all, leave this omitted and grant no `admin_scope` under its `role_bindings`. |
| `token` | secret reference | no | none | The operator ADMIN credential, only meaningful on a provider whose `module` is the built-in `admin-tokens`; anywhere else it is a boot error. |
| `browser_login` | map | no | none | `{ client_id?, client_secret? }`. PRESENCE puts a button on the hosted login page; a provider without it is headless-only (still usable via `POST /auth/token`). |

**Where did `auth.upstream_credentials` go?** To `pools.upstream_credentials` (1.5.3): whose credential reaches the provider is a ROUTING property, not an inbound-auth one. See [`pools`](#pools).

**Token extraction order (data plane):** `Authorization: Bearer`, then `x-api-key`, then
`x-goog-api-key`. Blank values are treated as absent.

**Three orthogonal axes (as of 1.5.3).** Data-plane admission, admin-API access, and governance
enforcement are independent, each with one local source of truth:

- **Data-plane admission** is decided **solely** by `auth.chain`: `[]` = open/anonymous, `[keys]` =
  a virtual key is required and resolved, an IdP/plugin chain requires that IdP. Nothing else, in
  particular **not** the admin token, decides whether a data-plane request needs a credential.
- **Admin-API access** is decided **solely** by `auth.admin_auth`; it gates `/api/v1/admin/*` and
  never touches the data plane. Minting lives behind it simply because mint is an admin endpoint.
- **Governance enforcement** is automatic: it applies to whatever principal-with-group the chain
  resolved. An open chain resolves no principal, so there is nothing to enforce.

This makes **"protected admin API + open (anonymous) relay for users"** expressible: set
`chain: []` with an `admin_auth` operator credential. (Before 1.5.2, configuring an admin token
silently forced a virtual key onto every data-plane request, so that posture was impossible.)

**Bedrock ingress.** Native Bedrock SDK clients authenticate with AWS SigV4. Mint a key with
`"issue_aws_credential": true`; the response includes `aws_access_key_id` +
`aws_secret_access_key` (shown once). Busbar verifies the inbound SigV4 signature natively
(including body-hash integrity), then applies the key's group limits and pool ACL.

#### `auth.role_bindings`: provider-scoped role policy

A role asserted by an identity provider earns exactly what the binding under THAT provider NAME
grants, nothing else: `ad.platform` and `oidc.platform` are distinct grants, and a provider can never
ride another provider's binding. An unbound role grants nothing (fail closed). Because the nesting key
is the provider NAME (not the backing module's name), two named providers may share one `module:` and
still hold independent grants.

| Field | Notes |
|---|---|
| `allowed_pools` | DATA-PLANE grant: pools this role may target. OMITTED = ALL pools; an explicit `[]` = NO pools (an empty list is the empty set, everywhere in the 1.5.0 config). Pool lists union across a principal's granting roles; any omitted grant widens the union to all pools. |
| `group` | The `groups:` bucket this role's principals charge through. Absent = no group (authed + unlimited). With several bound groups the first in role order wins. |
| `admin_scope` | The admin authority this role grants: `read-only` \| `full` (see [admin-api.md](admin-api.md#authentication--scopes)). Absent = none. A principal holds the highest scope its bound roles grant, then the asserting provider's `max_admin_scope` ceiling caps it (a `read-only` ceiling, which is the default and the recommended posture for an external IdP, reduces a `full` grant to `read-only`). Omitting `admin_scope` here is how a role gets no admin authority at all. |

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
own setup guide. For the first-party OIDC/SSO plugin, see the **[OIDC auth plugin](/plugins/auth/oidc/)**:
JWKS verification, claim-to-role mapping, and a full Microsoft Entra ID (Azure AD) example.

> **Entra ID gotcha: app roles vs. security groups.** The single most common OIDC misconfiguration.
> The `oidc` plugin's `role_claim` setting picks ONE of two, entirely different Entra objects. Mixing
> them up produces a token that verifies fine but binds to nothing (silent no-match, not an error):
>
> | `role_claim` | Reads | Claim value | Where you define it in Entra |
> |---|---|---|---|
> | `roles` | **App roles** | The role's **Value** string, verbatim (e.g. `busbar.dev`) | App registration → App roles (allowed member types: Users/Groups), then assign it under Enterprise application → Users and groups |
> | `groups` | **Security groups** | The group's **Object ID**, a GUID, never the display name | App registration → Token configuration → Add groups claim → Security groups (must be enabled, it's off by default) |
>
> A security group named `busbar.dev` does **not** satisfy `role_claim: roles`. App roles and security
> groups are different Entra objects, full stop. It only matches under `role_claim: groups`, bound by
> its GUID:
> ```yaml
> # role_claim: roles (app role): binding key is the role's Value, human-readable
> role_bindings:
>   oidc:
>     "busbar.dev": { group: engineering }
>
> # role_claim: groups (security group): binding key is the group's Object ID (GUID)
> role_bindings:
>   oidc:
>     "3fa85f64-5717-4562-b3fc-2c963f66afa6": { group: engineering }
> ```
> **Recommended pattern:** keep `role_claim: roles` for a readable config, then **assign the app role to
> your security group** (Enterprise application → Users and groups → add the group → assign the role).
> Members inherit the role through the group, so you manage access by group membership while
> `role_bindings` keeps naming a human-readable role instead of a GUID.

##### Walkthrough: configuring OIDC with Microsoft Entra ID

The rest of this section is the reference; this is the click-by-click path through Entra's portal.
Blade names matter: App registrations and Enterprise applications are two different areas of the
same app object, and steps 4 and 5 below live on **different** blades. Follow it in order.

1. **Create (or locate) the app registration.** Entra admin center → **App registrations** → New
   registration (or select your existing one). From its **Overview** pane, grab two IDs:
   - **Directory (tenant) ID** → `issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"`
   - **Application (client) ID** → `audience: "<client-id>"`

2. **Client secret.** App registration → **Certificates & secrets** → New client secret. Copy the
   secret's **Value** column (a string like `kqf8Q~...`) immediately. It's shown once. This goes to
   `browser_login.client_secret` (as a secret reference, e.g. `{ env: OIDC_CLIENT_SECRET }`).
   Do **not** copy the **Secret ID** column next to it: that's a GUID that identifies the secret
   record itself, not a credential, and it will fail to authenticate.

3. **Redirect URI.** App registration → **Authentication** → Add a platform → **Web** (not
   *Single-page application*). Busbar is a confidential client (it holds the client secret
   server-side), so it needs the **Web** platform type; SPA is for public, PKCE-only clients with no
   secret and will reject the exchange. Set the URI to `<public_url>/auth/token` (busbar's own
   callback route, built from your `public_url`). Entra permits `http://localhost:<port>/auth/token`
   for local dev.

4. **Choose app roles or security groups for `role_claim`, and set it up on the right blade(s).**
   This is the step people get lost on, because "define" and "assign" happen in two different places:
   - **App roles (recommended, `role_claim: roles`).** *Define* the role under App registration →
     **App roles** → Create app role (allowed member types: Users/Groups). Its **Value** field (e.g.
     `busbar.dev`) is what lands verbatim in the token's `roles` claim. That string is your
     `role_bindings` key. Then, on the **other** blade, *assign* it: **Enterprise applications** →
     your app → **Users and groups** → Add user/group → pick a user or a security group → select the
     role. Members of an assigned security group inherit the app role.
   - **Security groups (`role_claim: groups`).** First enable the claim (it's off by default): App
     registration → **Token configuration** → Add groups claim → check **Security groups**. Group
     membership then appears in the token as each group's **Object ID (a GUID)**, never its display
     name, so the `role_bindings` key must be that GUID.
   - **A security group named `busbar.dev` does not satisfy `role_claim: roles`.** App roles and
     security groups are different Entra objects; a group only matches under `role_claim: groups`,
     keyed by its GUID. If you want to manage access by group *and* keep a readable
     `role_bindings` config, use the recommended pattern above: `role_claim: roles`, with the app
     role assigned to the group.

5. **Put it together.** Config on the busbar side, all three pieces from above:

   ```yaml
   public_url: "https://busbar.example.com"
   identity-providers:
     oidc:                                                              # the provider NAME
       module: oidc                                                     # the `kind: auth` plugin
       settings:
         issuer:   "https://login.microsoftonline.com/<tenant-id>/v2.0" # step 1: tenant ID
         audience: "<client-id>"                                        # step 1: client ID
         role_claim: roles                                              # step 4: app roles
       browser_login:
         client_secret: { env: OIDC_CLIENT_SECRET }                     # step 2: secret Value
       # max_admin_scope omitted ⇒ read-only, the most restrictive ceiling; with no
       # `admin_scope` in the role_bindings below, SSO grants no admin authority at all.
   auth:
     signing_key: { file: /run/secrets/busbar-signing.key }
     chain: [keys, oidc]                                                # bare provider NAMES
     role_bindings:
       oidc:                                                            # keyed by PROVIDER NAME
         "busbar.dev": { group: engineering }                           # step 4: app role's Value
   groups:
     engineering:
       limits:
         - { budget: 200000, per: month }
   ```

**Common mistakes, at a glance:**

| Mistake | Fix |
|---|---|
| Redirect URI set to **Single-page application** | Use **Web**: busbar holds a client secret server-side |
| Pasted the **Secret ID** (GUID) instead of the secret **Value** | Copy the **Value** column at creation time; it's shown once |
| Created a security group and expect `role_claim: roles` to see it | App roles and security groups are different objects. Either switch to `role_claim: groups` + the group's GUID, or assign the app role to the group |
| Defined an app role but never assigned it | Definition (App registrations → App roles) and assignment (Enterprise applications → Users and groups) are separate steps on separate blades |
| Bound a `role_bindings` key to a group's display name under `role_claim: groups` | The claim carries the group's **Object ID (GUID)**, never the name |
| `groups` claim missing from the token entirely | It's off by default. Enable it under App registration → Token configuration → Add groups claim |

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
- **`budget`** derives at admission from the bucket's token ledger x the current `rate_card`
  plus `per_request_fee` x its request count, in abstract cents. Rejection: the vendor's native
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

The ONLY cost source. Tokens are the ledger; every dollar figure is DERIVED at read time as
`tokens x rate_card + requests x per_request_fee`, so correcting a rate is a config edit + reload
with no re-billing and no data migration.

```yaml
rate_card:
  sonnet-anthropic: { input_utok: 3.0, output_utok: 15.0, cache_read_utok: 0.3, cache_write_utok: 3.75 }
  sonnet-bedrock:   { input_utok: 2.8, output_utok: 14.0 }
per_request_fee: 0
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `rate_card` | map | absent (token pricing = 0) | Per-model, per-tier token rates in MICRO-units (1e-6 abstract cost unit) per token; an omitted tier prices 0. ALL-OR-NOTHING: absent = every model's tokens price at 0 (budgets count only the flat fee); present = AUTHORITATIVE and COMPLETE: every configured model must have an entry or boot/`--validate` fail with a paste-ready stub of exactly the missing models. With a card present, a request for an arbitrary passthrough model with no rate is rejected pre-forward. |
| `per_request_fee` | integer | `0` | Flat charge per request in abstract cents, charged at admission into every chain bucket's request count (refunded on a non-2xx outcome). |

The rate numbers are **abstract cost units**: Busbar does pure integer math and never knows what
currency they represent. Currency, symbols, and FX are display concerns owned by your dashboard.
Routing's `cheapest` strategy derives its per-member scalar from the card as
`(input_utok + output_utok) / 2`; pool members carry no cost fields.

---

### `store`

The durable store as a plugin instance: `{ module, settings }`. The default `memory` module is the
compiled-in ephemeral RAM store (keys, usage, and the audit log reset on restart); every durable
backend is a signed plugin tarball.

```yaml
store:
  module: postgres
  settings: { url: "postgres://user:pass@host/busbar" }
```

| `module` (alias or canonical name) | Plugin tarball | `settings` |
|---|---|---|
| `memory` (default) | compiled in, no plugin | none |
| `sqlite` / `busbar-store-sqlite` | `busbar-store-sqlite-<ver>-<target>.tar.gz` | `db_path` (file path), `busy_timeout_ms` (default 5000) |
| `postgres` / `busbar-store-postgres` | `busbar-store-postgres-<ver>-<target>.tar.gz` | `url` (`postgres://` libpq URL); cluster-shared |
| `valkey` / `busbar-store-valkey-plugin` | `busbar-store-valkey-<ver>-<target>.tar.gz` | `url` (`redis://`, `rediss://` for TLS); cluster-shared |

`settings` is the store module's OWN opaque configuration, passed through verbatim; a third-party
store plugin documents its own keys. A non-`memory` store requires `plugins.enabled: true` and the
store's tarball in `plugins.dir`, or Busbar refuses to boot naming the flag/plugin.

**Fleet semantics (honest):** with a cluster-shared store (postgres/valkey) behind N Busbar nodes,
virtual keys, accumulated usage, the audit log, and the revocation denylist are genuinely shared.
The limit hard caps are enforced PER NODE from each node's in-memory counters and reconciled
durably through ADDITIVE flushes, so the shared store converges on the true fleet total, but
between flushes N nodes splitting traffic can admit up to ~N times a configured cap. The caps are
not a synchronous cluster-wide gate.

**Metering retention (ALL backends, not just Valkey):** `usage_metering` rows are one per (key,
metering-bucket day, model, provider), accumulated forever. Busbar has no prune path on any store
backend (sqlite, postgres, valkey, or a third-party plugin), because metering is observability only,
never consulted for enforcement (`add_metering`'s own doc comment, `crates/api/src/store.rs`). Row
CARDINALITY is bounded by your config (keys × buckets × models × providers), but the TIME dimension
is not, so the table grows without bound unless you retain it yourself. `list_metering(bucket)` reads
exactly one day, so deleting rows for buckets older than N days is safe and cannot affect admission,
billing, or any other enforcement path. It is a plain `DELETE` against your store's own schema, on
your own retention horizon; Busbar does not choose one for you.

**Backend caveats:** the Valkey store supports TLS (`rediss://`), transparent reconnect, and atomic
multi-key cascades (MULTI/EXEC), and scrubs the URL password from error strings; it writes WITHOUT
TTLs (usage/metering/audit grow unboundedly by design: apply your own retention, per the metering
note above). The Postgres store currently connects `NoTls` and without automatic reconnect: run it
over a trusted network segment (or a TLS-terminating proxy such as pgbouncer/stunnel) and let your
supervisor restart Busbar on a persistent connection loss.

---

### `providers`

Declares which catalog providers this deployment uses and supplies the env var holding each one's credential.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `api_key` | secret reference | **yes** | n/a | The upstream credential as a secret reference: `{ env: VAR }`, `{ file: /path }`, or `{ module: <secret-plugin>, settings: {...} }`. Resolved once at boot. A reference resolving to an empty value logs a startup warning; the lane starts but will fail upstream auth. |
| `protocol` | string | no | Catalog value | Override the catalog protocol. Rarely needed. |
| `base_url` | string | no | Catalog value | Override the upstream base URL. Must use `https://` for public/external hosts. Plain `http://` is permitted only for private or loopback hosts (e.g. a local Ollama or vLLM instance). Cloud-metadata hosts are blocked regardless of scheme (see SSRF guard). |
| `error_map` | map<string, string> | no | `{}` merged onto catalog | Merged with the catalog's `error_map`; deployment entries win per code. |
| `path` | string | no | Catalog value | Override the upstream path. Must begin with `/`. |
| `path_base` | string | no | Catalog value | Override the URL-model base segment (Gemini or Anthropic), keeping the per-request verb suffix. Must begin with `/`. For Gemini-on-Vertex and Claude-on-Vertex. |
| `auth` | string | no | Catalog value | `bearer`, `api-key`, `jwt-bearer` (OAuth service-account, e.g. Vertex AI), or `oauth-client-credentials` (e.g. Azure Entra ID). |
| `token_url` | string | no | Catalog value | OAuth token endpoint for `oauth-client-credentials`. |
| `scope` | string | no | Catalog value | OAuth scope for `oauth-client-credentials`. |
| `subject` | string | no | Catalog value | JWT-bearer assertion `sub` claim (RFC 7523 §3) for `jwt-bearer`. Opt-in. See the catalog `subject` row above; unset means no `sub` claim, the correct default for a plain Vertex AI service account. |
| `health` | object | no | Catalog value | Override the catalog's health probe config. |
| `allow_metadata_hosts` | list<string> | no | `[]` | Per-provider surgical exception: hosts/IPs to unblock from the cloud-metadata SSRF denylist for **this provider only**. See [Security: Provider upstreams & SSRF](/docs/security/#the-control-matrix). |

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
| `model` | string | **yes** | n/a | Name of a model in `models`. Must be a configured model; a missing model is a startup error. (Renamed from the 1.4.x `target`; the old key is a startup error.) |
| `weight` | integer | no | `1` | Relative selection share under smooth weighted round-robin (SWRR), computed over the currently healthy/usable members. Must be ≥ 1. `0` is a startup error. |
| `context_max` | integer | no | none | This member's maximum context window (tokens). Used for [context-length failover](#context-length-failover). |
| `attempt_timeout_ms` | integer | no | the model's value | Per-attempt time-to-response-headers cap for this member **in this pool**, overriding the model-level `attempt_timeout_ms`. Lets the same model carry different hang tolerances per pool (e.g. `10000` in a batch pool, `50` in a latency-critical one). Must be ≥ 1 when set (0 is a startup error). See [Per-attempt timeouts](#per-attempt-timeouts-attempt_timeout_ms). |
| `reasoning` | bool | no | the model's value | Per-pool override of the model-level `reasoning` capability flag (member wins), so the same lane can allow thinking in a research pool and refuse it in a latency-critical one. See [Cross-protocol reasoning](#cross-protocol-reasoning-reasoning). |
| `tier` | string | no | none | Operator-declared routing tier label (e.g. `"primary"`, `"overflow"`, `"large"`, `"small"`). Inert for plain weighted pools (no hooks). Exposed to gate hooks as the `tier` field on each candidate. See [Pool `hooks`](#pool-hooks-ordering-and-gates). |
| `tags` | list<string> | no | `[]` | Free-form string labels (e.g. `["opus", "large-context"]`). The `restrict` gate verb intersects the candidate set against these tags (compliance pinning). Exposed to gate hooks for tag-based candidate selection. Inert for plain weighted pools. |

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

**1.5.3: hooks are DEFINED once, at the top level, and REFERENCED by bare name.** The top-level
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
  `kind: hook` plugin by signed-manifest name/alias (1.5.0 retired the built-in `socket`/`webhook`
  transports; a hook is now always a signed plugin), so it requires `plugins.enabled: true` and the
  tarball installed in `plugins.dir`. Out-of-process forwarding to an HTTPS sidecar is the
  first-party `busbar-webrequest-hook` plugin (`settings.url`). An unresolvable `module:`, or a
  reference to a name that no `hooks:` entry defines, is a fail-closed boot error.

```yaml
plugins: { enabled: true, dir: /etc/busbar/plugins }

hooks:                                                 # the DEFINITION map (define once)
  audit:
    module: busbar-audit-hook
    kind: tap
    phase: [request, response]                         # a LIST of stages; omit = all four
    on_error: nothing
  pii:
    module: webrequest                                 # forwards to an HTTPS sidecar
    settings: { url: "https://sidecar.internal/pii" }
    groups: [engineering]                              # SCOPE: omit or [] = every caller
    kind: gate
    timeout_ms: 5
    prompt: ro
    on_error: reject
  rank:
    module: webrequest                                 # the SAME module, a second named hook
    settings: { url: "https://router.internal/rank" }
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
| `settings` | map | `{}` | The plugin's own opaque config, pushed to it via the `configure` wire message. For the first-party `busbar-webrequest-hook`, `settings.url` is the sidecar endpoint (SSRF-guarded: loopback allowed; RFC-1918/CGNAT/link-local/metadata blocked; remote must be `https://`). |
| `groups` | list<string> | `[]` (every caller) | SCOPE: the caller groups this hook fires for. A USER is a leaf group (e.g. `user:bob`); membership walks the [`groups:`](#groups) tree, matching the caller's own group or any ancestor. |
| `phase` | list<string> | all four stages | The pipeline stages this hook fires at: `request` \| `candidate` \| `routing` \| `response`. A **LIST**. 1.5.3 generalized the single-valued tap `at:` into it (`route`→`candidate`, `attempt`→`routing`, `completion`→`response`). Omitting `phase:` means exactly those four core stages. |
| `kind` | `tap` \| `gate` | `gate` | `gate` = fire-and-wait (may rank/reject/restrict/rewrite); `tap` = fire-and-forget observation. |
| `timeout_ms` | integer | `1` | Hard wall-clock deadline for a gate decision. Raise it when the hook does I/O. On timeout the decision is coerced to `on_error`. |
| `on_error` | keyword or ref | `nothing` | Fallback when a gate times out / errors / saturates: a bare terminal (`nothing` \| `weighted` \| `reject` \| `first`) or a structured hook reference `{ hook: <name> }` (a chain, proven terminating at boot). A gate's deliberate `reject` reply is a decision, not a failure. |
| `on_empty` | string | `reject` | A restrict gate's empty-intersection behavior: `reject` (fail closed, 503) or `weighted` (advisory escape). |
| `prompt` | `no` \| `ro` \| `rw` | `no` | Prompt-content grant: `ro` sends the prompt read-only; `rw` additionally allows a `rewrite` reply. `rw` on a tap is a startup error. |
| `user` | `no` \| `ro` | `no` | Caller-identity grant: governance key id/name (never the secret) + the body's end-user field. |
| `priority` | integer | `0` | Chain ordering key: orders the rewrite transform chain and tie-breaks the reconcile. |

The per-member `tier` and `tags` fields documented in [Members and weights](#members-and-weights)
feed the ordering strategies and gate candidates. Gate observability: see
[observability.md#response-headers](observability.md#response-headers) for the opt-in
`x-busbar-route-policy` / `x-busbar-route-target` response headers, which name the deciding hook and
chosen lane.

---

#### `breaker`

Circuit-breaker tuning for one target. On the LLM plane a target is a `(pool, lane)` cell, and the state is independent per pool: a lane open in pool A can be closed in pool B. Lane-global state (hard-down, lifetime budget, concurrency semaphore) is shared across all pools.

**This block is accepted under `pools:` and nowhere else.** An earlier version of this reference said `tools.<server>.breaker:` and `agents.<agent>.breaker:` were also accepted. They are not, they never were, and because `tools:` and `agents:` reject unknown keys, a config written against that sentence fails at boot rather than running with the block ignored. MCP and A2A share the one breaker through `tool_pools:` / `agent_pools:` (see [circuit-breaker.md](circuit-breaker.md#failover-on-mcp-and-a2a-the-same-server-deployed-twice)), which take `members:` and `repeatable:` only, so those planes run on the built-in breaker defaults. There is no field reference for `mcp:`, `tools:`, `agents:`, `tool_pools:` or `agent_pools:` on this page; the complete grammar for each, with every boot refusal, is in [mcp.md](mcp.md) and [a2a.md](a2a.md).

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
| `trip.window_secs` | integer | `30` | Must be ≥ 1 | Sliding outcome window for `error_rate` mode. Outcomes older than `window_secs` are evicted. (`window_secs` is the ONLY spelling; the pre-1.0 `window_s` alias is gone and fails boot.) |
| `trip.threshold` | float | `0.5` | Must be in `(0.0, 1.0]` | Error fraction threshold for `error_rate` mode. `0.5` means more than half of outcomes in the window must be errors to trip. |
| `trip.min_requests` | integer | `5` | Must be ≥ 1 | `error_rate` mode: minimum outcomes required in the window before the threshold is evaluated. Prevents tripping on a single failure with no baseline. |
| `trip.consecutive_n` | integer | `3` | Must be ≥ 1 | `consecutive` mode: number of consecutive failures that trip the breaker. (`consecutive_n` is the ONLY spelling; the pre-1.0 `n` alias is gone and fails boot.) |
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

A keyword stays bare; a reference is structured (the 1.5.0 `on_X` convention):

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

Optional. Exposes thirteen operational limits (mostly previously hardcoded, plus `max_inbound_concurrent`, `pool_idle_timeout_secs`, and `request_body_read_timeout_secs`) so operators can tune them without rebuilding. All fields default to their historical values, so omitting this block is a no-op.

```yaml
limits:
  max_inbound_concurrent: 8192    # 0 = unlimited; > 0 caps in-flight inbound and sheds excess (503)
  request_body_max_bytes: 33554432  # 32 MiB
  upstream_request_timeout_secs: 300
  tls_handshake_timeout_secs: 10
  request_body_read_timeout_secs: 30  # max gap between inbound body frames (slow-loris body defense)
  pool_max_idle_per_host: 1024
  pool_idle_timeout_secs: 300     # 5 min
  hard_down_cooldown_secs: 1800   # 30 min
  upstream_error_body_max_bytes: 262144  # 256 KiB
  max_honored_retry_after_secs: 86400 # 24 h
  default_max_tokens: 4096
  max_keys_per_principal: 0       # 0 = unlimited; >0 caps LIVE keys bound to one group (per-user anti-sprawl)
  max_auto_provisioned_groups: 0  # 0 = unlimited; >0 caps how many groups a mint may auto-provision
  hook_content_max_bytes: 65536   # 64 KiB; ceiling on the content a `prompt: ro|rw` hook is shown
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `max_inbound_concurrent` | integer | `8192` | Global inbound concurrency cap, applied outermost (before request bodies are buffered), so it is the global bound on peak request memory: worst case is this limit times `request_body_max_bytes`. A request that arrives while the cap is full is **shed**, returned a `503` with `Retry-After` immediately, rather than queued behind the cap (the layer is a `tower::limit::GlobalConcurrencyLimitLayer` wrapped in `tower::load_shed`). `0` = unlimited (no cap layer installed, the pre-1.5.0 posture). **Restart-to-apply**: it is captured once in `main()` and baked into the router at process start; a config apply swaps only the `App`, never the router, so the semaphore's permit count cannot change live. `reload_to_apply` flags `limits.max_inbound_concurrent` when set. |
| `request_body_max_bytes` | integer | `33554432` | Maximum inbound request body size (bytes). Exceeding this returns a protocol-native 413. **Partially restart-to-apply, undocumented in the API today (known gap, tracked for post-1.5.0):** the inbound 413 threshold (`axum::extract::DefaultBodyLimit`) is boot-frozen the same way as `max_inbound_concurrent` above, but the coupled egress translate/buffer cap (`limits::translate_body_max_bytes()`) reads a live snapshot re-installed on every apply. A live `PUT` therefore only half-applies: **lowering** this value moves the egress cap down immediately while the inbound 413 threshold stays at the boot value, so a request body can land in the gap between the two: accepted inbound, but no longer buffer-translatable on a cross-protocol hop, breaking the "accepted implies translatable" invariant. `reload_to_apply` does not flag this field: flagging it dotted would mis-state that the whole field is stored-not-live when three of its four consumers are in fact live. The fix (make the inbound limit read the live snapshot, or otherwise pin the coupling) is deferred past 1.5.0 because it touches the request path and the router layer stack. |
| `upstream_request_timeout_secs` | integer | `300` | Per-upstream-request wall-clock timeout. Applies to both the connect and the full response. **Restart-to-apply**: the upstream `reqwest::Client` is built once at boot and reused across config applies (warm connection pools are kept deliberately), so a live `PUT` changes the stored value but not the running client. `reload_to_apply` flags `limits.upstream_request_timeout_secs` when set. |
| `tls_handshake_timeout_secs` | integer | `10` | Wall-clock cap on each inbound TLS handshake; prevents slowloris / handshake-flood. Ignored when `tls:` is absent. |
| `request_body_read_timeout_secs` | integer | `30` | Maximum time allowed between inbound request-body frames before the connection is dropped. Closes the slow-loris body gap the header-read timeout does not cover. |
| `pool_max_idle_per_host` | integer | `1024` | HTTP connection pool idle connection limit per upstream host. **Restart-to-apply** (same boot-scoped `UpstreamClients` reuse as above; `reload_to_apply` flags `limits.pool_max_idle_per_host`). |
| `pool_idle_timeout_secs` | integer | `300` | How long an idle keep-alive connection stays in the upstream pool before being closed. The 300s default keeps the warm working set alive across inter-burst gaps (TCP keepalive validates idle sockets in the meantime); lower it to shed idle sockets sooner. **Restart-to-apply** (same boot-scoped `UpstreamClients` reuse; `reload_to_apply` flags `limits.pool_idle_timeout_secs`). The connect timeout (10s) and TCP keepalive (60s) baked into the same client builder are not configurable at all. |
| `hard_down_cooldown_secs` | integer | `1800` | Sticky cooldown for `auth`/`billing` breaker dispositions (hard-down). Recovering these lanes requires a successful health probe. |
| `upstream_error_body_max_bytes` | integer | `262144` | Maximum bytes buffered from a non-2xx upstream response body for error classification. |
| `max_honored_retry_after_secs` | integer | `86400` | Maximum value honored from an upstream `Retry-After` header (to prevent overflow). |
| `default_max_tokens` | integer | `4096` | Gateway-wide default injected on cross-protocol hops to Anthropic when the caller omitted `max_tokens`. Overridden by a per-model `default_max_tokens` when set. |
| `max_keys_per_principal` | integer | `0` | Anti-sprawl cap: the maximum number of **live** keys (enabled and not revoked) that may be bound to one group, the unbound bucket included. `0` = unlimited. Enforced on `POST /keys` **and** on a `PATCH /keys/{id}` rebind; over cap is a terminal `409 conflict`. |
| `max_auto_provisioned_groups` | integer | `0` | Anti-sprawl cap on the SHAPE of the limit tree: the maximum size of the runtime group set that `POST /keys` may grow by auto-provisioning (`parent:`). `0` = unlimited. Over ceiling is a terminal `409 conflict`; binding to an existing group is unaffected. |
| `hook_content_max_bytes` | integer | `65536` | Ceiling on the request CONTENT a hook holding a `prompt: ro`/`rw` grant is shown in one projection. Over-cap content is omitted **whole** — never truncated mid-value, because a guardrail that screens half a payload and passes it is worse than one that refuses — and the hook receives a present-but-empty content projection, which the wire distinguishes from the absent one an ungranted hook sees; the always-present size fields still report the real totals, so an omission is visible in the payload rather than silent. `busbar_hook_content_truncated_total` counts it. `0` = unlimited. Live: a `PUT` takes effect on the next request. This bounds the tool-argument and tool-result content a hook now sees, which on an agent request is limited by neither a context window nor a token count. |

---

### `export`

**1.5.3: `export:` is the single telemetry-egress surface, and the `observability:` block is DELETED.**
It is a NAMED map (`<instance-name>: { module, settings }`), so the SAME module can back SEVERAL
instances, which the retired type-keyed block could not express at all (two request-log webhooks to
two URLs is a real deployment: app logs plus SIEM). Presence is the switch; an absent/empty block
leaves collection inert.

```yaml
export:
  metrics:  { module: prometheus,          settings: { buffer_seconds: 60 } }
  req-log:  { module: request-log-webhook, settings: { url: "https://logs.example.com/busbar" } }
  req-siem: { module: request-log-webhook, settings: { url: "https://siem.internal/ingest" } }
  traces:   { module: otlp,                settings: { url: "http://localhost:4318/v1/traces" } }
```

| `module` | Stream | `settings` | Notes |
|---|---|---|---|
| `prometheus` | Metrics (PULL) | `buffer_seconds` (**required**), `key_gauge_limit` (default 2000) | Installs the recorder and serves `/metrics` (auth-gated, same rules as `/stats`). At most ONE instance: it owns the one well-known route, so a second is a boot error rather than a silent loss. `buffer_seconds: 0` is a boot error (it would retain nothing while still paying the recording cost); OMIT the instance to turn metrics off. |
| `request-log-webhook` | Logs (PUSH) | `url` (**required**, `https://`-only), `auth_header: { name, value }`, `max_inflight_deliveries` (default 64), `delivery_timeout_secs` (default 2) | Fire-and-forget JSON POST per completed request: `{ts, ingress_protocol, pool, outcome, latency_ms}`. SSRF-guarded. Drops rather than queues when saturated. Timeout is PER INSTANCE; the in-flight bound is shared across instances and takes the maximum. |
| `request-log-file` | Logs (PUSH) | `path` (**required**), `rotate_mb` | Appends each request-log line as JSONL. |
| `otlp` | Traces | `url` (**required**) | OTLP/HTTP trace exporter. Loopback `http://` is allowed (standard collector default); remote endpoints must use `https://`. SSRF-guarded: rejects RFC-1918, link-local, CGNAT, metadata hosts. Traces are flushed on graceful shutdown. At most ONE instance (it installs the one process-global tracer subscriber). |

The whole `export:` block is **restart-to-apply**: edit it in `config.yaml` and apply via a plugin
reload / restart. It is deliberately NOT part of the single-value `PUT /config/settings` overlay: the
sinks seed process-global `OnceLock`s (and, for OTLP, a one-shot `tracing_subscriber` init) that a
live apply structurally cannot re-point.

**OTLP credential hygiene.** If your OTLP endpoint requires auth, supply credentials in the URL userinfo (`https://user:pass@collector.example.com/…`): Busbar moves them to an `Authorization: Basic` header and strips them from the URL before logging, so they do not appear in logs or spans.

**Response headers moved.** `Server-Timing: busbar;dur=<ms>` (formerly `observability.emit_server_timing`) and the `x-busbar-route-policy` / `x-busbar-route-target` headers are now both `advanced.response_headers` toggles, default `false`. See [`advanced`](#advanced) below and [observability.md#response-headers](observability.md#response-headers) for the full catalogue. `busbar --migrate-config` moves an old `observability.emit_server_timing` key for you; the old key is otherwise an `unknown field` boot error.

---

### Virtual keys and enforcement

The 1.5.0 identity/enforcement model in one page. (The config pieces live in the sections above:
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
[`groups`](#groups) for per-metric semantics). Spend derives at check time from the token ledger
x the current `rate_card` + `per_request_fee` x requests: tokens are the only stored truth, so a
rate correction reprices everything on the next read. A key bound to a group missing from the
running config fails CLOSED (the rejection names the unconfigured bucket); minting validates the
group exists, and boot re-checks every stored key.

**Admin API routes** (guarded by `auth.admin_auth`, served on `admin_listen`):

| Route | Method | Description |
|---|---|---|
| `/api/v1/admin/keys` | `POST` | Mint a key. Returns the signed token once (`"issue_aws_credential": true` adds the AWS pair, also shown once). |
| `/api/v1/admin/keys` | `GET` | List key metadata: `{id, name, allowed_pools, group, enabled, created_at, labels}` (never a secret). |
| `/api/v1/admin/keys/{id}` | `PATCH` | `{enabled?, group??}`: freeze/unfreeze the binding, or rebind/unbind the group (three-state: absent = unchanged, `null` = unbind, value = rebind to an existing group). |
| `/api/v1/admin/keys/{id}/usage` | `GET` | The key's all-time attribution counters (derived spend, tokens, requests) plus chain-derived `rate_headroom`. |
| `/api/v1/admin/keys/{id}` | `DELETE` | Revoke: adds the subject to the durable denylist (enforced immediately, survives restart). Returns 404 if not found. |

See [operations.md](operations.md) for worked payloads and [admin-api.md](admin-api.md) for the
full admin contract (which carries its own version, independent of the binary's SemVer).

---

### `plugins`

The dynamic plugin subsystem: signed plugin tarballs (store, secret, auth, and hook plugins share the same machinery) that Busbar verifies and loads at boot. **Off by default**: with `plugins.enabled: false` (or the whole block absent) no plugin is ever discovered or loaded, and a tarball dropped into the directory is inert. See [plugins.md](plugins.md) for the plugin author guide, the artifact format, and the full trust model.

```yaml
plugins:
  enabled: true                 # MASTER SWITCH, default false. Off = no plugin ever loads.
  dir: plugins                  # where the signed .tar.gz plugin tarballs live (default: plugins)
  trust:
    # busbar's own release key is EMBEDDED in the binary: busbar-signed plugins verify with
    # zero configuration. This block is for THIRD-PARTY publishers and explicit opt-ins.
    publishers:                 # third-party ed25519 signing keys (allowlist)
      - name: acme
        public_key: "<64-hex ed25519 public key>"
    allow_unsigned: false       # default false: unsigned/tampered plugins are logged + skipped
    allow_third_party: false    # default false: signed-but-unknown-publisher plugins are skipped
  min_versions:                 # anti-downgrade floors, keyed by manifest name (third-party;
    acme-store-dynamo: "2.0.0"  # first-party is automatically floored at the binary's version)
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `enabled` | bool | no | `false` | Master switch. `false`/absent = NO plugin loads (drop-is-inert). A non-`memory` `store.module` with plugins disabled is a boot error naming this flag. |
| `dir` | string | no | `plugins` | Directory holding the signed plugin tarballs (`*.tar.gz`), relative to the working directory. Filenames are irrelevant: identity comes from each tarball's signed manifest. |
| `trust.publishers` | list | no | empty | Third-party publishers: `{ name, public_key }` pairs (hex ed25519). The name `busbar` is reserved for the embedded release key and cannot be configured. |
| `trust.allow_unsigned` | bool | no | `false` | EXPLICIT opt-in to load plugins with no valid signature (unsigned/tampered). Without it they are logged and skipped, never `dlopen`ed. |
| `trust.allow_third_party` | bool | no | `false` | EXPLICIT opt-in to load validly-signed plugins from a publisher NOT in `publishers`. |
| `min_versions` | map | no | empty | Anti-downgrade floors: manifest `name` -> minimum `version`. A floored plugin must prove (trusted signature at/above the floor) that it meets it; no opt-in flag can bypass a floor. First-party plugins are automatically floored at the running binary's version. |

**Fail-closed guarantees:** with plugins enabled, ANY invalid tarball or manifest in `dir` (unparseable, missing/malformed fields, sha256 mismatch, unsupported `abi_version`) aborts boot naming the file and reason; any name/alias conflict between loadable plugins aborts boot naming both. `busbar --validate` runs the exact same pipeline ahead of time (zero side effects, nothing loaded), and `busbar --list-plugins` prints the manifest-only inventory with each plugin's signature verdict and load status.

### `security`

Optional. Extends or overrides the hardcoded cloud-metadata SSRF denylist. When absent, only the built-in denylist applies. See [Security: Provider upstreams & SSRF](https://getbusbar.com/docs/security/) for the full threat model, the complete denylist, and worked examples.

```yaml
security:
  blocked_metadata_hosts:
    - "169.254.100.1"
  allow_metadata_hosts:
    - "metadata.google.internal"
  allow_all_metadata: false   # default; set true only for dev, logs a startup WARNING
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `blocked_metadata_hosts` | list<string> | `[]` | Additional hosts/IPs appended to the hardcoded denylist. Entries may be IP literals or DNS hostnames. Matched with the same obfuscation-aware canonicalization as the built-in list. |
| `allow_metadata_hosts` | list<string> | `[]` | Hosts/IPs to **unblock globally**: removed from the effective denylist for all providers. Use per-provider `allow_metadata_hosts` for a narrower exception. |
| `allow_all_metadata` | bool | `false` | Disables the SSRF guard entirely. Every cloud-metadata endpoint becomes reachable by every provider. **Logs a startup WARNING.** Development use only. |

**Precedence:** a host is blocked iff it is in the denylist (hardcoded union `blocked_metadata_hosts`) **and not** in any allow-override (`security.allow_metadata_hosts` union that provider's `allow_metadata_hosts`) **and not** `allow_all_metadata`. Allow always wins.

---

## Minimal working example

The smallest config that parses and resolves. `providers` and `models` are the only required top-level sections.

**`config.yaml`:**

<!-- doc-check: config -->
```yaml
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
- `GET /metrics`, Prometheus (admitted unconditionally under `chain: []`).

`listen` defaults to `0.0.0.0:8080`. No auth gate. No pools.

---

## Full annotated example

This example requires: `BUSBAR_ADMIN_TOKEN`, `ANTHROPIC_KEY`, `OPENAI_KEY`, `GEMINI_KEY`.

```yaml
listen: "0.0.0.0:8080"
admin_listen: "127.0.0.1:8081"      # the admin API always runs on its own listener

# ---------------------------------------------------------------------------
# Auth: data-plane callers present minted signed keys (the built-in `keys`
# verifier); the admin API is gated by the admin-tokens operator credential.
# ---------------------------------------------------------------------------
identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }

auth:
  signing_key: { file: /run/secrets/busbar-signing.key }  # REQUIRED with `keys`; no auto-gen
  #                                                        # (`busbar --generate-signing-key`)
  chain:
    - keys
  admin_auth: [admin-tokens]           # a bare PROVIDER NAME (defined above)

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
  claude-sonnet: { input_utok: 3.0, output_utok: 15.0, cache_read_utok: 0.3, cache_write_utok: 3.75 }
  gpt-4o:        { input_utok: 2.5, output_utok: 10.0 }
  gpt-4o-mini:   { input_utok: 0.15, output_utok: 0.6 }
  gemini-1.5-pro: { input_utok: 1.25, output_utok: 5.0 }
per_request_fee: 1

# ---------------------------------------------------------------------------
# Store: durable keys/usage/audit/denylist (a loadable plugin; omit the block
# for the ephemeral RAM default).
# ---------------------------------------------------------------------------
store:
  module: sqlite
  settings: { db_path: /var/lib/busbar/governance.db }

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
# logging are all NAMED instances here (1.5.3 deleted `observability:` and the
# top-level `metrics:` block). Prometheus is OPT-IN: omit the instance and busbar
# records nothing and does not mount /metrics. When it IS present,
# `buffer_seconds` is REQUIRED: how many seconds of observations to retain
# (quantiles cover that window; _sum and _count stay cumulative), which is what
# bounds the memory cost of metrics.
# ---------------------------------------------------------------------------
export:
  metrics: { module: prometheus,          settings: { buffer_seconds: 60 } }
  traces:  { module: otlp,                settings: { url: "http://localhost:4318/v1/traces" } }
  req-log: { module: request-log-webhook, settings: { url: "https://logs.example.com/busbar" } }

# ---------------------------------------------------------------------------
# Response headers: every busbar-injected header is opt-in, default OFF (see
# observability.md#response-headers). This example opts into both.
# ---------------------------------------------------------------------------
advanced:
  response_headers:
    server_timing: true
    route_policy: true
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
| `base_url` SSRF | `base_url` resolves to a cloud-metadata/IMDS host (e.g. `169.254.169.254`, `100.100.100.200`, `metadata.google.internal`) or uses an alternate IP encoding (decimal-int, hex, octal, IPv4-mapped IPv6) that decodes to a metadata address |
| `base_url` plaintext | `base_url` uses `http://` with a public (non-private, non-loopback) host: plain HTTP to a public host would expose the API key on the wire |
| `error_map` value unknown | A value in `error_map` is not one of the nine canonical disposition classes |
| `auth` value unknown | `auth` field value not `bearer`, `api-key`, `jwt-bearer`, or `oauth-client-credentials` |
| `affinity.mode` value unknown | `affinity.mode` not `session` (the only supported value) |
| 1.x config detected | A 1.x structural marker is present (a `governance:` block, `auth.group_map:`, `auth.mode:`, a top-level `hooks:` **REGISTRY** block (one with `socket:`/`webhook:` entries, or any entry lacking `module:`; the 1.5.3 `hooks:` DEFINITION map is valid and passes straight through), `api_key_env`, `target:` in a pool member): boot refuses with "this looks like a Busbar 1.x config; run `busbar --migrate-config`" |
| Retired 1.5.3 key present | A retired grammar key is present (`global_hooks:`, `observability:`, a top-level `metrics:` block, `admin_insecure:`, `auth.upstream_credentials:`, `auth.methods:`, `otlp_url`/`otlp_endpoint`): boot refuses, naming the key AND its 1.5.3 home, with the `busbar --migrate-config` breadcrumb |
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
| Pool `hooks:` bare name not a built-in strategy | An out-of-process hook is an inline `{ module: ... }` ref; bare names are only `weighted`/`cheapest`/`fastest`/`least_busy`/`usage` |
| Unknown hook module | An inline ref's `module` does not resolve to a loaded `kind: hook` plugin (by manifest name/alias) |
| Hook plugin subsystem disabled | An inline ref names a plugin while `plugins.enabled` is false, or the tarball is not installed in `plugins.dir` |
| Hook `busbar-webrequest` SSRF-blocked | RFC-1918, CGNAT, link-local, and metadata hosts are blocked in its `settings.url` (loopback allowed; remote must be `https://`) |
| `prompt: rw` on a `kind: tap` hook | A tap observes; it can never rewrite |
| Groups tree faults | A `parent` that does not exist (paste-ready stub), a cycle (the path is printed), or a chain deeper than 8 |
| Malformed group limit | A limit without exactly one metric key, a windowed metric without `per:`, or `concurrent` with a `per:` |
| Breaker `max_cooldown < base_cooldown` | Cooldown ceiling below the base |
| Rate card incomplete | `rate_card` present but missing an entry for a configured model (a paste-ready zeroed stub of the missing models is printed) |
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
| A provider `api_key` reference resolves empty at boot (lane will fail auth) |
| `allowed_pools` on a virtual key (admin API) names a pool not currently configured |
| The ephemeral `memory` store with minted keys: keys, usage, and the revocation denylist reset on restart (choose a durable `store.module` for persistence) |

---

### `advanced`

Internal tuning knobs, normally omitted; each field defaults to its historical value.

```yaml
advanced:
  rate_sweep_interval: 256          # rate-limiter stale-entry sweep amortization (every Nth check_rate)
  usage_flush_interval_ms: 100      # write-behind flush cadence for in-memory usage/budget counters
  worker_threads: 4                 # tokio worker pool size (1.5.3 ← BUSBAR_WORKER_THREADS); omit ⇒ one per core
  upstream_http1_only: false        # pin the upstream client to HTTP/1.1 (1.5.3 ← BUSBAR_UPSTREAM_HTTP1_ONLY)
  upstream_h2_prior_knowledge: false # force h2c prior-knowledge to cleartext upstreams (1.5.3 ← BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE)
  response_headers:                 # every busbar-injected response header, opt-in, default OFF
    server_timing: false            # `Server-Timing: busbar;dur=<ms>` (formerly observability.emit_server_timing)
    route_policy: false             # `x-busbar-route-policy` / `x-busbar-route-target`
```

`worker_threads`, `upstream_http1_only`, and `upstream_h2_prior_knowledge` are **boot-time** knobs (read
once at process/client construction), so unlike `rate_sweep_interval` / `usage_flush_interval_ms` they are
not live-mutable via `PUT /config/settings`. A change takes effect on the next restart. The corresponding
env vars are honored for one release as a deprecated fallback.

`response_headers` is likewise **restart-to-apply**: `server_timing` is baked into router middleware
composition at boot and `route_policy` seeds a process-wide flag, so a live `PUT` stores the new value
durably (`reload_to_apply` flags `advanced.response_headers`) but only takes effect on the next
restart. Full catalogue, rationale for defaulting off, and exactly when each header fires:
[observability.md#response-headers](observability.md#response-headers).

### `providers_file`

Top-level pointer to the provider catalog (1.5.3 ← `BUSBAR_PROVIDERS`). Relative paths resolve against the
config.yaml directory; absent ⇒ `providers.yaml` next to config.yaml. The two-file model is unchanged. This
just names the catalog that config.yaml's `providers:` map references.

```yaml
providers_file: providers.yaml
```

---

## Migrating a 1.4.x config

The config format is an operator artifact outside the SemVer freeze; it changed shape in 1.5.0
WITH tooling:

1. `busbar --migrate-config old-config.yaml > config-1.5.yaml`: mechanically converts every
   deterministic change and prints `# TODO(migrate)` / `# WARNING(migrate)` comments where a human
   must decide. The loudest warning: every `allowed_pools: []` occurrence, whose meaning FLIPPED
   (it used to mean all pools, it now means NO pools).
2. Review the TODO/WARNING items, then `busbar --validate` the result.
3. Re-mint every virtual key (`POST /api/v1/admin/keys`): 1.4.x bearer secrets and static
   `client_tokens` no longer authenticate. 1.5.0 keys are signed tokens that expire (default 90
   days), the release's security headline.

Booting a 1.x config directly REFUSES with a named error pointing at the migrator; nothing from
1.x can boot-and-silently-flip semantics.
