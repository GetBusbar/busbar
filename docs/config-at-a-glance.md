# Config at a glance

One whole, realistic `config.yaml` (Busbar 1.5.3) on a single page. It is a **map, not a
reference**: every section header links to the exhaustive per-field docs in
[configuration.md](configuration.md), so you can see the shape of a complete deployment and click
straight through to the detail for any part. For the per-field tables with defaults and validation
rules use [configuration.md](configuration.md); for a bootable file use
[`examples/clean-config-1.5.0.yaml`](../examples/clean-config-1.5.0.yaml).

> A fully hyperlinked version of this page (where every key, value, module name and enum links to
> its own spec section) lives at **<https://getbusbar.com/docs/config-at-a-glance/>**. This file is
> the plain-markdown equivalent kept in the repo; the website page is the canonical rendering.

The whole surface follows a few rules, all locked by the 1.5.3 grammar freeze: **every
plugin-instance kind is a top-level NAMED-DEFINITION map (`name -> {module, settings, …}`) referenced
BY BARE NAME everywhere else**: `hooks:`, `identity-providers:`, `export:` (and singular `store:`);
built-ins (`keys`, `admin-tokens`, `cheapest`) are referenced bare. Beyond that: the object that OWNS
a concept is the only place it is defined; every secret is a reference (`{ env: VAR }` /
`{ file: /path }` / `{ module: <secret-plugin> }`); an omitted list means "all", an explicit `[]`
means "none"; a setting shared by every entity in a section is a RESERVED key at that section's level
(`pools.hooks`, `pools.upstream_credentials`), where LISTS combine ADDITIVELY and SCALARS OVERRIDE;
windows are nouns (`minute|hour|day|month|total`); unknown keys fail boot.

## Transport: [`listen` / `tls`](configuration.md#listen)

```yaml
listen: "0.0.0.0:8080"          # data-plane bind
admin_listen: "127.0.0.1:8081"  # admin-plane bind (always its own listener; loopback by default)
admin_require_mtls: true        # DEFAULT: an exposed admin_listen without admin_tls.client_ca
                                #   refuses to boot. `false` waives it (mTLS terminated upstream).
                                #   Replaces the retired, INVERTED `admin_insecure:` (1.5.3)

tls:                            # absent = plain HTTP. Each field is a SECRET REFERENCE.  → #tls
  cert: { file: /run/secrets/tls-cert.pem }
  key:  { file: /run/secrets/tls-key.pem }
  # client_ca: { file: /run/secrets/tls-ca.pem }   # present = mutual TLS required
# admin_tls: { cert: {...}, key: {...}, client_ca: {...} }   # same shape; client_ca = admin mTLS
```

## Plugins: [`plugins`](configuration.md#plugins)

One signed artifact format, trust model, and loader for all four plugin kinds (**store**,
**secret**, **auth**, and **hook**), every one loaded **in-process** over the hybrid ABI (see
[plugins.md](plugins.md)). For out-of-process isolation, the first-party `busbar-webrequest-hook`
plugin forwards to an HTTPS sidecar.

```yaml
plugins:
  enabled: false                # MASTER SWITCH (default false): nothing loads while off
  dir: plugins                  # where signed tarballs live
  trust:                        # Busbar's release key is embedded; untrusted plugins never dlopen
    publishers: [ { name: acme, public_key: "<64-hex ed25519>" } ]
    allow_unsigned: false
    allow_third_party: false
  # min_versions: { acme-store-dynamo: "2.0.0" }   # anti-downgrade floors
```

Referenced below wherever a section names a `module:` outside the built-in default: `auth.chain`
(an IdP), `store.module` (a durable backend), a `secret` reference, or a hook.

## Identity: [`auth`](configuration.md#auth)

```yaml
identity-providers:             # DEFINE each IdP ONCE; every chain references it BY BARE NAME
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }
  oidc:
    module: oidc                # a kind:auth plugin
    settings: { issuer: "https://login.example/" }
    # max_admin_scope:          # per-provider ADMIN ceiling: `read-only` | `full` ONLY.
    #                           # OMITTED = read-only (the most restrictive default)

auth:
  chain: [keys, oidc]           # ordered DATA-PLANE auth, as bare PROVIDER NAMES.
                                # `keys` = built-in signed-key verifier. [] = open (dev)
  admin_auth: [admin-tokens]    # chain gating /api/v1/admin/*
  signing_key: { file: /run/secrets/busbar-signing.key }     # REQUIRED with keys; no auto-gen
  #                                                          # (`busbar --generate-signing-key`)
  role_bindings:                # role → policy, NESTED BY PROVIDER NAME
    oidc:
      platform: { group: acme, admin_scope: full }   # admin_scope: read-only|full
```

`upstream_credentials` is NOT here: whose key hits the provider is a ROUTING property, so it lives at
`pools.upstream_credentials` (all-pools default) with a per-pool override.

Keys themselves are **minted over the admin API** (`POST /api/v1/admin/keys`), not configured. A
minted key is a signed, expiring token bound to at most one group. See
[Virtual keys and enforcement](configuration.md#virtual-keys-and-enforcement) and
[admin-api.md](admin-api.md).

## Limits: [`groups`](configuration.md#groups)

The ONE limit tree; keys carry no limits, every cap lives here. Admission walks the `parent` chain
and ANDs every limit (atomic, all-or-nothing); a rejection names the exact blocking bucket.

```yaml
groups:
  acme:                                    # an org/team/user are the same primitive (a user = a leaf)
    limits:
      - { requests: 500, per: minute }     # requests|tokens|budget need a `per:` window
      - { budget: 1000000, per: month }
      - { concurrent: 20 }                 # instantaneous in-flight cap: no `per:`, no `pool:`
  search-team:
    parent: acme                           # acyclic; leaf limits are sub-capped by every ancestor
    limits:
      - { budget: 5000, per: month, pool: frontier }   # optional `pool:` = per-(group, pool) budget
    child_default: { limits: [ { budget: 500, per: month } ] }   # template for auto-provisioned children
```

## Pricing: [`rate_card` + `per_request_fee`](configuration.md#rate_card-and-per_request_fee)

```yaml
rate_card:                      # the ONLY cost source: per-model token rates in abstract MICRO-units.
  claude-sonnet-4-5:            # ALL-OR-NOTHING: present = must cover every configured model.
    { input_utok: 3, output_utok: 15, cache_read_utok: 0, cache_write_utok: 4 }
per_request_fee: 0              # flat abstract charge added per request at admission
```

## Durability: [`store`](configuration.md#store)

```yaml
store:
  module: memory                # default: compiled-in, EPHEMERAL. sqlite|postgres|valkey = signed
  # module: postgres            #   plugin tarballs (need plugins.enabled + the tarball in plugins.dir)
  # settings: { url: "postgres://user:pass@host/busbar" }
```

## Hooks: [`hooks`](hooks.md)

Hooks are DEFINED once here and REFERENCED by bare name from the reserved `pools.hooks:` all-pools
list or a pool's own `hooks:` list. No inline instances anywhere (1.5.3 removed them, along with the
old top-level `global_hooks:` list). The SAME `module:` may back several named hooks.

```yaml
hooks:
  audit:                        # the NAME is the instance
    module: busbar-audit-hook   # which kind:hook plugin backs it
    kind: tap                   # gate (fire-and-wait, may decide) | tap (fire-and-forget)
    phase: [response]           # a LIST: request|candidate|routing|response. Omit = those four.
    on_error: nothing           #   (1.5.3 generalized the old single-valued tap `at:` into this)
  pii:
    module: busbar-phi
    groups: [engineering]       # SCOPE: which callers. Omit/[] = all. A user is a leaf group.
    kind: gate
    prompt: ro                  # no|ro|rw   (prompt-content grant)
    user: no                    # no|ro      (caller-identity grant)
    on_error: reject            # nothing|weighted|first|reject|{ hook: <name> }
```

## Routing surface: [`providers`](configuration.md#providers) · [`models`](configuration.md#models) · [`pools`](configuration.md#pools)

```yaml
providers:
  openai:
    api_key: { env: OPENAI_KEY }          # a SECRET REFERENCE (no *_env fields)  → #providers
    # protocol / base_url / error_map / auth / health … override the shipped catalog

models:                                    # a model is one LANE (a model at a provider)  → #models
  gpt-4o:        { provider: openai, max_concurrent: 20 }
  gpt-4o-mini:   { provider: openai }

pools:                                      # a pool is weighted lanes with shared reliability  → #pools
  hooks: [audit]                            # RESERVED all-pools attach (LIST → ADDITIVE, deduped)
  upstream_credentials: own                 # RESERVED all-pools default (SCALAR → OVERRIDE);
                                            #   own | passthrough, overridable per pool
  chat:
    members:                                # no cost fields: pricing lives on rate_card
      - { model: gpt-4o,      weight: 3, tier: primary }
      - { model: gpt-4o-mini, weight: 1, tier: overflow }
    hooks: [cheapest, pii]                  # one ordering strategy + gate NAMES defined above
                                            #   #pool-hooks-ordering-and-gates
    breaker:                                # per-(pool, lane) circuit breaking  → #breaker
      trip: { mode: error_rate, window_secs: 30, threshold: 0.5, min_requests: 5 }
    failover: { timeout_secs: 30, max_hops: 3 }   # per-request retry budget  → #failover
    on_exhausted: { fallback_pool: overflow }     # reject | least_bad | fallback_pool | { queue: { max_ms } }  → #on_exhausted
    affinity: { mode: session }                   # session pinning  → #affinity
```

## Operational: [`security`](configuration.md#security) · [`export`](configuration.md#export) · [`limits`](configuration.md#limits) · [`health`](configuration.md#health-probing)

```yaml
security:                       # SSRF metadata denylist tuning  → #security
  { allow_metadata_hosts: [], allow_all_metadata: false }
export:                         # THE telemetry-egress surface, a NAMED map, so SEVERAL instances
                                #   of one module are legal. 1.5.3 DELETED `observability:` and the
                                #   top-level `metrics:` block into it.  → #export
  metrics:  { module: prometheus,          settings: { buffer_seconds: 60 } }   # OPT-IN; at most one
  req-log:  { module: request-log-webhook, settings: { url: "https://logs.example.com/busbar" } }
  req-siem: { module: request-log-webhook, settings: { url: "https://siem.internal/ingest" } }
  traces:   { module: otlp,                settings: { url: "http://localhost:4318/v1/traces" } }
limits:                         # global operational caps  → #limits
  { upstream_request_timeout_secs: 300, request_body_max_bytes: 33554432, max_inbound_concurrent: 8192 }
health:                         # process-wide probe fallbacks  → #health-probing
  { default_probe_interval_secs: 30, default_probe_timeout_secs: 5 }
routing: { default_policy_timeout_ms: 1 }
advanced:                       # internal tuning (normally omitted)  → #advanced
  { rate_sweep_interval: 256, usage_flush_interval_ms: 100,
    worker_threads: 4, upstream_http1_only: false, upstream_h2_prior_knowledge: false,
    response_headers: { server_timing: false, route_policy: false } }  # opt-in headers → observability.md#response-headers
config:                         # config-management policy (durable-by-default)  → #config
  { locked: false, overlay: { file: busbar-overlay.json } }
providers_file: providers.yaml  # provider catalog pointer (overridden by the --providers flag)
```

## Not config, but adjacent

- **[Minting keys](admin-api.md)**: `POST /api/v1/admin/keys`. The signed token is shown once and
  expires (default 90 days). Requires `full` scope.
- **[Migrating from 1.4.x](migration-1.5.md)**: `busbar --migrate-config old.yaml` prints the
  converted config with TODO/WARNING comments; a 1.x config refuses to boot with a named error.
- **[Validation](configuration.md#startup-validation-summary)**: `busbar --validate` runs the exact
  boot pipeline (config + plugins) with zero side effects. A clean validate means a clean boot.
