# Config at a glance

One whole, realistic `config.yaml` (Busbar 1.6.0) on a single page. It is a **map, not a
reference**: every section header links to the exhaustive per-field docs in
[configuration.md](configuration.md), so you can see the shape of a complete deployment and click
straight through to the detail for any part. For the per-field tables with defaults and validation
rules use [configuration.md](configuration.md); for a bootable file, start from the `config.yaml` shipped in the repository root.

> A fully hyperlinked version of this page (where every key, value, module name and enum links to
> its own spec section) lives at **<https://getbusbar.com/docs/config-at-a-glance/>**. This file is
> the plain-markdown equivalent kept in the repo; the website page is the canonical rendering.

The whole surface follows a few rules, all locked by the config grammar freeze: **every
plugin-instance kind is a top-level NAMED-DEFINITION map (`name -> {module, settings, …}`) referenced
BY BARE NAME everywhere else**: `hooks:`, `identity-providers:`, `export:` (and singular `store:`);
built-ins (`keys`, the operator-credential provider, `cheapest`) are referenced bare. Beyond that: the object that OWNS
a concept is the only place it is defined; every secret is a reference (`{ env: VAR }` /
`{ file: /path }` / `{ module: <secret-plugin> }`); an omitted list means "all", an explicit `[]`
means "none"; a setting shared by every entity in a section is a RESERVED key at that section's level
(`pools.hooks`, `pools.upstream_credentials`, and `tools.hooks`/`agents.hooks` on the MCP and A2A
planes, whose failover pools sit under their own section as `tools.pools`/`agents.pools`), where
LISTS combine ADDITIVELY and SCALARS OVERRIDE;
windows are nouns (`minute|hour|day|month|total`); unknown keys fail boot.

> The first key of a config is `config_version: 1`, written by the first 1.6.0 boot of a 1.5.5 config; do not
> edit it ([`config_version`](configuration.md#config_version)).

## Transport: [`listen` / `tls`](configuration.md#listen)

```yaml
listen: "0.0.0.0:8080"          # data-plane bind
admin_listen: "127.0.0.1:8081"  # admin-plane bind (always its own listener; loopback by default)
admin_require_mtls: true        # DEFAULT: an exposed admin_listen without admin_tls.client_ca
                                #   refuses to boot. `false` waives it (mTLS terminated upstream).

tls:                            # absent = plain HTTP. Each field is a SECRET REFERENCE.  → #tls
  cert: { file: /run/secrets/tls-cert.pem }
  key:  { file: /run/secrets/tls-key.pem }
  # client_ca: { file: /run/secrets/tls-ca.pem }   # present = mutual TLS required
# admin_tls: { cert: {...}, key: {...}, client_ca: {...} }   # same shape; client_ca = admin mTLS
```

## Plugins: [`plugins`](configuration.md#plugins)

One signed artifact format, trust model, and loader for all seven plugin kinds (**store**,
**secret**, **auth**, **hook**, **export**, **plane** and **transport**), every one loaded
**in-process** over the memory ABI (see [plugins.md](plugins.md)). A hook plugin may forward to an out-of-process sidecar; that is the plugin's own documentation.

```yaml
plugins:
  enabled: false                # MASTER SWITCH (default false): nothing loads while off
  dir: plugins                  # where signed tarballs live
  trust:                        # Busbar's release key is embedded; untrusted plugins never dlopen
    publishers:
      - { name: acme, plugins: [acme-store-dynamo], keys: [ { public_key: "<64-hex ed25519>", revoked: false } ] }
    allow_untrusted: false      # unsigned or unknown-publisher code: refused unless opted in, always unverified
  # min_versions: { acme-store-dynamo: "2.0.0" }   # anti-downgrade floors
```

Referenced below wherever a section names a `module:` outside the built-in default: `auth.chain`
(an IdP), `store.module` (a durable store plugin), a `secret` reference, or a hook.

## Identity: [`auth`](configuration.md#auth)

```yaml
identity-providers:             # DEFINE each IdP ONCE; every chain references it BY BARE NAME
  <operator-auth>: { module: <operator-auth-module>, token: { env: BUSBAR_ADMIN_TOKEN } }
  sso:
    module: <auth-plugin>       # a kind:auth plugin
    settings: { }               # the plugin's own settings
    # max_admin_scope:          # per-provider ADMIN ceiling: `read-only` | `full` ONLY.
    #                           # OMITTED = read-only (the most restrictive default)

auth:
  chain: [keys, sso]           # ordered DATA-PLANE auth, as bare PROVIDER NAMES.
                                # `keys` = built-in signed-key verifier. [] = open (dev)
  admin_auth: [<operator-auth>]  # chain gating /api/v1/admin/*
  signing_key: { file: /run/secrets/busbar-signing.key }     # REQUIRED with keys; no auto-gen
  #                                                          # (`busbar --generate-signing-key`)
  # require_if_match: false     # true = guarded config mutations without If-Match are refused 428
  role_bindings:                # role → policy, NESTED BY PROVIDER NAME
    sso:
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
      - { budget: 5000, per: month, pool: chat }       # optional `pool:` = per-(group, pool) budget
    child_default: { limits: [ { budget: 500, per: month } ] }   # template for auto-provisioned children
```

## Pricing: [`rate_card` + `per_request_fee`](configuration.md#rate_card-and-per_request_fee)

```yaml
rate_card:                      # the ONLY cost source: per-model token rates in abstract MICRO-units.
  gpt-4o-mini: { input_utok: 0.15, output_utok: 0.6 }
  gpt-4o:                       # ALL-OR-NOTHING: present = must cover every configured model AND
    { input_utok: 2.5, output_utok: 10, cache_read_utok: 1.25, cache_write_utok: 2.5,
      units: { search_units: 0, classifications: 0, web_fetch_requests: 0, unitemized_tokens: 0,
               images: 0, audio_ms: 0, guardrail_automated_reasoning_policies: 0,
               guardrail_automated_reasoning_policy_units: 0, guardrail_content_policy_image_units: 0,
               guardrail_content_policy_units: 0, guardrail_contextual_grounding_policy_units: 0,
               guardrail_sensitive_information_policy_free_units: 0,
               guardrail_sensitive_information_policy_units: 0, guardrail_topic_policy_units: 0,
               guardrail_word_policy_units: 0 } }   # every billable class the plane declares (0 = free, still counts)
per_request_fee: 0              # flat abstract charge added per request at admission
```

`units: { <class>: <rate> }` prices an OPEN class alongside the four reserved `*_utok` tiers — same
MICRO-units scale, integer or an exact decimal STRING only (a bare float is refused). A present
card silent about a class the plane declares fails BOOT naming the section and every missing class;
silent about a class/lane it actually serves REFUSES that hit at run time instead of billing `0`
(surfaced on `/usage` reads as `409 unpriced_class`). Non-LLM planes take the SAME reserved
`rate_card` key under their own section — `tools.rate_card` (keyed by tool name, prices
`tool_calls`/`bytes`), `agents.rate_card` (keyed `agent:<id>`, prices `bytes` = request + response
body bytes per hop), `streams.rate_card`, `decisions.rate_card` — each independent of this flat card
and of each other; absent = that plane's traffic bills `0`, no refusal.

## Durability: [`store`](configuration.md#store)

```yaml
store:                          # REQUIRED (no default; BUSBAR-3120 when absent)
  module: memory                # compiled-in, EPHEMERAL
  # module: <store-plugin>      # a durable store = a signed kind:store plugin tarball
  # settings: { }               #   (needs plugins.enabled + the tarball in plugins.dir); the plugin's own settings
```

## Hooks: [`hooks`](hooks.md)

Hooks are DEFINED once here and REFERENCED by bare name from the reserved `pools.hooks:` all-pools
list or a pool's own `hooks:` list. No inline instances anywhere (there is no top-level
`global_hooks:` list). The SAME `module:` may back several named hooks.

```yaml
hooks:
  audit:                        # the NAME is the instance
    module: <hook-plugin>      # which kind:hook plugin backs it
    kind: tap                   # gate (fire-and-wait, may decide) | tap (fire-and-forget)
    phase: [response]           # a LIST: request|candidate|routing|response. Omit = those four.
    on_error: nothing
  pii:
    module: <hook-plugin>
    groups: [engineering]       # SCOPE: which callers. Omit/[] = all. A user is a leaf group.
    kind: gate
    prompt: ro                  # no|ro|rw   (prompt-content grant)
    user: no                    # no|ro      (caller-identity grant)
    on_error: reject            # nothing|weighted|first|reject|{ hook: <name> }
```

## Plane sections: `tools` · `agents` · `streams` · `decisions` · `mcp` · `oauth_as`

Each non-LLM plane owns its own top-level section, parsed and documented by that plane (see
[MCP](mcp.md), [A2A](a2a.md) and [voice.md](voice.md)). Core
reserves only `hooks`, `upstream_credentials`, `usage_observations`, `pools`, `rate_card` and `fees` inside
them ([Reserved names](configuration.md#reserved-names)). `oauth_as:` is an opaque section owned by the OAuth
authorization-server plane. Neither is detailed here.

## Routing surface: [`providers`](configuration.md#providers) · [`models`](configuration.md#models) · [`pools`](configuration.md#pools)

```yaml
providers:
  openai:
    api_key: { env: OPENAI_KEY }          # a SECRET REFERENCE (no *_env fields)  → #providers
    # … { file: /path } · { module: <secret-plugin> } · or `none` for a keyless local upstream.
    # A reference that does not resolve REFUSES BOOT — it never degrades to an empty credential.
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
    on_exhausted: least_bad                       # reject | least_bad | { fallback_pool: <pool> } | { queue: { max_ms } }  → #on_exhausted
    affinity: { mode: session }                   # session pinning  → #affinity
```

## Operational: [`security`](configuration.md#security) · [`export`](configuration.md#export) · [`limits`](configuration.md#limits) · [`health`](configuration.md#health-probing)

```yaml
security:                       # SSRF metadata denylist tuning  → #security
  { blocked_metadata_hosts: [] }  # extends the denylist; nothing admits cloud metadata
export:                         # THE telemetry-egress surface, a NAMED map, so SEVERAL instances
                                #   of one module are legal. There is no `observability:` or
                                #   top-level `metrics:` block.  → #export
  <name>: { module: <export-plugin>, settings: { } }   # a kind:export plugin and its own settings
limits:                         # global operational caps  → #limits
  { upstream_request_timeout_secs: 300, request_body_max_bytes: 33554432, max_inbound_concurrent: 8192 }
health:                         # process-wide probe fallbacks  → #health-probing
  { default_probe_interval_secs: 30, default_probe_timeout_secs: 5 }
routing: { default_policy_timeout_ms: 1 }
advanced:                       # durability tuning (normally omitted)  → #advanced
  { usage_flush_interval_ms: 100 }
outbound:                       # how the engine dials out (restart to apply)  → #outbound
  { block_private_addresses: true, proxy_resolution: local,
    http1_only: false, h2_prior_knowledge: false, tls: { roots: bundled } }
client_address:                 # ingress addresses whose X-Forwarded-For is believed  → #client_address
  { trusted_proxies: [] }
shutdown:                       # deregistration interval before draining; default none  → #shutdown
  { deregister_delay: 10s }
config:                         # config-management policy (persistence follows Store) → #config
  { locked: false }
telemetry:                      # in-process metric registry → #telemetry
  { enabled: true, retention_seconds: 300, max_lane_series: 1024,
    response_headers: { server_timing: false } }   # opt-in headers → observability.md#response-headers
providers_file: providers.yaml  # provider catalog pointer (overridden by the --providers flag)
```

## Not config, but adjacent

- **[Minting keys](admin-api.md)**: `POST /api/v1/admin/keys`. The signed token is shown once and
  expires (default 90 days). Requires `full` scope.
- **Upgrading**: from 1.5.5, see [Upgrade from 1.5.5 to 1.6.0](migration-1.6.md); from anything
  older, [Upgrade to 1.5.5](upgrade-to-1.5.5.md) first.
- **Upgrading from 1.5.5**: a 1.5.5 `rate_card:` that priced only the four reserved token tiers now
  FAILS BOOT — every plane whose section carries a card must configure every billable class that
  plane declares. The 1.6.0 upgrade adds the missing units at `0` for you; by hand, add the `units:` map above (every LLM open class at `0`) to
  any one entry of the flat/`pools` card (declared classes per plane: `pools` = `input`, `output`,
  `cache_read`, `cache_write`, `search_units`, `classifications`, `web_fetch_requests`, `unitemized_tokens`, `images`, `audio_ms`, `guardrail_automated_reasoning_policies`, `guardrail_automated_reasoning_policy_units`, `guardrail_content_policy_image_units`, `guardrail_content_policy_units`, `guardrail_contextual_grounding_policy_units`, `guardrail_sensitive_information_policy_free_units`, `guardrail_sensitive_information_policy_units`, `guardrail_topic_policy_units`, `guardrail_word_policy_units` · `tools` = `tool_calls`, `bytes` · `agents` = `bytes` ·
  `decisions` = `decision`, `input_tokens`, `output_tokens` · `streams` = `audio_tokens_in`, `audio_tokens_out`, `text_tokens_in`,
  `text_tokens_out`, `audio_seconds_in`, `tool_calls`, `image_tokens_in`, `video_tokens_in`; `cached_tokens` is carried
  as attribution only, never billed). A plane section with no
  card of its own is unaffected.
- **[Validation](configuration.md#startup-validation-summary)**: `busbar --validate` runs the exact
  boot pipeline (config + plugins) without opening a Store or making network calls. It is an offline check of operator inputs and local artifacts: passing does not guarantee boot, plugin readiness or backend reachability.
