# Config at a glance

One whole, realistic `config.yaml` (Busbar 1.5.0) on a single page. It is a **map, not a
reference**: every section header links to the exhaustive per-field docs in
[configuration.md](configuration.md), so you can see the shape of a complete deployment and click
straight through to the detail for any part. For the per-field tables with defaults and validation
rules use [configuration.md](configuration.md); for a bootable file use
[`examples/clean-config-1.5.0.yaml`](../examples/clean-config-1.5.0.yaml).

The whole surface follows a few rules: the object that OWNS a concept is the only place it is
defined; every loadable unit is `module` + `settings`; every secret is a reference
(`{ env: VAR }` / `{ file: /path }` / `{ module: <secret-plugin> }`); an omitted list means "all",
an explicit `[]` means "none"; windows are nouns (`minute|hour|day|month|total`); unknown keys fail
boot.

## Transport — [`listen` / `tls`](configuration.md#listen)

```yaml
listen: "0.0.0.0:8080"          # data-plane bind
admin_listen: "127.0.0.1:8081"  # admin-plane bind (always its own listener; loopback by default)
admin_insecure: false           # waive the "exposed admin requires mTLS" boot guard (opt-in)

tls:                            # absent = plain HTTP. Each field is a SECRET REFERENCE.  → #tls
  cert: { file: /run/secrets/tls-cert.pem }
  key:  { file: /run/secrets/tls-key.pem }
  # client_ca: { file: /run/secrets/tls-ca.pem }   # present = mutual TLS required
# admin_tls: { cert: {...}, key: {...}, client_ca: {...} }   # same shape; client_ca = admin mTLS
```

## Plugins — [`plugins`](configuration.md#plugins)

One signed artifact format, trust model, and loader for all four plugin kinds — **store**,
**secret**, **auth**, and **hook** — every one loaded **in-process** over the hybrid ABI (see
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

Referenced below wherever a section names a `module:` outside the built-in default — `auth.chain`
(an IdP), `store.module` (a durable backend), a `secret` reference, or a hook.

## Identity — [`auth`](configuration.md#auth)

```yaml
auth:
  chain: [keys]                 # ordered DATA-PLANE auth. `keys` = built-in signed-key verifier;
                                # any other name loads a kind:auth plugin (e.g. oidc). [] = open (dev)
  admin_auth:                   # chain gating /api/v1/admin/*
    - admin-tokens: { token: { env: BUSBAR_ADMIN_TOKEN } }   # the operator credential (secret ref)
  upstream_credentials: own     # own (default) | passthrough (forward the caller's key upstream)
  signing_key: { file: /run/secrets/busbar-signing.key }     # REQUIRED with keys; no auto-gen
  #                                                          # (`busbar --generate-signing-key`)
  role_bindings:                # role → policy, NESTED BY MODULE (for kind:auth / IdP modules)
    oidc:
      platform: { group: acme, admin_scope: full }   # admin_scope: read-only|hooks-register|mint|full
```

Keys themselves are **minted over the admin API** (`POST /api/v1/admin/keys`), not configured — a
minted key is a signed, expiring token bound to at most one group. See
[Virtual keys and enforcement](configuration.md#virtual-keys-and-enforcement) and
[admin-api.md](admin-api.md).

## Limits — [`groups`](configuration.md#groups)

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

## Pricing — [`rate_card` + `per_request_fee`](configuration.md#rate_card-and-per_request_fee)

```yaml
rate_card:                      # the ONLY cost source: per-model token rates in abstract MICRO-units.
  claude-sonnet-4-5:            # ALL-OR-NOTHING: present = must cover every configured model.
    { input_utok: 3, output_utok: 15, cache_read_utok: 0, cache_write_utok: 4 }
per_request_fee: 0              # flat abstract charge added per request at admission
```

## Durability — [`store`](configuration.md#store)

```yaml
store:
  module: memory                # default: compiled-in, EPHEMERAL. sqlite|postgres|redis = signed
  # module: postgres            #   plugin tarballs (need plugins.enabled + the tarball in plugins.dir)
  # settings: { url: "postgres://user:pass@host/busbar" }
```

## Routing surface — [`providers`](configuration.md#providers) · [`models`](configuration.md#models) · [`pools`](configuration.md#pools)

```yaml
providers:
  openai:
    api_key: { env: OPENAI_KEY }          # a SECRET REFERENCE (no *_env fields)  → #providers
    # protocol / base_url / error_map / auth / health … override the shipped catalog

models:                                    # a model is one LANE (a model at a provider)  → #models
  gpt-4o:        { provider: openai, max_concurrent: 20 }
  gpt-4o-mini:   { provider: openai }

pools:                                      # a pool is weighted lanes with shared reliability  → #pools
  chat:
    members:                                # no cost fields — pricing lives on rate_card
      - { model: gpt-4o,      weight: 3, tier: primary }
      - { model: gpt-4o-mini, weight: 1, tier: overflow }
    hooks:                                  # one ordering strategy + inline kind:hook gate refs
      - cheapest                            #   #pool-hooks-ordering-and-gates
      - { module: busbar-webrequest-hook, settings: { url: "https://sidecar/pii" }, kind: gate, prompt: ro }
    breaker:                                # per-(pool, lane) circuit breaking  → #breaker
      trip: { mode: error_rate, window_secs: 30, threshold: 0.5, min_requests: 5 }
    failover: { timeout_secs: 30, max_hops: 3 }   # per-request retry budget  → #failover
    on_exhausted: { fallback_pool: overflow }     # reject | least_bad | fallback_pool  → #on_exhausted
    affinity: { mode: session }                   # session pinning  → #affinity

global_hooks:                               # hook instances firing on EVERY request, ordered  → hooks.md
  - { module: busbar-headroom-hook, kind: gate, prompt: rw }
```

## Operational — [`security`](configuration.md#security) · [`observability`](configuration.md#observability) · [`limits`](configuration.md#limits) · [`health`](configuration.md#health-probing)

```yaml
security:                       # SSRF metadata denylist tuning  → #security
  { allow_metadata_hosts: [], allow_all_metadata: false }
observability:                  # opt-in sinks  → #observability
  { otlp_url: null, request_log_webhook_url: null, emit_server_timing: false }
limits:                         # global operational caps  → #limits
  { upstream_request_timeout_secs: 300, request_body_max_bytes: 33554432, max_inbound_concurrent: 8192 }
health:                         # process-wide probe fallbacks  → #health-probing
  { default_probe_interval_secs: 30, default_probe_timeout_secs: 5 }
metrics:                        # OPT-IN — omit the block and metrics are OFF  → #metrics
  { buffer_seconds: 60, key_gauge_limit: 2000 }   # buffer_seconds REQUIRED when the metrics block is present
routing: { default_policy_timeout_ms: 1 }
advanced:                       # internal tuning (normally omitted)
  { rate_sweep_interval: 256, usage_flush_interval_ms: 100 }
```

## Not config, but adjacent

- **[Minting keys](admin-api.md)**: `POST /api/v1/admin/keys` — the signed token is shown once and
  expires (default 90 days). Requires `mint` scope or `full`.
- **[Migrating from 1.4.x](migration-1.5.md)**: `busbar --migrate-config old.yaml` prints the
  converted config with TODO/WARNING comments; a 1.x config refuses to boot with a named error.
- **[Validation](configuration.md#startup-validation-summary)**: `busbar --validate` runs the exact
  boot pipeline (config + plugins) with zero side effects — a clean validate means a clean boot.
```
