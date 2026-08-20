# Migrating from 1.4.x to 1.5.0

1.5.0 is the config / identity / cost REDESIGN. The `config.yaml` changed shape, so this is a
**clean cut**: a 1.4.x config does not boot. Busbar detects the old structural markers and refuses
to start with a message naming what to write instead, and `busbar --migrate-config <old.yaml>`
mechanically rewrites the deterministic changes (printing the new YAML to stdout and a TODO/WARNING
summary to stderr. Review every one, especially each `allowed_pools: []`, whose meaning flipped
from *all pools* to *none*). Two changes are not just config: **every 1.4.x virtual key stops
working and must be re-minted** (keys are now signed tokens that expire), and a durable store is
dropped and recreated on first open (usage history resets). This guide covers every config change.

The recommended path: `busbar --migrate-config old.yaml > config-1.5.yaml`, review the TODO/WARNING
comments, `busbar --validate`, then re-mint keys. If Busbar boots, you're done. There are no silent
fallbacks.

---

## 1. Static token auth: `auth.client_tokens` / `BUSBAR_CLIENT_TOKEN` → signed minted keys

The static-token allowlist is **removed**. The `tokens` / `static-tokens` module and
`auth.client_tokens` no longer authenticate anyone. Data-plane auth is now the built-in `keys`
module (Busbar-signed, expiring virtual keys minted over the Admin API) plus any `kind: auth` IdP
plugins.

**Before (1.4.x):**

<!-- config-check: historical -->
```yaml
auth:
  chain: [tokens]
  client_tokens: [ "${BUSBAR_CLIENT_TOKEN}" ]
```

**After (1.5.3):** the operator credential is a NAMED identity-provider definition, referenced by
bare name. (1.5.0 wrote it inline in `admin_auth:`; 1.5.3 retired the inline form. See
[the 1.5.3 config grammar lock](#the-153-config-grammar-lock) below.)

```yaml
identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }

auth:
  chain: [keys]                                    # the built-in signed-key verifier
  admin_auth: [admin-tokens]                       # a bare PROVIDER NAME
```

Mint a key with `POST /api/v1/admin/keys` (the signed token is returned once) and roll the new
tokens out to callers; the old `BUSBAR_CLIENT_TOKEN` secrets are dead. The operator credential that
guards the Admin API is the built-in `admin-tokens` module, whose `token` is a secret reference
(`BUSBAR_ADMIN_TOKEN` by convention). See [admin-api.md](admin-api.md) for minting.

---

## 2. Hooks: the top-level `hooks:` registry + built-in `socket`/`webhook` transports → `kind: hook` plugins

The 1.4.x `hooks:` REGISTRY block is **gone**, and the built-in `socket`/`webhook` hook transports
are retired. A hook is now a signed `kind: hook` plugin and requires `plugins.enabled: true`. For the
HTTP-sidecar case (out-of-process forwarding), use the first-party `busbar-webrequest-hook` plugin.

**Before (1.4.x):** a registry entry carrying a built-in transport.

<!-- config-check: historical -->
```yaml
hooks:
  pii-guard:
    kind: gate
    webhook: https://sidecar.internal/pii
    prompt: ro
pools:
  smart:
    hooks: [pii-guard]
```

**After (1.5.3):** the top-level `hooks:` key is back, but as a **named-DEFINITION map** whose
entries name a `module:` (never a `socket:`/`webhook:` transport) and are referenced by bare name.
(1.5.0 briefly used an INLINE plugin ref in the pool list instead; 1.5.3 retired inline instances, so
write the definition map. Busbar tells the two top-level `hooks:` shapes apart by shape, not by
presence: a legacy registry entry still loud-fails at boot.)

```yaml
plugins: { enabled: true, dir: /etc/busbar/plugins }

hooks:
  pii-guard:
    module: webrequest
    settings: { url: "https://sidecar.internal/pii" }
    kind: gate
    prompt: ro

pools:
  smart:
    hooks: [pii-guard]                             # a bare NAME, exactly as in 1.4.x
```

The `global:` / `default:` flags on a hook are gone. The two bare-name lists (the reserved all-pools
`pools.hooks:` and a pool's own `hooks:`) subsume them. See [hooks.md](hooks.md) and
[plugins.md](plugins.md).

---

## 3. Governance: the `governance:` block → `groups:`, `rate_card`, `per_request_fee`, `store`

The `governance:` block dissolved; its contents moved to owning top-level keys:

| 1.4.x | 1.5.0 |
|---|---|
| `governance.budget_groups` | `groups:` (the generic limit tree, described below) |
| `governance.rate_card` | top-level `rate_card:` |
| `governance.price_per_request_cents` | top-level `per_request_fee:` |
| `governance.price_per_1k_tokens_cents` / member `cost_per_mtok` | `rate_card:` is the only cost source (`--migrate-config` synthesizes card entries) |
| `governance.store` / `governance.db_path` | `store: { module, settings }` |
| `governance.admin_token` | the `admin-tokens` module's `token` secret reference |
| `governance.rate_sweep_interval` / `usage_flush_interval_ms` | `advanced:` |
| `governance.enabled` / `governance.budget_on_store_error` | removed (governance is always-on; admission never touches the store) |

Governance has no on/off switch in 1.5.0: it is inert until keys exist. Spend is derived from a
token ledger × the `rate_card` at read time; nothing dollar-shaped is stored.

### 1.5.2: the admin token no longer gates the data plane

Data-plane admission is now decided **solely** by the shape of `auth.chain` (see
[configuration.md](configuration.md#authauth) → "Three orthogonal axes"). The operator admin token
(`auth.admin_auth`) gates only `/api/v1/admin/*`. Two behavior changes fall out:

- **`chain: []` + an admin token** now means **open (anonymous) relay + protected admin API**, the
  previously-inexpressible "admin-managed box, anonymous inference" posture. Before 1.5.2, setting an
  admin token silently forced a virtual key onto **every** data-plane request, overriding the empty
  chain. Deployments that set an admin token but named **no** data-plane chain change from
  "vkey-required" to "open relay". Add `keys` to `auth.chain` if you intended the data plane to
  require a virtual key.
- **`chain: [keys]` with no usable admin mint path is now a boot error** (previously it booted as a
  silent open relay that admitted anonymously). Provide a mint path: an `admin_auth` `admin-tokens`
  entry with a `token:`, an admin module granting `mint`/`full`, or (dev only) an explicit open
  `admin_auth: []`.

The idle-RAM property is preserved: with no `keys` in the chain and no minted keys, the store stays
idle. A durable store that still holds keys while `auth.chain` does not name `keys` now logs the
inert-keys advisory (recomputed from the chain shape, not the admin token).

---

## 4. Per-key limits → the `groups:` limit tree

The per-key cap fields are **removed** from mint, `PATCH`, the store schema, and key metadata:
`rpm_limit`, `tpm_limit`, `max_budget_cents`, `budget_period`. A **key is pure auth**; every limit
lives on the `group` the key is bound to.

```yaml
# 1.5.0: limits live on a group, keys bind to it
groups:
  search-team:
    limits:
      - { requests: 300, per: minute }
      - { tokens: 500000, per: minute }
      - { budget: 20000, per: month }
```

A group is `{ parent?, enabled, limits: [...], child_default? }`, forming an acyclic chain;
admission walks the chain up through `parent` and ANDs every limit. A budget derives at check time
from the token ledger × the current `rate_card` + the flat `per_request_fee`. Mint a key with
`group: search-team` to enforce these. See
[Configuration → `groups`](configuration.md#groups).

---

## 5. Store: durable backends are signed plugins; `memory` is the default

The default store is now `memory`, the compiled-in **ephemeral** RAM store (keys, usage, audit
reset on restart). Every durable backend (`sqlite` / `postgres` / `valkey`) is a signed plugin
tarball loaded through `plugins`, so it requires `plugins.enabled: true` and the tarball in
`plugins.dir`.

```yaml
# 1.5.0
plugins: { enabled: true, dir: /etc/busbar/plugins }
store:
  module: postgres                                 # or sqlite / valkey, or memory (default)
  settings: { url: "postgres://user:pass@host/busbar" }
```

> **Renamed in 1.5.3 (the only place these words still appear):** the first-party Redis-protocol store plugin is now **Valkey**. `store.module: redis` → `valkey`, artifact `busbar-store-redis-*.tar.gz` → `busbar-store-valkey-<ver>-<target>.tar.gz`, manifest name `busbar-store-redis` → `busbar-store-valkey-plugin`. `busbar --migrate-config` rewrites the module for you and boot loud-fails on the old spelling; install the renamed tarball, and leave your `settings.url` alone (`redis://` / `rediss://` is the driver's URL scheme, not a Busbar name). Any `plugins.min_versions` / pinned version floor keyed by the OLD name no longer applies. Re-pin it under the new name if you rely on it.

See [Configuration → `store`](configuration.md#store) and [plugins.md](plugins.md).

---

## 6. TLS: `cert_file` / `key_file` / `client_ca_file` → secret references

The plaintext path keys are gone. Each TLS field (`cert`, `key`, `client_ca`) is now a **secret
reference**, taking `{ file: /path }`, `{ env: VAR }`, or `{ module: <secret-plugin>, settings:
{...} }`. The same shape applies to `admin_tls`.

**Before (1.4.x):**

```yaml
tls:
  cert_file: /etc/busbar/tls/fullchain.pem
  key_file:  /etc/busbar/tls/privkey.pem
  client_ca_file: /etc/busbar/tls/ca.pem
```

**After (1.5.0, unchanged in 1.5.3):**

```yaml
tls:
  cert: { file: /etc/busbar/tls/fullchain.pem }
  key:  { file: /etc/busbar/tls/privkey.pem }
  client_ca: { file: /etc/busbar/tls/ca.pem }
```

See [Configuration → `tls`](configuration.md#tls) and [operations.md](operations.md#inbound-tls--mutual-tls-mtls).

---

## 7. Provider credentials: `api_key_env:` → `api_key: { env: VAR }`

Every secret in config is now a reference; there are no `*_env` suffix fields. A provider's
credential moves from `api_key_env` to a secret reference under `api_key`.

**Before (1.4.x):**

<!-- config-check: historical -->
```yaml
providers:
  openai:
    api_key_env: OPENAI_KEY
```

**After (1.5.0, unchanged in 1.5.3):**

```yaml
providers:
  openai:
    api_key: { env: OPENAI_KEY }                   # or { file: /path } / { module: <secret-plugin> }
```

The same conversion applies to `auth.signing_key` and the admin token. See
[Configuration → `providers`](configuration.md#providers).

---

## 8. Retired config aliases

Along with the above, these one-name-each renames are enforced (unknown keys fail boot):

| 1.4.x alias | 1.5.0 canonical |
|---|---|
| `auth.mode` | `auth.chain` / `pools.upstream_credentials` (1.5.3) |
| member `target` | member `model` |
| `window_s` | `window_secs` |
| `n` (breaker) | `consecutive_n` |
| `deadline_secs` | `timeout_secs` |
| `cap` (failover) | `max_hops` |
| `otlp_endpoint` | an `export:` instance with `module: otlp` (1.5.3) |

---

## Quick checklist

- [ ] `busbar --migrate-config old.yaml > config-1.5.yaml`; review every TODO/WARNING (esp. each `allowed_pools: []`, whose meaning flipped to *none*)
- [ ] `auth.client_tokens` / `BUSBAR_CLIENT_TOKEN` → `auth.chain: [keys]` + `admin_auth: [admin-tokens]` (`BUSBAR_ADMIN_TOKEN`)
- [ ] 1.4.x `hooks:` REGISTRY + `socket`/`webhook` transports → a 1.5.3 `hooks:` DEFINITION map of `kind: hook` plugins (`busbar-webrequest-hook` for the HTTP sidecar), referenced by bare name
- [ ] `governance:` → `groups:` + `rate_card:` + `per_request_fee:` + `store:`
- [ ] per-key `rpm_limit`/`tpm_limit`/`max_budget_cents`/`budget_period` → group `limits:`
- [ ] durable store → `store: { module: sqlite|postgres|valkey }` + `plugins.enabled: true` (default is ephemeral `memory`)
- [ ] tls `cert_file`/`key_file`/`client_ca_file` → `cert`/`key`/`client_ca` secret references
- [ ] provider `api_key_env:` → `api_key: { env: VAR }`
- [ ] `busbar --validate`, then **re-mint every virtual key** (1.4.x keys no longer authenticate)

If Busbar starts and `--validate` passes, the migration is complete. There are no silent fallbacks,
so a clean boot means a fully migrated config.

---

## Migrating from 1.5.0 to 1.5.1

1.5.1 is a small, targeted breaking change on top of 1.5.0: **busbar no longer auto-generates a
signing key at boot.**

### What changed, and why

In 1.5.0, if `auth.signing_key` was absent, busbar generated an ed25519 secret on first boot and
wrote it to `busbar-signing.key` (mode `0600`) beside the config file. That write-on-first-boot
behavior boot-loops any deployment where the config directory is a read-only mount (the common case
for config delivered via a container image, a ConfigMap, or a read-only bind mount): busbar fails
the write, exits, and, because nothing was persisted, tries to generate and write the key again on
the very next boot, forever, with a Permission-denied error that doesn't obviously point at the
signing key as the cause.

1.5.1 removes the auto-generation entirely. `auth.signing_key` is now a plain secret **reference**
like any other (`{ env: VAR }` / `{ file: /path }`). Busbar only ever resolves it, never creates it.

### Do you need to do anything?

Only if your deployment verifies busbar-signed keys, i.e. `auth.chain` names the built-in `keys`
module. If it does, and `auth.signing_key` was relying on the old auto-generated
`busbar-signing.key`, you must now generate and provide the key explicitly. `config_validate` fails
closed at `--validate`/boot with an actionable error if `keys` is in the chain and
`auth.signing_key` is unset.

If `auth.chain` never names `keys` (no signed-token verification), nothing changes for you.

### Migration steps

1. Generate a key. `--generate-signing-key` has zero side effects: it mints a fresh ed25519 secret
   from the OS RNG and prints it; it does not write any file or touch your config.

   ```sh
   busbar --generate-signing-key > /run/secrets/busbar-signing.key
   ```

   (The 64-hex-char secret goes to stdout only, so it's safe to redirect straight to a file; guidance
   goes to stderr and never contains the secret.)

2. Point `auth.signing_key` at it:

   Before (1.5.0, implicit; no `auth.signing_key` set, so busbar generated one on first boot):

   ```yaml
   auth:
     chain: [keys]
   ```

   After (1.5.1 and later, explicit):

   ```yaml
   auth:
     chain: [keys]
     signing_key: { file: /run/secrets/busbar-signing.key }   # or { env: BUSBAR_SIGNING_KEY }
   ```

3. If you already have an existing `busbar-signing.key` file that busbar auto-generated under
   1.5.0, you can keep using it. Copy or mount its bytes to wherever you now point
   `auth.signing_key`, so upgrading doesn't invalidate outstanding minted keys. There's nothing
   special about a freshly-generated key versus the old auto-generated one; both are just 32
   raw bytes (or 64 hex chars) of ed25519 secret material.

### Fleet note

`auth.signing_key` is a **shared secret**: every node that verifies busbar-signed keys must resolve
the exact same bytes, or nodes will reject each other's tokens. Generate the key **once**, then
distribute that same value to every node in the fleet (a shared secrets file, the same env var
sourced from a central vault, etc.). Do not run `busbar --generate-signing-key` separately on each
node. Rotating the key revokes every outstanding key fleet-wide, since every node stops being able to
verify tokens signed with the old secret.

### Quick checklist

- [ ] Does `auth.chain` name `keys`? If not, no action needed.
- [ ] `busbar --generate-signing-key > /path/to/secret` (or capture the stdout value into your
      secret manager / env var)
- [ ] Set `auth.signing_key: { file: /path/to/secret }` or `{ env: VAR }`
- [ ] Distribute the same secret value to every node in the fleet
- [ ] `busbar --validate`

---

## Migrating from 1.5.2 to 1.5.3

1.5.3 is the **break-once config-stability release**. Two independent changes ship in it: a
**grammar lock** (breaking, mechanical, migrated for you) and a **config consolidation** (soft,
env-var deprecations). After 1.5.3 the config grammar is frozen and additive-only forever, enforced
by a CI gate.

### The 1.5.3 config grammar lock

One pattern replaces several ad-hoc ones: **every plugin-instance kind is a top-level NAMED
DEFINITION map (`name → {module, settings, …}`) and is REFERENCED BY BARE NAME everywhere else.**
Define once, reference many; the name is the instance, `module:` is which plugin backs it. Built-ins
(`keys`, `admin-tokens`, `cheapest`) are referenced bare and need a definition entry only when they
carry config.

Every change below is detected at boot: an un-migrated config **refuses to start**, naming the
retired key AND its new home. `busbar --migrate-config <config.yaml>` rewrites all of them.

| Retired in 1.5.2 and earlier | 1.5.3 |
|---|---|
| top-level `global_hooks:` (a list of inline hook instances) | the top-level `hooks:` DEFINITION map + the reserved all-pools `pools.hooks: [names]` attach list |
| an inline hook instance in any `hooks:` list | a `hooks:` definition entry, referenced by bare name |
| an inline identity provider under `auth.chain:` / `auth.admin_auth:` | an `identity-providers:` definition entry, referenced by bare name |
| `auth.methods:` | the matching `identity-providers:` definition (`settings:` + `browser_login:` are per-provider) |
| `auth.modules:` | the top-level `identity-providers:` map |
| `auth.upstream_credentials:` | `pools.upstream_credentials:` (the all-pools default) + a per-pool override |
| the whole `observability:` block, incl. `otlp_url` / `otlp_endpoint` | an `export:` instance with `module: otlp` and `settings.url` |
| `observability.request_log_webhook_url` (and its `max_inflight_*` / `*_timeout_secs` siblings) | an `export:` instance with `module: request-log-webhook` and `settings.url` |
| `observability.emit_server_timing` | `advanced.response_headers.server_timing` |
| the top-level `metrics:` block | an `export:` instance with `module: prometheus` and `settings.buffer_seconds` |
| `admin_insecure: true` | `admin_require_mtls: false`. **INVERTED**, so the safe posture is what an omitted key gives you |
| a tap's single-valued `at: route` / `attempt` / `completion` | a hook's `phase:` **LIST**: `candidate` / `routing` / `response` (plus `request`) |

**Before (1.5.2):**

<!-- config-check: historical -->
```yaml
admin_insecure: true

global_hooks:
  - { module: busbar-audit-hook, kind: tap, at: completion }

auth:
  chain: [keys]
  upstream_credentials: own
  admin_auth:
    - admin-tokens: { token: { env: BUSBAR_ADMIN_TOKEN } }
  methods:
    oidc: { issuer: "https://idp.example.com/", audience: "busbar" }

observability:
  otlp_url: "http://localhost:4318/v1/traces"
  request_log_webhook_url: "https://logs.example.com/busbar"

metrics:
  buffer_seconds: 60

pools:
  smart:
    hooks:
      - { module: busbar-pii-hook, kind: gate, prompt: ro, on_error: reject }
    members: [ { model: claude-sonnet-4-5 } ]
```

**After (1.5.3):**

```yaml
admin_require_mtls: false          # INVERTED; omit it entirely to keep the safe default

identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }
  oidc:
    module: oidc
    settings: { issuer: "https://idp.example.com/", audience: "busbar" }
    #                              # per-provider admin ceiling, on the DEFINITION:
    #                              # OMIT max_admin_scope for the most restrictive default
    #                              # (read-only). The only accepted values are `read-only`
    #                              # and `full`.

hooks:                             # define once…
  audit: { module: busbar-audit-hook, kind: tap, phase: [response] }
  pii:   { module: busbar-pii-hook,  kind: gate, prompt: ro, on_error: reject }

export:                            # …a NAMED map: several instances of one module are fine
  metrics: { module: prometheus,          settings: { buffer_seconds: 60 } }
  traces:  { module: otlp,                settings: { url: "http://localhost:4318/v1/traces" } }
  req-log: { module: request-log-webhook, settings: { url: "https://logs.example.com/busbar" } }

auth:
  chain: [keys, oidc]              # bare provider NAMES
  admin_auth: [admin-tokens]

pools:
  hooks: [audit]                   # reserved all-pools attach (LIST → additive)
  upstream_credentials: own        # reserved all-pools default (SCALAR → override)
  smart:
    hooks: [pii]                   # …reference many, by bare name
    members: [ { model: claude-sonnet-4-5 } ]
```

**The two combine rules**, which govern every inherited setting: **LISTS are ADDITIVE**. A pool
fires `pools.hooks` ∪ its own `hooks:`, deduped by name, so a hook named in both fires exactly ONCE
at its first position. **SCALARS OVERRIDE**. A pool's own `upstream_credentials:` replaces the
all-pools default outright. `hooks` and `upstream_credentials` are therefore RESERVED names at the
`pools:` level: a pool may not be called either.

**One deliberate exemption:** `secrets:` stays keyed BY MODULE, not by instance name. It configures a
secret plugin's `open()`: the delivery path (address, namespace, CA) that is a property of the
module itself, not an instance of one. It is the one block that is not a named-definition map, on
purpose.

**Terminology:** "auth module" is now "identity provider" throughout config and docs.

#### Quick checklist

- [ ] `busbar --migrate-config config.yaml > config-1.5.3.yaml`, then `busbar --validate`
- [ ] `global_hooks:` + every inline hook instance → a top-level `hooks:` definition map + bare-name `pools.hooks:` / `pools.<p>.hooks:` lists
- [ ] every inline `auth.chain` / `auth.admin_auth` entry and every `auth.methods:` / `auth.modules:` entry → an `identity-providers:` definition, referenced by bare name (`max_admin_scope:` belongs on the definition; its only accepted values are `read-only` and `full`. For an external IdP, OMIT it and get the most restrictive default, `read-only`)
- [ ] `observability:` + top-level `metrics:` → `export:` instances (`prometheus` / `otlp` / `request-log-webhook` / `request-log-file`)
- [ ] `observability.emit_server_timing` → `advanced.response_headers.server_timing`
- [ ] `admin_insecure: true` → `admin_require_mtls: false` (or drop it and keep the safe default)
- [ ] `auth.upstream_credentials:` → `pools.upstream_credentials:` (+ per-pool overrides)
- [ ] tap `at: route|attempt|completion` → hook `phase: [candidate|routing|response]`
- [ ] check no pool is named `hooks` or `upstream_credentials`

### 1.5.3 config consolidation

1.5.3 also moves operational config out of environment variables and **into `config.yaml`**, and makes admin-API
config mutability explicit and **durable by default**. Every migrated env var still works for **one release**
(each logs a deprecation warning). This is a soft migration, not a clean cut. Move each into config.yaml at
your convenience before the next release removes the env var.

#### Env var → config.yaml

| Deprecated env var | New home in config.yaml |
|---|---|
| `BUSBAR_PROVIDERS` | `providers_file:` (top-level; relative to config.yaml; default `providers.yaml` next to it), or the `--providers <path>` flag. **Removed in 1.6.0** — the env var no longer works. |
| `BUSBAR_CONFIG_OVERLAY` | `config.overlay.file` |
| `BUSBAR_WORKER_THREADS` | `advanced.worker_threads` |
| `BUSBAR_UPSTREAM_HTTP1_ONLY` | `advanced.upstream_http1_only` |
| `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` | `advanced.upstream_h2_prior_knowledge` |

`BUSBAR_CONFIG` (which locates config.yaml), secret `{ env: NAME }` references, `RUST_LOG`, and
`TOKIO_WORKER_THREADS` (a standard tokio fallback) are unchanged.

```yaml
# before: env
#   BUSBAR_PROVIDERS=/etc/busbar/providers.yaml
#   BUSBAR_CONFIG_OVERLAY=/var/lib/busbar/overlay.json
#   BUSBAR_WORKER_THREADS=4

# after: config.yaml
providers_file: /etc/busbar/providers.yaml
config:
  locked: false
  overlay:
    file: /var/lib/busbar/overlay.json
advanced:
  worker_threads: 4
```

#### Behavior change: durable-by-default config mutation

Before 1.5.3, admin-API config changes were **live-only unless** you set `BUSBAR_CONFIG_OVERLAY`, so a group
or hook provisioned over the API **silently vanished on restart**. Now, with nothing configured, config is
*mutable* and mutations persist to `busbar-overlay.json` next to config.yaml. **No action needed** for the
common (writable config directory) case: your admin-API changes simply become durable.

Two new postures:

- **`config.locked: true`**: an immutable/GitOps deployment. Admin-API config mutations are refused at
  runtime (edit config.yaml + `POST /config/reload` to change config). Set this if you never want runtime
  mutation.
- **Boot invariant**: no snapshot ever carries an overlay backend it cannot durably write. A
  *mutable* config whose `overlay:` is explicitly disabled **refuses to boot**; one whose backend
  path is merely not writable (a read-only mount) **boots with no overlay** and refuses config
  mutations instead.

#### Upgrade action for read-only-config deployments

If your `config.yaml` lives on a **read-only mount** (e.g. `/etc/busbar` mounted read-only, or a read-only
container layer), the default overlay path is not writable. Busbar **still starts and serves traffic**;
it logs a warning and refuses admin-API config mutations, because a change it cannot persist would
silently revert on the next restart. No action is required if that is the posture you want. To change
it, choose one:

1. **Point the overlay at a writable path** (a persistent volume) so runtime mutations are durable:
   ```yaml
   config:
     overlay:
       file: /var/lib/busbar/busbar-overlay.json   # a writable, persistent location
   ```
2. **Declare the deployment immutable**, the natural choice for a GitOps/read-only rollout that never
   mutates config at runtime anyway:
   ```yaml
   config:
     locked: true
   ```

Either resolves the boot refusal. Busbar never silently falls back to the old lose-on-restart behavior.

### 1.5.3 behavior change: `busbar --validate` resolves secret references

**What changed.** Through 1.5.2, `--validate` checked that a secret reference was well FORMED and
stopped there: a config saying `api_key: { env: ANTHROPIC_KEY }` with `ANTHROPIC_KEY` unset printed
`ok: config valid` and exited `0`. From 1.5.3 it RESOLVES every built-in `env:` and `file:`
reference and exits `1` naming the first one that fails.

**Why.** Exit `0` meant "this config is good", and it was being returned for a config that cannot
serve a single request. Every provider lane in it fails upstream on a missing credential. A gate
whose green result does not distinguish a working deployment from a broken one is not a gate.

**Scope.** Only `--validate` changed.

- BOOT is unchanged. An unresolvable reference still logs a warning and Busbar still serves, so no
  running deployment starts failing on upgrade and no restart turns into an outage.
- The admin apply/reload path is unchanged, and still WARNS rather than rejecting. A live config
  change must not be refused for a secret that will resolve on the next deploy.
- References served by a secret PLUGIN are not resolved by `--validate`. Only the built-in `env:`
  and `file:` modules are.

**Upgrade action.** If a CI pipeline runs `busbar --validate` without production secrets present, it
will go red on the first upgraded run. Pick one:

1. **Give the job the references it needs.** This is the honest fix and it is usually cheap, because
   `--validate` only needs the values to EXIST, never for them to be correct. Dummy values are fine:

   ```sh
   # CI: satisfy the references the config names, without shipping real secrets to CI
   export ANTHROPIC_KEY=ci-placeholder
   export OPENAI_KEY=ci-placeholder
   busbar --validate
   ```

   For a `{ file: /path }` reference, write a stand-in at that path, or point the config at one.

2. **Validate a config whose references resolve in CI.** Keep the production config for the deploy
   step and validate a CI variant whose `env:` names are ones your runner sets. This is the right
   shape when the pipeline validates on a runner that legitimately has no access to production
   secret material.

3. **Real secrets in the job** if your CI already has them (an OIDC-federated secrets manager, for
   example). Nothing about `--validate` requires this, but it makes the gate cover the most.

Do NOT work around it by dropping `--validate` from the pipeline. The exit code is now telling you
something true that it used to hide.
