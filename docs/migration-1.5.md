# Migrating from 1.4.x to 1.5.0

1.5.0 is the config / identity / cost REDESIGN. The `config.yaml` changed shape, so this is a
**clean cut**: a 1.4.x config does not boot. Busbar detects the old structural markers and refuses
to start with a message naming what to write instead, and `busbar --migrate-config <old.yaml>`
mechanically rewrites the deterministic changes (printing the new YAML to stdout and a TODO/WARNING
summary to stderr — review every one, especially each `allowed_pools: []`, whose meaning flipped
from *all pools* to *none*). Two changes are not just config: **every 1.4.x virtual key stops
working and must be re-minted** (keys are now signed tokens that expire), and a durable store is
dropped and recreated on first open (usage history resets). This guide covers every config change.

The recommended path: `busbar --migrate-config old.yaml > config-1.5.yaml`, review the TODO/WARNING
comments, `busbar --validate`, then re-mint keys. If Busbar boots, you're done — there are no silent
fallbacks.

---

## 1. Static token auth: `auth.client_tokens` / `BUSBAR_CLIENT_TOKEN` → signed minted keys

The static-token allowlist is **removed**. The `tokens` / `static-tokens` module and
`auth.client_tokens` no longer authenticate anyone. Data-plane auth is now the built-in `keys`
module (Busbar-signed, expiring virtual keys minted over the Admin API) plus any `kind: auth` IdP
plugins.

```yaml
# 1.4.x
auth:
  chain: [tokens]
  client_tokens: [ "${BUSBAR_CLIENT_TOKEN}" ]

# 1.5.0
auth:
  chain: [keys]                                    # the built-in signed-key verifier
  admin_auth:
    - admin-tokens: { token: { env: BUSBAR_ADMIN_TOKEN } }   # operator credential for the Admin API
```

Mint a key with `POST /api/v1/admin/keys` (the signed token is returned once) and roll the new
tokens out to callers; the old `BUSBAR_CLIENT_TOKEN` secrets are dead. The operator credential that
guards the Admin API is the built-in `admin-tokens` module, whose `token` is a secret reference
(`BUSBAR_ADMIN_TOKEN` by convention). See [admin-api.md](admin-api.md) for minting.

---

## 2. Hooks: the top-level `hooks:` registry + built-in `socket`/`webhook` transports → `kind: hook` plugins

The top-level `hooks:` registry block is **gone**, and the built-in `socket`/`webhook` hook
transports are retired. A hook is now a signed `kind: hook` plugin, referenced **inline** where it
runs — in a pool's `hooks:` list or in top-level `global_hooks` — and requires `plugins.enabled:
true`. For the HTTP-sidecar case (out-of-process forwarding), use the first-party
`busbar-webrequest-hook` plugin.

```yaml
# 1.4.x — registry entry + built-in transport
hooks:
  pii-guard:
    kind: gate
    webhook: https://sidecar.internal/pii
    prompt: ro
pools:
  smart:
    hooks: [pii-guard]

# 1.5.0 — inline plugin ref (no registry)
plugins: { enabled: true, dir: /etc/busbar/plugins }
pools:
  smart:
    hooks:
      - { module: busbar-webrequest-hook, settings: { url: "https://sidecar.internal/pii" },
          kind: gate, prompt: ro }
```

The `global:` / `default:` flags on a hook are gone — the two lists (`pools.<p>.hooks` and
`global_hooks`) subsume them. See [hooks.md](hooks.md) and [plugins.md](plugins.md).

---

## 3. Governance: the `governance:` block → `groups:`, `rate_card`, `per_request_fee`, `store`

The `governance:` block dissolved; its contents moved to owning top-level keys:

| 1.4.x | 1.5.0 |
|---|---|
| `governance.budget_groups` | `groups:` (the generic limit tree — see below) |
| `governance.rate_card` | top-level `rate_card:` |
| `governance.price_per_request_cents` | top-level `per_request_fee:` |
| `governance.price_per_1k_tokens_cents` / member `cost_per_mtok` | `rate_card:` is the only cost source (`--migrate-config` synthesizes card entries) |
| `governance.store` / `governance.db_path` | `store: { module, settings }` |
| `governance.admin_token` | the `admin-tokens` module's `token` secret reference |
| `governance.rate_sweep_interval` / `usage_flush_interval_ms` | `advanced:` |
| `governance.enabled` / `governance.budget_on_store_error` | removed (governance is always-on; admission never touches the store) |

Governance has no on/off switch in 1.5.0: it is inert until keys exist. Spend is derived from a
token ledger × the `rate_card` at read time; nothing dollar-shaped is stored.

---

## 4. Per-key limits → the `groups:` limit tree

The per-key cap fields are **removed** from mint, `PATCH`, the store schema, and key metadata:
`rpm_limit`, `tpm_limit`, `max_budget_cents`, `budget_period`. A **key is pure auth**; every limit
lives on the `group` the key is bound to.

```yaml
# 1.5.0 — limits live on a group, keys bind to it
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

The default store is now `memory` — the compiled-in **ephemeral** RAM store (keys, usage, audit
reset on restart). Every durable backend (`sqlite` / `postgres` / `redis`) is a signed plugin
tarball loaded through `plugins`, so it requires `plugins.enabled: true` and the tarball in
`plugins.dir`.

```yaml
# 1.5.0
plugins: { enabled: true, dir: /etc/busbar/plugins }
store:
  module: postgres                                 # or sqlite / redis, or memory (default)
  settings: { url: "postgres://user:pass@host/busbar" }
```

See [Configuration → `store`](configuration.md#store) and [plugins.md](plugins.md).

---

## 6. TLS: `cert_file` / `key_file` / `client_ca_file` → secret references

The plaintext path keys are gone. Each TLS field is now a **secret reference** — `cert`, `key`,
`client_ca` — taking `{ file: /path }`, `{ env: VAR }`, or `{ module: <secret-plugin>, settings:
{...} }`. The same shape applies to `admin_tls`.

```yaml
# 1.4.x
tls:
  cert_file: /etc/busbar/tls/fullchain.pem
  key_file:  /etc/busbar/tls/privkey.pem
  client_ca_file: /etc/busbar/tls/ca.pem

# 1.5.0
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

```yaml
# 1.4.x
providers:
  openai:
    api_key_env: OPENAI_KEY

# 1.5.0
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
| `auth.mode` | `auth.chain` / `auth.upstream_credentials` |
| member `target` | member `model` |
| `window_s` | `window_secs` |
| `n` (breaker) | `consecutive_n` |
| `deadline_secs` | `timeout_secs` |
| `cap` (failover) | `max_hops` |
| `otlp_endpoint` | `otlp_url` |

---

## Quick checklist

- [ ] `busbar --migrate-config old.yaml > config-1.5.yaml`; review every TODO/WARNING (esp. each `allowed_pools: []` — meaning flipped to *none*)
- [ ] `auth.client_tokens` / `BUSBAR_CLIENT_TOKEN` → `auth.chain: [keys]` + `admin_auth: [admin-tokens]` (`BUSBAR_ADMIN_TOKEN`)
- [ ] top-level `hooks:` registry + `socket`/`webhook` transports → inline `kind: hook` plugin refs (`busbar-webrequest-hook` for the HTTP sidecar)
- [ ] `governance:` → `groups:` + `rate_card:` + `per_request_fee:` + `store:`
- [ ] per-key `rpm_limit`/`tpm_limit`/`max_budget_cents`/`budget_period` → group `limits:`
- [ ] durable store → `store: { module: sqlite|postgres|redis }` + `plugins.enabled: true` (default is ephemeral `memory`)
- [ ] tls `cert_file`/`key_file`/`client_ca_file` → `cert`/`key`/`client_ca` secret references
- [ ] provider `api_key_env:` → `api_key: { env: VAR }`
- [ ] `busbar --validate`, then **re-mint every virtual key** (1.4.x keys no longer authenticate)

If Busbar starts and `--validate` passes, the migration is complete. There are no silent fallbacks,
so a clean boot means a fully migrated config.
