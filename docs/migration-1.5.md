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

### 1.5.2: the admin token no longer gates the data plane

Data-plane admission is now decided **solely** by the shape of `auth.chain` (see
[configuration.md](configuration.md#authauth) → "Three orthogonal axes"). The operator admin token
(`auth.admin_auth`) gates only `/api/v1/admin/*`. Two behavior changes fall out:

- **`chain: []` + an admin token** now means **open (anonymous) relay + protected admin API** — the
  previously-inexpressible "admin-managed box, anonymous inference" posture. Before 1.5.2, setting an
  admin token silently forced a virtual key onto **every** data-plane request, overriding the empty
  chain. Deployments that set an admin token but named **no** data-plane chain change from
  "vkey-required" to "open relay" — add `keys` to `auth.chain` if you intended the data plane to
  require a virtual key.
- **`chain: [keys]` with no usable admin mint path is now a boot error** (previously it booted as a
  silent open relay that admitted anonymously). Provide a mint path: an `admin_auth` `admin-tokens`
  entry with a `token:`, an admin module granting `mint`/`full`, or — dev only — an explicit open
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
| `auth.mode` | `auth.chain` / `pools.upstream_credentials` (1.5.3) |
| member `target` | member `model` |
| `window_s` | `window_secs` |
| `n` (breaker) | `consecutive_n` |
| `deadline_secs` | `timeout_secs` |
| `cap` (failover) | `max_hops` |
| `otlp_endpoint` | an `export:` instance with `module: otlp` (1.5.3) |

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

---

# Migrating from 1.5.0 to 1.5.1

1.5.1 is a small, targeted breaking change on top of 1.5.0: **busbar no longer auto-generates a
signing key at boot.**

## What changed, and why

In 1.5.0, if `auth.signing_key` was absent, busbar generated an ed25519 secret on first boot and
wrote it to `busbar-signing.key` (mode `0600`) beside the config file. That write-on-first-boot
behavior boot-loops any deployment where the config directory is a read-only mount (the common case
for config delivered via a container image, a ConfigMap, or a read-only bind mount): busbar fails
the write, exits, and — because nothing was persisted — tries to generate and write the key again on
the very next boot, forever, with a Permission-denied error that doesn't obviously point at the
signing key as the cause.

1.5.1 removes the auto-generation entirely. `auth.signing_key` is now a plain secret **reference**
like any other (`{ env: VAR }` / `{ file: /path }`) — busbar only ever resolves it, never creates it.

## Do you need to do anything?

Only if your deployment verifies busbar-signed keys, i.e. `auth.chain` names the built-in `keys`
module. If it does, and `auth.signing_key` was relying on the old auto-generated
`busbar-signing.key`, you must now generate and provide the key explicitly — `config_validate` fails
closed at `--validate`/boot with an actionable error if `keys` is in the chain and
`auth.signing_key` is unset.

If `auth.chain` never names `keys` (no signed-token verification), nothing changes for you.

## Migration steps

1. Generate a key. `--generate-signing-key` has zero side effects — it mints a fresh ed25519 secret
   from the OS RNG and prints it; it does not write any file or touch your config.

   ```sh
   busbar --generate-signing-key > /run/secrets/busbar-signing.key
   ```

   (The 64-hex-char secret goes to stdout only, so it's safe to redirect straight to a file; guidance
   goes to stderr and never contains the secret.)

2. Point `auth.signing_key` at it:

   ```yaml
   # 1.5.0 (implicit — no auth.signing_key set, busbar generated one on first boot)
   auth:
     chain: [keys]

   # 1.5.1
   auth:
     chain: [keys]
     signing_key: { file: /run/secrets/busbar-signing.key }   # or { env: BUSBAR_SIGNING_KEY }
   ```

3. If you already have an existing `busbar-signing.key` file that busbar auto-generated under
   1.5.0, you can keep using it — copy/mount its bytes to wherever you now point
   `auth.signing_key`, so upgrading doesn't invalidate outstanding minted keys. There's nothing
   special about a freshly-generated key versus the old auto-generated one; both are just 32
   raw bytes (or 64 hex chars) of ed25519 secret material.

## Fleet note

`auth.signing_key` is a **shared secret**: every node that verifies busbar-signed keys must resolve
the exact same bytes, or nodes will reject each other's tokens. Generate the key **once**, then
distribute that same value to every node in the fleet (a shared secrets file, the same env var
sourced from a central vault, etc.) — do not run `busbar --generate-signing-key` separately on each
node. Rotating the key revokes every outstanding key fleet-wide, since every node stops being able to
verify tokens signed with the old secret.

## Quick checklist

- [ ] Does `auth.chain` name `keys`? If not, no action needed.
- [ ] `busbar --generate-signing-key > /path/to/secret` (or capture the stdout value into your
      secret manager / env var)
- [ ] Set `auth.signing_key: { file: /path/to/secret }` or `{ env: VAR }`
- [ ] Distribute the same secret value to every node in the fleet
- [ ] `busbar --validate`

---

## 1.5.3 config consolidation

1.5.3 moves operational config out of environment variables and **into `config.yaml`**, and makes admin-API
config mutability explicit and **durable by default**. Every migrated env var still works for **one release**
(each logs a deprecation warning) — this is a soft migration, not a clean cut. Move each into config.yaml at
your convenience before the next release removes the env var.

### Env var → config.yaml

| Deprecated env var | New home in config.yaml |
|---|---|
| `BUSBAR_PROVIDERS` | `providers_file:` (top-level; relative to config.yaml; default `providers.yaml` next to it) |
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

### Behavior change: durable-by-default config mutation

Before 1.5.3, admin-API config changes were **live-only unless** you set `BUSBAR_CONFIG_OVERLAY` — so a group
or hook provisioned over the API **silently vanished on restart**. Now, with nothing configured, config is
*mutable* and mutations persist to `busbar-overlay.json` next to config.yaml. **No action needed** for the
common (writable config directory) case — your admin-API changes simply become durable.

Two new postures:

- **`config.locked: true`** — an immutable/GitOps deployment. Admin-API config mutations are refused at
  runtime (edit config.yaml + `POST /config/reload` to change config). Set this if you never want runtime
  mutation.
- **Boot invariant** — a *mutable* config with no writable overlay **refuses to boot**.

### Upgrade action for read-only-config deployments

If your `config.yaml` lives on a **read-only mount** (e.g. `/etc/busbar` mounted read-only, or a read-only
container layer), the default overlay path is not writable, so an unconfigured mutable busbar will now
**refuse to boot** with a message naming the fix. Choose one:

1. **Point the overlay at a writable path** (a persistent volume) so runtime mutations are durable:
   ```yaml
   config:
     overlay:
       file: /var/lib/busbar/busbar-overlay.json   # a writable, persistent location
   ```
2. **Declare the deployment immutable** — the natural choice for a GitOps/read-only rollout that never
   mutates config at runtime anyway:
   ```yaml
   config:
     locked: true
   ```

Either resolves the boot refusal. Busbar never silently falls back to the old lose-on-restart behavior.
