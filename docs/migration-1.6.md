# Upgrade from 1.5.5 to 1.6.0

**On an older version? [Upgrade to 1.5.5](upgrade-to-1.5.5.md) first.**

The upgrade path is: any older version → 1.5.5 → 1.6.0. 1.6.0 converts only 1.5.5 data and
config. 1.5.5 has been the stable release for three months, so going through it means every
upgrade runs on proven code. 1.6.0 refuses to start on anything older and tells you to upgrade to
1.5.5 first.

**Which page do I need?** On 1.5.5: this page. On anything older: [Upgrade to 1.5.5](upgrade-to-1.5.5.md)
first, run 1.5.5 once so it converts your data, then come back here.

---

## Before you start

- **Get 1.6.0 builds of your plugins.** A plugin built for 1.5.5 does not load in 1.6.0. That
  includes the first-party stores (SQLite, Postgres, MySQL, Valkey), sign-in plugins, the Vault
  secret plugin and the web-request hook. Install their 1.6.0 releases. On a host with no network,
  copy the signed 1.6.0 archives into `plugins.dir`. A drop-in native archive needs its SHA-256 in
  its `plugins.fetch` entry ([how plugins are secured](plugins.md#how-plugins-are-secured)). A
  plugin someone else built must be rebuilt by its author with
  [the plugin SDK guide](plugin-sdk-migration-1.6.md).
- **Check provider credentials.** In 1.6.0 a provider `api_key` that does not resolve stops startup
  (1.5.5 started the provider with an empty key). Fix the reference, or write `api_key: none` for a
  provider that takes no key. See [credentials](#a-provider-credential-that-cannot-resolve-refuses-startup).
- **Using OIDC with a principal format change?** Read [principal transition](operations/principal-transition.md)
  before starting 1.6.0 on a kept 1.5.5 store.

## Upgrade

1. **Stop every 1.5.5 instance.** 1.6.0 detects a 1.5.5 instance still writing to the store and
   refuses to migrate.
   <!-- TODO(migrate-design): Valkey residual and Kubernetes rollout strategy (Recreate, zero
   replicas) per MIGRATE-ON-BOOT Q2; add only once decided. -->
2. **Back up your store** (database dump or snapshot) and your config directory.
3. **Start 1.6.0** with the same config, environment and working directory that 1.5.5 used.
   Migration runs automatically at boot; there is no separate command.
   - Config files are rewritten once to the 1.6.0 shape. The original is kept beside each one as
     `<file>.1.5.5`, and the new file is stamped `config_version: N`.
   - Your store's 1.5.5 records are converted to 1.6.0.
   - Each plugin upgrades its own data and settings when it first loads.
   - Busbar logs what it changed and anything you should review.
   <!-- TODO(migrate-design): read-only config files (ConfigMap, config.locked) and whether an
   offline `busbar migrate-config` remains; document only once decided. -->
4. **Check it.** Read the migration log lines, especially warnings. Confirm readiness and your
   usual traffic. Then remove the [retired environment variables](#retired-environment-variables)
   from your launcher.

**If startup refuses**, the message explains what is wrong and nothing has been changed. Fix it
and start 1.6.0 again.

**Every boot after that** sees a matching `config_version` and does no migration work.

## Rolling back

Stop 1.6.0, restore your store backup and the `.1.5.5` config files, and start 1.5.5. Changes
made while 1.6.0 was running are not carried back.
<!-- TODO(migrate-design): the store unfence/rollback step (MIGRATE-ON-BOOT §10) and its command
name; add here once decided. -->

---

## What the migration changes for you

Your keys, groups, audit records and usage history carry over. `auth.signing_key` is read as
before, so every outstanding key keeps verifying; nothing is re-minted. Pools, members, weights,
providers and models are left as you wrote them. Where a decision belongs to you, the migration
reports it instead of guessing.

The config migration:

- adds `store: {module: memory}` when the config has no `store:` block (what 1.5.5 used in that
  case). 1.6.0 requires the block;
- points `plugins.fetch` at the 1.6.0 release of each plugin your config uses;
  <!-- TODO(migrate-design): confirm plugins.fetch pinning stays in the boot migration. -->
- adds `units:` at `0` to each `rate_card:` entry for every billable unit 1.5.5 never billed, so
  your bill does not change ([rate cards](#rate-cards));
- adds to `advanced.allow_destinations` exactly the private or loopback hosts your providers and
  sign-in plugins use, because 1.6.0 blocks private addresses by default;
- writes `role_bindings.<provider>."*": {}` for each sign-in provider whose users 1.5.5 let in with
  no grant, and warns you to tighten it. Without it, 1.6.0 refuses those users (401);
- removes metadata block-list entries that name no usable host (they never matched anything);
- removes a webhook exporter's auth header that 1.5.5 never sent;
- rewrites hook `plugin:` to `module:` and `at: <stage>` to `phase: [<stage>]`;
- turns a `jwt-bearer` credential that held a filename into an explicit `{ file: /path }`
  reference (relative names resolve against the 1.5.5 working directory). If the file cannot be
  found, the old reference is kept and reported;
- captures the retired environment variables below.

### Retired environment variables

1.6.0 no longer reads these at runtime. The first 1.6.0 boot copies their values into config, so
keep them set for that boot and remove them afterwards.

| Retired env var | Config key |
|---|---|
| `BUSBAR_PROVIDERS` | `providers_file:` |
| `BUSBAR_WORKER_THREADS` | `advanced.worker_threads` |
| `BUSBAR_UPSTREAM_HTTP1_ONLY` | `advanced.upstream_http1_only` |
| `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` | `advanced.upstream_h2_prior_knowledge` |
| `BUSBAR_CONFIG_OVERLAY` | none; the overlay is imported into the store (below) |

`BUSBAR_CONFIG`, secret `{ env: NAME }` references, `RUST_LOG`, `TOKIO_WORKER_THREADS` and the
`--providers` flag are unchanged.

**Containers.** The 1.5.x image set `BUSBAR_PROVIDERS=/etc/busbar/providers.yaml`; the 1.6.0 image
does not. With `config.yaml` at the default `/etc/busbar/config.yaml` nothing changes. If you
mounted it elsewhere, set `BUSBAR_PROVIDERS` for the first boot or put `providers.yaml` beside it.

### Your saved config overlay

In 1.6.0, changes made through the admin API are stored in the store, not in an overlay file. The
first boot imports your 1.5.5 overlay file (`config.overlay.file`, else `BUSBAR_CONFIG_OVERLAY`,
else `busbar-overlay.json` beside the config) into the store once:

- hooks, wiring, groups, root controls, named definitions and plugin floors are kept;
- if the overlay chose the store, that choice is written into `config.yaml`;
- with `config.locked: true` the overlay is ignored, as it was in 1.5.5 (`locked` itself is kept);
- the import needs a durable store; an overlay with the memory store is refused;
- an unknown or invalid overlay is refused, never partly imported;
- the old file is not read again after import.
<!-- TODO(migrate-design): whether the imported overlay file is renamed (design: <file>.imported-1.5.5). -->

### Credentials moved to files

A plugin setting that held a literal credential is replaced with a `{ file: ... }` reference. The
credential is written, byte for byte, to a private file in `.busbar-migrated-secrets` beside the
config (directory mode `0700`, files `0600`, owned by the Busbar user). File names never contain
the credential. Busbar never overwrites an existing file: an identical one is reused and a
different one is refused. Keep these files with your config backups.

Symlinks in the path and insecure permissions are refused, as are filesystems without atomic
publication. On Windows the files are not created automatically: create a private file with the
exact credential bytes and set the setting to `{file: 'C:\private\credential'}` yourself.

---

## What you must decide

The migration does not guess these.

### A provider credential that cannot resolve refuses startup

1.5.5 started a provider whose `api_key` did not resolve with an empty key; every request to it
then failed upstream with a 401. 1.6.0 refuses at startup and on an admin reload, naming the
provider and the reference, never the value. For each one:

- if it should resolve: set the variable, mount the file, or install the secret plugin;
- if the upstream takes no key (a local ollama or vLLM), declare it:

```yaml
providers:
  ollama:
    api_key: none          # this upstream takes no credential
```

`none` is accepted only on a provider `api_key`. Such a provider sends no auth header and is not
health-probed.

### Other items

- A `file:` secret that is a directory, device or pipe is refused. Point it at a regular file.
- An identity provider whose discovery or key URL redirects to a private address fails sign-in.
  Point the issuer at the address it finally serves from.
- A third-party plugin built for 1.5.5 needs a 1.6.0 build from its author.

---

## What you will notice

None of these need action.

- **Diagnostic codes.** `[error]`, `[warn]` and `warning:` lines start with `BUSBAR-NNNN:`, and boot
  log lines carry `diag=BUSBAR-NNNN`. If a log pipeline matches the start of those lines, allow for
  the code. See [diagnostics](diagnostics.md).
- **Plugin logs** go to each plugin's own file under `plugins.logs.dir` (default `logs/plugins/`).
- **`/metrics`.** One new series on an unchanged config, `busbar_metering_pending_coalesced_total`.
  `busbar_lane_state` now reads each pool's own breaker: a pool whose breaker tripped reads `2`
  even if another pool can still reach the same lane. See [observability](observability.md).
- **Admin API views gained fields.** Hooks carry `fires_at`, `groups` and `phase`.
- **`--version` prints two lines** (the second is a build stamp). `-c`/`--config` is a new flag.
- **Streams that fail over to an OpenAI Chat Completions lane are billed** their real tokens
  (1.5.5 billed them zero).
- **Bedrock and Responses streams** match the provider's spec more closely. See
  [protocols](protocols.md#spec-fidelity).
- **Thread-per-core data plane** on unix: one `busbar-core-N` thread and listener per core;
  `advanced.worker_threads` sets the count.
- **A configured voice `session_fee` now charges** once per session (it never charged in 1.5.x).

See the [1.6.0 advisories](advisories/1.6.0/README.md) for the full disclosures.

## Admin API client changes

- Hook writes require `module:` (not `plugin:`) and `phase: [...]` (not `at:`). Hook reads no longer
  return `at`; read `fires_at` and `phase`.
- Remove `persist` from `PUT /api/v1/admin/config/settings` requests; it is refused with 400.
  Every successful change is saved to the store.
- A `rate_card` written through the admin API must include the `units:` map below.

## Rate cards

**Every billable unit must have a rate.** A `rate_card:` must price every unit its plane counts
(`0` is a rate), or startup refuses and names the missing units. The migration adds these at `0`,
which is what 1.5.5 billed:

`search_units`, `classifications`, `web_fetch_requests`, `unitemized_tokens`, `images`, `audio_ms`,
and the nine Bedrock `guardrail_*` units.

```yaml
rate_card:
  claude-sonnet: { input_utok: 3, output_utok: 15,
                   units: { search_units: 0, classifications: 0, web_fetch_requests: 0,
                            unitemized_tokens: 0, images: 0, audio_ms: 0,
                            guardrail_automated_reasoning_policies: 0,
                            guardrail_automated_reasoning_policy_units: 0,
                            guardrail_content_policy_image_units: 0, guardrail_content_policy_units: 0,
                            guardrail_contextual_grounding_policy_units: 0,
                            guardrail_sensitive_information_policy_free_units: 0,
                            guardrail_sensitive_information_policy_units: 0,
                            guardrail_topic_policy_units: 0, guardrail_word_policy_units: 0 } }
```

Put the map on every entry: an entry silent about a unit refuses that traffic. Set a real rate when
you want to bill a unit. These units do not count toward `tokens:` caps.

**Rate cards are a dated history.** Changing a card prices only what comes after the change; past
usage keeps the price it was earned at (1.5.5 repriced everything on the next read). To fix a
wrong past rate, post a correction to `POST /api/v1/admin/ledger/amend-rate-history` naming the
window. `GET /admin/usage` accepts `as_of` to read figures at a past history point. Figures are
cost units with no currency. See [card history](store-card-history.md).

## New, optional sections

None is added by the migration; write one to turn a plane on.

| Section | What it declares | Guide |
|---|---|---|
| `mcp:` | Busbar as an MCP server | [MCP](mcp.md) |
| `tools:` | Upstream MCP servers Busbar governs | [MCP](mcp.md), [tool and agent trust](tool-and-agent-trust.md) |
| `agents:` | A2A agents | [A2A](a2a.md) |
| `streams:` | Live voice sessions | [Voice](voice.md) |
| `oauth_as:` | The built-in OAuth 2.1 authorization server | [MCP](mcp.md) |
| `decisions:` | The decisions plane | [Changelog](../CHANGELOG.md#additive-planes) |
