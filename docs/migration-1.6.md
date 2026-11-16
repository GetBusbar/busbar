# Upgrade from 1.5.5 to 1.6.0

**On an older version? [Upgrade to 1.5.5](upgrade-to-1.5.5.md) first.**

- adds the `store:` block a 1.5.5 config left implicit (`store: {module: memory}`);
- pins, in `plugins.fetch`, the 1.6.0 release of each plugin the config uses that this binary does
  not carry, and rewrites a 1.5.5-era `plugins.fetch` pin to the 1.6.0 release (dropping its stale
  `sha256`). The operator must authorize replacement native bootstrap/check/migration archives
  with their exact new base fetch hashes before they execute (see below). A 1.5.5 build left in
  `plugins.dir` beside its 1.6.0 build is skipped with a warning;
- prices every billable unit a `rate_card:` entry left out at `0`, which is what 1.5.5 billed, except
  the cache-write TTL units `cache_write_30m` and `cache_write_12h`. 1.5.5 billed those tokens inside
  input, so they take the entry's `cache_write_utok`, else its `input_utok`;
- removes a root `rate_card.<model>.cache_write_utok: 0`, which in 1.5.5 meant "no separate write
  tariff"; cache writes then price at `input_utok`, never 0;
- adds to `advanced.allow_destinations` exactly the private or loopback hosts a provider's plane or a
  sign-in plugin reports it dials (never a blanket `block_private_addresses: false`);
- removes a metadata block-list entry that names no usable host (it never matched anything);
- removes a webhook exporter's auth header that 1.5.5 never sent (the exporter's own migration);
- writes, for each data-plane sign-in provider whose users 1.5.5 admitted with no grant, the
  explicit binding `role_bindings.<provider>."*": {}` that keeps their access, with a warning to
  tighten it;
- rewrites the old hook spellings `plugin:` and `at:`.

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

1.6.0 no longer reads these at runtime. Run the explicit configuration migration with the original
environment before starting 1.6. It captures the supported values in the generated configuration.
Review that output, then remove the retired variables from the normal service environment.
Startup does not import them.

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
mounted it elsewhere, set `providers_file:`, pass `--providers`, or put `providers.yaml` beside it.
Keep the old `BUSBAR_PROVIDERS` value only for the explicit migration command.

`BUSBAR_CONFIG_OVERLAY` selects old file-overlay migration input only; serving never reads it.
The old `config.overlay` file/boolean field is refused by `--validate` (the current reader), which
names it as retired and gives the migration commands; serving normalizes it at startup. One-time migration removes that field while preserving `config.locked`;
use `locked: true` to keep an immutable/GitOps deployment. 1.6 runtime configuration is persisted
through Store. Follow the [overlay import instructions](migration-overlay-1.6.md) before serving
old state: serving refuses to start while the overlay file 1.5.5 would have read still holds
settings this Store has not imported (BUSBAR-3027; that guide lists the remedy for each Store
state). Selectors and `BUSBAR_CONFIG_OVERLAY` that hold nothing get a warning (BUSBAR-3028).
`BUSBAR_CONFIG`, explicit secret `{ env: NAME }` references, `RUST_LOG` and the
`TOKIO_WORKER_THREADS` fallback are unchanged. Preserve existing signing-key material and Store
records when upgrading 1.5.5: existing signed keys do not need to be reminted merely for this upgrade.

In 1.6.0, changes made through the admin API are stored in the store, not in an overlay file. The
explicit migration command imports your 1.5.5 overlay file (`config.overlay.file`, else `BUSBAR_CONFIG_OVERLAY`,
else `busbar-overlay.json` beside the old config) into the store once. Run it before serving; startup refuses unimported legacy state:

- hooks, wiring, groups, root controls, named definitions and plugin floors are kept;
- if the overlay chose the store, that choice is written into `config.yaml`;
- with `config.locked: true` the overlay is ignored, as it was in 1.5.5 (`locked` itself is kept);
- the import needs a durable store; an overlay with the memory store is refused;
- an unknown or invalid overlay is refused, never partly imported;
- the old file is not read again after import.
The original files remain unchanged; the import and digest receipt commit atomically. See [overlay import](migration-overlay-1.6.md).

### Credentials moved to files

See [the full 1.6.0 advisories index](advisories/1.6.0/README.md) for these and two further
disclosures (an upstream-429-as-503 status-code clarification, and a fee defect on a refund that
crosses a billing window) that require no operator action but are recorded for completeness.

## 4. New optional sections for the planes

Each plane is declared by writing its section and is absent otherwise: a config with none of them
gains no endpoint and no route, and the migrator adds none of them.

| Section | What it declares | Guide |
|---|---|---|
| `mcp:` | Busbar as an MCP server: canonical URI, identity provider, OAuth 2.1 discovery | [MCP](https://getbusbar.com/docs/mcp/) |
| `tools:` | Registered upstream MCP servers Busbar governs (`transport: stdio` for local ones) | [MCP](https://getbusbar.com/docs/mcp/), [Tool and agent trust](tool-and-agent-trust.md) |
| `agents:` | Registered A2A agents, served over JSON-RPC, HTTP+JSON and gRPC | [A2A](https://getbusbar.com/docs/a2a/) |
| `streams:` | The live-voice plane: full-duplex realtime sessions over one IR | [Voice](voice.md) |
| `oauth_as:` | The embedded OAuth 2.1 authorization server the MCP door can use | [MCP](https://getbusbar.com/docs/mcp/) |
| `decisions:` | The decisions plane: `jev` and `nanojev` served as passthrough | [Changelog](../CHANGELOG.md#additive-planes) |

Two things about them are worth knowing before you write one. An `mcp:` block with an empty
`auth.chain` refuses to start, because an anonymous MCP request is never narrowed by a key and
would run with wildcard grants over every registered server. And an MCP or A2A failover pool is
written in the top-level `pools:` map with `tools:` / `agents:` entries as bare-name members, so
the same breaker and failover you already run for models applies to them; see
[Circuit breaker](circuit-breaker.md).

Validation messages keep 1.5.5's wording, but the key lists they print are not frozen: where a
message lists what a section accepts (`expected one of …`), the list now also names what 1.6.0
added, such as the new sections and the group-limit token sub-metrics `tokens_input`,
`tokens_output`, `tokens_cache_read` and `tokens_cache_write` (see
[Configuration → `groups`](configuration.md#groups)). A script that matched the exact 1.5.5 list
needs to allow for the longer one.

## 5. Retired 1.5.x spellings, rewritten for you

Hook configuration and admin writes use one canonical spelling. Convert existing configuration
once and update clients that submit or read retired fields.

- **`config.overlay` is retired.** 1.6.0 keeps admin-API config changes in the configured Store,
  not in an overlay file, so `config:` accepts only `locked`. `busbar --migrate-config` removes `overlay: false` and `overlay: { file: <path> }` and keep
  `config.locked`. Import the old file into the Store once with
  `busbar --config <new-config.yaml> --migrate-overlay <old-config.yaml>`
  ([overlay import](migration-overlay-1.6.md)). Where the selector is still present and nothing
  migrates it (`--validate`, a reload), it is refused with that instruction.
- **Hook `plugin:` → `module:`.** Current configuration and `POST`/`PUT /api/v1/admin/hooks`
  bodies require `module:`. `busbar --migrate-config` rewrites old YAML; explicit legacy overlay
  import converts the old persisted field before committing it to the Store.
- **Hook `at: <stage>` → `phase: [<stage>]`.** Current configuration and admin writes require the
  phase list. One-shot YAML and overlay migration preserve the selected stage and an existing
  non-empty phase list. For example, replace `at: response` with `phase: [response]`. An omitted
  phase list still selects the four core stages. Ordinary Store reads do not rewrite retired keys.
- **Remove `persist` from `PUT /api/v1/admin/config/settings` clients.** Both settings-section
  writes and `document_patch` requests reject this retired field with 400, regardless of its value.
  Successful mutations are durable through the configured Store; locked deployments refuse them.
  No replacement flag is needed, and this client request change does not alter stored configuration.
- **Hook readback:** `GET /api/v1/admin/hooks[/{name}]` and hook-write responses no longer include
  `at`. Read `fires_at` for the effective stages and `phase` for the configured list. Update clients
  and dashboards that previously read `at`.

- **`tools.<server>.allow_private` and `agents.<agent>.allow_private` → `advanced.allow_destinations`.**
  One setting governs every outbound connection busbar and its plugins make; the per-registration
  switch is retired and a configuration that still sets it is refused (BUSBAR-3135), naming the
  registration. `busbar --migrate-config` removes the key and lists exactly the hosts that
  registration dials (its `url`, and a token endpoint it names), never a wildcard or a network:

  ```yaml
  # before
  tools:
    search:
      url: https://mcp.tools.internal/mcp
      allow_private: true
  # after
  advanced:
    allow_destinations: [mcp.tools.internal]
  tools:
    search:
      url: https://mcp.tools.internal/mcp
  ```

  `allow_private: false` is simply removed. A cloud-metadata host is never listed. Every line the
  migration writes for it carries BUSBAR-3410. A registration whose URL is plaintext `http://` to a
  host other than loopback is reported: it is refused at 1.6.0 (the MCP and A2A planes admit `http://`
  to loopback only), so move it to `https://`; a per-destination `plaintext: true` entry arrives
  after 1.6.0.

- **`security.allow_metadata_hosts`, `security.allow_all_metadata` and
  `providers.<p>.allow_metadata_hosts` are retired.** Cloud metadata is refused for every outbound
  connection, in every egress class, and no configuration admits it; a configuration that still
  carves an exception is refused at startup (BUSBAR-3136). `busbar --migrate-config` removes the keys
  and names each removed entry (BUSBAR-3411). `security.blocked_metadata_hosts` stays and still
  extends the denylist. An `advanced.allow_destinations` entry that names a cloud-metadata host or
  address is refused too (BUSBAR-3134). A workload that needs cloud credentials uses
  workload-identity federation (IRSA, AKS workload identity, GKE workload identity federation)
  through a projected token file.

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
- `GET /stats` lanes no longer carry `limit`; read `max_concurrent` (same value).
- Remove `persist` from `PUT /api/v1/admin/config/settings` requests; it is refused with 400.
  Every successful change is saved to the store.
- A `rate_card` written through the admin API must include the `units:` map below.
- The admin API speaks kinds. Discover what exists with `GET /api/v1/admin/kinds`, then each
  kind's instances with `GET /kinds/{kind}/instances`, then one instance with
  `GET /kinds/{kind}/instances/{id}`. These 1.5.5 paths are removed and answer 404 `not_found`:
  - `GET /models`: read `GET /kinds/core/instances/routing` (`config.models`), and the `core/routing`
    view `lanes`.
  - `GET /providers`: read `GET /kinds/core/instances/routing` (`config.providers`).
  - `GET /pools` and `GET /pools/{name}`: read `GET /kinds/core/instances/routing`
    (`config.pools`), and the `core/routing` view `pools` (live member status).
  - `GET /export` and `GET /export/{name}`: read `GET /kinds/export/instances` and
    `GET /kinds/export/instances/{name}`.
  - `PUT` and `DELETE /export/{name}`, `PATCH /export/{name}/settings`: write the `export.<name>`
    section with `PUT /config/settings` and `POST /config/apply`; read it back on
    `GET /kinds/export/instances/{name}`.
  - `GET /identity-providers` and `GET /identity-providers/{name}`: read `GET /kinds/auth/instances`
    and `GET /kinds/auth/instances/{name}`.
  - `PUT` and `DELETE /identity-providers/{name}`, `PATCH /identity-providers/{name}/settings`: write
    the identity-provider section with `PUT /config/settings` and `POST /config/apply`; read it
    back on `GET /kinds/auth/instances/{name}`.
  - `GET /plane-facts` (1.6 pre-releases only): read the plane instance's `runtime.plane.facts`.
- 1.6 refuses a config that uses one instance name in two sections, or a core instance id
  (`process`, `routing`, `units`, `limits`, `ledger`, `credentials`, `durability`, `connector`,
  `trust`); rename the instance before upgrading, and update any client that filters by
  `instance`.

## Rate cards

**Price every billable unit deliberately.** With a rate card present, a missing required lane
is a validation error; missing billable classes produce unpriced warnings. A deployment with no
rate card has usage pricing disabled. Do not treat successful startup as proof that every unit
is priced. The migration adds the following units at `0`, which is what 1.5.5 billed:

**This is the one edit a 1.5.5 config with a `rate_card:` needs.** Every count a provider reports
is a ledger line under its own unit (owner ruling LEDGER-100). The LLM plane counts `input`,
`output`, `cache_read`, `cache_write` (the `*_utok` tiers: an omitted or `null` `cache_write_utok`
prices writes at `input_utok`, and a root-YAML `cache_write_utok: 0` is read the same way on every
path; other omitted tiers are `0`, as in 1.5.5) and these open units, which have no tier:

| unit | what the provider reported |
|---|---|
| `search_units` | a rerank's billed search units; an Anthropic turn's web searches |
| `classifications` | Cohere `billed_units.classifications` |
| `web_fetch_requests` | Anthropic `usage.server_tool_use.web_fetch_requests` |
| `unitemized_tokens` | the tokens a provider's stated total (`total_tokens`, `totalTokenCount`, `totalTokens`) counts above the buckets it itemizes |
| `images` | the images a per-image provider returned (dall-e, Imagen, Titan, SDXL) |
| `audio_ms` | a transcription's reported duration, in whole milliseconds |
| `guardrail_*` (nine) | the Bedrock guardrail policy units, one unit per policy type |

If you migrate by hand instead of running `--migrate-config`: delete `cache_write_utok: 0` from a
1.5.5 entry. 1.6.0 removes it and logs a WARN at boot, and cache writes bill at `input_utok`. A
config reload that adds it is refused with the reason. YAML cannot yet make cache writes free; use
the admin API.

1.5.5 billed every one of them at `0`, so the upgrade that keeps every figure 1.5.5 billed is to
price each at `0`:

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

Put the map on every entry and resolve unpriced warnings. Set a real rate when
you want to bill a unit. These units do not count toward `tokens:` caps.

**Rate cards are a dated history.** Changing a card prices only what comes after the change; past
usage keeps the price it was earned at (1.5.5 repriced everything on the next read). To fix a
wrong past rate, post a correction to `POST /api/v1/admin/ledger/amend-rate-history` naming the
window. `GET /admin/usage` accepts `as_of` to read figures at a past history point. Figures are
cost units with no currency. See [card history](store-card-history.md).

## New, optional sections

None is added by the migration; write one to turn a plane on.

**Card-history durability follows the Store.** Applied rate cards and their dated history are
Store-backed; no `data_dir` or host journal file participates in their recovery. A durable Store
restores the recorded history on restart. When the Store history is empty, boot writes an opening
entry from the configured card at instant zero. A memory Store loses that history on restart and
starts with a new opening entry.

**No currencies.** Rate-card figures are abstract cost units with no currency and no conversion. A
correction body that names a `currency` is refused.

**New, additive ledger surface.** No 1.5.5 path or field is changed. The one administrative OpenAPI
document (`GET /api/v1/admin/openapi.json`; the unfiltered copy at
`GET /api/v1/admin/ledger/openapi.json`) now describes these operations beside every 1.5.5 one, each
marked `x-busbar-since: 1.6.0`; a 1.5.5 operation's entry is unchanged. What is served today is
exactly these:

- `GET /api/v1/admin/ledger/totals`, `/checkpoints`, `/reconciliation`, `/migration` and
  `/openapi.json` — the five additive reads.
- `POST /api/v1/admin/ledger/amend-rate-history` — the correction write.

**Back-dating is available, and it is attributable.** The `amend-rate-history` verb appends a dated
entry and journals one record per correction, naming the window, the corrected cells, the card it
corrects, the principal that posted it and the SHA-256 of its reason. The body carries no signer and
no signature. The original line and the correction are both visible forever, and no booked line is
rewritten.

**What to do if a rate was wrong.** Post a correction through
`POST /api/v1/admin/ledger/amend-rate-history` naming the window it repairs, rather than editing the
live card. The correction is an append and it leaves an attributed record. Editing the live card
prices only what happens after the edit; it cannot repair a window that is already past.

---

## 8. Telemetry attribute names changed in 1.6

The OTLP trace exporter (`busbar-export-otlp`) now writes Busbar's own span and span-event
attributes under the `busbar.` namespace. A key that already carries a namespace (it contains a
`.`) is written unchanged: the resource's `service.name`, `code.file.path`, `code.module.name`,
`code.line.number`, `thread.id`, `thread.name` and any standard OpenTelemetry key such as
`http.request.method`. Span names (`forward`, `request_attempts`, `named`, `adhoc`,
`gemini_ingress`, `bedrock_converse`, …), attribute values and value types are unchanged, and
`/metrics` is not affected.

| 1.5.5 key | 1.6 key | Where it appears |
|---|---|---|
| `pool` | `busbar.pool` | projected spans; the `named` span |
| `ingress` | `busbar.ingress` | projected spans; `forward` |
| `op` | `busbar.op` | projected spans; `forward` |
| `lane` | `busbar.lane` | projected spans |
| `provider` | `busbar.provider` | projected spans; the `adhoc` span |
| `model` | `busbar.model` | projected spans; the `adhoc` span |
| `target` | `busbar.target` | every full span and every span event |
| `busy_ns` | `busbar.busy_ns` | every full span |
| `idle_ns` | `busbar.idle_ns` | every full span |
| `request_id` | `busbar.request_id` | `forward` and `request_attempts` |
| `level` | `busbar.level` | every span event |
| any other bare field `<name>` | `busbar.<name>` | any span or event field recorded without a namespace |
| a bare `<name>` on a record that also carries `busbar.<name>` | `busbar.original.<hex>` | `<hex>` is the UTF-8 bytes of `<name>` in lower-case hex; a further `.original` suffix is added while the name is taken, so neither value overwrites the other |

Before upgrading, update every dashboard, alert, saved query, sampling or filtering rule, and
collector processor (for example an `attributes` or `transform` processor) that matches one of
the 1.5.5 keys above to the 1.6 key.

## Quick checklist

- [ ] Run `busbar --migrate-config config.yaml > config-1.6.yaml` and read what it printed: every
      change it made, the WARNINGs (the `role_bindings."*"` entries that keep 1.5.5's access) and the
      TODOs.
- [ ] Act on the TODOs. A provider `api_key` that does not resolve: fix the reference, or — for an
      upstream that takes no credential (local ollama / vLLM) — declare `api_key: none`
      ([§6](#6-a-provider-credential-that-cannot-resolve-refuses-boot)). A third-party plugin built
      for 1.5.5: get its 1.6.0 build from its author.
- [ ] On a host with no network, copy the 1.6.0 tarball of each plugin `plugins.fetch` pins into
      `plugins.dir` ([a plugin built for 1.5.5 does not load](#a-plugin-built-for-155-does-not-load)).
- [ ] Before dropped native bootstrap/check/migration code executes, authorize each selected
      archive's complete SHA-256 in the operator base `plugins.fetch` entry. Replace stale hashes
      when replacing archives; a release-index download does not supply this authorization.
- [ ] Install the intended 1.6.0 build, `busbar --validate` the migrated file, start, and verify
      Store recovery, readiness and the supported application flows.
- [ ] If a log pipeline matches on the leading text of `[error]` / `[warn]` lines, allow for the
      `BUSBAR-NNNN:` prefix.
- [ ] If any key's traffic routinely fails over to an OpenAI Chat Completions lane while streaming,
      expect its spend to rise to what it actually used.
- [ ] Convert retired environment overrides using the migration command with the old environment,
      then remove those variables from launchers; serving uses the resulting configuration.
- [ ] Hooks spelled `plugin:` or `at:` in config.yaml: run `busbar --migrate-config` once
      and explicitly import old persisted overlays before serving. Ordinary Store reads do not
      rewrite retired fields.
- [ ] If a dashboard or reconciliation relied on `GET /admin/usage` totals recalculating after a
      rate-card edit: they no longer do (a card prices only what follows it). Post an
      `amend-rate-history` correction for booked usage, and pass `?as_of=<history_seq>` to read money
      as of a past history point ([§7](#7-rate-cards-became-a-dated-history-and-get-adminusage-prices-by-it)).
- [ ] Want MCP, A2A or voice? Add the section; see the guide in the table above.

### JWT service-account credential references

Runtime OAuth credentials must resolve to service-account JSON. A resolved filename is no
longer opened as a second credential source. Use `api_key: { file: /absolute/key.json }`
when the JSON lives in a file; an environment reference containing the JSON remains valid.

The one-shot 1.5.5 configuration migration recognizes `auth: jwt-bearer`, including the
original providers catalog's auth default. It resolves the deployment's original credential
reference and converts a verified filename to an explicit file reference. Run it with the
same secret sources and working directory as the 1.5.5 process: historical relative filenames
were relative to that directory, not to the configuration or catalog file. Exact spaces in
filenames are preserved. Only the file reference is written; JSON and private keys are never
copied into the output or report. Inline JSON sources remain unchanged. If the original source
or file cannot be resolved, the original reference is retained with a migration TODO; resolve
that TODO before starting 1.6. Dropped-in secret sources unavailable to the migration resolver
require an explicit file reference from the operator.

This historical conversion lives in the one-shot configuration migrator because the current
OAuth plugin has no outbound-binding migration entry; its generic auth migration surface
receives identity-provider settings, not deployment credential references.

## Released 1.5.5 persistent configuration

Run the explicit [file-overlay import](migration-overlay-1.6.md) after configuration migration and before first startup. The original files remain unchanged, the effective Store selection is captured in the new YAML, and the overlay plus digest receipt commit atomically. Current startup never applies the old file or its retired environment selector; it refuses to start while that file still holds settings the Store has not imported (BUSBAR-3027).
