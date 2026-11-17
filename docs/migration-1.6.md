# Upgrade from 1.5.5 to 1.6.0

**On an older version? [Upgrade to 1.5.5](upgrade-to-1.5.5.md) first**, and run it once
so its own data conversions finish.

1.6.0 uses a new plugin ABI and Store-backed administrative configuration. Configuration
migration runs on the first boot; there is no `--migrate-config` or `--migrate-overlay`
command. Core migrates its own configuration and records. Each Store implementation owns its
database schema and data migration during initialization; core does not convert a backend's
physical schema. Keep the original files and a complete Store backup until you have verified
the upgrade.

> This guide is being checked against development builds. The release-candidate check must
> finish before it is used as the final 1.6.0 upgrade procedure. Approved changes still awaiting
> integration are listed under [release-candidate checks](#release-candidate-checks). No Store
> backend is yet qualified for this upgrade by complete, direct CI migration evidence. A
> successful build or ordinary Store test run does not establish upgrade or rollback safety.

## Before you start

- Get 1.6.0 builds of every external kind implementation you use: stores, authentication,
  secret sources, hooks, exports, planes and transports. A native library built for 1.5.5
  cannot be reused. Third-party authors must rebuild against the
  [1.6.0 SDK](plugin-sdk-migration-1.6.md).
- Keep the deployment's signing-key material and secret sources available. Do not generate a
  replacement signing key as an upgrade step. If an identity provider changes principal
  format, follow [principal transition](operations/principal-transition.md).
- Check provider credential references. A credential that cannot resolve refuses startup;
  for an upstream that needs no credential, use `api_key: none`. Runtime service-account
  credentials must resolve to JSON; if the JSON is in a file, use an explicit
  `api_key: { file: /absolute/key.json }` reference. Do not rely on a resolved string being
  opened again as a filename.
- Review [transport security](#transport-security) and [environment inputs](#environment-inputs).
  Preserve the working directory and mounts needed by the old deployment's relative paths.
- Make the configuration directory writable for the first boot. Migration replaces files by
  rename and keeps backups beside them. A read-only ConfigMap or a single-file mount cannot
  support that operation: migrate with the directory mounted writable, then restore the
  intended read-only mounting arrangement.

## Upgrade

1. Stop **every** 1.5.5 process that can access this deployment's Store or configuration
   directory. Do not run a mixed-version rolling upgrade. Startup probes can detect a live
   writer; they are not a substitute for stopping the old deployment.
2. Back up the complete Store and configuration directory, including the old file overlay,
   providers catalog and any credential files. Retain the old launch environment for rollback.
   Take the whole set in the documented order, with the Store backup and the exported audit
   stream taken at the same point in time: see
   [backup set and order](operations.md#backup-set-and-order).
3. Install the intended 1.6.0 executable and compatible external artifacts. Where native
   bootstrap, check or migration code requires authorization, put the selected archive's
   complete SHA-256 in the operator base `plugins.fetch` entry. A downloaded release index
   does not authorize execution; see [plugin security](plugins.md#how-plugins-are-secured).
4. Start 1.6.0 with the deployment's config path, secret sources and working directory.
   Do not add `--ignore-overlay` to bypass an old overlay that still needs folding.
   For an unstamped config, do not use `--providers`: set `providers_file:` in the document.
5. Read the migration reports and refusals. The first boot plans configuration changes,
   initializes the configured instances (each brings its own supported settings and data to
   its current format), migrates core-owned records through the opened Store, writes the
   accepted configuration and re-executes the executable onto the stamped files. It does not
   serve application traffic before that handoff completes.
6. Check readiness, sign-in and administrative access, normal requests and failover,
   Store recovery, export delivery and usage figures. Review every migration warning,
   particularly the wildcard role bindings described below. Remove retired launch variables
   once their intended settings are represented in configuration.

Use the installed executable with the deployment's actual paths and environment:

```sh
busbar --config /deployment/config.yaml --validate
busbar --config /deployment/config.yaml
```

Validation checks configuration and plugin preflight; it does not prove backend reachability
or serving readiness. After startup, check `GET /readyz` on the configured listener and verify
the application flows above. `GET /livez` reports liveness; `GET /healthz` is observational.
Listener TLS and mTLS still apply. See [health and readiness](operations.md#health--readiness).

The original config is retained as `<config>.1.5.5`; the accepted config is stamped
`config_version: 1`. A matching stamp skips the one-shot file migration. A format newer than
the executable supports is refused. The config stamp does not skip a Store's own initialization
or data-version checks. Do not add a stamp yourself to bypass migration.

**A startup refusal does not mean the Store is unchanged.** Planning refusals happen before
instances open, but a later failure can follow a Store data conversion or an overlay guard
write. Fix the reported prerequisite and retry 1.6.0. Do not restart 1.5.5 against that Store.
If a backup or generated catalog already exists with different bytes, preserve it and
investigate the conflict; do not overwrite it to force the upgrade through.

### Shared datasets with a changing core record format

The maintenance procedure for a core record-format change requires a full stop, including
readers. The reviewed protocol is still being integrated and qualified; these preconditions
do not assert that a development binary can already perform that conversion. A configuration
stamp and a plugin's physical database migration are separate from core record-format admission.

- Inventory all dataset users and credentials, including read-only nodes, export, replay,
  repair and bootstrap jobs. Withdraw traffic and new administrative writes, and settle
  outstanding durable work through its supported recovery path before stopping the old cohort.
  Process exit alone does not establish that work settled.
- Stop every reader and producer. Disable old-cohort restarts, autoscaling and automatic
  rollback for the maintenance window. Writer fencing does not stop stale reads or cached
  responses from an old process.
- Select one final-target executable and compatible artifact/converter cohort. Retain their
  digests, the allowed migration contenders and evidence of dataset access exclusion. Only
  that cohort may start during conversion; exclude intermediate-target binaries even during
  a multi-step upgrade. The Store manifest does not authenticate the intended ultimate target.
- Keep traffic withdrawn through conversion and recovery. After a terminal refusal, disable
  automatic restart, preserve the evidence and resolve the reported cause. Resume only with
  the supported target cohort; never clear a migration cursor or tail, reduce a writer epoch,
  or point an old executable at partially converted records.
- Release traffic only after final/current format admission with no migration cursor and
  ordinary boot readiness. To roll back instead, restore the complete pre-upgrade snapshot
  as described below.

These are operator preconditions. A quiet writer list, socket probe or successful build cannot
prove them. The final executable, converter and backend cohort still requires direct migration,
interruption, recovery and rollback evidence before this procedure is qualified.

## Rolling back

Stop every 1.6.0 process. Restore the complete pre-upgrade Store backup and configuration
snapshot together, including the providers catalog, credential files, overlay and old launch
settings. Then start 1.5.5. Changes made after the upgrade are not carried back; this
includes key revocations and trust demotions made under 1.6.0, which must be re-applied (see
[backup set and order](operations.md#backup-set-and-order)).

Restoring only `config.yaml.1.5.5` does **not** undo Store migrations. Restore the old overlay
path too: the upgrader may have replaced it with a directory containing `busbar-1.6-folded`.
An interrupted fold can leave the original bytes at `<overlay>.busbar-folding`; a completed
fold keeps them at `<overlay>.1.5.5`. Preserve these recovery files until rollback is complete.
To restore the overlay path by hand, writing `<o>` for the overlay path: move `<o>.busbar-folding` back to `<o>` if it exists, else move `<o>.1.5.5` back.
A rollback that moves only `<o>.1.5.5` back loses the overlay a crash left at `<o>.busbar-folding`.
If both an ordinary overlay file and a folding copy exist, stop all writers and reconcile
which snapshot to restore before booting 1.5.5. Prefer restoring the complete backup rather
than reconstructing the deployment from individual recovery files.

## Configuration and persistence

### The old overlay moves into the Store

1.5.5's file overlay held administrative changes. On the upgrade boot, its effective contents
are folded into `config.yaml`; subsequent administrative changes use the configured Store.
`config.overlay` is retired; `config.locked` remains the switch for an immutable deployment.
See [overlay migration](migration-overlay-1.6.md).

The upgrade selects the old overlay as 1.5.5 did: `config.overlay.file`, otherwise
`BUSBAR_CONFIG_OVERLAY` when no selector was supplied, otherwise `busbar-overlay.json` beside
the config. A locked config has no overlay. A file that 1.5.5 could not write was not read by
that version and is not folded. Read the report naming the selected absolute path and whether
it was folded, absent or not writable. An unexpected absence needs investigation before you
accept the upgrade.

Groups, hooks, global hook attachments, supported named definitions, root overrides and
removals are folded. Conflicting definitions, invalid old shapes and unsupported default-hook
ordering refuse the upgrade rather than guessing. Old plugin rollback pins are dropped because
1.6.0 cannot load their 1.5.x artifacts. The original overlay is retained byte for byte and its
path is guarded with the marker directory described under rollback. Keep that guard while an
old executable could still be launched against the directory.

An unknown **top-level** key in an otherwise valid 1.5.5 overlay is dropped with a report naming
the key, matching the old reader's behavior. This does not relax validation of recognized fields,
current YAML or plugin settings. Invalid overlay JSON and unsupported overlay versions refuse
the upgrade; review the report and retained original before accepting the fold.

1.6.0 checks the overlay only on this one upgrade boot. A stamped boot does not read that old overlay file or its environment selector. The CLI option
`--safe-mode` is removed and returns a usage error. After migration, `--ignore-overlay` boots
from the base configuration alone and leaves the **Store** overlay untouched; boot without it
to apply the stored configuration again.

### Every configuration names its Store

A current configuration requires `store.module`; an omitted Store is not a default selection.
When upgrading a store-less 1.5.5 config, migration names the build's single linked ephemeral
Store. A standard build with that implementation produces `store: { module: memory }`.
A build with no such implementation, or several, refuses and asks you to name one.
An ephemeral Store loses its state on restart; the migration does not make it durable.

The local `.wal` segments and quarantine files are retired as persistence inputs.
Persistence belongs to the configured Store. Do not use a host journal directory as your
backup or recovery procedure.

### Environment inputs

Serving no longer uses these launch overrides. Boot and `--validate` refuse them with
`BUSBAR-3029` before configuration migration or validation, naming each replacement without
echoing its value. Write their intended values into configuration, then remove the variables
from the launcher and validate. No automatic environment capture or separate conversion command
is provided. An empty `BUSBAR_PROVIDERS` counts as unset; all other retired variables refuse
even when empty. This refusal prevents an HTTP/1-only or worker setting from silently changing
on upgrade; exact-artifact upgrade qualification remains required.

| Retired variable | Current configuration |
|---|---|
| `BUSBAR_PROVIDERS` | `providers_file:` |
| `BUSBAR_WORKER_THREADS` | `advanced.worker_threads` |
| `BUSBAR_UPSTREAM_HTTP1_ONLY` | `advanced.upstream_http1_only` |
| `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` | `advanced.upstream_h2_prior_knowledge` |
| `BUSBAR_CONFIG_OVERLAY` | One-time old-overlay selection only; no serving equivalent |

The 1.6.0 container no longer sets `BUSBAR_PROVIDERS`. Put `providers.yaml` beside the selected
config or name it with `providers_file:`. `BUSBAR_CONFIG` and `-c`/`--config` still select the
config; explicit `{ env: NAME }` secret references still resolve environment values.
`RUST_LOG` and the `TOKIO_WORKER_THREADS` fallback remain available. `BUSBAR_DATA_DIR` is still
used for registry data; it does not restore the retired journal.

### A configuration with no `auth:` block

1.5.5 booted a configuration with no `auth:` block (or an empty one) as an open relay: every
caller that could reach the listener used the configured provider credentials, with only a
banner. 1.6.0 never boots an open relay by omission: it refuses a configuration with no `auth:`
block (BUSBAR-8014).

The one-time upgrade does not write an `auth:` block for you. It reports the missing block as an
action item (BUSBAR-8014) and the first 1.6.0 boot refuses it. Both give the same remedy: add
`auth: { chain: [] }` explicitly to run an open relay, or configure a chain
(`auth: { chain: [keys] }` with virtual keys minted through the admin API).

`auth: { chain: [] }` is the one explicit open-relay acknowledgement. It is bannered on stderr and
logged at ERROR at every boot, and audited as `open_relay` in the `node.boot` event. The MCP
plane refuses to boot behind it.

### Grants and hooks

The migrator adds `auth.role_bindings.<provider>."*": {}` for non-key providers in `auth.chain`
that lack that binding. This explicitly preserves access 1.5.5 admitted without a grant and
prints a warning. Review and narrow it: the empty binding grants every pool without a group
or budget. Keep any deliberately configured per-role restrictions.

Hook definitions use `module:` and `phase: [...]`. Old overlay hooks are converted from
`plugin:` and `at:` during folding. For authored configuration or API requests, use the current
spellings; for example, `at: response` becomes `phase: [response]`. Read `fires_at` for effective
stages. An omitted phase list selects the four core phases, not every future phase.

Cloud-metadata exceptions `security.allow_metadata_hosts`, `security.allow_all_metadata` and
`providers.<name>.allow_metadata_hosts` (and the same key in a providers catalog) are removed with one
warning (BUSBAR-3411) that names every removed path and never an entry value, and an audit record
of the removed paths is written once the upgrade completes. No configuration admits
cloud-metadata destinations. `security.blocked_metadata_hosts` still extends the denylist;
entries that name no usable host are removed and reported.

### Recoverable credentials and literal secrets

A Store containing recoverable 1.5.5 credentials, such as SigV4 secret keys, requires a resolved
`auth.signing_key` before conversion. 1.6.0 seals those credentials under a key derived from
that signing key. Preserve the existing key and use the same key on every node sharing the
Store. If none is configured, follow the startup refusal to create a protected key file and
reference it with `auth.signing_key: { file: /absolute/signing.key }`, then retry 1.6.0. Keep
the key with the deployment's protected backups; replacing it prevents recovery of credentials
sealed under the previous key.

### Conversion and canonical settings

An unstamped configuration selects an explicit conversion boot. Each configured instance must
return its settled current settings; core validates and combines those answers before writing
the configuration. Temporary conversion planes are not published for serving. After core-record
processing and successful configuration write-back, the process closes its temporary owners and
re-executes onto the stamped files.

A stamped configuration selects canonical opens. This is not a second opportunity to fold an
old overlay or invent historical core settings. Supported settings normalization is validated
before guarded write-back; if that write fails, the authored file is retained and a warning is
logged. A stamp does not bypass Store format admission or plugin initialization.

The production boot now passes settled settings to the writer, including its literal-secret
externalization path (`0600` `.secret` files and references in place of literals). This source
integration is not complete release evidence: verify the selected artifacts' actual converted
settings, protected files and references, restart readback and reload behavior. Do not assume
that every literal in every configuration source has been externalized merely because boot
succeeded. Preserve the original secret sources until the converted deployment is verified.

### Transport security

Outbound connections require verified TLS unless the instance has an explicit, reasoned
exception. Loopback addresses and Unix sockets do not imply an exception. The upgrader does not
invent consent to plaintext or unverified TLS. Prefer enabling TLS and installing the required
trust anchor or pin. If an exception is intentional, add the applicable instance setting:

```yaml
insecure_transport: { accept: plaintext, reason: "<deployment-specific justification>" }
```

For encrypted transport with deliberately unverified certificates, the acceptance value is
`unverified_tls`. Follow the implementation's refusal and schema for where to place the setting.
Add it after stopping 1.5.5, which does not understand the new field. Store DSN details and
implementation-specific error codes belong to the selected kind's own documentation; do not
assume a code emitted by one implementation applies to another.

### Listeners without TLS

1.5.5 served the data listener (`listen`) and the admin listener (`admin_listen`) in plaintext
whenever `tls:` / `admin_tls:` was absent, with no acceptance and no audit. 1.6.0 refuses to boot
a listener without TLS unless its plaintext is accepted explicitly (BUSBAR-3172). No address is
exempt: the default loopback admin listener needs its acceptance too, so this affects almost every
1.5.5 configuration. The upgrader does not write the acceptance for you; the refusal names each
listener and its one-line remedy. Add TLS, or accept the plaintext deliberately in config.yaml:

```yaml
listen_insecure_transport: { accept: [plaintext], reason: "<deployment-specific justification>" }
admin_listen_insecure_transport: { accept: [plaintext], reason: "<deployment-specific justification>" }
```

The reason is required (one printable line, at most 256 characters, not the `<why>` placeholder)
and `plaintext` is the only word a listener accepts. A listener with TLS takes no acceptance:
writing both is refused. The acceptance is file-only; the Store overlay cannot set it. A 1.5.5
overlay `tls` folded by the upgrade satisfies the rule, and an overlay that sets TLS later makes a
file acceptance inert (the boot warns that it can be removed). Each listener served in the clear
prints an error banner at boot and writes a `config.insecure_transport_accepted` audit row with
resource `listener:<setting>:accept=plaintext`.

## HTTP endpoints and spend refusals

Configure clients to call a declared endpoint, including any explicitly configured prefix.
1.6.0 does not infer an inference endpoint from an arbitrary path suffix or an Anthropic
header. For example, `/v1/chat/completions` is declared; `/x/v1/chat/completions` returns 404
when `/x` is not configured. Unknown paths return the ordinary audited 404 without an
upstream request. Deliberately declared named-pool and provider/model paths remain routes;
their path parameters do not establish a general catch-all. A missing model or price on a
declared route remains a separate request error.

When an operator-configured monetary spend cap is exhausted, the LLM plane uses the caller's
native error contract:

| Caller API | HTTP status | Error body |
|---|---:|---|
| Anthropic Messages | 400 | `invalid_request_error` |
| OpenAI Chat Completions | 429 | `insufficient_quota` |
| OpenAI Responses | 429 | `insufficient_quota` |
| Gemini | 429 | `RESOURCE_EXHAUSTED` |
| Cohere | 402 | Native message envelope |
| Bedrock Runtime | 400 | `ServiceQuotaExceededException` |

Anthropic's spend-cap status changes from 429 to 400 and Cohere's from 429 to 402. The
Anthropic error type is `invalid_request_error`; a local operator cap is distinct from an
upstream payment failure. These are caller API conventions: HTTP itself reserves 402 for
future use and does not require it for every monetary limit.

Request/token/concurrency quota limits remain 429. For a spend refusal, review the configured
limit and its reset period before retrying. Busbar supplies `Retry-After` only when the
policy provides a known wait; a 429 alone does not promise that a short retry will succeed.
Refusals retain the normal audit and no-upstream-call behavior. This change adds no proprietary
client fields exposing internal policy identifiers.

## Administrative clients

Paths below are relative to `/api/v1/admin`, unless written in full. Use the running
`GET /api/v1/admin/openapi.json` and kind discovery to inspect the operations available in your
build. Update clients before accepting the upgrade.

| Removed path | Replacement |
|---|---|
| `/models`, `/providers` | `/kinds/core/instances/routing`, including its config and advertised views |
| `/pools`, `/pools/{name}` | The same routing instance's config and pool views |
| `/export`, `/export/{name}` | `/kinds/export/instances[/{name}]` |
| `/identity-providers`, `/identity-providers/{name}` | `/kinds/auth/instances[/{name}]` |
| Plane-specific `/tools…` and `/agents…` admin paths | The selected plane kind instance's advertised operations under `/kinds/{kind}/instances/{id}/ops/…` |
| `POST /signing-key/rotate` (it reported the key id and changed nothing) | None. Rotating the signing key is an operator action: replace `auth.signing_key`, restart every node in lockstep, and re-mint every key |

Start with `GET /kinds`, then `GET /kinds/{kind}/instances`, then the instance and its advertised
views and operations. Do not infer a kind name or operation from an artifact filename.
For configuration changes formerly made through removed exporter or identity-provider writes,
use `PUT /config/settings` and `POST /config/apply` with the appropriate configuration section.

Remove `persist` from settings and `document_patch` requests: it is rejected with 400. Accepted
changes use the Store; locked deployments refuse configuration mutations.

Config ETags are quoted `"<deployment_id>.<config_generation>"`, rather than a bare config
version. Treat them as opaque and return them verbatim in `If-Match`. A stale precondition
returns 409 `version_conflict` with `retryable: false`: re-read the resource, review the new
state and decide whether to submit a new mutation. Do not automatically replay the old write.

Errors have a top-level diagnostic `code` and an `error` object containing `code`, `reason`,
`message`, `request_id`, `retryable` and `details`. Clients reading `error.code` and
`error.message` can continue to do so. Core diagnostic codes use `BUSBAR-NNNN`; implementation
codes use `BUSBAR-<implementation>-NNNN`. Update log matching to accept the diagnostic prefix.

The engine always mints `X-Request-Id`, whatever the client sends. A valid
client id (1 to 128 of `[A-Za-z0-9._:-]`) comes back in `X-Client-Request-Id` and is kept on the
audit rows as `client_request_id`. Join on that, or on `trace_id` when you send a W3C `traceparent`.

`POST /restart` answers `{restarting, note}`; `supervisor_detected` is removed. `POST /adjust` answers carry the outcome in the body (`effect`, `receipt_durable`); the `x-busbar-adjust-effect` and `x-busbar-receipt-durable` response headers are removed.

Instance names must be unique across configuration sections and must not collide with core
instance IDs. Resolve a reported collision and update clients that select by instance name.

`GET /info` is this node's identity only. Its removed members and their replacements:

| Removed `/info` member | Replacement |
|---|---|
| `nodes[]` | The `core/process` view `nodes` (`/kinds/core/instances/process/views/nodes`), times in `*_ms` |
| `build` (`auth_modules`, `hook_plugins`, `weighted_floor`) | `/plugins` and `/kinds` show what is installed and running |
| `topology` | `/kinds` (`instance_count`) and the `core/routing` instance |
| `process_boot_nonce` | `incarnation` (same value) |
| `started_at`, `uptime_seconds` | `started_at_ms` |
| `config_version` | `config_generation` |
| `config_persistence` | The `core/durability` instance's `state.store.persistence` (`/kinds/core/instances/durability`) |
| `kinds_revision` | The `/kinds` ETag |
| `overlay_ignored` | A `warnings[]` entry with `code: "overlay_ignored"` |

`/info` gains `crypto` (`{validated_mode, validation}`). The crypto backend's name and module version,
which `/healthz` showed as `crypto_module`, are the `core/process` instance's `state.crypto`
(`{backend, module, api, validated_mode, validation}`, `/kinds/core/instances/process`).

## Usage and rate cards

Review prices explicitly. Migration removes root `cache_write_utok: 0`, the 1.5.5 spelling of
no separate write tariff, so writes price at `input_utok`. It adds newly declared open billable
units at zero where 1.5.5 billed nothing. The TTL-specific `cache_write_30m` and
`cache_write_12h` units instead take the resolved write rate, falling back to `input_utok`.
Read any report of an unrepresentable rate rather than assuming it was converted.

Rate-card changes price subsequent usage; they do not reprice booked usage. Corrections use
`POST /api/v1/admin/ledger/amend-rate-history`. The ledger exposes totals, checkpoints,
reconciliation and migration reads under `/api/v1/admin/ledger/`. Prices are abstract cost
units; do not add a currency field. See [the admin API](admin-api.md).

Card history follows the Store's durability. An ephemeral Store loses it on restart. Do not
rely on the retired host journal for rate-card recovery.

## Release-candidate checks

- Exercise the HTTP spend-cap matrix above through the actual listener and live policy.
  Confirm declared routes and configured prefixes, unknown/unconfigured paths returning 404,
  and refusal audit/no-upstream-call behavior. Renderer-only tests do not establish these
  end-to-end guarantees.

This section records required checks while 1.6.0 is in development. These are **not instructions
to add pre-release keys**. Replace this section with verified final behavior before release:

- Confirm the removal of core `upstreams` and `advanced.allow_destinations`, and the restored
  per-registration `allow_private` shape, including automatic migration and private-host policy.
- `auth.require_if_match` is the 1.6.0 spelling; `auth.policy.require_if_match` is refused as an
  unknown field (the kernel parser and the admin config form both place it at the auth level). List
  the removed `auth.policy` keys and fixed engine constants against the final strict schema.
- Confirm the removals of pool-level legacy fields, browser-login tuning, plugin log settings,
  credential-at-rest configuration and the remaining retired settings; distinguish automatic
  rewrites from required operator edits.
- Recheck optional rate-card units and the final unpriced-unit behavior; an old requirement to
  populate every `units` map must not be carried into the release procedure.
- Reconcile first-boot providers-catalog selection with the removal of serving environment
  overrides. Verify preservation or an explained refusal for each retired launch variable;
  a warning followed by different worker-count or upstream-protocol behavior is not sufficient.
- Recheck the final administrative resource model; a proposed replacement for `/config/settings`,
  `/config/apply`, RPC roots and instance `ops` must not be documented as implemented before it lands.

- Require direct CI migration evidence for each selected Store artifact: a real 1.5.5 dataset,
  initialization into the current format, preserved core records, interruption and retry,
  refusal of live old writers and newer data, and restoration of the pre-upgrade backup.
  Keep backend qualification open until those checks pass; fixture setup failures and partial
  migration tests do not qualify a backend.
- Qualify the restricted pre-serving admission and recovery protocol for shared core
  record-format changes; a warning followed by ordinary startup is not sufficient.
- Verify that plugin initialization results reach configuration write-back on the first boot,
  stamped boots and reloads, including literal-secret externalization and restart readback.
  The production MIN-3 boot now collects settled results and invokes the writer; this still
  requires direct through-boot evidence with the selected artifacts. A generic SDK fixture
  proves its own declared case, not a backend migration or real application readiness.
- Check kind operations, authentication-token migration, exports, plane behavior, telemetry
  attribute changes and Store rollback requirements against the final core and artifact cohort.
- Run the final docs-versus-code check at the release-candidate SHA, including every link,
  command, diagnostic, migration warning and supported upgrade/rollback path.

## Telemetry queries

The OTLP export implementation prefixes bare span and span-event attribute names with
`busbar.`: for example `pool` becomes `busbar.pool`, `request_id` becomes `busbar.request_id`,
and `target` becomes `busbar.target`. Keys already containing a dot, such as `service.name`
and `http.request.method`, remain unchanged. Update collector transforms, dashboards, alerts
and saved queries that select the old bare names. When both spellings occur in one record,
the bare field is preserved under `busbar.original.<hex>` (with `.original` suffixes as needed
for uniqueness), where `<hex>` encodes the original field name's UTF-8 bytes.

The old top-level `metrics:` configuration was already retired in 1.5.3; use an `export:`
instance. If it remains in your files, complete the older-version upgrade before this procedure.

## Retired TLS upgrade flag

`UPGRADE_VERIFY_OFF` is refused in 1.6.0 for every egress class, including operator
infrastructure. Plugins must use the Need API and its core-held
`insecure_transport` policy; a plugin flag cannot disable certificate verification.

### Declared upstream registrations

The core `upstreams:` and `advanced.allow_destinations` keys are removed. Keep each upstream's `url` or `command`, `tls`, `auth`, `upstream_credentials`, and optional boolean `allow_private` within the registration declared by its plane. Private reach applies to that registration only; it does not bypass metadata, own-listener, or TLS checks. A pre-release flat `upstreams:` document is refused with guidance rather than assigned to a plane by guesswork.

A legacy A2A `client_identity: {cert: ..., key: ...}` is refused without modifying the source config. Combine the certificate chain and private key into one PEM secret and use `tls: {client_identity: {module: file, settings: {path: /run/secrets/client.pem}}}` in the canonical registration. The plane cannot combine opaque references, and neither part is silently discarded.

Direct contract plugins must rebuild against the current 1.6 SDK. The retired host policy
callback has been removed; principal scope decisions use the plane `ENTITLE` intent. Admission
rejects artifacts carrying an earlier common host-table layout fingerprint.

### Removed pre-release limits and drain settings

The pre-release `limits.migration_index_bytes`, `limits.migration_value_bytes`,
`limits.datagram_line_memory_bytes`, `advanced.shutdown`, and `advanced.governance`
keys are refused. The current startup Store frame bound is fixed at 64 MiB;
datagram LINE pairings retain their former unlimited default. The shutdown drain
budget is fixed at 20 seconds and the governed settlement backlog cap at 20,000.
Released 1.5.5 configurations do not contain these pre-release settings.

## Other changes from 1.5.5

These changes were recorded as owner rulings or adopted designs. Each is a difference you can
see after the upgrade. Nothing here is carried back by an alias, a deprecated spelling or a
compatibility flag: 1.6.0 removes a 1.5.5 surface rather than keeping it beside the new one. The
[changelog](../CHANGELOG.md) lists the remaining behavior changes release by release.

### Command line

Core owns the whole command line; no plugin of any kind defines a flag.

- `busbar --stdio` serves the one configured plane line route on the process's own stdin and
  stdout, for a host that runs Busbar as a child process. Pre-release builds spelled the MCP
  form `--mcp-stdio`; that spelling is an unknown argument. See
  [the MCP stdio entry point](mcp.md#inbound-busbar---stdio).
- `--migrate-config`, `--migrate-overlay` and `--safe-mode` are gone, as described above.
  `--ignore-overlay` replaces `--safe-mode`.

### Listener TLS

A listener without TLS refuses boot unless the operator sets an explicit, audited acceptance.
There is no loopback exception, and the upgrade does not write the acceptance for you. The
refusal names the one-line fix. The data listener's acceptance is `listen_insecure_transport`
and the admin listener's is `admin_listen_insecure_transport`; each is stated with a reason, like
the outbound `insecure_transport` setting under [transport security](#transport-security).
Because 1.5.5's default admin listener is plaintext on loopback, a 1.5.5 configuration that
relied on it refuses its first 1.6.0 boot until you either configure TLS for that listener
or record the acceptance.

### Authentication, keys and sign-in

- **The admin token becomes a digest on the first boot.** The first 1.6.0 boot replaces the
  1.5.5 admin token (an `identity-providers.<name>.token:` secret reference) with a one-way
  SHA-256 digest in `config.yaml`, in the admin-tokens plugin's `settings: {sha256: [...]}`.
  Core resolves the reference once during the migration; the plugin never reads the 1.5.5 form.
  There is no opt-out and the boot warns. The digest is never logged; the audit label is
  `sha256[<index>]` plus the generation. Rotate the token through the admin API, not by editing
  the file. Keep the plaintext token wherever your clients read it from: Busbar no longer holds it.
- **`keys` is still core's.** Virtual keys are minted only by `POST /api/v1/admin/keys` for a
  principal holding `full` admin scope. No authentication plugin mints keys.
- **Operator plugins are first-party only.** `plugins.trust.operator` is reserved; a
  configuration that sets it is refused with a named error.
- **A node with a measured clock skew above 5 seconds refuses virtual-key and stateless-ticket
  admission.** The store's clock is the only expiry authority. 1.5.5 served these requests on
  any skew. A stale measurement does not refuse. Keep node clocks synchronized.
- **An identified principal that earns no grant is refused with `401`.** 1.5.5 admitted it
  ungoverned and booked its spend to `anonymous`. The migrator's wildcard role bindings,
  described under [grants and hooks](#grants-and-hooks), keep existing access; narrow them.
- **A key whose stored `expires_at` has passed is refused with `401`**, and the refusal is
  audited. 1.5.5 enforced only the signed token's own expiry.
- **A disabled key stays disabled and a revoked key is permanent.** A login or refresh no longer
  re-enables a key an administrator disabled, and a revoked key cannot be restored by a login,
  a refresh or an admin `PATCH`. The refusal answers `403` with `BUSBAR-4043`; the `PATCH` on a
  revoked key answers `409` with `BUSBAR-4044`. `DELETE` is still the reset.
- **The key refresh link rotates only from Busbar's own page.** `GET /auth/token?method=<m>&refresh=1`
  rotates only on a same-origin browser navigation; otherwise it re-shows the current key.
- **Sign-in is rate limited.** Hosted credential sign-in refuses repeated failures per account
  and per client source with `429`, and an administrator credential refused repeatedly is
  throttled. See the changelog for the limits and audit records.
- **An identity provider that is unavailable answers `503`, not `401`.** A rejected credential is
  still `401`.
- `POST /api/v1/admin/ledger/amend-rate-history` needs only a `full` admin grant;
  `auth.operator_pub` is gone, so stop signing corrections.

### Configuration reading

- **YAML is read as YAML 1.2.** A NEL character (U+0085) is content, not a line break, and an
  alias bomb is refused even inside a field that is otherwise ignored. 1.5.5 differed on both;
  the owner accepted the differences.
- **A configuration refusal begins with its diagnostic code and ends with a link.** Each line
  reads `BUSBAR-NNNN: <what is wrong>. See <link>`, under a header that carries its own code (for
  example `BUSBAR-3131` on an export definition, under `BUSBAR-3015`). Update scripts that match
  the bare 1.5.5 text.
- `RUST_LOG` is read strictly: an invalid value stops boot with `BUSBAR-9007`, where 1.5.5
  silently logged at `info`.
- A provider `api_key` reference that does not resolve refuses boot and any apply or reload.
  An upstream that needs no credential declares `api_key: none`; the migration does not insert it.
- `auth.policy.require_if_match` is spelled `auth.require_if_match`, and the browser-login
  `max_failures` setting is removed: the limit is fixed at 3.

### Plugins and diagnostics

- **1.5.5 plugins are refused.** Each plugin ABI version is its 1.5.5 value plus one and must
  match exactly. A 1.5.5 build, including the published 1.5.5 stores, is refused cleanly with an
  explanation, an audit record and a download link; rebuild or install the 1.6.0 release.
  Third-party authors follow the [SDK migration note](plugin-sdk-migration-1.6.md).
- **Plugin diagnostic codes are in plugin form.** Core codes are `BUSBAR-NNNN`. Every plugin,
  first-party or not, uses `BUSBAR-<PLUGIN>-NNNN`; a bad or duplicate declaration is refused for
  that plugin only, is audited, and boot continues. The 1.5.5 plugin codes 7070 to 7073 are now
  in that form. Update log matching.
- A URL-userinfo credential is sent only over a secured connection; http userinfo to a private
  host is refused at dial time and audited.

### Requests and callers

- **A request that repeats a key Busbar decides on is refused.** The LLM plane answers `400`
  with an audited refusal when the top-level JSON repeats `model`, `stream`, `max_tokens` or
  another routing or budget key, rather than forwarding the shadowed value.
- **A malformed rewrite under fallback forwards the original request unmodified** to the named
  fallback; it never forwards a half-rewritten one.
- **A Decisions policy hook that rejects returns the native interface's generic refusal**, not
  the hook's own message text. Status codes, refusal types and the no-upstream-call guarantee
  are unchanged.
- **Embedding floats are written as the shortest `f32` text.** A consumer that compared the old
  longer text byte for byte sees different digits for the same value.
- **A hook with `on_error: reject` whose transform fails answers `503`;** 1.5.5 passed the
  request through.
- **A request that asks for a stream gets a stream** in the caller's dialect, even when the
  upstream answered with one whole body.
- **An explicit operator-acknowledged open relay stays available** as an audited opt-in for pools
  that claim it; it is never the default.
- **Plane trust approvals are keyed by plane instance name** and their digests are written
  `sha256:<hex>`. A 1.5.5 A2A `fingerprint` in another form reads as drift until you approve the
  agent again.

### Support policy

Each `x.y` line receives security fixes until the later of 12 months after `x.y.0` or 6 months
after the next `x.y.0`. 1.5.5 is the only supported source for this upgrade.
