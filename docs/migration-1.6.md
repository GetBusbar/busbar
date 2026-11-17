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
> integration are listed under [release-candidate checks](#release-candidate-checks). This guide
> does not qualify any Store backend without complete, direct CI migration evidence. A
> successful build or ordinary Store test run does not establish upgrade or rollback safety.

The migration-specific behavior below is checked against core source
`04b89c2eb6680f5230577a605bb4a57936c54e81`; see [source notes](#source-notes).
This source snapshot is not a released or qualified artifact cohort. The supported upgrade
keeps a released 1.5.5 deployment's configuration through migrate-on-boot; it does not keep
removed CLI flags, administrative paths or pre-release configuration aliases.

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
3. Install the intended 1.6.0 executable and compatible external artifacts. A native artifact
   used before Store-backed admission, including an early grammar/check callback, requires
   its complete archive SHA-256 in the operator base `plugins.fetch` entry matching that
   archive's filename. A missing, conflicting or mismatched pin refuses loading. This is in
   addition to ordinary artifact integrity and publisher admission; a downloaded release
   index or an unread Store overlay cannot authorize its own bootstrap dependency. Linked
   implementations do not need an archive pin. See [plugin security](plugins.md#how-plugins-are-secured).
4. Start 1.6.0 with the deployment's config path, secret sources and working directory.
   Do not add `--ignore-overlay` to bypass an old overlay that still needs folding.
   For an unstamped config, do not use `--providers`: migration selects the catalog that
   1.5.5 selected, including a nonempty `BUSBAR_PROVIDERS`. See [environment inputs](#environment-inputs).
5. Read the migration reports and refusals. The first boot plans configuration changes,
   initializes the configured instances (each brings its own supported settings and data to
   its current format), migrates core-owned records through the opened Store, writes the
   accepted configuration and re-executes the executable onto the stamped files. It does not
   serve application traffic before that handoff completes.
6. Check readiness, sign-in and administrative access, normal requests and failover,
   Store recovery, export delivery and usage figures. Review every migration warning,
   particularly the wildcard role bindings described below. Remove retired launch variables
   once their intended settings are represented in configuration.

Use the installed executable with the deployment's actual paths and environment for the
first boot:

```sh
busbar --config /deployment/config.yaml
```

After conversion has produced a stamped configuration, an offline check is available:

```sh
busbar --config /deployment/config.yaml --validate
```

`--validate` judges the authored configuration; it does not run migrate-on-boot. It checks
configuration and artifact preflight and may execute authorized native grammar/check callbacks.
It does not start a server, open the application Store or recover its overlay, and it does not
prove backend reachability or serving readiness. After startup, check `GET /readyz` on the
configured listener and verify the application flows above. `GET /livez` reports liveness;
`GET /healthz` is observational.
Listener TLS and mTLS still apply. See [health and readiness](operations.md#health--readiness).

The original config is retained as `<config>.1.5.5`; the accepted config is stamped
`config_version: 1`. A matching stamp skips the one-shot file migration. A format newer than
the executable supports is refused. The config stamp does not skip a Store's own initialization
or data-version checks. Do not add a stamp yourself to bypass migration.

**A startup refusal does not mean the Store or configuration directory is unchanged.**
Planning checks existing configuration and overlay backup conflicts before instances open.
The final write repeats those checks under the directory lock; concurrent changes, a lock
failure or a later write failure can still refuse after a Store data conversion. The writer
can already have created protected secret files, a converted catalog or an overlay guard
before the new configuration is installed. A message about an unchanged YAML file, or
"nothing was written" for one failed operation, does not establish that the whole upgrade
had no effects. Fix the reported prerequisite and retry 1.6.0. Do not restart 1.5.5 against
that Store.
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

The upgrade selects the old overlay as 1.5.5 did: `config.overlay.file`, otherwise a nonempty
`BUSBAR_CONFIG_OVERLAY` when the selector is absent or null, otherwise `busbar-overlay.json` beside
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
The current production migration writes `store: { module: memory }` for a store-less 1.5.5
config, naming the Store that release implied. If that implementation is not installed and
admitted, boot refuses; it does not silently choose another Store.
An ephemeral Store loses its state on restart; the migration does not make it durable.

The local `.wal` segments and quarantine files are retired as persistence inputs.
Persistence belongs to the configured Store. Do not use a host journal directory as your
backup or recovery procedure.

### Publisher trust and native artifacts

Use `plugins.trust.allow_untrusted`, default off, for an explicit decision to admit unsigned
or unknown-publisher artifacts. A verified artifact from the installed Busbar root or a
configured publisher scoped to that plugin needs no separate third-party switch. Integrity
failures, invalid signatures from known publishers, revoked keys and incompatible ABI remain
refusals even with the opt-in; trust does not grant runtime permission.

The unstamped conversion rewrites old `allow_unsigned` and `allow_third_party` fields only
when both resolve to the same boolean (an omitted old field counts as false). A single enabled
old permission, a mix with `allow_untrusted`, or a publisher without explicit `plugins` and
`keys` scope refuses rather than broadening trust. Follow the refusal to make the operator's
trust decision explicit. Keep artifact enablement, publisher trust and the early archive pin
as separate requirements. See [plugin security](plugins.md#how-plugins-are-secured).

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
| `BUSBAR_PROVIDERS` | Captured on an unstamped upgrade boot; serving uses `providers_file:` or `--providers` |
| `BUSBAR_WORKER_THREADS` | `advanced.worker_threads` |
| `BUSBAR_UPSTREAM_HTTP1_ONLY` | `advanced.upstream_http1_only` |
| `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` | `advanced.upstream_h2_prior_knowledge` |

`BUSBAR_CONFIG_OVERLAY` is a separate one-time old-overlay selector, described above; a stamped
boot does not read it. It is not one of the four `BUSBAR-3029` launch-warning entries.

The 1.6.0 container no longer sets `BUSBAR_PROVIDERS`. Put `providers.yaml` beside the selected
config or name it with `providers_file:`. `BUSBAR_CONFIG` and `-c`/`--config` still select the
config; explicit `{ env: NAME }` secret references still resolve environment values.
`RUST_LOG` and the `TOKIO_WORKER_THREADS` fallback remain available. `BUSBAR_DATA_DIR` is still
used for registry data; it does not restore the retired journal.

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

- Exercise the declared upstream registration and private-reach rules below with the selected
  plane artifacts; a schema or source correction does not establish through-boot migration.
- `auth.require_if_match` is the 1.6.0 spelling; `auth.policy.require_if_match` is refused as an
  unknown field (the kernel parser and the admin config form both place it at the auth level). List
  the removed `auth.policy` keys and fixed engine constants against the final strict schema.
- Confirm the removals of pool-level legacy fields, browser-login tuning, plugin log settings,
  credential-at-rest configuration and the remaining retired settings; distinguish automatic
  rewrites from required operator edits.
- Recheck optional rate-card units and the final unpriced-unit behavior; an old requirement to
  populate every `units` map must not be carried into the release procedure.
- Verify the first-boot providers-catalog capture and preservation or an explained refusal for
  each remaining retired launch variable. A warning followed by different worker-count or
  upstream-protocol behavior is not sufficient.
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

### Audit verifying-key pages

`GET /api/v1/admin/audit/keys` now returns public keys under `items` with
`next_cursor`, while retaining its algorithm, signature domain and recipe metadata.
Pass `limit` (default 200, maximum 1000) and follow `next_cursor` until it is null.
Keys are ordered by `key_id`; only public verifying material is returned.

## Source notes

The links below are pinned to the inspected core snapshot
`04b89c2eb6680f5230577a605bb4a57936c54e81`. They support the migration-specific distinctions
in this guide and the [overlay guide](migration-overlay-1.6.md). They establish source behavior,
not execution results. An installed artifact, a plugin backend and a complete deployment each
need their own evidence; the release-candidate checks above remain open until that evidence
exists for the final cohort.

| Migration claim | Pinned source |
|---|---|
| No-stamp conversion, current/newer stamp admission, `--providers` refusal and re-execution | [Root migration seam][source-root-migrate], [format stamp][source-format] |
| Offline validation reads authored input, can run authorized callbacks, and does not run the migration/server | [CLI parser, help and validation path][source-cli] |
| Retired launch-warning table, empty providers-variable behavior and no value logging | [Launch environment handling][source-env] |
| First-boot providers precedence, captured absolute path, stripped catalog and retained source | [Catalog planner/writer][source-catalog] |
| Literal implied Store in the production facts path versus optional declaration-based selection | [Production facts][source-root-migrate], [facts defaults][source-migrate], [step dispatch][source-steps], [absent-Store pass][source-store] |
| Base archive filename/hash authorization, linked exemption and retained native admission proof | [Bootstrap archive checks][source-bootstrap], [native load guard][source-boot] |
| Single untrusted opt-in, hard integrity/signature/revocation refusals and scoped publisher trust | [Artifact trust policy and verification][source-trust], [config conversion/refusals][source-conversions] |
| Overlay selector, writability, fold/refusal rules, size bound, recovery files and marker guard | [Overlay migration][source-overlay], [hook conversion][source-overlay-hooks] |
| Plan-time backup checks, repeated locked checks, secret/catalog/guard writes before YAML replacement | [Migration plan and writer][source-migrate], [secret writer][source-settle] |
| Core-owned metadata, wildcard-role and opening-price conversions | [Core config conversion passes][source-conversions] |
| Plugin-settled settings and protected literal-secret files | [Settled settings and secret writer][source-settle], [root write-back integration][source-root-migrate] |

Shared core record-format maintenance, the final administrative resource model and the selected
plugins' own upgrade behavior must be rechecked with their integrated producers and consumers.
The operator preconditions in this guide do not assert that those pending protocols are active.
In particular, a library helper, a draft design or a successful build is not a shipped upgrade path.

[source-root-migrate]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/busbar/src/root/migrate.rs
[source-format]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/busbar-contract/src/upgrade.rs
[source-cli]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/busbar/src/root/cli.rs
[source-env]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/busbar/src/root/retired_env.rs
[source-catalog]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/busbar-migrate/src/catalog.rs
[source-migrate]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/busbar-migrate/src/lib.rs
[source-steps]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/busbar-migrate/src/steps.rs
[source-store]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/busbar-migrate/src/absent_store.rs
[source-bootstrap]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/busbar-kernel/src/appbuild.rs
[source-boot]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/busbar/src/root/boot.rs
[source-trust]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/plugin-loader/src/sign.rs
[source-conversions]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/busbar-migrate/src/migrate_1_6.rs
[source-overlay]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/busbar-migrate/src/overlay.rs
[source-overlay-hooks]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/busbar-migrate/src/overlay_hooks.rs
[source-settle]: https://github.com/GetBusbar/busbar/blob/04b89c2eb6680f5230577a605bb4a57936c54e81/crates/busbar-migrate/src/settle.rs
