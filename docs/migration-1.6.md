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

The original config is retained as `<config>.1.5.5`; the accepted config is stamped
`config_version: 1`. A matching stamp skips the one-shot file migration. A format newer than
the executable supports is refused. The config stamp does not skip a Store's own initialization
or data-version checks. Do not add a stamp yourself to bypass migration.

**A startup refusal does not mean the Store is unchanged.** Planning refusals happen before
instances open, but a later failure can follow a Store data conversion or an overlay guard
write. Fix the reported prerequisite and retry 1.6.0. Do not restart 1.5.5 against that Store.
If a backup or generated catalog already exists with different bytes, preserve it and
investigate the conflict; do not overwrite it to force the upgrade through.

## Rolling back

Stop every 1.6.0 process. Restore the complete pre-upgrade Store backup and configuration
snapshot together, including the providers catalog, credential files, overlay and old launch
settings. Then start 1.5.5. Changes made after the upgrade are not carried back.

Restoring only `config.yaml.1.5.5` does **not** undo Store migrations. Restore the old overlay
path too: the upgrader may have replaced it with a directory containing `busbar-1.6-folded`.
An interrupted fold can leave the original bytes at `<overlay>.busbar-folding`; a completed
fold keeps them at `<overlay>.1.5.5`. Preserve these recovery files until rollback is complete.
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

A stamped boot does not read that old overlay file or its environment selector. The CLI option
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

Serving no longer uses these launch overrides. Write their intended values into configuration;
there is no separate conversion command to run.

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
`providers.<name>.allow_metadata_hosts` are removed and reported. No configuration admits
cloud-metadata destinations. `security.blocked_metadata_hosts` still extends the denylist;
entries that name no usable host are removed and reported.

### Literal secrets

An implementation can identify a literal secret in its old settings for externalization. Core
writes that secret to a `0600` file beside the config and replaces the setting with a secret
reference. Back up these generated `.secret` files with the migrated configuration, preserve
their permissions and mount them wherever the deployment runs. The migration report names the
location without printing the secret.

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

Instance names must be unique across configuration sections and must not collide with core
instance IDs. Resolve a reported collision and update clients that select by instance name.

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

This section records required checks while 1.6.0 is in development. These are **not instructions
to add pre-release keys**. Replace this section with verified final behavior before release:

- Confirm the removal of core `upstreams` and `advanced.allow_destinations`, and the restored
  per-registration `allow_private` shape, including automatic migration and private-host policy.
- Confirm `auth.policy.require_if_match` becomes `auth.require_if_match`, and list the removed
  `auth.policy` keys and fixed engine constants against the final strict schema.
- Confirm the removals of pool-level legacy fields, browser-login tuning, plugin log settings,
  credential-at-rest configuration and the remaining retired settings; distinguish automatic
  rewrites from required operator edits.
- Recheck optional rate-card units and the final unpriced-unit behavior; an old requirement to
  populate every `units` map must not be carried into the release procedure.
- Reconcile first-boot providers-catalog selection with the removal of serving environment
  overrides. Verify exactly which old variables the final migrator consumes.
- Recheck the final administrative resource model; a proposed replacement for `/config/settings`,
  `/config/apply`, RPC roots and instance `ops` must not be documented as implemented before it lands.

- Require direct CI migration evidence for each selected Store artifact: a real 1.5.5 dataset,
  initialization into the current format, preserved core records, interruption and retry,
  refusal of live old writers and newer data, and restoration of the pre-upgrade backup.
  Keep backend qualification open until those checks pass; fixture setup failures and partial
  migration tests do not qualify a backend.
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

Direct contract plugins must rebuild against the current 1.6 SDK. The retired host policy
callback has been removed; principal scope decisions use the plane `ENTITLE` intent. Admission
rejects artifacts carrying an earlier common host-table layout fingerprint.
