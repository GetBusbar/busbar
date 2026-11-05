# Admin API v1: drive Busbar over HTTP

Everything Busbar knows about itself (its topology, its hooks, its auth posture, its live health, its keys, its limit groups, its metering) is readable and mutable over one authenticated, versioned HTTP surface: **`/api/v1/admin`**. Point `curl`, Terraform, a dashboard, or your own tooling at it and build against a contract that does not move.

---

## Authentication & scopes

Every `/api/v1/admin` request is authenticated by the **`admin_auth:` chain** (default `[admin-tokens]`, the single operator admin token). Present the credential as either header:

```
x-admin-token: <token>
Authorization: Bearer <token>
```

A missing or wrong credential is `401 unauthorized` (in the same JSON error envelope as every other admin error) on every endpoint. `admin_auth: []` is the explicit open dev posture (anonymous, full authority); external identity providers (SSO/AD, each a `kind: auth` plugin defined under `identity-providers:`) slot into the same chain by name. Admin requests deliberately bypass virtual-key governance: the operator credential manages keys, it is not one.

**Authorization is two scopes** on the authenticated principal, derived from **method + path, never the request body** (a crafted body cannot escalate): `read-only` (reads) and `full` (everything else).

| Scope | May | Notes |
|---|---|---|
| `read-only` | Every `GET`, **plus `POST /config/validate`** (a stateless dry-run: a read in POST clothing, so a read-only CI token can lint configs) **and `POST /plugins/inspect`** (a stateless preview of a candidate plugin tarball: it verifies its signature and returns its manifest/schema without ever installing it) | Satisfied by `full` too |
| `full` | Every mutation: keys (mint + lifecycle), the `groups:` limit tree, hook registration, config apply/reload/rollback, the admin auth chain, cache flush, overlay reset | Satisfies every requirement |

The check is a simple two-level test: `read-only` satisfies every read; every mutation needs `full`. A `max_admin_scope: read-only` ceiling on an identity-provider DEFINITION caps that provider's principals to reads regardless of what `role_bindings` grants. The accepted ceiling tokens are exactly `read-only` and `full`. Anything else (including `none`) fails `--validate`/boot; an OMITTED `max_admin_scope` is the most restrictive default, `read-only`. To deny admin entirely through a provider, grant no `admin_scope` in its `role_bindings`. An unbound role, or a bound role with no `admin_scope`, grants nothing.

The operator admin token holds `full`. Role-carrying principals (external identity providers) get the highest scope their bound roles grant under `auth.role_bindings.<provider>`, capped by that provider's `max_admin_scope:`; unbound roles grant nothing. Insufficient scope is `403 forbidden` naming the scope that would have sufficed. Unknown HTTP methods fail closed to `full`.

A role may instead (or as well) be granted admin verbs ONE BY ONE with `verbs:` on its binding (1.6.0): `verbs: "*"` is exactly `admin_scope: full`, and `verbs: [get_keys, post_keys]` admits exactly those operations, each whatever scope it needs. Operations are named by the closed verb table's snake-case names (`get_audit`, `post_config_apply`, `verify`, `get_ledger_totals`, …). A verb the list does not name is the same `403 forbidden` an insufficient scope gets. A binding without `verbs:` behaves exactly as in 1.5.5. See [configuration.md](configuration.md).

**Mutation rate limits.** Mutations are budgeted per principal in fixed one-minute windows, spent *before* the handler runs (failed attempts count, anti-enumeration):

| Class | Budget | Covers |
|---|---|---|
| config | 10/min | `POST /config/apply`, `PUT /config/settings`, `POST /config/reload`, `POST /config/rollback`, `PUT /admin-auth`, `DELETE /overlay/{section}`, `POST /plugins/reload`, `POST /plugins/rollback`, `POST /restart`, and the named-definition-map writes `PUT /identity-providers/{name}`, `PATCH /identity-providers/{name}/settings`, `DELETE /identity-providers/{name}`, `PUT /export/{name}`, `PATCH /export/{name}/settings`, `DELETE /export/{name}`, `PUT /tools/{name}`, `PATCH /tools/{name}/settings`, `DELETE /tools/{name}`, `PUT /agents/{name}`, `PATCH /agents/{name}/settings`, `DELETE /agents/{name}`, plus the MCP trust verb `POST /tools/{name}/connect` and the A2A trust verbs `POST /agents/{name}/connect` and `POST /agents/{name}/approve` (the blast-radius set: each rebuilds and swaps the whole App. The trust verb does not rebuild it, but it reaches an operator-named endpoint on the estate and replaces the recorded observation, which can demote a server, so it takes the same 10/min budget rather than the 6x-looser CRUD one; the A2A pair is the same shape: the preview reaches the registered agent's card endpoint, and the approval moves a registration into service) |
| CRUD | 60/min | every other mutation: hooks, keys, groups, cache flush, and the 1.6.0 mutating verbs (`adjust`, `ledger/amend-rate-history`, `ledger/recovery/list`, `ledger/recovery/resolve`, `plane-record-write`, `commit-upgrade`, `chain-break`, `store-restore`, `trust/approve`, `trust/revoke`), **and `/config/validate`** (a dry-run never contends with the config budget) |
| plugin-inspect | 30/min | `POST /plugins/inspect` ONLY. It gets its own dedicated bucket, not the shared CRUD budget (decompressing + parsing an attacker-controlled archive is a heavier, mutation-like cost profile per call than an ordinary CRUD mutation, and a fleet-wide upgrade preview would otherwise burn the same 60/min an operator needs for real mutating work in that window) and not unmetered either, despite being `read-only` scope |

Over-budget is `429 rate_limited` with a **`Retry-After: 60`** header, and the event is audited. Reads are unmetered.

**The static admin token is one shared principal.** Per-principal budgeting is only as isolating as the principal identity, and the built-in `admin-tokens` module ([GetBusbar/busbar-auth-admin-tokens](https://github.com/GetBusbar/busbar-auth-admin-tokens), linked into the default build at a pinned rev) maps *every* successful static-token authentication, regardless of which holder presented it, to the same constant principal id, `"admin"`. So if you hand the one static token to busbar-ui, your CI, your Terraform, and an operator's `curl`, they all collapse onto that single principal and **share one bucket per class** (10/min config-mutation, 60/min CRUD, 30/min plugin-inspect): a script hammering one of them can 429 the others, and the two are indistinguishable from the response alone. Failed attempts also spend budget (deliberate, anti-enumeration), which sharpens this. If you need per-caller isolation and attribution, don't fan the static token out to multiple automations. Authenticate them through a **role-bound external admin module** instead (OIDC/SSO/AD; see `admin_auth:` above and `auth.role_bindings.<provider>`). Role-carrying principals from an external module get distinct principal ids and therefore distinct rate buckets.

## Security-sensitive config and queued effects

Named edits, whole-config apply, document pointers (including parent replacement and removal),
overlay reset, rollback and reload share the semantic config transaction policy. A named verb
such as `put_config_settings` permits ordinary configuration edits; it does **not** confer full
operator authority. Changes to authentication chains, role bindings, identity-provider definitions,
credential/secret sources, transport security or plugin trust require a whole `full` grant
(`admin_scope: full` or `verbs: "*"`), capped by the identifying provider. The engine derives this
from the authenticated grant, never from a subject spelling such as `admin`.

Even a full operator cannot raise an identity-provider ceiling through the API, replace an
existing hook's immutable kind/prompt/user grants, or change a protected nonempty admin chain to
an empty one. Configure the intentional open development posture at startup. A chain replacement
must preserve this operator's full access under the proposed chain. These checks compare resolved
candidates before builder plugin/provider opening and generations before persistence and publication, so broader document representations are not an
alternate permission path. Boot and internal kernel maintenance are not administrative requests.

Config, detached credential and root-owned mutation work carries its original authenticated
identity to effect admission. The shared admission gate serializes not-yet-started work with
local configuration-policy publication; queued work authenticates again against the current
chain and must retain the same principal, asserted role set and operation grant. A changed role set
requires a fresh request; old request roles cannot continue feeding credential mint ceilings. The config worker rechecks after
its blocking-work queue and before persistence. Failure before admission returns `forbidden`
without the requested effect. Provider unavailability also fails closed at this boundary.
Once an effect has been admitted, local policy publication waits for its custody section;
revocation cannot undo an already committed Store write. Completion and retained receipt
reconciliation continue to report the actual outcome. HTTP cancellation is not rollback.

This is a **local engine admission** guarantee, not instantaneous fleet or issuer revocation.
An external admin provider is called again, but its own cached JWKS, introspection, role and
revocation data determine what it can observe; operators must qualify the pinned provider's
expiry, refresh, outage and revocation behavior. The shared static operator credential still
identifies all holders as the same full-authority operator. Data-plane virtual-key revocation
is a separate mechanism: it is applied synchronously on the writing node, while peers may serve
the prior set during refresh (five-second staleness windows, approximately two windows with a
healthy Store; freshness can degrade during Store outage). No credential-provider or fleet-wide
instant revocation claim follows from a successful local mutation.

## The error contract

Ordinary `/api/v1/admin` refusals (including 401, unmatched-path 404, and wrong-method 405) use this shape. The explicitly selected durable `/adjust` action profile can instead return its typed outcome body at non-2xx statuses. Branch on known `code` values and preserve unknown strings; never branch on human-facing `message`:

```json
{ "error": { "code": "not_found", "message": "pool `west` not found" } }
```

| `code` | HTTP | Meaning |
|---|---|---|
| `not_found` | 404 | The named resource (or path) does not exist |
| `unauthorized` | 401 | No or invalid admin credential |
| `method_not_allowed` | 405 | The path exists, but not with this method |
| `forbidden` | 403 | Authenticated but under-scoped (the message names the sufficient scope) |
| `invalid_request` | 400 | Malformed body, bad parameter, malformed `If-Match`, or a malformed pagination cursor |
| `version_conflict` | 409 | **Retryable**: your `If-Match` is stale, re-read for a fresh ETag and retry |
| `conflict` | 409 | State/precondition refusal. Recovery is operation-specific: base ownership and immutable grants require a changed proposal; an in-flight replay or config race requires reconciliation before retry |
| `unpriced_class` | 409 | **Terminal**: a usage read (`GET /usage`, `/groups/{name}/usage`, `/keys/{id}/usage`) hit a billable class or lane the rate card in force names no price for, so the figure cannot be priced (see [configuration.md](configuration.md#per-plane-rate-cards-toolsrate_card-agentsrate_card-streamsrate_card-decisionsrate_card)) |
| `idempotency_mismatch` | 409 | The caller action is already bound to different exact request bytes; no second effect |
| `mutation_applied` | 409 | The named key mutation committed; subsequent cache/readback reconciliation failed. Read the typed effect/recovery fields |
| `action_in_flight` | 409 | A durable adjustment action was claimed but its receipt binding is not available; reconcile, never start another delta automatically |
| `request_too_large` | 413 | Admin request exceeds the listener body limit |
| `rate_limited` | 429 | The principal's per-minute mutation budget is spent (`Retry-After: 60`) |
| `internal` | 500 | An internal failure (details are logged server-side, never returned) |
| `unavailable` | 503 | The node could not take the request into its administrative loop, or could not record what the operation would do (an administrative write that cannot be journalled is not performed). Retry later |

`version_conflict` names stale revision intent. Reread and review the new proposal before resubmitting; do not automatically rebase an approved mutation. `conflict` recovery depends on the operation, never message parsing.

## Pagination

Every list endpoint speaks one envelope: `{ "items": [...], "next_cursor": "..." }`. `next_cursor` is nullable: a string means more rows, null means the observed end; round-trip it verbatim into `?cursor=`. It is **opaque** by contract (never parse it). A malformed cursor is `400 invalid_request`. The legacy offset cursor is not bound to an operation or filter, so a syntactically valid token from another legacy list may be accepted. Lists are live observations: insertion/removal between pages may duplicate or skip rows; deduplicate identities and do not claim snapshot completeness. `?limit=` bounds the page:

| List | Default limit | Cap |
|---|---|---|
| `GET /keys` | 200 | 1000 |
| `GET /audit` | 200 | 1000 |
| `GET /config/versions` | 100 | 1000 |
| `GET /groups` | 200 | 1000 |

The topology reads (`/pools`, `/models`, `/providers`, `/hooks`, `/plugins`) return the same envelope in a single page (`next_cursor: null`). They are bounded by static config. `/groups` is cursor-paginated like `/keys`/`/audit`/`/config/versions` instead: `plan_mint_group` auto-provisions a leaf group per self-service key mint, so the group tree grows at runtime and is not safe to return unbounded.

Numeric limits on legacy keys/groups/audit/versions lists are clamped to 1–1000. Groups/audit/versions use their default for malformed values; keys refuses malformed values. These existing parser differences remain part of v1.

### Audit coverage and bounded range retrieval

`GET /audit` remains the newest-first, filtered live offset inventory of the admin
mutation ring (at most 1000 retained entries). Its additive `returned_from` and
`returned_to` identify the actual page bounds; `retained_from`, `retained_to` and
`retention_limit` describe the unfiltered ring captured under the same lock.
All these new exact quantities are decimal strings, with null bounds for empty sets.
`semantics: "live_offset"` and `complete: false` explicitly prohibit treating a
finished traversal as a complete audit. `truncated` means matching rows remained
in that observation. Concurrent appends and evictions can duplicate or skip rows;
a null `next_cursor` is only the observed end. A syntactically valid legacy offset
cursor is not bound to its list or filters; foreign-token rejection is not promised.

`GET /audit/range?from=F&to=T` reads the **separate sealed unit audit chain**, in
ascending audit position. Keep the original inclusive `from` and `to` unchanged
and round-trip each `next_cursor` as `cursor` until it is null, even if `records`
is empty. The first page pins `snapshot_to` to the lesser of `to` and the captured
chain tip. This is `semantics: "bounded_live_range"`: later appends do not extend
the range, but retained storage can change between requests. No snapshot is held.
The cursor is scoped to the node, incarnation and requested bounds; malformed,
mismatched or expired-incarnation cursors receive `400 invalid_request`.

Legacy `from`/`to` continue to echo the request. New `returned_from`/`returned_to`
are actual returned bounds (null on an empty page). `truncated` means further
bounded scanning is required, and is equivalent to non-null `next_cursor`.
`complete` is true only on a terminal page after this traversal observed every
requested audit position; it does not certify signatures or guarantee retention
for later reads. `incomplete` carries forward a detected gap or missing/oversized
journal record. `gaps` lists newly detected missing inclusive audit intervals,
including an unsealed requested tail. Do not infer completeness from HTTP 200,
requested bounds, an anchor, a full page or an empty page. Deduplicate by chain
identity and position, verify hashes/signatures, and preserve coverage metadata.
Audit positions are 1-based; `from=0` includes the first position without inventing
an audit record at zero.

Each stored page examines at most 64 journal positions, at most 256 parts of 512
bytes per position, with no rescan/retry against concurrent appends. Store calls
run outside the durability lock. The ring fast path returns at most 1024 records;
the memory-only journal is bounded by its existing 8192-record capacity.
`scanned_positions` and `scan_limit` expose the Store position work bound. This
bounds call count and scanned bytes, not a Store plugin's response latency.
Missing or oversized records mark `incomplete`; malformed, unreadable or corrupt
records refuse the read rather than silently skipping them. Each record's journal
digest is checked; this paged read is not a whole-journal verification operation.

`retention.ring_from`/`ring_to` identify the ring at page capture. The Store does not
publish an audit retention floor, so `durable_from` is null and
`durable_from_known` is false. A requested older range is scanned and any missing
coverage is reported explicitly. All new sequence/scan values and gap endpoints
are exact decimal strings; existing numeric envelope fields retain their wire
format. The published anchor is at or before the pinned upper bound; its history
may itself be pruned, in which case it is null. This sealed unit chain does not
replace the separate admin mutation ring.

## Exact-number client profile

`x-busbar-exact-numbers.profile: lossless-number-token-v1` describes the legacy numeric wire. Parse raw JSON integer/decimal tokens losslessly before binary64 conversion. Existing Count values are signed i128 mantissas at scale 6 (range -170141183460469231731687303715884.105728 through 170141183460469231731687303715884.105727). Existing u64 counters range from 0 through 18446744073709551615. For example, `9007199254740993` and `9007199254.740993` must survive parsing unchanged. An already rounded JavaScript Number cannot be repaired later.

Count units follow the field's billable class; `spend_cents`, `spend_micros` and ledger nano-units are distinct. The schema marks exact fields with `x-busbar-exact-number`; a double format is not promised for Count. New exact quantities use decimal strings. Existing numeric fields retain their numeric wire types; a browser adapter delivers exact strings after raw-token parsing.

## Concurrency: ETag + If-Match

Optimistic concurrency is **one mechanism across the whole surface**: the RFC-7232 `If-Match` header; there is no body-level `expected_version` twin:

- **Config plane** (hooks, groups, config, admin-auth): the ETag is the config version, quoted: `ETag: "42"`. It rides on `GET /hooks`, `GET /hooks/{name}`, `GET /groups`, `GET /groups/{name}`, `GET /config`, `GET /admin-auth`, and on **every successful config-plane mutation response** (including the `204` from a hook or group DELETE), so a scripted mutation chain never needs a re-read.
- **Keys**: each record's ETag is a 16-hex-char digest of its mutable metadata, returned in the `ETag` header of `GET /keys/{id}`. `PATCH` and `DELETE /keys/{id}` accept it.
- `If-Match: *` matches unconditionally (no guard); an absent header is also unguarded.
- A stale tag is `409 version_conflict` and nothing changes. A **malformed** `If-Match` is `400 invalid_request`. A broken guard never silently passes as "no guard".

Guarded mutations: `POST /hooks`, `PUT|DELETE /hooks/{name}`, `PATCH /hooks/{name}/settings`, `POST /groups`, `PUT|PATCH|DELETE /groups/{name}`, `PUT /admin-auth`, `POST /config/apply`, `POST /config/rollback`, `PUT /config/settings`, `PATCH|DELETE /keys/{id}`. Deliberately unguarded: `validate` (stateless), `reload` (returns to disk truth unconditionally), `cache/flush`, key create/rotate (no versioned resource).

Plugin artifact preconditions are independent of the config generation: an install may replace an archive without incrementing `config_version`. A disk-backed `PluginView.archive_sha256` is the SHA-256 of the complete `.tar.gz` bytes read for that catalog response, not the digest of its library or the loaded generation. Rows without a readable archive omit it. Send `expected_archive_sha256` in the rollback JSON body, or as the query parameter on `DELETE /plugins/{file}`. It must be exactly 64 lowercase hexadecimal characters. Omission preserves unconditional behavior; explicit null in the rollback body is invalid. A changed or missing guarded archive returns `409 conflict` before deletion, pin persistence, rebuild, or publication. Install, inventory read, comparison, and mutation share the engine's config transaction; external filesystem writers are outside that process-local serialization.

`POST /restart` accepts the same optional `If-Match` config-version header. The comparison and drain admission happen under the config mutation lock. A stale version returns `409 version_conflict` without requesting a drain; malformed headers return 400. Omission or `*` remains unconditional. The existing `confirm` and supervisor checks still apply. This fences the generation at admission, rather than promising that no later configuration request can arrive during draining.

## Discovery

```
GET /api/v1/admin/openapi.json
```

The OpenAPI 3.1 schema of the whole surface: generate a client, or point tooling at it. Every path it lists resolves (a node serves it filtered to the planes it configured — see below); its known error-code enum covers the envelope above (clients tolerate future strings); every operation is annotated with `x-busbar-required-scope` from the same matrix the middleware enforces (all three are test-locked). Browse it rendered, endpoint by endpoint, in the [API reference](https://getbusbar.com/docs/api/).

### Configuration form schemas

The same document publishes `x-busbar-config-schemas` with `version: 1` and
`context: "user_configuration"`. Its `schema` is a standalone JSON Schema 2020-12 document:
extract that object before resolving its local `#/$defs/...` references. The document declares
`x-busbar-settings-profile: "integer-token-v1"`; numeric fields marked
`x-busbar-integer-token` require the original signed or unsigned integer token, not a decimal or
exponent spelling of the same number. Preserve exact integer values when parsing and editing.

| Configuration path | Definition under `schema.$defs` | Owning grammar |
|---|---|---|
| `auth` | `Auth`, `AuthPolicy`, `MintCeiling`, `RoleBinding` | Host auth input parser and policy prepass; role bindings are nested by provider, then role |
| `identity-providers.<name>` | `IdentityProvider`, `BrowserLogin` | Host wrapper; the named module owns `settings` |
| `export.<name>` | `Export` | Host wrapper and actual export projection resolver; the module owns `settings` |
| `providers.<name>` | `ProviderDeployment` | Deployment override parser; `api_key` is a required SecretRef |
| Separate provider catalog entry | `ProviderCatalogEntry` | Catalog parser; `protocol` and `base_url` are required |
| `models.<name>` | `Model` | Shared typed model input parser |
| `pools` / `pools.<name>` | `Pools` / `PoolDocument` | Owning section/pool grammar, including reserved section keys, member shorthand and the document parser’s null-to-empty collection behavior; `Pool` describes direct JSON input |
| Host secret-reference fields | `SecretRef` | Actual core SecretRef grammar; never an inline credential |

The export schema derives its producer capabilities from the resolver: supported streams are
`metrics`, `logs`, `traces`, and `events`. `durable: true` is rejected because durable spooling is
unimplemented. Explicit `fields` is an exhaustive replacement; currently only `events` supports
it, and `seq`, `ts`, and `prev_hash` must remain. Module-specific carried streams and omitted-stream
defaults are checked when the normal configuration resolver knows the selected module.

This is a partial user-input document, explicitly marked `x-busbar-partial: true`, rather than a
complete boot certificate. The extension's `ownership` map and each schema's
`x-busbar-runtime-validation` identify checks that require installed modules, plane declarations,
references, resolved secrets or cross-field policy. Other plane sections and protocol-specific
provider options retain their declaring parser's ownership. An installed module's lifecycle
`settings_schema` describes the settings after host secret resolution; it does not replace the
user-input wrapper or authorize copying secret material into a form. Opaque options remain opaque.

### Pinning a released schema

Core authoring definitions now include `Group`, compact `Limit`, `ChildDefault`, admin/overlay `Hook`, and deploy `HookDefinition`. Admin group/hook bodies reference ordinary `ConfigInput*` OpenAPI components for generated clients. The deploy named hook wrapper differs from admin `HookCfg`: `default`, `signals`, `global` and legacy `at` belong to runtime/admin Hook, not deploy HookDefinition. Runtime module selection, fallback/tree references and current policy remain canonical validation requirements. Dynamic settings remain module-owned and are validated after SecretRef resolution.

Group budget readback retains authored `admission` (`exact|estimate`) and `on_exhaustion` (`finish-unit|cut-stream`); omission retains its default meaning. Read views remain projections, not full writable definitions. Group limits are whole-list replacements, so preserve every unchanged policy from readback deliberately.

The live endpoint requires a booted, authenticated instance. So that tooling can consume the contract without one, every tagged release **attaches the schema as a release asset**: `busbar-openapi-<tag>.json` on the [GitHub Release](https://github.com/GetBusbar/busbar/releases). CI emits it in-repo from the same `openapi_doc()` the gateway serves (test-locked against drift), and its `info.version` is stamped from the binary's version, so each release's artifact is self-identifying. Downstream tooling can pin a client to an exact version and diff the API surface release-over-release without decompiling or running the gateway.

### One document, and how to read its marks

There is one administrative OpenAPI document. It is generated from the code and describes every
operation the build can serve — the 1.6.0 additions included. A node serves it at
`GET /api/v1/admin/openapi.json` filtered to the planes that node configured, so a node running a
1.5.5 config describes no `tools`/`agents` operation; the release asset is the full document. The
full document describes 103 operations: the 66 carried from 1.5.5, the 22 the 1.6.0 closed verb
table adds, and the 15 the MCP and A2A planes contribute. Two marks say what a reader cannot tell
from the path alone (the document explains them itself, under `info.x-busbar-marks`):

- **`x-busbar-plane: <section>`** — the operation belongs to a plane (`tools`, `agents`) and is
  mounted only on a node whose config carries that `<section>:` block. On any other node its path
  answers `404 not_found`, exactly as a path the surface has never had, and the document that node
  serves leaves the operation out (with every schema only it references).
- **`x-busbar-since: 1.6.0`** — one of the 22 operations 1.6.0 adds to the closed verb table, answered
  by the node's administrative loop: the 14 kernel verbs (ten money-governance verbs, three
  trust verbs and the telemetry read), the five ledger views and the three audit-chain reads.

`GET /api/v1/admin/ledger/openapi.json` serves the full document, unfiltered.

The 1.6.0 kernel verbs (each is served; every mutation is audited and spends the CRUD rate budget):

| Operation | Path | Scope | Does |
| --- | --- | --- | --- |
| `verify` | `GET /api/v1/admin/verify` | `read-only` | Verify this node's ledger: every sealed checkpoint re-hashes to its body, no node sequence goes backwards, the book is measured against the last checkpoint, and postings reconcile with the previous release's rows. A failed verification is still `200`: `ok` is the answer and `findings` says why |
| `get_telemetry` | `GET /api/v1/admin/telemetry` | `read-only` | Bounded snapshot of collected request-phase duration counts, sums and exclusive bins; no outbound connection |
| `plane_facts` | `GET /api/v1/admin/plane-facts?plane=` | `read-only` | What a plane this node serves declares about itself (config sections, grant kinds, billable classes, record kinds, operation classes) |
| `plane_record_write` | `POST /api/v1/admin/plane-record-write` | `full` | Upsert one record, by `(kind, id)`, of a kind the named plane declares. Honors `Idempotency-Key` |
| `adjust` | `POST /api/v1/admin/adjust` | `full` | Correct a recorded unit's counts (below) |
| `recovery_list` | `POST /api/v1/admin/ledger/recovery/list` | `full` | Inspect retained ledger operations whose landing outcome needs an operator verdict (below); observation only, spends the ordinary CRUD rate budget |
| `recovery_resolve` | `POST /api/v1/admin/ledger/recovery/resolve` | `full` | Record an explicit landed or not-landed verdict for the exact retained operation and recovery version (below) |
| `amend_rate_history` | `POST /api/v1/admin/ledger/amend-rate-history` | `full` | Append a signed, back-dated correction to the dated rate-card history (below) |
| `commit_upgrade` | `POST /api/v1/admin/commit-upgrade` | `full` | Commit the fleet to the release this node runs; a release this node does not run is refused. Honors `Idempotency-Key` |
| `chain_break` | `POST /api/v1/admin/chain-break` | `full` | Deliberately break the journal chain (disaster recovery). `204` |
| `store_restore` | `POST /api/v1/admin/store-restore` | `full` | Always refused: the configured store has no restore operation (a body without `backup_ref` is `400`; an admitted call is `503 unavailable`). Restore off-node with the store's own tooling |
| `get_trust` | `GET /api/v1/admin/trust` | `read-only` | Every trust key in the kernel's trust book and its state: what it is approved at and what it was last sighted at |
| `trust_approve` | `POST /api/v1/admin/trust/approve` | `full` | Approve one trust key at what it was last sighted at. Durable across restart; idempotent |
| `trust_revoke` | `POST /api/v1/admin/trust/revoke` | `full` | Revoke one trust key: refused until approved again. Durable across restart; idempotent |

### Retained ledger operation recovery

`POST /api/v1/admin/ledger/recovery/list` observes operations retained by the configured Store when
an operation was sent but its landing outcome could not be established within the Store's receipt
retention window. The list contains identifiers, immutable body fingerprints and recovery versions;
it does not expose the retained bodies or a mutable dollar balance. Listing an operation grants no
resolution authority. Both recovery endpoints require `full` scope and spend the ordinary CRUD
request budget, including the observation-only list.

`POST /api/v1/admin/ledger/recovery/resolve` requires the exact `operation_id`, `body_fingerprint`
and `recovery_version` inspected by the operator, an explicit `verdict` (`landed` or `not_landed`),
and a nonempty `reason` (at most 1024 bytes). Unknown fields are rejected. A verdict must follow an
independent check of the Store's authoritative records. An expired receipt is never evidence that
an operation did not land. The node refuses a stale version, a different immutable body, conflicting
verdicts and an operation it has no current authority to resolve. Cross-node or old-owner operations
require explicit fencing; observing them in a list cannot bypass it.

Both `sender_quiesced: true` and `backend_quiesced: true` are required explicit operator attestations: all senders for this operation have been retired or disarmed, and all outstanding backend mutations for it have settled. The durable verdict records both attestations and its operator evidence. A node lease or recovery-head change does not cancel an already-running backend write; a disconnect or matching aggregate count does not prove quiescence or whether the operation landed. A local in-flight sender still prevents resolution even when the operator attests quiescence.

A foreign entry includes `owner_node` as 16 lower-case hexadecimal characters, so its sender can be identified without JSON integer rounding. Foreign inspection is read-only. Explicit resolution can adopt its selected custody under the new node only after both quiescence attestations; ordinary replay never adopts another live node's operations. Handover of an already definitive outcome preserves that outcome and its original audit; an opposite verdict is refused. A journal ownership change never proves that a backend call stopped.



The Store confirms the durable, attributed verdict before the kernel can repost retained work or
release a dependent negative correction. Retrying the same resolution returns its durable outcome;
cancelling an HTTP request does not cancel a verdict already being recorded. No short-lived HTTP
idempotency cache authorizes a second posting. Until an explicit verdict is durable, the original
sent operation stays retained and is never automatically replayed with a fresh operation id. Fresh
positive usage can continue; a dependent negative correction stays retained. Money continues to be
the raw ledger counts priced against their historical rate cards.

The ledger views and audit-chain reads:

| Operation | Path | Scope |
| --- | --- | --- |
| `GetLedgerTotals` | `GET /api/v1/admin/ledger/totals` | `read-only` |
| `GetLedgerCheckpoints` | `GET /api/v1/admin/ledger/checkpoints` | `read-only` |
| `GetLedgerReconciliation` | `GET /api/v1/admin/ledger/reconciliation` | `read-only` |
| `GetLedgerMigration` | `GET /api/v1/admin/ledger/migration` | `read-only` |
| `GetLedgerOpenapiJson` | `GET /api/v1/admin/ledger/openapi.json` | `read-only` |
| `GetAuditHead` | `GET /api/v1/admin/audit/head` | `read-only` |
| `GetAuditRange` | `GET /api/v1/admin/audit/range?from=&to=` | `read-only` |
| `GetAuditKeys` | `GET /api/v1/admin/audit/keys` | `read-only` |

Every one is a read and takes exactly what `GET /api/v1/admin/usage` takes — the same credential,
presented the same way. Money figures come back as **decimal strings**, not JSON numbers: the ledger
keeps them in 128-bit integers; binary64 client numbers are exact only through 2^53, so a busy day's
nano-unit total would lose digits in a binary64 client. Existing Count fields remain exact scale-6 JSON numeric tokens and require lossless parsing.

With one `Idempotency-Key` header (1–128 ASCII graphic bytes), `POST /adjust` selects the durable exact-Count action profile. Per-class deltas accept decimal strings (preferred for new clients) or lossless JSON numeric tokens, within signed i128 scale 6. The same actor/action and exact body bytes replay one retained outcome across restart; changed bytes return `idempotency_mismatch`. Claims and receipts do not automatically expire or recycle. Without the header, the legacy signed-integer request remains `nonretryable_without_idempotency_key`.

The action response is `{operation_id,operation:"adjust",actor,target,fingerprint,reason_hash,effect,applied,retry:"same_action_only",recovery,count_scale:6}`. It does not echo counts or the free-text reason. `effect` is `applied`, `not_applied` or `unknown`; unknown is HTTP 409 and requires `reconcile_ledger_recovery`. Known refusal may also use this outcome body at HTTP 400, so do not assume every non-2xx body is the generic Error envelope. The reason must be nonblank and at most 4096 UTF-8 bytes. `x-busbar-receipt-durable:false` means final receipt settlement was not confirmed; a later process may see the retained unknown receipt and must reconcile before another action.

`POST /api/v1/admin/adjust` corrects a recorded unit's **counts** — a signed whole delta per
billable class on the key's counts for one lane — never a money figure; what the unit costs stays
its counts x the card in effect at the unit's own time. The body names the key, the lane, the
rate-card history `entry` the counts were priced with, and the unit's **`card_epoch_ms`** (its
arrival instant): the correction lands where the unit was ledgered — in each budget window, card
entry segment and metering day holding that instant — never in the window or card current when the
correction is made. It fails closed: a future arrival epoch, an epoch no card entry covers, an `entry` other than the one
the unit's counts were dated with, a window that no longer holds the counts a downward delta moves,
or a count taken below zero is refused `400 invalid_request` with a message saying why, and nothing
is applied. The body also names the **`pool`** the unit was dispatched through, and it is
required: a pool-scoped group budget for that pool takes the correction as well as the group-wide
budgets, so `/groups/{name}/usage` and the `/metrics` bucket gauges agree with `/admin/usage`
afterwards. A missing pool, or one this node has not configured, is refused `400 invalid_request`
with a message naming the fault. `POST /api/v1/admin/ledger/amend-rate-history` appends a correction signed by the
fleet's operator key to the dated rate-card history. Each corrected rate's `micro_per_unit` is a
decimal in micro-units per unit, and it must be exact to one nano-unit (a multiple of `0.001`): the
card holds integers, and a finer figure is refused `400 invalid_request` rather than rounded into a
price the signature does not cover. The correction changes only what it names: the card in force
for the window keeps every other rate, every other plane's card and its `per_request_fee` unless the
correction names a fee. A lane spelt `<plane>\u001f<lane>` corrects that plane's card. A window
that two cards price (a config apply or an earlier correction lands inside it), or a cell on a plane
with no card of its own, is refused `400 invalid_request` and nothing is recorded: split the
window at the boundary and sign each part.

The money-governance verbs the design once named but 1.6.0 does not ship (`set_operator_key`,
`set_escrow`, `set_dual_control`, `set_overdraft_ceiling`, `set_dispute_max_age`, `resolve_dispute`,
`resolve_slice`, `export_keyset`, `approve`) are not in the closed verb table at all: their paths
answer exactly what a path the node does not have answers (`404 not_found`, no audit row), and the
OpenAPI document does not describe them.

These paths are served by the composition root's own loop. A node built without it answers them
exactly as it answers any other path it does not have — the same `404` envelope, no hint that the
operation exists elsewhere.

---

## What you can read

### Server & topology

| Endpoint | Returns |
|---|---|
| `GET /info` | `version`, `build` (the **compiled-in plugin proof**: `auth_modules`, `hook_plugins`, the always-true `weighted_floor`), `uptime_seconds`, `started_at` (epoch of process start, the boot-epoch marker: `config_version` resets on restart, so a changed `started_at` reads as "new epoch", never "reverted"), `topology` (pool/model/provider counts), `config_persistence` (whether API changes survive restart), `config_version` (monotonic, +1 per apply, drift detection) |
| `GET /pools` | Every pool with its member models and SWRR weights. **`?detail=true`** inlines each member's live status (the same row shape as `/pools/{name}`): the whole topology-with-health in one call |
| `GET /pools/{name}` | One pool's **live** per-member status: `usable` + `cooldown_remaining_seconds` (breaker), `available_concurrency`, `inflight`, `latency_ms` (EWMA), `ok`/`err` tallies, `dead`, and **`trip_count`** + `last_trip_at`, a monotonic Closed→Open trip counter, so alerting diffs the count instead of trying to catch a breaker episode live |
| `GET /models` | Every model lane and its upstream provider |
| `GET /providers` | Distinct providers and how many lanes route through each |

`GET /info` doubles as the **compliance-by-compilation proof**: `build.auth_modules`/`build.hook_plugins` reflect the actual binary. A build compiled with `--no-default-features` reports empty lists: a provable, not merely configured, smaller surface.

### Hooks & plugins

| Endpoint | Returns |
|---|---|
| `GET /hooks` | The hook registry: each hook's `kind` (tap/gate), transport, access grants (`prompt`/`user`), `priority`, `on_error`, `timeout_ms`, `settings_keys` (key names only, never values), whether it's globally wired, and its SELECTION scope: `groups` (which callers, empty = all) and the stage pair below |
| `GET /hooks/{name}` | One hook's definition |
| `GET /hooks/{name}/health` | Best-effort reachability of a forwarding hook's sidecar (a short-timeout connect probe against its configured `settings.url`; `reachable` is `null` for an in-process `kind: hook` plugin with no external endpoint, with a `detail` note). Never fires the hook |
| `GET /hooks/{name}/schema` | The hook's **self-described settings schema** (the `describe` wire message, proxied verbatim; `{"name", "schema": null}` when the hook doesn't answer) |
| `GET /hooks/{name}/status` | The hook's **observed** state, live-queried over its transport: `{name, desired, reported, drift, drift_keys, metrics, as_of, source}`. Both `desired` and `reported` carry `settings_keys`, the settings **key names**, never their values (the reported bag is the hook's echo of the SECRET-RESOLVED settings Busbar pushed it, and this read is read-only scope), plus their version. The **`drift`** verdict (a differing settings version, or a desired key missing/changed in the observed settings; extra self-managed keys are not drift) is computed against the RESOLVED desired settings, and `drift_keys` names exactly which desired keys the hook is not running. Self-reported metrics are validated and bounded. `reported`/`drift` are `null` when the hook doesn't answer (fail-open: the desired view still serves) |
| `POST /tools/{name}/connect` | **Fetch a registered MCP server's LIVE tool list, hash it per tool, and record the observation.** This is what gives the dispatch gate something real to compare against: with no observation it compares the operator's approved digest against the `schema_hash` the operator wrote in config, which is intent compared with itself and cannot notice an upstream changing its schema underneath. Answers the derived trust state (`pending` \| `approved` \| `quarantined` \| `suspended` \| `error`), the changes queue (`added` / `changed` / `removed` / `pin_changed`), and every capability's standing status. **Approves nothing.** Adopting what was seen is a separate operator act, so a poisoned tool list cannot be adopted by the same call that fetched it. A refresh that lands a drift is still `200`; the drift is in the body, and the server stops serving until it is worked. `full` scope, audited, config-class rate budget |
| `GET /tools/{name}/changes` | The changes queue for one MCP server, DERIVED from the last observation and the current approval. Contacts nothing, so it is safe to poll. Same body as `connect` |
| `GET /tools/{name}/health` | Whether one MCP server currently serves (`serving`), its derived `state`, whether it has ever been `contacted`, the last `failure`, and how many tools the last observation carried |
| `POST /agents/{name}/connect` | **Fetch a registered A2A agent's card, verify it against the operator's out-of-band trust root, and report what it found.** This is the verb that captures a sighting for a human to approve. Answers the derived trust state, the changes queue, and the **canonical card fingerprint**: the one string the approval below must name. **Grants nothing and writes nothing**: it is a preview, and a preview never reports `approved`. A card that cannot be fetched or cannot be authenticated is still a `200` with `state: error` and the reason in `failure`; the request succeeded, and what it found is that the endpoint cannot be trusted. `full` scope, audited, config-class rate budget |
| `POST /agents/{name}/approve` | **Lock a registered agent to the card fingerprint the operator has SEEN.** Body: `{"fingerprint": "…"}`, exactly as `connect` reported it. The card is re-fetched and re-verified on this call and the two must agree, so an approval is always a statement about a document a human actually read. An approve that adopted whatever the endpoint happened to be serving would be trust-on-first-use with a button on it. A registration whose `pin.mechanism` is `unpinned` has no authenticity root and is refused: registrable, inspectable, never approvable. The approval is the KERNEL's: the verb approves the agent's trust key `<instance>/<agent>` on the kernel's trust book, the same decision `POST /trust/approve` makes, and the book keeps it across a config apply and a restart. A fronted agent serves only while its key is approved. `full` scope, audited, config-class rate budget |
| `GET /plugins?type=auth\|hooks\|store\|secret\|export\|plane\|transport` | Catalog for one required type. `hooks` retains its configured hook/ranking summaries and adds installed hook artifacts; all seven types include their applicable linked or installed rows. Linked stores come from this distribution, without a hard-coded default. Artifact rows include `file`, optional `archive_sha256`, `version`, `publisher`, `interface_version`, validity/trust, and `schema_url`/`schema_error`. The archive digest identifies the complete current disk file; it does not assert that those bytes are already loaded. `has_schema` tracks a published schema reference, including a malformed legacy schema reported separately. Catalog inspection never executes a dropped artifact. The canonical Statement schema takes precedence over the legacy manifest field |
| `POST /plugins/inspect` | STATELESS preview of a candidate plugin tarball (`read-only` scope, with its own `plugin-inspect` rate bucket, see above). Body: same shape as `POST /plugins` (`{file, tarball_b64}`; `file` unused, since nothing is written). Verifies the signature, parses the manifest, and returns the SAME response shape as `GET /plugins/{file}/schema` plus `name`/`version`: `{name, version, kind, schema, schema_error, trust, source: "manifest", restart_required_default}`. `trust` may be `"rejected"`. An untrusted candidate is REPORTED, not refused (the point is previewing what a not-yet-trusted plugin would need without ever installing or executing it). Never writes to `plugins.dir`, never conflict-checks against the installed set. Call this before `POST /plugins` to preview, or after downloading a candidate from a third-party release page before deciding whether to trust it |

**Hook stages:** write `phase: [response]` to select one stage, or list several stages.
Admin hook writes require `module` and `phase`; retired `plugin` and `at` keys are refused.

| Field | Meaning |
|---|---|
| `phase` | The configured stage list. An empty list selects the four core stages. |
| `fires_at` | The effective stage set in pipeline order, computed by the runtime firing predicate. |

Hook readback no longer includes `at`. A non-empty phase list selects exactly those stages;
an empty list selects `request`, `candidate`, `routing`, and `response`.

No hook read ever includes a secret. A hook's `settings:` bag is a `SecretRef` carrier by design
(Busbar resolves it before every `configure` push) and an operator may also write a literal
credential there, so every hook read projects `settings_keys` (the sorted key names) and never the
values. The values are readable only where they are writable: the config file and the config
overlay.

### Auth posture

| Endpoint | Returns |
|---|---|
| `GET /auth` | The ingress auth chain (module names) + the upstream-credential mode (`own`/`passthrough`) + whether the front door is open |
| `GET /admin-auth` | `{configured, modules}`: which modules guard the admin surface itself (the same resource `PUT /admin-auth` writes) |

Module names and modes only, never a token.

### Config, versions & audit

| Endpoint | Returns |
|---|---|
| `GET /config` | The effective running config as one redacted snapshot (`version`, auth, pools, models, providers, hooks, `global_hooks`) for drift detection. Carries the config-plane `ETag`. **`global_hooks` here is an API RESPONSE field**, not the retired config key. It projects the resolved all-pools attach set (config-side, that is the reserved `pools.hooks:` list) |
| `GET /config/settings` | `settings` contains only desired root-section Store overrides, never implied base-file values. `settings_source` is `desired_root_overlay`; `desired_revision` identifies the exact verified Store document, separately from the installed `config_version`. `desired_status` distinguishes loaded, absent, disabled, unreadable and newer-version overlays. The additive `configuration` field contains a sanitized view captured from the installed generation, with the same version as the response ETag. Opaque settings expose key names and explicitly public schema values only. Configured values do not acknowledge physical or asynchronous plugin activation; pending restart paths remain explicit. Hidden and unavailable fields are not empty/default values. Do not round-trip this read as a replacement body |
| `PUT /config/settings` | Two mutually exclusive modes: the existing root-section body (`rate_card`, `per_request_fee`, `security`, `limits`, `advanced`, `health`, `routing`, `listen`, `admin_listen`, `tls`, `admin_tls`, `admin_require_mtls`, `store`) retains its merge semantics; `document_patch` edits the boot document using JSON pointers, as described below. Both use Store persistence and atomic generation publication, honor `If-Match`, and refuse locked configuration. The legacy response keeps `settings`; document mode returns `persisted` and `configuration`. `reload_to_apply` identifies boot-bound changes such as listeners, TLS, Store, upstream client settings and router limits. `config.yaml` is never written. The legacy optional boolean `persist` retains its previous no-op meaning; document mode is always durable and refuses `persist:false`. Full scope |
| `GET /audit` | The admin audit log: every mutation *attempt* with its outcome (`applied`/`rejected`), newest first, attributed to the acting principal. Filters: `?action=hook.register`, `?resource=hook:x` (exact match). Paginated. No secrets. Each entry is hash-chained; its `scheme` names the recipe its `hash` was taken over. Scheme 1 is 1.5.5's `sha256(prev_hash\|seq\|ts\|action\|resource\|outcome\|principal)`. Scheme 2, used when `action`, `resource` or `outcome` holds a `\|`, is `prev_hash\|seq`, a zero byte, then `ts`, `action`, `resource`, `outcome` and `principal`, each as an 8-byte big-endian length and its bytes (`ts` as its 8-byte big-endian value). The OpenAPI `AuditEntry.hash` states the same recipe |
| `GET /config/versions` | Version history metadata, newest first: `version`, `ts`, `principal`, `summary`. Paginated |
| `GET /config/versions/{v}` | One retained version with its full hook-surface snapshot: `{version, ts, principal, summary, hooks, global_hooks}`, hooks projected through the same wire shape as `/hooks`, so one parser covers both. `404` if pruned or never recorded |
| `GET /config/diff?from=&to=` | A structured diff between two retained versions: `{from, to, hooks: {added, removed, changed}}` + a `global_hooks: {from, to}` delta when the wiring changed. `400` for missing/non-numeric params; `404` names *which* version is missing |

The configured public projection additionally includes `auth.role_bindings` (pool grants, group, admin scope, validated verb grants and declared plane grants), preserving absent versus empty grant lists. `pools.definitions` contains explicitly selected typed routing, member, timeout, breaker, failover and affinity values; free-form tag values remain hidden. Model entries expose the current typed model fields. Provider entries add typed health settings, auth-style and metadata-host policy, plus `protocol_override` captured from the authored deployment. `provider_catalog.public` carries the catalog's typed protocol/auth-style/health/policy fields. URLs, paths, credential references, OAuth scope/subject, error-map values and opaque option values remain presence/key-name projections. These are explicit allowlists, not serialization of the root config or the plane's opaque options. A hidden value must be retained by omission from partial edits; it is not an empty input or a removable default.

### Durable document edits

Use `PUT /config/settings` with `If-Match` from the current config ETag:

```json
{
  "document_patch": {
    "set": {"/limits/request_body_max_bytes": 5000123},
    "remove": ["/providers/retired"]
  }
}
```

Paths use JSON Pointer escaping (`~1` for `/`, `~0` for `~`). Objects can be traversed and absent object parents are created. An array index is a canonical zero-based integer naming an existing element; `set` replaces that element or an addressed object leaf within it. Terminal `-` appends one element. Signed, leading-zero, missing and out-of-range indices are refused, as is traversal through `-`. An entire array can still be intentionally replaced. A missing `set` or `remove` means no edits of that kind. Setting null is different from removal. Omission preserves existing values, including hidden credentials. The composed document enters the same parser and validation path as boot; it introduces no plane-specific config vocabulary.

All indices in one request refer to its input snapshot. Sets and appends run first; removals run in descending index order so removing one element cannot retarget another removal. For example, an edit to `/pools/west/members/0/weight` preserves that object's hidden tags; setting `/pools/west/members/-` adds a new complete member, and removing `/pools/west/members/1` removes the input snapshot's second member. A stale `If-Match` or any invalid later operation rejects the complete mutation. Subsequent requests use the current authored indices, not the original file's positions. The Store retains internal ordered stages when needed; clients continue to send only the public `set`/`remove` envelope and may not supply `$stages`.

A persisted patch is bounded to 4096 operations, 1 MiB serialized bytes and pointer depth 128. Safe dominated replacements and source-equivalent edit cycles may compact internally; this does not change the authored result or expose hidden data.

This Store layer sits below existing root, named-map, hook/group and plugin-version overrides. An edit shadowed by one of those overrides returns a conflict identifying the override and installed version. Use that section's existing mutation/reset route rather than assuming the new value took effect. Within one document edit, parent/child and set/remove overlap is refused. Object-only edits retain their existing merge behavior: exact-path edits supersede previous edits, while changing a prior parent edit to child edits requires explicitly resetting that parent. `reset_document_paths` removes every stored operation at each exact named path, including across ordered stages; the remaining stages must still replay and pass validation or the whole request is refused. Unrelated edits and typed overlays remain intact.

The applied response describes an installed configuration generation. Boot-bound paths remain pending until restart; plugin settings are configured intent, not acknowledgement from an asynchronous refresh. A persisted `advanced.worker_threads` value selects data workers after Store recovery on restart, preserving the existing environment precedence. Unix uses pinned data runtimes; non-Unix uses a dedicated data scheduler while retaining the bootstrap/control runtime. The bootstrap plugin dispatcher keeps its own worker budget.

The installed-generation readback also includes
`configuration.values.sections.pools.authored`. When `state` is `available`, it records the
current authored routing sequence, separately from the resolved values in `pools.definitions`:

- `definitions.<pool>.members` has `state: absent|null|list`, a JSON Pointer `path`, and ordered
  `entries`. Each entry carries its current `index`, escaped `path`, `model`, `form: bare|object`,
  `declared_fields`, safe typed `values`, and `tags: {state: hidden|absent, count}`. Tag values never
  leave the engine. The typed values are from the unresolved input parser, including its defaults;
  `declared_fields` distinguishes an explicit member override from an omitted value.
- `definitions.<pool>.hooks` preserves the authored list order and spelling: each entry is either
  a bare hook/strategy name or `{strategy: name}`. `pools.authored.hooks` separately describes the
  all-pools attach list. These lists contain public names only and may be used for intentional hook
  ordering edits. Resolved `ordering_strategy`, `ordering_explicit`, and `gates` are not substitutes
  for the authored list.
- `state: unavailable` means there is no authoritative source projection, as with programmatically
  constructed configurations. It does not mean the arrays are empty. The optional projection never
  changes whether the normal boot parser accepts a configuration.

Every authored index belongs to the response's `configuration.config_version` and ETag. Send that
ETag in `If-Match` for a reviewed edit, then use fresh readback after a successful mutation; indices
can change after a removal or reorder. Every nonempty document/catalog edit or reset also compares
the relevant operator source with the exact preprocessed source consumed by the installed generation.
This includes first-list initialization, whole-list replacement/null/removal, ancestor replacement and
reset paths; it is not limited to numeric indices or a fixed list of schema fields. A changed source
or unavailable binding returns `409` without changing the Store or installed generation until an
explicit reload and fresh readback. An unchanged ETag alone cannot authorize editing an unseen
external source change. This binding is private: no source digest or
secret-bearing source text is returned. For an object-form member, editing its weight leaf preserves
omitted fields and hidden tags. A bare member is a complete scalar name: changing it to a rich member
is an intentional replacement of that one entry. Never reconstruct the complete `members` array
from sanitized resolved readback. Missing and null lists remain explicit, so clients can distinguish
creating a list from appending to an existing one.

The same document-mode request can include `providers_patch` with `set`/`remove` paths rooted at catalog entry names, and `reset_providers_paths` to forget exact prior catalog edits. For example, `{"document_patch":{},"providers_patch":{"set":{"/example/base_url":"https://api.example.com"}}}` edits the provider catalog atomically with any config edits. The catalog uses the same parser as `providers.yaml`; neither operator file is written. Catalog edits shadowed by deployment values return a conflict. `providers_file` follows the effective config on reload unless the process has an explicit CLI/environment catalog override; edits shadowed by that override are refused.

The overlay document format remains version 2. A reader that does not understand the internal ordered patch shape refuses it rather than silently ignoring sequence edits. The Store used to find the overlay remains the operator's base Store anchor; a Store change takes effect at restart after that anchor is recovered.

### Metering: `GET /usage`

Usage totals, model rows, key rows, and the optional `others` rollup itemize every ledgered open
class in `classes`, including classes such as pools `search_units`. Reserved token quantities
remain in their existing token fields. Empty `classes` maps are omitted. Counts are exact JSON
decimal numbers with up to six fractional digits, including quantities beyond 64-bit mantissas.

The fleet FinOps read. Design principle: Busbar exposes the **raw inputs of cost**, not just its own number: every row carries the full token split (input / output / cache-read / cache-creation, each of which prices differently), so a consumer with its own negotiated price catalog reconstructs cost independently.

```json
{
  "window": { "start": 1782950400, "end": 1783036800 },
  "as_of": 1782998113,
  "currency": "USD",
  "total": { "tokens_input": 91240, "tokens_output": 30112, "tokens_cache_read": 402000,
             "tokens_cache_creation": 12050, "requests": 512, "spend_micros": 1834200 },
  "by_model": [ { "model": "smart", "provider": "anthropic", "tokens_input": 91240, "...": "..." } ],
  "by_key":   [ { "id": "vk_ab12cd34ef56ab78", "name": "ci", "tokens_input": 91240, "...": "..." } ],
  "by_key_truncated": false
}
```

- **One bucket, always.** A response is exactly one fixed UTC-day metering bucket (`window` is `[start, end)` epoch seconds). `?window=<bucket-start-epoch>` selects a past bucket (default: the current one); a value that isn't a bucket start, or is in the future, is `400`. Billing periods aggregate client-side from day buckets: raw counts are stored, so the math is exact.
- **The ledger rule:** `spend_micros` (MICRO-units of the cost unit the operator priced the top-level `rate_card` in, so the math is integer and sub-cent precise; the response's top-level **`currency`** field names its denomination, currently `"USD"`) is a **mutable estimate** derived at read time per model from the *current* rate card plus the flat per-request fee (a rate correction re-prices history on the next read). Never store it as a ledger charge; **bill from the raw token split**. With no `rate_card` configured, the token component derives to 0 and only the flat fee contributes. `currency` is emitted ONLY on this endpoint. The per-key/per-group usage views stay currency-agnostic raw-split ledgers.
- `by_key` is capped at the top 1000 rows by spend; `by_key_truncated` says the cap fired, and `others` (present exactly then) carries the summed remainder, so `total == sum(by_key) + others` always holds. `by_model` is never capped. A deleted key's history keeps its `id` (`name` goes `null`).
- `as_of` marks read freshness (counters accumulate live). With no keys minted the aggregations are truthfully empty. Key ids/names only, never a token.

Per-key budget *enforcement* state lives on `GET /keys/{id}/usage`, not here.

---

## Keys

The virtual-key surface at `/api/v1/admin/keys` (`full` scope for mutations). Key metadata is `{id, name, allowed_pools, group, enabled, created_at, labels, state}` (`allowed_pools: null` = all pools, `[]` = none), never the secret or hash. Keys are PURE AUTH: every limit lives on the bound group.

**`state`** (additive): `enabled` alone cannot tell a reversible pause apart from either of the two permanent dispositions. `PATCH {enabled:false}`, `POST /keys/{id}/revoke`, and `DELETE /keys/{id}` all leave `enabled: false`, with nothing else on the old wire shape to distinguish them. `state` is one of exactly four values, always derived (never independently settable): `"active"` (enabled, not revoked, not deleted); `"disabled"` (`PATCH {enabled:false}`: reversible, and `PATCH {enabled:true}` restores it); `"revoked"` (`POST /keys/{id}/revoke`: permanent, denylisted, but the row stays live on `GET /keys/{id}`); `"tombstoned"` (`DELETE /keys/{id}`: permanent, denylisted **and** hard-deleted; the row survives only so id-attributed billing/audit history keeps resolving, and it is omitted from a plain `GET /keys` unless you pass `?include=tombstoned`).

| Endpoint | Does |
|---|---|
| `POST /keys` | Mint a key: `201`, body is the metadata plus the **signed token, returned exactly once**. Body: `{name, group?, parent?, allowed_pools?, labels?, expires_in\|expires_at?, issue_aws_credential?}` (default expiry 90d). `group` binds the key into the `groups:` limit chain. **Auto-provision**: when `group` names a leaf that does NOT yet exist and `parent` is an existing group, the leaf is created automatically (limits stamped from the nearest-ancestor `child_default`, inherit-only when none) and the key is bound to it. The first self-mint materializes a `user:<sub>` personal budget bucket live in the enforcement chain. If the group already exists, `parent` must match its actual parent (a `409` otherwise, since a mint never re-homes an existing group). `allowed_pools` omitted = all pools, `[]` = none (the intent is stored verbatim); `labels` (`{"team": "growth"}`) are echoed onto the key's metric series, never interpreted by enforcement. `issue_aws_credential: true` also returns a once-shown `aws_access_key_id` + `aws_secret_access_key` for SigV4 clients. A fresh mint is always `state: "active"`. Requires **`full`** scope |
| `GET /keys` | List metadata, id-sorted. Strict filters (`?enabled=true\|false`, `?prefix=vk_ab`, `?group=<name>`) where an unparseable value is a `400`, never a silently dropped filter. `?group=` is an exact bound-group match with **no existence check** against the registry: a key can reference a group the running config no longer has, and listing "keys of `g`" must still find them (that dangling state is exactly what an operator hunts). Tombstoned keys are omitted by default; pass `?include=tombstoned` to see them too (their `state` reads `"tombstoned"`). Otherwise "it is gone" and "it never existed" looked the same. An unrecognized `?include=` value is a `400`. Cursor-paginated |
| `GET /keys/{id}` | One key's metadata (including `state`) + its `ETag` header (16 hex chars). Returns the row for a tombstoned id too. `DELETE` never 404s a subsequent single-resource `GET`, only the list omits it by default |
| `PATCH /keys/{id}` | Adjust `enabled` and/or `group`. `group` is three-state: absent = unchanged, `null` = unbind (authed + unlimited), value = rebind to an existing group (mint-parity validated). The 1.4.x cap fields are rejected. Honors `If-Match` |
| `DELETE /keys/{id}` | **Tombstone: permanent, irreversible.** Every credential the key has (signed-token binding, SigV4, any future kind) is destroyed; the id is denylisted; `enabled` is forced `false`; a subsequent `GET /keys/{id}` reports `state: "tombstoned"`. The metadata row itself is KEPT (id/name/group/labels only, with no un-delete, no re-enable, and the id never reissued) purely so `GET /keys/{id}/usage` and audit attribution keep resolving by id forever. `204 No Content`; the key stops authenticating immediately. Honors `If-Match`; `404` for an unknown id. **`revoke` is also permanent: there is no reinstatement path for either verb** (see below) |
| `POST /keys/{id}/revoke` | **Non-destructive retirement, but still one-way, and recommended for normal key retirement**: every credential is revoked and the id is denylisted, same as `DELETE`, but `enabled` is the only durable flag touched, and there is no tombstone. `{revoked: id}` on success, `404` for an unknown id; a subsequent `GET /keys/{id}` reports `state: "revoked"`. Because nothing is marked permanently deleted, this is the reach-for-first verb over `DELETE`, and the metadata row (and its usage/audit history) survives. But there is **no un-revoke API**: the denylist has no removal method on any backend, and a revoked subject id stays denylisted forever regardless of `PATCH {enabled:true}` or a fresh credential mint. `verify_token`/SigV4 admission both gate on the denylist before anything else. The real difference from `DELETE` is history retention (metadata row kept vs. tombstoned), **not** reversibility |
| `POST /keys/{id}/rotate` | Re-issue the key's **credential in place**: `200`, same id (budgets, rate windows, usage history, audit attribution carry over), the **previous credential stops authenticating immediately** (fleet-wide, because the new binding generation is durable), the new one is shown exactly once. Answers `{token, expires_at, state}` (every token issued before the rotation is now rejected, and 1.5.0 has exactly one bearer-credential shape, so rotation always re-issues a signed token). Rotate does not itself change `enabled`/revoked/tombstoned status, so `state` reflects whatever the key's disposition already was (`active` or `disabled`, or `revoked`, since rotating a revoked key is legal and leaves it revoked); a tombstoned key refuses to rotate at all (`404`). An attached SigV4 credential is untouched. Bearer rotation and SigV4 rotation are independent planes |
| `GET /keys/{id}/usage` | The **attribution view**: `{id, budget_period: "total", window_start: 0, as_of, group, spend_cents, tokens, requests, rate_headroom}`, the key's all-time attribution counters (its limits, if any, live on the bound group's own windows). `spend_cents` is DERIVED at read time from the key bucket's token ledger x the current `rate_card` plus fee x requests (reprice-on-read; nothing dollar-shaped is stored). `rate_headroom`: the fraction `[0,1]` of the tightest `requests`/`tokens` limit across the group chain left in each limit's own window (`null` = no such limit), back off *before* tripping a 429 |

**Idempotency.** `POST /keys` and `POST /keys/{id}/rotate` accept `Idempotency-Key`. Authenticated actor, operation, target and SHA256 of the exact request bytes bind a replay for about 10 minutes; whitespace changes are changed bytes. A changed request returns `409 idempotency_mismatch` with `effect:not_applied` and no cached secret. In-flight reservations refuse another effect. Secret-bearing responses can replay only while the current process retains their secret; durable applied receipts survive restart without storing the secret and refuse secret replay. Retention is finite: never reuse a completed action key as a new action or blindly retry after its replay window.

A key rotate/PATCH/delete that committed but cannot refresh its cache returns `409 mutation_applied` with `effect:applied`, `operation`, non-secret `resource:key:<id>`, `recovery` and `credential_recoverable:false`. Rotation's recovery is `rotate_with_new_action`; other writes use `reread_resource`. This response is evidence of the committed effect, not rejection. A lost secret is never disclosed by parsing a backend message.

If a mint's key write commits but cache reconciliation fails, `POST /keys` returns `409 conflict` with `MINT APPLIED (new secret not returned)` and the committed public key ID. It returns no token or issued secret. The applied outcome is audited and retained for its `Idempotency-Key`; retrying that key does not mint again, including after the response cache is lost. Recover the Store/cache service, then revoke or delete the identified key before minting a replacement. A Store write failure without a confirmed commit keeps the existing uncertain-outcome handling; it is not reported as applied.


**Anti-sprawl caps.** Two optional knobs, both `0` = unlimited by default (an absent knob changes nothing):

- `limits.max_keys_per_principal` caps how many keys may be bound to **one group** (a group = one principal in the self-service model; a user leaf can only hold so many keys). It counts **live** keys only (revoking or disabling a key returns its slot) and it applies to the unbound (`no group`) bucket too. Enforced on **both** `POST /keys` and a `PATCH /keys/{id}` rebind, so a principal cannot be walked past its ceiling one rebind at a time. Over cap ⇒ terminal `409 conflict`.
- `limits.max_auto_provisioned_groups` caps how many groups a mint may **auto-provision** (`parent:`), bounding the *shape* of the limit tree rather than its contents. Every leaf is a new enforcement bucket, version-log entry and overlay row. Over ceiling ⇒ terminal `409 conflict`; mints that bind to an existing group are unaffected.

Minting a key requires `full` scope. A mint should always name a `group` (an unbound key carries no limits at all); issuing an unbound key is a `full`-only action too.

With no store/keys, one unambiguous rule: `GET /keys` answers `200` with an empty page (the keyspace is truthfully empty), single-resource reads answer `404 not_found` (also truthful), and writes answer with an actionable message.

---

## Groups

The `groups:` limit tree, where every limit lives (keys are pure auth), is fully readable and mutable at runtime under `/api/v1/admin/groups`. Reads are `read-only` scope; every mutation is `full`. The read shape (`GroupView`) is `{name, parent?, enabled, limits, child_default?}`; each limit is projected **explicitly** as `{metric, amount, per?, pool?, on_exhaust?, downgrade_to?}` (`metric` ∈ `requests`|`tokens`|`budget`|`concurrent`; `per` absent only for `concurrent`; `pool` present only on a pool-scoped limit). The config file's compact `{ budget: 3000, per: month }` form is write-side sugar, a consumer never has to know the metric is the map key. The **write** verbs accept a `GroupCfg` verbatim: paste a `groups:` block from config.yaml.

### Reading the tree

| Endpoint | Returns |
|---|---|
| `GET /groups` | Every group, name-sorted. Carries the config-plane `ETag`, so a client reads then mutates without a second round-trip. Cursor-paginated (see Pagination above) |
| `GET /groups/{name}` | One group definition (+ config-plane `ETag`); `404` for an unknown name |
| `GET /groups/{name}/usage` | The group's **derived** current-window usage, one row per enforcement bucket (each `(window, pool?)` its limits materialise): `{group, enabled, buckets: [{window, pool?, requests, tokens, spend_cents, requests_cap?, tokens_cap?, budget_cap?, budget_remaining_cents?}], as_of}`. Spend is repriced at read time from the token ledger × the *current* `rate_card` (nothing dollar-shaped is stored). `buckets` is empty for a group with only a `concurrent` limit (or none): there is no windowed ledger to read. The self-service dashboard read: a `user:<sub>` leaf's usage is one person's view |
| `GET /keys?group=<name>` | The keys bound to a group (see the keys table above): a leaf group's keys are one person's keys; a team group's are the team's |

### Mutating the tree

| Endpoint | Does |
|---|---|
| `POST /groups` | Create (or replace) a group at runtime. Body `{ "name": "...", "config": { "parent": ..., "enabled": ..., "limits": [...], "child_default": ... } }`, a config.yaml group block verbatim. **`201` when the name is new; `200` when it replaces an existing overlay group** (honest upsert; re-creating a deleted name clears its tombstone) |
| `PUT /groups/{name}` | Replace an existing **overlay** group, live. `404` for an unknown name (PUT replaces; POST creates) |
| `PATCH /groups/{name}` | **Partial** update: omitted and null legacy fields preserve current values. Non-null values replace the field. This is the ergonomic "raise Alice's budget" (send just `limits`) and "freeze this team" (send `enabled: false`) verb. `limits`/`child_default` replace their whole list when present (a list can't be field-merged); to *clear* `parent` or `child_default`, send `{"clear":["parent","child_default"]}` (either name may be selected). Setting a non-null value and clearing the same field is `400`. An empty child template remains present and stops ancestor-template lookup; it is distinct from clearing. A typo'd field is a `400`, never a silent no-op |
| `DELETE /groups/{name}` | Remove an overlay group, live. **`204`** (still carrying the new config ETag); `404` if unknown; terminal `409` if another group still names it as `parent` (re-parent or remove the children first, because a delete never silently orphans them). The name is tombstoned in the overlay so the deletion survives restart |

**Validate-at-the-door.** Every write runs the mutated registry through the *same* `validate_groups` boot uses (parent exists, chain acyclic, pool qualifiers resolve, limit values sane): a bad group (dangling or cyclic parent, a `pool:` naming no pool) is a `400` that changes nothing. On success the enforcement projection is rebuilt atomically and the new limits are live for the next request; the usage **ledger survives the swap**, so past accrual is preserved across a limit change.

**Base groups are file-owned.** A group defined in config.yaml answers every mutation with a terminal `409 conflict`: the API cannot silently shadow operator file config (mirrors hooks). Edit config.yaml and reload instead.

All group mutations honor `If-Match` against the config-plane ETag, are audited (including rejections), recorded in version history, and persisted through the configured Store. A durable Store preserves them across restart; a memory Store is ephemeral. `config.overlay` is no longer a current configuration field, and serving does not read `BUSBAR_CONFIG_OVERLAY`.

```bash
# Raise one group's limits without touching the rest of its definition
curl -s -X PATCH -H "x-admin-token: $TOK" -H 'content-type: application/json' \
  --data '{"limits":[{"budget":500000,"per":"month"}]}' \
  http://localhost:8081/api/v1/admin/groups/growth

# How is the team tracking against its caps?
curl -s -H "x-admin-token: $TOK" http://localhost:8081/api/v1/admin/groups/growth/usage
```

---

## Changing config over the API

Busbar's config plane is live: an authenticated write takes effect immediately, with no restart and without disturbing in-flight requests. Under the hood an apply atomically swaps the running config snapshot: new requests see the new config; requests already in flight finish on the old one; and surviving lanes keep their learned health (breakers, latency) **by identity**. Config-plane mutations are serialized internally, so concurrent writes can never silently lose one.

**Persistence follows the configured Store.** API-applied hooks, groups and root settings are
persisted through the base `store:` and recovered before serving. A durable Store preserves them
across restart; the memory Store is ephemeral. Busbar leaves the source `config.yaml` unchanged.
The current management grammar is:

```yaml
config:
  locked: false                 # mutable; true selects immutable/GitOps management
```

`config.locked: true` refuses config-mutating admin calls; edit the source configuration and reload
instead. Mutable management requires the Store's atomic conditional-record capability. A mutation
must persist before its new generation is published; a failed persistence operation refuses it.
A read-only config directory does not prevent Store persistence.

An unavailable, incomplete, corrupt or newer Store overlay refuses recovery. Boot with
`--safe-mode` to quarantine it and use the base configuration without deleting overlay records.
`config.overlay` file and boolean selectors are refused by current parsing. One-time migration
removes the old selector while preserving `config.locked` and imports old file state separately;
serving never reads `BUSBAR_CONFIG_OVERLAY`. See [the migration guide](migration-1.6.md).

### The config plane

| Endpoint | Does |
|---|---|
| `POST /config/validate` | **Dry-run** a proposed config (body `{ "config": {...}, "providers": {...} }`, the `config.yaml` deploy block + `providers.yaml` defs) through the same resolve + validate Busbar runs at boot, applying nothing. A well-formed request is always `200` with the `{ "ok": bool, "errors": [...] }` verdict (an invalid *config* is `ok: false`, not an HTTP error); only a malformed *body* is `400`. Read-only scope: CI can lint |
| `POST /config/apply` | Apply a full config from the request body (validate's exact shape), atomically: invalid = `400`, nothing changes. Returns `{applied, config_version, note}` + the new ETag. Live until the next reload/restart returns to disk truth; persist by updating config.yaml. A locked config (`config.locked: true`) refuses with `400` (no runtime config mutation on an immutable/GitOps deployment) |
| `POST /config/reload` | **Re-read config.yaml + providers.yaml from disk and apply atomically**, the boot pipeline at runtime, under normal admin auth (no second credential path). Returns `{reloaded, config_version}`. Invalid disk config is `400` and changes nothing; a Busbar started without config files is `400`. The GitOps primitive: push config, call reload, no restart, no health amnesia |
| `POST /config/rollback` | Restore a retained version's hook surface. Body `{ "version": N }`; guard with `If-Match`. The target is **re-validated against current reality** before the swap (`400` if it no longer resolves); the result is a **new** version; history is append-only. Returns `{restored_version, config_version}`. `404` for a pruned/unknown target |
| <a id="post-apiv1adminrestart"></a>`POST /restart` | **Apply the restart-scoped settings by restarting the process**, so an operator never needs a shell (see the `PUT /config/settings` row above for what is restart-scoped). Body is OPTIONAL (`{}` and absent are the same, and `confirm` defaults `false`): `{ "confirm": bool? }`. Drains through the SAME path a signal takes (final budget flush and tracing shutdown happen as they do on `SIGTERM`), so durable audit history is never rewound (the `seq`/`durable_high` counters only advance via `fetch_max`, and this is a process boundary, the only thing that resets them). Responds `202 {restarting, supervisor_detected, note}` **BEFORE the drain begins**; the drain then closes the connection carrying that response, so a caller who saw no response cannot tell a restart from a crash. Always read the body first. Refuses (`409 conflict`) rather than exit-and-hope: `NoSupervisor` when no process manager is detected and `confirm` was not set (an unsupervised exit would leave Busbar down); `NotRestartable` when this process cannot restart itself. Requires **`full`** scope |
| `PUT /admin-auth` | **Replace the admin auth chain at runtime.** Body `{ "admin_auth": ["admin-tokens", ...] }`; unknown module names are `400` (a typo can never silently drop auth). Guarded against self-lockout: the calling request's own credentials are re-evaluated against the *new* chain, and unless they would still hold `full` scope the change is a terminal `409` that changes nothing. Response is the resource (`{configured, modules, applied, config_version, note}`). Live until the next reload/restart. A locked config (`config.locked: true`) refuses with `400` (no runtime config mutation on an immutable/GitOps deployment) |
| `POST /auth/cache/flush` | **Instant revocation of the credential cache's allow window.** Body `{ "module": "name" }` flushes one identity provider's partition; an empty body flushes everything. Returns `{flushed}` (entries dropped). The deny path never needs this; rejections are never cached |
| `POST /signing-key/rotate` | **Reports** the current signing key's id and revoke-all instructions. It does NOT rotate anything itself. `200 {current_kid, revoke_all: true, message}`. 1.5.0 is single-key: an actual rotation is an operator action (replace `auth.signing_key` / the persisted key file, then restart or reload every node in lockstep) because a new signing key makes every token minted under the old one stop verifying. This endpoint exists so an operator can confirm the current kid and get the exact revoke-all warning before doing that, not to perform the swap in-process. `409 conflict` if no signing key is configured |
| `DELETE /overlay/{section}` | **Revert one overlay section to base `config.yaml` truth** (`section` ∈ `groups` \| `hooks` \| `root` \| `plugin_versions` \| `identity-providers` \| `export` \| `tools` \| `agents`). Discards ALL overlay mutations for that section: a `groups` reset restores the base limit tree, a `hooks` reset restores base hooks, a **`root` reset discards every durable `PUT /config/settings` override** (rate_card, per_request_fee, security, limits, listen, tls, store, and everything else that block covers), a `plugin_versions` reset discards every first-party-plugin rollback pin, and a **named-definition map reset (`identity-providers` / `export` / `tools` / `agents`) discards every definition that map was given through the API**. For `tools`, that is every MCP server registered and approved through the API, and for `agents`, every A2A agent registered through it, each reverting its plane to whatever `config.yaml`'s own `tools:` or `agents:` block declares. The other sections' runtime mutations are left untouched. `full` scope, `If-Match` optimistic concurrency, audited, versioned, and the cleared overlay is persisted (the revert survives restart). A section with no overlay state is an idempotent no-op (`changed: false`, ETag/version unchanged). Only a section OUTSIDE the set above is `400`. `root`, `plugin_versions` and the named maps are real, consequential targets, not safe no-ops. A named-map reset that would leave `config.yaml` naming a definition it removes is refused `409` `conflict` naming the entry and its referents; nothing is cleared. An ephemeral Busbar with no config files has nothing to revert to and returns `400` |

### Hooks lifecycle

| Endpoint | Does |
|---|---|
| `POST /hooks` | Register a hook at runtime. Body `{ "name": "...", "config": { "kind": "gate\|tap", "module": "<kind: hook plugin name/alias>", "settings": {...}, ... } }`. `module` names a loaded `kind: hook` plugin (1.5.0 retired the built-in `socket`/`webhook` transports; for HTTPS-sidecar forwarding use the first-party `busbar-hook-webrequest` plugin, and note `plugins.enabled: true` is required). **`201` when the name is new; `200` when it replaces an existing overlay hook** (honest upsert). A `global: true` hook is live for the next request. Invalid definitions are `400` and change nothing; a base-config-defined name is a terminal `409` (the API never silently shadows file config) |
| `PUT /hooks/{name}` | Replace an existing **overlay** hook, live. `404` for an unknown name (PUT replaces; POST creates); terminal `409` for a base-defined hook or a grant change: `kind`/`prompt`/`user` are immutable (delete and re-register to change them) |
| `DELETE /hooks/{name}` | Remove an overlay hook, live. **`204`** (still carrying the new config ETag); `404` if unregistered; terminal `409` for a base-defined hook. The deletion is tombstoned in the overlay so it survives restart |
| `PATCH /hooks/{name}/settings` | Choose exactly one body mode: `{"settings":{...}}` replaces the entire bag, dropping omitted keys; `{"edit":{"set":{...},"remove":[...]}}` preserves all unmentioned fields, including hidden secrets. set/remove overlap is `400`; null values are authored values, never removal. Never copy redacted readback into a replacement. Both modes push an opaque settings map to the **running** hook and **commit on ack**: Busbar sends the `configure` op (5s deadline) and only a version-echoing acknowledgment commits the change (audited, versioned, persisted). A nack/timeout commits nothing (`400` names the reason); if another mutation landed during the push, the commit is refused with `409`, retry. A forwarding hook (e.g. `busbar-hook-webrequest`) relays committed settings to its sidecar, so a restarted sidecar never runs blind |

All hook mutations honor `If-Match` against the config-plane ETag, are audited (including rejections: probing which names exist leaves a trail), recorded in version history, and overlay-persisted.

```bash
# Register a global compression gate, live immediately (forwarding to an HTTPS sidecar via the
# first-party busbar-hook-webrequest plugin; requires plugins.enabled: true)
curl -s -X POST -H "x-admin-token: $TOK" -H 'content-type: application/json' \
  --data '{"name":"compress","config":{"kind":"gate","module":"webrequest","settings":{"url":"https://127.0.0.1:8900/"},"prompt":"rw","global":true}}' \
  http://localhost:8081/api/v1/admin/hooks

# Is it running what we pushed? (desired vs reported, with a drift verdict)
curl -s -H "x-admin-token: $TOK" http://localhost:8081/api/v1/admin/hooks/compress/status

# Remove it
curl -s -X DELETE -H "x-admin-token: $TOK" http://localhost:8081/api/v1/admin/hooks/compress
```

### Named-definition maps: `identity-providers`, `export`, `tools`, `agents`

Each top-level named-definition map (`name -> {module, settings, ...}`) has the same five
operations under its own root. `tools` and `agents` are plane operations (`x-busbar-plane`):
mounted only on a node whose config carries that section.

| Endpoint | Does |
|---|---|
| `GET /<map>` | Every definition in the map. Secrets are never projected (`read-only`) |
| `GET /<map>/{name}` | One definition; `404` for an unknown name (`read-only`). Core identity-provider/export definitions additionally expose `configuration` with schema-public settings values, bound to the same installed generation as the ETag. `configured` and `restart_pending` describe configuration, not a runtime refresh acknowledgement. Plane-owned summaries retain their own disclosure contract |
| `PUT /<map>/{name}` | Create or replace one definition (upsert), persisted to the overlay and live after an atomic rebuild-and-swap. A base-config-defined entry is `409` (edit config.yaml). On `identity-providers`, raising `max_admin_scope` is refused outright. Honors `If-Match` |
| `PATCH /<map>/{name}/settings` | Supply exactly one mode: `{settings:{...}}` retains whole-bag replacement; `{edit:{set:{...},remove:[...]}}` replaces only named top-level setting values and explicitly removes named keys. Omitted settings, including hidden credentials, survive edit mode. Null remains a value; set/remove overlap is refused. Every other definition field is unchanged. The existing base-file and trust-ceiling restrictions remain. Honors `If-Match` |
| `DELETE /<map>/{name}` | Remove one definition; refused `409` while another config section still references it by bare name. Honors `If-Match` |

All of these mutations take the config-class rate budget (see above). The plane trust verbs
(`POST /tools/{name}/connect`, `GET /tools/{name}/changes`, `GET /tools/{name}/health`,
`POST /agents/{name}/connect`, `POST /agents/{name}/approve`) are described in the
[Hooks & plugins](#hooks--plugins) table.

## Dynamic plugins: install, list, remove, reload

The admin API can push a signed plugin tarball into `plugins.dir` remotely, the same artifact you
would otherwise copy by hand (see [plugins.md](plugins.md)). Full scope, audited, and it CANNOT
bypass the trust model:

- The upload goes through the SAME gates as a boot-time load: in-memory structural validation
  (tarball shape, manifest completeness, `sha256` binding, `abi_version`), the SAME trust
  evaluation (embedded first-party key / `plugins.trust.publishers` / the explicit `allow_unsigned`
  and `allow_third_party` opt-ins / anti-downgrade floors), and a name/alias conflict check against
  the already-installed loadable set. An untrusted upload is a `409 conflict` naming the exact
  reason and flag; a malformed one is a `400`; nothing is written in either case.
- The endpoint is MANIFEST-ONLY: the uploaded code is never executed during install or listing.
  Loading only ever happens through the boot pipeline (restart / config apply), which re-runs the
  identical three-phase validation. Pushing over the API therefore grants nothing that dropping a
  file in the directory would not; both are inert until the trust gates pass at load.
- Admin-scoped and audited: every attempt (accept AND reject) lands in the hash-chained audit log
  as `plugin.install` / `plugin.remove` with the acting principal.

| Endpoint | Effect |
|---|---|
| `POST /plugins` | Install a signed plugin tarball. Body: `{"file": "<name>.tar.gz", "tarball_b64": "<base64 tarball>"}` (`file` is storage-only; identity comes from the signed manifest inside). `201 Created` with `{file, name, interface_version, trust, version, publisher, note}` |
| `DELETE /plugins/{file}` | Remove a tarball from `plugins.dir` (`204`; `404` if absent). A currently-loaded store keeps running on its loaded handle; removal affects the NEXT load (folder = source of truth) |
| `POST /plugins/reload` | **Live hot swap** (no restart): re-runs the fail-closed plugin pipeline from disk+overlay, rebuilds the registry and `kind: hook` transports, and old libraries drain then unmap. Fail-closed: a bad artifact leaves old plugins serving. Full scope, audited |
| `POST /plugins/rollback` | Explicit, audited, If-Match-guarded rollback. Body: `{"file": "<tarball-filename>"}`. Pins a prior version and lowers the anti-downgrade floor **only for this operator action**. Automatic silent downgrade stays refused. Persists the version pin to the overlay. Full scope, audited |
| `GET /plugins/{name}/schema` | Schema for a module resolved by name or alias in the current registry, or for a configured hook name. Response: `{name, schema, schema_error, trust, source, kind, restart_required_default}`. Supports every plugin kind. The loaded Statement schema takes precedence over the legacy manifest field; absence is `schema:null, schema_error:null`, while malformed legacy schema text is reported separately. Invalid Statement UTF-8/JSON is refused during admission/loading. `source` is `statement` for a linked row, `manifest` for a dropped row (including its Statement projection), or `describe` when a configured hook returns a non-null live schema; a null live reply falls back to the loaded schema. Artifact catalog URLs use `?source=installed_archive&expected_archive_sha256=<digest>` with the encoded archive filename. This authenticated read inspects the exact current archive bytes under the mutation lock, without loading code or falling back to an older loaded schema; it works before reload. The response adds `file`, `archive_sha256`, and `schema_state` (`present`, `absent`, or `invalid` legacy schema), with `source: installed_archive`. Changed or missing guarded bytes return 409; malformed requests/archive metadata return 400. The legacy query-free name/alias lookup still reads the current registry. Follow the catalog's relative `schema_url`; use `POST /plugins/inspect` for candidates before installation. Module settings schemas describe lifecycle inputs after host secret resolution; they do not replace the separate user SecretRef checks or the surrounding deployment schema |

Catalog rows with a published schema carry a server-resolved relative `schema_url` under the admin origin. Artifact URLs identify the exact complete archive digest. An unreadable/oversized backing archive omits the URL and reports `schema_error`, instead of suggesting a loaded schema describes those unknown bytes. Linked rows can publish it too. When no Statement or legacy schema exists, the URL is omitted. A malformed legacy schema keeps a URL and reports `schema_error`; clients must display that error rather than infer an empty settings object. Module schema publication does not claim activation or expose hidden settings values.

```bash
# Install a signed store plugin tarball (takes effect on the next plugin (re)load)
curl -s -X POST -H "x-admin-token: $TOK" -H 'content-type: application/json' \
  -d "{\"file\": \"busbar-store-valkey-1.6.0.tar.gz\",
       \"tarball_b64\": \"$(base64 < busbar-store-valkey-1.6.0-x86_64-linux.tar.gz | tr -d '\n')\"}" \
  http://localhost:8081/api/v1/admin/plugins
# -> 201 {"file":"busbar-store-valkey-1.6.0.tar.gz","name":"busbar-store-valkey",
#         "interface_version":3,"trust":"trusted","version":"1.6.0","publisher":"busbar",
#         "note":"installed durably in the plugins directory; ..."}

# An UNSIGNED tarball against the strict default posture is refused, nothing written:
# -> 409 {"error":{"code":"conflict","message":"plugin rejected by the trust policy: manifest
#         carries no signature; refusing to load an unsigned plugin. Set
#         plugins.trust.allow_unsigned=true to permit unsigned plugins."}}

# Inspect the store-plugin catalog (manifest-only; never executes plugin code)
curl -s -H "x-admin-token: $TOK" 'http://localhost:8081/api/v1/admin/plugins?type=store'

# Remove it
curl -s -X DELETE -H "x-admin-token: $TOK" \
  http://localhost:8081/api/v1/admin/plugins/busbar-store-valkey-1.6.0.tar.gz
```

## Example

```bash
# What am I running, and which plugins are compiled in?
curl -s -H "x-admin-token: $TOK" http://localhost:8081/api/v1/admin/info

# The whole topology with live health, in one call
curl -s -H "x-admin-token: $TOK" 'http://localhost:8081/api/v1/admin/pools?detail=true'

# Preview a config change without applying it
curl -s -X POST -H "x-admin-token: $TOK" -H 'content-type: application/json' \
  --data @proposed.json http://localhost:8081/api/v1/admin/config/validate

# Guarded apply: read the config ETag, then chain it
ETAG=$(curl -sI -H "x-admin-token: $TOK" http://localhost:8081/api/v1/admin/config | grep -i ^etag | cut -d' ' -f2)
curl -s -X POST -H "x-admin-token: $TOK" -H "If-Match: $ETAG" -H 'content-type: application/json' \
  --data @proposed.json http://localhost:8081/api/v1/admin/config/apply
```

---

## The freeze

**v1 is frozen, additive-only.** New fields may appear in any view; no field is ever removed or repurposed; no error `code` ever changes meaning; the scope matrix and the mount prefix are pinned by tests. A breaking change would ship as `/admin/v2/` alongside v1, never in place. Build against v1 and it keeps working.

### Bounded request telemetry

`GET /api/v1/admin/telemetry` uses the existing admin read-only authority. It reads metrics already
collected by the configured recorder; it neither enables collection nor forwards requests to a
plugin or upstream. Disabled or unavailable collection returns `503 unavailable`, never invented
zero measurements. Successful responses use `Cache-Control: no-store`.

The response contains a random 128-bit hexadecimal `process_boot_nonce`, `uptime_since_start_ms`,
`captured_at_unix_ms`, `upper_bounds_ms`, `identities`, `omitted_identities`, `truncated`, and `dropped`. The nonce is stable
across scrapes and config reloads, and changes with a new process. Uptime is monotonic elapsed
milliseconds since shared process-generation initialization (first use), not the operating system's
process-creation time. Reading `GET /info` may establish that epoch before metrics are enabled.
`captured_at_unix_ms` is engine wall-clock Unix milliseconds sampled during capture, separately from
monotonic uptime or consumer receive time. Invalid or out-of-range engine wall time is unavailable.
Counts, microsecond sums, bins, omission/drop counters and timestamps are unsigned decimal strings,
including values above JavaScript's exact-number range.

Each identity names `plane`, `phase`, `pool`, and `ingress_protocol`; its `count`, `errors`, `client_errors`, `sum_us`, and
16 `bins` are cumulative in that process and read coherently. `errors` counts the existing
`error` and `exhausted` outcomes (including HTTP 503); `client_errors` counts HTTP 4xx. They use
the same observed phase event as count and duration, not a separate completion claim. Each bin is exclusive: values are
at most its inclusive upper bound and greater than the preceding bound. The upper bounds in
milliseconds are `[1,5,10,25,50,100,250,500,1000,2500,5000,10000,30000,60000,120000,null]`;
the final null means positive infinity. The bins sum to count. These are not Prometheus cumulative
buckets. Durations are individually truncated to whole microseconds before accumulation.

`LlmProducerDrive` ends when the model producer drive returns; buffered body bytes can still be
pending. `MountedResponseReady` ends when a mounted handler returns its response, before its
body completes. Neither measures completed client delivery or proves a successful body transfer.
Cancellation that bypasses those observation points contributes no completion measurement.

At most 32 identities and 65536 JSON bytes are returned. This response-body cap is distinct from
any transport frame cap or forwarding envelope; callers must account for their own framing. Selection is lexical and stable; labels
over 256 UTF-8 bytes and identities beyond either limit are omitted. `omitted_identities` reports
the number omitted and `truncated` says whether it is nonzero; missing identities are not zeroes.
The fixed `dropped` fields are `invalid_duration`, `integer_overflow`, `series_capacity`,
`boot_nonce_unavailable`, `histogram_capacity`, and `unregistered_labels`. Drop counters are
cumulative diagnostics, not one atomic snapshot with every other counter. Clients should reset
their delta baseline when the process nonce changes and must retain the measured phase labels.

`GET /api/v1/admin/info` also returns the same `process_boot_nonce`, even when metrics are disabled.
It initializes only the process generation, without creating a recorder or histogram buffers.
The value is a 32-character lowercase hexadecimal string, or null if OS randomness failed.
A caller can compare this nonce before and after an approved restart, including restarts within
one wall-clock second. Existing `started_at`, `uptime_seconds`, and configuration fields retain
their meanings; null nonce is unavailable identity, not proof of either a restart or continuity.


### Additional authored host and plane metadata

The host form extension publishes `Plugins` directly from `PluginsCfg`, including `trust`, publisher public keys, fetch variants, anti-downgrade floors and current plugin-log settings. `first_party_floors` is runtime-only: use digest-fenced plugin rollback and its persisted version pins instead of authoring that field. Fetch URLs/environment resolution, signature admission and log semantics still use native validation; `--validate` performs no network fetch. Edit loader policy through the canonical source-fenced document transaction, then follow the operation's actual activation/restart result.

`OAuthAS` comes from the installed OAuth authorization-server owner's input schema callback. A build with no owner publishes an explicitly unsupported non-null schema. The actual current grammar includes issuer, raw signing SecretRef, key ID, default grants, access and refresh lifetimes, FAPI2 posture, and operator-provisioned public-key clients. This is separate from identity-provider settings. Missing signing_key deliberately uses an ephemeral boot key; issuer/key/grant/crypto constraints and security-sensitive changes require canonical native validation. Use explicit source-fenced keep/set/remove/reset edits, preserving private input; configured presence is not activation proof.

A2A and MCP schema documents may carry `x-busbar-user-configuration.version:1`, context `raw_user_configuration`. Follow its `schema_ref` and `member_schema_refs` against the **same returned schema document**. This profile covers the owning plane's raw `agents`/`agent_push` or `tools`/`mcp` inputs, including raw SecretRefs; the lifecycle schema root remains separate. The profile stays partial for a complete host document: apply the published host context and native validation, not only a plane's standalone parser. Section `pools` is an injected runtime projection, not an authored registration; use the top-level host `Pools` input instead. A2A protocol_version is accepted but ignored, nonempty egress_scopes is refused, and MCP pinned_pubkey is unsupported. These controls must never be advertised as enforced policy.

Bind an authored profile to the returned canonical module name, kind, version and declaration source, plus exact installed archive digest when supplied. A linked lookup uses `source=linked_statement`; an installed-archive lookup is digest-fenced and describes those bytes, not active runtime. A legacy manifest schema fallback is not proof of Statement origin. Rejected or unavailable module metadata confers no authoring authority. The existing `input_schema_complete:false` continues to describe lifecycle-schema completeness; it is not silently promoted by the authored extension.

Durable adjustment outcomes additionally expose optional `x-busbar-adjust-effect` (`applied|not_applied|unknown`) from the host's known outcome. A claim-before-binding `action_in_flight` error carries `operation_id`, `effect:unknown` and `recovery:reconcile_ledger_recovery`; clients reconcile those fields without parsing its message.
