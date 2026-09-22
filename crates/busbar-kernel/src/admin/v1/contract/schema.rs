// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SCHEMA-ONLY response views for the admin endpoints whose handlers build an ad-hoc
//! `serde_json::json!({…})` body rather than serializing a named contract struct (the keys resource,
//! the config-mutation results, `hooks/{name}/schema`+`/status`, the version detail/diff, and the
//! `{items,next_cursor}` list envelopes the keys/audit/versions handlers hand-roll).
//!
//! These types are **never serialized at runtime** — they exist purely so `openapi_doc()` can emit a
//! typed `$ref` for every operation instead of a bodyless `{"description":"OK"}`. Each mirrors, field
//! for field, the exact JSON its handler produces; the golden/drift test (`#[cfg(feature =
//! "openapi-schema")]`) keeps the whole doc — and therefore these shapes — locked to the code. The
//! module is compiled ONLY under `openapi-schema` (a CI-only feature), so it adds nothing to the
//! shipped binary. `#[allow(dead_code)]` because the fields are read by schemars' derive, not by
//! Rust code.

use schemars::JsonSchema;
use serde::Serialize;

use super::{AdminError, HookView};

/// Virtual-key metadata: the `key_meta()` shape returned by `GET /keys/{id}`, `PATCH /keys/{id}`,
/// and as each item of `GET /keys`. Never the secret or its hash. 1.5.0: keys are PURE AUTH, no
/// inline limits; `allowed_pools` is `null` = all pools, `[]` = no pools; `group` names the
/// bound `groups:` entry (`null` = unlimited).
#[derive(Serialize, JsonSchema)]
pub struct KeyView {
    pub id: String,
    pub name: String,
    pub allowed_pools: Option<Vec<String>>,
    pub group: Option<String>,
    pub enabled: bool,
    pub created_at: u64,
    pub labels: std::collections::BTreeMap<String, String>,
    /// `enabled` alone cannot distinguish a reversible pause from either of the two permanent
    /// dispositions. `PATCH {enabled:false}`, `POST /keys/{id}/revoke`, and `DELETE /keys/{id}` all
    /// used to leave `enabled: false` with nothing else to tell them apart. One of exactly four
    /// values, additive and derived (never independently settable):
    /// - `"active"`: enabled, not revoked, not deleted.
    /// - `"disabled"`: `PATCH {enabled:false}`. Reversible: `PATCH {enabled:true}` restores it.
    /// - `"revoked"`: `POST /keys/{id}/revoke`. Permanent: denylisted, but the binding row (and
    ///   `GET /keys/{id}`) stays live for audit/usage attribution.
    /// - `"tombstoned"`: `DELETE /keys/{id}`. Permanent: denylisted AND hard-deleted; the row is
    ///   kept only so id-attributed billing/audit history keeps resolving. Omitted from a plain
    ///   `GET /keys` by default; visible there with `?include=tombstoned`.
    pub state: String,
}

/// `POST /keys` (mint): the key metadata plus the ONCE-shown signed token, and (when an AWS SigV4
/// credential was requested) the AccessKeyId + secret access key. The AWS fields are absent on a
/// bearer-only mint.
#[derive(Serialize, JsonSchema)]
pub struct CreatedKeyView {
    pub id: String,
    pub name: String,
    pub allowed_pools: Option<Vec<String>>,
    pub group: Option<String>,
    pub enabled: bool,
    pub created_at: u64,
    pub labels: std::collections::BTreeMap<String, String>,
    /// Same field as `KeyView.state`; a fresh mint is always `"active"` (enabled, not
    /// revoked, not deleted).
    pub state: String,
    /// The busbar-SIGNED token: the key credential (1.5.0), shown EXACTLY once and never
    /// returned by any read. (This is the field a client must capture to authenticate.)
    pub token: String,
    /// Unix-seconds expiry of the signed token.
    pub expires_at: u64,
    /// Whether this mint AUTO-PROVISIONED its bound group leaf (self-service); lets a portal
    /// distinguish "bound to an existing bucket" from "created your personal bucket + bound".
    pub group_provisioned: bool,
    /// AWS AccessKeyId (present only when `issue_aws_credential` was set). Not secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_access_key_id: Option<String>,
    /// AWS SigV4 secret access key, shown once (present only with an AWS credential).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_secret_access_key: Option<String>,
}

/// `POST /keys/{id}/rotate`: the key metadata plus the ONCE-shown fresh CREDENTIAL. Exactly one of
/// `token`+`expires_at` (a 1.5.0 signed-token key: a new token at a new binding generation, every
/// prior token now rejected) or `secret` (a legacy hashed-secret key) is present.
#[derive(Serialize, JsonSchema)]
pub struct RotatedKeyView {
    pub id: String,
    pub name: String,
    pub allowed_pools: Option<Vec<String>>,
    pub group: Option<String>,
    pub enabled: bool,
    pub created_at: u64,
    pub labels: std::collections::BTreeMap<String, String>,
    /// Same field as `KeyView.state`; rotate does not change `enabled`/revoked/tombstoned
    /// status, so this reflects whatever the key's disposition already was (rotating a `disabled` or
    /// `revoked` key is legal and leaves it exactly that; only a `tombstoned` key refuses to rotate,
    /// which surfaces as 404 instead of this response).
    pub state: String,
    /// The fresh busbar-SIGNED token, shown EXACTLY once (signed-token keys).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Unix-seconds expiry of the re-minted signed token (present with `token`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// The fresh bearer secret, shown EXACTLY once (legacy hashed-secret keys only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

/// `GET /keys/{id}/usage`: the key's all-time attribution counters (a 1.5.0 key bucket accrues in
/// the `total` window; limits live on the bound group's own windows) plus the fraction of the
/// tightest `requests`/`tokens` limit across the group chain remaining (`null` = no such limit).
#[derive(Serialize, JsonSchema)]
pub struct KeyMeteringView {
    pub id: String,
    /// Always `"total"` (the key attribution window).
    pub budget_period: String,
    /// Always `0` (the all-time window start).
    pub window_start: u64,
    pub as_of: u64,
    /// The bound `groups:` entry (`null` = unlimited key).
    pub group: Option<String>,
    pub spend_cents: i64,
    pub tokens: u64,
    pub requests: u64,
    pub rate_headroom: Option<f64>,
}

/// `GET /keys`: the cursor-paginated key list envelope (`{items, next_cursor}`, hand-rolled in the
/// keys handler rather than via `Page<T>`).
#[derive(Serialize, JsonSchema)]
pub struct KeyPageView {
    pub items: Vec<KeyView>,
    pub next_cursor: Option<String>,
}

/// `POST /config/apply`: apply-a-full-config result. The change is live but not written to disk.
#[derive(Serialize, JsonSchema)]
pub struct ConfigApplyView {
    pub applied: bool,
    pub config_version: u64,
    pub note: String,
}

/// `POST /config/reload`: reload-from-disk result.
#[derive(Serialize, JsonSchema)]
pub struct ConfigReloadView {
    pub reloaded: bool,
    pub config_version: u64,
}

/// `POST /restart`: accepted-and-draining result.
#[derive(Serialize, JsonSchema)]
pub struct RestartView {
    pub restarting: bool,
    /// Whether a process supervisor was detected. False means the caller confirmed explicitly.
    pub supervisor_detected: bool,
    pub note: String,
}

/// `POST /config/rollback`: restore-a-retained-version result (the restored version + the NEW
/// config version the rollback produced).
#[derive(Serialize, JsonSchema)]
pub struct ConfigRollbackView {
    pub restored_version: u64,
    pub config_version: u64,
}

/// `DELETE /overlay/{section}`, per-section overlay reset result: the section reverted, the
/// resulting config version, and whether anything changed (`false` = the section had no overlay state,
/// an idempotent no-op).
#[derive(Serialize, JsonSchema)]
pub struct OverlayResetView {
    /// The section that was reset. This endpoint's `section` path parameter enumerates the valid
    /// set; it is deliberately not restated here, because the hand-written copy that used to sit on
    /// this line went stale the moment a section was added.
    pub reset: String,
    pub config_version: u64,
    /// `true` when the reset discarded overlay mutations; `false` for an already-empty section.
    pub changed: bool,
}

/// `POST /auth/cache/flush`: number of cached credential-decision entries dropped.
#[derive(Serialize, JsonSchema)]
pub struct CacheFlushView {
    pub flushed: usize,
}

/// `POST /keys/{id}/revoke`: the revoked key's id (denylisted without deleting the binding). 1.5.0.
#[derive(Serialize, JsonSchema)]
pub struct RevokeView {
    /// The id that was revoked (durably denylisted; the binding record remains).
    pub revoked: String,
}

/// `POST /signing-key/rotate`: the current key-signing key id plus the REVOKE-ALL warning. 1.5.0 is
/// single-key: the actual swap is an operator action, so this reports intent, not an in-process swap.
#[derive(Serialize, JsonSchema)]
pub struct SigningKeyRotateView {
    /// The current signing-key id (`kid`) that tokens are minted under.
    pub current_kid: String,
    /// Always `true`: rotating the signing key revokes every outstanding key (all must be re-minted).
    pub revoke_all: bool,
    /// Human-readable guidance for the operator-driven lockstep rotation.
    pub message: String,
}

/// `GET`/`PUT /config/settings` (1.5.0 full-config coverage): the API-settable single-value config
/// overlay (`root` section) and, on a PUT, the apply metadata. `settings` is the CURRENT effective
/// root override (the merge of prior overlay + this request). It is overlay-persisted so it survives
/// a restart. 1.5.3: a MUTABLE config always has a writable `config.overlay` backend (the boot
/// invariant), so a successful PUT is ALWAYS durable; a LOCKED config (`config.locked: true`) refuses
/// the PUT (`400`) instead of applying it in memory only; the silent-loss outcome is gone.
/// `reload_to_apply` names the fields whose new value is DURABLY STORED but not yet LIVE: the
/// process-level binds (`listen`/`admin_listen` socket, `tls`/`admin_tls` bind, and the
/// `admin_require_mtls` boot-guard) are read once at process start, and the durable `store` backend
/// is reused across a hot reload; none can hot-swap, so they take effect on the next RESTART (or a
/// supervisor restart), NEVER on a
/// `POST /config/reload`: a reload re-reads disk and rebuilds the `App` but does not rebind sockets,
/// rebuild the TLS acceptor, or re-open the store. It is always EMPTY when nothing was durably stored
/// (no overlay); `note` names the affected fields instead. Everything else
/// (`rate_card`/`per_request_fee`/`security`/`health`/`routing`) is LIVE on the swap;
/// `limits` is live EXCEPT four boot-scoped fields (see `reload_to_apply_fields`):
/// `upstream_request_timeout_secs`/`pool_max_idle_per_host`/`pool_idle_timeout_secs`, which the
/// reused `UpstreamClients` only reads once at boot, and `max_inbound_concurrent`, which is baked
/// once into the data router's `GlobalConcurrencyLimitLayer` at process start (a config apply swaps
/// only `Arc<App>`, never the router): two independent freezing mechanisms. There is NO
/// `observability` section here, and no `metrics` one either: 1.5.3 DELETED both from the config
/// grammar, and `RootSettings` (what this endpoint projects) carries neither field: a PUT naming
/// `observability` is a loud `400` (`deny_unknown_fields`), never a silent no-op. All telemetry
/// egress is now `export:`, a NAMED MAP of exporter instances that this endpoint does not reach at
/// all: it is edited in `config.yaml` and made live by a plugin reload, not by `PUT /config/settings`.
/// Each `export:` entry is keyed by an operator-chosen instance name and carries a `module:` naming
/// the exporter plus a `settings:` bag that module validates, and MAY carry a `streams:`
/// subscription list. The built-in modules are `prometheus` (carries the `metrics` stream), `otlp`
/// (`traces`), and `request-log-webhook` + `request-log-file` (`logs`); subscribing an instance to a
/// stream its module does not carry is rejected rather than silently delivering nothing. An entry
/// MAY also carry a `fields:` projection, but do NOT plan on it in 1.5.3: it is parsed and enforced
/// yet unreachable with every built-in module, because each stream they carry has a pinned field
/// that has no producer yet, so any `fields:` on them is rejected. Omit it and receive the stream's
/// produced default set.
/// `advanced` is live EXCEPT `response_headers`: `response_headers.server_timing` is
/// baked into router middleware state at boot (same "config apply swaps `Arc<App>`, never the
/// router" freezing as `max_inbound_concurrent`) and `response_headers.route_policy` seeds a
/// process-global `OnceLock`; neither is rebuilt by an apply.
#[derive(Serialize, JsonSchema)]
pub struct ConfigSettingsView {
    /// `true` on a PUT that stored + swapped; `false` on a GET (a pure read).
    pub applied: bool,
    pub config_version: u64,
    /// The current effective root-section overlay (only the fields the operator has set; base
    /// `config.yaml` stands for the rest). An arbitrary JSON object (the `RootSettings` projection),
    /// REDACTED by `service::redact_settings_bags`: every opaque `settings:` bag inside it (today
    /// `store.settings`, whose `url` is a credential in busbar's own docs) appears as
    /// `settings_keys`: sorted key names, no values. Same on the GET and on the PUT echo.
    ///
    /// This field NAME is frozen wire and is the response ENVELOPE member, not a plugin settings
    /// bag; the redaction applies to the bags nested INSIDE it.
    // settings-leak-lint: allow — response ENVELOPE member; every bag nested inside it is reduced to
    // `settings_keys` by `service::redact_settings_bags` before serialization (both verbs).
    pub settings: serde_json::Value,
    /// Fields that were stored durably but are RESTART-TO-APPLY: a socket rebind, a TLS acceptor
    /// build and a store open all happen once at process start, so a `POST /config/reload` does NOT
    /// make them live; `POST /restart` (or a supervisor restart) does. Empty when the PUT touched
    /// only live-swappable fields (or on a GET). The field NAME is frozen wire; only this description
    /// changed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reload_to_apply: Vec<String>,
    /// A human note describing the live-vs-reload split (absent on a GET).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// `PUT /admin-auth`: the resource post-state (`{configured, modules}`, the same shape
/// `GET /admin-auth` returns) plus apply metadata, so a client uses the PUT response as post-state.
#[derive(Serialize, JsonSchema)]
pub struct AdminAuthPutView {
    pub configured: bool,
    pub modules: Vec<String>,
    pub applied: bool,
    pub config_version: u64,
    pub note: String,
}

/// `GET /hooks/{name}/schema`: the hook's self-described settings JSON Schema (proxied over the
/// `describe` wire message), or `null` when the hook/transport does not answer.
#[derive(Serialize, JsonSchema)]
pub struct HookSchemaView {
    pub name: String,
    /// The hook's settings JSON Schema verbatim (an arbitrary JSON object), or `null`.
    pub schema: Option<serde_json::Value>,
}

/// `GET /plugins/{name}/schema`: the generalized, all-kinds sibling of [`HookSchemaView`].
/// Carries `trust`/`source`/`schema_error` on top of
/// `{name, schema}` so busbar-ui never has to infer trust state or the describe/manifest
/// precedence rule from context; the server always picks exactly one source and reports which.
#[derive(Serialize, JsonSchema)]
pub struct PluginSchemaView {
    pub name: String,
    /// The plugin's semantic version from its manifest. Present on `POST /plugins/inspect` (which
    /// previews an on-disk candidate's manifest); `null`/absent on `GET /plugins/{file}/schema`, which
    /// does not surface the version. Declared here so a codegen'd client keeps the field the inspect
    /// handler always sends, rather than silently dropping it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The plugin's settings JSON Schema verbatim, or `null`, either because the manifest never
    /// set `settings_schema`, or (distinctly, see `schema_error`) because it did but the value
    /// failed to parse.
    pub schema: Option<serde_json::Value>,
    /// Set only when the manifest's `settings_schema` was present but failed to parse as JSON;
    /// `null` for a manifest that genuinely never set the field. Never collapsed into a bare
    /// `schema: null`: a present-but-corrupt schema is a real
    /// authoring/packaging bug, not "this plugin simply has none."
    pub schema_error: Option<String>,
    /// `"trusted" | "unverified" | "rejected"`: the same vocabulary the plugin catalog already
    /// uses (never `"verified"`).
    pub trust: String,
    /// `"describe"` when a currently-loaded `kind: hook` answered its live `describe` wire
    /// message (the existing describe-proxy behavior, unchanged); `"manifest"` otherwise. Lets
    /// busbar-ui explain "why does this form look different from what I expected" without
    /// implementing the describe/manifest precedence rule itself.
    pub source: String,
    /// The plugin's `kind` (`hook` | `secret` | …) from its manifest. Both `GET /plugins/{file}/schema`
    /// and `POST /plugins/inspect` emit it (`null` only when the plugin cannot be resolved to a
    /// manifest). Declared so codegen'd clients keep it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The kind-derived restart-scoping default (`busbar_plugin_sign::kind_restart_default`), so
    /// busbar-ui need not hardcode the kind→default table. Emitted by both schema endpoints (`null`
    /// only when the plugin has no resolvable manifest/kind). Declared so codegen'd clients keep it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_required_default: Option<bool>,
}

/// The DESIRED settings side of `hooks/{name}/status`: busbar's registry copy of the hook's settings
/// (KEY NAMES only, see [`super::HookView::settings_keys`]) and their version.
#[derive(Serialize, JsonSchema)]
pub struct HookDesiredStatus {
    /// Sorted KEY NAMES of the desired settings bag, never its values.
    pub settings_keys: Vec<String>,
    pub settings_version: u64,
}

/// The REPORTED settings side of `hooks/{name}/status`: what the hook says it is actually running
/// (present only when the hook answered `status`).
///
/// KEY NAMES only, and for a sharper reason than the desired side: the reported bag is the hook's
/// ECHO of the SECRET-RESOLVED settings busbar pushed it, i.e. the PLAINTEXT of every `SecretRef`,
/// and this read is reachable at READ-ONLY admin scope. `null` when the hook answered `status` but
/// reported no settings.
#[derive(Serialize, JsonSchema)]
pub struct HookReportedStatus {
    /// Sorted KEY NAMES of the observed settings bag, never its values.
    pub settings_keys: Option<Vec<String>>,
    pub settings_version: Option<u64>,
}

/// `GET /hooks/{name}/status`, the hook's OBSERVED state: desired vs reported settings with a
/// `drift` verdict, plus the hook's self-reported metrics. `reported`/`drift` are `null` and `note`
/// is present when the hook did not answer (fail-open); `metrics` is invariantly an array.
#[derive(Serialize, JsonSchema)]
pub struct HookStatusView {
    pub name: String,
    pub desired: HookDesiredStatus,
    pub reported: Option<HookReportedStatus>,
    pub drift: Option<bool>,
    /// The DESIRED settings KEY NAMES the hook is not actually running: the actionable half of
    /// `drift`, carrying names this body already serves and no value from either bag. Invariantly an
    /// array (empty on the no-answer branch, where no drift is known).
    pub drift_keys: Vec<String>,
    /// Validated + bounded self-reported metrics; each entry carries `{name, type, value}` and, when
    /// the hook sent them, optional `labels`/`quantiles`/`estimated`/`ci_low`/`ci_high`/`help`/
    /// `label`/`unit`/`viz`/`max` members.
    ///
    /// schemars' blanket `JsonSchema` impl for
    /// `serde_json::Value` renders as the JSON-Schema-2020-12 boolean `true` (`schemars-1.2.1`'s
    /// `json_schema_impls/serdejson.rs`), which is legal 2020-12 but, nested here as this array's
    /// `items`, is a boolean SUB-schema, and `kin-openapi` (the parser under `oapi-codegen`, which
    /// every published SDK generates through) cannot represent one at all: the parse aborts, taking
    /// out Python/TS/Go SDK regeneration simultaneously. `#[schemars(schema_with)]` overrides just
    /// this field's schema to `{"type": "array", "items": {}}`; `{}` is the equivalent "accepts
    /// anything" schema every generator DOES understand, and is what busbar-ui's own
    /// `openapi-prep.py` already rewrites `items: true` into client-side. This is the only
    /// `items: true` in the document; every other `additionalProperties: true` schemars emits
    /// elsewhere is a boolean in a position `kin-openapi` handles fine and is deliberately untouched.
    #[schemars(schema_with = "hook_status_metrics_schema")]
    pub metrics: Vec<serde_json::Value>,
    pub as_of: u64,
    /// Always `"live"` (the read is a live transport query).
    pub source: String,
    /// A short human note present only on the fail-open (no-answer) branch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The `HookStatusView.metrics` array's item schema: `{}`, not schemars' default boolean
/// `true` for `serde_json::Value` — the "accepts anything" schema every generator understands, in a
/// position (`items`) where the boolean form is fatal to `kin-openapi`/`oapi-codegen`.
fn hook_status_metrics_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "array",
        "items": {}
    })
}

/// `GET /config/versions/{v}`: one retained config version WITH its full hook-surface snapshot
/// (projected through the wire `HookView`, keyed by hook name) and the global wiring at that version.
#[derive(Serialize, JsonSchema)]
pub struct ConfigVersionDetailView {
    pub version: u64,
    pub ts: u64,
    pub principal: String,
    pub summary: String,
    pub hooks: std::collections::BTreeMap<String, HookView>,
    pub global_hooks: Vec<String>,
}

/// The `hooks` object of a `GET /config/diff`: hook names added / removed / changed between the two
/// versions.
#[derive(Serialize, JsonSchema)]
pub struct ConfigDiffHooks {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

/// The `global_hooks` delta of a `GET /config/diff`, present only when the global wiring changed.
#[derive(Serialize, JsonSchema)]
pub struct ConfigDiffGlobalHooks {
    pub from: Vec<String>,
    pub to: Vec<String>,
}

/// `GET /config/diff`: structured hook-surface diff between two retained versions. `global_hooks` is
/// present only when the global wiring differed between the two sides.
#[derive(Serialize, JsonSchema)]
pub struct ConfigDiffView {
    pub from: u64,
    pub to: u64,
    pub hooks: ConfigDiffHooks,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_hooks: Option<ConfigDiffGlobalHooks>,
}

/// `GET /audit`: the cursor-paginated audit-log envelope (`{items, next_cursor}`, hand-rolled in the
/// audit handler).
#[derive(Serialize, JsonSchema)]
pub struct AuditPageView {
    pub items: Vec<crate::audit_ring::AuditEntry>,
    pub next_cursor: Option<String>,
}

/// `GET /config/versions`: the cursor-paginated version-history envelope (`{items, next_cursor}`).
#[derive(Serialize, JsonSchema)]
pub struct ConfigVersionPageView {
    pub items: Vec<crate::admin::versions::ConfigVersion>,
    pub next_cursor: Option<String>,
}

/// The stable v1 error envelope (`{"error":{"code","message"}}`). Kept as a schema-only type so the
/// generated `Error` component matches the hand-written one exactly and both stay code-derived.
/// Referenced only via its TYPE (schemars' derive walks it for the schema) -- never constructed as
/// a value, so it needs the struct-level allow the module doc promises, not just a field-level one.
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

/// The `error` member of [`ErrorBody`]: a stable machine `code` + human `message`.
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub struct ErrorDetail {
    /// One of the frozen [`AdminError`] codes (see the `code` enum on the generated schema).
    pub code: String,
    pub message: String,
}

/// A compile-time cross-check that this schema module stays in step with the frozen error taxonomy:
/// referencing every [`AdminError`] variant here means adding a new variant forces a look at this
/// module. (Never called — the match is the assertion.)
#[allow(unused)]
fn _error_taxonomy_is_referenced(e: &AdminError) {
    match e {
        AdminError::NotFound { .. }
        | AdminError::Unauthorized
        | AdminError::MethodNotAllowed
        | AdminError::Forbidden { .. }
        | AdminError::Validation(_)
        | AdminError::VersionConflict(_)
        | AdminError::Conflict(_)
        | AdminError::RateLimited
        | AdminError::Internal
        | AdminError::Unavailable(_) => {}
    }
}
