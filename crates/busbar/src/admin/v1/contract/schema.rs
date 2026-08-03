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

/// Virtual-key metadata — the `key_meta()` shape returned by `GET /keys/{id}`, `PATCH /keys/{id}`,
/// and as each item of `GET /keys`. Never the secret or its hash. 1.5.0: keys are PURE AUTH, no
/// inline limits; `allowed_pools` is `null` = all pools, `[]` = no pools (C6); `group` names the
/// bound `groups:` entry (`null` = unlimited).
#[derive(Serialize, JsonSchema)]
pub(crate) struct KeyView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) allowed_pools: Option<Vec<String>>,
    pub(crate) group: Option<String>,
    pub(crate) enabled: bool,
    pub(crate) created_at: u64,
    pub(crate) labels: std::collections::BTreeMap<String, String>,
    /// E-007: `enabled` alone cannot distinguish a reversible pause from either of the two permanent
    /// dispositions — `PATCH {enabled:false}`, `POST /keys/{id}/revoke`, and `DELETE /keys/{id}` all
    /// used to leave `enabled: false` with nothing else to tell them apart. One of exactly four
    /// values, additive and derived (never independently settable):
    /// - `"active"` — enabled, not revoked, not deleted.
    /// - `"disabled"` — `PATCH {enabled:false}`. Reversible: `PATCH {enabled:true}` restores it.
    /// - `"revoked"` — `POST /keys/{id}/revoke`. Permanent: denylisted, but the binding row (and
    ///   `GET /keys/{id}`) stays live for audit/usage attribution.
    /// - `"tombstoned"` — `DELETE /keys/{id}`. Permanent: denylisted AND hard-deleted; the row is
    ///   kept only so id-attributed billing/audit history keeps resolving. Omitted from a plain
    ///   `GET /keys` by default; visible there with `?include=tombstoned`.
    pub(crate) state: String,
}

/// `POST /keys` (mint) — the key metadata plus the ONCE-shown signed token, and (when an AWS SigV4
/// credential was requested) the AccessKeyId + secret access key. The AWS fields are absent on a
/// bearer-only mint.
#[derive(Serialize, JsonSchema)]
pub(crate) struct CreatedKeyView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) allowed_pools: Option<Vec<String>>,
    pub(crate) group: Option<String>,
    pub(crate) enabled: bool,
    pub(crate) created_at: u64,
    pub(crate) labels: std::collections::BTreeMap<String, String>,
    /// E-007: same field as `KeyView.state` — a fresh mint is always `"active"` (enabled, not
    /// revoked, not deleted).
    pub(crate) state: String,
    /// The busbar-SIGNED token — the key credential (1.5.0, S1), shown EXACTLY once and never
    /// returned by any read. (This is the field a client must capture to authenticate.)
    pub(crate) token: String,
    /// Unix-seconds expiry of the signed token.
    pub(crate) expires_at: u64,
    /// Whether this mint AUTO-PROVISIONED its bound group leaf (self-service D2) — lets a portal
    /// distinguish "bound to an existing bucket" from "created your personal bucket + bound".
    pub(crate) group_provisioned: bool,
    /// AWS AccessKeyId (present only when `issue_aws_credential` was set). Not secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) aws_access_key_id: Option<String>,
    /// AWS SigV4 secret access key — shown once (present only with an AWS credential).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) aws_secret_access_key: Option<String>,
}

/// `POST /keys/{id}/rotate` — the key metadata plus the ONCE-shown fresh CREDENTIAL. Exactly one of
/// `token`+`expires_at` (a 1.5.0 signed-token key: a new token at a new binding generation, every
/// prior token now rejected) or `secret` (a legacy hashed-secret key) is present.
#[derive(Serialize, JsonSchema)]
pub(crate) struct RotatedKeyView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) allowed_pools: Option<Vec<String>>,
    pub(crate) group: Option<String>,
    pub(crate) enabled: bool,
    pub(crate) created_at: u64,
    pub(crate) labels: std::collections::BTreeMap<String, String>,
    /// E-007: same field as `KeyView.state` — rotate does not change `enabled`/revoked/tombstoned
    /// status, so this reflects whatever the key's disposition already was (rotating a `disabled` or
    /// `revoked` key is legal and leaves it exactly that; only a `tombstoned` key refuses to rotate,
    /// which surfaces as 404 instead of this response).
    pub(crate) state: String,
    /// The fresh busbar-SIGNED token — shown EXACTLY once (signed-token keys).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) token: Option<String>,
    /// Unix-seconds expiry of the re-minted signed token (present with `token`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expires_at: Option<u64>,
    /// The fresh bearer secret — shown EXACTLY once (legacy hashed-secret keys only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) secret: Option<String>,
}

/// `GET /keys/{id}/usage`: the key's all-time attribution counters (a 1.5.0 key bucket accrues in
/// the `total` window; limits live on the bound group's own windows) plus the fraction of the
/// tightest `requests`/`tokens` limit across the group chain remaining (`null` = no such limit).
#[derive(Serialize, JsonSchema)]
pub(crate) struct KeyMeteringView {
    pub(crate) id: String,
    /// Always `"total"` (the key attribution window).
    pub(crate) budget_period: String,
    /// Always `0` (the all-time window start).
    pub(crate) window_start: u64,
    pub(crate) as_of: u64,
    /// The bound `groups:` entry (`null` = unlimited key).
    pub(crate) group: Option<String>,
    pub(crate) spend_cents: i64,
    pub(crate) tokens: u64,
    pub(crate) requests: u64,
    pub(crate) rate_headroom: Option<f64>,
}

/// `GET /keys` — the cursor-paginated key list envelope (`{items, next_cursor}`, hand-rolled in the
/// keys handler rather than via `Page<T>`).
#[derive(Serialize, JsonSchema)]
pub(crate) struct KeyPageView {
    pub(crate) items: Vec<KeyView>,
    pub(crate) next_cursor: Option<String>,
}

/// `POST /config/apply` — apply-a-full-config result. The change is live but not written to disk.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigApplyView {
    pub(crate) applied: bool,
    pub(crate) config_version: u64,
    pub(crate) note: String,
}

/// `POST /config/reload` — reload-from-disk result.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigReloadView {
    pub(crate) reloaded: bool,
    pub(crate) config_version: u64,
}

/// `POST /restart` — accepted-and-draining result.
#[derive(Serialize, JsonSchema)]
pub(crate) struct RestartView {
    pub(crate) restarting: bool,
    /// Whether a process supervisor was detected. False means the caller confirmed explicitly.
    pub(crate) supervisor_detected: bool,
    pub(crate) note: String,
}

/// `POST /config/rollback` — restore-a-retained-version result (the restored version + the NEW
/// config version the rollback produced).
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigRollbackView {
    pub(crate) restored_version: u64,
    pub(crate) config_version: u64,
}

/// `DELETE /overlay/{section}` — per-section overlay reset result: the section reverted, the
/// resulting config version, and whether anything changed (`false` = the section had no overlay state,
/// an idempotent no-op).
#[derive(Serialize, JsonSchema)]
pub(crate) struct OverlayResetView {
    /// The section that was reset (`groups` | `hooks` | `root` | `plugin_versions`).
    pub(crate) reset: String,
    pub(crate) config_version: u64,
    /// `true` when the reset discarded overlay mutations; `false` for an already-empty section.
    pub(crate) changed: bool,
}

/// `POST /auth/cache/flush` — number of cached credential-decision entries dropped.
#[derive(Serialize, JsonSchema)]
pub(crate) struct CacheFlushView {
    pub(crate) flushed: usize,
}

/// `POST /keys/{id}/revoke` — the revoked key's id (denylisted without deleting the binding). 1.5.0.
#[derive(Serialize, JsonSchema)]
pub(crate) struct RevokeView {
    /// The id that was revoked (durably denylisted; the binding record remains).
    pub(crate) revoked: String,
}

/// `POST /signing-key/rotate` — the current key-signing key id plus the REVOKE-ALL warning. 1.5.0 is
/// single-key: the actual swap is an operator action, so this reports intent, not an in-process swap.
#[derive(Serialize, JsonSchema)]
pub(crate) struct SigningKeyRotateView {
    /// The current signing-key id (`kid`) that tokens are minted under.
    pub(crate) current_kid: String,
    /// Always `true`: rotating the signing key revokes every outstanding key (all must be re-minted).
    pub(crate) revoke_all: bool,
    /// Human-readable guidance for the operator-driven lockstep rotation.
    pub(crate) message: String,
}

/// `GET`/`PUT /config/settings` (1.5.0 full-config coverage) — the API-settable single-value config
/// overlay (`root` section) and, on a PUT, the apply metadata. `settings` is the CURRENT effective
/// root override (the merge of prior overlay + this request). It is overlay-persisted so it survives
/// a restart WHEN a config overlay is configured (`BUSBAR_CONFIG_OVERLAY`) — a busbar with none
/// applies the change live only, and `note` says so; `PUT` with `"persist": true` makes storage
/// mandatory, refusing (`400`) rather than silently applying in memory when no overlay exists.
/// `reload_to_apply` names the fields whose new value is DURABLY STORED but not yet LIVE: the
/// process-level binds (`listen`/`admin_listen` socket, `tls`/`admin_tls` bind, `admin_insecure`) are
/// read once at process start, and the durable `store` backend is reused across a hot reload — none
/// can hot-swap, so they take effect on the next RESTART (or a supervisor restart), NEVER on a
/// `POST /config/reload` — a reload re-reads disk and rebuilds the `App` but does not rebind sockets,
/// rebuild the TLS acceptor, or re-open the store. It is always EMPTY when nothing was durably stored
/// (no overlay); `note` names the affected fields instead. Everything else
/// (`rate_card`/`per_request_fee`/`security`/`advanced`/`metrics`/`health`/`routing`) is LIVE on the
/// swap; `limits` is live EXCEPT four boot-scoped fields (see `reload_to_apply_fields`):
/// `upstream_request_timeout_secs`/`pool_max_idle_per_host`/`pool_idle_timeout_secs`, which the
/// reused `UpstreamClients` only reads once at boot, and `max_inbound_concurrent`, which is baked
/// once into the data router's `GlobalConcurrencyLimitLayer` at process start (a config apply swaps
/// only `Arc<App>`, never the router) — two independent freezing mechanisms. `observability` is live
/// EXCEPT three boot-scoped fields: `emit_server_timing` (baked into router middleware state at
/// boot), `request_log_webhook_url` (seeds a process-global `OnceLock` that no-ops after the first
/// `main()` call), and `otlp_url` (feeds a one-shot `tracing_subscriber` init) — none rebuilt by an
/// apply.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigSettingsView {
    /// `true` on a PUT that stored + swapped; `false` on a GET (a pure read).
    pub(crate) applied: bool,
    pub(crate) config_version: u64,
    /// The current effective root-section overlay (only the fields the operator has set; base
    /// `config.yaml` stands for the rest). An arbitrary JSON object (the `RootSettings` projection).
    pub(crate) settings: serde_json::Value,
    /// Fields that were stored durably but are RESTART-TO-APPLY: a socket rebind, a TLS acceptor
    /// build and a store open all happen once at process start, so a `POST /config/reload` does NOT
    /// make them live — `POST /restart` (or a supervisor restart) does. Empty when the PUT touched
    /// only live-swappable fields (or on a GET). The field NAME is frozen wire; only this description
    /// changed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) reload_to_apply: Vec<String>,
    /// A human note describing the live-vs-reload split (absent on a GET).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) note: Option<String>,
}

/// `PUT /admin-auth` — the resource post-state (`{configured, modules}`, the same shape
/// `GET /admin-auth` returns) plus apply metadata, so a client uses the PUT response as post-state.
#[derive(Serialize, JsonSchema)]
pub(crate) struct AdminAuthPutView {
    pub(crate) configured: bool,
    pub(crate) modules: Vec<String>,
    pub(crate) applied: bool,
    pub(crate) config_version: u64,
    pub(crate) note: String,
}

/// `GET /hooks/{name}/schema` — the hook's self-described settings JSON Schema (proxied over the
/// `describe` wire message), or `null` when the hook/transport does not answer.
#[derive(Serialize, JsonSchema)]
pub(crate) struct HookSchemaView {
    pub(crate) name: String,
    /// The hook's settings JSON Schema verbatim (an arbitrary JSON object), or `null`.
    pub(crate) schema: Option<serde_json::Value>,
}

/// `GET /plugins/{name}/schema` — the generalized, all-kinds sibling of [`HookSchemaView`]
/// (plugin-settings-schema-SPEC.md). Carries `trust`/`source`/`schema_error` on top of
/// `{name, schema}` so busbar-ui never has to infer trust state or the describe/manifest
/// precedence rule from context — the server always picks exactly one source and reports which.
#[derive(Serialize, JsonSchema)]
pub(crate) struct PluginSchemaView {
    pub(crate) name: String,
    /// The plugin's semantic version from its manifest. Present on `POST /plugins/inspect` (which
    /// previews an on-disk candidate's manifest); `null`/absent on `GET /plugins/{file}/schema`, which
    /// does not surface the version. Declared here so a codegen'd client keeps the field the inspect
    /// handler always sends, rather than silently dropping it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<String>,
    /// The plugin's settings JSON Schema verbatim, or `null` — either because the manifest never
    /// set `settings_schema`, or (distinctly, see `schema_error`) because it did but the value
    /// failed to parse.
    pub(crate) schema: Option<serde_json::Value>,
    /// Set only when the manifest's `settings_schema` was present but failed to parse as JSON —
    /// `null` for a manifest that genuinely never set the field. Never collapsed into a bare
    /// `schema: null` (question #3, round-4 correction): a present-but-corrupt schema is a real
    /// authoring/packaging bug, not "this plugin simply has none."
    pub(crate) schema_error: Option<String>,
    /// `"trusted" | "unverified" | "rejected"` — the same vocabulary the plugin catalog already
    /// uses (never `"verified"`; question #8, round-4 correction).
    pub(crate) trust: String,
    /// `"describe"` when a currently-loaded `kind: hook` answered its live `describe` wire
    /// message (the existing describe-proxy behavior, unchanged); `"manifest"` otherwise. Lets
    /// busbar-ui explain "why does this form look different from what I expected" without
    /// implementing the describe/manifest precedence rule itself (question #3, round-4
    /// correction).
    pub(crate) source: String,
    /// The plugin's `kind` (`hook` | `secret` | …) from its manifest. Both `GET /plugins/{file}/schema`
    /// and `POST /plugins/inspect` emit it (`null` only when the plugin cannot be resolved to a
    /// manifest). Declared so codegen'd clients keep it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kind: Option<String>,
    /// The kind-derived restart-scoping default (`busbar_plugin_sign::kind_restart_default`), so
    /// busbar-ui need not hardcode the kind→default table. Emitted by both schema endpoints (`null`
    /// only when the plugin has no resolvable manifest/kind). Declared so codegen'd clients keep it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) restart_required_default: Option<bool>,
}

/// The DESIRED settings side of `hooks/{name}/status`: busbar's registry copy of the hook's settings
/// and their version.
#[derive(Serialize, JsonSchema)]
pub(crate) struct HookDesiredStatus {
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
    pub(crate) settings_version: u64,
}

/// The REPORTED settings side of `hooks/{name}/status`: what the hook says it is actually running
/// (present only when the hook answered `status`).
#[derive(Serialize, JsonSchema)]
pub(crate) struct HookReportedStatus {
    pub(crate) settings: Option<serde_json::Map<String, serde_json::Value>>,
    pub(crate) settings_version: Option<u64>,
}

/// `GET /hooks/{name}/status` — the hook's OBSERVED state: desired vs reported settings with a
/// `drift` verdict, plus the hook's self-reported metrics. `reported`/`drift` are `null` and `note`
/// is present when the hook did not answer (fail-open); `metrics` is invariantly an array.
#[derive(Serialize, JsonSchema)]
pub(crate) struct HookStatusView {
    pub(crate) name: String,
    pub(crate) desired: HookDesiredStatus,
    pub(crate) reported: Option<HookReportedStatus>,
    pub(crate) drift: Option<bool>,
    /// Validated + bounded self-reported metrics; each entry carries `{name, type, value}` and, when
    /// the hook sent them, optional `labels`/`quantiles`/`estimated`/`ci_low`/`ci_high`/`help`/
    /// `label`/`unit`/`viz`/`max` members.
    ///
    /// E-004 (busbar-ui/docs/ENGINE-BUGS.md): schemars' blanket `JsonSchema` impl for
    /// `serde_json::Value` renders as the JSON-Schema-2020-12 boolean `true` (`schemars-1.2.1`'s
    /// `json_schema_impls/serdejson.rs`), which is legal 2020-12 but — nested here as this array's
    /// `items` — is a boolean SUB-schema, and `kin-openapi` (the parser under `oapi-codegen`, which
    /// every published SDK generates through) cannot represent one at all: the parse aborts, taking
    /// out Python/TS/Go SDK regeneration simultaneously. `#[schemars(schema_with)]` overrides just
    /// this field's schema to `{"type": "array", "items": {}}` — `{}` is the equivalent "accepts
    /// anything" schema every generator DOES understand, and is what busbar-ui's own
    /// `openapi-prep.py` already rewrites `items: true` into client-side. This is the only
    /// `items: true` in the document; every other `additionalProperties: true` schemars emits
    /// elsewhere is a boolean in a position `kin-openapi` handles fine and is deliberately untouched.
    #[schemars(schema_with = "hook_status_metrics_schema")]
    pub(crate) metrics: Vec<serde_json::Value>,
    pub(crate) as_of: u64,
    /// Always `"live"` (the read is a live transport query).
    pub(crate) source: String,
    /// A short human note present only on the fail-open (no-answer) branch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) note: Option<String>,
}

/// The `HookStatusView.metrics` array's item schema (E-004): `{}`, not schemars' default boolean
/// `true` for `serde_json::Value` — the "accepts anything" schema every generator understands, in a
/// position (`items`) where the boolean form is fatal to `kin-openapi`/`oapi-codegen`.
fn hook_status_metrics_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "array",
        "items": {}
    })
}

/// `GET /config/versions/{v}` — one retained config version WITH its full hook-surface snapshot
/// (projected through the wire `HookView`, keyed by hook name) and the global wiring at that version.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigVersionDetailView {
    pub(crate) version: u64,
    pub(crate) ts: u64,
    pub(crate) principal: String,
    pub(crate) summary: String,
    pub(crate) hooks: std::collections::BTreeMap<String, HookView>,
    pub(crate) global_hooks: Vec<String>,
}

/// The `hooks` object of a `GET /config/diff` — hook names added / removed / changed between the two
/// versions.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigDiffHooks {
    pub(crate) added: Vec<String>,
    pub(crate) removed: Vec<String>,
    pub(crate) changed: Vec<String>,
}

/// The `global_hooks` delta of a `GET /config/diff` — present only when the global wiring changed.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigDiffGlobalHooks {
    pub(crate) from: Vec<String>,
    pub(crate) to: Vec<String>,
}

/// `GET /config/diff` — structured hook-surface diff between two retained versions. `global_hooks` is
/// present only when the global wiring differed between the two sides.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigDiffView {
    pub(crate) from: u64,
    pub(crate) to: u64,
    pub(crate) hooks: ConfigDiffHooks,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) global_hooks: Option<ConfigDiffGlobalHooks>,
}

/// `GET /audit` — the cursor-paginated audit-log envelope (`{items, next_cursor}`, hand-rolled in the
/// audit handler).
#[derive(Serialize, JsonSchema)]
pub(crate) struct AuditPageView {
    pub(crate) items: Vec<crate::admin::audit::AuditEntry>,
    pub(crate) next_cursor: Option<String>,
}

/// `GET /config/versions` — the cursor-paginated version-history envelope (`{items, next_cursor}`).
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigVersionPageView {
    pub(crate) items: Vec<crate::admin::versions::ConfigVersion>,
    pub(crate) next_cursor: Option<String>,
}

/// The stable v1 error envelope (`{"error":{"code","message"}}`). Kept as a schema-only type so the
/// generated `Error` component matches the hand-written one exactly and both stay code-derived.
/// Referenced only via its TYPE (schemars' derive walks it for the schema) -- never constructed as
/// a value, so it needs the struct-level allow the module doc promises, not just a field-level one.
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct ErrorBody {
    pub(crate) error: ErrorDetail,
}

/// The `error` member of [`ErrorBody`]: a stable machine `code` + human `message`.
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct ErrorDetail {
    /// One of the frozen [`AdminError`] codes (see the `code` enum on the generated schema).
    pub(crate) code: String,
    pub(crate) message: String,
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
