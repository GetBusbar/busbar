// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLOSED REASON TABLE of the admin error envelope (ADMIN-API-1.6 section 1).
//!
//! Every admin error carries `error.reason`, a member of this table (`null` only for `internal`).
//! The table is the snake-case `Cond` set of core-admin's taxonomy, the reasons section 1.3 adds, and
//! one reason for each frozen code that no condition names. core-admin generates
//! `components.x-busbar-reasons` from it and its tests prove the table equals those sets.

/// One reason: the frozen `code` and HTTP status it rides on, and the schema of its `details`.
pub struct ReasonRow {
    pub reason: &'static str,
    pub code: &'static str,
    pub http: u16,
    /// Further `(code, http)` pairs the reason is declared with on some operation.
    pub also: &'static [(&'static str, u16)],
    /// The JSON schema of `details`, as JSON text.
    pub details_schema: &'static str,
}

pub const NO_DETAILS: &str = r#"{"type":"object","additionalProperties":false}"#;
const SCOPE_DETAILS: &str = r#"{"type":"object","additionalProperties":false,"required":["needed_scope","needed_verb"],"properties":{"needed_scope":{"type":"string"},"needed_verb":{"type":["string","null"]}}}"#;
const CURSOR_MISMATCH_DETAILS: &str = r#"{"type":"object","additionalProperties":false,"properties":{"cursor_node_id":{"type":"string"}}}"#;
const CURSOR_EXPIRED_DETAILS: &str = r#"{"type":"object","additionalProperties":false,"required":["oldest_available"],"properties":{"oldest_available":{"type":"string"}}}"#;
const RANGE_DETAILS: &str = r#"{"type":"object","additionalProperties":false,"required":["max_buckets"],"properties":{"max_buckets":{"type":"integer"}}}"#;
const PLUGIN_REFUSED_DETAILS: &str = r#"{"type":"object","additionalProperties":false,"required":["refusal","field","have","want","link"],"properties":{"refusal":{"type":"string"},"field":{"type":"string"},"have":{"type":"string"},"want":{"type":"string"},"link":{"type":["string","null"]},"byte":{"type":"integer"},"rule":{"type":"string"}}}"#;
/// `PluginTextDetails` (section 1.3): a plugin's own words and code, scrubbed, never in `message`.
const PLUGIN_TEXT_DETAILS: &str = r#"{"type":"object","additionalProperties":false,"required":["text","plugin_diag"],"properties":{"text":{"type":["string","null"]},"plugin_diag":{"type":["string","null"]},"condition":{"type":["string","null"]}}}"#;
/// The `details` of an unknown trust decision outcome (TRUST-ADMIN-PRODUCER-DESIGN r3 §4.5): the
/// attempt the replay of the same `Idempotency-Key` resolves. Absent on every other 503.
const SERVICE_UNAVAILABLE_DETAILS: &str = r#"{"type":"object","additionalProperties":false,"properties":{"key":{"type":"string"},"ruling":{"enum":["approve","revoke"]},"decided_at":{"type":"integer","description":"Wall seconds the attempt was stamped at"},"decided_by":{"type":"object","required":["kind","id"],"properties":{"kind":{"const":"principal"},"id":{"type":"string"}}},"operation":{"type":["string","null"],"description":"The deciding request's Idempotency-Key"}}}"#;
/// The `details` of `outcome_not_applied` (r3 §4.6): the replayed operation and its stamp.
const OUTCOME_NOT_APPLIED_DETAILS: &str = r#"{"type":"object","additionalProperties":false,"required":["operation","decided_at"],"properties":{"operation":{"type":["string","null"]},"decided_at":{"type":"integer"}}}"#;

macro_rules! row {
    ($r:literal, $c:literal, $h:literal) => {
        ReasonRow {
            reason: $r,
            code: $c,
            http: $h,
            also: &[],
            details_schema: NO_DETAILS,
        }
    };
    ($r:literal, $c:literal, $h:literal, also $a:expr) => {
        ReasonRow {
            reason: $r,
            code: $c,
            http: $h,
            also: $a,
            details_schema: NO_DETAILS,
        }
    };
    ($r:literal, $c:literal, $h:literal, details $d:expr) => {
        ReasonRow {
            reason: $r,
            code: $c,
            http: $h,
            also: &[],
            details_schema: $d,
        }
    };
}

pub const REASONS: &[ReasonRow] = &[
    // The conditions of core-admin's `Cond`.
    row!("stale_if_match", "version_conflict", 409),
    row!("archive_changed", "conflict", 409),
    row!("malformed_if_match", "invalid_request", 400),
    row!("unknown_resource", "not_found", 404),
    row!("malformed_body", "invalid_request", 400),
    row!("invalid_tree", "invalid_request", 400),
    row!("base_defined", "conflict", 409),
    row!("grant_change", "conflict", 409),
    row!("bound_keys", "conflict", 409),
    row!("still_parent", "conflict", 409),
    row!(
        "governance_off",
        "conflict",
        409,
        also & [("not_found", 404)]
    ),
    row!("no_signing_key", "conflict", 409),
    row!("idempotency_in_flight", "conflict", 409),
    row!("recovery_conflict", "conflict", 409),
    row!("at_key_cap", "conflict", 409),
    row!("key_revoked", "conflict", 409),
    row!("parent_without_group", "invalid_request", 400),
    row!("key_expiry_fields", "invalid_request", 400),
    row!("rebind_target_missing", "invalid_request", 400),
    row!("hook_no_ack", "invalid_request", 400, details PLUGIN_TEXT_DETAILS),
    row!("settings_push", "conflict", 409),
    row!("malformed_cursor", "invalid_request", 400),
    row!("missing_required_query", "invalid_request", 400),
    row!("invalid_query_value", "invalid_request", 400),
    row!("non_numeric_path", "invalid_request", 400),
    row!("invalid_config", "invalid_request", 400),
    row!("unknown_module", "invalid_request", 400),
    row!("lockout_self", "conflict", 409),
    row!("no_disk_base", "invalid_request", 400),
    row!("untrusted_upload", "conflict", 409),
    row!("invalid_filename", "invalid_request", 400),
    row!(
        "not_loadable",
        "conflict",
        409,
        also & [("invalid_request", 400)]
    ),
    row!("overlong", "invalid_request", 400),
    row!("no_supervisor", "conflict", 409),
    row!("not_restartable", "conflict", 409),
    row!("unknown_section", "invalid_request", 400),
    row!("name_collision", "conflict", 409),
    row!("invalid_labels", "invalid_request", 400),
    row!("trust_ceiling_raise", "conflict", 409),
    row!("operator_file_policy", "conflict", 409),
    row!("still_referenced", "conflict", 409),
    row!("unpriced", "unpriced_class", 409),
    row!("restart_unreachable", "conflict", 409),
    // Section 1.3.
    row!("scope_insufficient", "forbidden", 403, details SCOPE_DETAILS),
    row!("credential_expired", "unauthorized", 401),
    row!("credential_revoked", "unauthorized", 401),
    row!("credential_invalid", "unauthorized", 401),
    row!("if_match_required", "invalid_request", 428),
    row!("cursor_mismatch", "invalid_request", 400, details CURSOR_MISMATCH_DETAILS),
    row!("cursor_expired", "invalid_request", 410, details CURSOR_EXPIRED_DETAILS),
    row!("read_budget", "rate_limited", 429),
    row!("range_too_large", "invalid_request", 400, details RANGE_DETAILS),
    row!("currency_change", "conflict", 409),
    row!("telemetry_disabled", "unavailable", 503),
    row!("view_unavailable", "unavailable", 503),
    row!("instance_not_configured", "not_found", 404),
    row!("restart_required", "conflict", 409),
    row!("config_locked", "conflict", 409),
    row!("plugin_refused", "conflict", 409, details PLUGIN_REFUSED_DETAILS),
    row!("plugin_rejected", "invalid_request", 400, details PLUGIN_TEXT_DETAILS),
    // The frozen codes that no condition names.
    row!("method_not_allowed", "method_not_allowed", 405),
    row!("mutation_budget", "rate_limited", 429),
    row!("service_unavailable", "unavailable", 503, details SERVICE_UNAVAILABLE_DETAILS),
    row!("request_too_large", "request_too_large", 413),
    row!("state_conflict", "conflict", 409),
    row!("idempotency_mismatch", "conflict", 409),
    row!("mutation_applied", "conflict", 409),
    row!("action_in_flight", "conflict", 409),
    // TRUST-ADMIN-PRODUCER-DESIGN r3 §4.1, §4.6: the trust decision reasons, stable.
    row!("reviewed_digest_required", "invalid_request", 428),
    row!("reviewed_digest_stale", "conflict", 409),
    row!("decision_in_progress", "conflict", 409),
    row!("outcome_not_applied", "conflict", 409, details OUTCOME_NOT_APPLIED_DETAILS),
];

/// The closed list of `refusal` names a `plugin_refused` carries: the snake-case names of the 22
/// MIN-3 loader `RefusalCode` variants (`components.x-busbar-plugin-refusals`).
pub const PLUGIN_REFUSALS: [&str; 22] = [
    "integrity",
    "signature",
    "stamp_missing",
    "stamp_ambiguous",
    "stamp_malformed",
    "kind_unknown",
    "kind_abi",
    "mechanism",
    "layout",
    "semantic",
    "target",
    "engine_range",
    "crypto",
    "manifest_mismatch",
    "door_stamp_mismatch",
    "image_bounds",
    "describe_invalid",
    "cap_unknown",
    "out_of_process_unavailable",
    "local_build",
    "superseded",
    "name_conflict",
];

#[must_use]
pub fn row(reason: &str) -> Option<&'static ReasonRow> {
    REASONS.iter().find(|row| row.reason == reason)
}

/// The reason an error of this frozen `code` carries when the raiser named no finer condition.
/// `internal` has none: its reason is `null`.
#[must_use]
pub fn default_reason(code: &str) -> Option<&'static str> {
    Some(match code {
        "not_found" => "unknown_resource",
        "unauthorized" | "invalid_api_key" => "credential_invalid",
        "method_not_allowed" => "method_not_allowed",
        "forbidden" => "scope_insufficient",
        "invalid_request" => "malformed_body",
        "version_conflict" => "stale_if_match",
        "conflict" => "state_conflict",
        "rate_limited" => "mutation_budget",
        "unavailable" => "service_unavailable",
        "unpriced_class" => "unpriced",
        "request_too_large" => "request_too_large",
        "idempotency_mismatch" => "idempotency_mismatch",
        "mutation_applied" => "mutation_applied",
        "action_in_flight" => "action_in_flight",
        _ => return None,
    })
}

/// Section 1.2: `true` only for code `rate_limited`, code `unavailable` and reason
/// `idempotency_in_flight`.
#[must_use]
pub fn retryable(code: &str, reason: Option<&str>) -> bool {
    matches!(code, "rate_limited" | "unavailable") || reason == Some("idempotency_in_flight")
}
