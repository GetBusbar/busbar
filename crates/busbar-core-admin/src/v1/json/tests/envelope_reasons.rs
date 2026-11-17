// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 §1 (MR1): one error envelope with closed reasons.

use axum::http::StatusCode;
use axum::response::Response;

use crate::v1::contract::AdminError;
use crate::v1::json::{err_json, err_json_cond};

async fn parts(resp: Response) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    use http_body_util::BodyExt;
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).expect("body is JSON");
    (status, headers, body)
}

#[cfg(feature = "openapi-schema")]
/// The snake-case name of a `Cond` (its `Debug` form), the reason it puts on the wire.
fn snake(debug: &str) -> String {
    let mut out = String::new();
    for (i, c) in debug.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(feature = "openapi-schema")]
/// The 43 conditions of `Cond` at the time MR1 was written, as reasons.
const COND_REASONS: &[&str] = &[
    "stale_if_match",
    "archive_changed",
    "malformed_if_match",
    "unknown_resource",
    "malformed_body",
    "invalid_tree",
    "base_defined",
    "grant_change",
    "bound_keys",
    "still_parent",
    "governance_off",
    "no_signing_key",
    "idempotency_in_flight",
    "recovery_conflict",
    "at_key_cap",
    "key_revoked",
    "parent_without_group",
    "key_expiry_fields",
    "rebind_target_missing",
    "hook_no_ack",
    "settings_push",
    "malformed_cursor",
    "missing_required_query",
    "invalid_query_value",
    "non_numeric_path",
    "invalid_config",
    "unknown_module",
    "lockout_self",
    "no_disk_base",
    "untrusted_upload",
    "invalid_filename",
    "not_loadable",
    "overlong",
    "no_supervisor",
    "not_restartable",
    "unknown_section",
    "name_collision",
    "invalid_labels",
    "trust_ceiling_raise",
    "operator_file_policy",
    "still_referenced",
    "unpriced",
    "restart_unreachable",
];

#[cfg(feature = "openapi-schema")]
/// §1.3: the reasons MR1 adds.
const ADDED_REASONS: &[&str] = &[
    "scope_insufficient",
    "credential_expired",
    "credential_revoked",
    "credential_invalid",
    "if_match_required",
    "cursor_mismatch",
    "cursor_expired",
    "read_budget",
    "range_too_large",
    "currency_change",
    "telemetry_disabled",
    "view_unavailable",
    "instance_not_configured",
    "restart_required",
    "config_locked",
    "plugin_refused",
    "plugin_rejected",
];

#[cfg(feature = "openapi-schema")]
/// Reasons for the codes that no `Cond` names (a method refused, a budget spent, a body too large,
/// the replay outcomes, and a conflict or outage with no finer condition). Filed to the
/// coordinator as a design hole in §1.3: every code but `internal` needs a reason.
const CODE_REASONS: &[&str] = &[
    "method_not_allowed",
    "mutation_budget",
    "service_unavailable",
    "request_too_large",
    "state_conflict",
    "idempotency_mismatch",
    "mutation_applied",
    "action_in_flight",
];

#[cfg(feature = "openapi-schema")]
/// TRUST-ADMIN-PRODUCER-DESIGN r3 §4.1 and §4.6: the stable trust decision reasons.
const TRUST_REASONS: &[&str] = &[
    "reviewed_digest_required",
    "reviewed_digest_stale",
    "decision_in_progress",
    "outcome_not_applied",
];

#[cfg(feature = "openapi-schema")]
/// DES-331 §B10.8: the restore reasons registered so far (each problem names itself in `reason`).
const RESTORE_REASONS: &[&str] = &["restore_quarantine"];

#[cfg(feature = "openapi-schema")]
const PLUGIN_REFUSALS: &[&str] = &[
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

fn assert_envelope(
    status: StatusCode,
    headers: &axum::http::HeaderMap,
    body: &serde_json::Value,
    what: &str,
) {
    let error = body["error"]
        .as_object()
        .unwrap_or_else(|| panic!("{what}: no error object"));
    let keys: std::collections::BTreeSet<&str> = error.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        std::collections::BTreeSet::from([
            "code",
            "details",
            "message",
            "reason",
            "request_id",
            "retryable"
        ]),
        "{what}: the envelope's keys"
    );
    let request_id = error["request_id"].as_str().unwrap_or_default();
    assert!(
        request_id.starts_with("r_"),
        "{what}: request_id {request_id:?}"
    );
    assert_eq!(
        headers.get("x-request-id").and_then(|v| v.to_str().ok()),
        Some(request_id),
        "{what}: X-Request-Id equals request_id"
    );
    assert!(error["details"].is_object(), "{what}: details is an object");
    assert!(error["retryable"].is_boolean(), "{what}: retryable");
    let _ = status;
}

#[tokio::test]
async fn algorithmic_errors_carry_the_envelope() {
    let (status, headers, body) = parts(err_json(&AdminError::Internal)).await;
    assert_envelope(status, &headers, &body, "internal");
    assert!(
        body["error"]["reason"].is_null(),
        "internal's reason is null"
    );
    assert_eq!(body["error"]["retryable"], false);
    let (status, headers, body) = parts(err_json(&AdminError::RateLimited)).await;
    assert_envelope(status, &headers, &body, "rate_limited");
    assert_eq!(body["error"]["retryable"], true);
    assert!(body["error"]["reason"].is_string());
    let (status, headers, body) = parts(err_json(&AdminError::Unavailable("x".into()))).await;
    assert_envelope(status, &headers, &body, "unavailable");
    assert_eq!(body["error"]["retryable"], true);
    assert!(body["error"]["reason"].is_string());
}

/// DES-443 r3: a plugin inspection that is busy, past its deadline or at its cap is a 503 `unavailable`, retryable,
/// with a numeric `Retry-After`; 409 stays for state conflicts. The kernel admission's `Refusal::Unavailable`
/// carries the delay.
#[tokio::test]
async fn a_retry_later_refusal_is_a_503_with_retry_after() {
    let refused = busbar_kernel::admission::Refusal::Unavailable {
        text: "another plugin inspection is loading an image; retry when it finishes".into(),
        retry_after_s: 10,
    };
    let error = crate::v1::service::admission_refused(refused);
    let (status, headers, body) = parts(err_json(&error)).await;
    assert_envelope(status, &headers, &body, "unavailable");
    assert_eq!(status.as_u16(), 503);
    assert_eq!(body["error"]["retryable"], true);
    let retry_after = headers
        .get(axum::http::header::RETRY_AFTER)
        .expect("Retry-After is present")
        .to_str()
        .expect("Retry-After is text");
    assert_eq!(
        retry_after.parse::<u32>().expect("Retry-After is numeric"),
        10
    );
    assert!(body["error"]["message"]
        .as_str()
        .is_some_and(|m| m.contains("another plugin inspection")));
}

#[cfg(feature = "openapi-schema")]
fn admin_error_of(kind: crate::v1::contract::taxonomy::ErrKind) -> AdminError {
    use crate::v1::contract::taxonomy::ErrKind;
    match kind {
        ErrKind::NotFound => AdminError::not_found("x"),
        ErrKind::Validation => AdminError::Validation("x".into()),
        ErrKind::VersionConflict => AdminError::VersionConflict("x".into()),
        ErrKind::Conflict => AdminError::Conflict("x".into()),
        ErrKind::Forbidden => AdminError::Forbidden {
            needed: crate::v1::contract::Scope::Full,
        },
        ErrKind::UnpricedClass => AdminError::UnpricedClass {
            lane: "l".into(),
            class: None,
        },
    }
}

#[cfg(feature = "openapi-schema")]
fn declared_rows() -> Vec<(String, String, crate::v1::contract::taxonomy::DocErr)> {
    use crate::v1::contract::taxonomy::{declared_errors, MethodTag};
    let doc = crate::v1::json::handlers::openapi_doc();
    let prefix = crate::v1::contract::ADMIN_PREFIX;
    let mut rows = Vec::new();
    for (path, methods) in doc["paths"].as_object().expect("paths") {
        let rel = path.strip_prefix(prefix).unwrap_or(path);
        for (key, _) in methods.as_object().expect("methods") {
            let Some(method) = MethodTag::from_op_key(key) else {
                continue;
            };
            for de in declared_errors(method, rel) {
                rows.push((key.clone(), rel.to_string(), *de));
            }
        }
    }
    assert!(!rows.is_empty(), "no declared_errors rows found");
    rows
}

#[cfg(feature = "openapi-schema")]
#[tokio::test]
async fn every_error_has_reason_and_request_id() {
    for (method, rel, de) in declared_rows() {
        let what = format!("{method} {rel} {:?}", de.cond);
        let e = admin_error_of(de.kind);
        let (status, headers, body) = parts(err_json_cond(&e, de.cond)).await;
        assert_envelope(status, &headers, &body, &what);
        assert_eq!(status.as_u16(), de.kind.status(), "{what}");
        assert_eq!(body["error"]["code"], de.kind.code(), "{what}");
        let reason = snake(&format!("{:?}", de.cond));
        assert_eq!(body["error"]["reason"], reason.as_str(), "{what}");
        assert_eq!(
            body["error"]["retryable"],
            reason == "idempotency_in_flight",
            "{what}: retryable is true only for rate_limited, unavailable and idempotency_in_flight"
        );
    }
}

#[cfg(feature = "openapi-schema")]
fn reasons_table() -> serde_json::Map<String, serde_json::Value> {
    let doc = crate::v1::json::handlers::openapi_doc();
    doc["components"]["x-busbar-reasons"]
        .as_object()
        .expect("components.x-busbar-reasons is generated")
        .clone()
}

#[cfg(feature = "openapi-schema")]
#[test]
fn reason_table_is_closed() {
    let table = reasons_table();
    let expected: std::collections::BTreeSet<String> = COND_REASONS
        .iter()
        .chain(ADDED_REASONS)
        .chain(CODE_REASONS)
        .chain(TRUST_REASONS)
        .chain(RESTORE_REASONS)
        .map(|s| s.to_string())
        .collect();
    let have: std::collections::BTreeSet<String> = table.keys().cloned().collect();
    assert_eq!(have, expected, "the table is the Cond set plus section 1.3");
    for (reason, row) in &table {
        let row = row.as_object().expect("row");
        for key in ["code", "http", "retryable", "details_schema"] {
            assert!(row.contains_key(key), "{reason}: no {key}");
        }
    }
    for (method, rel, de) in declared_rows() {
        let reason = snake(&format!("{:?}", de.cond));
        let row = &table[&reason];
        let primary = row["code"] == de.kind.code() && row["http"] == de.kind.status();
        let also = row["also"].as_array().is_some_and(|a| {
            a.iter()
                .any(|r| r["code"] == de.kind.code() && r["http"] == de.kind.status())
        });
        assert!(
            primary || also,
            "{method} {rel}: {reason} is declared as {} {} but the table says {row}",
            de.kind.code(),
            de.kind.status()
        );
    }
}

#[cfg(feature = "openapi-schema")]
#[test]
fn plugin_refusal_map_total() {
    let doc = crate::v1::json::handlers::openapi_doc();
    let list: Vec<&str> = doc["components"]["x-busbar-plugin-refusals"]
        .as_array()
        .expect("components.x-busbar-plugin-refusals is generated")
        .iter()
        .map(|v| v.as_str().expect("a name"))
        .collect();
    assert_eq!(
        list, PLUGIN_REFUSALS,
        "exactly the 22 MIN-3 RefusalCode names"
    );
    let table = reasons_table();
    assert_eq!(table["plugin_refused"]["code"], "conflict");
    assert_eq!(table["plugin_refused"]["http"], 409);
}

#[cfg(feature = "openapi-schema")]
#[test]
fn if_match_required_is_invalid_request_428() {
    let table = reasons_table();
    assert_eq!(table["if_match_required"]["code"], "invalid_request");
    assert_eq!(table["if_match_required"]["http"], 428);
    assert_eq!(table["if_match_required"]["retryable"], false);
}

#[tokio::test]
async fn kernel_gate_401_carries_reason() {
    use busbar_kernel::admin::gate::{err_json as gate_err, ApiError};
    let (status, headers, body) = parts(gate_err(&ApiError::Unauthorized)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_envelope(status, &headers, &body, "gate 401");
    assert_eq!(body["error"]["code"], "unauthorized");
    assert_eq!(body["error"]["reason"], "credential_invalid");
    assert_eq!(body["error"]["retryable"], false);
    let (status, headers, body) = parts(gate_err(&ApiError::NotFound)).await;
    assert_envelope(status, &headers, &body, "gate 404");
    assert_eq!(body["error"]["reason"], "unknown_resource");
}

#[tokio::test]
async fn plane_refusal_maps_to_core_reason() {
    use crate::planeverbs::{refusal_response, PlaneVerbError};
    use busbar_kernel::admin_verbs::PlaneAdminCond;
    let (status, headers, body) = parts(refusal_response(
        "tools",
        "t",
        PlaneVerbError::ValidationOf("PLUGIN-WORDS".into(), PlaneAdminCond::InvalidConfig),
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_envelope(status, &headers, &body, "plane refusal");
    assert_eq!(body["error"]["code"], "invalid_request");
    assert_eq!(body["error"]["reason"], "plugin_rejected");
    assert_eq!(body["error"]["retryable"], false);
    assert_eq!(body["error"]["details"]["condition"], "invalid_config");
    let (_, _, body) = parts(refusal_response(
        "tools",
        "t",
        PlaneVerbError::Validation("PLUGIN-WORDS".into()),
    ))
    .await;
    assert_eq!(body["error"]["reason"], "plugin_rejected");
    assert!(body["error"]["details"]["condition"].is_null());
}

#[tokio::test]
async fn error_message_never_plugin_text() {
    use crate::planeverbs::{refusal_response, PlaneVerbError};
    for err in [
        PlaneVerbError::Validation("PLUGIN-SECRET-WORDS".into()),
        PlaneVerbError::ValidationOf(
            "PLUGIN-SECRET-WORDS".into(),
            busbar_kernel::admin_verbs::PlaneAdminCond::MalformedBody,
        ),
    ] {
        let (_, _, body) = parts(refusal_response("tools", "t", err)).await;
        let message = body["error"]["message"].as_str().expect("message");
        assert!(
            !message.contains("PLUGIN-SECRET-WORDS"),
            "the message carries plugin text: {message}"
        );
        assert_eq!(body["error"]["details"]["text"], "PLUGIN-SECRET-WORDS");
        assert!(body["error"]["details"]["plugin_diag"].is_null());
    }
}

#[tokio::test]
async fn a_hook_refusal_text_rides_in_details() {
    use crate::v1::contract::taxonomy::Cond;
    let e = AdminError::plugin_text(
        Cond::HookNoAck,
        Some("PLUGIN-SECRET-WORDS".into()),
        Some("plugin-diag-1".into()),
        None,
    );
    let (status, headers, body) = parts(err_json(&e)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_envelope(status, &headers, &body, "hook_no_ack");
    assert_eq!(body["error"]["code"], "invalid_request");
    assert_eq!(body["error"]["reason"], "hook_no_ack");
    assert!(!body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .contains("PLUGIN-SECRET-WORDS"));
    assert_eq!(body["error"]["details"]["text"], "PLUGIN-SECRET-WORDS");
    assert_eq!(body["error"]["details"]["plugin_diag"], "plugin-diag-1");
    assert!(
        body["error"]["details"].get("condition").is_none(),
        "condition is present only on plugin_rejected"
    );
}

#[tokio::test]
async fn forbidden_names_the_scope_it_needed() {
    let e = AdminError::Forbidden {
        needed: crate::v1::contract::Scope::Full,
    };
    let (status, headers, body) = parts(err_json(&e)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_envelope(status, &headers, &body, "forbidden");
    assert_eq!(body["error"]["reason"], "scope_insufficient");
    assert_eq!(body["error"]["details"]["needed_scope"], "full");
}

/// `components.x-busbar-unit-reasons` (ADMIN-API-1.6 §3.4) COVERS EVERY FAILURE: each refusal
/// and failure `ReasonCode` has one row with its `class` (`client`, `policy`, `upstream` or
/// `engine`, the record's own) and its `steps`, plus `timed_out`, which a record names without one.
#[cfg(feature = "openapi-schema")]
#[test]
fn unit_reasons_cover_failures() {
    use busbar_contract::caps::ReasonCode;
    let doc = crate::v1::json::handlers::openapi_doc();
    let table = doc["components"]["x-busbar-unit-reasons"]
        .as_object()
        .expect("components.x-busbar-unit-reasons is generated");
    for reason in ReasonCode::ALL {
        let row = table
            .get(reason.as_str())
            .unwrap_or_else(|| panic!("{} has no unit-reason row", reason.as_str()));
        let class = row["class"].as_str().expect("a class");
        assert!(
            ["client", "policy", "upstream", "engine"].contains(&class),
            "{}: {class}",
            reason.as_str()
        );
        assert_eq!(class, crate::v1::records::unit_reason_class(*reason));
        assert!(!row["steps"].as_array().expect("steps").is_empty());
    }
    for extra in ["superseded", "timed_out"] {
        assert!(table.contains_key(extra), "{extra} has no unit-reason row");
    }
    assert_eq!(
        table.len(),
        ReasonCode::ALL.len() + 1,
        "only timed_out beside them"
    );
}

/// #307: every production error the admin surface raises is the one envelope. The provisioning
/// guard's errors were `{"error":{"message":...}}` alone.
#[tokio::test]
async fn provisioning_guard_errors_carry_the_envelope() {
    use crate::provision::GuardAdminError;
    use axum::response::IntoResponse;
    for (error, status, code) in [
        (GuardAdminError::UnknownInstance, 404, "not_found"),
        (GuardAdminError::Invalid, 400, "invalid_request"),
        (GuardAdminError::Unavailable, 503, "unavailable"),
    ] {
        let (got, headers, body) = parts(error.into_response()).await;
        assert_eq!(got.as_u16(), status, "{code}");
        assert_envelope(got, &headers, &body, code);
        assert_eq!(body["error"]["code"], code);
    }
}
