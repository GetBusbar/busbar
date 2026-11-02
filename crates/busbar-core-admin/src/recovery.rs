// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dedicated operator surface for retained, ambiguous ledger operations.
//!
//! The ledger recovery facade owns custody, fencing, durable verdicts and replay identity.
//! This adapter only accepts the exact operation the operator inspected; it never mints an
//! operation id or infers resolution authority from a list result.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use busbar_kernel::governance::recovery::{
    RecoveryError, RecoveryItem, RecoveryKind, RecoveryResolution, RecoveryState, RecoveryVerdict,
};
use busbar_kernel::state::AppHandle;
use serde::{Deserialize, Serialize};

use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::AdminError;
use crate::v1::json::{err_json, err_json_cond, ok_json};

const DEFAULT_LIMIT: usize = 200;
const MAX_LIMIT: usize = 1000;
const CURSOR_PREFIX: &str = "ledger-recovery:v1:";

/// The bounded observation request. The cursor belongs only to this surface.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct ListRequest {
    #[cfg_attr(feature = "openapi-schema", schemars(range(min = 1, max = 1000)))]
    limit: Option<usize>,
    cursor: Option<String>,
}

impl ListRequest {
    fn page(&self) -> Result<(Option<[u8; 16]>, usize), &'static str> {
        let limit = self.limit.unwrap_or(DEFAULT_LIMIT);
        if limit == 0 || limit > MAX_LIMIT {
            return Err("limit must be between 1 and 1000");
        }
        let after = self
            .cursor
            .as_ref()
            .map(|cursor| {
                cursor
                    .strip_prefix(CURSOR_PREFIX)
                    .and_then(lower_hex)
                    .ok_or("invalid ledger recovery cursor")
            })
            .transpose()?;
        Ok((after, limit))
    }
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub(crate) enum KindView {
    Usage,
    Metering,
    Correction,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub(crate) enum StateView {
    Intent,
    Applied,
    ConditionConflict,
    LandedUnknown,
    VerdictLanded,
    VerdictNotLanded,
    Settled,
}

/// A safe observation of custody. The raw payload and operator evidence stay in the Store.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct ItemView {
    operation_id: String,
    body_fingerprint: String,
    recovery_version: u64,
    kind: KindView,
    state: StateView,
    first_sent_at_ms: Option<u64>,
    can_resolve: bool,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct ListView {
    items: Vec<ItemView>,
    next_cursor: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

impl From<RecoveryItem> for ItemView {
    fn from(item: RecoveryItem) -> Self {
        Self {
            operation_id: hex(&item.operation_id),
            body_fingerprint: hex(&item.body_fingerprint),
            recovery_version: item.revision,
            kind: match item.kind {
                RecoveryKind::Usage => KindView::Usage,
                RecoveryKind::Metering => KindView::Metering,
                RecoveryKind::Correction => KindView::Correction,
            },
            state: match item.state {
                RecoveryState::Intent => StateView::Intent,
                RecoveryState::Applied => StateView::Applied,
                RecoveryState::ConditionConflict => StateView::ConditionConflict,
                RecoveryState::LandedUnknown => StateView::LandedUnknown,
                RecoveryState::VerdictLanded => StateView::VerdictLanded,
                RecoveryState::VerdictNotLanded => StateView::VerdictNotLanded,
                RecoveryState::Settled => StateView::Settled,
            },
            first_sent_at_ms: item.first_sent_at_ms,
            can_resolve: item.can_resolve,
        }
    }
}

fn invalid(message: &str) -> Response {
    err_json_cond(&AdminError::Validation(message.into()), Cond::MalformedBody)
}

fn recovery_error(error: RecoveryError) -> Response {
    match error {
        RecoveryError::Conflict(_) => err_json_cond(
            &AdminError::Conflict("the operation, recovery version, verdict or resolution authority conflicts with this request".into()),
            Cond::RecoveryConflict,
        ),
        RecoveryError::Invalid(_) => invalid("the ledger recovery request was refused"),
        RecoveryError::Unavailable(_) => err_json(&AdminError::Unavailable("the ledger recovery Store is unavailable".into())),
    }
}

fn join_error() -> Response {
    err_json(&AdminError::Unavailable(
        "the ledger recovery task could not complete".into(),
    ))
}

pub(crate) async fn list(State(handle): State<Arc<AppHandle>>, body: Bytes) -> Response {
    let request = match busbar_kernel::json::parse::<ListRequest>(&body) {
        Ok(request) => request,
        Err(_) => return invalid("invalid ledger recovery list body"),
    };
    let (after, limit) = match request.page() {
        Ok(page) => page,
        Err(message) => return invalid(message),
    };
    let Some(governance) = handle.load().governance.clone() else {
        return recovery_error(RecoveryError::Unavailable(String::new()));
    };
    match tokio::task::spawn_blocking(move || governance.recovery().list(after, limit + 1)).await {
        Ok(Ok(mut items)) => {
            let more = items.len() > limit;
            items.truncate(limit);
            let next_cursor = if more {
                items
                    .last()
                    .map(|item| format!("{CURSOR_PREFIX}{}", hex(&item.operation_id)))
            } else {
                None
            };
            ok_json(
                StatusCode::OK,
                &ListView {
                    items: items.into_iter().map(ItemView::from).collect(),
                    next_cursor,
                },
            )
        }
        Ok(Err(error)) => recovery_error(error),
        Err(_) => join_error(),
    }
}

pub(crate) async fn resolve(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    body: Bytes,
) -> Response {
    let request = match busbar_kernel::json::parse::<ResolveRequest>(&body) {
        Ok(request) => request,
        Err(_) => return invalid("invalid ledger recovery resolve body"),
    };
    let (operation_id, body_fingerprint) = match request.validate() {
        Ok(identity) => identity,
        Err(message) => return invalid(message),
    };
    let app = handle.load();
    let Some(governance) = app.governance.clone() else {
        return recovery_error(RecoveryError::Unavailable(String::new()));
    };
    let cost = app.cost.clone();
    drop(app);
    let resolution = RecoveryResolution {
        operation_id,
        body_fingerprint,
        expected_revision: request.recovery_version,
        verdict: match request.verdict {
            Verdict::Landed => RecoveryVerdict::Landed,
            Verdict::NotLanded => RecoveryVerdict::NotLanded,
        },
        actor: principal.actor_id().to_string(),
        reason: request.reason,
    };
    // Once scheduled, the owned Store operation survives cancellation of the HTTP waiter.
    // The facade confirms its durable, attributed verdict before returning a safe observation.
    match tokio::task::spawn_blocking(move || governance.recovery().resolve(&cost, resolution))
        .await
    {
        Ok(Ok(item)) => ok_json(StatusCode::OK, &ItemView::from(item)),
        Ok(Err(error)) => recovery_error(error),
        Err(_) => join_error(),
    }
}

/// An explicit operator observation of whether the retained operation landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) enum Verdict {
    Landed,
    NotLanded,
}

/// The immutable operation and recovery version inspected by the operator.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct ResolveRequest {
    /// The original operation id as 32 lower-case hexadecimal characters.
    #[cfg_attr(
        feature = "openapi-schema",
        schemars(regex(pattern = r"^[0-9a-f]{32}$"))
    )]
    operation_id: String,
    /// The retained operation body's SHA-256 fingerprint as 64 lower-case hex characters.
    #[cfg_attr(
        feature = "openapi-schema",
        schemars(regex(pattern = r"^[0-9a-f]{64}$"))
    )]
    body_fingerprint: String,
    /// The current recovery version; a stale observation is refused.
    recovery_version: u64,
    verdict: Verdict,
    /// The evidence behind the explicit verdict; retained in the durable audit record.
    reason: String,
}

fn lower_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    fn digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
    let mut bytes = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Some(bytes)
}

impl ResolveRequest {
    fn validate(&self) -> Result<([u8; 16], [u8; 32]), &'static str> {
        let id = lower_hex(&self.operation_id)
            .ok_or("operation_id must contain 32 lower-case hex characters")?;
        let fingerprint = lower_hex(&self.body_fingerprint)
            .ok_or("body_fingerprint must contain 64 lower-case hex characters")?;
        if self.reason.trim().is_empty() || self.reason.len() > 1024 {
            return Err("reason must contain evidence and be at most 1024 bytes");
        }
        Ok((id, fingerprint))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> serde_json::Value {
        json!({
            "operation_id": "00112233445566778899aabbccddeeff",
            "body_fingerprint": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "recovery_version": 7,
            "verdict": "not_landed",
            "reason": "The store operator verified that the original operation did not land."
        })
    }

    #[test]
    fn list_is_bounded_and_rejects_foreign_cursors() {
        let empty: ListRequest = serde_json::from_value(json!({})).unwrap();
        assert_eq!(empty.page().unwrap(), (None, 200));
        for body in [
            json!({"limit": 0}),
            json!({"limit": 1001}),
            json!({"cursor": "keys:v1:123"}),
            json!({"cursor": "00112233445566778899aabbccddeeff"}),
        ] {
            assert!(serde_json::from_value::<ListRequest>(body)
                .unwrap()
                .page()
                .is_err());
        }
        let cursor = format!("{CURSOR_PREFIX}00112233445566778899aabbccddeeff");
        let page: ListRequest =
            serde_json::from_value(json!({"cursor":cursor,"limit":1000})).unwrap();
        assert_eq!(
            page.page().unwrap(),
            (lower_hex("00112233445566778899aabbccddeeff"), 1000)
        );
        assert!(serde_json::from_value::<ListRequest>(json!({"force":true})).is_err());
    }

    #[test]
    fn safe_item_projection_contains_no_operation_body_or_derived_balance() {
        let item = RecoveryItem {
            operation_id: [1; 16],
            body_fingerprint: [2; 32],
            revision: 9,
            kind: RecoveryKind::Correction,
            state: RecoveryState::LandedUnknown,
            first_sent_at_ms: Some(1234),
            can_resolve: false,
        };
        let view = serde_json::to_value(ItemView::from(item)).unwrap();
        assert_eq!(
            view,
            json!({
                "operation_id":"01".repeat(16), "body_fingerprint":"02".repeat(32),
                "recovery_version":9,"kind":"correction","state":"landed_unknown",
                "first_sent_at_ms":1234,"can_resolve":false,
            })
        );
    }

    #[tokio::test]
    async fn backend_error_details_are_never_exposed() {
        for (error, status, code) in [
            (
                RecoveryError::Unavailable("private-store-credential".into()),
                503,
                "unavailable",
            ),
            (
                RecoveryError::Conflict("private-operation-payload".into()),
                409,
                "conflict",
            ),
            (
                RecoveryError::Invalid("private-caller-reference".into()),
                400,
                "invalid_request",
            ),
        ] {
            let response = recovery_error(error);
            assert_eq!(response.status().as_u16(), status);
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["error"]["code"], code);
            assert!(!String::from_utf8_lossy(&bytes).contains("private-"));
        }
    }

    #[test]
    fn verdict_requires_the_inspected_operation_and_explicit_evidence() {
        let parsed: ResolveRequest = serde_json::from_value(request()).unwrap();
        assert_eq!(parsed.recovery_version, 7);
        assert_eq!(parsed.verdict, Verdict::NotLanded);
        assert!(parsed.validate().is_ok());
        for field in [
            "operation_id",
            "body_fingerprint",
            "recovery_version",
            "verdict",
            "reason",
        ] {
            let mut body = request();
            body.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<ResolveRequest>(body).is_err(),
                "{field}"
            );
        }
        for reason in ["".to_string(), "  \t\n".to_string(), "x".repeat(1025)] {
            let mut body = request();
            body["reason"] = json!(reason);
            assert!(serde_json::from_value::<ResolveRequest>(body)
                .unwrap()
                .validate()
                .is_err());
        }
    }

    #[test]
    fn resolver_rejects_implicit_or_foreign_authority_fields() {
        for field in [
            "force",
            "balance",
            "new_operation_id",
            "owner",
            "environment_hash",
        ] {
            let mut body = request();
            body[field] = json!(true);
            assert!(
                serde_json::from_value::<ResolveRequest>(body).is_err(),
                "{field}"
            );
        }
        for verdict in ["retry", "unknown", "not-landed", "LANDed"] {
            let mut body = request();
            body["verdict"] = json!(verdict);
            assert!(
                serde_json::from_value::<ResolveRequest>(body).is_err(),
                "{verdict}"
            );
        }
    }

    #[test]
    fn operation_and_fingerprint_are_canonical_fixed_width_hex() {
        for field in ["operation_id", "body_fingerprint"] {
            for value in [
                "".to_string(),
                "0".repeat(31),
                "A".repeat(64),
                "g".repeat(32),
                "é".repeat(16),
            ] {
                let mut body = request();
                body[field] = json!(value);
                assert!(
                    serde_json::from_value::<ResolveRequest>(body)
                        .unwrap()
                        .validate()
                        .is_err(),
                    "{field}"
                );
            }
        }
    }

    #[test]
    fn recovery_operations_are_exact_full_scope_crud_operations() {
        use crate::verb::{KernelVerb, VerbScope};
        for (path, verb) in [
            (
                "/api/v1/admin/ledger/recovery/list",
                KernelVerb::RecoveryList,
            ),
            (
                "/api/v1/admin/ledger/recovery/resolve",
                KernelVerb::RecoveryResolve,
            ),
        ] {
            assert_eq!(crate::verb::verb_for("POST", path), Some(verb));
            assert_eq!(crate::verbs::required_scope(verb), VerbScope::Full);
            assert_eq!(
                crate::rate::MutationClass::for_verb(verb, crate::rate::CONFIG_CLASS_RULES),
                crate::rate::MutationClass::Crud
            );
            assert!(crate::verb::verb_for("GET", path).is_none());
        }
        for path in [
            "/api/v1/admin/resolve_dispute",
            "/api/v1/admin/ledger/resolve-dispute",
            "/api/v1/admin/ledger/recovery/resolve/",
        ] {
            assert!(crate::verb::verb_for("POST", path).is_none());
        }
    }
}
