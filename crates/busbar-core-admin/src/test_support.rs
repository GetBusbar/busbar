// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The handles the composition root's admin tests drive this crate through: `cfg(test)` or the
//! `test-support` feature only.
//!
//! They get the handlers and documents the root's admin tests drive (`crates/busbar/tests/
//! admin_cross_plane/`), which need a linked plane this crate's tests may not link.

#[cfg(test)]
use crate::v1::contract::taxonomy::MethodTag;
#[cfg(test)]
use crate::v1::contract::{taxonomy::ErrKind, AdminError};

// The lowercase OpenAPI operation key for this verb. Only called from #[cfg(test)] sites
// (the taxonomy drift audit in json/mod.rs and admin/tests/tests.rs) — unlike `from_op_key`, never
// from openapi_doc's own body — so it needs no feature alternative.
#[cfg(test)]
impl MethodTag {
    pub fn as_str(self) -> &'static str {
        match self {
            MethodTag::Get => "get",
            MethodTag::Post => "post",
            MethodTag::Put => "put",
            MethodTag::Patch => "patch",
            MethodTag::Delete => "delete",
        }
    }
}

/// Classify an HTTP method into a `MethodTag`. `None` for a verb the admin surface never routes —
/// such a request can only be the router's 405 fallback, which is algorithmic, not declarable. Only
/// reached from the test-only recording layer (`json/mod.rs::record_declared_error`).
#[cfg(test)]
pub fn method_tag(m: &axum::http::Method) -> Option<MethodTag> {
    use axum::http::Method;
    Some(match *m {
        Method::GET => MethodTag::Get,
        Method::POST => MethodTag::Post,
        Method::PUT => MethodTag::Put,
        Method::PATCH => MethodTag::Patch,
        Method::DELETE => MethodTag::Delete,
        _ => return None,
    })
}

/// The `ErrKind ↔ AdminError` EXHAUSTIVENESS BRIDGE. Every `AdminError` variant is classified either
/// as a per-endpoint-DECLARABLE `ErrKind` (appears in `declared_errors`) or as `None` = ALGORITHMIC
/// (stamped on every op by `openapi_doc`, never declared per-endpoint). Adding an `AdminError`
/// variant WON'T COMPILE until it is classified here — so the taxonomy can never grow a code the doc
/// dimension doesn't know about. This subsumes and strengthens
/// `openapi_error_enum_matches_admin_error_codes`.
// Reached from the taxonomy tag stamp in `err_json_tagged`, in this crate's tests.
#[cfg(test)]
pub fn err_kind_of(e: &AdminError) -> Option<ErrKind> {
    match e {
        AdminError::NotFound { .. } => Some(ErrKind::NotFound),
        AdminError::Validation(_) => Some(ErrKind::Validation),
        AdminError::VersionConflict(_) => Some(ErrKind::VersionConflict),
        AdminError::Conflict(_) => Some(ErrKind::Conflict),
        AdminError::Forbidden { .. } => Some(ErrKind::Forbidden),
        // ALGORITHMIC (stamped on every op, never per-endpoint declared):
        AdminError::Unauthorized => None,
        AdminError::MethodNotAllowed => None,
        AdminError::RateLimited => None,
        AdminError::Internal => None,
        // Emitted by exactly one operation today (`GET /plugins?type=store`'s catalog-scan-gate
        // timeout), same posture as `RateLimited` above (which is likewise only ACTUALLY emitted by
        // mutation endpoints despite being classified algorithmic): documenting it per-endpoint would
        // be one entry with no cross-endpoint reuse, so it rides the same global 5xx bucket as
        // `Internal` rather than growing the declared-error machinery for a single call site.
        AdminError::Unavailable(_) => None,
        AdminError::UnpricedClass { .. } => Some(ErrKind::UnpricedClass),
    }
}

/// The admin service's `POST /config/apply` handler, driven directly by the composition root's admin
/// tests (`crates/busbar/tests/admin_cross_plane/`), which need a linked plane this crate's own tests
/// may not link.
pub async fn apply_config(
    state: axum::extract::State<std::sync::Arc<busbar_kernel::state::AppHandle>>,
    principal: axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    crate::v1::json::apply_config(state, principal, headers, body).await
}

/// The served `openapi.json`, inflated from the embedded document (the composition root's admin
/// tests compare it with what they document).
pub fn openapi_json() -> String {
    crate::v1::json::openapi_json()
}

/// The OpenAPI document generated from the typed route contract over the registered planes (the
/// composition root's admin tests generate it with the linked planes registered).
#[cfg(feature = "openapi-schema")]
pub fn openapi_doc() -> serde_json::Value {
    crate::v1::json::openapi_doc()
}
