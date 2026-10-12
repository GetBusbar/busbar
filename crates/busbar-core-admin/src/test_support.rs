// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The handles the composition root's admin tests drive this crate through: `cfg(test)` or the
//! `test-support` feature only.
//!
//! They get the handlers and documents the root's admin tests drive (`crates/busbar/tests/
//! admin_cross_plane/`), which need a linked plane this crate's tests may not link.

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
