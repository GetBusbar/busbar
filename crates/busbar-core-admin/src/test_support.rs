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

/// The OpenAPI document generated from the typed route contract over `doors`, the door table the
/// caller lends (the composition root's admin tests generate it over the linked planes' table).
#[cfg(feature = "openapi-schema")]
pub fn openapi_doc(doors: busbar_kernel::plane_driver::doors::Doors) -> serde_json::Value {
    crate::v1::json::openapi_doc(doors)
}

/// Every component schema a plane of `doors` (the lent door table) contributes through its
/// `openapi_schemas`, as `(plane key, schema name, schema)`, in the order `openapi_doc` inserts them
/// into its generator (the composition root's admin tests hold them to the committed document over
/// the door planes' table).
#[cfg(feature = "openapi-schema")]
pub fn plane_component_schemas(
    doors: busbar_kernel::plane_driver::doors::Doors,
) -> Vec<(&'static str, String, serde_json::Value)> {
    let mut out = Vec::new();
    for decl in doors.decls() {
        let Some(schemas) = decl.openapi_schemas.and_then(|stated| stated(decl)) else {
            continue;
        };
        for (name, schema) in schemas {
            out.push((decl.key, name, schema));
        }
    }
    out
}
