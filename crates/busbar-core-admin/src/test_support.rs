// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The verbs unit's own test-only `SecretOnce` mint (ARCHITECT ruling B, GATE-GREEN, 2026-10-02).
//!
//! `SecretOnce::mint(` is spelled only inside `crates/busbar-core-admin/src` (construction row
//! `token-sealed:secret-once-mint`): the verbs unit is the one place a minted secret's placeholder is
//! built. A dependent crate's tests (the composition root's replay-encoder proof) still need a real
//! placeholder, so this crate mints it here and hands it out; the caller names this function and
//! never the constructor. Compiled only under `cfg(test)` or this crate's `test-support` feature.
//!
//! It also hands the composition root's admin tests (`crates/busbar/tests/admin_cross_plane/`,
//! which need a linked plane this crate's tests may not link) the handlers and documents they drive.

use busbar_contract::caps::{AdminVerb, Grant, SecretOnce, UnitKey};

/// `SecretOnce::mint`: the placeholder for one minted secret, with the constructor's own arguments.
pub fn secret_once(
    admin: &Grant<AdminVerb>,
    nonce: u128,
    unit: UnitKey,
    target: impl Into<String>,
) -> SecretOnce {
    SecretOnce::mint(admin, nonce, unit, target)
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
