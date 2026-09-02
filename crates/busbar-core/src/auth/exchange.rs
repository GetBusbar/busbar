// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `POST /auth/token` — the DATA-PLANE token exchange (1.5.2).
//!
//! A caller presents a VERIFIED IdP identity (an id_token / bearer the configured auth chain
//! authenticates) and receives THEIR OWN busbar key, scoped to their budget. The identity is taken
//! SOLELY from the chain's verdict ([`ChainVerdict::Identified`]'s `principal.id`) — the request
//! body is never read, so a caller can never self-scope a key to another subject. The mint rides the
//! scheme-agnostic [`super::self_keys::SelfServeKeys`] seam.
//!
//! This handler is mounted with an EXACT-MATCH middleware bypass (see `AUTH_TOKEN_PATH`): the auth
//! middleware does not admit/deny it, because the handler runs the chain ITSELF to establish who the
//! caller is (an unauthenticated caller gets a 401 from here, not from the middleware).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};

use super::self_keys::{
    issue_key, resolve_exchange, DeterministicEd25519Keys, ExchangeError, HandleProvisioner,
    IssuedKey,
};
use super::AuthMiddleware;
use crate::diagnostics::{diag_error, TOKEN_EXCHANGE_MINT_FAILED};

/// The exact path the exchange is mounted at. The auth middleware bypasses this path so the handler
/// can run the chain itself; the GET browser flow is mounted at the same path.
pub(crate) const AUTH_TOKEN_PATH: &str = "/auth/token";

/// `POST /auth/token`: exchange a verified IdP identity for a self-serve busbar key.
pub(crate) async fn exchange(
    State(handle): State<Arc<crate::state::AppHandle>>,
    req: Request<Body>,
) -> Response {
    let app = handle.load();
    // A CREDENTIAL-flow form submission carries the browser login cookie (set by `begin` when a
    // Credential method rendered its form). Route it to the credential completer, which verifies the
    // submitted credential via the plugin and issues through the SAME seam. A headless IdP-bearer
    // exchange (CI/BYOK) has NO login cookie and falls through to the chain path below.
    if let Some(cookie) = crate::auth::token::read_login_cookie(&req) {
        // Small, bounded read of the form body (credential fields + the CSRF `__state`).
        let bytes = axum::body::to_bytes(req.into_body(), 64 * 1024)
            .await
            .unwrap_or_default();
        let form = crate::auth::token::parse_form_urlencoded(&String::from_utf8_lossy(&bytes));
        return crate::auth::token::credential_submit(&app, &handle, cookie, form).await;
    }
    // Identity comes from the VERIFIED chain, never the body. The IdP credential rides the same
    // carriers as any data-plane token (Authorization: Bearer / x-api-key / x-goog-api-key).
    let candidate = AuthMiddleware::extract_client_token(&req);
    let verdict = AuthMiddleware::run_chain_on_request_path(
        &app.auth,
        &app.credential_cache,
        candidate,
        app.governance.clone(),
        // `/auth/token` is a DATA-PLANE route and mints data-plane keys, so the expected audience is
        // `None` — which makes the verifier reject any audience-bound token presented here. That is
        // the plane boundary doing its job in the direction people forget: an MCP token must not be
        // able to mint itself a plain busbar key and step off the plane it was confined to.
        None,
    )
    .await;

    let (principal, team, pools) =
        match resolve_exchange(&verdict, &app.role_bindings, app.mint_policy.self_mint) {
            Ok(v) => v,
            Err(e) => return refusal(e),
        };

    let Some(gov) = app.governance.clone() else {
        return refusal(ExchangeError::MintFailed(
            "governance is disabled: cannot mint keys".to_string(),
        ));
    };
    let ttl = Duration::from_secs(app.self_key_ttl_secs);
    // The provisioner auto-creates the `user:<sub>` leaf under `team` on first exchange (limits from
    // the team's `child_default`) so the minted key is immediately usable, not a 429 MissingGroup.
    let provisioner = Arc::new(HandleProvisioner::new(handle.clone(), principal.id.clone()));
    let keys = DeterministicEd25519Keys::new(gov, team, pools, provisioner);
    match issue_key(&keys, principal, ttl, false).await {
        Ok(issued) => {
            // SELF-CONTAINED response: include `base_url` (= the configured `public_url`, verbatim, no
            // `/v1`) so a headless/CI caller has everything to point a BYOK tool in ONE payload.
            let base_url = app.public_url.as_deref().unwrap_or("");
            (
                StatusCode::OK,
                axum::Json(exchange_ok_body(&issued, base_url)),
            )
                .into_response()
        }
        Err(e) => refusal(e),
    }
}

/// The success body of `POST /auth/token`: the issued key plus `base_url` so the caller has the
/// complete BYOK payload (`{ api_key, key_id, group, exp, base_url }`).
fn exchange_ok_body(issued: &IssuedKey, base_url: &str) -> serde_json::Value {
    serde_json::json!({
        // `.expose_secret()`: the once-shown mint response is the intended, documented plaintext
        // egress of the issued token (Redacted has no Serialize, so json! cannot embed it directly).
        "api_key": issued.secret.expose_secret(),
        "key_id": issued.key_id,
        "group": issued.group,
        "exp": issued.exp,
        "base_url": base_url,
    })
}

/// Map an [`ExchangeError`] to its wire status + a minimal JSON body. No enumeration oracle: the
/// bodies are generic (the audit log carries the specifics).
fn refusal(e: ExchangeError) -> Response {
    let (status, msg) = match e {
        ExchangeError::StaticKeyPresented => (
            StatusCode::BAD_REQUEST,
            "present an IdP identity, not a busbar key",
        ),
        ExchangeError::Unauthorized => (StatusCode::UNAUTHORIZED, "not authenticated"),
        ExchangeError::SelfMintDisabled => (
            StatusCode::FORBIDDEN,
            "self-serve minting is disabled by policy",
        ),
        ExchangeError::Unbound => (
            StatusCode::FORBIDDEN,
            "no self-serve grant for this identity",
        ),
        ExchangeError::BadSubject => (StatusCode::FORBIDDEN, "identity is not a valid subject"),
        ExchangeError::MintFailed(ref detail) => {
            diag_error!(TOKEN_EXCHANGE_MINT_FAILED, error = %detail, "token-exchange mint failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "could not issue a key")
        }
    };
    (status, axum::Json(serde_json::json!({ "error": msg }))).into_response()
}

#[cfg(test)]
#[path = "tests/exchange_tests.rs"]
mod tests;
