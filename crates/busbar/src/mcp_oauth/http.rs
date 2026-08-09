// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HTTP surface of the resource server: the RFC 9728 metadata document, and the MCP mount's
//! placeholder handler.
//!
//! The 401 challenge is NOT here. It is emitted by the auth middleware (`crate::auth`), before any
//! handler runs, because an unauthenticated request must never reach a handler at all — putting the
//! challenge in a handler would mean the handler is the thing deciding admission, which is precisely
//! the arrangement the plane boundary exists to prevent.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

/// Admission for the MCP plane, run by `crate::auth::auth_middleware` for every path the resource
/// server owns and by nothing else.
///
/// This function is the whole reason the surface exists, and it is deliberately NOT the ordinary
/// data-plane bar:
///
/// - the credential is an OAuth access token from the operator's IdP, not a busbar key, so the
///   busbar key chain must not run here — a busbar key is inadmissible on the MCP plane exactly as
///   an MCP token is inadmissible on the data plane (the P1 plane boundary, from the other side);
/// - the credential is read from `Authorization: Bearer` ONLY. The vendor carriers (`x-api-key`,
///   `x-goog-api-key`) are LLM-SDK conveniences and are not OAuth; accepting one here would add a
///   second door to the plane whose bar nobody would think to check;
/// - a refusal answers `401` with the RFC 9728 challenge, which is what turns "you cannot come in"
///   into "here is how to come in" and makes the whole discovery flow work;
/// - the refusal REASON never reaches the wire, for the same reason
///   `auth::unauthorized_response` keeps its message independent of the cause: a 401 that says which
///   check failed is an oracle that walks an attacker toward a working token.
pub(crate) async fn admission(
    rs: &super::ResourceServer,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::auth::AuthMiddleware::extract_bearer_token)
        .unwrap_or_default();
    match rs.admit(&token, crate::store::now()) {
        Err(refusal) => {
            // The reason is a log fact, not a wire fact.
            tracing::debug!(
                target: "busbar::mcp_oauth",
                reason = refusal.tag(),
                "MCP request refused"
            );
            challenge_response(rs)
        }
        Ok(caller) => {
            let caller = Arc::new(caller);
            // The identity the existing governance path consumes — role bindings, budget, policy,
            // rate limits and audit all key off `AuthPrincipal` and none of them need to know that
            // this particular principal arrived over OAuth rather than over a busbar key.
            req.extensions_mut()
                .insert(crate::auth::AuthPrincipal(Some(caller.principal())));
            // The MCP-specific half: WHICH AGENT is acting. Kept beside the principal rather than
            // folded into it, because `Principal` is the shared identity contract every auth module
            // produces and the acting client is a fact only this plane has.
            req.extensions_mut()
                .insert(super::AdmittedMcpCaller(caller));
            next.run(req).await
        }
    }
}

/// The `401` that carries the RFC 9728 challenge. One constructor, so the challenge cannot be
/// attached on some refusal paths and forgotten on others.
///
/// The body is a JSON-RPC error rather than a vendor LLM envelope: the caller here is an MCP client,
/// and answering it in a dialect it does not speak would make a well-defined authorization failure
/// look like a malformed server.
fn challenge_response(rs: &super::ResourceServer) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::WWW_AUTHENTICATE, rs.challenge()),
            (header::CONTENT_TYPE, "application/json"),
        ],
        r#"{"jsonrpc":"2.0","error":{"code":-32001,"message":"Unauthorized"},"id":null}"#,
    )
        .into_response()
}

/// `GET /.well-known/oauth-protected-resource/mcp` (and its root alias). Serves the RFC 9728
/// document that tells an unauthenticated client which authorization servers can mint a token for
/// this resource.
///
/// PUBLIC by design and by RFC: discovery must work before a caller has any credential, which is the
/// whole point of the 401-then-discover flow. What keeps that safe is the document's contents, not
/// its access control — see `ResourceServer::build` for why it carries three members and no more.
///
/// Mounted only when `mcp:` is configured, so the 404 arm below is not reachable through the router.
/// It exists because the handler cannot prove that on its own and answering with a 500 for a
/// route that should not have been mounted would be worse than answering "no such thing".
pub(crate) async fn protected_resource_metadata(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
) -> Response {
    match app.mcp.as_ref() {
        Some(rs) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                // Cacheable: the document changes only when an operator changes config, and a client
                // that re-fetches it on every 401 turns a credential expiry into a thundering herd.
                (header::CACHE_CONTROL, "public, max-age=3600"),
            ],
            rs.metadata().to_string(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The MCP mount itself.
///
/// **This is a placeholder and is expected to be replaced**, not extended: the MCP JSON-RPC layer is
/// separate work, and this handler exists so the admission path this module owns has a real route to
/// terminate at. That matters for the tests: an admitted caller must be observably ADMITTED, and a
/// route that does not exist would answer 404 for an admitted caller and 404 for a rejected one,
/// which proves nothing about admission.
///
/// It answers `501` with a JSON-RPC-shaped error, so a real MCP client sees a protocol-legible "not
/// implemented" rather than an HTML error page, and echoes the admitted caller's identity nowhere —
/// a placeholder that reflected the token's claims back would be an oracle.
pub(crate) async fn mount_placeholder(
    axum::Extension(caller): axum::Extension<super::AdmittedMcpCaller>,
) -> Response {
    // The extension is inserted by the auth middleware on admission and by nothing else, so its
    // presence here is proof the admission path ran. Reading it (rather than ignoring it) is what
    // makes that a compile-time guarantee: if the middleware stopped inserting it, this handler
    // would fail its extractor rather than silently serving an unauthenticated caller.
    debug_assert!(
        !caller.0.subject.is_empty(),
        "an admitted caller has a subject"
    );
    (
        StatusCode::NOT_IMPLEMENTED,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"MCP transport not yet mounted"},"id":null}"#,
    )
        .into_response()
}
