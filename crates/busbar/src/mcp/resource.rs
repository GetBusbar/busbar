// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The RFC 9728 PROTECTED RESOURCE METADATA document.
//!
//! ## What this is for
//!
//! It is the second step of a discovery loop with exactly three steps, and it is the only step that
//! carries information the client could not have guessed:
//!
//! 1. The client posts to the MCP endpoint with no credential and gets `401` with
//!    `WWW-Authenticate: Bearer resource_metadata="<this document's URL>"`.
//! 2. It fetches this document and learns which authorization servers may mint tokens for this
//!    resource, and what this resource calls itself.
//! 3. It does ordinary OAuth against one of those authorization servers, asking for a token whose
//!    audience is the `resource` value below, and comes back.
//!
//! That is the whole of "an agent logs into busbar with no prior configuration". Nothing here is
//! busbar-specific; a client that has never heard of busbar completes it.
//!
//! ## Why it is unauthenticated, deliberately
//!
//! RFC 9728 §3 requires this document to be readable without credentials, and it must be: the entire
//! population of callers who need it are, by definition, the ones who do not have a token yet.
//! Requiring one would be a discovery loop that cannot be entered. It therefore declares
//! `RouteAuth::None` at its mount — the one exception on this plane, made explicitly at the route
//! rather than assumed by the handler.
//!
//! It discloses nothing that is not already public by construction: the deployment's own canonical
//! URI (which every client must know to obtain a token at all) and the operator's IdP issuer (which
//! every user of that IdP already knows). It does NOT enumerate tools, keys, pools or policy — the
//! catalogue is grant-scoped and lives behind the token.

use axum::response::{IntoResponse, Response};

/// `GET /.well-known/oauth-protected-resource<mcp-path>`.
///
/// The path is registered CONCRETELY at mount time from the operator's canonical URI, not matched as
/// a prefix. That is what lets the auth middleware keep its exact-match discipline: a prefix
/// exemption under `/.well-known/` would hand a free pass to every path beneath it, and the RFC's
/// path-insertion rule means the exact string is knowable at boot anyway.
pub(crate) async fn metadata(crate::state::CurrentApp(app): crate::state::CurrentApp) -> Response {
    let Some(resource) = app.mcp.as_ref() else {
        // Unreachable while the mount and the config are created in the same act. Kept as a clean
        // refusal rather than an unwrap because this is a request path.
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({ "error": "not_found" })),
        )
            .into_response();
    };

    // Field order follows RFC 9728 §2. `resource` is the only REQUIRED member, and it is the one
    // that matters: it is the audience a client must ask its authorization server to mint for, and
    // it is compared byte-for-byte against the `aud` of every token presented here. If this document
    // said one thing and the verifier expected another, every correctly-behaved client in the world
    // would obtain a token this server then refuses — so both read the same value from the same
    // validated config object, and there is no second spelling of it anywhere.
    let mut doc = serde_json::Map::new();
    doc.insert(
        "resource".into(),
        serde_json::Value::from(resource.canonical_uri()),
    );
    doc.insert(
        "authorization_servers".into(),
        serde_json::Value::from(resource.authorization_servers()),
    );
    if !resource.scopes_supported().is_empty() {
        doc.insert(
            "scopes_supported".into(),
            serde_json::Value::from(resource.scopes_supported()),
        );
    }
    // busbar accepts the bearer token in the `Authorization` header and nowhere else. RFC 6750 also
    // defines a form-encoded body parameter and a URI query parameter; both are advertised here by
    // some servers and both are mistakes for this surface — a token in a query string lands in
    // access logs, proxy logs and `Referer` headers. Stating `["header"]` explicitly tells a
    // conforming client not to try the others, rather than leaving it to discover by rejection.
    doc.insert(
        "bearer_methods_supported".into(),
        serde_json::Value::from(vec!["header"]),
    );

    (
        // Public, cacheable, and stable for the life of a config generation. A client that follows
        // the challenge on every request would otherwise re-fetch this document on every request.
        [
            (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
            (
                axum::http::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            ),
        ],
        axum::Json(serde_json::Value::Object(doc)),
    )
        .into_response()
}

#[cfg(test)]
#[path = "tests/resource_tests.rs"]
mod resource_tests;
