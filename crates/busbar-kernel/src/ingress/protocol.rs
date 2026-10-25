// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RFC 9728 PROTECTED-RESOURCE DOCUMENT RENDER, and nothing else.
//!
//! A door states its protected-resource facts (`PlaneSnapshot::resource_facts`, beside its
//! audience) and the kernel renders the one document from them (`busbar-contract/src/abi/plane/mod.rs`): no unit, no audit row. The composition root mounts it
//! at the path the door's snapshot names.
//!
//! The kernel speaks no JSON-RPC here. The envelope sequence that used to live in this file (the
//! `Origin` admission, the parse, the envelope read, the notification `202`, the method refusal)
//! is each plane's own arrive check (BUSBAR-1.6.0.md l.5024: "The Origin (DNS-rebinding) check
//! leaves the kernel with ingress/protocol: it is the plane's arrive check"); its pure reader is
//! `busbar_contract::jsonrpc` (F4).

use axum::response::{IntoResponse, Response};
use serde_json::Value;

/// THE RFC 9728 PROTECTED-RESOURCE METADATA DOCUMENT, written once.
///
/// It was written once per plane, and the ledger row retired by this function recorded (verified
/// 2026-08-11) that the two copies were the same document with the same audience rule. They were:
/// same member order, same `Cache-Control`, same `Content-Type`, and the same `resource` — the
/// audience a client must have its authorization server mint for, compared byte-for-byte against
/// the `aud` of every token presented under the mount.
///
/// The two differed only in which OPTIONAL members they carried, and RFC 9728 §2 makes both
/// optional, so an empty slice omits the member rather than asserting an empty one. That is what
/// makes one function byte-identical to both copies rather than a compromise between them.
///
/// ## Why it is unauthenticated
///
/// RFC 9728 §3 requires it, and it must: the entire population of callers who need this document
/// are the ones that do not have a token yet, so demanding one would be a discovery loop with no
/// entrance. The mount declares `RouteAuth::None` for exactly that reason — at the route, where
/// the openness travels with it.
pub struct Metadata<'a> {
    /// The audience. RFC 9728 §2's one REQUIRED member.
    ///
    /// A `Cow` because the two planes hold it differently and neither should have to change how it
    /// stores its own config to be rendered: MCP's canonical URI is borrowed straight out of the
    /// live snapshot, and A2A's arrives on an owned `PlaneAdmission` built per call. Borrowing pays
    /// nothing on the hot deployment and the owned side pays one `String` on a document served with
    /// `max-age=3600`.
    pub resource: std::borrow::Cow<'a, str>,
    /// Which authorization servers may mint for this resource. Omitted when empty.
    pub authorization_servers: &'a [String],
    /// The scopes this resource understands. Omitted when empty.
    pub scopes_supported: &'a [String],
}

/// Render one [`Metadata`].
///
/// `bearer_methods_supported` is `["header"]` and is not a parameter: busbar accepts a bearer token
/// in the `Authorization` header and nowhere else, on every plane. RFC 6750 also defines a
/// form-encoded body parameter and a URI query parameter, and both are mistakes for this surface —
/// a token in a query string lands in access logs, proxy logs and `Referer` headers. Stating
/// `["header"]` tells a conforming client not to try the others rather than leaving it to discover
/// by rejection, and making it a parameter would invite a protocol to say otherwise.
pub fn metadata(m: &Metadata<'_>) -> Response {
    let mut doc = serde_json::Map::new();
    doc.insert("resource".into(), Value::from(m.resource.as_ref()));
    if !m.authorization_servers.is_empty() {
        doc.insert(
            "authorization_servers".into(),
            Value::from(m.authorization_servers),
        );
    }
    if !m.scopes_supported.is_empty() {
        doc.insert("scopes_supported".into(), Value::from(m.scopes_supported));
    }
    doc.insert(
        "bearer_methods_supported".into(),
        Value::from(vec!["header"]),
    );
    (
        // Public, cacheable, and stable for the life of a config generation. A client that follows
        // the challenge on every request would otherwise re-fetch this document every time.
        [
            (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
            (
                axum::http::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            ),
        ],
        axum::Json(Value::Object(doc)),
    )
        .into_response()
}

#[cfg(test)]
#[path = "tests/protocol_tests.rs"]
mod protocol_tests;
