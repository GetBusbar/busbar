// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MCP HTTP ingress: the transport-level MUSTs of revision `2026-07-28`, enforced before any
//! JSON-RPC method is looked up.
//!
//! ## Why these checks are here and not in the method handlers
//!
//! Every rule in this file is a statement about the ENVELOPE, and each one exists because a
//! disagreement between two readings of the same request is exploitable. The mirrored headers are
//! the clearest case: `Mcp-Method` and `Mcp-Name` exist so an intermediary (a proxy, a WAF, a rate
//! limiter, busbar itself in front of an upstream) can route and police a request without parsing
//! its body. The moment the header and the body can disagree, the intermediary and the executor are
//! looking at two different requests — which is request smuggling, spelled in JSON. The spec's
//! answer is that the server MUST reject the disagreement outright, and that rejection has to happen
//! before anything acts on either reading. So: one place, before dispatch, no exceptions.
//!
//! ## The order of the checks, and why it is that order
//!
//! 1. `Origin`, because it is about who is allowed to speak at all, and it costs one header lookup.
//! 2. Body parse, because everything after it reads the body.
//! 3. Envelope shape (`jsonrpc`, `method`), because the header checks compare AGAINST the body.
//! 4. Mirrored headers, all of which fail as `HeaderMismatch` (`-32020`, `400`).
//! 5. Protocol version support (`-32022`, `400`), only once we know the request was well formed —
//!    telling a malformed request which versions we speak answers a question it did not ask.
//! 6. Method dispatch, whose miss is `-32601` with `404`.
//!
//! ## What this module does NOT do
//!
//! It looks nothing up. The method table is empty here, and every method therefore takes the
//! `-32601` arm. That is not a stub: `404` + `-32601` is exactly what this revision requires of a
//! server that does not implement a method, and it is the answer that stays correct, unchanged, for
//! every method still unimplemented after the CATALOGUE and DISPATCH units land.

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;

/// The single MCP protocol revision busbar implements.
///
/// ONE revision, deliberately. The conformance suite runs each scenario per revision and one run
/// does not cover another, so supporting two revisions is two test legs and two wire formats, not a
/// compatibility shim. `2025-11-25` and earlier are stateful: they have an `initialize` handshake,
/// protocol sessions and a GET stream, all of which this revision deleted, and building them means
/// building session machinery this release can otherwise skip entirely.
pub(crate) const PROTOCOL_VERSION: &str = "2026-07-28";

/// Every revision busbar will accept, echoed to a client that asked for one we do not implement so
/// it can pick a mutually supported one and retry. Exactly one entry today; the shape is plural
/// because the `UnsupportedProtocolVersionError` schema requires a list, and because the day a
/// second revision is added this constant is the only thing that has to know.
pub(crate) const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[PROTOCOL_VERSION];

/// The `_meta` key carrying the protocol version of an individual request. Under this revision
/// negotiation is ON DEMAND — there is no handshake, so every request states its own version, and
/// this key is where it states it.
///
/// It lives at `params._meta`, NOT at the top level of the JSON-RPC envelope. This module read the
/// top level first, and the official conformance suite caught it: every scenario failed at setup
/// with "the request body's `_meta` must carry …" against requests that carried it correctly. The
/// schema is unambiguous — `JSONRPCRequest.params` requires `_meta`, and that `RequestMetaObject`
/// requires this key — and the mistake is worth a comment because both placements read naturally
/// and only one of them is a request any client will send.
const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

/// The `_meta` key carrying the client's capabilities for THIS request.
///
/// Absent is treated as the EMPTY capability set, not as an error. The schema lists it as required,
/// but the security-relevant direction is one-way: a server must never INFER a capability the client
/// did not declare (the spec says so explicitly, because there is no handshake to have learned one
/// from). Treating absent as empty errs towards doing less on the client's behalf, which is the safe
/// side; refusing the request outright would err towards turning conforming-enough clients away for
/// no gain in authority.
const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";

/// The header mirroring the body's `method`. REQUIRED on every request.
const H_MCP_METHOD: &str = "mcp-method";
/// The header mirroring the target name. REQUIRED on `tools/call`, `resources/read`, `prompts/get`.
const H_MCP_NAME: &str = "mcp-name";
/// The header mirroring the `_meta` protocol version.
const H_PROTOCOL_VERSION: &str = "mcp-protocol-version";

/// JSON-RPC error codes this module emits. Named rather than inlined because three of the four are
/// MCP extensions rather than JSON-RPC standard codes, and a bare `-32022` in a match arm is a
/// magic number nobody can check against the schema.
mod code {
    /// JSON-RPC standard: the body was not valid JSON.
    pub(super) const PARSE_ERROR: i64 = -32700;
    /// JSON-RPC standard: valid JSON, but not a valid request object.
    pub(super) const INVALID_REQUEST: i64 = -32600;
    /// JSON-RPC standard: the method is not implemented. MCP pairs it with `404`, not `200`.
    pub(super) const METHOD_NOT_FOUND: i64 = -32601;
    /// MCP `HeaderMismatchError`: an HTTP header disagreed with the body. Always `400`.
    pub(super) const HEADER_MISMATCH: i64 = -32020;
    /// MCP `UnsupportedProtocolVersionError`: carries `data.requested` and `data.supported`. Always
    /// `400`.
    pub(super) const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;
}

/// `GET` and `DELETE` on the MCP endpoint.
///
/// Under earlier revisions `GET` opened the server-to-client SSE stream and `DELETE` terminated a
/// session. This revision removed both — there is no GET stream, no `Last-Event-ID` resumability,
/// and no session to delete — and says a server SHOULD answer `405`. Answering `405` rather than
/// `404` is the informative choice: it tells a client built against an older revision that it found
/// the right endpoint and used the wrong verb, which is a fixable diagnosis, where `404` would send
/// it looking for a path that is not missing.
///
/// This route is declared `RouteAuth::Key`, so an anonymous caller gets the `401` challenge and
/// never reaches here. That ordering is deliberate: the `405` is a statement about our protocol
/// surface, and a protected resource should not answer questions about its surface before it knows
/// who is asking.
pub(crate) async fn legacy_verb() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [("allow", "POST")],
        axum::Json(serde_json::json!({
            "error": "method_not_allowed",
            "error_description":
                "MCP revision 2026-07-28 has no GET stream and no sessions; the endpoint accepts POST only.",
        })),
    )
        .into_response()
}

/// The MCP endpoint: `POST`.
///
/// Auth has already happened — the route declares `RouteAuth::Key`, and the plane's admission facts
/// made the middleware verify the token's audience against this deployment's canonical URI. Anything
/// reaching this function is an admitted caller.
pub(crate) async fn rpc(
    axum::extract::State(handle): axum::extract::State<std::sync::Arc<crate::state::AppHandle>>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(principal): axum::extract::Extension<crate::auth::AuthPrincipal>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // The snapshot this request runs on, taken ONCE. `method::Ctx` also carries the handle, because
    // dispatch re-reads the LIVE snapshot to compare pin generations — a comparison against this
    // same value could never fail.
    let app = handle.load();
    // The resource is present whenever this route is mounted — the mount is what creates it. The
    // fallback exists only so a future refactor that mounts the route without the config produces a
    // clean refusal instead of a panic on a request path.
    let Some(resource) = app.mcp.as_ref() else {
        return error_response(
            StatusCode::NOT_FOUND,
            None,
            code::METHOD_NOT_FOUND,
            "MCP is not enabled on this deployment.",
            None,
        );
    };

    // (1) ORIGIN. A MUST, and the DNS-rebinding defence: a page on an attacker's origin resolves a
    // hostname to busbar's address and drives the tool plane with whatever ambient credential the
    // browser attaches. A request with NO `Origin` is not a browser request and is unaffected —
    // refusing those would refuse every agent, which is every real client.
    if let Some(origin) = header_str(&headers, "origin") {
        if !is_loopback_origin(origin) && !resource.origin_allowed(origin) {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({
                    "error": "invalid_origin",
                    "error_description":
                        "This Origin is not allowed. Browser origins must be listed in mcp.allowed_origins.",
                })),
            )
                .into_response();
        }
    }

    // (2) PARSE.
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            None,
            code::PARSE_ERROR,
            "Request body is not valid JSON.",
            None,
        );
    };

    // (3) ENVELOPE SHAPE. A JSON-RPC batch (a top-level array) is not part of this revision's
    // transport: the body carries a SINGLE message. Refusing it explicitly beats treating the array
    // as an object and reading `method` as absent, which would answer the wrong question.
    let Some(obj) = value.as_object() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            None,
            code::INVALID_REQUEST,
            "The request body must be a single JSON-RPC message object; batches are not supported.",
            None,
        );
    };
    // `id` is echoed on every error from here on, because a client correlating responses needs it
    // more on a failure than on a success. Absent `id` means a notification; it is simply not
    // echoed, which is what the schema requires (`id` is not a required member of an error
    // response).
    let id = obj.get("id").cloned();
    if obj.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return error_response(
            StatusCode::BAD_REQUEST,
            id,
            code::INVALID_REQUEST,
            "`jsonrpc` must be exactly \"2.0\".",
            None,
        );
    }
    let Some(method) = obj.get("method").and_then(|v| v.as_str()) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            id,
            code::INVALID_REQUEST,
            "`method` is required and must be a string.",
            None,
        );
    };

    // (4) MIRRORED HEADERS. All four failures below are one class — an intermediary and the executor
    // disagreeing about what this request is — so they share one code and one status.
    //
    // Header NAMES are case-insensitive (axum lower-cases them for us); header VALUES, including
    // method names, are case-sensitive. Comparing values case-insensitively here would let
    // `Mcp-Method: TOOLS/CALL` mirror `tools/call`, which is precisely a disagreement dressed as a
    // match.
    // `params._meta`, per the schema. See META_PROTOCOL_VERSION for why this is not the top level.
    let meta = obj.get("params").and_then(|p| p.get("_meta"));
    let body_version = meta
        .and_then(|m| m.get(META_PROTOCOL_VERSION))
        .and_then(|v| v.as_str());
    // Read but not required — see META_CLIENT_CAPABILITIES. Bound here rather than at the point of
    // use so the one place capabilities enter the server is visible in the envelope check, next to
    // the version they are negotiated alongside.
    let _client_capabilities = meta.and_then(|m| m.get(META_CLIENT_CAPABILITIES));
    let Some(header_version) = header_str(&headers, H_PROTOCOL_VERSION) else {
        return header_mismatch(
            id,
            "Every POST to the MCP endpoint must carry an `MCP-Protocol-Version` header.",
        );
    };
    let Some(body_version) = body_version else {
        return header_mismatch(
            id,
            "`params._meta` must carry `io.modelcontextprotocol/protocolVersion`; this revision \
             negotiates per request, so the version cannot be inferred.",
        );
    };
    if header_version != body_version {
        return header_mismatch(
            id,
            "The `MCP-Protocol-Version` header does not match the body's \
             `_meta.io.modelcontextprotocol/protocolVersion`.",
        );
    }
    let Some(header_method) = header_str(&headers, H_MCP_METHOD) else {
        return header_mismatch(id, "The `Mcp-Method` header is required on every request.");
    };
    if decode_sentinel(header_method).as_deref() != Some(method) {
        return header_mismatch(
            id,
            "The `Mcp-Method` header does not match the body's `method`.",
        );
    }
    // `Mcp-Name` mirrors `params.name` (`tools/call`, `prompts/get`) or `params.uri`
    // (`resources/read`). It is REQUIRED on exactly those three and meaningless elsewhere.
    if let Some(source) = name_source_of(method) {
        let body_name = obj
            .get("params")
            .and_then(|p| p.get(source))
            .and_then(|v| v.as_str());
        let Some(header_name) = header_str(&headers, H_MCP_NAME) else {
            return header_mismatch(
                id,
                "The `Mcp-Name` header is required on tools/call, resources/read and prompts/get.",
            );
        };
        // The sentinel is decoded BEFORE comparison, which is its own MUST. A server that compared
        // the encoded form would reject every client that legitimately encoded a name containing a
        // character no header value may carry — and, worse, a server that decoded only sometimes
        // would give two different answers to one request depending on the name.
        let Some(decoded) = decode_sentinel(header_name) else {
            return header_mismatch(
                id,
                "The `Mcp-Name` header carries a `=?base64?…?=` sentinel that is not valid Base64.",
            );
        };
        if body_name != Some(decoded.as_str()) {
            return header_mismatch(
                id,
                "The `Mcp-Name` header does not match the body's target name.",
            );
        }
    }

    // (5) VERSION SUPPORT. Only now, with a well-formed request in hand: `data.supported` is an
    // invitation to retry, and inviting a malformed request to retry teaches a client the wrong
    // lesson about why it failed.
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&body_version) {
        return error_response(
            StatusCode::BAD_REQUEST,
            id,
            code::UNSUPPORTED_PROTOCOL_VERSION,
            "This server does not implement the requested MCP protocol version.",
            Some(serde_json::json!({
                "requested": body_version,
                "supported": SUPPORTED_PROTOCOL_VERSIONS,
            })),
        );
    }

    // (6) DISPATCH. The method table owns everything from here: the CATALOGUE reads and the
    // DISPATCH path, both computed under the caller's grant. A method the table does not carry falls
    // through to `404` + `-32601`, which was always the correct answer for an unimplemented method
    // and did not have to change when the table gained entries.
    let ctx = crate::mcp::method::Ctx {
        app: &app,
        handle: &handle,
        gov: &gov,
        actor: principal.actor_id(),
    };
    let params = obj.get("params");
    match crate::mcp::method::dispatch(&ctx, method, params, id.clone()) {
        Some(response) => response,
        None => error_response(
            StatusCode::NOT_FOUND,
            id,
            code::METHOD_NOT_FOUND,
            &format!("Method `{method}` is not implemented by this server."),
            None,
        ),
    }
}

/// Whether `origin` is a LOOPBACK origin, which is always accepted regardless of the operator's
/// allowlist.
///
/// This is safe, and it is worth being precise about why, because "allow localhost" reads like a
/// weakening. The DNS-rebinding attack is a page served from an ATTACKER's origin —
/// `http://evil.example` — whose hostname the attacker has made resolve to the loopback address.
/// That page's `Origin` header is `http://evil.example`, never `http://localhost`. A browser will
/// only send a loopback `Origin` for a document that was itself served from loopback, which is a
/// document already inside the trust boundary. So loopback origins carry no rebinding risk, and
/// refusing them refuses the local inspector and the local agent — the two clients an operator is
/// most likely to try first — for no security gain.
///
/// The port is deliberately not constrained: any local port is the same trust boundary.
fn is_loopback_origin(origin: &str) -> bool {
    let host = match origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
    {
        Some(rest) => rest.split('/').next().unwrap_or(""),
        // `null` and every non-http scheme. `Origin: null` is what a sandboxed iframe and a
        // `file://` document send, and treating it as local would admit exactly the contexts that
        // deliberately have no origin.
        None => return false,
    };
    let host = host.rsplit_once(':').map_or(host, |(h, port)| {
        // Only strip a trailing `:port`; `[::1]` has colons of its own and must survive intact.
        if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() {
            h
        } else {
            host
        }
    });
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

/// Which `params` member `Mcp-Name` mirrors for `method`, or `None` when the header is not required.
///
/// The three methods are enumerated rather than pattern-matched on a prefix: `tools/call` requires
/// it and `tools/list` does not, so any rule shorter than the list is a rule that gets one of them
/// wrong.
fn name_source_of(method: &str) -> Option<&'static str> {
    match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        _ => None,
    }
}

/// Decode a header value that may carry the `=?base64?…?=` sentinel.
///
/// The markers are CASE-SENSITIVE and must appear exactly as shown in lowercase — so `=?BASE64?x?=`
/// is not a sentinel, it is a literal value that happens to look like one, and treating it as
/// encoded would decode a value the client sent verbatim. Returns `None` only when a well-formed
/// sentinel wraps something that is not valid Base64 or not valid UTF-8, which is a malformed
/// request rather than a mismatch — both answer `-32020`, but the message differs.
fn decode_sentinel(value: &str) -> Option<String> {
    let Some(inner) = value
        .strip_prefix("=?base64?")
        .and_then(|v| v.strip_suffix("?="))
    else {
        return Some(value.to_string());
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(inner)
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// A header's value as UTF-8, or `None` when absent or not UTF-8. A non-UTF-8 header value cannot
/// equal any JSON string, so treating it as absent and treating it as a mismatch reach the same
/// refusal; absent is the simpler statement.
fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// The `HeaderMismatchError` shorthand: always `400`, always `-32020`.
fn header_mismatch(id: Option<serde_json::Value>, description: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        id,
        code::HEADER_MISMATCH,
        description,
        None,
    )
}

/// One JSON-RPC error envelope builder, so the status and the code cannot drift apart across the
/// eight refusals above and every future one.
///
/// Visible to the method table for exactly that reason: a second builder in `method.rs` would be a
/// second place for a status and a code to disagree, and the pair is the whole contract.
pub(super) fn error_response(
    status: StatusCode,
    id: Option<serde_json::Value>,
    code: i64,
    message: &str,
    data: Option<serde_json::Value>,
) -> Response {
    let mut error = serde_json::Map::new();
    error.insert("code".into(), serde_json::Value::from(code));
    error.insert("message".into(), serde_json::Value::from(message));
    if let Some(d) = data {
        error.insert("data".into(), d);
    }
    let mut envelope = serde_json::Map::new();
    envelope.insert("jsonrpc".into(), serde_json::Value::from("2.0"));
    // Echoed only when the request carried one. A JSON-RPC error response has no required `id`
    // member, and inventing `null` for a notification would claim a correlation that does not exist.
    if let Some(id) = id {
        envelope.insert("id".into(), id);
    }
    envelope.insert("error".into(), serde_json::Value::Object(error));
    (status, axum::Json(serde_json::Value::Object(envelope))).into_response()
}

#[cfg(test)]
#[path = "tests/ingress_tests.rs"]
mod ingress_tests;
