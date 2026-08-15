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
//! 4. `params._meta`'s REQUIRED MEMBERS, which fail as invalid params (`-32602`, `400`). This is a
//!    statement about the request's own PARAMS — the schema makes `params._meta` required and makes
//!    `protocolVersion` and `clientCapabilities` required inside it — so it is settled before any
//!    header is consulted. It has to be: a header check compares the header against the body, and
//!    "the body has nothing to compare against" is not a disagreement between two readings, it is
//!    one reading that is incomplete. Answering `-32020` there told a client its HEADERS were wrong
//!    when its PARAMS were, which sends an operator to fix the one thing that was right.
//! 5. Mirrored headers, all of which fail as `HeaderMismatch` (`-32020`, `400`).
//! 6. Protocol version support (`-32022`, `400`), only once we know the request was well formed —
//!    telling a malformed request which versions we speak answers a question it did not ask.
//! 7. Method dispatch, whose miss is `-32601` with `404`.
//! 8. RESPONSE FRAMING — `application/json` or an SSE stream, by the client's own stated preference,
//!    plus the `notifications/message` records busbar produced while answering. Last, because what
//!    it frames is the answer. See [`super::sse`].
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
use std::sync::Arc;

use super::sse;
use crate::ingress::protocol::CoreRefusal;

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

// ══ THE WIRE WORDS, DEFINED EXACTLY ONCE ════════════════════════════════════════════════════════
//
// Five string literals — two `_meta` keys and three header names — are the vocabulary busbar both
// REQUIRES on the way in (here) and EMITS on the way out (`mcp::client::jsonrpc`). They were once
// written down twice, once per direction, and each copy was internally consistent with its own
// side: busbar would have refused a request busbar itself sent, and no single-direction test could
// see it. `client/jsonrpc.rs` now IMPORTS these rather than restating them, so the two directions
// cannot disagree by construction.
//
// `structure-lint.sh`'s declaration census keeps it that way: each of these literals must occur
// EXACTLY ONCE in production code. A second spelling anywhere in the tree is RED, and so is zero
// occurrences — a wire word that vanished took its census row's subject with it.

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
pub(crate) const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

/// The `_meta` key carrying the client's capabilities for THIS request.
///
/// REQUIRED, and absent is a refusal rather than the empty capability set. An earlier reading of
/// this treated absent as empty on the grounds that the security-relevant direction is one-way — a
/// server must never INFER a capability the client did not declare — and that much is still true.
/// What it missed is that "declared nothing" and "declared the empty set" are different statements
/// under a protocol with NO HANDSHAKE. With no `initialize` there is no earlier message this could
/// have been stated in, so a request that omits it has never stated its capabilities at all, and a
/// server that fills the gap in has decided on the client's behalf what the client can do. The
/// schema makes it required for exactly that reason, and both this repository's own battery
/// (`SRV.META.MISSING-CAPABILITIES`) and the official suite read the omission as `-32602`.
pub(crate) const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";

/// The header mirroring the body's `method`. REQUIRED on every request.
pub(crate) const H_MCP_METHOD: &str = "mcp-method";
/// The header mirroring the target name. REQUIRED on `tools/call`, `resources/read`, `prompts/get`.
pub(crate) const H_MCP_NAME: &str = "mcp-name";
/// The header mirroring the `_meta` protocol version.
pub(crate) const H_PROTOCOL_VERSION: &str = "mcp-protocol-version";

/// JSON-RPC error codes this module emits. Named rather than inlined because three of the four are
/// MCP extensions rather than JSON-RPC standard codes, and a bare `-32022` in a match arm is a
/// magic number nobody can check against the schema.
pub(super) mod code {
    // `-32700` (parse error) and `-32600` (invalid request) ARE NOT HERE ANY MORE. They are the base
    // protocol's own codes, they are emitted by two planes, and both are now owned and emitted by
    // `crate::ingress::jsonrpc` — the one reader that decides what an invalid envelope is. Copying
    // them back here would recreate the second opinion this module was just moved off.

    /// JSON-RPC standard: the method is not implemented. MCP pairs it with `404`, not `200`.
    pub(super) const METHOD_NOT_FOUND: i64 = -32601;
    /// JSON-RPC standard: the params were structurally wrong. What a missing or incomplete
    /// `params._meta` is, and what this revision requires for it — `400`, never `200`.
    ///
    /// Deliberately the JSON-RPC standard code and not an MCP extension: `_meta` is a member of
    /// `params`, so its absence is the ordinary "invalid params" the base protocol already has a
    /// code for. Reaching for `-32020` here (as this module once did) borrowed the HEADER
    /// vocabulary for a body defect.
    pub(in crate::mcp) const INVALID_PARAMS: i64 = -32602;
    /// MCP `HeaderMismatchError`: an HTTP header disagreed with the body. Always `400`.
    pub(in crate::mcp) const HEADER_MISMATCH: i64 = -32020;
    /// MCP `UnsupportedProtocolVersionError`: carries `data.requested` and `data.supported`. Always
    /// `400`.
    pub(super) const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;
}

/// THIS PROTOCOL'S WORDS FOR A REFUSAL CORE DECIDED.
///
/// A unit type, because a refusal's wording is a fact about the MCP revision and not about this
/// deployment's configuration of it. The match is TOTAL over `CoreRefusal` and there is no `_`
/// arm: a refusal core grows later stops this file compiling until somebody has written the
/// sentence MCP owes for it, which is exactly the property that stops a new refusal being folded
/// into a neighbouring arm because the neighbour was close enough.
///
/// Every message below is BYTE-IDENTICAL to the one this plane sent before the sequence moved to
/// core. That is the whole contract of the move: a caller cannot tell it happened.
#[derive(Default)]
pub(crate) struct McpWords;

impl crate::ingress::protocol::Words for McpWords {
    fn refuse(&self, refusal: CoreRefusal<'_>) -> Response {
        match refusal {
            // Unreachable while the mount and the config are created in one act; still answered
            // rather than unwrapped, because this is a request path.
            CoreRefusal::PlaneAbsent => error_response(
                StatusCode::NOT_FOUND,
                None,
                code::METHOD_NOT_FOUND,
                "MCP is not enabled on this deployment.",
                None,
            ),
            // The RFC 9728 endpoint is NOT a JSON-RPC endpoint, so its refusal is not a JSON-RPC
            // envelope. Separate arm, separate sentence — see `CoreRefusal::MetadataUnavailable`.
            CoreRefusal::MetadataUnavailable => crate::ingress::protocol::json_refusal(
                StatusCode::NOT_FOUND,
                serde_json::json!({ "error": "not_found" }),
            ),
            // `403`, which `HTTP.ORIGIN-VALIDATION` names for exactly this: "If the `Origin`
            // header is present and invalid, servers MUST respond with HTTP 403 Forbidden."
            CoreRefusal::ForbiddenOrigin => crate::ingress::protocol::json_refusal(
                StatusCode::FORBIDDEN,
                serde_json::json!({
                    "error": "invalid_origin",
                    "error_description":
                        "This Origin is not allowed. Browser origins must be listed in mcp.allowed_origins.",
                }),
            ),
            // Both of these are the BASE PROTOCOL's own codes, so both are rendered by the base
            // protocol's own reader rather than restated here — that is the arrangement `code`
            // above records, and it is why `-32700` and `-32600` are not in it.
            CoreRefusal::NotJson => crate::ingress::jsonrpc::parse_error(),
            CoreRefusal::InvalidEnvelope(invalid) => crate::ingress::jsonrpc::refused(invalid),
            // `404` + `-32601`: what this revision requires of a server that does not implement a
            // method, and the answer that stays correct for every method still unimplemented.
            // A caller that may not see a tool and a caller naming one that does not exist get the
            // SAME answer, so the catalogue does not leak what it hides. The `reason` in `data` is
            // for the OPERATOR, who is entitled to the distinction, and the audit row the call
            // site writes carries it too.
            CoreRefusal::Admission {
                id,
                status,
                message,
                reason,
            } => error_response(
                status,
                Some(id),
                super::method::CODE_REFUSED,
                &message,
                reason.map(|r| serde_json::json!({ "reason": r })),
            ),
            CoreRefusal::MethodNotFound { id, method } => error_response(
                StatusCode::NOT_FOUND,
                Some(id),
                code::METHOD_NOT_FOUND,
                &format!("Method `{method}` is not implemented by this server."),
                None,
            ),
        }
    }
}

/// THE RFC 9728 FACTS THIS PLANE PUBLISHES. The document itself — its member order, its two
/// headers and its `bearer_methods_supported` rule — is `crate::ingress::protocol`'s, once. This
/// states only what differs between deployments.
///
/// `resource` is the audience a client must ask its authorization server to mint for, and it is
/// compared byte-for-byte against the `aud` of every token presented here. Both sides read it from
/// the same validated config object, so there is no second spelling of it anywhere.
impl crate::ingress::protocol::ResourceMetadata for McpWords {
    fn document(app: &crate::state::App) -> Option<crate::ingress::protocol::Metadata<'_>> {
        let resource = app.mcp.as_ref()?;
        Some(crate::ingress::protocol::Metadata {
            resource: std::borrow::Cow::Borrowed(resource.canonical_uri()),
            authorization_servers: resource.authorization_servers(),
            scopes_supported: resource.scopes_supported(),
        })
    }
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
    // `Option` survives only so a future refactor that mounts the route without the config produces
    // a clean refusal instead of a panic on a request path; `serve` answers it as `PlaneAbsent`.
    let resource = app.mcp.clone();
    // Borrowed rather than moved into the closure so the `Origin` read below and the mirrored
    // header reads inside it are two immutable borrows of one map rather than a clone of it.
    let headers = &headers;
    // STEPS 1, 2, 4, 5, 6, 7, 8 AND 13 ARE CORE'S, and this plane no longer states any of them.
    // What follows the call is steps 9 to 12: `params._meta`, the mirrored routing headers, the
    // method vocabulary and the verb dispatch — the four the measurement in
    // `crate::ingress::protocol` found are genuinely this protocol's.
    crate::ingress::protocol::serve(
        &McpWords,
        crate::ingress::protocol::Request {
            present: resource.is_some(),
            origin: header_str(headers, "origin"),
            allowed_origins: resource.as_ref().map_or(&[][..], |r| r.allowed_origins()),
            // This revision's request-line rules are all COMPARISONS AGAINST THE BODY (the
            // mirrored headers), so there is nothing this plane can judge before the parse. A2A's
            // media type and `A2A-Version` gates are the other answer to the same question.
            wire_refusal: None,
            body: &body,
        },
        // THE NOTIFICATION OBSERVER. `notifications/roots/list_changed` is the one inbound
        // notification this plane acts on: the caller has announced that its filesystem roots are
        // no longer what they were, so every outstanding roots-bearing `requestState` sealed for
        // this principal stops verifying (see `crate::mcp::roots`). The principal is the SAME value
        // `method::caller_ask_decision` binds state to — the authenticated key id, or the one
        // honest constant on an ungoverned deployment — because an epoch compared under a different
        // name than it was sealed under is an epoch that never matches or always does.
        {
            let epochs = app.mcp_roots_epochs.clone();
            let notify_principal = gov
                .key
                .as_ref()
                .map_or_else(|| "<ungoverned>".to_string(), |k| k.id.clone());
            move |method: &str, _value: &serde_json::Value| {
                if method == crate::mcp::roots::METHOD_NOTIFY_ROOTS_LIST_CHANGED {
                    epochs.note_change(&notify_principal);
                }
            }
        },
        |value, id, method| async move {
            rpc_dispatch(&app, &handle, &gov, &principal, headers, value, id, method).await
        },
    )
    .await
}

/// STEPS 9 TO 12 — everything after the envelope, and everything this protocol genuinely owns.
///
/// `None` means step 13: the method vocabulary does not carry this method, which is
/// `crate::ingress::protocol`'s to answer with `404` + `-32601`. That was always the correct answer
/// for an unimplemented method and did not have to change when the table gained entries.
#[allow(clippy::too_many_arguments)]
async fn rpc_dispatch(
    app: &Arc<crate::state::App>,
    handle: &std::sync::Arc<crate::state::AppHandle>,
    gov: &crate::governance::GovCtx,
    principal: &crate::auth::AuthPrincipal,
    headers: &HeaderMap,
    value: serde_json::Value,
    id: serde_json::Value,
    method_name: String,
) -> Option<Response> {
    // From here `id` is a string or a number. It is carried as `Option` only because the method
    // table's constructors take one; it is never `None` on this path, and never `Null` at all.
    let id = Some(id);
    let method = method_name.as_str();
    // The envelope's members are read off the `Value` directly from here. There is no `as_object()`
    // rebinding: the shared reader has already refused everything that is not a message object, so
    // a second check would be a second opinion on a question that is already settled.

    // (9) `params._meta` AND ITS REQUIRED MEMBERS. A body defect, answered in the body's own
    // vocabulary: `-32602`, `400`. See the module header for why this precedes the header checks.
    //
    // `params._meta`, per the schema. See META_PROTOCOL_VERSION for why this is not the top level.
    let Some(meta) = value.get("params").and_then(|p| p.get("_meta")) else {
        return Some(invalid_params(
            id,
            "`params._meta` is required on every request. This revision has no handshake, so each \
             request states its own protocol version and client capabilities there.",
        ));
    };
    let body_version = meta
        .get(META_PROTOCOL_VERSION)
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty());
    let Some(body_version) = body_version else {
        return Some(invalid_params(
            id,
            "`params._meta` must carry `io.modelcontextprotocol/protocolVersion`; this revision \
             negotiates per request, so the version cannot be inferred.",
        ));
    };
    // Bound here rather than at the point of use so the one place capabilities enter the server is
    // visible in the envelope check, next to the version they are negotiated alongside. Its
    // ABSENCE is a refusal — see META_CLIENT_CAPABILITIES.
    //
    // THE VALUE IS NOW CARRIED, not just its presence. It used to be checked and discarded, which
    // was enough while nothing downstream had a decision to make with it. `mrtr.mdx:246` gives it
    // one: "Servers MUST NOT send an `inputRequests` that the client has not declared support for in
    // its capabilities." A server that refused the field's absence and then ignored its contents
    // would be insisting the client answer a question it never read.
    let Some(capabilities) = meta.get(META_CLIENT_CAPABILITIES) else {
        return Some(invalid_params(
            id,
            "`params._meta` must carry `io.modelcontextprotocol/clientCapabilities`. With no \
             handshake there is no earlier message it could have been declared in, and this server \
             will not decide on a client's behalf what that client can do; send `{}` to declare \
             none.",
        ));
    };
    let capabilities = capabilities.clone();

    // (10) MIRRORED HEADERS. All four failures below are one class — an intermediary and the executor
    // disagreeing about what this request is — so they share one code and one status.
    //
    // Header NAMES are case-insensitive (axum lower-cases them for us); header VALUES, including
    // method names, are case-sensitive. Comparing values case-insensitively here would let
    // `Mcp-Method: TOOLS/CALL` mirror `tools/call`, which is precisely a disagreement dressed as a
    // match.
    let Some(header_version) = header_str(headers, H_PROTOCOL_VERSION) else {
        return Some(header_mismatch(
            id,
            "Every POST to the MCP endpoint must carry an `MCP-Protocol-Version` header.",
        ));
    };
    if header_version != body_version {
        return Some(header_mismatch(
            id,
            "The `MCP-Protocol-Version` header does not match the body's \
             `_meta.io.modelcontextprotocol/protocolVersion`.",
        ));
    }
    let Some(header_method) = header_str(headers, H_MCP_METHOD) else {
        return Some(header_mismatch(
            id,
            "The `Mcp-Method` header is required on every request.",
        ));
    };
    if decode_sentinel(header_method).as_deref() != Some(method) {
        return Some(header_mismatch(
            id,
            "The `Mcp-Method` header does not match the body's `method`.",
        ));
    }
    // `Mcp-Name` mirrors `params.name` (`tools/call`, `prompts/get`) or `params.uri`
    // (`resources/read`). It is REQUIRED on exactly those three and meaningless elsewhere.
    if let Some(source) = name_source_of(method) {
        let body_name = value
            .get("params")
            .and_then(|p| p.get(source))
            .and_then(|v| v.as_str());
        let Some(header_name) = header_str(headers, H_MCP_NAME) else {
            return Some(header_mismatch(
                id,
                "The `Mcp-Name` header is required on tools/call, resources/read and prompts/get.",
            ));
        };
        // The sentinel is decoded BEFORE comparison, which is its own MUST. A server that compared
        // the encoded form would reject every client that legitimately encoded a name containing a
        // character no header value may carry — and, worse, a server that decoded only sometimes
        // would give two different answers to one request depending on the name.
        let Some(decoded) = decode_sentinel(header_name) else {
            return Some(header_mismatch(
                id,
                "The `Mcp-Name` header carries a `=?base64?…?=` sentinel that is not valid Base64.",
            ));
        };
        if body_name != Some(decoded.as_str()) {
            return Some(header_mismatch(
                id,
                "The `Mcp-Name` header does not match the body's target name.",
            ));
        }
    }

    // (11) VERSION SUPPORT. Only now, with a well-formed request in hand: `data.supported` is an
    // invitation to retry, and inviting a malformed request to retry teaches a client the wrong
    // lesson about why it failed.
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&body_version) {
        return Some(error_response(
            StatusCode::BAD_REQUEST,
            id,
            code::UNSUPPORTED_PROTOCOL_VERSION,
            "This server does not implement the requested MCP protocol version.",
            Some(serde_json::json!({
                "requested": body_version,
                "supported": SUPPORTED_PROTOCOL_VERSIONS,
            })),
        ));
    }

    // (12) DISPATCH. The method table owns everything from here: the CATALOGUE reads and the
    // DISPATCH path, both computed under the caller's grant. A method the table does not carry falls
    // through to `404` + `-32601`, which was always the correct answer for an unimplemented method
    // and did not have to change when the table gained entries.
    let ctx = crate::mcp::method::Ctx {
        app,
        handle,
        gov,
        actor: principal.actor_id(),
        capabilities: &capabilities,
        headers,
    };
    let params = value.get("params");
    // The slot the outbound transport appends upstream progress to, scoped to exactly this request.
    // Created unconditionally and usually left empty — the cost is one Arc per request, against
    // threading an optional channel through four layers that each model a single answer.
    // The caller's own token, lifted once here so the outbound builder can decide whether to ask the
    // upstream for progress at all, and so the frames can be mapped back to it on the way out.
    let progress_slot = std::sync::Arc::new(std::sync::Mutex::new(super::ProgressChannel {
        caller_token: meta.get("progressToken").cloned().filter(|v| !v.is_null()),
        frames: Vec::new(),
    }));
    let response = match super::UPSTREAM_PROGRESS
        .scope(
            progress_slot.clone(),
            crate::mcp::method::dispatch(&ctx, method, params, id.clone()),
        )
        .await
    {
        Some(response) => response,
        None => error_response(
            StatusCode::NOT_FOUND,
            id,
            code::METHOD_NOT_FOUND,
            &format!("Method `{method}` is not implemented by this server."),
            None,
        ),
    };

    // THE RESPONSE FRAMING, and the log records that ride it.
    //
    // Last, and it has to be last: what is framed is the ANSWER, so the answer has to exist. This is
    // also the only ordering under which a `notifications/message` record can describe the outcome
    // rather than merely the intent — a record emitted before dispatch could say what busbar was
    // asked to do and never what it did.
    //
    // A client that did not ask for a stream is unaffected: `prefers_event_stream` is false for
    // every `Accept` that puts `application/json` first, which is every MCP client that has not
    // deliberately asked otherwise, so this is a new answer to a new question rather than a change
    // to the old one.
    // A CALLER THAT SUPPLIED A `progressToken` HAS ASKED FOR PROGRESS, and a stream is the only
    // shape progress can arrive in — so the token is itself a request for one, independent of how
    // the `Accept` list happened to be ordered.
    //
    // This does NOT loosen the preference rule for anything else. Every MCP client sends both media
    // types, so answering SSE on mere membership would return a stream to every client on earth;
    // `prefers_event_stream` still decides that, unchanged. What is added is one narrow, explicit
    // ask: a client that named a token cannot be answered without a stream, and silently dropping
    // the progress it asked for would be the wrong half of the trade.
    //
    // A RESPONSE THAT IS ALREADY A STREAM IS RETURNED UNTOUCHED, and that check comes first. This
    // step re-frames ONE buffered document as a sequence of events, so it has to read the whole body
    // to do it; a body that never ends — `subscriptions/listen`'s, which is open for as long as the
    // subscription is — would be buffered until the deadline and delivered as one lump at the end,
    // which is the exact opposite of what a subscription is. The content type is the discriminator
    // rather than the method name because it is a property of the ANSWER: any future method whose
    // answer is a live stream gets this right without editing a list.
    if response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"))
    {
        return Some(response);
    }
    let asked_for_progress = meta.get("progressToken").is_some_and(|v| !v.is_null());
    if !sse::prefers_event_stream(headers) && !asked_for_progress {
        return Some(response);
    }
    let level = sse::requested_level(Some(meta));
    let logs: Vec<sse::LogRecord> = request_log(method, &value, &response)
        .into_iter()
        .filter(|r| sse::level_allows(level, r.level))
        .collect();
    // The upstream's progress, if this request made an upstream call that produced any. Drained
    // rather than read: the slot belongs to this request and nothing after this point may re-emit.
    // MAPPED BACK to the caller's own token. The frames still carry busbar's minted one, and a
    // client correlates progress to its request by that field — so relaying the upstream's spelling
    // would be uncorrelatable, and relaying busbar's would leak an internal identifier.
    let progress: Vec<serde_json::Value> = {
        let mut ch = progress_slot
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default();
        if let Some(token) = ch.caller_token.clone() {
            for f in &mut ch.frames {
                if let Some(p) = f.get_mut("params").and_then(|p| p.as_object_mut()) {
                    p.insert("progressToken".to_string(), token.clone());
                }
            }
        }
        ch.frames
    };
    Some(sse::as_event_stream(response, &logs, &progress).await)
}

/// The `notifications/message` records busbar produces about ITS OWN handling of one request.
///
/// Two records, and they are two rather than one on purpose. The `debug` one states what was
/// dispatched; the second states how it ended. A client that asks for `info` (the default) sees only
/// the outcome, which is what a log is for; a client that asks for `debug` sees both, which is what
/// makes the level filter something a caller can observe working rather than something it has to
/// take on trust.
///
/// The records describe BUSBAR, never an upstream. An upstream's own log records are not relayed:
/// they would arrive at busbar's caller under busbar's name, which is the same laundering an
/// upstream's `InputRequiredResult` is refused for. `logger` is prefixed `busbar.` so that stays
/// visible in a client's log even when nobody is thinking about it.
fn request_log(
    method: &str,
    envelope: &serde_json::Value,
    response: &Response,
) -> Vec<crate::mcp::sse::LogRecord> {
    let target = name_source_of(method)
        .and_then(|source| envelope.get("params").and_then(|p| p.get(source)).cloned());
    let status = response.status().as_u16();
    // The STATUS, not the body: the body has already been consumed into the response and re-reading
    // it here would mean buffering the answer twice. The status/code pair is one contract
    // (`error_response` builds both together), so the status is a faithful statement of the outcome.
    let ok = response.status() == StatusCode::OK;
    vec![
        crate::mcp::sse::LogRecord {
            level: "debug",
            logger: "busbar.mcp.dispatch",
            data: serde_json::json!({
                "message": "dispatching MCP method",
                "method": method,
                "target": target,
            }),
        },
        crate::mcp::sse::LogRecord {
            level: if ok { "info" } else { "warning" },
            logger: "busbar.mcp.dispatch",
            data: serde_json::json!({
                "message": if ok { "MCP method completed" } else { "MCP method refused" },
                "method": method,
                "httpStatus": status,
            }),
        },
    ]
}

/// Which `params` member `Mcp-Name` mirrors for `method`, or `None` when the header is not required.
///
/// The methods are enumerated rather than pattern-matched on a prefix, and the tasks namespace is
/// why that matters rather than being fastidious: `tasks/get` carries the header and `tasks/result`
/// — a method this revision REMOVED — does not, so a `tasks/*` prefix rule would answer `-32020`
/// (your headers are wrong) to a request whose only defect is that it names a method that no longer
/// exists, which must be `-32601`. Any rule shorter than the list gets one of them wrong.
///
/// SEP-2663 §"Streamable HTTP: Routing Headers" extends SEP-2243's requirement to the three tasks
/// methods, mirroring `params.taskId` — so an intermediary can route a poll to the node holding the
/// task without parsing the body, which is the whole purpose of the header.
///
/// READ FROM BOTH DIRECTIONS, and that is why it is `pub(crate)`. `crate::mcp::client::verb`'s
/// builder asks this same function which member to mirror into the `Mcp-Name` it SENDS. It carried
/// its own copy of the rule until 2026-08-13 and the two DISAGREED: this one names the three tasks
/// methods (SEP-2663 §"Streamable HTTP: Routing Headers") and that one did not, so a `tasks/get`
/// issued over streamable HTTP went out with no `Mcp-Name` — which busbar's own front door answers
/// `-32020` to. The divergence was invisible on stdio, which has no headers, and would have
/// surfaced as an upstream refusing a verb for a reason busbar could not see.
pub(crate) fn name_source_of(method: &str) -> Option<&'static str> {
    match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        "tasks/get" | "tasks/update" | "tasks/cancel" => Some("taskId"),
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
///
/// Exposed to the method table as [`decode_param_sentinel`] under its SEP-2243 name, because the
/// `Mcp-Param-*` custom headers use the identical encoding and a second decoder would be a second
/// place for "what counts as a sentinel" to be decided differently.
pub(super) fn decode_param_sentinel(value: &str) -> Option<String> {
    decode_sentinel(value)
}

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

/// The `InvalidParams` shorthand for a `params._meta` defect: always `400`, always `-32602`.
fn invalid_params(id: Option<serde_json::Value>, description: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        id,
        code::INVALID_PARAMS,
        description,
        None,
    )
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
    // THE BODY IS BUILT BY THE SHARED READER, not here. Both JSON-RPC planes emit error envelopes
    // and the `id`/`error` pairing is the contract; one builder is what stops two planes disagreeing
    // about it, which is the same lesson this module's `code` re-export records.
    //
    // `None` BECOMES `null`, and that is a correction rather than a translation. This function used
    // to OMIT the member for a request with no readable id, on the reasoning that inventing `null`
    // would claim a correlation that does not exist. JSON-RPC 2.0 section 5 says the opposite twice: the
    // member is "REQUIRED" on a Response, and "if there was an error in detecting the id in the
    // Request object (e.g. Parse error/Invalid Request), it MUST be Null" — `null` IS the spelling
    // for "no correlation", not a claim of one. The omission also made the envelope unrecognisable
    // to a conformant peer: the in-house battery's own `isResponse()` predicate is `'id' in msg`, so
    // a client would have classified these refusals as neither response nor notification.
    //
    // The case that motivated the omission — a NOTIFICATION — can no longer reach here at all: section 4.1
    // forbids answering one, and the envelope reader now returns `202` with no body before dispatch.
    let id = id.unwrap_or(serde_json::Value::Null);
    (
        status,
        axum::Json(crate::ingress::jsonrpc::error_body(id, code, message, data)),
    )
        .into_response()
}

#[cfg(test)]
#[path = "tests/ingress_tests.rs"]
mod ingress_tests;

#[cfg(test)]
#[path = "tests/request_meta_tests.rs"]
mod request_meta_tests;

// THE `id` MEMBER, all three cases. Mounted here rather than folded into `ingress_tests` because
// the claim spans BOTH planes — the sibling file is `a2a/tests/envelope_id_tests.rs`, asserting the
// same three properties against the same shared reader, and two files with one name is what makes
// "does this hold on the other plane too?" a question with an obvious answer.
#[cfg(test)]
#[path = "tests/envelope_id_tests.rs"]
mod envelope_id_tests;

// The RESPONSE FRAMING battery. Mounted from the INGRESS rather than from [`super::sse`] on purpose:
// every test in it drives a real socket and asserts on what a CLIENT received, which is a statement
// about this handler's last step, not about the framing helper in isolation.
#[cfg(test)]
#[path = "tests/sse_tests.rs"]
mod sse_tests;

// The CONTENT battery — binary resources, resource templates, typed prompt content and the
// missing-client-capability refusal. Mounted here for the same reason `sse_tests` is: every case in
// it drives a real socket and judges what a CLIENT received.
#[cfg(test)]
#[path = "tests/content_tests.rs"]
mod content_tests;

// A1.3 — the resource routing key. Mounted here because its headline case drives a real socket for
// the same reason the two above do: the claim is about what a CLIENT can address, and the four
// official scenarios that were failing sent exactly that request.
#[cfg(test)]
#[path = "tests/resource_uri_tests.rs"]
mod resource_uri_tests;
