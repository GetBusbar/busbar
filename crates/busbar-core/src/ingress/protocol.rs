// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE JSON-RPC INGRESS. **Core owns the sequence; a protocol supplies its method vocabulary, its
//! verb dispatch and its refusal wording.**
//!
//! ## What was measured before this existed
//!
//! `mcp/ingress.rs` and `a2a/ingress.rs` each mounted their own JSON-RPC entry point. Tabulated
//! step by step, the two handlers ran THIRTEEN steps between them and **nine of the thirteen were
//! core's**:
//!
//! | # | step | MCP | A2A | whose |
//! |---|---|---|---|---|
//! | 1 | is this plane configured at all? → 404 | yes | yes | **CORE** |
//! | 2 | `Origin` / DNS-rebinding → 403 | yes | **absent** | **CORE** |
//! | 3 | the plane's own request-line rules (media type, protocol version) | — | `Wire::refuse` | protocol |
//! | 4 | body parses as JSON → `-32700` | yes | yes | **CORE** |
//! | 5 | `jsonrpc` / `method` / `id` | [`super::jsonrpc::read`] | [`super::jsonrpc::read`] | **CORE** (already one) |
//! | 6 | a NOTIFICATION is not answered → `202` | [`super::jsonrpc::accepted`] | [`super::jsonrpc::accepted`] | **CORE** (already one) |
//! | 7 | which `id` a refusal echoes | [`super::jsonrpc::Invalid`] | [`super::jsonrpc::Invalid`] | **CORE** (already one) |
//! | 8 | an invalid envelope's refusal | [`super::jsonrpc::refused`] | `rpcerror::respond` | **CORE** decides, protocol words it |
//! | 9 | `params._meta` and its required members | yes | — | protocol |
//! | 10 | the mirrored routing headers | yes | — | protocol |
//! | 11 | **the method vocabulary** | the method table | `local` + relay | **PROTOCOL** |
//! | 12 | **the verb dispatch** | `method::dispatch` | the relay hop | **PROTOCOL** |
//! | 13 | a method the vocabulary does not carry → 404 | yes | (relays) | **CORE** decides, protocol words it |
//!
//! Five of the nine (5, 6, 7, and the two halves of 4) were ALREADY unified, by
//! [`super::jsonrpc`]. [`serve`] takes the other four, and what is left over — 3, 9, 10, 11, 12 —
//! is precisely `Protocol::route` and `Decoded` in `design/protocol-plugin-abi.md`. **The
//! measurement is what says the ABI's method set is right, and this module is what proves it.**
//!
//! ## A caller keeps its refusal VOCABULARY, not its DECISION
//!
//! That is [`crate::net_guard`]'s rule, and it is this module's rule too. [`CoreRefusal`] is the
//! CLOSED set of refusals core makes on this path. [`Words`] is the one thing a protocol has to
//! write to receive them, and it is a TOTAL match over that enum: a refusal core grows later
//! cannot be folded into a nearby arm, because the compiler makes every protocol give it a
//! sentence of its own. That is what keeps a wire shape the specification defines — A2A section
//! 5.4 binds a JSON-RPC code, an HTTP status and a ProtoJSON body to each of its errors; MCP binds
//! `-32020`/`-32022` to its own — while the DECISION about whether to refuse is made once.
//!
//! ## What a protocol still writes, and it is the honest list
//!
//! A [`Words`] impl (one total match), the facts of its RFC 9728 document, and its verb dispatch.
//! It writes NO ingress module, NO refusal shaper, NO 404 shaper, NO metadata handler and NO error
//! type. `a_third_plane_costs_a_method_vocabulary_and_nothing_else` declares an ingress for a
//! protocol busbar does not have, deliberately unlike both real ones, and drives all six.

// Shared plane infrastructure: this JSON-RPC ingress sequence serves the MCP and A2A planes and
// nothing else. With BOTH planes compiled out it has no mount, so its items read dead — scoped to
// exactly that config so a real single-plane build still lints every item its plane leaves unused
// (those carry their own per-plane attrs below).
#![cfg_attr(
    not(any(feature = "plane-mcp", feature = "plane-a2a")),
    allow(dead_code)
)]

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use super::jsonrpc::{self, Envelope, Invalid};

/// THE REFUSALS CORE DECIDES on a JSON-RPC ingress, and deliberately no others.
///
/// Every variant is a decision that is the SAME on every protocol — a body that is not JSON is not
/// JSON whoever asked, and an `Origin` a browser must not be allowed to drive from is not made
/// safe by the dialect on top of it. What differs per protocol is only how the answer is SPELLED,
/// which is what [`Words`] is for.
///
/// It is `#[non_exhaustive]` to nobody: it is crate-private, and the whole point is that adding a
/// variant BREAKS every implementor until each has written a sentence for it.
pub(crate) enum CoreRefusal<'a> {
    /// This deployment does not carry this plane at all. Unreachable while the mount and the
    /// config are created in one act, and still answered rather than unwrapped because it is on a
    /// request path.
    PlaneAbsent,
    /// The same fact, asked of the RFC 9728 metadata endpoint rather than of the RPC endpoint.
    ///
    /// A SEPARATE VARIANT, not a reuse of [`Self::PlaneAbsent`], because the two endpoints answer
    /// it differently and always have: the RPC endpoint owes a JSON-RPC envelope, and the metadata
    /// endpoint — which is not a JSON-RPC endpoint — does not. Folding them would have changed one
    /// plane's bytes to make an enum smaller.
    MetadataUnavailable,
    /// The request named an `Origin` that is neither loopback nor on the operator's allowlist.
    /// The DNS-rebinding defence; see [`origin_admitted`] for why loopback is unconditional.
    ForbiddenOrigin,
    /// The body is not JSON at all. JSON-RPC `-32700`.
    NotJson,
    /// The body is JSON and is not a JSON-RPC message. The `id` a refusal must echo is carried on
    /// the [`Invalid`] — decided once, by the one reader, per JSON-RPC 2.0 section 5.
    InvalidEnvelope(&'a Invalid),
    /// The request is well formed and this protocol's vocabulary does not carry `method`. The `id`
    /// is the caller's own, because by this point one was established.
    MethodNotFound { id: Value, method: &'a str },
    /// THIS PLANE'S ADMISSION OR CATALOGUE SAID NO — a caller with no grant, an unapproved server,
    /// a moved pin, a quarantined registration, a spent budget.
    ///
    /// It is a core refusal even though core did not make the JUDGEMENT, and that distinction is
    /// the whole reason it takes three fields instead of none. What core owns is the SHAPE: a
    /// refusal earns the status its own taxonomy chose, says the sentence its own `Display`
    /// writes, and names the reason its own `audit_reason` names. That triple was assembled
    /// identically on both planes and rendered in two shapers, which is what the ledger's `refuse`
    /// row recorded.
    ///
    /// `reason` is an `Option` because one plane names a machine-readable reason and the other
    /// does not: A2A section 5.4's `ErrorInfo.reason` is a FIXED vocabulary the specification owns,
    /// and a busbar reason string is not in it, so this plane publishes none rather than putting a
    /// value in that member no conformant client can read. `None` is that statement, made once,
    /// where a plane that silently ignored the field would look like one that forgot it.
    Admission {
        id: Value,
        status: StatusCode,
        message: String,
        // MCP-only field: the MCP shaper reads this machine-readable reason; the A2A shaper omits it
        // (A2A section 5.4 owns a fixed `reason` vocabulary busbar strings are not in), so with
        // `plane-mcp` off (and A2A on) it is constructed but never read.
        #[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
        reason: Option<&'a str>,
    },
}

/// WHAT A PROTOCOL SUPPLIES TO RECEIVE CORE'S REFUSALS: one total match, and nothing else.
///
/// Implemented on a UNIT type per protocol, never on a resource: a refusal's wording is a fact
/// about the dialect, not about this deployment's configuration of it, and a `Words` that could
/// read the config would be a place for the wording to vary between two requests.
pub trait Words {
    /// This protocol's own sentence for a refusal core decided.
    ///
    /// There is no default and there is no `_` arm anybody can write that the compiler will not
    /// eventually make wrong: the argument is a closed enum, so a new refusal is a compile error
    /// in every protocol until it has been given words.
    fn refuse(&self, refusal: CoreRefusal<'_>) -> Response;
}

/// THE FACTS OF ONE REQUEST that core's sequence reads, gathered by the protocol's handler because
/// only the handler has the extractors.
///
/// Everything here is a FACT, never a decision: whether the plane is configured, what the caller's
/// `Origin` said, what the operator allowed, what this protocol's own request-line rules already
/// earned. `serve` makes every decision from them.
pub(crate) struct Request<'a> {
    /// Is this plane configured on this deployment? `false` earns [`CoreRefusal::PlaneAbsent`].
    pub(crate) present: bool,
    /// The caller's `Origin` header, when it sent one. A request with NO `Origin` is not a browser
    /// request and is unaffected — refusing those would refuse every agent, which is every real
    /// client.
    pub(crate) origin: Option<&'a str>,
    /// Browser origins this deployment admits BEYOND loopback: the operator's allowlist.
    pub(crate) allowed_origins: &'a [String],
    /// The refusal this protocol's own request-line rules already earned, or `None`. Step 3 — the
    /// one pre-parse step that is genuinely the protocol's, because what media types and what
    /// protocol versions an endpoint reads is a statement the specification makes about that
    /// endpoint and about no other.
    pub(crate) wire_refusal: Option<Response>,
    /// The request body, unparsed.
    pub(crate) body: &'a [u8],
}

/// WHETHER `origin` MAY DRIVE THIS DEPLOYMENT.
///
/// The DNS-rebinding attack is a page served from an ATTACKER's origin — `http://evil.example` —
/// whose hostname the attacker has made resolve to busbar's address, driving the plane with
/// whatever ambient credential the browser attaches. That page's `Origin` header is
/// `http://evil.example`, never `http://localhost`: a browser sends a loopback `Origin` only for a
/// document that was itself served from loopback, which is a document already inside the trust
/// boundary. So loopback origins carry no rebinding risk, and refusing them would refuse the local
/// inspector and the local agent — the two clients an operator tries first — for no security gain.
///
/// The port is deliberately not constrained: any local port is the same trust boundary.
pub(crate) fn origin_admitted(origin: &str, allowed: &[String]) -> bool {
    is_loopback_origin(origin) || allowed.iter().any(|a| a == origin)
}

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

/// THE SEQUENCE. Steps 1, 2, 4, 5, 6, 7, 8 and 13 of the table in the module header, in that order,
/// with step 3 taken from `req.wire_refusal` and steps 9–12 taken by `dispatch`.
///
/// `dispatch` receives the three things the envelope reader ESTABLISHED — the parsed body, the
/// caller-correlatable `id`, and the method name — by VALUE, so nothing on this path is cloned.
/// Returning `None` from it means "my vocabulary does not carry this method", which is step 13 and
/// is core's to answer; returning `Some` means the protocol answered, and core does not touch what
/// it said.
///
/// ## Why the order is this order
///
/// `Origin` first, because it is about who is allowed to speak at all and it costs one header
/// lookup. The protocol's request-line rules next, and BEFORE the parse, because the order IS the
/// behaviour: a request with a media type an endpoint does not read usually also carries a body
/// that is not JSON, and a gate placed after the parse answers "your body is not JSON" forever and
/// never tells the caller the thing to fix is a header. Then the parse, then the envelope, then
/// the protocol.
/// `notify` is the plane's NOTIFICATION OBSERVER, called with the method name and the whole parsed
/// body exactly when the envelope is a well-formed notification, before the unconditional `202`.
/// It observes and it cannot answer — the return type is `()` — because JSON-RPC 2.0 section 4.1's
/// MUST NOT reply has no exception for a notification a plane found interesting. A plane with
/// nothing to observe passes `|_, _| {}`, which is what A2A does and what MCP did until
/// `notifications/roots/list_changed` gave it something a received notification honestly moves
/// (see `crate::mcp::roots`).
pub(crate) async fn serve<W, F, Fut>(
    words: &W,
    req: Request<'_>,
    notify: impl FnOnce(&str, &Value),
    dispatch: F,
) -> Response
where
    W: Words,
    F: FnOnce(Value, Value, String) -> Fut,
    Fut: std::future::Future<Output = Option<Response>>,
{
    // (1) IS THERE A PLANE HERE.
    if !req.present {
        return words.refuse(CoreRefusal::PlaneAbsent);
    }

    // (2) ORIGIN — a MUST on MCP's transport and the DNS-rebinding defence on every JSON-RPC plane
    // busbar serves. It is here, once, rather than on the plane that happened to be reviewed for
    // it: A2A had NO Origin check at all until this module existed, which is precisely the failure
    // mode `structure-lint`'s plane-coherence ledger names — one concern implemented twice, one
    // copy hardened, the other not.
    if let Some(origin) = req.origin {
        if !origin_admitted(origin, req.allowed_origins) {
            return words.refuse(CoreRefusal::ForbiddenOrigin);
        }
    }

    // (3) THE PROTOCOL'S OWN REQUEST-LINE RULES, already decided by the handler.
    if let Some(refusal) = req.wire_refusal {
        return refusal;
    }

    // (4) PARSE.
    let Ok(value) = serde_json::from_slice::<Value>(req.body) else {
        return words.refuse(CoreRefusal::NotJson);
    };

    // (5)(6)(7) THE ENVELOPE, read by the ONE reader both JSON-RPC planes share. A notification is
    // answered `202` with no body and is never dispatched — JSON-RPC 2.0 section 4.1's MUST NOT
    // has no exception for a notification that is also wrong about something else.
    let (id, method) = match jsonrpc::read(&value) {
        Ok(Envelope::Request { id, method }) => (id, method),
        Ok(Envelope::Notification { method }) => {
            // The observer runs and then the answer is the unconditional `202` regardless of what
            // it saw: acting is permitted, answering is not.
            notify(&method, &value);
            return jsonrpc::accepted();
        }
        // (8) The DECISION is the reader's, so both planes make it the same way; the WORDS are the
        // protocol's, because a refusal rendered in another dialect's shape is a body its own
        // conformance suite rejects by schema.
        Err(invalid) => return words.refuse(CoreRefusal::InvalidEnvelope(&invalid)),
    };

    // (9)–(12) THE PROTOCOL'S. Its `params` rules, its routing headers, its method vocabulary and
    // its verb dispatch — the four steps the measurement found are genuinely protocol-owned.
    match dispatch(value, id.clone(), method.clone()).await {
        Some(response) => response,
        // (13) A method this protocol's vocabulary does not carry.
        None => words.refuse(CoreRefusal::MethodNotFound {
            id,
            method: &method,
        }),
    }
}

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
pub(crate) struct Metadata<'a> {
    /// The audience. RFC 9728 §2's one REQUIRED member.
    ///
    /// A `Cow` because the two planes hold it differently and neither should have to change how it
    /// stores its own config to be rendered: MCP's canonical URI is borrowed straight out of the
    /// live snapshot, and A2A's arrives on an owned `PlaneAdmission` built per call. Borrowing pays
    /// nothing on the hot deployment and the owned side pays one `String` on a document served with
    /// `max-age=3600`.
    pub(crate) resource: std::borrow::Cow<'a, str>,
    /// Which authorization servers may mint for this resource. Omitted when empty.
    pub(crate) authorization_servers: &'a [String],
    /// The scopes this resource understands. Omitted when empty.
    pub(crate) scopes_supported: &'a [String],
}

/// THE THREE FACTS a protocol supplies so that ONE handler can serve its RFC 9728 document.
///
/// This is the whole of what a protocol writes for step 2 of the discovery loop. It is a trait and
/// not a function pointer because [`metadata_handler`] is mounted as `metadata_handler::<W>` — a
/// concrete fn item, which is what axum needs, and which is what makes the SAME handler serve two
/// planes without either of them owning a `metadata` function.
pub trait ResourceMetadata: Words + Default {
    /// This deployment's document facts, or `None` when this deployment does not carry the plane —
    /// which is [`CoreRefusal::MetadataUnavailable`], answered in this protocol's own words.
    fn document(app: &crate::state::App) -> Option<Metadata<'_>>;
}

/// `GET /.well-known/oauth-protected-resource<mount-path>`, for every protocol, once.
///
/// The path is registered CONCRETELY at mount time from the operator's canonical URI, never matched
/// as a prefix: a prefix exemption under `/.well-known/` would hand a free pass to every path
/// beneath it, and the RFC's path-insertion rule makes the exact string knowable at boot anyway.
pub async fn metadata_handler<W: ResourceMetadata>(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
) -> Response {
    match W::document(&app) {
        Some(doc) => metadata(&doc),
        None => W::default().refuse(CoreRefusal::MetadataUnavailable),
    }
}

/// Render one [`Metadata`].
///
/// `bearer_methods_supported` is `["header"]` and is not a parameter: busbar accepts a bearer token
/// in the `Authorization` header and nowhere else, on every plane. RFC 6750 also defines a
/// form-encoded body parameter and a URI query parameter, and both are mistakes for this surface —
/// a token in a query string lands in access logs, proxy logs and `Referer` headers. Stating
/// `["header"]` tells a conforming client not to try the others rather than leaving it to discover
/// by rejection, and making it a parameter would invite a protocol to say otherwise.
pub(crate) fn metadata(m: &Metadata<'_>) -> Response {
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

/// A JSON body with a status: the shape three of the refusals above are rendered in on planes whose
/// answer to them is not a JSON-RPC envelope. Kept here so a protocol's [`Words`] impl is a table
/// of SENTENCES rather than a table of `into_response` chains.
// MCP-only helper: only the MCP plane's `Words` impl renders a refusal as a bare JSON body here;
// the A2A plane answers with an envelope, so with `plane-mcp` off (and A2A on) it has no caller.
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
pub(crate) fn json_refusal(status: StatusCode, body: Value) -> Response {
    (status, axum::Json(body)).into_response()
}

#[cfg(test)]
#[path = "tests/protocol_tests.rs"]
mod protocol_tests;
