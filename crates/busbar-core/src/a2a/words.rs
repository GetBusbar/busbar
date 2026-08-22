// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THIS PLANE'S REFUSAL VOCABULARY, and the three facts of its RFC 9728 document.
//!
//! Everything in this file is an ANSWER TO A DECISION SOMETHING ELSE MADE. The decisions live in
//! `crate::ingress::protocol` — one sequence for every JSON-RPC plane busbar serves — and what
//! stays here is the WIRE: A2A section 5.4 binds a JSON-RPC code, an HTTP status and a ProtoJSON
//! body to each of this protocol's errors at once, so a refusal rendered in the sibling plane's
//! shape is a body the official TCK rejects by schema.
//!
//! That split — **a caller keeps its refusal VOCABULARY, not its DECISION** — is
//! `crate::net_guard`'s rule, stated for a second concern. It is why `mcp/envelope.rs` and this
//! file can say completely different things about the same refusal without either of them deciding
//! when it happens.

use axum::response::{IntoResponse, Response};

use super::inbound::InboundRefusal;
use crate::state::App;

/// THIS PROTOCOL'S WORDS FOR A REFUSAL CORE DECIDED.
///
/// A unit type, because a refusal's wording is a fact about A2A and not about this deployment's
/// configuration of it. The match is TOTAL over `CoreRefusal` and there is no `_` arm: a refusal
/// core grows later stops this file compiling until somebody has written the sentence A2A owes for
/// it. A2A section 5.4 binds a JSON-RPC code, an HTTP status and a ProtoJSON body to each of its
/// errors AT ONCE, so a refusal rendered in the sibling plane's shape is a body the official TCK
/// rejects by schema — which is exactly why the words stay here while the decision does not.
///
/// Every message below is BYTE-IDENTICAL to the one this plane sent before the sequence moved to
/// core, with ONE exception, and it is an ADDITION rather than a change: `ForbiddenOrigin` had no
/// wording on this plane at all, because this plane had no `Origin` check. See
/// `crate::ingress::protocol::origin_admitted`.
#[derive(Default)]
pub(crate) struct A2aWords;

impl crate::ingress::protocol::Words for A2aWords {
    fn refuse(&self, refusal: crate::ingress::protocol::CoreRefusal<'_>) -> Response {
        use crate::ingress::protocol::CoreRefusal;
        match refusal {
            // The mount and the config are created in one act, so this is unreachable; it is
            // answered rather than unwrapped because this is a request path.
            CoreRefusal::PlaneAbsent | CoreRefusal::MetadataUnavailable => {
                super::rpcerror::respond(
                    &serde_json::Value::Null,
                    super::rpcerror::A2aError::Internal,
                    "this deployment has no A2A plane",
                )
            }
            // NEW ON THIS PLANE. The sibling plane refused a non-loopback `Origin` and named
            // DNS-rebinding in its comment; this one had no check at all, which is the divergence
            // one concern implemented twice always produces. The status is `403` because that is
            // what the attack's own remedy calls for and what the sibling already answered; the
            // BODY is this plane's, because every other refusal it sends is.
            //
            // `UnsupportedOperation` is the nearest binding section 5.4 defines for "busbar will
            // not do this for you", which is the same choice `refuse` makes for an admission
            // refusal. An invented code in the A2A range would be indistinguishable, to a client,
            // from one the specification will define later.
            // THE STATUS IS `403` AND THE CODE IS THIS PLANE'S, which is the same split the hook
            // gate below already makes: `403` is what the rebinding defence calls for and what the
            // sibling plane answers, while `UnsupportedOperation.http_status()` is `400` because
            // section 5.4 binds that code to a client that asked for something undefined. This is
            // not that; the request is perfectly well formed and the ORIGIN is what is refused, so
            // the status is the refusal's and the body stays in A2A's vocabulary.
            CoreRefusal::ForbiddenOrigin => (
                axum::http::StatusCode::FORBIDDEN,
                axum::Json(super::rpcerror::body(
                    &serde_json::Value::Null,
                    super::rpcerror::A2aError::UnsupportedOperation,
                    "this Origin is not allowed: a browser origin may drive this plane only from \
                     loopback",
                )),
            )
                .into_response(),
            CoreRefusal::NotJson => super::rpcerror::respond(
                &serde_json::Value::Null,
                super::rpcerror::A2aError::Parse,
                "the request body is not JSON",
            ),
            CoreRefusal::InvalidEnvelope(invalid) => super::rpcerror::respond(
                &invalid.id,
                super::rpcerror::A2aError::InvalidRequest,
                invalid.message,
            ),
            // NO PRODUCTION CALL SITE CONSTRUCTS THIS ONE, and the sentence is still owed. busbar
            // is content-blind on this plane's receiving side: it admits, meters, records and then
            // relays the caller's envelope to the backend VERBATIM, so the backend is what says
            // "no such method". The arm exists because the enum is core's and total — which is the
            // point of the enum. If this plane ever answers a verb locally that it does not
            // recognise, the words are already here and are the specification's own code for it.
            // THE PLANE'S OWN ERROR ENVELOPE, and the HTTP status the refusal already chose. An
            // admission refusal has no A2A error type of its own, so it takes the nearest binding
            // (`UnsupportedOperationError`) with the real reason in the message — see `rpcerror`'s
            // note on why an invented code in the A2A range would be worse than a near one.
            //
            // `reason` is DELIBERATELY NOT PUBLISHED here: A2A section 5.4's `ErrorInfo.reason` is
            // a fixed vocabulary the specification owns, and putting a busbar reason string in it
            // would hand a conformant client a value no A2A client knows how to read.
            CoreRefusal::Admission {
                id,
                status,
                message,
                reason: _,
            } => (
                status,
                axum::Json(super::rpcerror::body(
                    &id,
                    super::rpcerror::A2aError::UnsupportedOperation,
                    message,
                )),
            )
                .into_response(),
            CoreRefusal::MethodNotFound { id, method } => super::rpcerror::respond(
                &id,
                super::rpcerror::A2aError::MethodNotFound,
                format!("this endpoint does not serve `{method}`"),
            ),
        }
    }
}

/// An admission refusal, rendered. The body names the reason token and never the backend:
/// `InboundRefusal`'s own `Display` is written to be safe to return, and `Dispatch::backend_url`
/// never leaves here.
///
/// THE TRIPLE IS ASSEMBLED BY CORE and worded by [`A2aWords`]. What this function is now is the
/// plane's REFUSAL TAXONOMY speaking: which status this refusal earns and which sentence it writes
/// are `InboundRefusal`'s own answers, and they are the only two facts that were ever this plane's.
///
/// `id` is `Null` because a refusal decided by `admit` has not read an envelope: `card` calls it
/// with no JSON-RPC message in hand at all, and JSON-RPC 2.0 section 5 spells "no correlation"
/// `null`.
pub(super) fn refuse_admission(refusal: &InboundRefusal) -> Response {
    use crate::ingress::protocol::Words as _;
    A2aWords.refuse(crate::ingress::protocol::CoreRefusal::Admission {
        id: serde_json::Value::Null,
        status: axum::http::StatusCode::from_u16(refusal.status())
            .unwrap_or(axum::http::StatusCode::FORBIDDEN),
        message: refusal.to_string(),
        // NONE, and the argument is on the variant: this plane's error body carries an
        // `ErrorInfo.reason` from A2A's own fixed vocabulary or it carries none.
        reason: None,
    })
}

/// THE RFC 9728 FACTS THIS PLANE PUBLISHES.
///
/// The document itself is not written here, and this is the row the plane-coherence ledger retired:
/// it had been written once per plane, and the ledger recorded (verified 2026-08-11) that the two
/// copies were the same document with the same audience rule. `crate::ingress::protocol` renders
/// it once and `metadata_handler::<A2aWords>` serves it, mounted `RouteAuth::None` for the reason
/// the sibling plane's is — every caller who needs this document is by definition one that does not
/// have a token yet, so requiring one would be a discovery loop with no entrance.
///
/// This plane declares NO `authorization_servers` and NO `scopes_supported`, and both members are
/// therefore omitted rather than emitted empty: RFC 9728 §2 makes both optional, and an empty array
/// asserts "there are none" where absence says "this resource does not state it". That is what lets
/// one renderer be byte-identical to both copies instead of a compromise between them.
///
/// `admission.audience` is the audience a client must have its authorization server mint for, and
/// it is compared byte-for-byte against the `aud` of every token presented under this mount. Both
/// sides read it from `A2aPlane::admission`, so there is no second spelling of it anywhere.
impl crate::ingress::protocol::ResourceMetadata for A2aWords {
    fn document(app: &App) -> Option<crate::ingress::protocol::Metadata<'_>> {
        let admission = crate::a2a::runtime(app).and_then(|p| p.admission())?;
        Some(crate::ingress::protocol::Metadata {
            resource: std::borrow::Cow::Owned(admission.audience),
            authorization_servers: &[],
            scopes_supported: &[],
        })
    }
}

/// THE SAME 404 THE SHARED SEQUENCE ANSWERS, at the four handlers on this plane that are not the
/// JSON-RPC endpoint and therefore do not run that sequence.
///
/// It is a call INTO the one shaper rather than a second shaper: `A2aWords` owns every sentence
/// this plane says to a refusal core decided, so "this deployment has no A2A plane" is written in
/// exactly one place and cannot come to mean two things.
pub(super) fn plane_absent() -> Response {
    use crate::ingress::protocol::Words as _;
    A2aWords.refuse(crate::ingress::protocol::CoreRefusal::PlaneAbsent)
}
