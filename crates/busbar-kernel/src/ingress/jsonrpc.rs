// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JSON-RPC 2.0 ENVELOPE READER — one reader, for every plane that speaks JSON-RPC.
//!
//! # Why this file exists, stated as the defect it closes
//!
//! Two planes carry JSON-RPC on the wire — MCP (server role) and A2A (receiving role) — and until
//! this module they read the envelope in two separate places, with two different answers:
//!
//! | | `mcp/ingress.rs` (before) | `a2a/ingress.rs` (before) |
//! |---|---|---|
//! | `jsonrpc` member checked | yes | **no, not at all** |
//! | `method` member checked | yes | no |
//! | `id` typed as | `Option<Value>` | `Value`, via `.unwrap_or(Value::Null)` |
//! | `"id": null` | accepted, served `200` + a `result` | accepted, served `200` + a `result` |
//! | no `id` member | served `200` + a `result` | served `200` + a `result` with `"id": null` |
//! | parse failure answered as | a JSON-RPC error | a bespoke `{"error":{"code":"invalid_request"}}` |
//!
//! One defect was REPORTED, on the MCP plane. Both planes had it, and the A2A plane had it worse:
//! `.unwrap_or(Value::Null)` destroyed the missing-versus-null distinction before anything could act
//! on it, so the two cases the specification treats most differently were literally the same value
//! by the time the handler saw them. That is the shape `structure-lint`'s plane-coherence check was
//! built to catch — one concern, implemented twice, fixed once.
//!
//! So the rule this module exists to make true is: **a plane supplies its wire transport, never its
//! own envelope semantics.** There is one `read`, one set of codes, one refusal envelope and one
//! notification acknowledgement, and a third JSON-RPC plane gets them for free.
//!
//! # What the specifications require, quoted, because the three cases differ
//!
//! **JSON-RPC 2.0 section 4 (Request object), `id`:** *"An identifier established by the Client that MUST
//! contain a String, Number, or NULL value if included. If it is not included it is assumed to be a
//! notification. The value SHOULD normally not be Null [1] …"* — and footnote **[1]**: *"The use of
//! Null as a value for the id member in a Request object is discouraged, because this specification
//! uses a value of Null for the id member in a Response object to indicate an unknown id (e.g.
//! Parse error/Invalid Request). Also, because JSON-RPC 1.0 uses an id value of Null for
//! Notifications this could cause confusion in handling."*
//!
//! **JSON-RPC 2.0 section 4.1 (Notification):** *"A Notification is a Request object without an `id`
//! member. … The Server MUST NOT reply to a Notification, including those that are within a batch
//! request."*
//!
//! **JSON-RPC 2.0 section 5 (Response object), `id`:** *"This member is REQUIRED. It MUST be the same as
//! the value of the id member in the Request Object. If there was an error in detecting the id in
//! the Request object (e.g. Parse error/Invalid Request), it MUST be Null."*
//!
//! **MCP, revision `2026-07-28`, `basic#requests`:** *"Requests MUST include a string or integer
//! ID."* and *"Unlike base JSON-RPC, the ID MUST NOT be `null`."* **`basic#notifications`:**
//! *"Notifications MUST NOT include an ID."* and *"The receiver MUST NOT send a response."*
//!
//! **A2A v0.3 section 3** binds the receiving plane to JSON-RPC 2.0 and adds no `id` clause of its own.
//!
//! # The one judgement call, and the argument for it
//!
//! Base JSON-RPC says `null` is *discouraged* (`SHOULD normally not be`); MCP says it is
//! *forbidden* (`MUST NOT`). This module REFUSES it on every plane, including the one whose spec
//! only discourages it, and that is a deliberate choice rather than an oversight:
//!
//! 1. section 5 spends the value `null` on a *different meaning* — "I could not tell which request this
//!    was". A SUCCESS response carrying `"id": null` is therefore byte-identical to the envelope
//!    reserved for an unattributable failure. A caller cannot correlate it, which is the entire
//!    purpose of the member. Footnote [1] says precisely this is why `null` is discouraged.
//! 2. `SHOULD NOT` binds the SENDER. Nothing obliges a server to accept a discouraged id, and
//!    `-32600 Invalid Request` is exactly the code for an envelope a server will not honour.
//! 3. The alternative is two readers again, differing on one member — and the whole cost of the
//!    defect above was paid for that difference existing.
//!
//! If a real A2A peer is ever found that sends `"id": null` and cannot be changed, the right answer
//! is a named, tracked variance here — not a second reader.
//!
//! # THE OTHER HALF: reading a RESPONSE, and why it is in this file
//!
//! [`read`] above reads a request busbar RECEIVES. [`read_response`] below reads a response busbar
//! GETS BACK from a party it called — the MCP client direction (`mcp/client/jsonrpc.rs`) and the
//! A2A delegating direction (`a2a/relay.rs`). Same envelope, same version member, same `id`
//! member, opposite direction of travel, and the identical failure mode when it is not read: three
//! separate implementations that agree on nothing.
//!
//! And it WAS three, all of them missing the same member. Before this:
//!
//! | | `mcp/client/jsonrpc.rs` | `a2a/relay.rs` (unary) | `a2a/relay.rs` (streamed) |
//! |---|---|---|---|
//! | `jsonrpc` member checked | yes | **no** | **no** |
//! | response `id` correlated | **no** | **no** | **no** |
//! | id the caller finally sees | n/a | busbar's own | **the backend's, verbatim** |
//!
//! An uncorrelated response is not a cosmetic gap. Section 5 exists so a client can tell WHICH
//! request an answer belongs to; a reader that never looks at `id` will accept a mismatched one, a
//! `null` one, or one with no `id` member at all as the answer to whatever it happened to be
//! waiting on. Under adversarial timing that is how caller A is served upstream B's reply.
//!
//! **The correlation is WITHIN ONE DISPATCH and introduces no state.** `sent_id` is passed in by
//! the code that built the outbound request, in the same function, and is gone when that function
//! returns. `mcp/client/jsonrpc.rs`'s header states the rule this respects — "there is no
//! `initialize` and there is no session … a counter that outlived a dispatch would be a session by
//! another name" — and a per-dispatch argument is the shape that honours it: nothing is remembered
//! between two calls, so there is nothing to invalidate.
//!
//! ## The direction-in-the-path question, answered rather than left to look like an oversight
//!
//! `ingress/` names the receiving direction and [`read_response`] serves the sending one, so the
//! path reads oddly. It is still one module, deliberately: the CONCERN is the JSON-RPC 2.0
//! envelope, not a direction, and the two halves share the version literal, the `id` legibility
//! rule and the argument for what `null` means. Splitting them across two directories to make two
//! path names read nicely would recreate, in the small, precisely the two-implementations defect
//! the top of this file is a record of. One envelope, one file; the module's own name (`jsonrpc`)
//! is what is true about it.

// Shared plane infrastructure: these JSON-RPC HTTP answers serve the MCP (server) and A2A
// (receiving) planes and nothing else. With BOTH planes compiled out they have no caller, so
// its items read dead — scoped to exactly that config so a real single-plane build still lints every
// item its plane leaves unused (those carry their own per-plane attrs below).
#![cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;

/// THE READER ITSELF — the codes, [`Envelope`], [`Invalid`], [`read`], [`Reply`], [`NotAnAnswer`],
/// [`read_response`] and [`error_body`] — is `busbar_contract::jsonrpc`: pure and stateless, so a
/// plane reads the one envelope through the contract rather than through the kernel (legacy fold
/// ruling F4). Re-exported here, so every `ingress::jsonrpc::…` path resolves the same items. What
/// stays is the host's half: the HTTP answers built from its verdicts.
pub use busbar_contract::jsonrpc::*;

/// The HTTP answer to an [`Invalid`] envelope: `400`, and the error envelope section 5 describes.
///
/// `400` rather than `200`-with-an-error-object: the request was malformed at the transport's own
/// level, and a `200` there tells every proxy, cache and dashboard between the peers that the call
/// succeeded.
// MCP-only: the MCP server answers a malformed envelope with this `400`; the A2A receiving role
// takes a different refusal path, so with `plane-mcp` off (and A2A on) it has no caller.
#[cfg_attr(not(feature = "dispatch"), allow(dead_code))]
pub fn refused(invalid: &Invalid) -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(error_body(
            invalid.id.clone(),
            invalid.code,
            invalid.message,
            None,
        )),
    )
        .into_response()
}

/// The HTTP answer to a NOTIFICATION: `202 Accepted`, **and no body at all**.
///
/// The empty body is the requirement — section 4.1's *"MUST NOT reply"* — and `202` is the status the MCP
/// Streamable HTTP binding names for it ("Notifications get `202 Accepted`"). A `204` would say the
/// same thing about the body and a wrong thing about the outcome: `202` means received and not yet
/// judged, which is exactly what a receiver can honestly claim about a message it may not answer.
pub fn accepted() -> Response {
    StatusCode::ACCEPTED.into_response()
}

/// The JSON-RPC answer to a refusal made BEFORE any envelope could be read — an oversized body the
/// transport capped, a path with no handler, a method the transport does not allow.
///
/// Three decisions, and each is the same one [`refused`] makes for a different reason:
///
/// * **`id` is Null.** Section 5: *"If there was an error in detecting the id in the Request object
///   … it MUST be Null."* No body was read, so no id was ever established. This is exactly the case
///   the clause describes, rather than a convenient default.
/// * **The code is `-32600`.** The message is one the server will not honour. `-32700` would claim
///   the JSON failed to parse, which is a different and untrue statement about a body that was
///   never parsed at all.
/// * **The STATUS is the caller's**, not `400`. The transport's own refusal (`413`, `404`, `405`)
///   is a fact about the HTTP hop that every proxy and dashboard between the peers reads, and
///   flattening it to `400` would discard it. Only the BODY is JSON-RPC's.
pub fn transport_refusal(status: StatusCode, message: &str) -> Response {
    (
        status,
        axum::Json(error_body(Value::Null, INVALID_REQUEST, message, None)),
    )
        .into_response()
}

/// A body that is not JSON at all: `-32700`, `id` Null, per section 5's *"e.g. Parse error"*.
// MCP-only: emitted only by the MCP server role (it reaches `PARSE_ERROR` above), so with
// `plane-mcp` off (and A2A on) it has no caller.
#[cfg_attr(not(feature = "dispatch"), allow(dead_code))]
pub fn parse_error() -> Response {
    refused(&Invalid {
        code: PARSE_ERROR,
        message: "Request body is not valid JSON.",
        id: Value::Null,
    })
}

#[cfg(test)]
#[path = "tests/jsonrpc_tests.rs"]
mod jsonrpc_tests;
