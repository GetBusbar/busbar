// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SSE RESPONSE STREAM ON THE POST, and the `notifications/message` log records that ride it.
//!
//! ## What revision `2026-07-28` removed, and what it did not
//!
//! The revision deleted the standalone GET stream, `Mcp-Session-Id`, and `Last-Event-ID`
//! resumability — [`super::envelope::legacy_verb`] answers `405` for exactly that reason. It did NOT
//! delete Server-Sent Events: SSE survives as a RESPONSE CONTENT TYPE on the POST. One request, one
//! response, still stateless — the only thing that changes is that the response arrives as a
//! sequence of framed events instead of one JSON document, which is what gives a server somewhere to
//! put the notifications it produced while answering.
//!
//! Reading "no GET stream" as "no SSE" is the mistake this module exists to correct, and it is an
//! easy one: every earlier revision's SSE WAS the GET stream.
//!
//! ## THE NEGOTIATION IS BY THE CLIENT'S OWN STATED PREFERENCE, and that is not a detail
//!
//! Every MCP client sends `Accept: application/json, text/event-stream` — both, always, because both
//! are legal answers. A server that returned SSE whenever `text/event-stream` appeared anywhere in
//! `Accept` would return SSE to every client on earth, including the ones that listed it only as a
//! fallback. That is not honouring a preference; it is ignoring one.
//!
//! So this module ranks the offer the way HTTP says to rank it — by `q`, then by the order the
//! client wrote it in — and answers SSE only when the client put `text/event-stream` AHEAD of
//! `application/json`. A client that wants a stream asks for one first. A client that lists it second
//! gets the single JSON document it preferred, byte-for-byte what it got before this module existed,
//! which is why no existing caller's behaviour changes.
//!
//! ## ONLY A `200` BECOMES A STREAM
//!
//! An error response is terminal: there is no result to follow, nothing to notify about, and the
//! status/code pair ([`super::envelope::error_response`]) is the whole content of the answer. Framing
//! it as a stream would add a stream that is over before it starts and would put a second reading of
//! the same failure on the wire. Errors stay JSON, whatever the client asked for.
//!
//! ## NO EVENT `id:`, AND NO `retry:` — DELIBERATELY, NOT AS AN OMISSION
//!
//! Under earlier revisions a server SHOULD stamp each event with an `id:` so a disconnected client
//! can resume from it with `Last-Event-ID`, and SHOULD send `retry:` to pace the reconnection. This
//! revision removed BOTH mechanisms: there is no GET stream to resume on, and busbar answers `405` to
//! the verb that would carry one. An `id:` is therefore an offer to resume that this server cannot
//! honour, and `retry:` paces a reconnection that has nowhere to go. Emitting them because an older
//! revision's checklist asks for them would be advertising resumability that does not exist — which
//! is worse than not advertising it, because a client would build on it.
//!
//! ## `notifications/message` — WHY THE LOG RECORDS LIVE HERE
//!
//! MCP logging is a server telling the client what it did while answering. Under a protocol with a
//! session, the client sets a level once with `logging/setLevel` and the server pushes records over
//! the standing stream. This revision has NEITHER: no session to hold a level, and no standing
//! stream to push over. Both halves therefore become per-request — the level is named in the
//! request's own `_meta` ([`META_LOGGING_LEVEL`]), and the records ride the response stream of the
//! request they describe.
//!
//! That is why `logging/setLevel` remains genuinely unimplemented after this module landed, and it
//! is not a gap: there is no state for it to set. See `tests/ingress_tests.rs::UNIMPLEMENTED`, whose
//! reasoning this module makes MORE true rather than less.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

// THE FRAMING ITSELF IS THE PLANE'S (`busbar_plane_mcp::framing`): the level vocabulary, the
// preference ranking, the log records and the event bytes, pure. What stays here is the axum
// adapter the engine's routes answer through.
pub(crate) use busbar_plane_mcp::framing::{
    level_allows, requested_level, LogRecord, META_LOGGING_LEVEL,
};

/// Whether the caller's `Accept` header prefers an event stream ([`busbar_plane_mcp::framing::prefers_event_stream`]).
pub(crate) fn prefers_event_stream(headers: &HeaderMap) -> bool {
    busbar_plane_mcp::framing::prefers_event_stream(
        headers.get("accept").and_then(|v| v.to_str().ok()),
    )
}

/// RE-FRAME a `200` JSON-RPC response as an SSE stream, with `logs` delivered AHEAD of the result.
///
/// The ordering is the whole reason the records are worth sending: a log record describing the work
/// must arrive before the answer that work produced, or a client has already finished the request by
/// the time it is told what happened during it.
///
/// A non-`200` is returned untouched — see the module header. So is a body that is not JSON, which
/// cannot happen from [`super::envelope::error_response`] or `method::result` and is passed through
/// rather than guessed at, because a stream framing a body this function did not understand would be
/// this function inventing content.
pub(crate) async fn as_event_stream(
    response: Response,
    logs: &[LogRecord],
    progress: &[serde_json::Value],
) -> Response {
    if response.status() != StatusCode::OK {
        return response;
    }
    let (parts, body) = response.into_parts();
    // `usize::MAX`: the body is one JSON-RPC result this process just serialised itself, not
    // attacker-supplied input being buffered — the inbound body limit is applied at the ingress, on
    // the way in, where it belongs.
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        // A drain failure must NOT masquerade as a `200` with an empty body — that is a failure
        // wearing success's clothes, which a client reads as "the call returned nothing" and stops.
        // Answer a JSON-RPC internal error (-32603) at `500`. The id is unrecoverable (it rode in the
        // body that never arrived), so it is `null` per JSON-RPC 2.0 section 5.
        return super::envelope::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            -32603,
            "the response body could not be read to re-frame it as an event stream",
            None,
        );
    };
    let Some(out) = busbar_plane_mcp::framing::event_stream(&bytes, logs, progress) else {
        return Response::from_parts(parts, axum::body::Body::from(bytes));
    };
    // Built through the explicit builder rather than a `(StatusCode, headers, String)` tuple. A
    // `String` body sets `content-type: text/plain` on its way through `IntoResponse`, and whether a
    // header tuple then REPLACES that or merely appends beside it is a property of the framework's
    // impl rather than of this code. The one thing this function exists to get right is the content
    // type; it should not depend on which of two headers a client picks first.
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", busbar_plane_mcp::framing::EVENT_STREAM)
        // A stream of one request's own answer is never a shared cache's business, and the catalogue
        // answers are computed under the CALLER'S GRANT — the same reasoning `method::CACHE_SCOPE`
        // states for the JSON form, restated at the transport because a cache reads the header and
        // not the body.
        .header("cache-control", busbar_plane_mcp::framing::NO_STORE)
        .body(axum::body::Body::from(out))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
