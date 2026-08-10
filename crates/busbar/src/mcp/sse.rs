// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SSE RESPONSE STREAM ON THE POST, and the `notifications/message` log records that ride it.
//!
//! ## What revision `2026-07-28` removed, and what it did not
//!
//! The revision deleted the standalone GET stream, `Mcp-Session-Id`, and `Last-Event-ID`
//! resumability — [`super::ingress::legacy_verb`] answers `405` for exactly that reason. It did NOT
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
//! status/code pair ([`super::ingress::error_response`]) is the whole content of the answer. Framing
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

/// The `params._meta` key naming the minimum severity of `notifications/message` the client wants on
/// this request's response stream.
///
/// In BUSBAR'S OWN namespace, not `io.modelcontextprotocol/`. That namespace belongs to the spec, and
/// a key invented inside it would be busbar legislating for every other implementation — the same
/// reason `io.busbar/schemaHash` is spelled the way it is in `tools/list`. A client that sends
/// nothing gets [`DEFAULT_LEVEL`], which is the level an operator reading a log expects by default.
pub(crate) const META_LOGGING_LEVEL: &str = "io.busbar/loggingLevel";

/// The level a request that names none is served at.
pub(crate) const DEFAULT_LEVEL: &str = "info";

/// The RFC 5424 severities MCP names, ORDERED least to most severe. The index IS the comparison, so
/// there is no second table mapping a name to a number that could disagree with this one.
///
/// A name not in this list is not silently ranked: [`severity_of`] answers `None` and the caller
/// falls back to the default, because a request that asks for level `verbose` has asked for nothing
/// this server can honour and inventing a rank for it would filter records by a guess.
const SEVERITIES: &[&str] = &[
    "debug",
    "info",
    "notice",
    "warning",
    "error",
    "critical",
    "alert",
    "emergency",
];

fn severity_of(name: &str) -> Option<usize> {
    SEVERITIES.iter().position(|s| *s == name)
}

/// ONE `notifications/message` record, before it is framed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LogRecord {
    /// An RFC 5424 severity from [`SEVERITIES`].
    pub(crate) level: &'static str,
    /// The emitting component, so an operator reading a client's log can tell busbar's own records
    /// from an upstream's. Always prefixed `busbar.` for that reason.
    pub(crate) logger: &'static str,
    /// The payload. STRUCTURED rather than a formatted string: a client that wants to filter on the
    /// method should not have to parse English to do it.
    pub(crate) data: serde_json::Value,
}

impl LogRecord {
    /// The JSON-RPC NOTIFICATION envelope. No `id`, ever — a notification with an id is a request,
    /// and `BASE.NOTIF.NO-ID` is a MUST NOT. That is why this builds the envelope rather than
    /// leaving each call site to remember.
    fn envelope(&self) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {
                "level": self.level,
                "logger": self.logger,
                "data": self.data,
            },
        })
    }
}

/// The minimum severity this request asked for, read from `params._meta`.
///
/// An unrecognised name falls back to [`DEFAULT_LEVEL`] rather than being refused. The level is a
/// PREFERENCE about diagnostics, not a statement the request depends on: failing a `tools/call`
/// because the caller spelled a log level wrong would refuse real work over a debugging knob.
pub(crate) fn requested_level(meta: Option<&serde_json::Value>) -> &'static str {
    let named = meta
        .and_then(|m| m.get(META_LOGGING_LEVEL))
        .and_then(|v| v.as_str());
    match named.and_then(severity_of) {
        Some(i) => SEVERITIES[i],
        None => DEFAULT_LEVEL,
    }
}

/// Whether a record at `level` is at or above the `requested` minimum.
///
/// Both names are looked up in [`SEVERITIES`]; an unknown one on either side answers `true`, which
/// is fail-OPEN and is correct here and only here: the failure mode of a mis-ranked log filter is a
/// record the client did not ask for, and the failure mode of the other choice is a record — possibly
/// the one explaining a refusal — silently dropped.
pub(crate) fn level_allows(requested: &str, level: &str) -> bool {
    match (severity_of(requested), severity_of(level)) {
        (Some(min), Some(at)) => at >= min,
        _ => true,
    }
}

/// Whether the caller PREFERRED a `text/event-stream` response over `application/json`.
///
/// See the module header: this is a preference comparison, not a membership test. `q` decides first
/// (an explicit `q=0` is a refusal, and is honoured as one); the client's own ordering breaks a tie,
/// which is the ordinary reading of an `Accept` list. A wildcard `*/*` matches neither branch — a
/// client that expressed no preference between the two is not asking for a stream.
pub(crate) fn prefers_event_stream(headers: &HeaderMap) -> bool {
    let Some(accept) = headers.get("accept").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let mut sse: Option<(f32, usize)> = None;
    let mut json: Option<(f32, usize)> = None;
    for (position, entry) in accept.split(',').enumerate() {
        let mut parts = entry.split(';');
        let media = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        // Absent `q` is 1.0, per RFC 9110. A malformed one is treated as absent rather than as zero:
        // reading `q=high` as a refusal would drop a media type the client did offer.
        let q = parts
            .filter_map(|p| p.trim().strip_prefix("q=").map(str::trim))
            .find_map(|v| v.parse::<f32>().ok())
            .unwrap_or(1.0);
        match media.as_str() {
            "text/event-stream" => sse = sse.or(Some((q, position))),
            "application/json" => json = json.or(Some((q, position))),
            _ => {}
        }
    }
    let Some((sse_q, sse_pos)) = sse else {
        return false;
    };
    if sse_q <= 0.0 {
        return false;
    }
    match json {
        // Named alone: the client asked for a stream and nothing else.
        None => true,
        // Named alongside: higher `q` wins, and equal `q` is decided by which the client wrote first.
        Some((json_q, json_pos)) => {
            if (sse_q - json_q).abs() > f32::EPSILON {
                sse_q > json_q
            } else {
                sse_pos < json_pos
            }
        }
    }
}

/// RE-FRAME a `200` JSON-RPC response as an SSE stream, with `logs` delivered AHEAD of the result.
///
/// The ordering is the whole reason the records are worth sending: a log record describing the work
/// must arrive before the answer that work produced, or a client has already finished the request by
/// the time it is told what happened during it.
///
/// A non-`200` is returned untouched — see the module header. So is a body that is not JSON, which
/// cannot happen from [`super::ingress::error_response`] or `method::result` and is passed through
/// rather than guessed at, because a stream framing a body this function did not understand would be
/// this function inventing content.
pub(crate) async fn as_event_stream(response: Response, logs: &[LogRecord]) -> Response {
    if response.status() != StatusCode::OK {
        return response;
    }
    let (parts, body) = response.into_parts();
    // `usize::MAX`: the body is one JSON-RPC result this process just serialised itself, not
    // attacker-supplied input being buffered — the inbound body limit is applied at the ingress, on
    // the way in, where it belongs.
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return (parts.status, "").into_response();
    };
    let Ok(result) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Response::from_parts(parts, axum::body::Body::from(bytes));
    };

    let mut out = String::new();
    for log in logs {
        push_event(&mut out, &log.envelope());
    }
    push_event(&mut out, &result);

    // Built through the explicit builder rather than a `(StatusCode, headers, String)` tuple. A
    // `String` body sets `content-type: text/plain` on its way through `IntoResponse`, and whether a
    // header tuple then REPLACES that or merely appends beside it is a property of the framework's
    // impl rather than of this code. The one thing this function exists to get right is the content
    // type; it should not depend on which of two headers a client picks first.
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        // A stream of one request's own answer is never a shared cache's business, and the catalogue
        // answers are computed under the CALLER'S GRANT — the same reasoning `method::CACHE_SCOPE`
        // states for the JSON form, restated at the transport because a cache reads the header and
        // not the body.
        .header("cache-control", "no-cache, no-store")
        .body(axum::body::Body::from(out))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// One `message` event. `serde_json` emits no raw newline, so the single-line `data:` framing is
/// exact rather than lucky — but the value is written through `to_string` here rather than
/// interpolated so that stays true by construction.
fn push_event(out: &mut String, value: &serde_json::Value) {
    use std::fmt::Write as _;
    let _ = write!(
        out,
        "event: message\ndata: {}\n\n",
        serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
    );
}
