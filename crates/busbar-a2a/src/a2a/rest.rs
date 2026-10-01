// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A2A'S **HTTP+JSON** BINDING — the plane's second wire format, and RE-FRAMING rather than
//! translation.
//!
//! ## What A2A section 11.3 actually says, and why it makes this module small
//!
//! The specification defines three bindings of ONE agent, and it defines the REST one BY REFERENCE
//! to the JSON-RPC one: **the request body IS the JSON-RPC `params` verbatim, and the success body
//! IS the JSON-RPC `result` verbatim.** Nothing about the operation, the admission, the meter, the
//! task row or the relay differs — only where the method NAME comes from (the request line rather
//! than a body member) and how the answer is WRAPPED (bare, rather than in a JSON-RPC envelope).
//!
//! So this module does exactly two things and deliberately nothing else:
//!
//! 1. **Compose the envelope** the JSON-RPC leg would have received, from the path, the query and
//!    the body, and hand it to [`super::receive::invoke`] — the SAME function, with the same
//!    admission, egress gate, SSRF guard, meter, audit chain and relay. There is no second sequence
//!    here and there must never be one: a second copy of that sequence is a second place for the
//!    egress gate or the push-callback guard to go missing, which is the argument `ingress::invoke`
//!    already makes for why its two endpoints are one function taking a two-variant target.
//! 2. **Re-frame the answer** — unwrap `result`, or re-shape `error` into AIP-193
//!    ([`super::rpcerror::aip193`]).
//!
//! ## The transport is a VALUE here, and it is never asked its identity
//!
//! [`busbar_contract::transport::transport::Transport::HttpJson`] is passed into `invoke` and used as a LABEL. There is
//! no `if transport ==` anywhere on this path, and there is no place for one: which framing applies
//! is settled by WHICH HANDLER THE ROUTER PICKED, before any code runs. That is what the framing
//! seam is for — a cell of the matrix is selected by lookup, never by a branch in the agnostic core
//! — and it is why arming a binding costs a module of routes rather than a fork through the plane.
//!
//! ## Why the answer is re-framed from the response rather than threaded through the sequence
//!
//! The alternative was a flag carried down `invoke`, through the hop context, into the relay, and
//! read at each of the six sites that build an answer. That is the transport-identity branch this
//! tree's structural lint refuses, six times over, and it would put the question "which binding is
//! this" inside code whose entire correctness argument is that it does not know. Re-framing at the
//! edge keeps the shared sequence genuinely shared: it produces ONE answer, and the binding that
//! asked for it decides how that answer is wrapped on the way out.
//!
//! ## The streaming legs are re-framed EVENT BY EVENT, incrementally
//!
//! `POST /message:stream` and `POST /tasks/{id}:subscribe` answer `text/event-stream`, and the TCK's
//! REST client parses each `data:` payload as the bare event. So the SSE body is re-framed as it
//! flows, not buffered: buffering would turn a long-running task's live stream into one delivery at
//! the end, which is the whole property streaming exists to provide, and the backpressure the
//! ingress builds its channel around would be spent into an unbounded buffer here.

use axum::response::{IntoResponse, Response};
use serde_json::Value;

use super::receive::{invoke, Target, Wire};
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_contract::transport::transport::Transport;
use busbar_kernel::plane_routes::{PlaneReqCtx, PlaneRouteFuture, PlaneRouteSpec};
use busbar_plane_a2a::door::{self, Line, Route};

/// THE METHOD NAMES and the fixed id every composed envelope carries have ONE home, the plane's
/// HTTP+JSON line ([`busbar_plane_a2a::rest`]); re-exported under their old in-crate paths.
pub(super) use busbar_plane_a2a::rest::{method, REST_RPC_ID};

/// ONE REQUEST ON THE LINE: compose the envelope its request spells (the plane's
/// [`busbar_plane_a2a::rest::compose_from`], over the captures the router decoded and the raw
/// query), run the shared sequence, re-frame the answer.
async fn line(ctx: PlaneReqCtx, route: &'static Route) -> Response {
    let (gov, principal, wire) = rest_key_ctx(ctx.engine, ctx.gov, ctx.principal, &ctx.headers);
    let var = |name: &str| super::receive::path_param(&ctx.path_params, name);
    let envelope =
        match busbar_plane_a2a::rest::compose_from(route, var, ctx.uri.query(), &ctx.body) {
            Ok(Some(envelope)) => envelope,
            // A `POST /tasks/…` naming no verb: `404` + `MethodNotFound`, in AIP-193.
            Err(refusal) => {
                let status = u16::try_from(refusal.status)
                    .ok()
                    .and_then(|s| axum::http::StatusCode::from_u16(s).ok())
                    .unwrap_or(axum::http::StatusCode::NOT_FOUND);
                return (status, axum::Json(refusal.aip193())).into_response();
            }
            // Every route mounted here is one of the line's, so this is a wiring fault.
            Ok(None) => {
                return super::rpcerror::respond(
                    &Value::Null,
                    super::rpcerror::A2aError::Internal,
                    "this route is not one the HTTP+JSON binding composes",
                )
            }
        };
    // THE AGENT IS RESOLVED FROM THE CALLER'S CATALOGUE, exactly as it is for `POST /a2a`: these
    // paths hang off the plane's own mount, so the caller has named no agent.
    let answered = invoke(
        ctx.host,
        gov,
        principal,
        Target::FromCatalogue,
        wire,
        Transport::HttpJson,
        axum::body::Bytes::from(envelope),
    )
    .await;
    reframe(answered).await
}

/// UNWRAP THE JSON-RPC ENVELOPE THE SHARED SEQUENCE ANSWERED IN.
///
/// Three answers can come back and each is re-framed by WHAT IT IS, never by what the caller asked
/// for:
///
/// * **A stream** (`text/event-stream`) — re-framed event by event as it flows. See
///   [`reframe_events`].
/// * **A JSON-RPC result** — the body becomes the `result` VERBATIM, which is section 11.3's rule.
/// * **A JSON-RPC error** — re-shaped to AIP-193 by [`super::rpcerror::aip193`], keeping the status
///   the shared sequence already chose. Section 5.4 binds the status and the body to one row of one
///   table, so the status is not re-derived here; re-deriving it would be a second answer to a
///   question the shared path has already answered.
///
/// ANYTHING ELSE PASSES THROUGH UNTOUCHED. Not every answer on this plane is a JSON-RPC envelope —
/// a `503` from a deployment with no governance is a plain document — and a re-framer that assumed
/// otherwise would replace a legible refusal with an empty one. The test for "is this an envelope"
/// is the presence of `result` or `error`, which is the same test the relay's event reader applies
/// for the same reason.
async fn reframe(response: Response) -> Response {
    let is_stream = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with(super::relay::SSE_CONTENT_TYPE));
    let (mut parts, body) = response.into_parts();
    if is_stream {
        return Response::from_parts(parts, reframe_events(body));
    }
    // The body is busbar's OWN answer, already fully composed in memory by the handler above; there
    // is no caller-controlled length to bound here, which is why this reads it whole.
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return crate::a2a::rpcerror::respond(
            &Value::Null,
            super::rpcerror::A2aError::Internal,
            "the answer could not be read back for re-framing",
        );
    };
    let Ok(envelope) = serde_json::from_slice::<Value>(&bytes) else {
        return Response::from_parts(parts, axum::body::Body::from(bytes));
    };
    let status = parts.status.as_u16();
    let reframed = match (envelope.get("result"), envelope.get("error")) {
        (Some(result), _) => result.clone(),
        (None, Some(error)) if !error.is_null() => super::rpcerror::aip193(status, error),
        _ => return Response::from_parts(parts, axum::body::Body::from(bytes)),
    };
    let rendered = serde_json::to_vec(&reframed).unwrap_or_default();
    // The length changed, so a stale `content-length` would describe the envelope that no longer
    // ships. Removed rather than recomputed: the body below is a known-length buffer and the server
    // sets it, which is one fewer place for the two to disagree.
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    Response::from_parts(parts, axum::body::Body::from(rendered))
}

/// RE-FRAME AN SSE BODY AS IT FLOWS: each `data:` payload that is a JSON-RPC response becomes its
/// `result`, and everything else — keep-alives, comments, a backend's own extension frames — is
/// passed through byte for byte.
///
/// ## Why this buffers by EVENT and not by chunk
///
/// An SSE event ends at a blank line, and nothing in HTTP promises that one read gives one event.
/// Re-framing per chunk would work for as long as the producer happened to write whole events and
/// would corrupt the stream the first time it did not — a failure that appears only under load or
/// behind a proxy, i.e. never in a test. So bytes accumulate until a `\n\n` and are re-framed one
/// complete event at a time; whatever is left over waits for the next chunk.
fn reframe_events(body: axum::body::Body) -> axum::body::Body {
    use futures::StreamExt;
    let stream = body
        .into_data_stream()
        .map(move |chunk| chunk.map(|bytes| axum::body::Bytes::from(reframe_frames(&bytes))));
    // A TRAILING PARTIAL EVENT IS NOT SYNTHESISED. If the upstream ends mid-event the caller gets a
    // truncated stream, which is what happened; inventing a terminator would present a torn event
    // as a complete one.
    axum::body::Body::from_stream(stream)
}

/// Re-frame every COMPLETE event in `buf`, returning what should be written. State-free by design:
/// the ingress writes one whole event per chunk (`relay::frame_sse`), so this holds nothing across
/// calls and a chunk that is not a complete event is written through unchanged rather than held —
/// see [`reframe_events`] for why the split point is the blank line and not the chunk boundary.
fn reframe_frames(buf: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(buf) else {
        return buf.to_vec();
    };
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let Some(payload) = trimmed.strip_prefix("data:") else {
            out.push_str(line);
            continue;
        };
        let Ok(envelope) = serde_json::from_str::<Value>(payload.trim()) else {
            out.push_str(line);
            continue;
        };
        let Some(result) = envelope.get("result") else {
            // An `error` frame mid-stream keeps its envelope: the status is already spent, and the
            // relay's own note says such a frame is content the caller is owed. Re-shaping it to
            // AIP-193 would claim an HTTP status this response no longer has one of to give.
            out.push_str(line);
            continue;
        };
        out.push_str("data: ");
        out.push_str(&result.to_string());
        // The line's own terminator is preserved, so an event's framing survives the substitution.
        out.push_str(&line[trimmed.len()..]);
    }
    out.into_bytes()
}

// ── THE ROUTES. One handler per (method, path) the specification names. ─────────────────────────

/// THE COMMON PREAMBLE FOR EVERY REST HANDLER (the neutral route-mount seam).
///
/// Each of the ten handlers is `RouteAuth::Key`, and each took `CurrentApp` plus the two auth
/// extensions plus `Wire`. The neutral seam hands those as fields on [`PlaneReqCtx`]: the live app is
/// downcast off the type-erased engine handle (App-sever is later), `gov`/`principal` are the values
/// the auth middleware resolved BEFORE this `Key` route ran (surfaced, never re-derived), and `Wire`
/// is the same three headers the extractor read, off `ctx.headers`. Consuming `engine`/`gov`/
/// `principal` here leaves `ctx.body`/`ctx.path_params`/`ctx.uri` for the caller to read.
fn rest_key_ctx(
    _engine: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    gov: Option<busbar_contract::records::PlaneRequestCtx>,
    principal: Option<busbar_contract::auth::AuthPrincipal>,
    headers: &axum::http::HeaderMap,
) -> (
    busbar_contract::records::PlaneRequestCtx,
    busbar_contract::auth::AuthPrincipal,
    Wire,
) {
    // The engine handle is no longer named here: the shared sequence closes its own request out
    // through the neutral `ctx.host` seam, so this key-ctx neither loads the app nor asserts the
    // handle's concrete type — the plane names no host application-state type on this path.
    let gov =
        gov.expect("the a2a REST routes are RouteAuth::Key, so the middleware attached a gov ctx");
    let principal = principal
        .expect("the a2a REST routes are RouteAuth::Key, so the middleware attached a principal");
    (gov, principal, Wire::from_headers(headers))
}

/// The router's method for a route's verb.
fn route_method(verb: &str) -> RouteMethod {
    match verb {
        "GET" => RouteMethod::Get,
        "DELETE" => RouteMethod::Delete,
        "PUT" => RouteMethod::Put,
        "PATCH" => RouteMethod::Patch,
        _ => RouteMethod::Post,
    }
}

/// MOUNT THE BINDING: the plane door's HTTP+JSON line, route for route and in its order (the door
/// states the routes once, and the door pins hold them equal to what the engine mounts).
///
/// Every path hangs off [`super::serve::MOUNT_PATH`], which is the URL busbar's agent card
/// publishes for BOTH bindings. `RouteAuth::Key` on every one, exactly as the JSON-RPC leg carries:
/// a binding is a way of SPELLING a request, never a way around the admission the plane applies to
/// it. One path template under two methods is two rows, as the router merges methods for one path.
pub(super) fn a2a_rest_routes() -> Vec<PlaneRouteSpec> {
    door::ROUTES
        .iter()
        .filter(|route| door::line_of(route) == Line::Target)
        .map(|route| PlaneRouteSpec {
            path: route.target.to_string(),
            method: route_method(route.verb),
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(move |ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(line(ctx, route))
            }),
        })
        .collect()
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/rest_tests.rs"]
mod rest_tests;
