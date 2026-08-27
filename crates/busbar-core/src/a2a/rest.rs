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
//! [`busbar_substrate::transport::Transport::HttpJson`] is passed into `invoke` and used as a LABEL. There is
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

use axum::response::Response;
use serde_json::{json, Map, Value};

use super::receive::{invoke, Target, Wire};
use busbar_substrate::plane_routes::PlaneReqCtx;
use busbar_substrate::transport::Transport;

/// THE `id` EVERY RE-FRAMED ENVELOPE CARRIES.
///
/// A JSON-RPC id is a CORRELATION handle: it exists so a client can match an answer to one of
/// several requests multiplexed over one channel. The HTTP+JSON binding has no such channel — one
/// HTTP request, one HTTP response, correlated by the connection — so there is no caller id to
/// echo, and the id here is never seen by the caller: [`reframe`] unwraps the envelope it appears
/// in before the answer leaves.
///
/// It is a fixed string rather than a generated one BECAUSE it is not a correlation handle. The
/// shared envelope reader requires an id that is a string or a number (an absent id is a
/// NOTIFICATION, which a server must not answer, and a `null` id is refused), so this satisfies
/// that contract with a value that says what it is. Making it unique per request would suggest a
/// multiplexing this binding does not have and would put a different value in the one place a
/// backend can see it — the relayed envelope — for no reader's benefit.
const REST_RPC_ID: &str = "a2a-http-json";

/// THE METHOD NAMES, in A2A v1.0's spelling.
///
/// The HTTP+JSON binding was introduced with v1.0 and the specification's own operation table names
/// these, so a REST request is composed as a v1.0 envelope. That is not a preference: `local::verb_of`
/// and `ingress::shape_of` both read a method name, both read BOTH dialects, and composing a v0.3
/// name here would compose an envelope for the version this binding does not belong to.
pub(super) mod method {
    pub(crate) const SEND_MESSAGE: &str = "SendMessage";
    pub(crate) const SEND_STREAMING_MESSAGE: &str = "SendStreamingMessage";
    pub(crate) const GET_TASK: &str = "GetTask";
    pub(crate) const LIST_TASKS: &str = "ListTasks";
    pub(crate) const CANCEL_TASK: &str = "CancelTask";
    pub(crate) const SUBSCRIBE_TO_TASK: &str = "SubscribeToTask";
    pub(crate) const CREATE_PUSH_CONFIG: &str = "CreateTaskPushNotificationConfig";
    pub(crate) const GET_PUSH_CONFIG: &str = "GetTaskPushNotificationConfig";
    pub(crate) const LIST_PUSH_CONFIGS: &str = "ListTaskPushNotificationConfigs";
    pub(crate) const DELETE_PUSH_CONFIG: &str = "DeleteTaskPushNotificationConfig";
    pub(crate) const GET_EXTENDED_AGENT_CARD: &str = "GetExtendedAgentCard";
}

/// THE TWO OPERATIONS `POST /tasks/{id}:<verb>` SPELLS, and the reason they arrive together.
///
/// A2A names them with a colon suffix inside the last path SEGMENT (`/tasks/abc:cancel`), which the
/// router captures whole. Two separate route templates differing only in that suffix would be two
/// patterns the path matcher cannot tell apart, so the segment is captured once and split here —
/// where an unknown verb is a `404` naming the two that exist, rather than a route that silently
/// never matches.
const VERB_CANCEL: &str = "cancel";
const VERB_SUBSCRIBE: &str = "subscribe";

/// A REQUEST'S PARAMS, built member by member, skipping what the caller did not send.
///
/// ABSENT IS NOT EMPTY, and this is where that is enforced for the whole binding. A query parameter
/// the caller omitted must not appear in the composed `params` at all: `historyLength` absent means
/// "no opinion", and `historyLength: null` (or `""`) means the caller asked for something. The
/// JSON-RPC leg gets this for free because an omitted member is simply not in the caller's body;
/// composing an envelope from a query string is the one place it has to be a decision.
#[derive(Default)]
struct Params(Map<String, Value>);

impl Params {
    fn new() -> Self {
        Self(Map::new())
    }

    /// Set `name` to a value the caller definitely supplied.
    fn set(mut self, name: &str, value: impl Into<Value>) -> Self {
        self.0.insert(name.to_string(), value.into());
        self
    }

    /// Set `name` only if the caller supplied it. See the type note.
    fn maybe(mut self, name: &str, value: Option<&String>) -> Self {
        if let Some(v) = value {
            self.0.insert(name.to_string(), json_scalar(v));
        }
        self
    }

    /// Merge a REQUEST BODY in, VERBATIM. Section 11.3's rule: the REST body IS the `params`. The
    /// path-derived members are set FIRST and a body member of the same name would overwrite one —
    /// which is why the two call sites that take a body set their path member AFTER this, so the
    /// URL a caller addressed cannot be re-pointed by a member of the document they posted.
    fn merge(mut self, body: &Value) -> Self {
        if let Some(obj) = body.as_object() {
            for (k, v) in obj {
                self.0.insert(k.clone(), v.clone());
            }
        }
        self
    }

    fn into_value(self) -> Value {
        Value::Object(self.0)
    }
}

/// A QUERY-STRING VALUE, TYPED THE WAY THE ENVELOPE WANTS IT.
///
/// Everything in a query string is a string, and `historyLength=5` means the NUMBER five to every
/// reader of the composed envelope. Left as `"5"`, the shared readers that ask for an integer see a
/// string and answer as though the caller had asked for nothing — a filter silently not applied,
/// which is the failure mode that is invisible because nothing errors. Booleans are the same fact:
/// `includeArtifacts=true` is a boolean member in the JSON-RPC binding.
///
/// A value that is neither stays a string, because a task id, a page token and a status name all
/// legitimately are one.
fn json_scalar(raw: &str) -> Value {
    if let Ok(n) = raw.parse::<i64>() {
        return json!(n);
    }
    match raw {
        "true" => json!(true),
        "false" => json!(false),
        other => json!(other),
    }
}

/// THE ONE PATH EVERY REST HANDLER TAKES: compose the envelope, run the shared sequence, re-frame
/// the answer.
async fn compose_and_invoke(
    app: std::sync::Arc<crate::state::App>,
    gov: busbar_api::PlaneRequestCtx,
    principal: busbar_api::AuthPrincipal,
    wire: Wire,
    method: &str,
    params: Value,
) -> Response {
    let envelope = json!({
        "jsonrpc": "2.0",
        "id": REST_RPC_ID,
        "method": method,
        "params": params,
    });
    // THE AGENT IS RESOLVED FROM THE CALLER'S CATALOGUE, exactly as it is for `POST /a2a`. These
    // paths hang off the plane's own mount — the address busbar's agent card publishes for this
    // binding — so the caller has named no agent, and `Target::FromCatalogue` is the same answer to
    // the same question the JSON-RPC leg's plane endpoint already gives.
    let body = axum::body::Bytes::from(serde_json::to_vec(&envelope).unwrap_or_default());
    let answered = invoke(
        app,
        gov,
        principal,
        Target::FromCatalogue,
        wire,
        Transport::HttpJson,
        body,
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
    let streaming = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with(super::relay::SSE_CONTENT_TYPE));
    let (mut parts, body) = response.into_parts();
    if streaming {
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
    engine: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    gov: Option<busbar_api::PlaneRequestCtx>,
    principal: Option<busbar_api::AuthPrincipal>,
    headers: &axum::http::HeaderMap,
) -> (
    std::sync::Arc<crate::state::App>,
    busbar_api::PlaneRequestCtx,
    busbar_api::AuthPrincipal,
    Wire,
) {
    let handle: std::sync::Arc<crate::state::AppHandle> = engine
        .downcast::<crate::state::AppHandle>()
        .expect("the a2a route engine handle is an AppHandle");
    let app = handle.load();
    let gov =
        gov.expect("the a2a REST routes are RouteAuth::Key, so the middleware attached a gov ctx");
    let principal = principal
        .expect("the a2a REST routes are RouteAuth::Key, so the middleware attached a principal");
    (app, gov, principal, Wire::from_headers(headers))
}

/// THE QUERY STRING AS A `name → value` MAP, replacing the `axum::extract::Query<HashMap<..>>` the
/// three query-bearing handlers took. Read off `ctx.uri.query()` on the neutral seam; decoded as
/// `application/x-www-form-urlencoded` (the same media type axum's `Query` deserialises), so `+`
/// becomes a space and `%XX` is a byte — exactly the value the extractor produced. A repeated key
/// keeps the last value, as the extractor's `HashMap` deserialisation does; a malformed pair yields
/// its own bytes rather than a request-wide rejection, which only widens what an odd query still
/// answers on this `Key`-authed surface.
fn query_map(uri: &axum::http::Uri) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let Some(raw) = uri.query() else {
        return map;
    };
    for pair in raw.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(form_decode(k), form_decode(v));
    }
    map
}

/// Decode ONE `application/x-www-form-urlencoded` component: `+` → space, `%XX` → the byte, anything
/// else verbatim, then interpret the bytes as UTF-8 lossily — the decoding `form_urlencoded` (and so
/// axum's `Query`) applies to a query-string key or value.
fn form_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `POST /message:send` — the body IS the `params`.
async fn message_send(ctx: PlaneReqCtx) -> Response {
    let (app, gov, principal, wire) =
        rest_key_ctx(ctx.engine, ctx.gov, ctx.principal, &ctx.headers);
    let params = json_body(&ctx.body);
    compose_and_invoke(app, gov, principal, wire, method::SEND_MESSAGE, params).await
}

/// `POST /message:stream` — the same body, the streaming method, an SSE answer.
async fn message_stream(ctx: PlaneReqCtx) -> Response {
    let (app, gov, principal, wire) =
        rest_key_ctx(ctx.engine, ctx.gov, ctx.principal, &ctx.headers);
    let params = json_body(&ctx.body);
    compose_and_invoke(
        app,
        gov,
        principal,
        wire,
        method::SEND_STREAMING_MESSAGE,
        params,
    )
    .await
}

/// `GET /tasks/{id}` — the task id from the path, `historyLength` from the query.
async fn task_get(ctx: PlaneReqCtx) -> Response {
    let (app, gov, principal, wire) =
        rest_key_ctx(ctx.engine, ctx.gov, ctx.principal, &ctx.headers);
    let id = super::receive::path_param(&ctx.path_params, "id");
    let query = query_map(&ctx.uri);
    let params = Params::new()
        .set("id", id)
        .maybe("historyLength", query.get("historyLength"))
        .into_value();
    compose_and_invoke(app, gov, principal, wire, method::GET_TASK, params).await
}

/// `POST /tasks/{id}:cancel` and `POST /tasks/{id}:subscribe` — one route, because the verb is a
/// suffix INSIDE the captured segment. See [`VERB_CANCEL`].
async fn task_verb(ctx: PlaneReqCtx) -> Response {
    let (app, gov, principal, wire) =
        rest_key_ctx(ctx.engine, ctx.gov, ctx.principal, &ctx.headers);
    let addressed = super::receive::path_param(&ctx.path_params, "id");
    let Some((id, verb)) = addressed.rsplit_once(':') else {
        return not_a_verb(&addressed);
    };
    let method = match verb {
        VERB_CANCEL => method::CANCEL_TASK,
        VERB_SUBSCRIBE => method::SUBSCRIBE_TO_TASK,
        _ => return not_a_verb(&addressed),
    };
    let params = Params::new().set("id", id).into_value();
    compose_and_invoke(app, gov, principal, wire, method, params).await
}

/// The refusal for a `POST /tasks/…` that names no verb this binding defines. `MethodNotFound`
/// rather than `TaskNotFound`: the fault is in the request line, and telling a caller their task
/// does not exist when what does not exist is the operation sends them looking in the wrong place.
fn not_a_verb(addressed: &str) -> Response {
    let error = super::rpcerror::body(
        &Value::Null,
        super::rpcerror::A2aError::MethodNotFound,
        format!(
            "`{addressed}` names no operation on this binding; the task operations are \
             `{{id}}:{VERB_CANCEL}` and `{{id}}:{VERB_SUBSCRIBE}`"
        ),
    );
    let status = super::rpcerror::A2aError::MethodNotFound.http_status();
    (
        axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::NOT_FOUND),
        axum::Json(super::rpcerror::aip193(status, &error["error"])),
    )
        .into_response()
}

/// `GET /tasks` — the filters ride the query string.
async fn tasks_list(ctx: PlaneReqCtx) -> Response {
    let (app, gov, principal, wire) =
        rest_key_ctx(ctx.engine, ctx.gov, ctx.principal, &ctx.headers);
    let query = query_map(&ctx.uri);
    let params = Params::new()
        .maybe("contextId", query.get("contextId"))
        .maybe("status", query.get("status"))
        .maybe("pageSize", query.get("pageSize"))
        .maybe("pageToken", query.get("pageToken"))
        .maybe("historyLength", query.get("historyLength"))
        .maybe("statusTimestampAfter", query.get("statusTimestampAfter"))
        .maybe("includeArtifacts", query.get("includeArtifacts"))
        .into_value();
    compose_and_invoke(app, gov, principal, wire, method::LIST_TASKS, params).await
}

/// `POST /tasks/{id}/pushNotificationConfigs` — the body IS the config, the task id is the path's.
async fn push_config_create(ctx: PlaneReqCtx) -> Response {
    let (app, gov, principal, wire) =
        rest_key_ctx(ctx.engine, ctx.gov, ctx.principal, &ctx.headers);
    let id = super::receive::path_param(&ctx.path_params, "id");
    // THE PATH WINS. `merge` first, `set` after: the task this config is for is the one the caller
    // ADDRESSED, and a `taskId` member in the posted document must not silently re-point it at
    // somebody else's task. The scoping in `local::addressed` would refuse another tenant's id
    // anyway; this makes the request unambiguous before it gets there.
    let params = Params::new()
        .merge(&json_body(&ctx.body))
        .set("taskId", id)
        .into_value();
    compose_and_invoke(
        app,
        gov,
        principal,
        wire,
        method::CREATE_PUSH_CONFIG,
        params,
    )
    .await
}

/// `GET /tasks/{id}/pushNotificationConfigs`.
async fn push_config_list(ctx: PlaneReqCtx) -> Response {
    let (app, gov, principal, wire) =
        rest_key_ctx(ctx.engine, ctx.gov, ctx.principal, &ctx.headers);
    let id = super::receive::path_param(&ctx.path_params, "id");
    let query = query_map(&ctx.uri);
    let params = Params::new()
        .set("taskId", id)
        .maybe("pageSize", query.get("pageSize"))
        .maybe("pageToken", query.get("pageToken"))
        .into_value();
    compose_and_invoke(app, gov, principal, wire, method::LIST_PUSH_CONFIGS, params).await
}

/// `GET /tasks/{id}/pushNotificationConfigs/{configId}`.
async fn push_config_get(ctx: PlaneReqCtx) -> Response {
    let (app, gov, principal, wire) =
        rest_key_ctx(ctx.engine, ctx.gov, ctx.principal, &ctx.headers);
    let id = super::receive::path_param(&ctx.path_params, "id");
    let config_id = super::receive::path_param(&ctx.path_params, "config_id");
    let params = Params::new()
        .set("taskId", id)
        .set("id", config_id)
        .into_value();
    compose_and_invoke(app, gov, principal, wire, method::GET_PUSH_CONFIG, params).await
}

/// `DELETE /tasks/{id}/pushNotificationConfigs/{configId}`.
async fn push_config_delete(ctx: PlaneReqCtx) -> Response {
    let (app, gov, principal, wire) =
        rest_key_ctx(ctx.engine, ctx.gov, ctx.principal, &ctx.headers);
    let id = super::receive::path_param(&ctx.path_params, "id");
    let config_id = super::receive::path_param(&ctx.path_params, "config_id");
    let params = Params::new()
        .set("taskId", id)
        .set("id", config_id)
        .into_value();
    compose_and_invoke(
        app,
        gov,
        principal,
        wire,
        method::DELETE_PUSH_CONFIG,
        params,
    )
    .await
}

/// `GET /extendedAgentCard`.
///
/// RE-FRAMED AND RELAYED LIKE EVERY OTHER OPERATION, rather than answered here. busbar's own card
/// says `extendedAgentCard: false` because busbar does not implement the verb — and this endpoint is
/// the binding, not the implementation. Answering it locally with a refusal busbar's JSON-RPC leg
/// does not give would make the two legs disagree about one operation, which is precisely the
/// divergence "re-framing, not translation" exists to prevent. When the verb lands it lands once, on
/// the shared sequence, and both bindings gain it together.
async fn extended_agent_card(ctx: PlaneReqCtx) -> Response {
    let (app, gov, principal, wire) =
        rest_key_ctx(ctx.engine, ctx.gov, ctx.principal, &ctx.headers);
    compose_and_invoke(
        app,
        gov,
        principal,
        wire,
        method::GET_EXTENDED_AGENT_CARD,
        json!({}),
    )
    .await
}

/// A REQUEST BODY, or the empty object when there is none.
///
/// An empty body is NOT a parse failure on this binding: `POST /tasks/{id}:cancel` carries no body
/// at all and neither does a `DELETE`. A body that is present and is not JSON falls through to the
/// shared sequence as an empty `params`, where the operation's own reader refuses it for the member
/// it is missing — the same refusal, from the same place, as a JSON-RPC caller who sent an envelope
/// with no params.
fn json_body(body: &axum::body::Bytes) -> Value {
    if body.is_empty() {
        return json!({});
    }
    serde_json::from_slice(body).unwrap_or_else(|_| json!({}))
}

use axum::response::IntoResponse;

/// MOUNT THE BINDING, under the plane's own mount and nowhere else.
///
/// Every path here hangs off [`super::serve::MOUNT_PATH`], which is the URL busbar's agent card
/// publishes for BOTH bindings — the specification models them as two interfaces of one agent at
/// (possibly) one address, and a card that advertised a second address nothing served is the defect
/// `serve` refuses one member down.
///
/// `RouteAuth::Key` on every one, exactly as the JSON-RPC leg carries. A binding is a way of
/// SPELLING a request, never a way around the admission the plane applies to it, and an unauthed
/// REST leg beside an authed JSON-RPC one would be precisely that.
pub(super) fn a2a_rest_routes() -> Vec<busbar_substrate::plane_routes::PlaneRouteSpec> {
    use busbar_plugin_loader::{RouteAuth, RouteMethod};
    use busbar_substrate::plane_routes::{PlaneReqCtx, PlaneRouteFuture, PlaneRouteSpec};
    let mount = super::serve::MOUNT_PATH;
    // Each spec's `(path, method, auth)` is handed VERBATIM to `CoreRouter::route` by the core
    // adapter, so the `CoreRouteTable` rows are byte-identical to the ones the old `mount` recorded —
    // SAME paths, SAME methods, SAME `RouteAuth::Key`, in THIS SAME ORDER. The handlers are the
    // neutral async fns over `PlaneReqCtx`. The two `{id}` templates differing only by method are two
    // rows here exactly as they were two `.route` calls before; the capture names `{id}`/`{config_id}`
    // are spelled verbatim so the seam's `path_params` carry the names the handlers read.
    vec![
        PlaneRouteSpec {
            path: format!("{mount}/message:send"),
            method: RouteMethod::Post,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(message_send(ctx))
            }),
        },
        PlaneRouteSpec {
            path: format!("{mount}/message:stream"),
            method: RouteMethod::Post,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(message_stream(ctx))
            }),
        },
        PlaneRouteSpec {
            path: format!("{mount}/tasks"),
            method: RouteMethod::Get,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(tasks_list(ctx))
            }),
        },
        // ONE PATH TEMPLATE, TWO METHODS, and the capture is named `{id}` in both. The router merges
        // methods for one path; two templates differing only in the capture NAME would be one
        // pattern registered twice, which is a startup panic rather than a route.
        PlaneRouteSpec {
            path: format!("{mount}/tasks/{{id}}"),
            method: RouteMethod::Get,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(task_get(ctx))
            }),
        },
        PlaneRouteSpec {
            path: format!("{mount}/tasks/{{id}}"),
            method: RouteMethod::Post,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(task_verb(ctx))
            }),
        },
        PlaneRouteSpec {
            path: format!("{mount}/tasks/{{id}}/pushNotificationConfigs"),
            method: RouteMethod::Post,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(push_config_create(ctx))
            }),
        },
        PlaneRouteSpec {
            path: format!("{mount}/tasks/{{id}}/pushNotificationConfigs"),
            method: RouteMethod::Get,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(push_config_list(ctx))
            }),
        },
        PlaneRouteSpec {
            path: format!("{mount}/tasks/{{id}}/pushNotificationConfigs/{{config_id}}"),
            method: RouteMethod::Get,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(push_config_get(ctx))
            }),
        },
        PlaneRouteSpec {
            path: format!("{mount}/tasks/{{id}}/pushNotificationConfigs/{{config_id}}"),
            method: RouteMethod::Delete,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(push_config_delete(ctx))
            }),
        },
        PlaneRouteSpec {
            path: format!("{mount}/extendedAgentCard"),
            method: RouteMethod::Get,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(extended_agent_card(ctx))
            }),
        },
    ]
}

#[cfg(test)]
#[path = "tests/rest_tests.rs"]
mod rest_tests;
