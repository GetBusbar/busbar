// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SERVING THE SESSION REVISIONS on the one endpoint: `2025-06-18` and `2025-11-25` (a session named
//! by a response header, a GET event stream, DELETE) and `2024-11-05` (a GET event stream whose first
//! event names the address messages are POSTed to).
//!
//! OWNER 2026-09-29 compat scope; the compat slot's C4. The dialect's rules are the plane's
//! (`revision`, `session`, `adapt` in the plane crate) and this file is only their I/O: it reads the
//! request, asks the plane what it is, and writes the answer. There is ONE dispatch: a session
//! request is raised into the stateless shape and answered by [`super::envelope::rpc_dispatch`]
//! behind the same shared envelope reader (`Origin`, parse, JSON-RPC shape) every stateless request
//! passes, and the answer is lowered back.
//!
//! ## The stateless revision is untouched
//!
//! [`intercept`] answers `None` for every POST the plane classifies as stateless (the stateless
//! marker in `_meta`, or neither a session nor `initialize`), and the caller then runs exactly the
//! code it always ran. A plain GET or a sessionless DELETE is still the `405` it always was.
//!
//! ## Sessions are per process, and bound to their owner
//!
//! The table lives on the plane's runtime and is carried across config applies. A client whose next
//! request lands on another replica gets `404` and re-initialises, which is the spec's own recovery.
//! A session belongs to the principal and the credential (the virtual key) that opened it; any other
//! caller reads it as a session that does not exist, on all four paths that name one. The ungoverned
//! open chain has one principal and one credential for everybody, so it isolates nothing, matching
//! that posture's wildcard grants. Only an id's eight-character prefix is ever logged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::envelope::{error_body, protocol, EngineHost, PlaneReqCtx};
use super::{adapt, plane_codec as codec, revision, session_rules as session};
use crate::plane_client::jsonrpc::encode_sentinel;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use adapt::{PostKind, SessionMethod};
use revision::{HeaderCheck, Revision, SessionlessGet};
use session::{Bounds, Carriage, OpenRefused, Owner, SessionTable};

/// The credential every caller of the ungoverned open chain shares.
const UNGOVERNED: &str = "<ungoverned>";
/// How many framed answers wait for a `2024-11-05` stream's reader before a sender waits.
const OUTLET_DEPTH: usize = 64;
/// How long a sender waits for that reader before the answer is dropped.
const OUTLET_SEND: Duration = Duration::from_secs(5);
/// How often an idle event stream writes a comment, and re-checks that its session still lives.
const KEEPALIVE: Duration = Duration::from_secs(15);
/// The largest answer lowered in memory. Every answer a session client can reach is a finished one.
const ANSWER_MAX_BYTES: usize = 16 << 20;

/// THE SESSION STATE OF ONE PLANE INSTANCE: the bounded table and, for each live `2024-11-05`
/// session, the sender its event stream reads.
pub(crate) struct SessionServe {
    table: Mutex<SessionTable>,
    outlets: Mutex<HashMap<String, tokio::sync::mpsc::Sender<String>>>,
    /// The ONE randomness source a session id is drawn from: the host's CSPRNG
    /// (the host's installed entropy source). There is no fallback; a failed draw mints nothing.
    draw: fn(&mut [u8]) -> bool,
    /// How many times the ungoverned event-stream warning was emitted: once per instance at most.
    ungoverned_warned: std::sync::atomic::AtomicUsize,
}

impl SessionServe {
    /// An empty table under the default bounds.
    pub(crate) fn new() -> Self {
        Self::drawing_from(busbar_contract::codec::fill_entropy)
    }

    /// An empty table whose ids are drawn from `draw`.
    fn drawing_from(draw: fn(&mut [u8]) -> bool) -> Self {
        Self {
            table: Mutex::new(SessionTable::new(Bounds::default())),
            outlets: Mutex::new(HashMap::new()),
            draw,
            ungoverned_warned: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Opens a session, drawing fresh entropy for each attempt. `None` when no entropy could be
    /// drawn (an id is never minted from a failed draw), or when the table is full and the caller
    /// holds no session of its own that could give way (another owner's is never evicted).
    fn mint(
        &self,
        owner: &Owner,
        revision: Revision,
        carriage: Carriage,
        now: u64,
    ) -> Option<String> {
        for _ in 0..3 {
            let mut entropy = [0u8; 16];
            if !(self.draw)(&mut entropy) {
                return None;
            }
            match held(&self.table).open(entropy, owner.clone(), revision, carriage, now) {
                Ok(id) => {
                    tracing::debug!(session = session::log_prefix(id.as_str()), "session opened");
                    return Some(id.as_str().to_string());
                }
                Err(OpenRefused::Collision) => continue,
                Err(OpenRefused::NoEntropy | OpenRefused::Full) => return None,
            }
        }
        None
    }

    /// The revision and carriage of `sid`, when `owner` holds it.
    fn find(&self, sid: &str, owner: &Owner, now: u64) -> Option<(Revision, Carriage)> {
        let mut t = held(&self.table);
        let revision = t.revision(sid, owner, now)?;
        let carriage = t.carriage(sid, owner, now)?;
        Some((revision, carriage))
    }

    /// THE UNGOVERNED EVENT-STREAM WARNING (reviewer follow-up 2, ARCHITECT 2026-09-29), emitted
    /// the first time this instance opens a `2024-11-05` stream for the shared ungoverned owner. The
    /// plane cannot see the auth chain at boot, so the first such stream is where it learns it.
    fn warn_ungoverned_event_stream(&self) {
        use std::sync::atomic::Ordering;
        if self
            .ungoverned_warned
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            tracing::warn!(
                "a 2024-11-05 event stream was opened with no governance configured: its session \
                 id travels in the message address's URL query, and without an auth chain every \
                 caller shares one owner, so sessions are not isolated between callers. Configure \
                 an auth chain to bind each session to the key that opened it."
            );
        }
    }

    /// How many times [`Self::warn_ungoverned_event_stream`] emitted: 0 or 1.
    #[cfg(test)]
    pub(crate) fn ungoverned_warnings(&self) -> usize {
        self.ungoverned_warned
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn end(&self, sid: &str, owner: &Owner, now: u64) -> bool {
        let closed = held(&self.table).close(sid, owner, now);
        if closed {
            held(&self.outlets).remove(sid);
        }
        closed
    }
}

fn held<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn header_of<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn owner_of(ctx: &PlaneReqCtx) -> Owner {
    Owner {
        principal: ctx
            .principal
            .as_ref()
            .map_or("anonymous", |p| p.actor_id())
            .to_string(),
        credential: ctx
            .gov
            .as_ref()
            .and_then(|g| g.key())
            .map_or_else(|| UNGOVERNED.to_string(), |k| k.id.clone()),
    }
}

fn sessions(ctx: &PlaneReqCtx) -> Arc<SessionServe> {
    super::runtime_of(&ctx.host).sessions.clone()
}

fn session_refusal(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        axum::Json(serde_json::json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

/// The one answer for a session that does not exist, has ended, was evicted, or is someone else's.
fn unknown_session() -> Response {
    session_refusal(
        StatusCode::NOT_FOUND,
        "session_not_found",
        "No such session. Send `initialize` to open a new one.",
    )
}

fn version_disagrees() -> Response {
    session_refusal(
        StatusCode::BAD_REQUEST,
        "protocol_version_mismatch",
        "The protocol version header names a revision other than the one this session negotiated.",
    )
}

fn no_session() -> Response {
    session_refusal(
        StatusCode::SERVICE_UNAVAILABLE,
        "session_unavailable",
        "No session could be opened now; try again.",
    )
}

fn rpc_result(id: Value, result: Value) -> Response {
    axum::Json(serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
}

/// `-32601` for a session client, with `200`: a session client reads `404` as "your session is
/// gone" and re-initialises, so a missing method must not say that.
fn method_absent(id: Value, method: &str) -> Response {
    super::envelope::error_response(
        StatusCode::OK,
        Some(id),
        codec::CODE_METHOD_NOT_FOUND,
        &format!("Method `{method}` is not available in this session's revision."),
        None,
    )
}

// ── POST ────────────────────────────────────────────────────────────────────────────────────────

/// THE POST SWITCH. `None` for a stateless request, which the caller answers exactly as before.
pub(crate) async fn intercept(ctx: &PlaneReqCtx) -> Option<Response> {
    let body: Value = serde_json::from_slice(&ctx.body).ok()?;
    let session_header = header_of(&ctx.headers, adapt::H_SESSION_ID);
    let message_session = adapt::message_session_of(ctx.uri.query());
    match adapt::classify_post(&body, session_header, message_session) {
        PostKind::Stateless => None,
        PostKind::Initialize => Some(initialize(ctx, &body).await),
        PostKind::InSession => Some(in_session(ctx, session_header?, body).await),
        PostKind::EventStreamMessage => {
            Some(event_stream_message(ctx, message_session?, body).await)
        }
    }
}

/// `initialize` on the endpoint: negotiate, answer from discovery, and open the session.
async fn initialize(ctx: &PlaneReqCtx, body: &Value) -> Response {
    let requested = body
        .pointer("/params/protocolVersion")
        .and_then(Value::as_str);
    // The event-stream revision is not carried on the endpoint, so a client asking for it here is
    // offered the latest session revision, as an unknown one is.
    let revision = Some(revision::negotiate(requested))
        .filter(|r| !r.is_event_stream_revision())
        .unwrap_or(revision::SESSION_REVISIONS[0]);
    let svc = sessions(ctx);
    let owner = owner_of(ctx);
    let minted: Mutex<Option<String>> = Mutex::new(None);
    let bytes = ctx.body.clone();
    let (svc, owner, minted_ref) = (&svc, &owner, &minted);
    let answer = shared_envelope(
        ctx,
        &bytes[..],
        |_, _| {},
        move |_value, id, method| async move {
            if method != adapt::METHOD_INITIALIZE {
                return Some(method_absent(id, &method));
            }
            let now = ctx.host.clock_now_ms();
            let Some(sid) = svc.mint(owner, revision, Carriage::Endpoint, now) else {
                return Some(no_session());
            };
            *held(minted_ref) = Some(sid);
            Some(rpc_result(id, initialize_result(ctx, revision).await))
        },
    )
    .await;
    let mut answer = answer;
    if let Some(sid) = held(&minted).take() {
        if let Ok(v) = HeaderValue::from_str(&sid) {
            answer.headers_mut().insert(adapt::H_SESSION_ID, v);
        }
    }
    answer
}

/// A message inside an endpoint session.
async fn in_session(ctx: &PlaneReqCtx, sid: &str, body: Value) -> Response {
    let svc = sessions(ctx);
    let owner = owner_of(ctx);
    let now = ctx.host.clock_now_ms();
    let Some((revision, Carriage::Endpoint)) = svc.find(sid, &owner, now) else {
        return unknown_session();
    };
    if revision::check_header(
        revision,
        header_of(&ctx.headers, super::envelope::H_PROTOCOL_VERSION),
    ) == HeaderCheck::Disagrees
    {
        return version_disagrees();
    }
    let lowered = converse(ctx, &svc, sid, &owner, revision, Carriage::Endpoint, body).await;
    lowered.into_endpoint_answer()
}

/// A message POSTed to a `2024-11-05` stream's address: accepted here, answered on the stream.
async fn event_stream_message(ctx: &PlaneReqCtx, sid: &str, body: Value) -> Response {
    let svc = sessions(ctx);
    let owner = owner_of(ctx);
    let now = ctx.host.clock_now_ms();
    let Some((revision, Carriage::EventStream)) = svc.find(sid, &owner, now) else {
        return unknown_session();
    };
    let Some(outlet) = held(&svc.outlets).get(sid).cloned() else {
        return unknown_session();
    };
    let lowered = converse(
        ctx,
        &svc,
        sid,
        &owner,
        revision,
        Carriage::EventStream,
        body,
    )
    .await;
    if lowered.messages.is_empty() {
        return lowered.into_endpoint_answer();
    }
    for m in &lowered.messages {
        let chunk = adapt::frame(None, Some(adapt::EVENT_MESSAGE), &m.to_string());
        if tokio::time::timeout(OUTLET_SEND, outlet.send(chunk))
            .await
            .map_or(true, |r| r.is_err())
        {
            tracing::debug!(
                session = session::log_prefix(sid),
                "event stream reader gone"
            );
            break;
        }
    }
    StatusCode::ACCEPTED.into_response()
}

/// Runs `bytes` through the shared envelope reader (`Origin`, parse, JSON-RPC shape, `202` for a
/// notification), then `dispatch`.
async fn shared_envelope<'a, F, Fut>(
    ctx: &'a PlaneReqCtx,
    bytes: &'a [u8],
    notify: impl FnOnce(&str, &Value),
    dispatch: F,
) -> Response
where
    F: FnOnce(Value, Value, String) -> Fut,
    Fut: std::future::Future<Output = Option<Response>>,
{
    let resource = super::resource_of(&ctx.host);
    protocol::serve(
        &super::envelope::McpWords,
        protocol::Request {
            present: resource.is_some(),
            origin: header_of(&ctx.headers, "origin"),
            allowed_origins: resource.as_ref().map_or(&[][..], |r| r.allowed_origins()),
            wire_refusal: None,
            body: bytes,
        },
        notify,
        dispatch,
    )
    .await
}

/// ONE SESSION MESSAGE, answered by the one dispatch and lowered into the session's revision.
async fn converse(
    ctx: &PlaneReqCtx,
    svc: &SessionServe,
    sid: &str,
    owner: &Owner,
    revision: Revision,
    carriage: Carriage,
    mut value: Value,
) -> Lowered {
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_string);
    let has_id = value.get("id").is_some_and(|v| !v.is_null());
    let mut headers = ctx.headers.clone();
    if adapt::session_method(method.as_deref(), has_id) == SessionMethod::Dispatch {
        if let Some(mirror) = adapt::raise(&mut value) {
            mirror_into(ctx, &mut headers, &mirror, &value);
        }
    }
    let bytes = serde_json::to_vec(&value).unwrap_or_default();
    let now = ctx.host.clock_now_ms();
    let answer = shared_envelope(
        ctx,
        &bytes,
        |m, _| {
            if m == adapt::METHOD_INITIALIZED {
                held(&svc.table).mark_initialized(sid, owner, now);
            } else if m == super::roots::METHOD_NOTIFY_ROOTS_LIST_CHANGED {
                super::runtime_of(&ctx.host)
                    .roots_epochs
                    .note_change(&owner.credential);
            }
        },
        |value, id, method| {
            let headers = &headers;
            async move {
                if method == adapt::METHOD_INITIALIZE && carriage == Carriage::EventStream {
                    return Some(rpc_result(id, initialize_result(ctx, revision).await));
                }
                match adapt::session_method(Some(&method), true) {
                    SessionMethod::Ping => Some(rpc_result(id, serde_json::json!({}))),
                    SessionMethod::Dispatch => {
                        let (Some(gov), Some(principal)) =
                            (ctx.gov.as_ref(), ctx.principal.as_ref())
                        else {
                            return Some(method_absent(id, &method));
                        };
                        Some(
                            super::envelope::rpc_dispatch(
                                &ctx.host,
                                gov,
                                principal,
                                headers,
                                value,
                                id.clone(),
                                method.clone(),
                            )
                            .await
                            .unwrap_or_else(|| method_absent(id, &method)),
                        )
                    }
                    SessionMethod::Accept | SessionMethod::NotFound => {
                        Some(method_absent(id, &method))
                    }
                }
            }
        },
    )
    .await;
    lower(answer).await
}

/// The header mirror a raised request carries: the stateless revision's version, method and name
/// headers, and the custom parameter headers the tool's schema annotates.
fn mirror_into(ctx: &PlaneReqCtx, headers: &mut HeaderMap, mirror: &adapt::Mirror, value: &Value) {
    use super::envelope::{
        H_MCP_METHOD as METHOD_HEADER, H_MCP_NAME as NAME_HEADER, H_PROTOCOL_VERSION,
    };
    headers.remove(adapt::H_SESSION_ID);
    headers.remove(adapt::H_LAST_EVENT_ID);
    // JSON first: a raised request's answer is lowered in memory, never relayed as a stream.
    headers.insert(
        "accept",
        HeaderValue::from_static("application/json, text/event-stream"),
    );
    headers.insert(H_PROTOCOL_VERSION, HeaderValue::from_static(mirror.version));
    if let Ok(v) = HeaderValue::from_str(&mirror.method) {
        headers.insert(METHOD_HEADER, v);
    }
    headers.remove(NAME_HEADER);
    if let Some(name) = &mirror.name {
        let encoded = encode_sentinel(name);
        if let Ok(v) = HeaderValue::from_str(&encoded) {
            headers.insert(NAME_HEADER, v);
        }
        if mirror.method == "tools/call" {
            let rt = super::runtime_of(&ctx.host);
            let schema = rt.catalogue.input_schema_of(name);
            let arguments = value.pointer("/params/arguments");
            for (k, v) in adapt::param_mirror(schema, arguments) {
                if let (Ok(k), Ok(v)) = (
                    HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_str(&v),
                ) {
                    headers.insert(k, v);
                }
            }
        }
    }
}

/// The `initialize` result, built from what `server/discover` answers this caller.
async fn initialize_result(ctx: &PlaneReqCtx, revision: Revision) -> Value {
    let empty = serde_json::json!({});
    let discovery = discover(ctx).await.unwrap_or(empty);
    adapt::initialize_result(&discovery, revision, false)
}

async fn discover(ctx: &PlaneReqCtx) -> Option<Value> {
    let (gov, principal) = (ctx.gov.as_ref()?, ctx.principal.as_ref()?);
    let mut probe = serde_json::json!({ "jsonrpc": "2.0", "id": 0, "method": "server/discover" });
    let mirror = adapt::raise(&mut probe)?;
    let mut headers = ctx.headers.clone();
    mirror_into(ctx, &mut headers, &mirror, &probe);
    let answer = super::envelope::rpc_dispatch(
        &ctx.host,
        gov,
        principal,
        &headers,
        probe,
        Value::from(0),
        mirror.method.clone(),
    )
    .await?;
    let bytes = axum::body::to_bytes(answer.into_body(), ANSWER_MAX_BYTES)
        .await
        .ok()?;
    serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .get("result")
        .cloned()
}

/// A dispatched answer, read back and lowered.
struct Lowered {
    status: StatusCode,
    accepted: bool,
    messages: Vec<Value>,
    passthrough: Option<Response>,
}

async fn lower(answer: Response) -> Lowered {
    let status = answer.status();
    if status == StatusCode::ACCEPTED {
        return Lowered {
            status,
            accepted: true,
            messages: Vec::new(),
            passthrough: None,
        };
    }
    let is_stream = answer
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"));
    let Ok(bytes) = axum::body::to_bytes(answer.into_body(), ANSWER_MAX_BYTES).await else {
        return Lowered {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            accepted: false,
            messages: Vec::new(),
            passthrough: None,
        };
    };
    let mut messages: Vec<Value> = if is_stream {
        String::from_utf8_lossy(&bytes)
            .split("\n\n")
            .filter_map(|event| {
                let data: Vec<&str> = event
                    .lines()
                    .filter_map(|l| l.strip_prefix("data:"))
                    .map(str::trim_start)
                    .collect();
                serde_json::from_str(&data.join("\n")).ok()
            })
            .collect()
    } else {
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) => vec![v],
            Err(_) => {
                let rebuilt = (status, bytes).into_response();
                return Lowered {
                    status,
                    accepted: false,
                    messages: Vec::new(),
                    passthrough: Some(rebuilt),
                };
            }
        }
    };
    for m in &mut messages {
        let Some(r) = m.get_mut("result") else {
            continue;
        };
        if adapt::lower_result(r).is_err() {
            let id = m.get("id").cloned().unwrap_or(Value::Null);
            *m = error_body(
                id,
                codec::CODE_INTERNAL,
                "The answer to this request cannot be expressed in this session's revision.",
                None,
            );
        }
    }
    // A session client reads `404` as a session that is gone, so no answer to a message it sent
    // inside a live session may carry it.
    let status = if status == StatusCode::NOT_FOUND {
        StatusCode::OK
    } else {
        status
    };
    Lowered {
        status,
        accepted: false,
        messages,
        passthrough: None,
    }
}

impl Lowered {
    fn into_endpoint_answer(self) -> Response {
        if let Some(r) = self.passthrough {
            return r;
        }
        if self.accepted {
            return StatusCode::ACCEPTED.into_response();
        }
        match self.messages.as_slice() {
            [one] => (self.status, axum::Json(one.clone())).into_response(),
            many => {
                let body: String = many
                    .iter()
                    .map(|m| adapt::frame(None, None, &m.to_string()))
                    .collect();
                (
                    self.status,
                    [
                        ("content-type", "text/event-stream"),
                        ("cache-control", "no-cache, no-store"),
                    ],
                    body,
                )
                    .into_response()
            }
        }
    }
}

// ── GET ─────────────────────────────────────────────────────────────────────────────────────────

fn accepts_event_stream(headers: &HeaderMap) -> bool {
    header_of(headers, "accept").is_some_and(|a| {
        a.split(',').any(|m| {
            m.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("text/event-stream")
        })
    })
}

/// GET on the endpoint: a session's stream (or its resumption), the `2024-11-05` stream, or `405`.
pub(crate) async fn serve_get(ctx: PlaneReqCtx) -> Response {
    let svc = sessions(&ctx);
    let owner = owner_of(&ctx);
    let now = ctx.host.clock_now_ms();
    let version = header_of(&ctx.headers, super::envelope::H_PROTOCOL_VERSION);
    if let Some(sid) = header_of(&ctx.headers, adapt::H_SESSION_ID) {
        let Some((revision, Carriage::Endpoint)) = svc.find(sid, &owner, now) else {
            return unknown_session();
        };
        if revision::check_header(revision, version) == HeaderCheck::Disagrees {
            return version_disagrees();
        }
        let head = if let Some(cursor) = header_of(&ctx.headers, adapt::H_LAST_EVENT_ID) {
            let Some(replay) = held(&svc.table).replay(sid, &owner, cursor, now) else {
                return unknown_session();
            };
            replay
                .events
                .iter()
                .map(|(id, data)| adapt::frame(Some(id), None, data))
                .collect::<String>()
        } else {
            let mut t = held(&svc.table);
            let Some(stream) = t.open_stream(sid, &owner, now) else {
                return unknown_session();
            };
            // `2025-11-25` primes a resumable stream with an event carrying only an id; the earlier
            // revision's clients read every event's data as a message, so theirs is not primed.
            if revision == Revision::R2025_11_25 {
                let Some(event_id) = t.push(sid, &owner, stream, "", now) else {
                    return unknown_session();
                };
                adapt::frame(Some(&event_id), None, "")
            } else {
                String::new()
            }
        };
        return event_stream(
            OpenStreamGuard {
                svc: svc.clone(),
                sid: sid.to_string(),
                owner,
                host: ctx.host.clone(),
                outlet: None,
                ends_session: false,
            },
            head,
        );
    }
    if !accepts_event_stream(&ctx.headers)
        || revision::sessionless_get(version) == SessionlessGet::NotAllowed
    {
        return super::envelope::legacy_verb(ctx).await;
    }
    if owner.credential == UNGOVERNED {
        svc.warn_ungoverned_event_stream();
    }
    let Some(sid) = svc.mint(&owner, Revision::R2024_11_05, Carriage::EventStream, now) else {
        return no_session();
    };
    let (tx, rx) = tokio::sync::mpsc::channel(OUTLET_DEPTH);
    held(&svc.outlets).insert(sid.clone(), tx);
    let mount = super::resource_of(&ctx.host)
        .map_or_else(|| ctx.path.clone(), |r| r.mount_path().to_string());
    let head = adapt::endpoint_event(&mount, &sid);
    event_stream(
        OpenStreamGuard {
            svc,
            sid,
            owner,
            host: ctx.host.clone(),
            outlet: Some(rx),
            ends_session: true,
        },
        head,
    )
}

/// One open event stream. Dropped when the client goes away; a `2024-11-05` session ends with it.
struct OpenStreamGuard {
    svc: Arc<SessionServe>,
    sid: String,
    owner: Owner,
    host: Arc<dyn EngineHost>,
    outlet: Option<tokio::sync::mpsc::Receiver<String>>,
    ends_session: bool,
}

impl Drop for OpenStreamGuard {
    fn drop(&mut self) {
        if self.ends_session {
            let now = self.host.clock_now_ms();
            self.svc.end(&self.sid, &self.owner, now);
            tracing::debug!(
                session = session::log_prefix(&self.sid),
                "event stream closed"
            );
        }
    }
}

fn event_stream(live: OpenStreamGuard, head: String) -> Response {
    let first = futures::stream::once(async move {
        Ok::<_, std::convert::Infallible>(bytes::Bytes::from(head))
    });
    let tail = futures::stream::unfold(live, |mut live| async move {
        let got = match live.outlet.as_mut() {
            Some(rx) => tokio::time::timeout(KEEPALIVE, rx.recv()).await.ok(),
            None => {
                tokio::time::sleep(KEEPALIVE).await;
                None
            }
        };
        match got {
            Some(Some(chunk)) => Some((Ok(bytes::Bytes::from(chunk)), live)),
            Some(None) => None,
            None => {
                let now = live.host.clock_now_ms();
                held(&live.svc.table).revision(&live.sid, &live.owner, now)?;
                Some((Ok(bytes::Bytes::from_static(b": keepalive\n\n")), live))
            }
        }
    });
    let body = axum::body::Body::from_stream(futures::StreamExt::chain(first, tail));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache, no-store")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ── DELETE ──────────────────────────────────────────────────────────────────────────────────────

/// DELETE on the endpoint: ends a session the caller holds, or `405` without one.
pub(crate) async fn serve_delete(ctx: PlaneReqCtx) -> Response {
    let Some(sid) = header_of(&ctx.headers, adapt::H_SESSION_ID).map(str::to_string) else {
        return super::envelope::legacy_verb(ctx).await;
    };
    let svc = sessions(&ctx);
    let owner = owner_of(&ctx);
    if svc.end(&sid, &owner, ctx.host.clock_now_ms()) {
        tracing::debug!(session = session::log_prefix(&sid), "session ended");
        StatusCode::NO_CONTENT.into_response()
    } else {
        unknown_session()
    }
}

#[cfg(test)]
#[path = "tests/session_draw_tests.rs"]
mod draw_tests;
