// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNARY RELAY, AS THE KERNEL'S ROUTE PUMP DRIVES IT (`BUSBAR-1.6.0.md` Part 3, section 12):
//! one JSON-RPC hop to the agent the kernel's walk picked, in the order the pump pushes its pieces,
//! and what the plane answers each with. Ported from the served engine's hop
//! (`busbar-a2a` `relay::relay_once`, `relay::read_reply`, `relay::build_request`,
//! `receive::refuse_hop_early`, `refusal_client`); the kernel now owns what the engine did around
//! it (the guard and pin, the live trust gate, the breaker, the lease's auth fields, the walk).
//!
//! | piece | answer |
//! |---|---|
//! | ATTEMPT (the agent the walk picked) | `POST` at the agent's own path, `content-type`, `accept`, `a2a-version` |
//! | the caller's body | relayed to the far end VERBATIM: busbar is content-blind on this plane |
//! | the far end's answer | gathered; on its last piece, the caller's answer |
//!
//! The caller's answer is the backend's `result` in busbar's own envelope (`200`), or a refusal
//! in the engine's fixed words (`502`, `-32006`): a status outside 2xx, a reply over the ceiling, a
//! reply that is not JSON, one that answers a different request, or the backend's own JSON-RPC
//! `error`. No refusal echoes a byte the backend or its address chose.
//!
//! A hop that EXPECTS EVENTS ([`Relay::expect_events`]: the engine's event-stream hop) accepts an
//! event stream or one document. A 2xx far end's bytes are framed as they come
//! ([`crate::sse::SseReader`]) and each event is read ([`crate::events::read_event`]) and answered
//! at once: the first event commits the caller's answer to an event stream, and every event that
//! reports a state or an artifact is settled on the task as it passes. A far end that frames no
//! event answers one document, which is read as the unary hop reads it. A frame that answers a
//! different request, or an unterminated event over the ceiling, refuses the hop before the first
//! event and ends the stream, its task `failed`, after it.
//!
//! Every answer is plain data; writing it into the host's buffers is the door's job. A new ATTEMPT
//! forgets what the previous attempt's far end said.

use busbar_contract::jsonrpc::{read_response, NotAnAnswerKind, Reply as RpcReply};
use serde_json::{json, Value};

use crate::a2a::task::TaskState;
use crate::arrival::{Refusal, JSON_MEDIA_TYPE};
use crate::binding::{self, Binding};
use crate::events::{self, ACCEPT_EVENTS};
use crate::identity;
use crate::sse::SseReader;

/// The verb every JSON-RPC hop is sent with.
pub const VERB: &str = "POST";

/// The `accept` a unary hop declares: the one document it reads.
pub const ACCEPT_UNARY: &str = JSON_MEDIA_TYPE;

/// The head field naming a body's media type.
pub const H_CONTENT_TYPE: &str = "content-type";
/// The head field naming the media types the hop reads.
pub const H_ACCEPT: &str = "accept";

/// The most reply bytes a hop reads (the engine's `FetchPolicy::max_body_bytes`): an unbounded read
/// is an allocation the backend chooses the size of.
pub const MAX_REPLY_BYTES: usize = 512 * 1024;

/// The status every refused hop answers with.
pub const STATUS_BAD_GATEWAY: u32 = 502;

/// The status a hop to an agent that is not currently serving is refused with.
pub const STATUS_NOT_SERVING: u32 = 503;

/// The sentence a hop to an agent that is not currently serving is refused with.
pub const NOT_SERVING: &str = "this agent is not currently serving";

/// The status a relayed answer is given.
pub const STATUS_OK: u32 = 200;

/// `InvalidAgentResponse`, the code every refused hop carries.
pub const CODE_INVALID_AGENT_RESPONSE: i64 = -32006;

/// The words a task hop that did not complete is refused with (the engine's `fail_task`).
pub const TASK_UNCOMPLETED: &str = "the backend agent did not complete this task";

/// The words an extended-card read through the relay that could not be made is refused with (the
/// engine's `card_fetch` arm of `receive.rs`).
pub const CARD_UNFETCHED: &str = "the extended agent card could not be fetched";
/// JSON-RPC's own internal error: a gRPC far end's error status that names no A2A code.
const CODE_INTERNAL_ERROR: i64 = -32603;

/// Who pushed a piece.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum From<'a> {
    /// The caller: the request body.
    Caller,
    /// The far end: its answer.
    FarEnd,
    /// The kernel: an ATTEMPT, with the URL the operator wrote for the agent it picked (`None`
    /// when the plane's section names no such agent).
    Kernel(Option<&'a str>),
}

/// One piece, as the door read it off the crossing.
#[derive(Debug, Clone, Copy)]
pub struct Piece<'a> {
    /// Who pushed it.
    pub from: From<'a>,
    /// Its bytes.
    pub bytes: &'a [u8],
    /// On the far end's first piece: the status it answered.
    pub status: Option<u32>,
    /// No piece of this `from` follows.
    pub last: bool,
}

/// The request one attempt sends the far end: the verb, the target under the agent's origin, and
/// the head fields in the order the engine wrote them. The kernel leads them with the member's auth
/// fields and sends the body that follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// The verb.
    pub verb: &'static str,
    /// The target: the agent URL's path and query.
    pub target: String,
    /// The head fields, in order.
    pub fields: Vec<(&'static str, String)>,
}

/// What the caller is answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The status.
    pub status: u32,
    /// The body's media type.
    pub content_type: &'static str,
    /// The body.
    pub body: Vec<u8>,
}

/// PART OF AN ANSWER IN EVENTS: whether it starts the caller's answer (its head: `200`, an event
/// stream), the whole events it carries, and whether it ends the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// It starts the caller's answer.
    pub head: bool,
    /// Whole events.
    pub body: Vec<u8>,
    /// No part follows: the unit is done.
    pub last: bool,
}

/// The plane's answer to one piece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Nothing to emit yet.
    Nothing,
    /// The request this attempt sends the far end; its body follows as [`Answer::ToFarEnd`].
    Attempt(Attempt),
    /// The request's body, bound for the far end.
    ToFarEnd(Vec<u8>),
    /// The caller's whole answer: the unit is done.
    ToCaller(Reply),
    /// Part of the caller's answer in events.
    Part(Part),
    /// The piece is one this relay never takes.
    Refused,
}

/// WHY A HOP HAS NO ANSWER TO RELAY, in the arms the plane can see (the engine's `RelayRefusal`;
/// the guard, the trust gate, the lease and the breaker are the kernel's now).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopRefusal {
    /// The backend answered outside 2xx.
    Status,
    /// The reply was over [`MAX_REPLY_BYTES`].
    BodyTooLarge,
    /// The reply is not a JSON-RPC answer.
    NotJson,
    /// The backend answered with a JSON-RPC `error`.
    BackendError,
    /// The reply names a different request.
    Uncorrelated,
    /// The agent is not currently serving: its re-verification demoted it.
    NotServing,
    /// The egress guard refused the agent's registered endpoint.
    EndpointRefused,
    /// The hop left for the agent and no answer came back: the connection could not be made, or
    /// it closed before the agent answered (the engine's `RelayRefusal::Transport`).
    Transport,
}

impl HopRefusal {
    /// The stable token a caller may quote (the engine's `RelayRefusal::client_code`).
    #[must_use]
    pub const fn client_code(self) -> &'static str {
        match self {
            HopRefusal::Status => "a2a.hop.backend_status",
            HopRefusal::BodyTooLarge => "a2a.hop.reply_too_large",
            HopRefusal::NotJson => "a2a.hop.reply_not_json",
            HopRefusal::BackendError => "a2a.hop.backend_refused",
            HopRefusal::Uncorrelated => "a2a.hop.reply_uncorrelated",
            HopRefusal::NotServing => "a2a.hop.agent_not_serving",
            HopRefusal::EndpointRefused => "a2a.hop.endpoint_refused",
            HopRefusal::Transport => "a2a.hop.transport_failed",
        }
    }

    /// The caller's sentence: fixed per arm, interpolating nothing a backend, its address or its
    /// bytes could choose (the engine's `RelayRefusal::client_text`).
    #[must_use]
    pub fn client_text(self) -> String {
        let sentence = match self {
            HopRefusal::Status => "this agent's backend refused busbar's request",
            HopRefusal::BodyTooLarge => {
                "this agent's backend replied with more than the configured ceiling"
            }
            HopRefusal::NotJson => {
                "this agent's backend replied with something that is not a JSON-RPC answer"
            }
            HopRefusal::BackendError => "this agent's backend refused the request",
            HopRefusal::Uncorrelated => {
                "this agent's backend answered something busbar cannot correlate to the request it \
                 sent, so it is refused rather than relayed"
            }
            HopRefusal::NotServing => NOT_SERVING,
            HopRefusal::EndpointRefused => {
                "busbar's egress guard refused the registered endpoint for this agent"
            }
            HopRefusal::Transport => "busbar could not reach this agent's backend",
        };
        format!("{}: {sentence}", self.client_code())
    }

    /// The OPERATOR's sentence (the engine's `RelayRefusal` `Display`, `relay.rs:499`): it names the
    /// backend's `url` on purpose, because a journal line is for diagnosing the backend. Never put
    /// in a reply to a caller.
    #[must_use]
    pub fn operator(self, url: &str, status: Option<u32>) -> String {
        match self {
            HopRefusal::Status => match status {
                Some(status) => format!("the backend agent at `{url}` answered HTTP {status}"),
                None => format!("the backend agent at `{url}` answered outside 2xx"),
            },
            HopRefusal::BodyTooLarge => {
                format!("the backend agent at `{url}` replied over the configured ceiling")
            }
            HopRefusal::NotJson => {
                format!("the backend agent at `{url}` replied with something that is not JSON")
            }
            HopRefusal::BackendError => format!("the backend agent at `{url}` refused the task"),
            HopRefusal::Uncorrelated => format!(
                "the backend agent at `{url}` answered something busbar cannot correlate to the \
                 request it sent, so it is refused rather than relayed"
            ),
            HopRefusal::NotServing => self.client_text(),
            HopRefusal::EndpointRefused => format!("the relay target `{url}` was refused"),
            HopRefusal::Transport => {
                format!("the relayed submission to `{url}` failed: no answer came back")
            }
        }
    }

    /// The caller's answer: the one error envelope, `-32006` with its `ErrorInfo`, at `502` (the
    /// engine's `receive::refuse_hop_early`).
    #[must_use]
    pub fn reply(self, id: &Value) -> Reply {
        let refusal = Refusal {
            status: STATUS_BAD_GATEWAY,
            id: Some(id.clone()),
            code: CODE_INVALID_AGENT_RESPONSE,
            message: self.client_text(),
        };
        Reply {
            status: STATUS_BAD_GATEWAY,
            content_type: JSON_MEDIA_TYPE,
            body: serde_json::to_vec(&refusal.envelope()).unwrap_or_default(),
        }
    }
}

/// The far end's whole answer, read AS THE ANSWER TO `id`: its `result`, or why it is refused (the
/// engine's `relay_once` checks after the send, then `read_reply`).
///
/// # Errors
///
/// The [`HopRefusal`] the answer earns.
pub fn read_answer(status: u32, body: &[u8], id: &Value) -> Result<Value, HopRefusal> {
    if !(200..300).contains(&status) {
        return Err(HopRefusal::Status);
    }
    if body.len() > MAX_REPLY_BYTES {
        return Err(HopRefusal::BodyTooLarge);
    }
    let envelope: Value = serde_json::from_slice(body).map_err(|_| HopRefusal::NotJson)?;
    match read_response(&envelope, id) {
        Ok(RpcReply::Result(result)) => Ok(result),
        Ok(RpcReply::Error { .. }) => Err(HopRefusal::BackendError),
        Err(e) => Err(match e.kind {
            NotAnAnswerKind::Uncorrelated => HopRefusal::Uncorrelated,
            NotAnAnswerKind::NotAResponse => HopRefusal::NotJson,
        }),
    }
}

/// An HTTP+JSON far end's whole answer, read as the answer to `id` once re-wrapped into the
/// JSON-RPC envelope ([`binding::rewrap`]); `None` when a 2xx body is not JSON (unframable).
fn read_rest_answer(status: u32, body: &[u8], id: &Value) -> Option<Result<Value, HopRefusal>> {
    if !(200..300).contains(&status) {
        return Some(Err(HopRefusal::Status));
    }
    if body.len() > MAX_REPLY_BYTES {
        return Some(Err(HopRefusal::BodyTooLarge));
    }
    let envelope = binding::rewrap(body, id).ok()?;
    Some(read_answer(status, &envelope, id))
}

/// The caller's answer to a relayed `result`, VERBATIM, under the caller's own `id`.
#[must_use]
pub fn relayed(id: &Value, result: Value) -> Reply {
    Reply {
        status: STATUS_OK,
        content_type: JSON_MEDIA_TYPE,
        body: serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": result }))
            .unwrap_or_default(),
    }
}

/// The target an attempt is sent at: the agent URL's path and query. The kernel joins it onto the
/// agent's origin, so the far end is posted to at exactly the URL the operator wrote (the JSON-RPC
/// binding appends nothing). `None` for a URL that does not parse.
#[must_use]
pub fn target_of(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let mut target = parsed.path().to_string();
    if let Some(query) = parsed.query() {
        target.push('?');
        target.push_str(query);
    }
    Some(target)
}

/// WHAT THE FAR END'S ANSWER SAYS ABOUT THE FAR END (the breaker's reading; the engine's
/// `classify_hop`, read where the answer's structure still exists): a well-formed protocol answer —
/// a result, or an error the protocol defines, at whatever status it came — is the destination
/// answering, the WORK failing and not the wire; a `401`/`403` is a hard refusal of busbar itself;
/// a `5xx` or `429` with no protocol answer in it is transient, as is a `2xx` whose body is not a
/// usable answer; any other `4xx` is the caller's. An answer this table does not read states
/// nothing, and the kernel's status table reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    /// The destination answered.
    Healthy,
    /// The caller's request was refused.
    Caller,
    /// A failure the destination may recover from.
    Transient,
    /// The destination refuses busbar itself.
    Hard,
}

/// The reading of a far end's whole answer at `status`, its body `body`, on `binding`, read as the
/// answer to `id` ([`Reading`]).
#[must_use]
pub fn reading_of(status: u32, body: &[u8], id: &Value, binding: Binding) -> Option<Reading> {
    if matches!(status, 401 | 403) {
        return Some(Reading::Hard);
    }
    if (200..300).contains(&status) {
        let answer = match binding {
            // A gRPC answer is read once transcoded to the JSON-RPC envelope it is.
            Binding::JsonRpc | Binding::Grpc => read_answer(status, body, id),
            // A 2xx body that is not JSON cannot be framed: the engine recorded nothing for it.
            Binding::HttpJson => read_rest_answer(status, body, id)?,
        };
        return Some(match answer {
            Ok(_) | Err(HopRefusal::BackendError) => Reading::Healthy,
            Err(_) => Reading::Transient,
        });
    }
    // Outside 2xx: an error the protocol defines, correlated to the request, is still the
    // destination answering (the JSON-RPC binding's error envelope).
    let protocol = binding == Binding::JsonRpc
        && body.len() <= MAX_REPLY_BYTES
        && serde_json::from_slice::<Value>(body)
            .ok()
            .is_some_and(|envelope| read_response(&envelope, id).is_ok());
    if protocol {
        return Some(Reading::Healthy);
    }
    match status {
        429 | 500..=599 => Some(Reading::Transient),
        400..=499 => Some(Reading::Caller),
        _ => None,
    }
}

/// ONE UNARY HOP: the caller's request id and negotiated version, and what the current attempt's
/// far end has said so far.
#[derive(Debug, Clone)]
pub struct Relay {
    id: Value,
    version: &'static str,
    sent: u64,
    status: Option<u32>,
    far: Vec<u8>,
    received: u64,
    answered: bool,
    task: Option<TaskHop>,
    instead: Option<Vec<u8>>,
    instead_sent: bool,
    settled: Vec<Settled>,
    binding: Binding,
    method: String,
    params: Value,
    events: Option<Events>,
    /// The reading of the far end's answer, once the answer says enough to read ([`Reading`]).
    reading: Option<Reading>,
    /// On the gRPC binding: what the far end's messages and trailers have said so far.
    grpc: GrpcRead,
    /// The agent this hop is for and its registered backend url: what the OPERATOR's journal line
    /// for a refusal names, and the one place either is held. Never part of a caller's answer.
    agent: String,
    url: String,
}

/// HOW FAR A gRPC FAR END'S ANSWER HAS BEEN READ: the length-prefixed bytes of an answer in events
/// not yet a whole message, and how the call ended, once its trailers said.
#[derive(Debug, Clone, Default)]
struct GrpcRead {
    pending: Vec<u8>,
    ended: Option<crate::framed::Ended>,
}

/// How far a hop that expects events has read its far end's answer.
#[derive(Debug, Clone, Default)]
struct Events {
    reader: SseReader,
    /// A frame was read: the answer is a stream, not one document.
    framed: bool,
    /// The far end answered one document: it is read whole, as a unary hop's is.
    document: bool,
    /// The caller's answer has started: no refusal is expressible any more.
    committed: bool,
}

/// Whether a frame is an event: its first line is an event-stream field or a comment, never the
/// first line of a document.
fn is_event(frame: &str) -> bool {
    let first = frame.trim_start_matches(['\r', '\n']);
    [":", "data", "event", "id", "retry"]
        .iter()
        .any(|field| first.starts_with(field))
}

/// THE TASK A RELAYED HOP IS FOR (ARCHITECT ruling B1): busbar's identity for it, whether the
/// request addressed a task the caller already holds, and the skill the arrival matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskHop {
    /// busbar's task id.
    pub task_id: String,
    /// busbar's `contextId`.
    pub context_id: String,
    /// The request named a task the caller holds: a failed hop says nothing about that task.
    pub addressed: bool,
    /// The skill the arrival matched, annotated on the answer.
    pub skill: Option<String>,
}

/// WHAT A TASK HOP'S ANSWER SAYS ABOUT ITS TASK, for the door to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settled {
    /// The far end answered: the state it reported, and its own id for the task.
    Reported {
        /// The reported state (`Working` when none could be read).
        state: TaskState,
        /// The far end's own task id, before the rewrite.
        backend_id: Option<String>,
    },
    /// The hop failed a task it opened: the task ends `failed`.
    Failed,
    /// One relayed event: the state it reported, whether it carried an artifact, and the far
    /// end's own id for the task.
    Event {
        /// The state it reported, if one this build can read.
        state: Option<TaskState>,
        /// It carried an artifact chunk.
        artifact: bool,
        /// The far end's own task id, before the rewrite.
        backend_id: Option<String>,
    },
}

impl Relay {
    /// A hop answering the request `id`, declaring the `version` busbar's edge negotiated.
    #[must_use]
    pub fn new(id: Value, version: &'static str) -> Self {
        Relay {
            id,
            version,
            sent: 0,
            status: None,
            far: Vec::new(),
            received: 0,
            answered: false,
            task: None,
            instead: None,
            instead_sent: false,
            settled: Vec::new(),
            binding: Binding::JsonRpc,
            method: String::new(),
            params: Value::Null,
            events: None,
            reading: None,
            grpc: GrpcRead::default(),
            agent: String::new(),
            url: String::new(),
        }
    }

    /// Name the agent this hop is for and its registered backend `url`, for the operator's journal
    /// (`journal`). The caller's answers never carry either.
    pub fn name_backend(&mut self, agent: &str, url: &str) {
        self.agent = agent.to_string();
        self.url = url.to_string();
    }

    /// THE OPERATOR'S LINE for a refused hop: the backend's url and the reason, at debug (predev
    /// `receive.rs:3326` `refuse_hop` for a hop with a task context, `:3300` `refuse_hop_early`
    /// for one without, `:3131` for a stream that ended in a refusal). The caller's answer is
    /// [`HopRefusal::reply`] and names no backend.
    fn journal(&self, refusal: HopRefusal, stream: bool) {
        let (agent, url) = (self.agent.as_str(), self.url.as_str());
        let error = refusal.operator(url, self.status);
        match (&self.task, stream) {
            (Some(task), true) => busbar_contract::diag_debug!(
                crate::diagnostics::A2A_RELAYED_STREAM_REFUSED,
                task = %task.task_id,
                error = %error,
                "a2a: the relayed stream ended in a refusal"
            ),
            (Some(task), false) => busbar_contract::diag_debug!(
                crate::diagnostics::A2A_RELAYED_SUBMISSION_FAILED,
                agent = %agent,
                task = %task.task_id,
                error = %error,
                "a2a: the relayed task submission failed"
            ),
            (None, _) => busbar_contract::diag_debug!(
                crate::diagnostics::A2A_RELAYED_SUBMISSION_FAILED,
                code = %refusal.client_code(),
                error = %error,
                "a2a: a hop was refused before a task context existed"
            ),
        }
    }

    /// The binding the hop's attempts speak.
    #[must_use]
    pub const fn binding(&self) -> Binding {
        self.binding
    }

    /// The reading of the far end's answer, once: on the piece that holds the whole answer, or on
    /// the first event of a stream ([`Reading`]); `None` until then (and for an answer the table
    /// does not read).
    pub fn take_reading(&mut self) -> Option<Reading> {
        self.reading.take()
    }

    /// The hop's answer may be a stream of events (the engine's event-stream hop): its attempts
    /// accept one, and its far end's events are answered as they come.
    pub fn expect_events(&mut self) {
        self.events = Some(Events::default());
    }

    /// Whether the hop's answer may be a stream of events ([`Self::expect_events`]).
    #[must_use]
    pub const fn expects_events(&self) -> bool {
        self.events.is_some()
    }

    /// The `accept` an attempt declares.
    fn accept(&self) -> &'static str {
        if self.events.is_some() {
            ACCEPT_EVENTS
        } else {
            ACCEPT_UNARY
        }
    }

    /// The binding the next attempt speaks (ARCHITECT ruling B4), for the request `envelope` (the
    /// translated one, when a task id was translated): HTTP+JSON composes its request line from the
    /// envelope's `method` and `params`. The request is read once, at the first attempt's binding;
    /// each following attempt keeps it.
    pub fn bind(&mut self, binding: Binding, envelope: &Value) {
        let first = self.method.is_empty() && self.params.is_null();
        self.binding = binding;
        if !first {
            return;
        }
        let translated = self
            .instead
            .as_deref()
            .and_then(|b| serde_json::from_slice::<Value>(b).ok());
        let envelope = translated.as_ref().unwrap_or(envelope);
        self.method = envelope
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        self.params = envelope.get("params").cloned().unwrap_or(Value::Null);
    }

    /// REFUSED BY NAME before the hop: the agent's card declares only `word`, a binding the plane
    /// does not frame (the engine's early `Unframable` refusal; the task stays as it is).
    pub fn refuse_unspeakable(&mut self, word: &str) -> Answer {
        self.answered = true;
        Answer::ToCaller(self.unframable_reply(word))
    }

    /// REFUSED AT THE HOP'S TRUST GATE: the agent was serving at admission and its re-verification
    /// demoted it (the engine's `RelayRefusal::Demoted`, as `receive::refuse_hop` and
    /// `refuse_hop_early` answer it). A fresh task is answered `503` naming it and stays as opened —
    /// a demotion does not burn it; a task the caller addressed is a failed read (`502`), never a
    /// failed task; a task-less hop is refused early in the hop's own words (`503`).
    pub fn refuse_demoted(&mut self) -> Answer {
        self.answered = true;
        let reply = match &self.task {
            Some(task) if task.addressed => task_refusal(None, task, &self.id).0,
            Some(task) => {
                let refusal = Refusal {
                    status: STATUS_NOT_SERVING,
                    id: Some(self.id.clone()),
                    code: crate::arrival::CODE_UNSUPPORTED_OPERATION,
                    message: NOT_SERVING.to_string(),
                };
                Reply {
                    status: STATUS_NOT_SERVING,
                    content_type: JSON_MEDIA_TYPE,
                    body: serde_json::to_vec(&identity::about_task(&refusal, &task.task_id))
                        .unwrap_or_default(),
                }
            }
            None => {
                let refusal = Refusal {
                    status: STATUS_NOT_SERVING,
                    id: Some(self.id.clone()),
                    code: CODE_INVALID_AGENT_RESPONSE,
                    message: HopRefusal::NotServing.client_text(),
                };
                Reply {
                    status: STATUS_NOT_SERVING,
                    content_type: JSON_MEDIA_TYPE,
                    body: serde_json::to_vec(&refusal.envelope()).unwrap_or_default(),
                }
            }
        };
        Answer::ToCaller(reply)
    }

    /// REFUSED AT THE RELAY'S GUARD: the agent's registered endpoint was refused before the hop
    /// (the engine's `RelayRefusal::Guard`). A task-less hop is refused early in the hop's fixed
    /// words (`502`, `a2a.hop.endpoint_refused`); a task hop answers as any failed hop does. The
    /// caller never reads the endpoint.
    pub fn refuse_endpoint(&mut self) -> Answer {
        self.answered = true;
        self.journal(HopRefusal::EndpointRefused, false);
        let Some(task) = &self.task else {
            return Answer::ToCaller(HopRefusal::EndpointRefused.reply(&self.id));
        };
        let (reply, failed) = task_refusal(None, task, &self.id);
        if failed {
            self.settled.push(Settled::Failed);
        }
        Answer::ToCaller(reply)
    }

    /// THE HOP LEFT AND NOTHING CAME BACK: the attempt went to the agent and the connection could
    /// not be made, or closed before any answer (the engine's `RelayRefusal::Transport`, answered by
    /// `receive::refuse_hop`). A task-less hop is refused early in the hop's fixed words (`502`,
    /// `a2a.hop.transport_failed`, never the endpoint); a task the caller addressed is a failed read
    /// (`502`, the task left as it is); a task the hop opened ends `failed` (`fail_task`: `502`
    /// "the backend agent did not complete this task", naming it). The caller's whole answer, and
    /// whether the task ends `failed`.
    #[must_use]
    pub fn refuse_transport(&mut self) -> (Reply, bool) {
        self.answered = true;
        self.journal(HopRefusal::Transport, false);
        match &self.task {
            None => (HopRefusal::Transport.reply(&self.id), false),
            Some(task) => task_refusal(None, task, &self.id),
        }
    }

    /// REFUSED FOR BUSBAR'S OWN CREDENTIAL: the agent's `upstream_credential`, re-resolved for this
    /// hop, was unavailable, so the kernel refused the unit before anything was dialled
    /// (`credential_unavailable`). The engine minted the lease after it opened the task and
    /// answered its failure with `fail_task` (`receive.rs`, the `mint_from` arm): `502`
    /// `InvalidAgentResponse` "the backend agent did not complete this task" naming the task, which
    /// ends `failed` whether the hop opened it or addressed it. The extended-card read opened no
    /// task: its own words, nothing settled. The caller's whole answer, and whether the task ends
    /// `failed`.
    #[must_use]
    pub fn refuse_credential(&mut self) -> (Reply, bool) {
        self.answered = true;
        let Some(task) = &self.task else {
            let refusal = Refusal {
                status: STATUS_BAD_GATEWAY,
                id: Some(self.id.clone()),
                code: CODE_INVALID_AGENT_RESPONSE,
                message: CARD_UNFETCHED.to_string(),
            };
            return (
                Reply {
                    status: STATUS_BAD_GATEWAY,
                    content_type: JSON_MEDIA_TYPE,
                    body: serde_json::to_vec(&refusal.envelope()).unwrap_or_default(),
                },
                false,
            );
        };
        let refusal = Refusal {
            status: STATUS_BAD_GATEWAY,
            id: Some(self.id.clone()),
            code: CODE_INVALID_AGENT_RESPONSE,
            message: TASK_UNCOMPLETED.to_string(),
        };
        (
            Reply {
                status: STATUS_BAD_GATEWAY,
                content_type: JSON_MEDIA_TYPE,
                body: serde_json::to_vec(&identity::about_task(&refusal, &task.task_id))
                    .unwrap_or_default(),
            },
            true,
        )
    }

    /// The early refusal of a request that cannot be carried over `word`.
    fn unframable_reply(&self, word: &str) -> Reply {
        let refusal = Refusal {
            status: STATUS_BAD_GATEWAY,
            id: Some(self.id.clone()),
            code: CODE_INVALID_AGENT_RESPONSE,
            message: binding::unframable_text(&self.method, word),
        };
        Reply {
            status: STATUS_BAD_GATEWAY,
            content_type: JSON_MEDIA_TYPE,
            body: serde_json::to_vec(&refusal.envelope()).unwrap_or_default(),
        }
    }

    /// The hop could not be framed on its binding: a task-less hop is refused by name; a task hop
    /// answers as any failed hop does.
    fn unframable(&mut self) -> Answer {
        self.answered = true;
        let Some(task) = &self.task else {
            return Answer::ToCaller(self.unframable_reply(self.binding.word()));
        };
        let (reply, failed) = task_refusal(None, task, &self.id);
        if failed {
            self.settled.push(Settled::Failed);
        }
        Answer::ToCaller(reply)
    }

    /// The request one attempt sends on the hop's binding, to the agent at `url`.
    fn attempt(&mut self, url: &str) -> Answer {
        let version = (crate::arrival::H_VERSION, self.version.to_string());
        match self.binding {
            Binding::JsonRpc => match target_of(url) {
                Some(target) => Answer::Attempt(Attempt {
                    verb: VERB,
                    target,
                    fields: vec![
                        (H_CONTENT_TYPE, JSON_MEDIA_TYPE.to_string()),
                        (H_ACCEPT, self.accept().to_string()),
                        version,
                    ],
                }),
                None => Answer::Refused,
            },
            Binding::HttpJson => match binding::compose(url, &self.method, &self.params) {
                Ok(framed) => {
                    let mut fields = Vec::new();
                    if framed.has_body {
                        fields.push((H_CONTENT_TYPE, JSON_MEDIA_TYPE.to_string()));
                    }
                    fields.push((H_ACCEPT, self.accept().to_string()));
                    fields.push(version);
                    self.instead = Some(framed.body);
                    Answer::Attempt(Attempt {
                        verb: framed.verb,
                        target: framed.target,
                        fields,
                    })
                }
                Err(_) => self.unframable(),
            },
            // THE gRPC BINDING (the engine's `GrpcFraming`): the rpc's own path under the service,
            // the params written as its request message; the grpc transport frames it.
            Binding::Grpc => {
                let framed = crate::framed::Rpc::of_method(&self.method).and_then(|rpc| {
                    crate::framed::request_message(rpc, &self.params)
                        .ok()
                        .map(|body| (rpc, body))
                });
                match framed {
                    Some((rpc, body)) => {
                        self.instead = Some(body);
                        let media = crate::framed::DIAL_CONTENT_TYPE.to_string();
                        Answer::Attempt(Attempt {
                            verb: VERB,
                            target: rpc.target(),
                            fields: vec![
                                (H_CONTENT_TYPE, media.clone()),
                                (H_ACCEPT, media),
                                version,
                            ],
                        })
                    }
                    None => self.unframable(),
                }
            }
        }
    }

    /// The hop is for `task`: its answer leaves under busbar's identity and its refusals name the
    /// task.
    pub fn for_task(&mut self, task: TaskHop) {
        self.task = Some(task);
    }

    /// The request id the hop answers.
    #[must_use]
    pub const fn id(&self) -> &Value {
        &self.id
    }

    /// The task this hop is for, once one is open.
    #[must_use]
    pub const fn task(&self) -> Option<&TaskHop> {
        self.task.as_ref()
    }

    /// Every attempt sends `body` in place of the caller's bytes (a request whose task ids were
    /// translated to the far end's).
    pub fn send_instead(&mut self, body: Vec<u8>) {
        self.instead = Some(body);
    }

    /// What the answer has said about the task since this was last asked, in order; empty before
    /// the answer or for a task-less hop.
    pub fn take_settled(&mut self) -> Vec<Settled> {
        std::mem::take(&mut self.settled)
    }

    /// `true` once the caller's answer has been given.
    #[must_use]
    pub const fn answered(&self) -> bool {
        self.answered
    }

    /// The payload bytes the hop has moved both ways, the request's and the reply's, once the far
    /// end has answered (an exchange that never happened moved nothing busbar can measure).
    #[must_use]
    pub fn moved(&self) -> u64 {
        if self.status.is_some() {
            self.sent.saturating_add(self.received)
        } else {
            0
        }
    }

    /// The plane's answer to `piece`.
    pub fn on_piece(&mut self, piece: Piece<'_>) -> Answer {
        if self.answered {
            return Answer::Nothing;
        }
        match piece.from {
            From::Kernel(url) => {
                // An answer already started in events cannot be attempted again.
                if self.events.as_ref().is_some_and(|e| e.committed) {
                    return Answer::Refused;
                }
                if let Some(events) = self.events.as_mut() {
                    *events = Events::default();
                }
                self.sent = 0;
                self.status = None;
                self.far.clear();
                self.received = 0;
                self.instead_sent = false;
                self.reading = None;
                self.grpc = GrpcRead::default();
                match url {
                    Some(url) => {
                        self.url = url.to_string();
                        self.attempt(url)
                    }
                    None => Answer::Refused,
                }
            }
            From::Caller => {
                let bytes = match &self.instead {
                    Some(_) if self.instead_sent => Vec::new(),
                    Some(instead) => {
                        self.instead_sent = true;
                        instead.clone()
                    }
                    None => piece.bytes.to_vec(),
                };
                self.sent = self.sent.saturating_add(bytes.len() as u64);
                if bytes.is_empty() {
                    Answer::Nothing
                } else {
                    Answer::ToFarEnd(bytes)
                }
            }
            From::FarEnd => self.far_end_piece(piece),
        }
    }

    fn far_end_piece(&mut self, piece: Piece<'_>) -> Answer {
        if self.binding == Binding::Grpc {
            return self.grpc_piece(&piece);
        }
        if let Some(status) = piece.status {
            self.status = Some(status);
        }
        self.received = self.received.saturating_add(piece.bytes.len() as u64);
        let in_events = self.events.as_ref().is_some_and(|e| !e.document)
            && self.status.is_some_and(|s| (200..300).contains(&s));
        if in_events {
            if let Some(answer) = self.events_piece(&piece) {
                return answer;
            }
        } else {
            self.keep(piece.bytes);
        }
        if !piece.last {
            return Answer::Nothing;
        }
        let Some(status) = self.status else {
            return Answer::Refused;
        };
        self.whole(status)
    }

    /// Keep `bytes` of a far end's answer read whole, only up to one byte past the ceiling: past it
    /// the reply is refused whole.
    fn keep(&mut self, bytes: &[u8]) {
        let room = (MAX_REPLY_BYTES + 1).saturating_sub(self.far.len());
        self.far.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    /// One 2xx far-end piece of a hop expecting events: `None` while the far end has framed no
    /// event (its bytes kept, as one document's are), else what the events it finished answer.
    fn events_piece(&mut self, piece: &Piece<'_>) -> Option<Answer> {
        let (frames, pending, framed) = {
            let events = self.events.as_mut()?;
            let frames = events.reader.feed(piece.bytes);
            (frames, events.reader.pending(), events.framed)
        };
        if !framed {
            // Until a first event is framed the answer may be one document: its bytes are kept.
            // A first frame that is no event (a document with a blank line in it) settles it.
            let document = frames.first().is_some_and(|f| !is_event(f));
            if frames.is_empty() || document {
                self.keep(piece.bytes);
                if let Some(events) = self.events.as_mut() {
                    events.document = document || pending > MAX_REPLY_BYTES;
                }
                return None;
            }
        }
        if let Some(events) = self.events.as_mut() {
            if !events.framed {
                // THE FIRST EVENT: the destination answered in events.
                self.reading = Some(Reading::Healthy);
            }
            events.framed = true;
        }
        let (task_id, context_id, skill) = match &self.task {
            Some(t) => (t.task_id.clone(), t.context_id.clone(), t.skill.clone()),
            None => (String::new(), String::new(), None),
        };
        let rest = self.binding == Binding::HttpJson;
        let id = self.id.clone();
        let mut body = Vec::new();
        for frame in frames {
            let frame = if rest {
                events::rewrap(frame, &id)
            } else {
                frame
            };
            match events::read_event(&frame, &id, &task_id, &context_id, skill.as_deref()) {
                Ok(event) => {
                    body.extend_from_slice(&event.sse);
                    let said =
                        event.state.is_some() || event.artifact || event.backend_task_id.is_some();
                    if self.task.is_some() && said {
                        self.settled.push(Settled::Event {
                            state: event.state,
                            artifact: event.artifact,
                            backend_id: event.backend_task_id,
                        });
                    }
                }
                Err(_) => return Some(self.events_refused(HopRefusal::Uncorrelated, body)),
            }
        }
        // The ceiling holds what is unterminated, not the stream's length over time.
        if pending > MAX_REPLY_BYTES {
            return Some(self.events_refused(HopRefusal::BodyTooLarge, body));
        }
        if piece.last {
            self.answered = true;
        }
        Some(self.part(body, piece.last))
    }

    /// Part of the caller's answer in events: the first one starts it.
    fn part(&mut self, body: Vec<u8>, last: bool) -> Answer {
        let Some(events) = self.events.as_mut() else {
            return Answer::Refused;
        };
        if body.is_empty() && !last {
            return Answer::Nothing;
        }
        let head = !events.committed;
        events.committed = true;
        Answer::Part(Part { head, body, last })
    }

    /// A hop expecting events is refused for `refusal`: before its answer started (and with no
    /// event of this piece to send) the caller is answered as a refused hop is; after it, the
    /// events already read go out and the answer ends there, its task `failed`.
    fn events_refused(&mut self, refusal: HopRefusal, body: Vec<u8>) -> Answer {
        self.answered = true;
        let started = self.events.as_ref().is_some_and(|e| e.committed);
        self.journal(refusal, started || !body.is_empty());
        if !started && body.is_empty() {
            return Answer::ToCaller(match &self.task {
                None => refusal.reply(&self.id),
                Some(task) => {
                    let (reply, failed) = task_refusal(None, task, &self.id);
                    if failed {
                        self.settled.push(Settled::Failed);
                    }
                    reply
                }
            });
        }
        if self.task.is_some() {
            self.settled.push(Settled::Failed);
        }
        self.part(body, true)
    }

    /// THE TRAILERS of the far end's answer (a field block after its body, `PIECE_FIELDS`), with
    /// the status the host reports beside them (`status`): on the gRPC binding they say how the
    /// call ended ([`crate::framed::ended`]); any other binding ignores them. Only `last` is acted
    /// on, as the end of the answer.
    pub fn on_far_fields(&mut self, bytes: &[u8], status: Option<u32>, last: bool) -> Answer {
        if self.answered {
            return Answer::Nothing;
        }
        self.received = self.received.saturating_add(bytes.len() as u64);
        if self.binding == Binding::Grpc {
            if let Some(ended) = crate::framed::ended(bytes, status) {
                self.grpc.ended = Some(ended);
            }
        }
        if !last {
            return Answer::Nothing;
        }
        self.far_end_piece(Piece {
            from: From::FarEnd,
            bytes: &[],
            status: None,
            last: true,
        })
    }

    /// ONE PIECE OF A gRPC FAR END'S ANSWER (the grpc transport's: its head, with no status of its
    /// own; each message length-prefixed; then the trailers, [`Self::on_far_fields`]). A unary
    /// answer is kept whole and read at its end ([`Self::grpc_envelope`]); an answer in events has
    /// each whole message read as the `StreamResponse` it is and answered as the JSON-RPC event it
    /// re-frames to (the engine's `GrpcFrameReader`), through the one event reader.
    fn grpc_piece(&mut self, piece: &Piece<'_>) -> Answer {
        if let Some(status) = piece.status {
            self.status = Some(status);
        }
        self.received = self.received.saturating_add(piece.bytes.len() as u64);
        if self.events.is_some() {
            let framed = self.grpc_events(piece.bytes);
            if self.grpc.pending.len() > MAX_REPLY_BYTES {
                return self.events_refused(HopRefusal::BodyTooLarge, Vec::new());
            }
            let as_events = Piece {
                from: From::FarEnd,
                bytes: &framed,
                status: None,
                last: piece.last,
            };
            if let Some(answer) = self.events_piece(&as_events) {
                return answer;
            }
        } else {
            self.keep(piece.bytes);
        }
        if !piece.last {
            return Answer::Nothing;
        }
        let Some(status) = self.status else {
            return Answer::Refused;
        };
        self.whole(status)
    }

    /// The whole messages `bytes` completes, each as one event-stream frame carrying the JSON-RPC
    /// response its `StreamResponse` is. A message that does not read is stepped over; a compressed
    /// one stops the reading (where the next message starts is no longer known).
    fn grpc_events(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.grpc.pending.extend_from_slice(bytes);
        let Some(rpc) = crate::framed::Rpc::of_method(&self.method) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut cursor = 0;
        while let Ok(Some((len, took))) = crate::framed::take_message(&self.grpc.pending[cursor..])
        {
            let start = cursor + crate::framed::MESSAGE_PREFIX;
            cursor += took;
            let Ok(result) =
                crate::framed::response_result(rpc, &self.grpc.pending[start..start + len])
            else {
                continue;
            };
            let envelope = json!({ "jsonrpc": "2.0", "id": self.id, "result": result });
            out.extend_from_slice(format!("data: {envelope}\n\n").as_bytes());
        }
        self.grpc.pending.drain(..cursor);
        out
    }

    /// A gRPC far end's whole answer, as the JSON-RPC envelope the one reader reads: a call that
    /// ended with an error status is that error (its A2A code, where its reason or its status
    /// names one); else its one message is the rpc's `result`. `None` when the answer carries no
    /// message to read and no error status (the engine's `Unframable`). A reply over the ceiling is
    /// handed on as it is, for the reader to refuse.
    fn grpc_envelope(&self) -> Option<Vec<u8>> {
        if self.far.len() > MAX_REPLY_BYTES {
            return Some(self.far.clone());
        }
        if let Some(ended) = self.grpc.ended.as_ref().filter(|e| !e.ok()) {
            // A status no A2A code is bound to reads as JSON-RPC's own internal error, as a
            // JSON-RPC agent's internal error reads.
            let code = ended.a2a_code().unwrap_or(CODE_INTERNAL_ERROR);
            let envelope = json!({
                "jsonrpc": "2.0",
                "id": self.id,
                "error": { "code": code, "message": format!("grpc-status {}", ended.code) },
            });
            return serde_json::to_vec(&envelope).ok();
        }
        let rpc = crate::framed::Rpc::of_method(&self.method)?;
        let (len, _) = crate::framed::take_message(&self.far).ok()??;
        let message = &self.far[crate::framed::MESSAGE_PREFIX..crate::framed::MESSAGE_PREFIX + len];
        let result = crate::framed::response_result(rpc, message).ok()?;
        serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": self.id, "result": result })).ok()
    }

    /// The caller's answer to a far end's whole answer at `status`, read as one document.
    fn whole(&mut self, status: u32) -> Answer {
        let status = if self.binding == Binding::Grpc {
            match self.grpc_envelope() {
                Some(envelope) => {
                    self.far = envelope;
                    STATUS_OK
                }
                None => {
                    // An agent refusing busbar at the HTTP layer (`401`/`403`, no gRPC answer)
                    // refuses busbar itself, as on every binding (predev `relay.rs:1583`: a
                    // non-2xx status is the one status table's to read, an auth status hard).
                    self.reading = matches!(status, 401 | 403).then_some(Reading::Hard);
                    return self.unframable();
                }
            }
        } else {
            status
        };
        self.reading = reading_of(status, &self.far, &self.id, self.binding);
        if let Some(ended) = self.grpc.ended.as_ref().filter(|e| !e.ok()) {
            // UNAUTHENTICATED and PERMISSION_DENIED refuse busbar itself, as a 401/403 does.
            if matches!(ended.code, 7 | 16) {
                self.reading = Some(Reading::Hard);
            }
        }
        let answer = match self.binding {
            Binding::JsonRpc | Binding::Grpc => read_answer(status, &self.far, &self.id),
            Binding::HttpJson => match read_rest_answer(status, &self.far, &self.id) {
                Some(answer) => answer,
                None => return self.unframable(),
            },
        };
        self.answered = true;
        if let Err(refusal) = &answer {
            self.journal(*refusal, false);
        }
        let Some(task) = &self.task else {
            return Answer::ToCaller(match answer {
                Ok(result) => relayed(&self.id, result),
                Err(refusal) => refusal.reply(&self.id),
            });
        };
        Answer::ToCaller(match answer {
            Ok(mut result) => {
                self.settled.push(Settled::Reported {
                    state: identity::reported_task_state(&result),
                    backend_id: identity::backend_task_id(&result),
                });
                identity::rewrite_identity(
                    &mut result,
                    &task.task_id,
                    &task.context_id,
                    task.skill.as_deref(),
                );
                relayed(&self.id, result)
            }
            Err(refusal) => {
                let code = (refusal == HopRefusal::BackendError)
                    .then(|| backend_error_code(&self.far))
                    .flatten();
                let (reply, failed) = task_refusal(code, task, &self.id);
                if failed {
                    self.settled.push(Settled::Failed);
                }
                reply
            }
        })
    }
}

/// The far end's JSON-RPC error `code`, when it answered one A2A defines.
fn backend_error_code(body: &[u8]) -> Option<i64> {
    serde_json::from_slice::<Value>(body)
        .ok()?
        .pointer("/error/code")?
        .as_i64()
        .filter(|c| identity::status_of_code(*c).is_some())
}

/// THE CALLER'S ANSWER TO A REFUSED TASK HOP, and whether the task ends `failed` (the engine's
/// `receive::refuse_hop`): the far end's own A2A error code travels, its prose never does, and the
/// refusal names the task. A hop addressed to a task the caller holds fails the request, never the
/// task.
fn task_refusal(code: Option<i64>, task: &TaskHop, id: &Value) -> (Reply, bool) {
    let (code, message, failed) = match (task.addressed, code) {
        (true, code) => (
            code.unwrap_or(CODE_INVALID_AGENT_RESPONSE),
            "the backend agent refused this request",
            false,
        ),
        (false, Some(code)) => (code, "the backend agent refused this task", true),
        (false, None) => (
            CODE_INVALID_AGENT_RESPONSE,
            "the backend agent did not complete this task",
            true,
        ),
    };
    let status = identity::status_of_code(code).unwrap_or(STATUS_BAD_GATEWAY);
    let refusal = Refusal {
        status,
        id: Some(id.clone()),
        code,
        message: message.to_string(),
    };
    let reply = Reply {
        status,
        content_type: JSON_MEDIA_TYPE,
        body: serde_json::to_vec(&identity::about_task(&refusal, &task.task_id))
            .unwrap_or_default(),
    };
    (reply, failed)
}

#[cfg(test)]
#[path = "tests/relay_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/relay_grpc_tests.rs"]
mod grpc_tests;
