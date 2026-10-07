// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S DOOR, SERVED: the slots the kernel calls over the plane ABI, on the SDK's safe
//! surface. [`door`] is the LINKED door; the same function is the DROPPED door once a `cdylib`
//! exports it (`busbar_contract::export_door!`), so the two cannot answer differently.
//!
//! The lifecycle is this plane's own:
//!
//! * `validate` reads the settings blob as the `agents:` section ([`door::read_settings`]) and
//!   refuses in the grammar's words;
//! * `open` judges the same section, reads the deployment's public base URL and publishes the
//!   first generation's snapshot ([`door::snapshot_spec`]); `refresh` judges the new section and
//!   publishes the next generation over the base URL `open` was given; `retire` drops a
//!   generation's snapshot. Each generation holds the section it serves beside its snapshot
//!   (`Generations<PlaneSnapshot, AgentsCfg>`), and an arrival keeps the newest one;
//! * `arrive` decides an arrival on the JSON-RPC line ([`crate::arrival::decide`]) and keeps it,
//!   with the generation it arrived under, keyed by its unit (`Keyed`); a refused arrival states
//!   its refusal in its own words, and `refusal` renders those, or the kernel's, in the line's
//!   dialect ([`crate::arrival::render`]);
//! * `on_piece` drives a unit's unary hop ([`crate::relay::Relay`]): the request each ATTEMPT
//!   sends the agent the kernel picked, the caller's body relayed verbatim, and the caller's
//!   answer from the far end's, written into the host's buffers across `more` re-calls. A hop
//!   that is about a task opens it at its first ATTEMPT and settles it on the far end's answer,
//!   over the task store's host records ([`crate::task_hop`]); its answer leaves under busbar's
//!   task identity ([`crate::identity`]);
//! * `on_piece` answers the verbs the plane answers itself over the task store's host records
//!   ([`crate::task_door`]);
//! * a hop whose answer moves its task queues the task's push notification, and `tick` delivers
//!   the due ones over the plane's outbound need ([`crate::push_door`]);
//! * `drive` has no session with unsolicited output, `cancel` finds nothing in flight, and
//!   `release`/`close` hold nothing the SDK does not already drop.

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneCancelIn, PlaneCancelOut,
    PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot,
    ProjectIn, ProjectOut, RecordWrite, RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount,
    CANCEL_ABORTED, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL,
    PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_NONE, PRINCIPAL_REQUIRED, RECORD_PUT, REFUSAL_ARRIVE,
    ROUTE_DIRECT, ROUTE_SCOPE, UNITS_REPORTED,
};
use busbar_contract::abi::sdk::conn::Host;
// THE ONE SHARED FAULT READING (ARCHITECT row 68): the breaker's vocabulary, stated on `OnPieceOut`.
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::publish::{Generations, Keyed};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot, Services};
use busbar_contract::abi::transport::{
    FAULT_CALLER, FAULT_HARD, FAULT_HEALTHY, FAULT_NONE, FAULT_TRANSIENT,
};

use std::sync::Arc;
use std::task::Poll;

use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};

use crate::a2a::config::AgentsCfg;
use crate::arrival::{self, Dialect, Disposition};
use crate::door::{self, Line};
use crate::relay::{self, Answer, Relay, Settled};
use crate::task_door::{kind_index, Via};
use crate::task_hop::{self, Opened};
use crate::tasks::{task_key, Halt, Write};

/// The most calls the kernel keeps in flight on one instance, as the transport doors state it.
const MAX_INFLIGHT: u32 = 64;

/// The version the Statement names: the crate's (a test pins the two equal).
pub const VERSION: &str = "1.6.0";

/// THE STATEMENT: the plane's name and version, the settings section it declares
/// ([`door::SECTIONS`]), its three outbound needs ([`door::NEEDS`]), the secret references its
/// section holds ([`door::SECRET_REFS`]) and its tail ([`door::TAIL`]).
pub const STATEMENT: Statement = Statement {
    kind_tail: (door::TAIL as *const busbar_contract::abi::plane::PlaneTail).cast::<KindTailHead>(),
    sections: door::SECTIONS.as_ptr(),
    sections_len: door::SECTIONS.len(),
    needs: door::NEEDS.as_ptr(),
    needs_len: door::NEEDS.len(),
    secret_refs: door::SECRET_REFS.as_ptr(),
    secret_refs_len: door::SECRET_REFS.len(),
    ..statement(crate::PLANE_KEY, VERSION, MAX_INFLIGHT)
};

/// The most units the instance keeps state for at once; past it, the oldest is dropped first.
pub const MAX_UNITS: usize = 4096;

/// One unit the instance keeps, from its arrival: what the arrival was, the agent the caller
/// addressed by name (if it did), the section of the generation it arrived under, and what its
/// pieces carry from one to the next ([`crate::task_door::Pass`]).
#[derive(Debug)]
pub struct Unit {
    /// The arrival, decided.
    pub disposition: Disposition,
    /// The agent a `/a2a/agents/{agent_id}` target names.
    pub agent: Option<String>,
    /// The section of the newest generation when it arrived.
    pub section: Option<Arc<AgentsCfg>>,
    /// The unit's unary hop and what it still owes the host; `None` for a unit `on_piece` does not
    /// serve yet.
    pub hop: Option<Hop>,
    /// The host services its pieces have made so far, and the piece in flight.
    pub pass: crate::task_door::Pass,
    /// The JSON-RPC envelope an HTTP+JSON arrival's request spells ([`crate::rest::compose`]):
    /// what its unit answers and relays in place of the caller's body, its answers re-framed for
    /// the line ([`crate::rest::reframe`]). `None` on the JSON-RPC line.
    pub envelope: Option<Vec<u8>>,
    /// The rpc a gRPC-line arrival called ([`crate::framed`]): its `envelope` is the JSON-RPC request
    /// the call's message composed, and its answers are transcoded back to the rpc's messages and
    /// status. `None` on every other line.
    pub framed: Option<crate::framed::Rpc>,
    /// The refresh generation it arrived under: the held cards it reads are that generation's.
    pub generation: u64,
    /// `project` refused a committed rewrite it could not read back: `refusal` answers the unit
    /// predev's internal error ([`unreadable_rewrite`]).
    pub unreadable_rewrite: bool,
}

/// One unit's unary hop, and the answer it is part way through writing.
#[derive(Debug)]
pub struct Hop {
    relay: Relay,
    outbox: Outbox,
    /// A task hop's request, until its first ATTEMPT opens the task.
    opening: Option<serde_json::Value>,
    /// The caller's request envelope: what a binding other than JSON-RPC composes from.
    request: Option<serde_json::Value>,
    /// What the far end's answer has said about the task, until its record writes are made.
    settle: Vec<Settled>,
    /// The second the piece in flight entered, kept across its re-entries.
    now: Option<u64>,
    /// A subscribe: busbar's own refusal of a task it does not hold live comes before the hop.
    subscribe: bool,
    /// How many of the piece in flight's task moves have queued their push notifications: a
    /// re-entry never queues one twice.
    queued: usize,
    /// What the piece in flight files for earlier deliveries, taken once across its re-entries.
    owed: Option<Vec<crate::push::Owed>>,
    /// The ATTEMPT passed the admission gate: its re-entries do not judge it again.
    admitted: bool,
    /// The skill the agent's held card matched at admission.
    skill: Option<String>,
    /// The flight epoch it waits on, while another unit's look at its agent is in flight.
    waits_on: Option<u64>,
    /// Verify-on-call's look, while one of its services is in flight.
    verifying: Option<LookParked>,
    /// The record writes the ATTEMPT made before verify-on-call paused it: they ride with its
    /// answer when it resumes.
    held_writes: Vec<Write>,
    /// The ATTEMPT's agent endpoint was judged by the relay's guard: its re-entries do not judge it
    /// again.
    endpoint_judged: bool,
    /// The hop has LEFT the plane for its agent (its request answered at an ATTEMPT, every gate
    /// of the plane's passed): the unit is served and its fee unit is reported from then on.
    left: bool,
    /// THE ENVELOPE A REQUEST-STAGE REWRITE LEFT (`project`'s `rewrite`): what the hop relays
    /// (its task ids translated over it, its binding composed from it). Everything else the hop
    /// reads (the task it opens, the callback it carries, the admission) reads the caller's own
    /// envelope, as the engine read the params its gate had already screened.
    rewritten: Option<serde_json::Value>,
    /// A gRPC send whose request carried no message: its first ATTEMPT mints the message's id
    /// ([`crate::framed::mints_message_id`]) before the task is opened.
    mint_message_id: bool,
    /// The agent the latest ATTEMPT reached (its route entry): the unit's ledger lane and the
    /// resource its audit row names.
    member: String,
    /// The task as its opening left it, kept for a refusal that must end it `failed`
    /// ([`credential_refusal`]): `refusal` is ticketless and reads no host.
    opened: Option<OpenedTask>,
    /// The caller's answer and the record writes of a hop refused for busbar's own credential,
    /// made once: a short `refusal` re-called renders the same again.
    credential: Option<(relay::Reply, Vec<Write>)>,
}

/// A TASK AS A HOP'S OPENING LEFT IT: the caller it is held under, the second it was opened at,
/// and the records that hold it (the writes the opening made, or the row it read).
#[derive(Debug)]
struct OpenedTask {
    caller: String,
    now: u64,
    records: Vec<Write>,
}

impl Hop {
    /// A task-less hop answering the request `id`, declaring `version`.
    #[must_use]
    pub fn new(id: serde_json::Value, version: &'static str) -> Self {
        Hop {
            relay: Relay::new(id, version),
            outbox: Outbox::default(),
            opening: None,
            request: None,
            settle: Vec::new(),
            now: None,
            subscribe: false,
            queued: 0,
            owed: None,
            admitted: false,
            skill: None,
            waits_on: None,
            verifying: None,
            held_writes: Vec::new(),
            endpoint_judged: false,
            left: false,
            rewritten: None,
            mint_message_id: false,
            member: String::new(),
            opened: None,
            credential: None,
        }
    }

    /// A task-less hop for the request `envelope`.
    #[must_use]
    pub fn of(
        id: serde_json::Value,
        version: &'static str,
        envelope: Option<serde_json::Value>,
    ) -> Self {
        Hop {
            request: envelope,
            ..Hop::new(id, version)
        }
    }

    /// A hop about a task: `envelope` opens it at the first ATTEMPT.
    #[must_use]
    pub fn task(id: serde_json::Value, version: &'static str, envelope: serde_json::Value) -> Self {
        Hop {
            opening: Some(envelope.clone()),
            request: Some(envelope),
            ..Hop::new(id, version)
        }
    }

    /// A hop about a task whose answer may be events (the engine's event-stream hop): `envelope`
    /// opens it at the first ATTEMPT; a `subscribe` answers busbar's own refusal first.
    #[must_use]
    pub fn events(
        id: serde_json::Value,
        version: &'static str,
        envelope: serde_json::Value,
        subscribe: bool,
    ) -> Self {
        let mut hop = Hop::task(id, version, envelope);
        hop.relay.expect_events();
        hop.subscribe = subscribe;
        hop
    }
}

/// What a piece's answer still owes the host: its head, once, then its bytes, `reply_cap` at a
/// time. `live` while any of it is unwritten; `recall` after a short answer, whose re-call carries
/// the same piece and must not apply it twice.
#[derive(Debug, Default)]
struct Outbox {
    live: bool,
    recall: bool,
    to_far: bool,
    done: bool,
    head: Option<Head>,
    bytes: Vec<u8>,
    at: usize,
    /// The record writes that ride with the head.
    writes: Vec<Write>,
    /// On the gRPC line: the messages after `bytes`, each emitted on an answer of its own.
    queue: std::collections::VecDeque<Vec<u8>>,
    /// On the gRPC line: `bytes` (and each queued one) is a message, its last byte a message
    /// boundary (`EMIT_MESSAGE_END`); `false` for a status's message text.
    messages: bool,
    /// On the gRPC line: the status a stream that already sent messages ends with, stated on its
    /// closing answer (`EMIT_FINAL_STATUS`).
    final_status: Option<crate::framed::Reply>,
    /// The breaker's reading of the far end's answer this piece read (`FAULT_NONE` = none yet),
    /// stated on the answer that writes it ([`relay::Reading`]).
    fault: u8,
}

/// The head an answer starts with.
#[derive(Debug)]
enum Head {
    /// The request bound for the far end: verb, target, fields.
    Attempt(relay::Attempt),
    /// The caller's reply: its status and media type.
    Reply(u32, &'static str),
    /// The caller's reply in events: `200`, an event stream nothing may cache.
    Events,
    /// The caller's reply on the gRPC line: its status in the line's own numbering (`0` = `OK`) and
    /// the status details' field value ([`crate::framed::Reply`]).
    Framed(u32, Option<String>),
}

/// The head field a whole answer states its length in.
pub(crate) const H_CONTENT_LENGTH: &str = "content-length";

/// The head fields an answer in events starts with (the engine's event-stream response).
const EVENTS_HEAD: [(&str, &str); 2] = [
    (relay::H_CONTENT_TYPE, crate::events::EVENTS_MEDIA_TYPE),
    ("cache-control", "no-store"),
];

impl Outbox {
    /// The outbox for `answer`; `None` for a piece the hop refuses.
    fn of(answer: Answer) -> Option<Self> {
        let (to_far, done, head, bytes) = match answer {
            Answer::Nothing => (false, false, None, Vec::new()),
            Answer::Refused => return None,
            Answer::Attempt(a) => (true, false, Some(Head::Attempt(a)), Vec::new()),
            Answer::ToFarEnd(bytes) => (true, false, None, bytes),
            Answer::ToCaller(r) => (
                false,
                true,
                Some(Head::Reply(r.status, r.content_type)),
                r.body,
            ),
            Answer::Part(part) => (
                false,
                part.last,
                part.head.then_some(Head::Events),
                part.body,
            ),
        };
        Some(Outbox {
            live: true,
            recall: false,
            to_far,
            done,
            head,
            bytes,
            at: 0,
            writes: Vec::new(),
            queue: std::collections::VecDeque::new(),
            messages: false,
            final_status: None,
            fault: FAULT_NONE,
        })
    }

    /// The outbox for `answer` on the gRPC line, the rpc `rpc` (the engine's bridge): a whole
    /// answer is the rpc's one message, or the status it ends with; an answer in events is one
    /// message per event, each on an answer of its own, an `error` event ending the stream (with its
    /// status when no message went before it). Everything bound for the far end is as on the
    /// JSON-RPC line.
    fn framed(answer: Answer, rpc: crate::framed::Rpc) -> Option<Self> {
        match answer {
            Answer::ToCaller(r) => Some(Self::framed_whole(crate::framed::reply(
                rpc, r.status, &r.body,
            ))),
            Answer::Part(part) => {
                let (messages, terminal) = crate::framed::events(rpc, &part.body);
                if let Some(status) = terminal.clone() {
                    if part.head && messages.is_empty() {
                        return Some(Self::framed_whole(status.into()));
                    }
                }
                let emits = !messages.is_empty();
                let mut queue: std::collections::VecDeque<Vec<u8>> = messages.into();
                let bytes = queue.pop_front().unwrap_or_default();
                Some(Outbox {
                    live: true,
                    recall: false,
                    to_far: false,
                    done: part.last || terminal.is_some(),
                    head: part.head.then_some(Head::Framed(0, None)),
                    bytes,
                    at: 0,
                    writes: Vec::new(),
                    queue,
                    messages: emits,
                    final_status: terminal.map(Into::into),
                    fault: FAULT_NONE,
                })
            }
            other => Self::of(other),
        }
    }

    /// A whole reply on the gRPC line.
    fn framed_whole(reply: crate::framed::Reply) -> Self {
        Outbox {
            live: true,
            recall: false,
            to_far: false,
            done: true,
            messages: reply.code == crate::framed::Code::Ok as u32,
            head: Some(Head::Framed(reply.code, reply.details)),
            bytes: reply.body,
            at: 0,
            writes: Vec::new(),
            queue: std::collections::VecDeque::new(),
            final_status: None,
            fault: FAULT_NONE,
        }
    }
}

/// ONE REQUEST BUSBAR ORIGINATES ([`crate::mirror::Originated`]): its agent's url judged as a
/// relayed hop's endpoint is, then `method` with `params` sent over the agent's need naming its
/// registration. Its answer's status and body; `None` for a request that could not be judged,
/// framed or answered; [`crate::mirror::Unleased`] for one the host refused for the agent's
/// unavailable credential, logged ([`crate::mirror::landed`]).
pub(crate) fn drive_originated(
    plane: &A2aDoor,
    ticket: Ticket,
    hop: &mut crate::mirror::Originated,
    method: &str,
    params: &serde_json::Value,
) -> Poll<Result<Option<(u16, Vec<u8>)>, crate::mirror::Unleased>> {
    use busbar_contract::abi::sdk::exchange::{exchange, Exchange};
    if hop.exchange.is_none() {
        let at = LookAt {
            plane,
            ticket,
            base: hop.seq,
        };
        let within = match judge_hop(&at, &hop.url, hop.allow_private, hop.seq) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => return Poll::Ready(Ok(None)),
            Poll::Ready(Ok((next, within))) => {
                hop.seq = next;
                within
            }
        };
        let request = crate::mirror::request(hop.binding, &hop.url, hop.version, method, params)
            .and_then(|r| Exchange::request(r).ok());
        let Some(ex) = request else {
            return Poll::Ready(Ok(None));
        };
        let ex = ex.landing_within(within).as_member(hop.agent.clone());
        hop.exchange = Some((hop.seq, Box::new(ex)));
    }
    let Some(host) = plane.host.as_ref() else {
        hop.exchange = None;
        return Poll::Ready(Ok(None));
    };
    let Some((start, ex)) = hop.exchange.as_mut() else {
        return Poll::Ready(Ok(None));
    };
    let mut conn = host.connector_from(ticket, *start);
    let need = match hop.binding {
        crate::binding::Binding::Grpc => door::NEED_GRPC,
        crate::binding::Binding::JsonRpc | crate::binding::Binding::HttpJson => door::NEED_AGENT,
    };
    match exchange(&mut conn, ex, need, Some(&hop.url)) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(answer) => {
            hop.seq = conn.issued();
            hop.exchange = None;
            Poll::Ready(crate::mirror::landed(
                hop.binding,
                &hop.agent,
                method,
                answer,
            ))
        }
    }
}

/// THE MIRROR ([`crate::mirror::Flight`]): each stage's request originated, until its last stage
/// is answered or one is refused for the agent's unavailable credential. Its outcome is only ever
/// the next stage.
pub(crate) fn drive_mirror(
    plane: &A2aDoor,
    ticket: Ticket,
    flight: &mut crate::mirror::Flight,
) -> Poll<()> {
    while flight.stage != crate::mirror::Stage::Done {
        let (method, params) = (flight.issuing(), flight.params());
        match drive_originated(plane, ticket, &mut flight.hop, method, &params) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(landed) => flight.land(match &landed {
                Ok(answered) => Ok(answered.as_ref().map(|(s, b)| (*s, b.as_slice()))),
                Err(unleased) => Err(*unleased),
            }),
        }
    }
    Poll::Ready(())
}

/// One instance: the public base URL `open` was given, the host tables, every live generation's
/// snapshot and section, the units in flight, the second the task store was last swept, and the
/// far end's own id for each relayed task busbar learnt it for.
pub struct A2aDoor {
    pub(crate) public_url: Option<String>,
    pub(crate) host: Option<Host>,
    pub(crate) services: Option<Services>,
    generations: Generations<PlaneSnapshot, AgentsCfg>,
    pub(crate) units: Keyed<u64, Unit>,
    pub(crate) swept: Keyed<(), u64>,
    /// `<caller>/<busbar task id>` to the far end's own id for the task: plane memory, so a
    /// restart forgets it (the engine's `idmap`, its bound included).
    backends: Keyed<String, String>,
    /// The agents' verified cards, held in plugin memory to their refresh generation.
    pub(crate) cards: crate::cards::Cards,
    /// The push notifications waiting for delivery, and the webhook credentials they present.
    pub(crate) deliveries: crate::push::Deliveries,
    /// Busbar's own callback tokens, by the task each names ([`crate::push::Tokens`]).
    pub(crate) tokens: crate::push::Tokens,
    /// The push-volume bound on busbar's own callback ([`crate::push::PushLimiter`]).
    pub(crate) pushes: crate::push::PushLimiter,
    /// The newest refresh generation published.
    newest: Keyed<(), u64>,
    /// The sizes short host-records answers named, per handle ([`crate::task_door::Grown`]).
    pub(crate) grown: crate::task_door::Grown,
    /// Each agent's verify-on-call flight: one look at a time.
    pub(crate) flights: Flights,
    /// Each registered agent's trust: the identity an operator approved (`approve`), the last
    /// sighting of its card and verify-on-call's ledger: plane memory, so a restart forgets it.
    pub(crate) trust: Keyed<String, crate::trust::Standing>,
}

impl A2aDoor {
    /// The agent's own id for `caller`'s task `task_id`, once the agent named it.
    pub(crate) fn backend_of(&self, caller: &str, task_id: &str) -> Option<String> {
        self.backends.get(&task_key(caller, task_id))
    }

    /// The newest refresh generation published; `0` before `open`.
    fn newest(&self) -> u64 {
        self.newest.get(&()).unwrap_or(0)
    }

    /// `generation` is published: the newest when it is newer.
    fn published(&self, generation: u64) {
        self.newest.with_all(|m| {
            if m.get(&()).is_none_or(|n| *n < generation) {
                m.insert((), generation);
            }
        });
    }
}

/// The most far-end task ids the instance remembers (the engine's `idmap::CAPACITY`).
pub const MAX_BACKEND_IDS: usize = 100_000;

/// The settings blob read as the `agents:` section, or the refusal in the grammar's words.
fn section(bytes: &[u8]) -> Result<AgentsCfg, Refusal> {
    door::read_settings(bytes).map_err(Refusal::refused)
}

/// Keep `value` under `key` in `map`, dropping the smallest keys first past `cap`.
fn keep<K: Ord, V>(map: &Keyed<K, V>, cap: usize, key: K, value: V) {
    map.with_all(|m| {
        while m.len() >= cap && !m.contains_key(&key) {
            if m.pop_first().is_none() {
                break;
            }
        }
        m.insert(key, value);
    });
}

/// The agent a JSON-RPC target names below the catalogue, if it names one.
fn agent_of(target: &str) -> Option<String> {
    let path = target.split(['?', '#']).next().unwrap_or(target);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segments.as_slice() {
        ["a2a", "agents", id] => Some((*id).to_string()),
        _ => None,
    }
}

/// The public base URL the host lent, when it states one.
fn public_url(bytes: &[u8]) -> Option<String> {
    std::str::from_utf8(bytes)
        .ok()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// [`ArriveOut::refusal`]: the arrival is refused in the plane's own words, at its own status
/// (the words ride in the head's error, and `refusal` renders them).
pub const REFUSED_IN_OWN_WORDS: u32 = 1;

/// [`ArriveOut::refusal`]: no line of this door serves the arrival yet (a 404).
pub const UNSERVED: u32 = 2;

/// The status of an arrival no line of this door serves yet.
const STATUS_NOT_FOUND: u32 = 404;

/// REFUSED in the plane's own words, at its own status: `refusal` renders them in the line's
/// dialect.
fn refused(out: &mut Out<'_, ArriveOut>, refusal: &arrival::Refusal) -> Outcome {
    out.set(|o| &o.refusal, REFUSED_IN_OWN_WORDS);
    out.set(|o| &o.refusal_status, refusal.status);
    out.fail(Refusal::refused(refusal.words()))
}

/// REFUSED: no line of this door serves the arrival yet. TRANSITIONAL: the gRPC and open lines
/// are filled when the kernel's plane driver serves the door's request path.
/// The status a gRPC call is refused with at its arrival, as the refusal its line renders it from
/// (the JSON-RPC code [`crate::framed::grpc_code`] maps back to it, and its message).
fn framed_refusal(status: &crate::framed::Status) -> arrival::Refusal {
    use crate::framed::Code;
    let code = match status.code() {
        Code::Unimplemented => -32601,
        Code::InvalidArgument => arrival::CODE_INVALID_PARAMS,
        _ => -32603,
    };
    arrival::Refusal {
        status: arrival::STATUS_BAD_REQUEST,
        id: None,
        code,
        message: status.message().to_string(),
    }
}

fn unserved(out: &mut Out<'_, ArriveOut>) -> Outcome {
    out.set(|o| &o.refusal, UNSERVED);
    out.set(|o| &o.refusal_status, STATUS_NOT_FOUND);
    out.fail(Refusal::bare())
}

/// One slot body on the SDK's safe surface, over this plane's [`A2aDoor`].
macro_rules! slot {
    ($(#[$doc:meta])* $name:ident, $in:ty, $out:ty,
     |$inst:pat_param, $input:pat_param, $o:pat_param| $body:block) => {
        $(#[$doc])*
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = A2aDoor;
            fn call($inst: Instance<'_, A2aDoor>, $input: Lent<'_, $in>, $o: Out<'_, $out>)
                -> Outcome $body
        }
    };
}

slot!(
    /// `validate`: the settings read as the section, or refused in the grammar's words.
    Validate, ValidateIn, OutHead, |_, input, mut out| {
        match section(&door::dealt_section(input.field(|i| &i.settings).bytes())) {
            Ok(_) => Outcome::Ready,
            Err(refusal) => out.fail(refusal),
        }
    }
);

slot!(
    /// `open`: the instance over the section and the public base URL, and the first generation's
    /// snapshot.
    Open, PlaneOpenIn, PlaneOpenOut, |instance, input, mut out| {
        let cfg = match section(input.field(|i| &i.open.settings).bytes()) {
            Ok(cfg) => cfg,
            Err(refusal) => return out.fail(refusal),
        };
        let generation = input.get().open.generation;
        let plane = A2aDoor {
            public_url: public_url(input.field(|i| &i.public_url).bytes()),
            host: input.field(|i| &i.open).host().map(|h| Host::of(h.get())),
            services: input
                .field(|i| &i.open)
                .host()
                .and_then(|h| Services::of(h.get())),
            generations: Generations::new(),
            units: Keyed::new(),
            swept: Keyed::new(),
            backends: Keyed::new(),
            cards: crate::cards::Cards::new(),
            deliveries: crate::push::Deliveries::new(),
            tokens: crate::push::Tokens::new(),
            pushes: crate::push::PushLimiter::new(),
            newest: Keyed::new(),
            grown: Keyed::new(),
            flights: Flights::default(),
            trust: Keyed::new(),
        };
        plane.published(generation);
        let spec = door::snapshot_spec(plane.public_url.as_deref());
        out.publish_with(|o| &o.snapshot, &plane.generations, generation, &spec, cfg);
        instance.open(plane);
        Outcome::Ready
    }
);

slot!(
    /// `refresh`: the new section judged, and the next generation's snapshot over the same public base
    /// URL.
    Refresh, RefreshIn, PlaneRefreshOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let cfg = match section(input.field(|i| &i.settings).bytes()) {
            Ok(cfg) => cfg,
            Err(refusal) => return out.fail(refusal),
        };
        let spec = door::snapshot_spec(plane.public_url.as_deref());
        let generation = input.get().generation;
        out.publish_with(|o| &o.snapshot, &plane.generations, generation, &spec, cfg);
        plane.published(generation);
        // EVERY REGISTRATION STARTS AGAIN at the fail-closed floor, as the engine rebuilt each one
        // on a config apply (`A2aPlane::from_config_carrying`): nothing approved, nothing sighted.
        plane.trust.with_all(std::collections::BTreeMap::clear);
        Outcome::Ready
    }
);

slot!(
    /// `retire`: the generation's snapshot is dropped.
    Retire, GenIn, OutHead, |instance, input, _| {
        if let Some(plane) = instance.get() {
            plane.generations.retire(input.get().generation);
            plane.cards.retire(input.get().generation);
        }
        Outcome::Ready
    }
);

slot!(
    /// `tick`: one due push notification attempted ([`crate::push_door::tick`]), and the next
    /// tick wanted when the earliest waiting one is due (`0`: none waits).
    Tick, TickIn, TickOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            out.set(|o| &o.next_tick_ns, 0);
            return Outcome::Ready;
        };
        let outcome = crate::push_door::tick(plane, &instance, input.get().now_ns);
        out.set(|o| &o.next_tick_ns, plane.deliveries.next_tick_ns());
        outcome
    }
);

slot!(
    /// `drive`: no session has unsolicited output.
    Drive, PlaneDriveIn, PlaneDriveOut, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `cancel`: nothing the far end moved is in flight, so nothing moved; a card look the
    /// cancelled unit held is abandoned, and every unit waiting on it is woken at once to look for
    /// itself (ARCHITECT Q-DEL-A2A-TIMED-WAKE: cancellation is a wake). No row is written: a
    /// caller that went away mid-answer stopped 1.5.5's relay without a task transition, and the
    /// task keeps the last state it reached.
    Cancel, PlaneCancelIn, PlaneCancelOut, |instance, input, mut out| {
        if let Some(plane) = instance.get() {
            let woken = plane.flights.abandon(input.cancel.ticket);
            if let Some(host) = plane.host.as_ref() {
                for waiter in woken {
                    host.wake(waiter);
                }
            }
        }
        out.set(|o| &o.cancel.disposition, CANCEL_ABORTED);
        Outcome::Ready
    }
);

slot!(
    /// `release`: this plane answers under no lease.
    Release, ReleaseIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `close`: the SDK drops the instance and every snapshot it still holds.
    Close, InHead, OutHead, |_, _, _| { Outcome::Ready }
);

// ── the request path ──────────────────────────────────────────────────────────────────────────
//
// Nothing routes to these before the flip: the engine still serves every request, and no
// production path loads this door (`tests/door_unrouted.rs` holds that). `arrive`, `on_piece`,
// `refusal` and `project` serve the JSON-RPC and HTTP+JSON lines, their one-reply hops and their
// hops answering in events; `serve`, `hydrate` and `start` are REFUSED.

slot!(
    /// `arrive`: an arrival on the JSON-RPC line, or on the HTTP+JSON line as the envelope its
    /// request spells ([`crate::rest::compose`]), decided and kept with the generation it arrived
    /// under, keyed by its unit; a refused one refused in its own words. A message whose method the
    /// vocabulary does not list is classed as the hop the engine relays it on, never refused.
    /// TRANSITIONAL: an arrival on the gRPC line or an open line is filled when the kernel's plane
    /// driver serves the door's request path.
    Arrive, ArriveIn, ArriveOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let given = input.get();
        let Some(route) = door::ROUTES.get(given.claim as usize) else {
            return unserved(&mut out);
        };
        let target = input.field(|i| &i.target).as_str().unwrap_or_default();
        let body = input.field(|i| &i.body).bytes();
        let (dialect, envelope, framed) = match door::line_of(route) {
            Line::Document => (door::DIALECT_DOCUMENT, None, None),
            Line::Target => match crate::rest::compose(route, target, body) {
                Ok(Some(envelope)) => (door::DIALECT_TARGET, Some(envelope), None),
                Ok(None) => return unserved(&mut out),
                Err(refusal) => return refused(&mut out, &refusal),
            },
            Line::Open => return arrive_card(plane, route, target, given.unit, &mut out),
            // THE gRPC LINE (the engine's `grpc.rs`): the rpc the target names, its one request
            // message composed as the v1.0 JSON-RPC request it is, served from there as the
            // JSON-RPC line serves its own; a method the service does not have, or a message that
            // does not read, is refused in the status the service answered it with.
            Line::Framed => {
                let Some(rpc) = crate::framed::Rpc::of_target(target) else {
                    return refused(&mut out, &framed_refusal(&crate::framed::unimplemented()));
                };
                match crate::framed::compose(rpc, body) {
                    Ok(envelope) => (door::DIALECT_FRAMED, Some(envelope), Some(rpc)),
                    Err(status) => return refused(&mut out, &framed_refusal(&status)),
                }
            }
        };
        let fields = input.fields();
        let field = |name: &str| {
            fields
                .iter()
                .find(|f| {
                    f.field(|f| &f.name)
                        .as_str()
                        .is_ok_and(|n| n.eq_ignore_ascii_case(name))
                })
                .and_then(|f| f.field(|f| &f.value).as_str().ok())
        };
        let disposition = match framed {
            // A gRPC call is read as the engine's bridge read it (`Wire::for_grpc`): no media type
            // and no `Origin` to judge, and the version its `a2a-version` names, `1.0` when it
            // names none.
            Some(_) => arrival::decide(envelope.as_deref().unwrap_or(body), |name| {
                if name.eq_ignore_ascii_case(arrival::H_VERSION) {
                    field(name).or(Some(crate::framed::DEFAULT_VERSION))
                } else if name.eq_ignore_ascii_case(arrival::H_CONTENT_TYPE)
                    || name.eq_ignore_ascii_case(arrival::H_ORIGIN)
                {
                    None
                } else {
                    field(name)
                }
            }),
            None => arrival::decide(envelope.as_deref().unwrap_or(body), field),
        };
        if let Disposition::Refused(refusal) = &disposition {
            return refused(&mut out, refusal);
        }
        let Some(op) = disposition.op_class().and_then(door::op_class_index) else {
            return unserved(&mut out);
        };
        out.set(|o| &o.op_class, op);
        out.set(|o| &o.principal_need, PRINCIPAL_REQUIRED);
        out.set(|o| &o.dialect, dialect);
        let agent = agent_of(target);
        let request: Option<serde_json::Value> =
            serde_json::from_slice(envelope.as_deref().unwrap_or(body)).ok();
        let generation = plane.newest();
        let mut hop = hop_of(&disposition, agent.is_some(), request.clone());
        if let (Some(hop), Some(rpc)) = (hop.as_mut(), framed) {
            hop.mint_message_id = crate::framed::mints_message_id(rpc, body);
        }
        // The HTTP+JSON line relays the envelope its request spelled, never the caller's body.
        if let (Some(hop), Some(composed)) = (hop.as_mut(), envelope.as_ref()) {
            hop.relay.send_instead(composed.clone());
        }
        // The entry the unit routes over: the addressed agent, its name inside the `agents:`
        // section, routed directly (ARCHITECT Q-SW6/Q-FL3); an unaddressed unit is routed by the
        // caller's scope, to the one agent its grant reaches, as 1.5.5 chose it (ARCHITECT
        // Q-DEL-A2A-SELECT).
        //
        // THE ADMISSION AND THE CATALOGUE AT ARRIVAL (the engine's `receive::admit`/`select`,
        // ARCHITECT Q-DEL-A2A-GATE/-SCOPE-TRUST): an addressed agent that is not serving, or whose
        // card the request does not fit, refuses the unit about that agent — the kernel judges the
        // caller's grant over it first and charges nothing; an unaddressed unit names the agents
        // that would serve it as its candidates, which the kernel intersects with the caller's
        // grant.
        let section = plane.generations.current();
        // BUSBAR'S EXTENDED CARD and A NOTIFICATION, the plane's own to answer before any agent
        // is selected ([`answered_here`]).
        if answered_here(&disposition, agent.is_some()) {
            out.local();
            keep(
                &plane.units,
                MAX_UNITS,
                given.unit,
                Unit {
                    disposition,
                    agent,
                    section,
                    hop: None,
                    pass: crate::task_door::Pass::default(),
                    envelope,
                    framed,
                    generation,
                    unreadable_rewrite: false,
                },
            );
            return Outcome::Ready;
        }
        // AT MOST ONCE (1.5.5's relay): an agent that ANSWERED with a failure is not retried on
        // another; its failure is the unit's answer, surfaced per attempt, while the walk still
        // moves past a member whose breaker is open before anything was sent.
        out.once();
        match &agent {
            Some(agent) => {
                out.route(ROUTE_DIRECT, agent);
                if let Some(def) = section.as_ref().and_then(|s| s.agents.get(agent)) {
                    if let Err(refusal) = admit_addressed(
                        plane,
                        (agent, def),
                        generation,
                        request.as_ref(),
                        &mut out,
                    ) {
                        return refused(&mut out, &refusal);
                    }
                }
            }
            None => {
                let candidates: Vec<&str> = section
                    .as_ref()
                    .map(|s| {
                        s.agents
                            .iter()
                            .filter(|(name, def)| {
                                admit_unit(plane, (name, def), None, generation, request.as_ref())
                                    .is_ok()
                            })
                            .map(|(name, _)| name.as_str())
                            .collect()
                    })
                    .unwrap_or_default();
                out.route(
                    ROUTE_SCOPE,
                    &candidates.join(busbar_contract::abi::plane::ROUTE_SCOPE_SEPARATOR),
                );
            }
        }
        let unit = Unit {
            disposition,
            agent,
            section: plane.generations.current(),
            hop,
            pass: crate::task_door::Pass::default(),
            envelope,
            framed,
            generation,
            unreadable_rewrite: false,
        };
        keep(&plane.units, MAX_UNITS, given.unit, unit);
        Outcome::Ready
    }
);

/// WHETHER THE PLANE ANSWERS AN ARRIVAL ITSELF, before any agent is selected: busbar's EXTENDED
/// card on the plane's own endpoint (the caller named no agent, so the verb asks busbar about itself;
/// the engine's `route::extended_agent_card`), and a NOTIFICATION wherever it arrived (received,
/// never answered and never relayed: the engine answered it `202` with no body and moved nothing).
pub(crate) fn answered_here(disposition: &Disposition, addressed: bool) -> bool {
    match disposition {
        Disposition::Request { row, .. } => !addressed && row.op == crate::ops::OP_AGENT_CARD,
        Disposition::Notice { .. } => true,
        _ => false,
    }
}

/// AN ARRIVAL ON THE OPEN LINE: a read of a card busbar serves ([`crate::served_card`]), kept with
/// the generation it arrived under. Busbar's own card (the well-known path) is unauthenticated and
/// the plane's own to answer (`ROUTE_LOCAL`); a fronted agent's card (`GET /a2a/agents/{id}`) needs
/// a principal and is routed to the addressed agent's entry, so the kernel judges the caller's grant
/// over it, and the agent's admission (its trust and a held card, the engine's `receive::admit`)
/// refuses about that agent. Every other open route (the protected-resource document is the
/// kernel's) is unserved here.
fn arrive_card(
    plane: &A2aDoor,
    route: &door::Route,
    target: &str,
    unit: u64,
    out: &mut Out<'_, ArriveOut>,
) -> Outcome {
    let generation = plane.newest();
    let (ask, agent) = if route.verb == "GET" && route.target == crate::WELL_KNOWN_CARD_PATH {
        (arrival::CardAsk::Own, None)
    } else if route.verb == "GET" && route.target == crate::mounted_route(crate::ROUTE_AGENT) {
        let Some(agent) = agent_of(target) else {
            return unserved(out);
        };
        (arrival::CardAsk::Agent, Some(agent))
    } else {
        return unserved(out);
    };
    let Some(op) = door::op_class_index(crate::ops::OP_AGENT_CARD) else {
        return unserved(out);
    };
    out.set(|o| &o.op_class, op);
    out.set(|o| &o.dialect, door::DIALECT_DOCUMENT);
    match &agent {
        None => {
            out.set(|o| &o.principal_need, PRINCIPAL_NONE);
            out.local();
        }
        Some(agent) => {
            out.set(|o| &o.principal_need, PRINCIPAL_REQUIRED);
            out.route(ROUTE_DIRECT, agent);
            let section = plane.generations.current();
            if let Some(def) = section.as_ref().and_then(|s| s.agents.get(agent)) {
                if let Err(refusal) = admit_addressed(plane, (agent, def), generation, None, out) {
                    return refused(out, &refusal);
                }
            }
        }
    }
    keep(
        &plane.units,
        MAX_UNITS,
        unit,
        Unit {
            disposition: Disposition::Card(ask),
            agent,
            section: plane.generations.current(),
            hop: None,
            pass: crate::task_door::Pass::default(),
            envelope: None,
            framed: None,
            generation,
            unreadable_rewrite: false,
        },
    );
    Outcome::Ready
}

/// The hop a unit's `on_piece` serves, as the engine relays it (`receive::unary_hop` and
/// `receive::stream_hop`): the extended-card read addressed to one agent, task-less (its
/// `card_fetch` arm); a request whose answer is events (the vocabulary's multi-frame rows, and an
/// unlisted method named as a stream), about a task, a subscribe answering busbar's own refusal
/// first; and every other relayed one-reply request, about a task (`request` is its envelope: the
/// caller's on the JSON-RPC line, the one its request spelled on the HTTP+JSON line). A verb the
/// plane answers itself has no hop.
fn hop_of(
    disposition: &Disposition,
    addressed: bool,
    request: Option<serde_json::Value>,
) -> Option<Hop> {
    use crate::local::{verb_of, LocalVerb};
    use crate::ops::{relay_class, OP_AGENT_CARD, OP_MESSAGE_SEND, OP_MESSAGE_STREAM};
    match disposition {
        Disposition::Request { row, id, version } if row.op == OP_AGENT_CARD => {
            addressed.then(|| Hop::of(id.clone(), version, request))
        }
        Disposition::Request { row, id, version } if row.multi_frame => {
            let subscribe = verb_of(row.method) == Some(LocalVerb::Subscribe);
            Some(Hop::events(id.clone(), version, request?, subscribe))
        }
        Disposition::Request { row, id, version } if verb_of(row.method).is_none() => {
            Some(Hop::task(id.clone(), version, request?))
        }
        Disposition::Unlisted {
            method,
            id,
            version,
        } => {
            let class = relay_class(method);
            if class == OP_MESSAGE_SEND {
                Some(Hop::task(id.clone(), version, request?))
            } else if class == OP_MESSAGE_STREAM {
                Some(Hop::events(id.clone(), version, request?, false))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The URL the operator wrote for agent `member` in the section the unit arrived under.
fn url_of<'a>(unit: &'a Unit, member: &str) -> Option<&'a str> {
    unit.section
        .as_ref()?
        .agents
        .get(member)
        .map(|a| a.url.as_str())
}

/// The host reach one piece's task work makes: the instance, and the piece's ticket.
struct Reach<'p> {
    plane: &'p A2aDoor,
    ticket: Ticket,
}

impl Reach<'_> {
    /// The piece's records and random bytes, counting on from the `issued` its unit's finished
    /// pieces made; `None` when the instance was opened without host tables.
    fn via(&self, issued: u32) -> Option<Via<'_>> {
        let host = self.plane.host.as_ref()?;
        Some(Via::new(
            host,
            self.plane.services,
            self.ticket,
            issued,
            &self.plane.grown,
        ))
    }

    /// Now, in seconds, from the host's clock.
    fn now(&self) -> Option<u64> {
        self.now_ms().map(|ms| ms / 1_000)
    }

    /// The host's wall clock, milliseconds.
    fn now_ms(&self) -> Option<u64> {
        let host = self.plane.host.as_ref()?;
        match host.connector(self.ticket).clock_now() {
            Poll::Ready(Ok(reading)) => Some(reading.wall_ns / 1_000_000),
            _ => None,
        }
    }
}

/// OPEN the task `hop` is about, at its first ATTEMPT ([`task_hop::open`]): its identity on the
/// relay and its record writes on `writes`, or the caller's whole answer when it does not go ahead.
fn open_task(
    reach: &Reach<'_>,
    hop: &mut Hop,
    pass: &mut crate::task_door::Pass,
    request: (&str, &str),
    skill: Option<String>,
    writes: &mut Vec<Write>,
) -> Result<Option<relay::Reply>, Outcome> {
    let (caller, member) = request;
    let Some(envelope) = hop.opening.as_ref() else {
        return Ok(None);
    };
    let now = match hop.now {
        Some(now) => now,
        None => *hop.now.insert(reach.now().ok_or(Outcome::Failed)?),
    };
    let mut via = reach.via(pass.issued).ok_or(Outcome::Failed)?;
    // THE MESSAGE ID a gRPC send with no message gets, as the SDK's model minted it (a v7 id over
    // the clock and ten random bytes), into every copy of the request the hop reads and relays.
    if hop.mint_message_id {
        let mut random = [0_u8; 10];
        if via.random(&mut random).is_err() {
            return Err(Outcome::Failed);
        }
        let ms = reach.now_ms().ok_or(Outcome::Failed)?;
        let id = crate::framed::message_id_v7(ms, &random);
        let minted = crate::framed::with_message_id(envelope, &id);
        if let Ok(bytes) = serde_json::to_vec(&minted) {
            hop.relay.send_instead(bytes);
        }
        hop.request = Some(minted.clone());
        hop.opening = Some(minted);
        hop.mint_message_id = false;
    }
    let Some(envelope) = hop.opening.as_ref() else {
        return Ok(None);
    };
    // A subscribe answers busbar's own refusal first, for a task it does not hold for this caller
    // or holds as terminal (the engine's local half of the verb); a live task is relayed.
    if hop.subscribe {
        let mut none = Vec::new();
        let refused = match crate::local::answer(
            &mut via,
            crate::local::LocalVerb::Subscribe,
            envelope,
            caller,
            now,
            &mut none,
        ) {
            Err(Halt::Pending) => return Err(Outcome::Pending),
            Err(Halt::Failed(_)) => Some(crate::local::unreadable(hop.relay.id())),
            Ok(answer) => answer,
        };
        if let Some(answer) = refused {
            pass.issued = via.issued();
            hop.opening = None;
            hop.now = None;
            return Ok(Some(relay::Reply {
                status: answer.status,
                content_type: crate::arrival::JSON_MEDIA_TYPE,
                body: answer.body,
            }));
        }
    }
    let backends = |id: &str| reach.plane.backends.get(&task_key(caller, id));
    let req = task_hop::Request {
        envelope,
        relayed: hop.rewritten.as_ref(),
        caller,
        member,
        now,
    };
    let opened = match task_hop::open(&mut via, &req, hop.relay.id(), &backends, writes) {
        Err(Halt::Pending) => return Err(Outcome::Pending),
        Err(Halt::Failed(_)) => return Err(Outcome::Failed),
        Ok(opened) => opened,
    };
    pass.issued = via.issued();
    hop.opening = None;
    hop.now = None;
    match opened {
        Opened::Refused(reply) => Ok(Some(reply)),
        Opened::Hop {
            mut task,
            instead,
            callback,
            read,
        } => {
            // The task as this opening left it: what a refusal before the dial ends `failed`.
            hop.opened = Some(OpenedTask {
                caller: caller.to_string(),
                now,
                records: read.into_iter().chain(writes.iter().cloned()).collect(),
            });
            // The credential an inline callback names is held in plane memory, as the engine's
            // delivery holds it: none clears one held.
            if let Some(callback) = callback {
                reach
                    .plane
                    .deliveries
                    .remember_auth(&task.task_id, callback.auth);
            }
            task.skill = skill;
            hop.relay.for_task(task);
            if let Some(body) = instead {
                hop.relay.send_instead(body);
            }
            Ok(None)
        }
    }
}

/// SETTLE the task `hop` is about on what its answer has said ([`task_hop::settle`]), in order: the
/// record writes ride with the answer, the far end's own id for the task is remembered, each move
/// of the task queues its push notification, and what earlier deliveries owe this caller's other
/// tasks' chains is filed.
fn settle_task(
    reach: &Reach<'_>,
    hop: &mut Hop,
    pass: &mut crate::task_door::Pass,
    caller: &str,
) -> Result<(), Outcome> {
    let settles = std::mem::take(&mut hop.settle);
    if settles.is_empty() {
        return Ok(());
    }
    let Some(task) = hop.relay.task().cloned() else {
        return Ok(());
    };
    let pend = |hop: &mut Hop, settles: Vec<Settled>| {
        hop.settle = settles;
        Err(Outcome::Pending)
    };
    let now = match hop.now {
        Some(now) => now,
        None => *hop.now.insert(reach.now().ok_or(Outcome::Failed)?),
    };
    let mut via = reach.via(pass.issued).ok_or(Outcome::Failed)?;
    let mut writes = Vec::new();
    let mut moved = Vec::new();
    let mut halted = false;
    for settled in &settles {
        match task_hop::settle(&mut via, &task, settled, caller, now, &mut writes) {
            Err(Halt::Pending) => {
                halted = true;
                break;
            }
            Err(Halt::Failed(_)) => {}
            Ok(row) => moved.extend(row),
        }
    }
    if halted {
        return pend(hop, settles);
    }
    // Each move owes its push notification. The config reads are made on every entry, so a
    // re-entry's host calls keep their order; each notification is queued once.
    for (i, row) in moved.iter().enumerate() {
        let config = match crate::local::held_config(&mut via, caller, &row.task_id) {
            Err(Halt::Pending) => return pend(hop, settles),
            Err(Halt::Failed(_)) => None,
            Ok(config) => config,
        };
        if i >= hop.queued {
            crate::push_door::queue(&reach.plane.deliveries, row, config.as_ref());
            hop.queued = i + 1;
        }
    }
    // What earlier deliveries owe this caller's other tasks' chains rides with this answer.
    let owed = hop
        .owed
        .get_or_insert_with(|| {
            reach
                .plane
                .deliveries
                .take_owed(caller, Some(task.task_id.as_str()))
        })
        .clone();
    if let Err(Halt::Pending) =
        crate::push_door::file_owed(&mut via, caller, &owed, now, &mut writes)
    {
        return pend(hop, settles);
    }
    hop.queued = 0;
    hop.owed = None;
    pass.issued = via.issued();
    for settled in settles {
        let backend = match settled {
            Settled::Reported { backend_id, .. } | Settled::Event { backend_id, .. } => backend_id,
            Settled::Failed => None,
        };
        // A far end that issued the SAME id busbar did needs no translation and holds no slot.
        if let Some(backend) = backend.filter(|b| *b != task.task_id) {
            keep(
                &reach.plane.backends,
                MAX_BACKEND_IDS,
                task_key(caller, &task.task_id),
                backend,
            );
        }
    }
    hop.outbox.writes.extend(writes);
    hop.now = None;
    Ok(())
}

/// A HOP THE KERNEL REFUSED FOR BUSBAR'S OWN CREDENTIAL (`credential_unavailable`: the agent's
/// `upstream_credential`, re-resolved for this hop, no longer resolves, so nothing was dialled):
/// logged as the engine logged a lease it could not mint (`A2A_OUTBOUND_CRED_UNLEASED`), the caller
/// answered in the engine's words ([`Relay::refuse_credential`]), re-framed on the HTTP+JSON line,
/// and a task the hop opened or addressed ended `failed` over the records its opening left
/// ([`task_hop::fail_unhosted`]: `refusal` is ticketless and reads no host), its push notification
/// queued as the engine's `end_task` sent one. Made once per unit: a short `refusal` re-called
/// renders the same answer and writes. `None` for a unit with no hop.
fn credential_refusal(plane: &A2aDoor, unit: &mut Unit) -> Option<(relay::Reply, Vec<Write>)> {
    let target_line = unit.envelope.is_some() && unit.framed.is_none();
    let addressed = unit.agent.clone();
    let hop = unit.hop.as_mut()?;
    if let Some(made) = &hop.credential {
        return Some(made.clone());
    }
    let agent = if hop.member.is_empty() {
        addressed.unwrap_or_default()
    } else {
        hop.member.clone()
    };
    busbar_contract::diag_warn!(
        crate::diagnostics::A2A_OUTBOUND_CRED_UNLEASED,
        agent = %agent,
        "a2a: the outbound credential could not be leased"
    );
    let (mut reply, failed) = hop.relay.refuse_credential();
    let mut writes = Vec::new();
    if let (true, Some(task), Some(opened)) = (failed, hop.relay.task().cloned(), hop.opened.take())
    {
        let (made, moved) =
            task_hop::fail_unhosted(&task, &opened.records, &opened.caller, opened.now);
        writes = made;
        if let Some(row) = moved {
            crate::push_door::queue(&plane.deliveries, &row, None);
        }
    }
    if target_line {
        reply.body = crate::rest::reframe(reply.status, &reply.body);
    }
    hop.credential = Some((reply.clone(), writes.clone()));
    Some((reply, writes))
}

/// THE KERNEL'S VERDICT ON `agent` (`trust.serves`: the kernel's Approve as a query, ARCHITECT
/// FLIP-A2A; it never pends, so it rides no ticket): [`svc::DISTRUST_NONE`] serves, any other
/// `DISTRUST_*` refuses. An instance opened without host services, or a service that does not
/// answer, is trusted with nothing.
pub(crate) fn verdict(plane: &A2aDoor, agent: &str) -> u64 {
    use busbar_contract::abi::host::service as svc;
    let Some(services) = plane.services else {
        return svc::DISTRUST_UNKNOWN;
    };
    let handle = CompletionHandle {
        ticket: Ticket::NONE,
        seq: 0,
        _reserved: 0,
    };
    services
        .trust_serves(handle, agent, None, None)
        .unwrap_or(svc::DISTRUST_UNKNOWN)
}

/// AN ARRIVAL ADDRESSED TO `member` STATES ITS TRUST FACTS (the agent, as the counterparty, ARCHITECT
/// FLIP-A2A): the kernel's Approve judges them and refuses an agent its trust book does not serve
/// (`untrusted`, rendered by `refusal` in the admission's words). Only an agent the book serves is
/// held to the plane's own admission here ([`admit_unit`]: its suspension and its card's fit), so
/// trust is judged before the fit, as 1.5.5's admission ordered them.
fn admit_addressed(
    plane: &A2aDoor,
    (member, def): (&str, &crate::a2a::config::AgentDefCfg),
    generation: u64,
    envelope: Option<&serde_json::Value>,
    out: &mut Out<'_, ArriveOut>,
) -> Result<Option<String>, arrival::Refusal> {
    out.trust(member, None, None);
    if verdict(plane, member) != busbar_contract::abi::host::service::DISTRUST_NONE {
        return Ok(None);
    }
    admit_unit(plane, (member, def), Some(member), generation, envelope)
}

/// THE ADMISSION AND THE CATALOGUE (the engine's `receive::admit`, after the kernel's identity and
/// grant), for a unit routed to `member` (`def`): an agent the anomaly breaker suspended, or one
/// the KERNEL'S TRUST BOOK does not serve ([`verdict`]: never approved, or quarantined), is refused
/// in the admission's words ([`crate::trust::not_serving`]); one with no held card, or whose held
/// card the request's shape (`envelope`) does not fit, is excluded from the catalogue — addressed,
/// the catalogue's refusal naming the exclusion (`403`, [`crate::skill::refusal`]), routed by
/// scope, the none-refusal. The skill the card matched.
pub(crate) fn admit_unit(
    plane: &A2aDoor,
    (member, _def): (&str, &crate::a2a::config::AgentDefCfg),
    addressed: Option<&str>,
    generation: u64,
    envelope: Option<&serde_json::Value>,
) -> Result<Option<String>, arrival::Refusal> {
    use crate::trust::{not_serving, state_of, State, NOT_SERVING_STATUS, UNTRUSTED_STATUS};
    let standing = plane.trust.get(&member.to_string());
    if let Some(reason) = standing.as_ref().and_then(|s| s.suspension.as_deref()) {
        return Err(not_serving(
            addressed,
            State::Suspended,
            Some(reason),
            NOT_SERVING_STATUS,
        ));
    }
    let distrust = verdict(plane, member);
    if distrust != busbar_contract::abi::host::service::DISTRUST_NONE {
        return Err(not_serving(
            addressed,
            state_of(distrust),
            None,
            UNTRUSTED_STATUS,
        ));
    }
    let excluded = |unfit: crate::skill::Unfit| match addressed {
        Some(_) => crate::skill::refusal(&unfit),
        None => arrival::scope_refusal(""),
    };
    let Some(card) = plane.cards.at(member, generation) else {
        return Err(excluded(crate::skill::Unfit::NoCachedCard));
    };
    let shape = envelope
        .map(crate::skill::TaskShape::of)
        .unwrap_or_default();
    crate::skill::fit(&card, &shape).map_err(excluded)
}

/// A refusal as the caller's whole answer: its status, and its envelope.
fn reply_of(refusal: &arrival::Refusal) -> relay::Reply {
    relay::Reply {
        status: refusal.status,
        content_type: arrival::JSON_MEDIA_TYPE,
        body: serde_json::to_vec(&refusal.envelope()).unwrap_or_default(),
    }
}

/// BIND the hop to the binding `member`'s card held under `generation` declares; the refusal's
/// answer when the plane frames none of them.
fn bind(reach: &Reach<'_>, hop: &mut Hop, member: &str, generation: u64) -> Option<Answer> {
    let card = reach.plane.cards.at(member, generation);
    let word = crate::binding::binding_of(card.as_deref());
    match crate::binding::speakable(&word) {
        Some(binding) => {
            let envelope = hop
                .rewritten
                .clone()
                .or_else(|| hop.request.clone())
                .unwrap_or(serde_json::Value::Null);
            hop.relay.bind(binding, &envelope);
            None
        }
        None => Some(hop.relay.refuse_unspeakable(&word)),
    }
}

/// The caller's answer as its line spells it: on the HTTP+JSON line (`target_line`) a whole answer
/// is re-framed ([`crate::rest::reframe`]) and each event to its bare result
/// ([`crate::events::reframe_events`]), as the engine re-frames what its shared sequence answered;
/// on the JSON-RPC line it leaves as the relay wrote it.
#[must_use]
pub fn for_line(answer: Answer, target_line: bool) -> Answer {
    match answer {
        Answer::ToCaller(mut reply) if target_line => {
            reply.body = crate::rest::reframe(reply.status, &reply.body);
            Answer::ToCaller(reply)
        }
        Answer::Part(mut part) if target_line => {
            part.body = crate::events::reframe_events(&part.body);
            Answer::Part(part)
        }
        other => other,
    }
}

/// One piece of `unit`'s hop: applied (unless it continues or re-calls the answer still owed) and
/// written into the host's buffers. A task hop's first ATTEMPT opens its task first, and the far
/// end's answer settles it before anything is written. Answers the outcome and whether the unit is
/// done.
fn piece(
    reach: &Reach<'_>,
    unit: &mut Unit,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> (Outcome, bool) {
    let given = input.get();
    let bytes = input.field(|i| &i.bytes).bytes();
    let given_member = input.field(|i| &i.member).as_str().unwrap_or_default();
    let caller = input.field(|i| &i.caller_ref).as_str().unwrap_or_default();
    // The agent the unit's ATTEMPT reached, kept for its later pieces (the far end's name none).
    if let Some(hop) = unit.hop.as_mut() {
        if given.from == FROM_KERNEL && !given_member.is_empty() {
            hop.member = given_member.to_string();
        }
    }
    let member_owned = unit
        .hop
        .as_ref()
        .map(|h| h.member.clone())
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| given_member.to_string());
    let member = member_owned.as_str();
    let url = url_of(unit, member).map(str::to_string);
    // THE AGENT'S REGISTRATION, as the unit's generation holds it: what the trust gates judge.
    let def = unit
        .section
        .as_ref()
        .and_then(|s| s.agents.get(member))
        .cloned();
    let addressed = unit.agent.clone();
    let framed = unit.framed;
    let target_line = unit.envelope.is_some() && framed.is_none();
    let pass = &mut unit.pass;
    let Some(hop) = unit.hop.as_mut() else {
        return (Outcome::Refused, false);
    };
    // A re-call carries the same piece again (after a short or pending answer) or nothing at all
    // (after `more = 1`: no bytes, no flags, no attempt); either way it is served from what is owed.
    let continues = hop.outbox.live
        && (hop.outbox.recall || (bytes.is_empty() && given.flags == 0 && given.attempt_no == 0));
    if !continues {
        let mut writes = std::mem::take(&mut hop.held_writes);
        // THE ADMISSION GATE (the engine's ordered gate, its artifact step), on the ATTEMPT's first
        // entry: an agent whose recorded state is not `approved` is refused before anything else
        // the hop does, in the admission's words.
        let admission = match (&def, given.from == FROM_KERNEL && !hop.admitted) {
            (Some(def), true) => {
                let admitted = admit_unit(
                    reach.plane,
                    (member, def),
                    addressed.as_deref(),
                    unit.generation,
                    hop.request.as_ref(),
                );
                match admitted {
                    Ok(skill) => {
                        hop.admitted = true;
                        hop.skill = skill;
                        None
                    }
                    Err(refusal) => Some(reply_of(&refusal)),
                }
            }
            _ => None,
        };
        let opened = if let Some(reply) = admission {
            Some(reply)
        } else if given.from == FROM_KERNEL {
            // The skill the agent's held card matched at admission (ARCHITECT ruling B2).
            let skill = hop.skill.clone();
            match open_task(reach, hop, pass, (caller, member), skill, &mut writes) {
                Err(outcome) => return (outcome, false),
                Ok(refused) => refused,
            }
        } else {
            None
        };
        // VERIFY-ON-CALL, then THE HOP'S TRUST GATE: after the task is opened (the engine's order:
        // its local verbs and the addressed task's lookup first), the agent's card is re-verified
        // when its `reverify_ttl` has lapsed, and an agent the look demoted is not sent the request.
        let demoted = match (&def, given.from == FROM_KERNEL && opened.is_none()) {
            (Some(def), true) => {
                match verify_on_call(reach, hop, pass, member, def, unit.generation) {
                    Poll::Pending => {
                        hop.held_writes = writes;
                        return (Outcome::Pending, false);
                    }
                    Poll::Ready(true) => None,
                    Poll::Ready(false) => Some(hop.relay.refuse_demoted()),
                }
            }
            _ => None,
        };
        // The binding this attempt speaks, off the agent's held card (JSON-RPC when none is held);
        // a card naming only a binding the plane does not frame refuses the hop by name.
        let unspeakable = if given.from == FROM_KERNEL && opened.is_none() && demoted.is_none() {
            bind(reach, hop, member, unit.generation)
        } else {
            None
        };
        // THE RELAY'S GUARD, last before the attempt goes (the engine's `relay::prepare`).
        let unguarded = match (&def, &url) {
            (Some(def), Some(url))
                if given.from == FROM_KERNEL
                    && opened.is_none()
                    && demoted.is_none()
                    && unspeakable.is_none() =>
            {
                match guard_relay(reach, hop, pass, url, def) {
                    Poll::Pending => {
                        hop.held_writes = writes;
                        return (Outcome::Pending, false);
                    }
                    Poll::Ready(refused) => refused,
                }
            }
            _ => None,
        };
        let answer = match (opened, demoted.or(unspeakable).or(unguarded)) {
            (Some(reply), _) => Answer::ToCaller(reply),
            (None, Some(answer)) => answer,
            (None, None) => {
                let from = match given.from {
                    FROM_KERNEL => relay::From::Kernel(url.as_deref()),
                    FROM_CALLER => relay::From::Caller,
                    FROM_FAR_END => relay::From::FarEnd,
                    _ => return (Outcome::Refused, false),
                };
                let status = (given.flags & PIECE_HAS_STATUS != 0).then_some(given.status_code);
                let last = given.flags & PIECE_LAST != 0;
                // THE FAR END'S TRAILERS (`PIECE_FIELDS`): the relay reads what they say (a gRPC
                // call's status), never as bytes of the answer.
                if from == relay::From::FarEnd
                    && given.flags & busbar_contract::abi::plane::PIECE_FIELDS != 0
                {
                    hop.relay.on_far_fields(bytes, status, last)
                } else {
                    hop.relay.on_piece(relay::Piece {
                        from,
                        bytes,
                        status,
                        last,
                    })
                }
            }
        };
        let outbox = match framed {
            Some(rpc) => Outbox::framed(answer, rpc),
            None => Outbox::of(for_line(answer, target_line)),
        };
        let Some(outbox) = outbox else {
            return (Outcome::Refused, false);
        };
        hop.outbox = outbox;
        hop.outbox.writes = writes;
        // THE BREAKER'S READING (ARCHITECT ruling, FAULT_HEALTHY): the far end's answer read where
        // its structure still exists — on the piece holding the whole answer, or on a stream's
        // first event — the engine's `classify_hop` table; none stated, the kernel's table reads it.
        hop.outbox.fault = hop.relay.take_reading().map_or(FAULT_NONE, fault_of);
        hop.settle.extend(hop.relay.take_settled());
        // Until it is written, a re-call of this piece is served from what is owed.
        hop.outbox.recall = true;
    }
    if !hop.settle.is_empty() {
        if let Err(outcome) = settle_task(reach, hop, pass, caller) {
            return (outcome, false);
        }
    }
    // THE FEE UNIT: a hop that left the plane for its agent is served, whatever the agent then
    // answered (the served engine billed a hop that went to the transport, and gave the fee back
    // only to one refused before the socket).
    if matches!(hop.outbox.head, Some(Head::Attempt(_))) {
        hop.left = true;
    }
    let left = hop.left;
    let admitted = hop.admitted;
    let need = attempt_need(hop.relay.binding());
    let ob = &mut hop.outbox;
    let (mut reply, mut fields, mut records, mut arena, mut units) = (
        input.reply_buf(),
        input.fields_buf(),
        input.records_buf(),
        input.arena_buf(),
        input.units_buf(),
    );
    let moved = hop.relay.moved();
    if moved != 0 {
        units.push(UnitCount {
            class: door::CLASS_BYTES_INDEX,
            source: UNITS_REPORTED,
            amount: moved,
        });
    }
    if left {
        units.push(UnitCount {
            class: door::CLASS_FEE_INDEX,
            source: UNITS_REPORTED,
            amount: 1,
        });
    }
    let mut head_fields = |list: &[(&'static str, String)]| {
        for (name, value) in list {
            fields.push(OutField {
                name: arena.span(name.as_bytes()),
                value: arena.span(value.as_bytes()),
            });
        }
    };
    let (mut verb, mut target, mut status) = (None, None, 0);
    match &ob.head {
        Some(Head::Attempt(a)) => {
            head_fields(&a.fields);
            verb = Some(arena.span(a.verb.as_bytes()));
            target = Some(arena.span(a.target.as_bytes()));
        }
        Some(Head::Reply(s, content_type)) => {
            // A WHOLE answer states its length, so it is sent under it as the engine sent its
            // buffered JSON answer (never chunked).
            head_fields(&[
                (relay::H_CONTENT_TYPE, (*content_type).to_string()),
                (H_CONTENT_LENGTH, ob.bytes.len().to_string()),
            ]);
            status = *s;
        }
        Some(Head::Events) => {
            head_fields(&EVENTS_HEAD.map(|(name, value)| (name, value.to_string())));
            status = relay::STATUS_OK;
        }
        // The gRPC line's head carries no media type and no length (the grpc transport frames):
        // its status, and the status details when there are any.
        Some(Head::Framed(code, details)) => {
            if let Some(details) = details {
                head_fields(&[(crate::framed::DETAILS_FIELD, details.clone())]);
            }
            status = *code;
        }
        None => {}
    }
    for w in &ob.writes {
        records.push(RecordWrite {
            kind: kind_index(w.kind),
            op: RECORD_PUT,
            key: arena.span(w.key.as_bytes()),
            value: arena.span(&w.value),
        });
    }
    // THE UNIT'S AUDIT ROW, with the head of the caller's answer, for a unit its admission passed:
    // served when its hop left the plane, rejected when it was refused before it did (the engine's
    // hop charge: `settle` applied, `refused` rejected).
    let caller_head = matches!(
        ob.head,
        Some(Head::Reply(..) | Head::Events | Head::Framed(..))
    );
    if caller_head && admitted && !member.is_empty() {
        records.push(door::audit_write(
            &mut arena,
            &door::agent_resource(member),
            left,
        ));
    }
    // THE UNIT'S LEDGER LANE (SEAM-L(j)): the agent it reached, as the engine's meter named it
    // (`agent:<id>`), so the agent's rate card prices it and the metering rows read as 1.5.5's.
    let lane = (!member.is_empty()).then(|| arena.span(door::agent_resource(member).as_bytes()));
    // A stream that already sent messages states the status it ends with on its closing answer:
    // its message and details are in the arena by then.
    let closing_final = ob
        .final_status
        .as_ref()
        .filter(|_| ob.done && ob.queue.is_empty())
        .map(|f| {
            (
                f.code,
                arena.span(&f.body),
                arena.span(f.details.as_deref().unwrap_or_default().as_bytes()),
            )
        });
    let short = !(fields.fits() && records.fits() && arena.fits() && units.fits());
    let (fw, fnd) = fields.settle(short);
    let (rw, rnd) = records.settle(short);
    let (aw, and) = arena.settle(short);
    let (uw, und) = units.settle(short);
    out.set(|o| &o.fields_written, fw as u32);
    out.set(|o| &o.fields_needed, fnd as u32);
    out.set(|o| &o.records_written, rw as u32);
    out.set(|o| &o.records_needed, rnd as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, and as u64);
    out.set(|o| &o.units_written, uw as u32);
    out.set(|o| &o.units_needed, und as u32);
    if short {
        ob.recall = true;
        return (Outcome::Failed, false);
    }
    let n = reply.stream(&ob.bytes[ob.at..]);
    ob.at += n;
    // A message's last byte is written: the boundary that frames it (the gRPC line).
    let message_end = ob.messages && ob.at >= ob.bytes.len();
    // The gRPC line's next message, once this one is written: emitted on an answer of its own.
    if ob.at >= ob.bytes.len() {
        if let Some(next) = ob.queue.pop_front() {
            ob.bytes = next;
            ob.at = 0;
        }
    }
    ob.head = None;
    ob.writes.clear();
    ob.recall = false;
    let more = ob.at < ob.bytes.len();
    ob.live = more;
    let mut flags = 0;
    if ob.to_far {
        flags |= EMIT_TO_FAR_END;
    }
    let done = ob.done && !more;
    if done {
        flags |= EMIT_DONE;
    }
    if message_end {
        flags |= busbar_contract::abi::plane::EMIT_MESSAGE_END;
    }
    if let Some((code, message, details)) = closing_final.filter(|_| done) {
        flags |= busbar_contract::abi::plane::EMIT_FINAL_STATUS;
        out.set(|o| &o.final_status, code);
        out.set(|o| &o.final_message, message);
        out.set(|o| &o.final_details, details);
    }
    if let (Some(v), Some(t)) = (verb, target) {
        out.set(|o| &o.verb, v);
        out.set(|o| &o.target, t);
        // THE NEED THE ATTEMPT RIDES: a gRPC-bound agent is dialled over the door's gRPC need.
        out.set(|o| &o.need, need);
    }
    if let Some(lane) = lane {
        out.set(|o| &o.lane, lane);
    }
    out.set(|o| &o.emitted, n as u64);
    out.set(|o| &o.more, u32::from(more));
    out.set(|o| &o.flags, flags);
    out.set(|o| &o.reply_status, status);
    // Stated once, on the READY answer that writes it (a short answer's re-call states it then).
    out.set(|o| &o.fault, std::mem::replace(&mut ob.fault, FAULT_NONE));
    (Outcome::Ready, done)
}

/// THE NEED AN ATTEMPT ON `binding` RIDES, as `OnPieceOut::need` names it (its index plus one;
/// `0` = the member's own, [`door::NEED_AGENT`]): the gRPC binding rides [`door::NEED_GRPC`], every
/// other binding the agent's own need.
#[must_use]
pub fn attempt_need(binding: crate::binding::Binding) -> u32 {
    match binding {
        crate::binding::Binding::Grpc => door::NEED_GRPC + 1,
        crate::binding::Binding::JsonRpc | crate::binding::Binding::HttpJson => 0,
    }
}

/// The shared fault reading a [`relay::Reading`] is.
fn fault_of(reading: relay::Reading) -> u8 {
    match reading {
        relay::Reading::Healthy => FAULT_HEALTHY,
        relay::Reading::Caller => FAULT_CALLER,
        relay::Reading::Transient => FAULT_TRANSIENT,
        relay::Reading::Hard => FAULT_HARD,
    }
}

slot!(
    /// `on_piece`: the unit's unary hop, one piece at a time ([`crate::relay`]); otherwise a verb
    /// the plane answers itself, over the task store ([`crate::task_door`]); a unit that is
    /// neither is REFUSED. A finished hop's unit is forgotten.
    OnPiece, OnPieceIn, OnPieceOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let unit = input.get().unit;
        let card = plane.units.with(&unit, |u| match u {
            Some(u) => match &u.disposition {
                Disposition::Card(ask) => Some(*ask),
                Disposition::Request { row, .. }
                    if row.op == crate::ops::OP_AGENT_CARD && u.agent.is_none() =>
                {
                    Some(arrival::CardAsk::Extended)
                }
                _ => None,
            },
            None => None,
        });
        if let Some(ask) = card {
            return crate::task_door::card_piece(plane, &instance, input, out, ask);
        }
        let relayed = plane.units.with(&unit, |u| u.is_some_and(|u| u.hop.is_some()));
        if !relayed {
            return crate::task_door::on_piece(plane, &instance, input, out)
                .unwrap_or(Outcome::Refused);
        }
        let reach = Reach {
            plane,
            ticket: instance.ticket(),
        };
        let (outcome, done) = plane.units.with(&unit, |u| match u {
            Some(u) => piece(&reach, u, input, &mut out),
            None => (Outcome::Refused, false),
        });
        if done {
            plane.units.remove(&unit);
        }
        outcome
    }
);

/// THE AGENTS OF `reachable` (the kernel's list for a unit routed by scope) IN THE CALLER'S
/// CATALOGUE: the engine chose among those, and an agent the kernel's trust book does not serve,
/// holds no card, or
/// whose card the unit's request does not fit, is in no catalogue ([`admit_unit`]). Where exactly
/// one of them is, the kernel's list stands: the engine would have chosen that one, and a refusal
/// naming it alone would name no choice.
fn serving_of(plane: &A2aDoor, unit: u64, reachable: &str) -> String {
    use busbar_contract::abi::plane::ROUTE_SCOPE_SEPARATOR;
    let (generation, envelope) = plane.units.with(&unit, |u| {
        u.map_or((plane.newest(), None), |u| {
            (u.generation, u.hop.as_ref().and_then(|h| h.request.clone()))
        })
    });
    let section = plane.generations.current();
    let serving: Vec<&str> = reachable
        .split(ROUTE_SCOPE_SEPARATOR)
        .filter(|id| {
            section
                .as_ref()
                .and_then(|s| s.agents.get(*id))
                .is_some_and(|def| {
                    admit_unit(plane, (id, def), Some(id), generation, envelope.as_ref()).is_ok()
                })
        })
        .collect();
    if serving.len() == 1 {
        return reachable.to_string();
    }
    serving.join(ROUTE_SCOPE_SEPARATOR)
}

slot!(
    /// `refusal`: a refused arrival rendered in its own words and status, and a kernel or gate
    /// refusal in the engine's admission words at the kernel's status, each in the line's dialect;
    /// on the gRPC line, the envelope at its neutral status, for the grpc transport to map. The
    /// gate-rejected marker is the kernel's: this rendering never sets it.
    RefusalSlot, RefusalIn, RefusalOut, |instance, input, mut out| {
        let given = input.get();
        // An unaddressed unit no one agent of the caller's grant reaches (the kernel's
        // `no_destination` for a unit routed by scope): 1.5.5's own words, the several agents it
        // reaches named from the kernel's text.
        let scoped = given.reason == busbar_contract::abi::plane::RefusalCode::NoDestination.code()
            && instance.get().is_some_and(|plane| {
            plane
                .units
                .with(&given.unit, |u| u.is_some_and(|u| u.agent.is_none()))
        });
        let dialect = match given.dialect {
            door::DIALECT_DOCUMENT => Dialect::JsonRpc,
            door::DIALECT_TARGET => Dialect::RestJson,
            door::DIALECT_FRAMED => Dialect::Framed,
            _ => return Outcome::Refused,
        };
        let text = input.field(|i| &i.text).bytes();
        // A unit its agent's open breaker refused before it dialled: 1.5.5's words for it, naming
        // the agent and the seconds until it may be dialled again, which `Retry-After` repeats.
        let retry_after = given.retry_after_s.max(1);
        let tripped = (given.reason
            == busbar_contract::abi::plane::RefusalCode::BreakerOpen.code())
        .then(|| {
            instance.get().and_then(|plane| {
                plane.units.with(&given.unit, |u| {
                    let u = u?;
                    let id = match &u.disposition {
                        Disposition::Request { id, .. } | Disposition::Unlisted { id, .. } => {
                            (!id.is_null()).then(|| id.clone())
                        }
                        _ => None,
                    };
                    let agent = u.agent.clone()?;
                    Some(arrival::breaker_refusal(&agent, id, retry_after))
                })
            })
        })
        .flatten();
        // A unit whose agent the KERNEL'S TRUST BOOK does not serve (its Approve refused the trust
        // facts the arrival stated: never approved, or quarantined): the admission's words for an
        // agent that is not serving, at the kernel's status, its state the book's verdict.
        let untrusted = (given.reason
            == busbar_contract::abi::plane::RefusalCode::Untrusted.code())
        .then(|| {
            instance.get().and_then(|plane| {
                plane.units.with(&given.unit, |u| {
                    let agent = u?.agent.clone()?;
                    Some(crate::trust::not_serving(
                        Some(&agent),
                        crate::trust::state_of(u64::from(given.trust)),
                        None,
                        given.status,
                    ))
                })
            })
        })
        .flatten();
        // A unit `project` refused for a committed rewrite it could not read back: predev's
        // conformant internal error, echoing the request id.
        let unreadable = instance
            .get()
            .and_then(|plane| {
                plane.units.with(&given.unit, |u| {
                    let u = u.filter(|u| u.unreadable_rewrite)?;
                    let id = match &u.disposition {
                        Disposition::Request { id, .. } | Disposition::Unlisted { id, .. } => {
                            (!id.is_null()).then(|| id.clone())
                        }
                        _ => None,
                    };
                    Some(unreadable_rewrite(id))
                })
            });
        // A hop the kernel refused for busbar's own credential: the engine's answer to a lease it
        // could not mint, and its task ended `failed` ([`credential_refusal`]).
        let credential = (given.reason
            == busbar_contract::abi::plane::RefusalCode::CredentialUnavailable.code())
        .then(|| {
            instance.get().and_then(|plane| {
                plane
                    .units
                    .with(&given.unit, |u| u.and_then(|u| credential_refusal(plane, u)))
            })
        })
        .flatten();
        let rendered = if let Some(refusal) = &unreadable {
            arrival::render(dialect, refusal, true)
        } else if let Some((reply, _)) = &credential {
            arrival::Rendered {
                status: reply.status,
                body: reply.body.clone(),
                content_type: reply.content_type,
            }
        } else if let Some(refusal) = &tripped {
            arrival::render(dialect, refusal, true)
        } else if let Some(refusal) = &untrusted {
            arrival::render(dialect, refusal, true)
        } else if scoped {
            let reachable = std::str::from_utf8(text).unwrap_or_default();
            let serving = instance
                .get()
                .map_or_else(|| reachable.to_string(), |plane| {
                    serving_of(plane, given.unit, reachable)
                });
            arrival::render(dialect, &arrival::scope_refusal(&serving), true)
        } else if given.cause == REFUSAL_ARRIVE {
            let Some(refusal) = arrival::Refusal::from_words(text) else {
                return Outcome::Refused;
            };
            arrival::render(dialect, &refusal, true)
        } else {
            let text = std::str::from_utf8(text).unwrap_or_default();
            // A refusal of the caller's governance (a spent budget, a request limit, a frozen
            // group, a reached overdraft ceiling) in the engine's own words for it.
            use busbar_contract::abi::plane::RefusalCode as Code;
            let governance = [
                Code::RateLimited,
                Code::OverBudget,
                Code::GroupFrozen,
                Code::OverdraftCeiling,
            ]
            .iter()
            .any(|c| c.code() == given.reason);
            let text = if governance { arrival::BUDGET_SPENT } else { text };
            // A caller whose grant does not reach the agent it addressed: the engine's
            // `NotInScope` sentence, naming the agent's scope.
            let ungranted = (given.reason == Code::ScopeDenied.code())
                .then(|| {
                    instance.get().and_then(|plane| {
                        plane
                            .units
                            .with(&given.unit, |u| u.and_then(|u| u.agent.clone()))
                    })
                })
                .flatten()
                .map(|agent| arrival::not_granted(&door::agent_resource(&agent)));
            let text = ungranted.as_deref().unwrap_or(text);
            arrival::render(dialect, &arrival::kernel_refusal(given.status, text), false)
        };
        // ON THE gRPC LINE the rendered envelope is the status the call ends with, as the engine's
        // bridge read its ingress's envelope: the status in the line's own numbering, its message
        // as the reply's bytes, its details as the details field.
        let (body, head, status) = if dialect == Dialect::Framed {
            let neutral = if rendered.status == 0 {
                given.status
            } else {
                rendered.status
            };
            let reply = crate::framed::refusal(&rendered.body, neutral);
            let head = reply
                .details
                .map(|d| (crate::framed::DETAILS_FIELD, d))
                .into_iter()
                .collect::<Vec<_>>();
            (reply.body, head, reply.code)
        } else {
            let mut head = vec![("content-type", rendered.content_type.to_string())];
            if tripped.is_some() {
                head.push(("retry-after", retry_after.to_string()));
            }
            (rendered.body, head, rendered.status)
        };
        // THE UNIT'S AUDIT ROW, rejected, for a refusal the engine made after its admission (a
        // gate's veto, a spent budget, an open breaker), naming the unit's agent (or busbar's
        // extended card's plane pool); a refusal before it (no key, no grant) leaves none.
        use busbar_contract::abi::plane::RefusalCode;
        let after_admission = given.cause == busbar_contract::abi::plane::REFUSAL_GATE
            || [
                RefusalCode::HookVeto,
                RefusalCode::OverBudget,
                RefusalCode::GroupFrozen,
                RefusalCode::OverdraftCeiling,
                RefusalCode::BreakerOpen,
                RefusalCode::CredentialUnavailable,
            ]
            .iter()
            .any(|c| c.code() == given.reason)
            // predev audited an unreadable rewrite's refusal `rejected`, as a hook's own.
            || unreadable.is_some();
        let audited = after_admission
            .then(|| {
                instance.get().and_then(|plane| {
                    plane.units.with(&given.unit, |u| {
                        u.and_then(|u| match (&u.disposition, &u.agent) {
                            (Disposition::Request { row, .. }, None)
                                if row.op == crate::ops::OP_AGENT_CARD =>
                            {
                                Some(door::PLANE_POOL_RESOURCE.to_string())
                            }
                            (_, Some(agent)) => Some(door::agent_resource(agent)),
                            _ => None,
                        })
                    })
                })
            })
            .flatten();
        let (mut reply, mut fields, mut arena, mut records) = (
            input.reply_buf(),
            input.fields_buf(),
            input.arena_buf(),
            input.records_buf(),
        );
        reply.extend(&body);
        for (name, value) in &head {
            fields.push(OutField {
                name: arena.span(name.as_bytes()),
                value: arena.span(value.as_bytes()),
            });
        }
        // The writes ending the task a credential refusal failed, before the unit's audit row.
        for w in credential.iter().flat_map(|(_, writes)| writes) {
            records.push(RecordWrite {
                kind: kind_index(w.kind),
                op: RECORD_PUT,
                key: arena.span(w.key.as_bytes()),
                value: arena.span(&w.value),
            });
        }
        if let Some(resource) = &audited {
            records.push(door::audit_write(&mut arena, resource, false));
        }
        let short = !(reply.fits() && fields.fits() && arena.fits() && records.fits());
        let (rw, rnd) = reply.settle(short);
        let (fw, fnd) = fields.settle(short);
        let (cw, cnd) = records.settle(short);
        out.set(|o| &o.records_written, cw as u32);
        out.set(|o| &o.records_needed, cnd as u32);
        let (aw, and) = arena.settle(short);
        out.set(|o| &o.reply_written, rw as u64);
        out.set(|o| &o.reply_needed, rnd as u64);
        out.set(|o| &o.fields_written, fw as u32);
        out.set(|o| &o.fields_needed, fnd as u32);
        out.set(|o| &o.arena_written, aw as u64);
        out.set(|o| &o.arena_needed, and as u64);
        if short {
            return Outcome::Failed;
        }
        out.set(|o| &o.status, status);
        Outcome::Ready
    }
);

// ── THE TRUST VERBS (ARCHITECT Q-L3B-VERBS) ──────────────────────────────────────────────────────

/// The agent a trust verb's target names: the segment its route's `{name}` stands at.
fn verb_agent(route: &str, target: &[u8]) -> Option<String> {
    let target = std::str::from_utf8(target).ok()?;
    let path = target.split(['?', '#']).next().unwrap_or(target);
    let at = route.split('/').position(|seg| seg == "{name}")?;
    let name = path.split('/').nth(at)?;
    (!name.is_empty()).then(|| name.to_string())
}

/// What one look landed: the sighting, and the card document a verified sighting was taken from.
#[derive(Debug)]
struct Looked {
    sighting: crate::trust::Sighting,
    card: Option<serde_json::Value>,
}

/// A look paused: its card fetch on the connection need (the legacy path's or the canonical's,
/// the handle it counts on from, the exchange), or its sighting on the kernel's trust book (what
/// it landed, and the handles it issued).
#[derive(Debug)]
enum LookParked {
    /// One hop of the card fetch is in flight: its destination's judgement (`exchange` absent), or
    /// its request (the exchange, and the handle it counts on from).
    Fetching {
        hop: CardHop,
        exchange: Option<ParkedExchange>,
    },
    /// `trust.sight` is in flight.
    Sighted(Looked, u32),
}

/// Where a look runs: the instance, the op's ticket, and the completion handle its host services
/// count on from (every service the op made before it, so a handle is never issued twice on the
/// op: the replay rule).
struct LookAt<'a> {
    plane: &'a A2aDoor,
    ticket: Ticket,
    base: u32,
}

impl LookAt<'_> {
    fn handle(&self, seq: u32) -> CompletionHandle {
        CompletionHandle {
            ticket: self.ticket,
            seq,
            _reserved: 0,
        }
    }
}

/// A card fetch's request in flight: the handle it counts on from, and the exchange.
type ParkedExchange = (u32, Box<busbar_contract::abi::sdk::exchange::Exchange>);

/// ONE HOP OF A CARD FETCH: which discovery path it is on, how many redirects its chain followed,
/// the URL it reaches, and the handle its services count on from.
#[derive(Debug, Clone)]
struct CardHop {
    legacy: bool,
    redirects: u8,
    url: String,
    issued: u32,
}

/// The most addresses one card host's judgement is read for.
const JUDGED_ADDRESSES: usize = 16;
/// Room for those addresses, or for the resolver's reason a refusal names.
const JUDGED_BYTES: usize = 4096;

/// THE GUARD, AS THE ENGINE APPLIED IT TO EVERY HOP (`fetch::guard_hop`, the card fetch's and the
/// relay's alike): the host's ONE destination judgement of `url` (the name, then every address it
/// resolves to), on handle `base`. A registration without `allow_private` is refused every private
/// address and loopback name whatever the deployment's `block_private_addresses` says
/// (`DEST_REFUSE_PRIVATE`); one with it reaches them as the operator's own infrastructure; a
/// cloud-metadata host is refused either way. Admitted: the handles issued and the address set the
/// dial must land on; refused: the engine's sentence, naming the refused address or the resolver's
/// reason (`DEST_EXPLAIN`). PENDING while the resolution is in flight.
fn judge_hop(
    at: &LookAt<'_>,
    url: &str,
    allow_private: bool,
    base: u32,
) -> Poll<Result<(u32, String), String>> {
    use busbar_contract::abi::host::conn::connector::{
        EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
    };
    use busbar_contract::abi::host::service::{
        ItemSpan, DEST_ALLOWED, DEST_EXPLAIN, DEST_REFUSE_PRIVATE,
    };
    use busbar_contract::abi::mechanism::check::SPAN_ABSENT;
    let Some(services) = at.plane.services else {
        return Poll::Ready(Ok((base, String::new())));
    };
    // A REACHED agent (`allow_private: true`) is judged as the operator's own destination: its
    // private or loopback address passes, a metadata host and the deployment's extra refusals never
    // do, in the engine's words. The address set is left to the dial, which the one guard judges
    // again holding the agent's private reach (SEAM-4f1): the plane-callable judgement names no
    // need, so its `within` is not the reached dial's.
    let (class, flags) = if allow_private {
        (EGRESS_OPERATOR_INFRASTRUCTURE, DEST_EXPLAIN)
    } else {
        (EGRESS_OPEN_WEB, DEST_EXPLAIN | DEST_REFUSE_PRIVATE)
    };
    let absent = busbar_contract::abi::mechanism::call::Span {
        offset: SPAN_ABSENT,
        len: 0,
    };
    let mut bytes = vec![0u8; JUDGED_BYTES];
    let mut spans = [ItemSpan {
        key: absent,
        value: absent,
    }; JUDGED_ADDRESSES];
    let judged = services.dest_judge_as(
        at.handle(base),
        url,
        class,
        flags,
        Some((&mut bytes[..], &mut spans[..])),
    );
    Poll::Ready(match judged {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(e)) => Err(format!("agent card fetch of `{url}` failed: {e:?}")),
        Poll::Ready(Ok(judged)) if judged.verdict == DEST_ALLOWED => Ok((
            base + 1,
            if allow_private {
                String::new()
            } else {
                judged.within()
            },
        )),
        Poll::Ready(Ok(judged)) => Err(crate::trust::refused_judgement(
            url,
            judged.verdict,
            judged.detail(),
        )),
    })
}

/// THE RELAY'S GUARD (the engine's `relay::prepare`, which guarded the registered endpoint through
/// the card fetch's own hop door before every relayed submission): the agent's `url` judged on the
/// registration's `allow_private`, once per attempt. `None` = the hop may go; a refusal is the
/// hop's answer (`a2a.hop.endpoint_refused`).
fn guard_relay(
    reach: &Reach<'_>,
    hop: &mut Hop,
    pass: &mut crate::task_door::Pass,
    url: &str,
    def: &crate::a2a::config::AgentDefCfg,
) -> Poll<Option<Answer>> {
    if hop.endpoint_judged {
        return Poll::Ready(None);
    }
    // The refusal's sentence is the operator's (the engine journalled it); the caller reads the
    // hop's fixed words.
    let refused = match crate::trust::scheme_refusal(url, def.allow_private) {
        Some(_) => true,
        None => {
            let at = LookAt {
                plane: reach.plane,
                ticket: reach.ticket,
                base: pass.issued,
            };
            match judge_hop(&at, url, def.allow_private, pass.issued) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok((issued, _))) => {
                    pass.issued = issued;
                    false
                }
                Poll::Ready(Err(_)) => {
                    pass.issued += 1;
                    true
                }
            }
        }
    };
    hop.endpoint_judged = true;
    Poll::Ready(refused.then(|| hop.relay.refuse_endpoint()))
}

/// THE CARD at the agent origin's well-known paths, canonical first, over the agent's connection
/// need, as the engine fetched it (`fetch::fetch_card`): every hop guarded from scratch
/// ([`judge_hop`]), a redirect followed — resolved against the hop that sent it — up to
/// [`crate::trust::MAX_REDIRECTS`], and the legacy path only when the canonical one produced no
/// document. The card (or why there is none), what the last hop's connection observed (the
/// connector's facts: the far end's key and whether busbar presented its client identity,
/// Q-DEL-A2A-SPKI) and the handles issued; the parked fetch while one of its services is in flight.
fn fetch_card(
    at: &LookAt<'_>,
    name: &str,
    def: &crate::a2a::config::AgentDefCfg,
    resumed: Option<(CardHop, Option<ParkedExchange>)>,
) -> Result<
    (
        Result<serde_json::Value, String>,
        crate::trust::Handshake,
        u32,
    ),
    LookParked,
> {
    use busbar_contract::abi::sdk::exchange::{exchange, Exchange, Request};
    let urls = match crate::trust::discovery_urls(&def.url) {
        Ok(urls) => urls,
        Err(refusal) => return Ok((Err(refusal), crate::trust::Handshake::default(), at.base)),
    };
    let (mut hop, mut parked) = resumed.unwrap_or_else(|| {
        let first = CardHop {
            legacy: false,
            redirects: 0,
            url: urls[0].clone(),
            issued: at.base,
        };
        (first, None)
    });
    loop {
        let url = hop.url.clone();
        let mut seen = crate::trust::Handshake::default();
        let got: Result<Option<serde_json::Value>, String> = 'hop: {
            let (start, state) = match parked.take() {
                Some((start, state)) => (start, Ok(*state)),
                None => {
                    if let Some(refusal) = crate::trust::scheme_refusal(&url, def.allow_private) {
                        break 'hop Err(refusal);
                    }
                    let (start, within) = match judge_hop(at, &url, def.allow_private, hop.issued) {
                        Poll::Pending => {
                            return Err(LookParked::Fetching {
                                hop,
                                exchange: None,
                            })
                        }
                        Poll::Ready(Err(refusal)) => break 'hop Err(refusal),
                        Poll::Ready(Ok(judged)) => judged,
                    };
                    let target = url::Url::parse(&url)
                        .map(|u| match u.query() {
                            Some(q) => format!("{}?{q}", u.path()),
                            None => u.path().to_string(),
                        })
                        .unwrap_or_default();
                    // The stream's facts are read before it closes: what the connector observed of
                    // the far end's key, which a transport-pinned registration is judged by.
                    let request = Exchange::request(Request {
                        method: b"GET".to_vec(),
                        target: target.into_bytes(),
                        // No field of the plane's own: the engine's card fetch named only the
                        // host its connection carries (the predev fence's bytes). It presents no
                        // credential either: the agent's own credential rides its hops, never its
                        // card fetch, so the fetch waives the member's binding (the host's field,
                        // stripped before anything is encoded).
                        fields: vec![(
                            busbar_contract::abi::auth::NO_MEMBER_AUTH_FIELD
                                .as_bytes()
                                .to_vec(),
                            b"1".to_vec(),
                        )],
                        body: Vec::new(),
                        timeout_ms: crate::trust::CARD_FETCH_TIMEOUT_MS,
                    })
                    // RESOLVE, PIN, DIAL THE PIN: the dial lands on an address the judgement judged,
                    // and the stream's facts are read before it closes.
                    // ... and names the registration it reaches, so that registration's own private
                    // reach (SEAM-4k/4p) is the one the dial holds.
                    .map(|request| request.landing_within(within).observing().as_member(name));
                    (start, request)
                }
            };
            let answer = match (state, at.plane.host.as_ref()) {
                (Err(e), _) => Err(e.to_string()),
                (Ok(_), None) => {
                    Err(busbar_contract::abi::sdk::conn::ConnFailure::Unarmed.to_string())
                }
                (Ok(mut state), Some(host)) => {
                    let mut conn = host.connector_from(at.ticket, start);
                    match exchange(&mut conn, &mut state, door::NEED_AGENT, Some(&url)) {
                        Poll::Pending => {
                            return Err(LookParked::Fetching {
                                hop,
                                exchange: Some((start, Box::new(state))),
                            });
                        }
                        Poll::Ready(answer) => {
                            hop.issued = conn.issued();
                            if let Some(observed) = state.observed() {
                                seen = crate::trust::Handshake {
                                    peer_key_pin: observed.peer_key_pin.clone(),
                                    client_identity_offered: observed.client_identity,
                                };
                            }
                            answer.map_err(|e| crate::trust::transport_err(conn.cause(), &e))
                        }
                    }
                }
            };
            let response = match answer {
                Ok(response) => response,
                Err(e) => break 'hop crate::trust::read_card(&url, Err(e)).map(Some),
            };
            let location = response
                .fields
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(b"location"))
                .and_then(|(_, value)| std::str::from_utf8(value).ok());
            match crate::trust::next_hop(&url, response.status, location, hop.redirects) {
                Err(refusal) => Err(refusal),
                Ok(Some(next)) => {
                    hop.redirects += 1;
                    hop.url = next;
                    Ok(None)
                }
                Ok(None) => {
                    crate::trust::read_card(&url, Ok((response.status, &response.body))).map(Some)
                }
            }
        };
        match got {
            Ok(None) => {}
            Ok(Some(card)) => return Ok((Ok(card), seen, hop.issued)),
            Err(_) if !hop.legacy => {
                hop = CardHop {
                    legacy: true,
                    redirects: 0,
                    url: urls[1].clone(),
                    issued: hop.issued,
                };
            }
            Err(refusal) => return Ok((Err(refusal), seen, hop.issued)),
        }
    }
}

/// The kernel's verdict on `card`'s signatures against the root key it holds for agent `name`
/// (`trust.verify`, on handle `seq`): `Ok` when they verified, else the refusal in this plane's
/// words.
fn signed_by_root(
    at: &LookAt<'_>,
    seq: u32,
    name: &str,
    card: &serde_json::Value,
) -> Result<(), String> {
    let (payload, signatures) = crate::trust::signed_parts(card)?;
    let unjudged = |why: String| format!("the agent card's signatures were not judged: {why}");
    let Some(services) = at.plane.services else {
        return Err(unjudged(
            "the instance was handed no host services".to_string(),
        ));
    };
    let handle = at.handle(seq);
    let (mut buf, mut grown) = (vec![0u8; 256], Vec::new());
    // A short buffer is re-called once, on the same handle, at the size the kernel named.
    let answer = match services.trust_verify(handle, name, &payload, &signatures, &mut buf) {
        Err(busbar_contract::abi::sdk::ServiceError::Short { bytes, .. }) => {
            grown.resize(usize::try_from(bytes).unwrap_or(usize::MAX).min(1 << 16), 0);
            services.trust_verify(handle, name, &payload, &signatures, &mut grown)
        }
        other => other,
    };
    match answer {
        Ok(signed) => {
            crate::trust::jws_refusal(signed.verdict, signed.named, card).map_or(Ok(()), Err)
        }
        Err(e) => Err(unjudged(format!("{e:?}"))),
    }
}

/// THE CATALOGUE HASH a card that failed its verification is sighted under: no fingerprint is ever
/// this, so a pinned (approved) agent sighted under it has drifted, and the kernel quarantines it.
const UNVERIFIED_CARD: &str = "unverified";

/// THE LOOK every trust read shares (`connect`, `approve` and verify-on-call), so no two of them
/// judge a card differently: fetch the card, verify it against the registration's pin, and record
/// the verified fingerprint on the kernel's trust book (`trust.sight`, which stamps the agent's
/// re-verification clock and judges it against a declared fingerprint). A failed fetch or
/// verification is a sighting too: it derives `error`, never "unchanged". What it landed and the
/// handles it issued; the parked look while a service is in flight.
fn look(
    at: &LookAt<'_>,
    name: &str,
    def: &crate::a2a::config::AgentDefCfg,
    parked: Option<LookParked>,
) -> Result<(Looked, u32), LookParked> {
    use crate::trust::Sighting;
    let resumed = match parked {
        Some(LookParked::Sighted(looked, issued)) => return Ok((looked, issued)),
        Some(LookParked::Fetching { hop, exchange }) => Some((hop, exchange)),
        None => None,
    };
    let (card, hop, issued) = fetch_card(at, name, def, resumed)?;
    let (verify_seq, sight_seq) = (issued, issued + 1);
    // A fetch the connector refused for the agent's pinned key reads as the pin's own refusal.
    let refused_hop = card.as_ref().err().map(|_| ());
    let card = card.map_err(|e| crate::trust::hop_refusal(&def.pin, &hop, &def.url).unwrap_or(e));
    // A fetch that brought no document back reached nothing: the kernel keeps its last verdict.
    // A pinned key the connector refused is the card failing its pin, not the agent unreachable.
    let unreachable =
        refused_hop.is_some() && crate::trust::hop_refusal(&def.pin, &hop, &def.url).is_none();
    let looked = match card.and_then(|card| {
        crate::trust::verify(&def.pin, &card, &hop, || {
            signed_by_root(at, verify_seq, name, &card)
        })
        .map(|seen| (seen, card))
    }) {
        Ok((seen, card)) => Looked {
            sighting: Sighting::Seen(seen),
            card: Some(card),
        },
        Err(reason) => Looked {
            sighting: Sighting::Failed(reason),
            card: None,
        },
    };
    let issued = sight_seq + 1;
    // THE SIGHTING ON THE KERNEL'S TRUST BOOK (ARCHITECT FLIP-A2A: the plane reports, the kernel
    // pins and demotes): the verified fingerprint as the agent's catalogue hash; a card that did
    // not verify against its pin as [`UNVERIFIED_CARD`], which is never an approved catalogue, so
    // an approved agent whose card stopped verifying is quarantined; an agent that could not be
    // reached at all as `trust.unreachable`, its last verdict kept. An `unpinned` card has no
    // fingerprint and is sighted never (it can never be approved).
    let Some(services) = at.plane.services else {
        return Ok((looked, issued));
    };
    let sighted = match &looked.sighting {
        Sighting::Seen(seen) => seen
            .pin
            .fingerprint()
            .map(|fp| services.trust_sight(at.handle(sight_seq), name, fp)),
        Sighting::Failed(_) if unreachable => {
            Some(services.trust_unreachable(at.handle(sight_seq), name))
        }
        Sighting::Failed(_) => {
            Some(services.trust_sight(at.handle(sight_seq), name, UNVERIFIED_CARD))
        }
        Sighting::Never => None,
    };
    if sighted.is_some_and(|s| s.is_pending()) {
        return Err(LookParked::Sighted(looked, issued));
    }
    Ok((looked, issued))
}

/// VERIFY-ON-CALL (the served engine's `receive::verify_agent_on_call` and `verify::reverify_once`):
/// a relayed unit's agent whose last look is older than its `reverify_ttl` is looked at again
/// before the hop, and what the look found is folded into its standing by the recovery rule
/// ([`crate::trust::Cadence::settle`]); a verified card is held for the relay. Whether the agent
/// still serves afterwards; the parked look while a service is in flight.
fn verify_on_call(
    reach: &Reach<'_>,
    hop: &mut Hop,
    pass: &mut crate::task_door::Pass,
    member: &str,
    def: &crate::a2a::config::AgentDefCfg,
    generation: u64,
) -> Poll<bool> {
    let plane = reach.plane;
    let key = member.to_string();
    let standing = plane.trust.get(&key).unwrap_or_default();
    let cadence = crate::trust::Cadence::of(def);
    let Some(now_ms) = reach.now_ms() else {
        return Poll::Ready(false);
    };
    // SERVING is the kernel's verdict on the agent's key, and not a suspension of the plane's.
    // A CARD THE LAST LOOK COULD NOT REACH OR VERIFY FAILS THE HOP CLOSED (ARCHITECT 2026-10-07,
    // predev baseline: `receive::verify_agent_on_call` recorded `Error`, which its hop gate refused):
    // the hop is refused here without asking `trust.serves`, and the kernel's last verdict, which
    // the look's `trust.unreachable` kept, is left untouched.
    let serves = |standing: &crate::trust::Standing| {
        standing.suspension.is_none()
            && !matches!(standing.sighting, crate::trust::Sighting::Failed(_))
            && verdict(plane, member) == busbar_contract::abi::host::service::DISTRUST_NONE
    };
    // A UNIT WAITING ON ANOTHER'S LOOK takes its verdict, never a look of its own — unless that
    // look was abandoned before it landed, when the waiter looks again (the engine's gate,
    // released by its dropped holder, re-checks and fetches).
    if let Some(seen) = hop.waits_on {
        match plane.flights.state(&key, seen, reach.ticket) {
            FlightState::InFlight => return Poll::Pending,
            FlightState::Landed => {
                hop.waits_on = None;
                let standing = plane.trust.get(&key).unwrap_or_default();
                return Poll::Ready(serves(&standing));
            }
            FlightState::Released => hop.waits_on = None,
        }
    }
    if hop.verifying.is_none() {
        if !cadence.due(&standing.ledger, now_ms) {
            return Poll::Ready(serves(&standing));
        }
        // SINGLE-FLIGHT (the engine's `VerifyGate::ensure_fresh`): one look per agent at a time;
        // a unit due while another's is in flight waits for its verdict.
        if let Some(seen) = plane.flights.join(&key, reach.ticket) {
            hop.waits_on = Some(seen);
            return Poll::Pending;
        }
    }
    let at = LookAt {
        plane,
        ticket: reach.ticket,
        base: pass.issued,
    };
    let (looked, issued) = match look(&at, member, def, hop.verifying.take()) {
        Ok(done) => done,
        Err(parked) => {
            hop.verifying = Some(parked);
            return Poll::Pending;
        }
    };
    pass.issued = issued;
    // RE-READ: another unit may have moved the standing while this look was in flight.
    let mut standing = plane.trust.get(&key).unwrap_or_default();
    standing.sighting = cadence.settle(looked.sighting, &mut standing.ledger, now_ms);
    if let Some(card) = looked.card {
        plane.cards.hold(member, generation, card);
    }
    let serving = serves(&standing);
    plane.trust.insert(key.clone(), standing);
    // THE FLIGHT LANDS: every unit that waited on it is woken to take its verdict.
    if let Some(host) = plane.host.as_ref() {
        for waiter in plane.flights.land(&key) {
            host.wake(waiter);
        }
    }
    Poll::Ready(serving)
}

/// ONE AGENT'S LOOK IN FLIGHT (the engine's `VerifyGate` flight): how many looks have landed, the
/// unit looking now, and the units waiting on it.
#[derive(Debug, Clone, Default)]
pub struct Flight {
    epoch: u64,
    owner: Option<Ticket>,
    waiters: Vec<Ticket>,
}

/// Where a waiter's flight stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlightState {
    /// The look it waits on is still in flight.
    InFlight,
    /// The look landed: its verdict is recorded.
    Landed,
    /// The look was abandoned before it landed: nothing was recorded, and the waiter looks again.
    Released,
}

/// Every agent's flight.
#[derive(Debug, Default)]
pub struct Flights(Keyed<String, Flight>);

impl Flights {
    /// `ticket` is due to look at `agent`: `None` = it holds the flight and looks; `Some(epoch)` =
    /// another unit's look is in flight, and `ticket` waits on it.
    fn join(&self, agent: &str, ticket: Ticket) -> Option<u64> {
        self.0.with_all(|m| {
            let f = m.entry(agent.to_string()).or_default();
            match f.owner {
                Some(owner) if owner != ticket => {
                    if !f.waiters.contains(&ticket) {
                        f.waiters.push(ticket);
                    }
                    Some(f.epoch)
                }
                _ => {
                    f.owner = Some(ticket);
                    None
                }
            }
        })
    }

    /// Where the flight `ticket` joined at `seen` stands; still in flight, `ticket` stays a waiter.
    fn state(&self, agent: &str, seen: u64, ticket: Ticket) -> FlightState {
        self.0.with_all(|m| {
            let Some(f) = m.get_mut(agent) else {
                return FlightState::Released;
            };
            if f.epoch != seen {
                return FlightState::Landed;
            }
            if f.owner.is_none() {
                return FlightState::Released;
            }
            if !f.waiters.contains(&ticket) {
                f.waiters.push(ticket);
            }
            FlightState::InFlight
        })
    }

    /// The flight on `agent` landed: the next epoch, no owner, and the units that waited on it.
    fn land(&self, agent: &str) -> Vec<Ticket> {
        self.0.with_all(|m| {
            let f = m.entry(agent.to_string()).or_default();
            f.epoch += 1;
            f.owner = None;
            std::mem::take(&mut f.waiters)
        })
    }

    /// THE UNIT ON `ticket` WAS ABANDONED (cancelled): every flight it held is released, landing
    /// nothing, and the units that waited on them are answered to be woken; it waits on none any
    /// more.
    fn abandon(&self, ticket: Ticket) -> Vec<Ticket> {
        self.0.with_all(|m| {
            let mut woken = Vec::new();
            for f in m.values_mut() {
                f.waiters.retain(|w| *w != ticket);
                if f.owner == Some(ticket) {
                    f.owner = None;
                    woken.append(&mut f.waiters);
                }
            }
            woken
        })
    }
}

/// The head fields a trust verb's view is answered with.
const VIEW_FIELDS: &[(&str, &str)] = &[(relay::H_CONTENT_TYPE, crate::arrival::JSON_MEDIA_TYPE)];

/// A trust verb's refusal: `status`, the message alone (the kernel frames it in the admin
/// taxonomy), the condition it is when it names one, and its audit row.
fn verb_refused(
    input: &Lent<'_, ServeIn>,
    out: &mut Out<'_, ServeOut>,
    status: u32,
    message: &str,
    condition: Option<&str>,
    audit: u32,
) -> Outcome {
    use busbar_contract::plane::ADMIN_CONDITION_FIELD;
    let mut fields = vec![(relay::H_CONTENT_TYPE, "text/plain")];
    fields.extend(condition.map(|c| (ADMIN_CONDITION_FIELD, c)));
    out.answer(input, status, &fields, message.as_bytes(), audit)
}

slot!(
    /// `serve`: the trust verbs over the section's registrations (ARCHITECT Q-L3B-VERBS), in the
    /// served engine's order and words, over the KERNEL'S trust book (ARCHITECT FLIP-A2A: the
    /// plane holds no approval; the book pins, quarantines and keeps the operator's decision):
    ///
    /// * an unregistered name is `404` before anything else, audited nowhere;
    /// * `approve` reads its body (`{"fingerprint": "…"}`) next, and a malformed one is `400`
    ///   (the malformed-body condition), audited nowhere;
    /// * both then LOOK ([`look`]): the card fetched over the agent's own connection need,
    ///   verified against its pin and SIGHTED on the kernel's trust book;
    /// * `connect` answers its preview and decides nothing;
    /// * `approve` compares what the endpoint serves now against the fingerprint the operator
    ///   names and refuses any disagreement `400` (the invalid-config condition), audited
    ///   rejected; otherwise it APPROVES the agent's trust key on the kernel's book
    ///   (`trust.decide`, the same decision `POST /admin/trust/approve` makes), holds the verified
    ///   card for the relay, and answers the registration as it now stands.
    Serve, ServeIn, ServeOut, |instance, input, mut out| {
        use busbar_contract::abi::plane::{AUDIT_APPLIED, AUDIT_NONE, AUDIT_REJECTED};
        use busbar_contract::plane::{
            ADMIN_CONDITION_INVALID_CONFIG as INVALID_CONFIG,
            ADMIN_CONDITION_MALFORMED_BODY as MALFORMED_BODY,
        };
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        if input.get().route as usize == door::PUSH_ROUTE {
            return crate::push_serve::serve(plane, &instance, input, out);
        }
        let Some((_, route)) = door::ADMIN_VERBS.get(input.get().route as usize) else {
            return verb_refused(&input, &mut out, STATUS_NOT_FOUND, "", None, AUDIT_NONE);
        };
        let approving = route.ends_with("/approve");
        let registered = |name: &str| {
            plane
                .generations
                .current()
                .and_then(|held| held.agents.get(name).cloned())
        };
        let found = verb_agent(route, input.field(|i| &i.target).bytes())
            .and_then(|name| registered(&name).map(|def| (name, def)));
        let Some((name, def)) = found else {
            return verb_refused(&input, &mut out, STATUS_NOT_FOUND, "", None, AUDIT_NONE);
        };
        let claimed = if approving {
            let fields = input.fields();
            let content_type = fields
                .iter()
                .find(|f| {
                    f.field(|f| &f.name)
                        .as_str()
                        .is_ok_and(|n| n.eq_ignore_ascii_case(relay::H_CONTENT_TYPE))
                })
                .and_then(|f| f.field(|f| &f.value).as_str().ok());
            match crate::trust::approve_body(content_type, input.field(|i| &i.body).bytes()) {
                Ok(fingerprint) => Some(fingerprint),
                Err(refusal) => {
                    let condition = Some(MALFORMED_BODY);
                    return verb_refused(&input, &mut out, 400, &refusal, condition, AUDIT_NONE);
                }
            }
        } else {
            None
        };
        let at = LookAt {
            plane,
            ticket: instance.ticket(),
            base: 0,
        };
        let looked = match look(&at, &name, &def, instance.resume::<LookParked>().map(|p| *p)) {
            Ok((looked, _)) => looked,
            Err(parked) => {
                instance.park(parked);
                return Outcome::Pending;
            }
        };
        let mut standing = plane.trust.get(&name).unwrap_or_default();
        let state_now = |plane: &A2aDoor, standing: &crate::trust::Standing| {
            if standing.suspension.is_some() {
                crate::trust::State::Suspended
            } else {
                crate::trust::state_of(verdict(plane, &name))
            }
        };
        let Some(claimed) = claimed else {
            // A PREVIEW DECIDES NOTHING: the key stands where the book has it.
            if let Some(card) = looked.card {
                plane.cards.hold(&name, plane.newest(), card);
            }
            let view = crate::trust::connect_view(
                &name,
                state_now(plane, &standing),
                &looked.sighting,
            );
            standing.sighting = looked.sighting;
            plane.trust.insert(name, standing);
            return out.answer(&input, 200, VIEW_FIELDS, view.as_bytes(), AUDIT_APPLIED);
        };
        if let Err(refusal) = crate::trust::agrees(&looked.sighting, claimed.trim()) {
            let condition = Some(INVALID_CONFIG);
            return verb_refused(&input, &mut out, 400, &refusal, condition, AUDIT_REJECTED);
        }
        // RE-FOUND, NOT ASSUMED: a refresh may have dropped the registration or moved its pin
        // while the card was fetched, and an approval is the operator's decision about the
        // registration as it stands.
        if registered(&name).is_none_or(|now| now.pin != def.pin) {
            return verb_refused(&input, &mut out, STATUS_NOT_FOUND, "", None, AUDIT_REJECTED);
        }
        // THE KERNEL'S DECISION: the agent's trust key approved at what this look just sighted.
        if let Err(refusal) = approve_key(plane, &at, &name, claimed.trim()) {
            return verb_refused(&input, &mut out, 400, &refusal, None, AUDIT_REJECTED);
        }
        // THE SERVED CARD, warmed from the document this approval just verified: the relay reads
        // the agent's binding and skills off it.
        if let Some(card) = looked.card {
            plane.cards.hold(&name, plane.newest(), card);
        }
        let view = crate::trust::registration_view(
            &name,
            state_now(plane, &standing),
            &looked.sighting,
        );
        standing.sighting = looked.sighting;
        plane.trust.insert(name, standing);
        out.answer(&input, 200, VIEW_FIELDS, view.as_bytes(), AUDIT_APPLIED)
    }
);

/// APPROVE `agent`'s trust key on the KERNEL'S trust book at the fingerprint the operator named
/// and this look just sighted (`trust.decide`, the ONE decide path `POST /admin/trust/approve`
/// takes for `<instance>/<agent>`).
///
/// # Errors
///
/// The refusal in the served engine's words: no host services, nothing sighted to approve, a
/// sighting other than the one named, or an agent with no authenticity root.
fn approve_key(plane: &A2aDoor, at: &LookAt<'_>, agent: &str, seen: &str) -> Result<(), String> {
    use busbar_contract::abi::host::service as svc;
    let services = plane
        .services
        .ok_or_else(|| "the instance was handed no host services".to_string())?;
    match services.trust_decide(at.handle(TRUST_DECIDE_SEQ), agent, None, Some(seen), true) {
        Ok(svc::UNDECIDED_UNPINNED) => Err(
            "the agent's card could not be authenticated, so there is nothing to approve".to_string(),
        ),
        Ok(svc::UNDECIDED_STALE) => Err(format!(
            "the endpoint's card moved while it was being approved: `{seen}` is no longer what the \
             trust book last sighted; re-run `connect` and read the new fingerprint before approving."
        )),
        Ok(svc::UNDECIDED_ROOTLESS) => Err(
            "cannot approve: this registration has no authenticity root (unpinned). Supply an \
             issuer key out of band, or pin the endpoint at the transport layer."
                .to_string(),
        ),
        Ok(svc::UNDECIDED_UNKNOWN) => Err(format!("the trust book declares no agent `{agent}`")),
        Ok(_) => Ok(()),
        Err(e) => Err(format!("the trust book did not decide: {e:?}")),
    }
}

/// The completion handle the approve's decision rides: past every handle its look issued.
const TRUST_DECIDE_SEQ: u32 = u32::MAX - 1;

slot!(
    /// `hydrate`: nothing to load. The door's durable state is host records (its tasks, their push
    /// configs and chains), read on demand through `records.get`/`records.list`; what it holds in
    /// memory (cards, the far-end id map, owed push outcomes) is plane memory a restart forgets, as
    /// the engine's was.
    Hydrate, GenIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `start`: the door runs nothing of its own. Its timed work is the lifecycle `tick` (push
    /// delivery) and the retention sweep the first relayed piece of each second runs
    /// ([`crate::task_door`]).
    Start, GenIn, OutHead, |_, _, _| { Outcome::Ready }
);

/// THE HOOK PROJECTION of one request envelope (the design's legacy engine folds and its plane
/// driver): `{tool, arguments}`, the method and its `params` (`null` when it has none), as the
/// engine's gate projects an A2A submission: the prose a screening hook reads lives in the
/// message's parts, inside `params`.
/// `None` for a body that is not a JSON object.
#[must_use]
pub fn projection(envelope: &[u8]) -> Option<Vec<u8>> {
    let envelope: serde_json::Value = serde_json::from_slice(envelope).ok()?;
    envelope.as_object()?;
    let tool = envelope
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let arguments = envelope
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    serde_json::to_vec(&serde_json::json!({ "tool": tool, "arguments": arguments })).ok()
}

/// THE SESSION a request's hook view carries: the `contextId` its message names, which groups an
/// A2A conversation's tasks (the engine keyed its gate's incremental scan on it); `None` when the
/// message names none, so the request is screened whole. ARCHITECT RULING 2026-10-03
/// (Q-FOLD-A2A-2-PROJECT-POOL, session half): `project` writes it into the view's opaque session.
#[must_use]
pub fn session_of(envelope: &[u8]) -> Option<String> {
    let envelope: serde_json::Value = serde_json::from_slice(envelope).ok()?;
    let context = crate::identity::context_of(&envelope);
    (!context.is_empty()).then(|| context.to_string())
}

/// A REQUEST-STAGE HOOK'S REWRITE, read as the served engine read a `prompt: rw` reply to an A2A
/// submission (`plane_host::apply_rewrite_to_invoke_args`, the invoke rewrite contract, in rule):
/// the hook stage hands the plane the reply as `{"messages": [...], "tools": ...}`; an A2A request
/// has one untrusted content member, its `params` object, and the rewrite REPLACES it: a
/// `messages` entry's `content` (an object verbatim, or a JSON string that parses to an object) or,
/// for an entry with no `role`, the entry itself; the LAST entry that yields an object wins.
///
/// `Ok(None)` = not applied: a reply whose entries yield no object leaves the request as it came,
/// as the served engine's invoke contract left a submission's params untouched.
///
/// # Errors
///
/// A COMMITTED REWRITE BUSBAR CANNOT READ BACK (bytes that are not JSON, or a reply that is not the
/// stage's `{"messages": [...]}`): the reason. The unit is REFUSED on it, never relayed with the
/// params the hook said it had replaced (predev `receive::committed_params` and its apply site: a
/// redaction hook that reported its rewrite applied is never silently undone).
pub fn rewritten_params(rewrite: &[u8]) -> Result<Option<serde_json::Value>, String> {
    use serde_json::Value;
    let reply: Value =
        serde_json::from_slice(rewrite).map_err(|e| format!("the output is not JSON: {e}"))?;
    let messages = reply
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "the output is JSON but names no `messages` list".to_string())?;
    let mut params: Option<Value> = None;
    for message in messages {
        let candidate = match message.get("content") {
            Some(content) => content,
            None if message.get("role").is_none() => message,
            None => continue,
        };
        let resolved = match candidate {
            Value::Object(_) => Some(candidate.clone()),
            Value::String(text) => serde_json::from_str::<Value>(text)
                .ok()
                .filter(Value::is_object),
            _ => None,
        };
        if resolved.is_some() {
            params = resolved;
        }
    }
    Ok(params)
}

/// The sentence a committed rewrite busbar cannot read back is refused with (predev's, verbatim).
pub const UNREADABLE_REWRITE: &str = "a rewrite hook attached to this agent committed a rewrite \
     that busbar could not read back. The submission is refused rather than relayed with the \
     params the hook said it had replaced.";

/// The status a committed rewrite busbar cannot read back is refused with: A2A section 5.4's
/// `InternalError` row.
pub const UNREADABLE_REWRITE_STATUS: u32 = 500;

/// THE REFUSAL OF A COMMITTED REWRITE BUSBAR CANNOT READ BACK, as predev answered it: a conformant
/// A2A internal error (`-32603` at `500`, one row of section 5.4) echoing the request id `id`.
#[must_use]
pub fn unreadable_rewrite(id: Option<serde_json::Value>) -> arrival::Refusal {
    arrival::Refusal {
        status: UNREADABLE_REWRITE_STATUS,
        id,
        code: crate::jsonrpc::CODE_INTERNAL,
        message: UNREADABLE_REWRITE.to_string(),
    }
}

/// THE ENVELOPE `envelope` WITH ITS `params` REPLACED by `params`, re-serialized (the served
/// engine wrote a committed rewrite back into the envelope and relayed it re-serialized). `None`
/// for a body that is not a JSON object.
#[must_use]
pub fn with_params(
    envelope: &[u8],
    params: serde_json::Value,
) -> Option<(serde_json::Value, Vec<u8>)> {
    let mut value: serde_json::Value = serde_json::from_slice(envelope).ok()?;
    value.as_object_mut()?.insert("params".to_string(), params);
    let bytes = serde_json::to_vec(&value).ok()?;
    Some((value, bytes))
}

/// THE HTTP+JSON BODY THAT SPELLS `params` on `route`, where the line's body is the request's
/// params ([`crate::rest::compose`]: a message sent or streamed, a push config posted, whose task
/// the path names again); `None` on a route whose params the path and query spell.
fn target_body(route: &door::Route, params: &serde_json::Value) -> Option<Vec<u8>> {
    let rel = route
        .target
        .strip_prefix(crate::MOUNT_PATH)
        .unwrap_or(route.target);
    let bodied = route.verb == "POST"
        && [
            crate::ROUTE_MESSAGE_SEND,
            crate::ROUTE_MESSAGE_STREAM,
            crate::ROUTE_PUSH_CONFIGS,
        ]
        .contains(&rel);
    bodied.then(|| serde_json::to_vec(params).ok()).flatten()
}

slot!(
    /// `project`: the hook view of an arrival on the JSON-RPC or the HTTP+JSON line: its
    /// [`projection`] as the body (the envelope its request spelled, on the HTTP+JSON line), the
    /// plane's own key as the ingress dialect (the engine's gate label), the agent the target
    /// addresses by name as the pool (none when the kernel's walk picks one), its [`session_of`] as
    /// the session, and the prompt view a content-granted hook reads (the one `user` turn of the
    /// params as JSON text, as the served engine projected an A2A submission). No signals.
    ///
    /// A request-stage hook's rewrite ([`rewritten_params`]) is applied first: the envelope with its
    /// params replaced is the request projected and the request the unit relays from then on (kept
    /// on the unit, [`Hop`]); the body the kernel keeps and re-pushes is answered in `rewritten`
    /// (the envelope on the JSON-RPC line, the params where the HTTP+JSON line's body is the params).
    /// Any other line, or a body that is no envelope, projects nothing (REFUSED).
    Project, ProjectIn, ProjectOut, |instance, input, mut out| {
        let Some(route) = door::ROUTES.get(input.get().claim as usize) else {
            return Outcome::Refused;
        };
        let target = input.field(|i| &i.target).as_str().unwrap_or_default();
        let body = input.field(|i| &i.body).bytes();
        let line = door::line_of(route);
        let envelope = match line {
            Line::Document => body.to_vec(),
            Line::Target => match crate::rest::compose(route, target, body) {
                Ok(Some(envelope)) => envelope,
                _ => return Outcome::Refused,
            },
            // The gRPC line projects the JSON-RPC request its call's message composed at arrival.
            Line::Framed => {
                let composed = instance.get().and_then(|plane| {
                    plane
                        .units
                        .with(&input.get().unit, |u| u.and_then(|u| u.envelope.clone()))
                });
                match composed {
                    Some(envelope) => envelope,
                    None => return Outcome::Refused,
                }
            }
            // A card read on the open line carries no request to screen (1.5.5 answered it with no
            // hook in the way): its view names no entry and no turn, so no entry's hooks bind.
            Line::Open => {
                let mut arena = input.arena_buf();
                let dialect = arena.span(crate::PLANE_KEY.as_bytes());
                let short = !arena.fits();
                let (aw, and) = arena.settle(short);
                out.set(|o| &o.arena_written, aw as u64);
                out.set(|o| &o.arena_needed, and as u64);
                if short {
                    return Outcome::Failed;
                }
                out.host_str(|o| &o.view.ingress_dialect, &arena, dialect);
                return Outcome::Ready;
            }
        };
        let rewrite = input.field(|i| &i.rewrite).bytes();
        let read = if rewrite.is_empty() {
            Ok(None)
        } else {
            rewritten_params(rewrite)
        };
        // A COMMITTED REWRITE BUSBAR CANNOT READ BACK, OR WRITE BACK, REFUSES THE UNIT (predev's
        // apply site): it is never relayed with the params the hook said it had replaced. The
        // unit is marked, and `refusal` answers it predev's internal error.
        let applied = match read.and_then(|params| {
            params
                .map(|params| {
                    let kept = match line {
                        Line::Target => target_body(route, &params),
                        _ => None,
                    };
                    with_params(&envelope, params)
                        .map(|(value, bytes)| (value, bytes, kept))
                        .ok_or_else(|| "the request is no envelope to write it into".to_string())
                })
                .transpose()
        }) {
            Ok(applied) => applied,
            Err(_) => {
                if let Some(plane) = instance.get() {
                    plane.units.with(&input.get().unit, |u| {
                        if let Some(u) = u {
                            u.unreadable_rewrite = true;
                        }
                    });
                }
                return Outcome::Refused;
            }
        };
        let (envelope, rewritten) = match applied {
            Some((value, bytes, kept)) => {
                if let Some(plane) = instance.get() {
                    plane.units.with(&input.get().unit, |u| {
                        if let Some(u) = u {
                            // A line that composed its request relays the composition, so the
                            // rewrite is what it relays (the HTTP+JSON and gRPC lines).
                            let composed = u.envelope.is_some();
                            if let Some(hop) = u.hop.as_mut() {
                                if composed {
                                    hop.relay.send_instead(bytes.clone());
                                }
                                hop.rewritten = Some(value.clone());
                            }
                        }
                    });
                }
                let kept = match line {
                    Line::Document => Some(bytes.clone()),
                    _ => kept,
                };
                (bytes, kept)
            }
            None => (envelope, None),
        };
        let Some(projected) = projection(&envelope) else {
            return Outcome::Refused;
        };
        let invocation = invocation_of(&envelope);
        let shape = busbar_contract::ir::facts::IrFacts::shape(&invocation);
        let turns: Vec<(&str, String)> = busbar_contract::ir::facts::IrFacts::content(&invocation)
            .iter()
            .map(|item| (item.author(), item.screenable_text().into_owned()))
            .collect();
        let session = session_of(&envelope);
        let pool = agent_of(target).unwrap_or_default();
        let (signals, mut arena, mut messages) =
            (input.signals_buf(), input.arena_buf(), input.messages_buf());
        let pool = arena.span(pool.as_bytes());
        let dialect = arena.span(crate::PLANE_KEY.as_bytes());
        let projected = arena.span(&projected);
        let session = session.map(|s| arena.span(s.as_bytes()));
        let rewritten = rewritten.as_deref().map(|r| arena.span(r));
        let turns: Vec<_> = turns
            .iter()
            .map(|(role, text)| (arena.span(role.as_bytes()), arena.span(text.as_bytes())))
            .collect();
        for (role, text) in turns {
            messages.push_turn(&arena, role, text);
        }
        let short = !arena.fits() || !messages.fits();
        let (aw, and) = arena.settle(short);
        let (turns_written, turns_needed) = messages.settle(short);
        out.set(|o| &o.arena_written, aw as u64);
        out.set(|o| &o.arena_needed, and as u64);
        out.set(|o| &o.messages_needed, turns_needed as u32);
        if short {
            return Outcome::Failed;
        }
        out.host_str(|o| &o.view.pool, &arena, pool);
        out.host_str(|o| &o.view.ingress_dialect, &arena, dialect);
        if let Some(session) = session {
            out.host_octets(|o| &o.view.session, &arena, session);
        }
        out.host_list(|o| &o.view.signals, |o| &o.view.signals_len, &signals);
        out.set(|o| &o.view.message_count, shape.turn_count as u64);
        out.set(|o| &o.view.total_chars, shape.text_chars as u64);
        let mut flags = 0;
        if shape.has_tools {
            flags |= busbar_contract::abi::hook::REQUEST_HAS_TOOLS;
        }
        out.set(|o| &o.view.flags, flags);
        out.set(|o| &o.body, projected);
        out.host_rows(|o| &o.prompt.messages, &messages);
        out.set(|o| &o.prompt.messages_len, turns_written);
        out.set(|o| &o.prompt.message_count, turns_written as u64);
        if let Some(rewritten) = rewritten {
            out.set(|o| &o.rewritten, rewritten);
        }
        Outcome::Ready
    }
);

/// THE INVOCATION the served engine's hooks read an A2A request as: the method as the tool and the
/// `params` as the arguments (`null` when it has none, or for a body that is no envelope).
#[must_use]
pub fn invocation_of(envelope: &[u8]) -> busbar_contract::ir::invoke::InvokeReq {
    let value: serde_json::Value =
        serde_json::from_slice(envelope).unwrap_or(serde_json::Value::Null);
    busbar_contract::ir::invoke::InvokeReq {
        tool: value
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        arguments: value
            .get("params")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        extra: Default::default(),
    }
}

#[cfg(test)]
#[path = "tests/plane_door_tests.rs"]
mod tests;

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::plane::Ops,
    statement: STATEMENT,
    lifecycle: {
        validate: Safe<Validate>, open: Safe<Open>, refresh: Safe<Refresh>, retire: Safe<Retire>,
        tick: Safe<Tick>, drive: Safe<Drive>, cancel: Safe<Cancel>, release: Safe<Release>,
        close: Safe<Close>,
    },
    kind_ops: {
        arrive: Safe<Arrive>, on_piece: Safe<OnPiece>, refusal: Safe<RefusalSlot>,
        serve: Safe<Serve>, hydrate: Safe<Hydrate>, start: Safe<Start>, project: Safe<Project>,
    },
}
