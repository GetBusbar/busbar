// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STDIO UPSTREAM SERVERS (ARCHITECT round 5 Q-L3B-STDIO-UPSTREAM (A)): a `transport: stdio`
//! registration is a member of the door's PROGRAM need ([`crate::door::NEED_PROGRAM`]), and the
//! host keeps ONE long-lived program per member. Every exchange the door has with that program — the
//! relayed `tools/call` over the kernel's walk, verify-on-call's `tools/list`, an operator's
//! `connect`, a further round, a reply to the program's own ask — is a lease on the same running
//! child, so this module correlates what it reads BY JSON-RPC ID, the previous release's rule:
//!
//! * Each lease reads every message the child writes after it opened. A message is a JSON value
//!   ([`Frames`]: the child's frames, read whole however the host's buffer cut them); only a
//!   response carrying the id this exchange sent is its answer ([`Correlator::take`]). A response
//!   to another id is another exchange's and is passed over.
//! * A message of the child's own is handled as the previous release handled it on the stdio leg
//!   (`client::peer`): `notifications/progress` carrying this call's token is relayed; a list-changed
//!   notification brings verify-on-call forward; every other notification is passed over; `ping`,
//!   an unknown method and an UNGRANTED authority ask are ANSWERED (the empty result, `-32601`, the
//!   operator's refusal), once per child generation whichever exchange read it first
//!   ([`Peer::claim`]). A GRANTED authority ask is busbar's caller's to answer (Law 11), and only
//!   the caller whose call it serves: calls whose asks may be relayed reach a child ONE AT A TIME,
//!   in arrival order (the door's line), so the ask is the call's first in line ([`first_in_line`],
//!   fixed by the first exchange to read it, [`Peer::owner`]); that call's exchange takes it
//!   ([`Correlator::asks`]) and busbar writes nothing back, every other exchange passes it over,
//!   and an ask raised while no such call is open is refused on the child's input, once. At most
//!   [`MAX_INTERLEAVED_MESSAGES`] such messages per exchange.
//! * `initialize` runs ONCE PER GENERATION of the child (the generation each lease's head names):
//!   an exchange that opens on a generation the door has not greeted greets it first
//!   ([`ProgramExchange`]); a JSON-RPC refusal of the handshake is recorded and the leg continues,
//!   as the previous release did, and only a transport failure fails it.
//! * Every id busbar sends a child is its own: a call's carries the unit, so concurrent exchanges on
//!   one child never share one ([`call_id`], [`list_id`]).

use std::collections::VecDeque;
use std::task::Poll;

use busbar_contract::abi::host::conn::connector::{
    ReplyPiece, REPLY_ACK, REPLY_BODY, REPLY_END, REPLY_HEAD,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::Host;
use serde_json::Value;

use crate::client::jsonrpc::{ServerRequestGrants, HANDSHAKE_REQUEST_ID};
use crate::client::peer::{NotificationEffect, ServerMessage};

/// THE WORK BUDGET of one exchange: how many messages of its own a child may send while busbar
/// waits for one answer (the previous release's bound, and its reason: the deadline bounds the
/// exchange in time, this bounds it in work).
pub const MAX_INTERLEAVED_MESSAGES: u32 = 256;

/// The most host services one exchange makes (each read is one): past it the exchange fails
/// rather than read without end. A further exchange on the same ticket numbers its services this
/// far apart.
pub const EXCHANGE_SERVICES: u32 = 1 << 12;

/// How much one read of a child's messages asks for.
const READ_CHUNK: usize = 16 * 1024;

/// The most one message may grow to before the exchange fails (the exchange SDK's reply bound).
const MESSAGE_MAX: usize = busbar_contract::abi::sdk::exchange::REPLY_MAX;

/// The ids busbar's program exchanges carry: above every dispatch id and the handshake's, so none
/// meets another's (`client::jsonrpc`'s id space).
const PROGRAM_IDS: u64 = 1 << 40;

/// Within [`PROGRAM_IDS`]: the `tools/list` exchanges.
const LIST_IDS: u64 = 1 << 39;

const _: () = assert!(PROGRAM_IDS > HANDSHAKE_REQUEST_ID);

/// The JSON-RPC id unit `unit`'s call carries on a child, round `round`: the unit's own, so two
/// units' calls on one child never share an id.
#[must_use]
pub const fn call_id(unit: u64, round: u32) -> u64 {
    PROGRAM_IDS | ((unit & 0xFFFF_FFFF) << 7) | (round as u64 & 0x7F)
}

/// The JSON-RPC id a `tools/list` exchange carries: `key` its op's own number (a unit's, or an
/// operator verb's ticket), `n` which of its fetches.
#[must_use]
pub const fn list_id(key: u64, n: u32) -> u64 {
    PROGRAM_IDS | LIST_IDS | ((key & 0xFFFF_FFFF) << 7) | (n as u64 & 0x7F)
}

/// The sentence a child that ended its output mid-exchange fails the exchange with.
pub const CLOSED: &str = "stdio MCP child closed its stdout";

/// One message a child wrote: a JSON value, or bytes that are none (returned as an answer, never
/// judged here: the JSON-RPC reader owns that complaint).
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// A JSON value.
    Value(Value),
    /// Not JSON at all.
    NotJson(Vec<u8>),
}

/// THE CHILD'S MESSAGES, out of its frames however the host's buffer cut them: whole JSON values,
/// back to back (the stdio framer hands each line without its newline). Each byte is scanned ONCE
/// for where a value ends (its nesting depth, outside strings) and a value is parsed only once it is
/// whole, so a message read in many pieces costs its size, never its size per piece (the design's
/// no-blocking rule: bounded work on the worker).
#[derive(Debug, Default)]
pub struct Frames {
    buf: Vec<u8>,
    /// How far `buf` is scanned.
    seen: usize,
    /// Where the value being read starts in `buf`, once its first byte came.
    start: Option<usize>,
    depth: usize,
    in_string: bool,
    escaped: bool,
}

impl Frames {
    /// Take `bytes`; every message they complete.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Message> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        let mut used = 0;
        while let Some(&b) = self.buf.get(self.seen) {
            let at = self.seen;
            self.seen += 1;
            let Some(start) = self.start else {
                match b {
                    b' ' | b'\t' | b'\r' | b'\n' => used = self.seen,
                    b'{' | b'[' => {
                        self.start = Some(at);
                        self.depth = 1;
                    }
                    _ => {
                        // Not a message: what is held cannot be resynchronised, so it is handed on
                        // whole.
                        let rest = self.buf.split_off(at);
                        *self = Frames::default();
                        out.push(Message::NotJson(rest));
                        return out;
                    }
                }
                continue;
            };
            if self.in_string {
                match b {
                    _ if self.escaped => self.escaped = false,
                    b'\\' => self.escaped = true,
                    b'"' => self.in_string = false,
                    _ => {}
                }
                continue;
            }
            match b {
                b'"' => self.in_string = true,
                b'{' | b'[' => self.depth += 1,
                b'}' | b']' => {
                    self.depth -= 1;
                    if self.depth == 0 {
                        let whole = &self.buf[start..self.seen];
                        out.push(match serde_json::from_slice(whole) {
                            Ok(value) => Message::Value(value),
                            Err(_) => Message::NotJson(whole.to_vec()),
                        });
                        self.start = None;
                        used = self.seen;
                    }
                }
                _ => {}
            }
        }
        self.buf.drain(..used);
        self.seen -= used;
        self.start = self.start.map(|s| s - used);
        out
    }

    /// Whether a message is part way through, past [`MESSAGE_MAX`].
    #[must_use]
    pub fn overgrown(&self) -> bool {
        self.buf.len() > MESSAGE_MAX
    }
}

/// What an exchange needs of the door while it reads a child's own messages.
pub trait Peer {
    /// The member's grants, read now.
    fn grants(&self) -> ServerRequestGrants;
    /// Whether this exchange is the first to read the request `id` of the child of `generation`,
    /// and so answers it.
    fn claim(&mut self, generation: u64, id: &Value) -> bool;
    /// WHOSE the child's GRANTED ask `id` of `generation` is, fixed by the first exchange to read
    /// it ([`first_in_line`]) and the same for every exchange after.
    fn owner(&mut self, generation: u64, id: &Value) -> AskOwner;
    /// The child said its lists changed: verify-on-call is brought forward.
    fn notice(&mut self);
}

/// Whose one of a child's granted asks is, as the exchange reading it is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskOwner {
    /// The call relayed under this id: the call first in the child's line when the ask was first
    /// read. Its exchange takes the ask for its caller; every other passes it over.
    Call(u64),
    /// No call of the child's: this exchange read it first, and refuses it on the child's input.
    Refuse,
    /// No call of the child's, and an exchange that read it first refused it.
    Refused,
}

/// THE CALL A CHILD'S ASK BELONGS TO (finding 5). A request over stdio names no call it serves
/// (MCP carries no related-request id on the wire, a call's progress token is its own and is never
/// echoed on an ask, and the child numbers its own requests), so the door makes the answer
/// unambiguous instead: calls whose asks may be relayed reach a child one at a time, in arrival
/// order, and the ask is the call FIRST in that line. `line` is the child's member's calls in
/// arrival order, each its id and the generation its lease reached (`0` before its head, which
/// counts on every generation). An empty line, or one whose first call is on another generation's
/// child, is `None`: the ask is refused, never handed to whichever exchange reads first (Law 11:
/// relayed down the session it belongs to, as-is).
pub fn first_in_line(line: impl IntoIterator<Item = (u64, u64)>, generation: u64) -> Option<u64> {
    let (call, on) = line.into_iter().next()?;
    (on == 0 || on == generation).then_some(call)
}

/// The audit word a child's ask that no call owns is refused under.
pub const UNATTRIBUTED: &str = "ask_unattributed";

/// ONE EXCHANGE'S READING of a child's messages: its answer by id, the replies it owes the child,
/// and the progress it relays.
#[derive(Debug, Default)]
pub struct Correlator {
    frames: Frames,
    interleaved: u32,
    /// The replies to the child's own requests, owed on its input, in order.
    pub outbox: VecDeque<Vec<u8>>,
    /// The progress frames carrying this exchange's token, in order.
    pub progress: Vec<Value>,
    /// This exchange relays a caller's call: a granted authority ask it reads is the caller's
    /// ([`Self::asks`]), never answered here.
    pub relays: bool,
    /// THE CHILD'S GRANTED ASKS this exchange took, in order, for busbar's caller to answer.
    pub asks: Vec<ChildAsk>,
}

/// ONE REQUEST OF A CHILD'S OWN, for busbar's caller to answer (Law 11): its id (the answer goes
/// back under it) and the request as the child sent it, less its envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct ChildAsk {
    /// The child's request id, verbatim.
    pub id: Value,
    /// `{method, params}`, verbatim: the `inputRequests` entry the caller is handed.
    pub request: Value,
}

impl Correlator {
    /// The reading of an exchange that relays a caller's call ([`Self::relays`]).
    #[must_use]
    pub fn relaying() -> Self {
        Correlator {
            relays: true,
            ..Correlator::default()
        }
    }
}

/// THE CHILD'S ASKS AS THE CALLER IS HANDED THEM: an `input_required` result whose `inputRequests`
/// carries each request verbatim, keyed by the child's own id (a string id as it is, any other as
/// its JSON), and the keys paired with the ids the answers go back under.
#[must_use]
pub fn relayed_asks(asks: &[ChildAsk]) -> (Value, Vec<(String, Value)>) {
    let mut requests = serde_json::Map::new();
    let mut keys = Vec::new();
    for ask in asks {
        let base = match &ask.id {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let mut key = base.clone();
        let mut n = 1;
        while requests.contains_key(&key) {
            n += 1;
            key = format!("{base}#{n}");
        }
        requests.insert(key.clone(), ask.request.clone());
        keys.push((key, ask.id.clone()));
    }
    let result = serde_json::json!({
        "resultType": crate::jsonrpc::RESULT_TYPE_INPUT_REQUIRED,
        "inputRequests": Value::Object(requests),
    });
    (result, keys)
}

/// THE CALLER'S ANSWERS, AS THE CHILD IS WRITTEN THEM: one JSON-RPC response per request it asked,
/// under the child's own id, its `result` the caller's answer verbatim. A key the caller did not
/// answer has no reply ([`crate::ask::decide`] refuses such a retry before it gets here).
#[must_use]
pub fn child_replies(child: &crate::ask::ChildLeg, responses: Option<&Value>) -> Vec<Vec<u8>> {
    child
        .asks
        .iter()
        .filter_map(|(key, id)| {
            let answer = responses?.get(key)?;
            serde_json::to_vec(&serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": answer }))
                .ok()
        })
        .collect()
}

impl Correlator {
    /// Read `bytes` of member `member`'s messages (its child of `generation`), waiting for the
    /// answer to `wait`: that answer (its bytes) once it came. Messages of the child's own are
    /// handled on the way.
    ///
    /// # Errors
    ///
    /// The child sent more than [`MAX_INTERLEAVED_MESSAGES`] of its own, or one message past the
    /// bound, in the previous release's words.
    pub fn take(
        &mut self,
        bytes: &[u8],
        wait: u64,
        member: &str,
        generation: u64,
        peer: &mut dyn Peer,
    ) -> Result<Option<Vec<u8>>, String> {
        let mut answer = None;
        for message in self.frames.push(bytes) {
            let value = match message {
                Message::NotJson(raw) => {
                    answer.get_or_insert(raw);
                    continue;
                }
                Message::Value(value) => value,
            };
            let Some(own) = crate::client::peer::classify(&value) else {
                // A response (or a value that is no message): ours by id, or another exchange's.
                if value.get("id").and_then(Value::as_u64) == Some(wait) || !value.is_object() {
                    answer.get_or_insert_with(|| serde_json::to_vec(&value).unwrap_or_default());
                }
                continue;
            };
            self.interleaved += 1;
            if self.interleaved > MAX_INTERLEAVED_MESSAGES {
                return Err(format!(
                    "stdio MCP child sent more than {MAX_INTERLEAVED_MESSAGES} messages of its own \
                     while busbar waited for one answer; the exchange is abandoned rather than \
                     served at whatever rate the child chooses"
                ));
            }
            self.own(&value, own, (wait, generation), member, peer);
        }
        if answer.is_none() && self.frames.overgrown() {
            return Err(format!(
                "stdio MCP child wrote more than {MESSAGE_MAX} bytes without ending its message; \
                 the read is abandoned rather than grown to whatever the child chooses"
            ));
        }
        Ok(answer)
    }

    /// One message of the child's own, handled.
    fn own(
        &mut self,
        value: &Value,
        message: ServerMessage,
        (wait, generation): (u64, u64),
        member: &str,
        peer: &mut dyn Peer,
    ) {
        let reply = match message {
            ServerMessage::Notification(n) => {
                match n.effect() {
                    NotificationEffect::BringRefreshForward
                    | NotificationEffect::RelayResourceUpdate => peer.notice(),
                    NotificationEffect::RelayProgress => {
                        let token = format!("busbar-{wait}");
                        if value
                            .pointer("/params/progressToken")
                            .and_then(Value::as_str)
                            == Some(token.as_str())
                        {
                            self.progress.push(value.clone());
                        }
                    }
                    NotificationEffect::Log => {}
                }
                None
            }
            ServerMessage::UnknownNotification(_) => None,
            // A GRANTED AUTHORITY ASK is the caller's (Law 11), and only the caller whose call it
            // serves: the exchange relaying the call first in the child's line takes it, every
            // other passes it over, and one raised while no call is open is refused once.
            ServerMessage::Request { id, verb }
                if verb.ask().is_some_and(|a| peer.grants().allows(a)) =>
            {
                match peer.owner(generation, &id) {
                    AskOwner::Call(call) if self.relays && call == wait => {
                        let mut request = value.as_object().cloned().unwrap_or_default();
                        request.remove("jsonrpc");
                        request.remove("id");
                        self.asks.push(ChildAsk {
                            id,
                            request: Value::Object(request),
                        });
                        None
                    }
                    AskOwner::Refuse => {
                        let kind = verb.ask().map(|a| a.key()).unwrap_or_default();
                        Some(crate::client::peer::refused(
                            &id,
                            UNATTRIBUTED,
                            format!(
                                "server `{member}` asked for `{kind}` while busbar was relaying it \
                                 no call, and a request over stdio names no call it serves, so the \
                                 ask has no caller to go to; it is refused rather than put to \
                                 another caller."
                            ),
                        ))
                    }
                    AskOwner::Call(_) | AskOwner::Refused => None,
                }
            }
            ServerMessage::Request { id, verb } => peer
                .claim(generation, &id)
                .then(|| crate::client::peer::answer(&id, verb, &peer.grants(), member))
                .flatten(),
            ServerMessage::UnknownRequest { id, method } => peer
                .claim(generation, &id)
                .then(|| crate::client::peer::method_not_found(&id, &method)),
        };
        if let Some(reply) = reply {
            self.outbox
                .push_back(serde_json::to_vec(&reply).unwrap_or_default());
        }
    }
}

/// What a [`ProgramExchange`] came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchanged {
    /// The generation of the child it reached.
    pub generation: u64,
    /// The answer to its request, when it sent one.
    pub answer: Option<Vec<u8>>,
    /// It greeted the child (`initialize`): the generation is the door's now.
    pub greeted: bool,
}

/// Where a [`ProgramExchange`] is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Establish,
    Head,
    Next,
    Write(Vec<u8>),
    Read,
    Close,
}

/// ONE EXCHANGE WITH A MEMBER'S CHILD over the door's own program need, parked across its op's
/// pending entries: open a lease on the member, read its head (the generation), greet a generation
/// the door has not greeted, write each message and read to each one's answer by id (answering the
/// child's own requests on the way), close the lease. Each host service is numbered on from the
/// exchange's base, so a pending one is re-issued under its own number and a completed one never
/// runs twice.
#[derive(Debug)]
pub struct ProgramExchange {
    member: String,
    need: u32,
    step: Step,
    issued: u32,
    stream: u64,
    buf: Box<[u8]>,
    slot: Box<ReplyPiece>,
    corr: Correlator,
    generation: u64,
    /// The messages still to send, each with the id whose answer it waits for.
    queue: VecDeque<(Vec<u8>, Option<u64>)>,
    /// The answer being waited for.
    waiting: Option<u64>,
    /// Write only on this generation (a reply owed to one child is never written to the next).
    only: Option<u64>,
    greet: bool,
    greeted: bool,
    answer: Option<Vec<u8>>,
    failed: Option<String>,
    /// The bound the lease is opened under, milliseconds (`0` = the need's own): the host holds the
    /// exchange to it until the child first answers.
    timeout_ms: u32,
}

impl ProgramExchange {
    /// An exchange with member `member` over need `need`: `messages` sent in order, each read to
    /// the answer to its id when it names one; `greet` = greet a generation the door has not.
    #[must_use]
    pub fn new(
        member: &str,
        need: u32,
        messages: Vec<(Vec<u8>, Option<u64>)>,
        greet: bool,
    ) -> Self {
        Self {
            member: member.to_string(),
            need,
            step: Step::Establish,
            issued: 0,
            stream: 0,
            buf: vec![0; READ_CHUNK].into_boxed_slice(),
            slot: Box::default(),
            corr: Correlator::default(),
            generation: 0,
            queue: messages.into(),
            waiting: None,
            only: None,
            greet,
            greeted: false,
            answer: None,
            failed: None,
            timeout_ms: 0,
        }
    }

    /// Opened under `timeout_ms`: the server's own `timeout:` (ARCHITECT timeout ruling).
    #[must_use]
    pub fn timed(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = u32::try_from(timeout_ms).unwrap_or(u32::MAX);
        self
    }

    /// Write only to the child of `generation`: on another, nothing is sent.
    #[must_use]
    pub fn only_on(mut self, generation: u64) -> Self {
        self.only = Some(generation);
        self
    }

    /// The progress frames the exchange relayed.
    #[must_use]
    pub fn progress(&self) -> &[Value] {
        &self.corr.progress
    }

    /// Drive the exchange on `ticket`, its services numbered from `base`: READY with what it came
    /// to, PENDING (to be driven again on the op's next entry), or why it failed. `greeted` says
    /// whether the door already greeted a generation.
    pub fn drive(
        &mut self,
        host: &Host,
        ticket: Ticket,
        base: u32,
        greeted: &dyn Fn(u64) -> bool,
        peer: &mut dyn Peer,
    ) -> Poll<Result<Exchanged, String>> {
        loop {
            if self.issued >= EXCHANGE_SERVICES {
                self.failed.get_or_insert_with(|| {
                    "the exchange with the stdio MCP child passed its bound".to_string()
                });
                if self.step != Step::Close {
                    self.step = Step::Close;
                } else {
                    return Poll::Ready(Err(self.failed.take().unwrap_or_default()));
                }
            }
            let mut c = host.connector_from(ticket, base.saturating_add(self.issued));
            match self.step.clone() {
                Step::Establish => {
                    match c.establish_timed(self.need, Some(&self.member), "", self.timeout_ms) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(stream)) => {
                            self.issued += 1;
                            self.stream = stream;
                            self.step = Step::Head;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e.to_string())),
                    }
                }
                Step::Head => match c.read_reply(self.stream, &mut self.buf, &mut self.slot) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(got)) => {
                        self.issued += 1;
                        if got.piece.kind != REPLY_HEAD {
                            self.fail(CLOSED.to_string());
                            continue;
                        }
                        let block = spanned(&self.buf[..got.len], got.piece.fields);
                        self.generation = generation_of(block);
                        if self.only.is_some_and(|g| g != self.generation) {
                            self.queue.clear();
                        }
                        if self.greet && !greeted(self.generation) {
                            self.queue.push_front((initialized_notification(), None));
                            self.queue
                                .push_front((initialize(), Some(HANDSHAKE_REQUEST_ID)));
                        }
                        self.step = Step::Next;
                    }
                    Poll::Ready(Err(e)) => self.fail(e.to_string()),
                },
                Step::Next => {
                    if let Some(reply) = self.corr.outbox.pop_front() {
                        self.step = Step::Write(reply);
                    } else if self.waiting.is_some() {
                        self.step = Step::Read;
                    } else if let Some((message, wait)) = self.queue.pop_front() {
                        self.waiting = wait;
                        self.step = Step::Write(message);
                    } else {
                        self.step = Step::Close;
                    }
                }
                Step::Write(message) => match c.write(self.stream, &message) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(_)) => {
                        self.issued += 1;
                        if message == initialized_notification() {
                            self.greeted = true;
                        }
                        self.step = Step::Next;
                    }
                    Poll::Ready(Err(e)) => self.fail(e.to_string()),
                },
                Step::Read => match c.read_reply(self.stream, &mut self.buf, &mut self.slot) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(got)) => {
                        self.issued += 1;
                        match got.piece.kind {
                            REPLY_BODY => {
                                let wait = self.waiting.unwrap_or_default();
                                let taken = self.corr.take(
                                    &self.buf[..got.len],
                                    wait,
                                    &self.member,
                                    self.generation,
                                    peer,
                                );
                                match taken {
                                    Ok(Some(answer)) => {
                                        self.waiting = None;
                                        if wait == HANDSHAKE_REQUEST_ID {
                                            self.greeted(&answer);
                                        } else {
                                            self.answer = Some(answer);
                                        }
                                        self.step = Step::Next;
                                    }
                                    Ok(None) => self.step = Step::Next,
                                    Err(e) => self.fail(e),
                                }
                            }
                            REPLY_END | REPLY_ACK => self.fail(CLOSED.to_string()),
                            _ => {}
                        }
                    }
                    Poll::Ready(Err(e)) => self.fail(e.to_string()),
                },
                Step::Close => {
                    if c.close(self.stream).is_pending() {
                        return Poll::Pending;
                    }
                    self.issued += 1;
                    if let Some(failed) = self.failed.take() {
                        return Poll::Ready(Err(failed));
                    }
                    return Poll::Ready(Ok(Exchanged {
                        generation: self.generation,
                        answer: self.answer.take(),
                        greeted: self.greeted,
                    }));
                }
            }
        }
    }

    /// The exchange failed: the lease is closed, and the failure is its answer.
    fn fail(&mut self, why: String) {
        self.failed.get_or_insert(why);
        self.step = Step::Close;
    }

    /// The handshake's answer: a result is acknowledged; a refusal (a child that does no handshake)
    /// is recorded and the leg continues, unacknowledged.
    fn greeted(&mut self, answer: &[u8]) {
        let accepted = matches!(
            crate::client::jsonrpc::parse_response(answer, HANDSHAKE_REQUEST_ID),
            crate::client::jsonrpc::RpcOutcome::Result(_)
        );
        if accepted {
            return;
        }
        self.queue.retain(|(m, _)| *m != initialized_notification());
        self.greeted = true;
    }
}

/// The bytes `span` names in `buf`.
fn spanned(buf: &[u8], span: busbar_contract::abi::transport::FrameSpan) -> &[u8] {
    let at = usize::try_from(span.offset).unwrap_or(usize::MAX);
    let len = usize::try_from(span.len).unwrap_or(0);
    buf.get(at..at.saturating_add(len)).unwrap_or(&[])
}

/// The generation a lease's head names; `0` when it names none.
#[must_use]
pub fn generation_of(block: &[u8]) -> u64 {
    busbar_contract::abi::transport::fields::lines(block)
        .find(|(n, _)| {
            n.eq_ignore_ascii_case(busbar_contract::conn::PROGRAM_GENERATION_FIELD.as_bytes())
        })
        .and_then(|(_, v)| std::str::from_utf8(v).ok()?.trim().parse().ok())
        .unwrap_or(0)
}

/// The handshake: `initialize`, under its own id.
#[must_use]
pub fn initialize() -> Vec<u8> {
    crate::client::verb::UpstreamVerb::Initialize {
        client_version: crate::tool_door::VERSION,
    }
    .build("", HANDSHAKE_REQUEST_ID, None)
    .body
}

/// The handshake's acknowledgement, a notification.
#[must_use]
pub fn initialized_notification() -> Vec<u8> {
    crate::client::verb::UpstreamVerb::NotificationsInitialized
        .build("", HANDSHAKE_REQUEST_ID, None)
        .body
}

#[cfg(test)]
#[path = "tests/tool_program.rs"]
mod tests;
