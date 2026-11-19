// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Upstream exchanges over the plane port (IF §8.6, §12.3; PLANE-DRIVER.md slice 5).
//!
//! One attempt of a forwarded session is: the member walk picks a [`Candidate`], core calls `upstream` with the
//! [`TargetIn`] it makes ([`Candidate::with_target`]), the plane answers the exchange it wants sent (or
//! ATT_DECLINE, and the walk moves on without dialling), the far end is sent it ([`UpSend`]), and its reply is fed
//! back as `piece(FROM_UPSTREAM)` HEAD, BODY and END, whose answer classifies the attempt: ATT_RETRY and ATT_HARD
//! are the walk's failures ([`Members::failed`], with the plane's class and Retry-After), anything else serves.
//! [`run_attempts`] is that loop over two seams: [`Members`], the egress walk and its breaker, and [`UpSend`], the
//! carrier. A send that fails before any reply fails the member over without asking the plane (nothing reached
//! it). Probes ([`probe_member`], FB_PROBES) run the same exchange once against one member; a failed probe call
//! waits as `RetrySite::PlaneProbe` says ([`probe_wait`]).
//!
//! The plane's calls are synchronous entries made between awaits on the request's own task; the walk, the send
//! and the reply are awaited. Every seam here is static: the session is generic over its walk and its carrier, so
//! no seam call boxes a future.

use std::future::Future;
use std::time::Duration;

use busbar_contract::transport::fields::lines;
use busbar_plugin_abi::fail::refused::R_NO_ROUTE;
use busbar_plugin_abi::plane::{
    ATT_DECLINE, ATT_HARD, ATT_RETRY, FC_SERVER, FROM_UPSTREAM, F_PROBE_OK, P_BODY, P_END, P_ERROR,
    P_HEAD, P_TRAILERS, W_AFFINITY, W_CAPABILITY, W_MAX_TOKENS, W_MODEL, W_STREAM, W_UPSTREAM,
};
use busbar_plugin_abi::records::{self, Reply, Writer};
use busbar_plugin_abi::types::{Bytes, Pair, Str};
use busbar_ports::codec::plane::{encode_refusal, encode_upstream_head};
use busbar_ports::plane::TargetIn;
use busbar_ports::{FactVal, PortError};

use super::port_session::{
    hand_out, AttemptItem, Calls, Effects, SessionError, Task, ToClient, UpExchange, Violation,
};
use super::HeadFields;
use crate::retry::{Retry, RetryPolicy, RetrySite};

/// The longest W_AFFINITY text (§8.6 round 13).
const AFFINITY_MAX: usize = 256;

/// What a FORWARD asked core to choose candidates by (§8.6 wants). A key stated with the wrong shape, and any
/// key core does not read, is ignored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Wants {
    pub model: Option<Box<str>>,
    pub stream: bool,
    pub capability: Option<Box<str>>,
    pub max_tokens: Option<u64>,
    /// W_UPSTREAM: the walk tries only this member and never reroutes.
    pub upstream: Option<Box<str>>,
    /// W_AFFINITY: the sticky-routing key (≤ 256 bytes).
    pub affinity: Option<Box<str>>,
}

impl Wants {
    #[must_use]
    pub fn from_facts(facts: &[(u32, FactVal)]) -> Self {
        let mut wants = Wants::default();
        for (key, value) in facts {
            match (*key, value) {
                (W_MODEL, FactVal::Text(t)) => wants.model = Some(t.clone()),
                (W_STREAM, FactVal::U(n)) => wants.stream = *n != 0,
                (W_CAPABILITY, FactVal::Text(t)) => wants.capability = Some(t.clone()),
                (W_MAX_TOKENS, FactVal::U(n)) => wants.max_tokens = Some(*n),
                (W_UPSTREAM, FactVal::Text(t)) => wants.upstream = Some(t.clone()),
                (W_AFFINITY, FactVal::Text(t)) if t.len() <= AFFINITY_MAX => {
                    wants.affinity = Some(t.clone());
                }
                _ => {}
            }
        }
        wants
    }
}

/// One member the walk picked, as the plane's `Target` states it (operator vocabulary, never a plugin).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetIdentity {
    /// A declared registration uses the requesting plane's dialect and request model.
    Registration,
    /// A provider model always uses the values resolved in this generation's catalog.
    Model { dialect: Box<str>, model: Box<str> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// Exact pool and member returned by the admitted walk, before display-name conversion.
    pub pool: Box<str>,
    pub qualified_member: Box<str>,
    pub identity: TargetIdentity,
    /// Frozen configured rate-resource label; descriptive data, never admission authority.
    pub resource: Option<Box<str>>,
    /// The configured upstream (member) name.
    pub upstream: Box<str>,
    /// The plane-owned provider keys as one canonical JSON object (`{}` when none).
    pub provider: Box<str>,
    pub base_path: Box<str>,
    /// TGT_* flags.
    pub flags: u32,
    /// The route's configured parameters.
    pub params: Vec<(Box<str>, Box<str>)>,
}

impl Candidate {
    /// Runs `f` over the [`TargetIn`] of attempt `attempt` (from 1) to this member.
    pub fn with_target<R>(
        &self,
        attempt: u32,
        dialect: &str,
        model: &str,
        f: impl FnOnce(&TargetIn<'_>) -> R,
    ) -> R {
        self.with_admission_target(attempt, dialect, model, &[], f)
    }

    pub(crate) fn with_admission_target<R>(
        &self,
        attempt: u32,
        dialect: &str,
        model: &str,
        admission: &[u8],
        f: impl FnOnce(&TargetIn<'_>) -> R,
    ) -> R {
        let (dialect, model) = match &self.identity {
            TargetIdentity::Registration => (dialect, model),
            TargetIdentity::Model { dialect, model } => (dialect.as_ref(), model.as_ref()),
        };
        let params: Vec<Pair<'_>> = self
            .params
            .iter()
            .map(|(k, v)| Pair {
                name: Str::new(k),
                value: Bytes::new(v.as_bytes()),
            })
            .collect();
        f(&TargetIn {
            attempt,
            flags: self.flags,
            dialect,
            model,
            base_path: &self.base_path,
            upstream: &self.upstream,
            provider: &self.provider,
            params: &params,
            admission,
        })
    }
}

/// An attempt that failed this member: ATT_RETRY (another member may serve it) or ATT_HARD (this member is
/// down, a breaker input with `class`), with what the upstream asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure {
    pub verdict: u32,
    /// FC_* (§8.6).
    pub class: u32,
    pub retry_after_s: u64,
}

/// The member walk: candidates in the walk's order, and what each attempt taught it. The egress walk and its
/// breaker implement it.
pub trait Members: Send {
    fn request_walk(&self) -> Option<&super::request_admission::RequestWalk> {
        None
    }
    fn select_request(
        &mut self,
        _receipt: &super::request_admission::RequestPoolReceipt,
        _wants: &Wants,
    ) -> bool {
        false
    }
    fn admit_request(&mut self, _request: &super::request_admission::AdmittedRequest) -> bool {
        false
    }
    fn hook_remaining(&self) -> Option<usize> {
        None
    }
    fn hook_failure(&self) -> Option<&str> {
        None
    }

    /// Inspect the same configured walk that will choose the first member.
    fn hook_candidates(&mut self, _wants: &Wants) -> Option<super::hooks::Candidates> {
        None
    }
    fn hook_scope(&mut self, _wants: &Wants) -> Option<super::RoutedScope> {
        None
    }
    fn hook_lane(&mut self, _wants: &Wants, _index: usize) -> Option<String> {
        None
    }
    /// False means no enforcing constraint was installed; core must not dial.
    fn hook_constrain(&mut self, _wants: &Wants, _constraint: super::hooks::Constraint) -> bool {
        false
    }
    /// The next member to try, `None` when the walk is exhausted. `wants.upstream` pins one member. The pick is
    /// awaited on the session's task (the breaker's permit, the pool's terminal).
    fn next(&mut self, wants: &Wants) -> impl Future<Output = Option<Candidate>> + Send;
    /// The plane will not send to this member; it was never dialled.
    fn declined(&mut self, member: &Candidate);
    fn failed(&mut self, member: &Candidate, failure: &Failure);
    fn served(&mut self, member: &Candidate);
    /// Once `next` answered `None`: how long the walk says the client should wait before asking again (the
    /// exhaustion's Retry-After, IF §12.3), in whole seconds. `None` = it states none (the default).
    fn retry_after(&self) -> Option<u32> {
        None
    }
}

/// The far end's reply to an exchange, whole.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpReply {
    pub status: u16,
    pub headers: HeadFields,
    pub body: Vec<u8>,
}

/// The exchange could not be sent, or no reply came.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendFailed;

/// One piece of a reply after its head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Chunk {
    /// Body bytes, as the far end delivered them.
    Body(Vec<u8>),
    /// The far end's fields after its body, as the transport's field block.
    Trailers(Vec<u8>),
}

/// The rest of a reply being read.
pub trait UpChunks: Send {
    /// The next piece; `Ok(None)` = the reply ended. `Err` = it was cut (a failed connection, an expired
    /// deadline). Awaited on the session's task.
    fn next(&mut self) -> impl Future<Output = Result<Option<Chunk>, SendFailed>> + Send;

    /// The next message piece of a far end that answered a WebSocket handshake with 101 (the relay's read,
    /// [`super::port_duplex`]); `Ok(None)` = the far end closed. Cancel-safe: dropped while it waits, it has
    /// taken nothing. A carrier with no messages (the default) hands each body chunk up as one binary message.
    fn next_message(
        &mut self,
    ) -> impl Future<Output = Result<Option<super::port_duplex::UpMessage>, SendFailed>> + Send
    {
        async move {
            loop {
                match self.next().await? {
                    Some(Chunk::Body(bytes)) => {
                        return Ok(Some(super::port_duplex::UpMessage {
                            flags: busbar_plugin_abi::plane::MSG_BINARY
                                | busbar_plugin_abi::plane::MSG_FIN,
                            bytes,
                        }))
                    }
                    Some(Chunk::Trailers(_)) => {}
                    None => return Ok(None),
                }
            }
        }
    }

    /// One whole message for the far end (`flags`: `MSG_TEXT` or `MSG_BINARY`, with `MSG_FIN`), written
    /// before this returns. `false` = it could not be written: the far end is gone. A carrier with no
    /// messages (the default) writes none.
    fn write_message(&mut self, flags: u32, bytes: Vec<u8>) -> impl Future<Output = bool> + Send {
        let _ = (flags, bytes);
        std::future::ready(false)
    }

    /// The engine closes the far end's side of a message session (its close frame goes out). Nothing is read
    /// or written after it.
    fn close(&mut self) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }

    /// The code the far end closed its side of a message session with, as its transport stated it
    /// (`PollConns::close_code`), once a read answered `Err`. `None` = it stated none (a dropped
    /// connection, a deadline, a write that was not taken), or the carrier has no messages (the default).
    /// The number is the far end's, not judged: the relay writes it to the caller only where
    /// [`super::port_duplex::caller_close_code`] allows.
    fn close_code(&self) -> Option<u32> {
        None
    }

    /// The messages the `upstream` answer wrote for the far end before it answered (UP_MSG beside the
    /// handshake head): the relay writes them first, after the 101.
    fn take_queued(&mut self) -> Vec<(u32, Vec<u8>)> {
        Vec::new()
    }
}

/// A reply whose head has arrived and whose rest (`R`, the carrier's own reader) is read piece by piece, so a
/// streamed reply reaches the plane (and through it the client) as it is produced instead of joined into one body.
pub struct UpOpen<R> {
    pub status: u16,
    pub headers: HeadFields,
    pub rest: R,
}

/// A whole body as a stream of at most one chunk: the reader of a carrier that answers whole replies.
pub struct Whole(Option<Vec<u8>>);

impl UpChunks for Whole {
    fn next(&mut self) -> impl Future<Output = Result<Option<Chunk>, SendFailed>> + Send {
        std::future::ready(Ok(self.0.take().filter(|b| !b.is_empty()).map(Chunk::Body)))
    }
}

impl UpReply {
    /// This whole reply as an open one whose rest is its body.
    #[must_use]
    pub fn opened(self) -> UpOpen<Whole> {
        UpOpen {
            status: self.status,
            headers: self.headers,
            rest: Whole(Some(self.body)),
        }
    }
}

/// The carrier: core adds the host, the carrier's defaults and the credential and sends the exchange.
pub trait UpSend: Send {
    /// How this carrier reads the rest of a reply it opened.
    type Rest<'a>: UpChunks + 'a
    where
        Self: 'a;

    fn open_selected<'a>(
        &'a mut self,
        prepared: super::port_egress::OwnedPreparation,
    ) -> impl Future<
        Output = Result<
            super::port_egress::SelectedOpen<Self::Rest<'a>>,
            super::port_egress::SelectedSendError,
        >,
    > + Send
           + 'a {
        drop(prepared);
        std::future::ready(Err(super::port_egress::SelectedSendError::backend()))
    }

    /// The reply's head and a reader for the rest, awaited on the session's task.
    fn open<'a>(
        &'a mut self,
        member: &'a Candidate,
        exchange: UpExchange,
    ) -> impl Future<Output = Result<UpOpen<Self::Rest<'a>>, SendFailed>> + Send + 'a;
}

/// How the walk ended.
#[derive(Debug)]
pub enum Attempted {
    /// A member served: what the client sees so far (nothing when a [`ClientSink`](super::port_session::ClientSink)
    /// took it as it came), and the verdict that said so (`None` = implied ATT_OK).
    Served {
        client: Vec<ToClient>,
        member: Box<str>,
        attempts: u32,
        attempt: Option<AttemptItem>,
    },
    /// No member is left.
    Exhausted { attempts: u32, local_quota: bool },
}

/// The reply's head as the piece it is fed in: H_STATUS, PAIR*.
fn head_piece(status: u16, headers: &HeadFields) -> Result<Reply, SessionError> {
    let mut head = Reply::new();
    encode_upstream_head(&mut head, status, &[], None, None).map_err(|_| SessionError::Encode)?;
    for (name, value) in headers.iter() {
        if let Some(name) = std::str::from_utf8(name).ok().filter(|n| !n.is_empty()) {
            head.put_pair(records::tag::PAIR, name, value)
                .map_err(|_| SessionError::Encode)?;
        }
    }
    Ok(head)
}

/// The far end's trailing fields as the PAIR* a TRAILERS piece carries.
fn trailer_piece(block: &[u8]) -> Result<Reply, SessionError> {
    let mut out = Reply::new();
    for (name, value) in lines(block) {
        if let Some(name) = std::str::from_utf8(name).ok().filter(|n| !n.is_empty()) {
            out.put_pair(records::tag::PAIR, name, value)
                .map_err(|_| SessionError::Encode)?;
        }
    }
    Ok(out)
}

/// What feeding a reply produced.
#[derive(Default)]
struct Fed {
    /// Client items not yet handed to a sink (all of them without one).
    client: Vec<ToClient>,
    attempt: Option<AttemptItem>,
    /// The client's response has begun: the plane wrote an item for it.
    began: bool,
    /// The reply was cut before the client's response began: nothing reached the plane's decision, the member
    /// failed over.
    broken: bool,
    /// The client went away; the rest of the reply is let go.
    gone: bool,
    /// What the answers asked of a message exchange (an upgrade session's; empty for every other).
    asked: super::port_duplex::Asked,
}

fn failing(attempt: Option<&AttemptItem>) -> bool {
    attempt.is_some_and(|a| matches!(a.verdict, ATT_RETRY | ATT_HARD))
}

/// One `piece(FROM_UPSTREAM)`. `false` = stop reading: a failing verdict, or the client went away.
async fn step<K: Calls + ?Sized>(
    task: &mut Task<'_, K>,
    fed: &mut Fed,
    flags: u32,
    bytes: &[u8],
    effects: &dyn Effects,
) -> Result<bool, SessionError> {
    let mut answer = task.piece(FROM_UPSTREAM, 0, flags, bytes, effects)?;
    if task.carries_messages() {
        // An upgrade session: what the answer asks of its message exchange is kept for the relay.
        fed.asked.take(&mut answer);
    }
    fed.client.extend(answer.client);
    if answer.attempt.is_some() {
        fed.attempt = answer.attempt;
    }
    if failing(fed.attempt.as_ref()) {
        return Ok(false);
    }
    // An item for the client means the plane decided (the attempt rule: it writes the response or it fails the
    // attempt with nothing for the client), so it goes out at once when a sink takes it.
    fed.began |= !fed.client.is_empty();
    effects.observed_usage(task.usage());
    if !hand_out(effects, &mut fed.client).await {
        fed.gone = true;
        return Ok(false);
    }
    Ok(true)
}

/// Feeds the reply to exchange 0 as `piece(FROM_UPSTREAM)`: HEAD, then BODY and TRAILERS as they arrive, END.
/// Stops at the first failing verdict. A reply cut after the client's response began is `P_ERROR` (one REFUSAL
/// to render in-stream); cut before, the member fails over.
async fn feed<K: Calls + ?Sized, R: UpChunks>(
    task: &mut Task<'_, K>,
    mut reply: UpOpen<R>,
    effects: &dyn Effects,
) -> Result<Fed, SessionError> {
    let mut fed = Fed::default();
    let head = head_piece(reply.status, &reply.headers)?;
    // An upgrade request's session (its client side takes messages): a 101 for the caller in the answer to
    // the far end's handshake answer commits the session to the relay.
    let caller = effects.client().and_then(|sink| sink.messages());
    if !step(task, &mut fed, P_HEAD, head.as_bytes(), effects).await? {
        // A failing verdict (the far end refused the handshake: the walk moves on), or the caller went
        // away as its 101 was handed over. Nothing was relayed; the far end is closed by its drop.
        return Ok(fed);
    }
    if let (Some(caller), true) = (caller, fed.asked.switched) {
        // The caller has its 101 (handed out by the step above): the rest of this attempt is the session.
        let asked = std::mem::take(&mut fed.asked);
        let relayed =
            super::port_duplex::relay(task, &mut reply.rest, caller, asked, effects).await?;
        fed.began = true;
        fed.gone = relayed.gone;
        return Ok(fed);
    }
    loop {
        match reply.rest.next().await {
            Ok(Some(Chunk::Body(bytes))) => {
                if !bytes.is_empty() && !step(task, &mut fed, P_BODY, &bytes, effects).await? {
                    return Ok(fed);
                }
            }
            Ok(Some(Chunk::Trailers(block))) => {
                let bytes = trailer_piece(&block)?;
                if !step(task, &mut fed, P_TRAILERS, bytes.as_bytes(), effects).await? {
                    return Ok(fed);
                }
            }
            Ok(None) => {
                step(task, &mut fed, P_END, &[], effects).await?;
                return Ok(fed);
            }
            Err(SendFailed) => {
                if fed.began {
                    let mut refusal = Reply::new();
                    encode_refusal(
                        &mut refusal,
                        502,
                        R_NO_ROUTE,
                        "the upstream failed before its reply ended",
                    )
                    .map_err(|_| SessionError::Encode)?;
                    step(task, &mut fed, P_ERROR, refusal.as_bytes(), effects).await?;
                } else {
                    fed.broken = true;
                }
                return Ok(fed);
            }
        }
    }
}

fn exchange_zero(exchanges: Vec<UpExchange>) -> Result<UpExchange, SessionError> {
    exchanges
        .into_iter()
        .find(|e| e.id == 0)
        .ok_or(SessionError::Violation(Violation::MissingExchange))
}

/// Whether a session's attempt walk may run. `data` is `None` for a session with no native DATA
/// unit, else whether that unit carries a resource selection. The borrowed sender cannot own a
/// selected-attempt partition or its transport reservation, so a DATA unit with a selection runs
/// only in the selected-attempt cohort. A DATA unit with no selection (its route selects nothing)
/// runs only the ordinary walk: its money is the ordinary unit its pending admission committed,
/// and the selected cohort has no selection to prepare from.
pub(crate) fn attempts_driven(data: Option<bool>, selected_attempts: bool) -> bool {
    match data {
        None => true,
        Some(selected) => selected == selected_attempts,
    }
}

/// The attempt walk of one forwarded session (§8.6, §12.3).
pub async fn run_attempts<K: Calls + ?Sized, M: Members + ?Sized, S: UpSend>(
    task: &mut Task<'_, K>,
    wants: &Wants,
    dialect: &str,
    model: &str,
    members: &mut M,
    send: &mut S,
    effects: &dyn Effects,
) -> Result<Attempted, SessionError> {
    let data = task.data().map(|data| data.selected().is_some());
    if !attempts_driven(data, task.selected_attempts()) {
        return Err(SessionError::NotDriven);
    }
    // An upgrade request's session (its client side takes messages, §12.27): from its first attempt on the
    // plane's answers may carry messages for the far end and, once it commits, for the caller. The unit and
    // its money were admitted before this walk began, exactly as for any forwarded request.
    if effects.client().and_then(|sink| sink.messages()).is_some() {
        task.message_session();
    }
    let mut attempts = 0_u32;
    let mut local_quota = false;
    loop {
        let Some(member) = members.next(wants).await else {
            return Ok(Attempted::Exhausted {
                attempts,
                local_quota,
            });
        };
        attempts += 1;
        effects.routing(
            attempts,
            &member.upstream,
            members.hook_remaining(),
            members.hook_failure(),
        );
        let unsent = Failure {
            verdict: ATT_RETRY,
            class: FC_SERVER,
            retry_after_s: 0,
        };
        let fed = if task.selected_attempts() {
            let Some(prepared) =
                task.prepare_selected(&member, attempts, dialect, model, effects)?
            else {
                members.declined(&member);
                continue;
            };
            let owned = super::port_egress::OwnedPreparation::new(prepared, task.data().cloned());
            effects.dialled();
            let opened = match send.open_selected(owned).await {
                Ok(opened) => opened,
                Err(error) => {
                    use super::port_egress::SelectedFailure;
                    match &error.0 {
                        SelectedFailure::NoSend | SelectedFailure::Policy(crate::governance::selected_policy::SelectedPolicyRefusal::StalePolicyTarget) => {
                            members.declined(&member);
                            continue;
                        }
                        SelectedFailure::Quota => {
                            local_quota = true;
                            members.declined(&member);
                            continue;
                        }
                        _ => return Err(SessionError::SelectedRefused(error)),
                    }
                }
            };
            task.install_attempt(opened.attempt)?;
            match opened.opened {
                Ok(reply) => {
                    task.answered_attempt()?;
                    feed(task, reply, effects).await?
                }
                Err(_) => {
                    task.finish_attempt()?;
                    members.failed(&member, &unsent);
                    continue;
                }
            }
        } else {
            let answer =
                member.with_target(attempts, dialect, model, |t| task.upstream(t, effects))?;
            if answer
                .attempt
                .as_ref()
                .is_some_and(|a| a.verdict == ATT_DECLINE)
            {
                members.declined(&member);
                continue;
            }
            let exchange = exchange_zero(answer.exchanges)?;
            let Ok(reply) = send.open(&member, exchange).await else {
                members.failed(&member, &unsent);
                continue;
            };
            task.answered_attempt()?;
            feed(task, reply, effects).await?
        };
        if fed.broken {
            task.finish_attempt()?;
            members.failed(&member, &unsent);
            continue;
        }
        if let Some(a) = fed
            .attempt
            .as_ref()
            .filter(|a| matches!(a.verdict, ATT_RETRY | ATT_HARD))
        {
            task.finish_attempt()?;
            members.failed(
                &member,
                &Failure {
                    verdict: a.verdict,
                    class: a.class,
                    retry_after_s: a.retry_after_s,
                },
            );
            continue;
        }
        task.served_attempt()?;
        members.served(&member);
        return Ok(Attempted::Served {
            client: fed.client,
            member: member.upstream.clone(),
            attempts,
            attempt: fed.attempt,
        });
    }
}

/// What one probe found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// F_PROBE_OK = 1: the member answered correctly.
    Healthy,
    /// The plane said it did not, or the far end never answered.
    Unhealthy,
    /// The plane does not probe this member (ATT_DECLINE): no verdict.
    Declined,
}

/// One health probe of `member` (FB_PROBES): `probe`, send what it asked, feed the reply, `end`. A probe whose
/// send fails is cancelled and unhealthy.
pub async fn probe_member<K: Calls + ?Sized, S: UpSend>(
    calls: &K,
    member: &Candidate,
    dialect: &str,
    model: &str,
    send: &mut S,
    effects: &dyn Effects,
) -> Result<ProbeOutcome, SessionError> {
    let (mut task, answer) =
        member.with_target(1, dialect, model, |t| Task::probe(calls, t, effects))?;
    if answer
        .attempt
        .as_ref()
        .is_some_and(|a| a.verdict == ATT_DECLINE)
    {
        return Ok(ProbeOutcome::Declined);
    }
    let exchange = exchange_zero(answer.exchanges)?;
    let Ok(reply) = send.open(member, exchange).await else {
        return Ok(ProbeOutcome::Unhealthy);
    };
    feed(&mut task, reply, effects).await?;
    let last = task.end(effects)?;
    let well = last
        .facts
        .iter()
        .any(|(key, value)| *key == F_PROBE_OK && *value == FactVal::U(1));
    Ok(if well {
        ProbeOutcome::Healthy
    } else {
        ProbeOutcome::Unhealthy
    })
}

/// How long to wait before probing again after a failed probe call: `RetrySite::PlaneProbe` (§12.3); `None` =
/// stop.
#[must_use]
pub fn probe_wait(policy: &dyn RetryPolicy, attempt: u32, error: &PortError) -> Option<Duration> {
    match policy.next(RetrySite::PlaneProbe, attempt, error) {
        Retry::After(wait) => Some(wait),
        Retry::Stop => None,
    }
}

#[cfg(test)]
#[path = "tests/port_upstream_tests.rs"]
mod tests;
