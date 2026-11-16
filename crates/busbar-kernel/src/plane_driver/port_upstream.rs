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
//! The calls are synchronous, so a driver runs this inside `spawn_blocking` with a blocking `UpSend`.

use std::time::Duration;

use busbar_contract::abi::transport::fields::lines;
use busbar_plugin_abi::fail::refused::R_NO_ROUTE;
use busbar_plugin_abi::plane::{
    ATT_DECLINE, ATT_HARD, ATT_RETRY, FC_SERVER, FROM_UPSTREAM, F_PROBE_OK, P_BODY, P_END, P_ERROR,
    P_HEAD, P_TRAILERS, W_AFFINITY, W_CAPABILITY, W_MAX_TOKENS, W_MODEL, W_STREAM, W_UPSTREAM,
};
use busbar_plugin_abi::records::{self, Reply, Writer};
use busbar_plugin_abi::types::{Bytes, Pair, Str};
use busbar_plugin_loader::encode::plane::{encode_refusal, encode_upstream_head};
use busbar_plugin_loader::ports::plane::TargetIn;
use busbar_plugin_loader::ports::{FactVal, PortError};

use super::port_session::{
    hand_out, AttemptItem, Calls, Effects, SessionError, Task, ToClient, UpExchange, Violation,
};
use super::HeadFields;
use crate::retry::{Retry, RetryPolicy, RetrySite};

/// The longest W_AFFINITY text (§8.6 round 13).
pub const AFFINITY_MAX: usize = 256;

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
pub struct Candidate {
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
pub trait Members {
    /// The next member to try, `None` when the walk is exhausted. `wants.upstream` pins one member.
    fn next(&mut self, wants: &Wants) -> Option<Candidate>;
    /// The plane will not send to this member; it was never dialled.
    fn declined(&mut self, member: &Candidate);
    fn failed(&mut self, member: &Candidate, failure: &Failure);
    fn served(&mut self, member: &Candidate);
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
pub trait UpChunks {
    /// The next piece; `Ok(None)` = the reply ended. `Err` = it was cut (a failed connection, an expired
    /// deadline).
    fn next(&mut self) -> Result<Option<Chunk>, SendFailed>;
}

/// A reply whose head has arrived and whose rest is read piece by piece, so a streamed reply reaches the plane
/// (and through it the client) as it is produced instead of joined into one body.
pub struct UpOpen<'a> {
    pub status: u16,
    pub headers: HeadFields,
    pub rest: Box<dyn UpChunks + 'a>,
}

/// A whole body as a stream of at most one chunk.
struct Whole(Option<Vec<u8>>);

impl UpChunks for Whole {
    fn next(&mut self) -> Result<Option<Chunk>, SendFailed> {
        Ok(self.0.take().filter(|b| !b.is_empty()).map(Chunk::Body))
    }
}

/// The carrier: core adds the host, the carrier's defaults and the credential and sends the exchange.
pub trait UpSend {
    /// The whole reply. A carrier that streams implements [`open`](Self::open) and need not implement this one's
    /// buffering; a carrier that does not stream implements this one and gets `open` for free.
    fn send(&mut self, member: &Candidate, exchange: &UpExchange) -> Result<UpReply, SendFailed>;

    /// The reply's head and a reader for the rest. The default reads the whole reply with [`send`](Self::send).
    fn open<'a>(
        &'a mut self,
        member: &Candidate,
        exchange: &UpExchange,
    ) -> Result<UpOpen<'a>, SendFailed> {
        let reply = self.send(member, exchange)?;
        Ok(UpOpen {
            status: reply.status,
            headers: reply.headers,
            rest: Box::new(Whole(Some(reply.body))),
        })
    }
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
    Exhausted { attempts: u32 },
}

/// The reply's head as the piece it is fed in: H_STATUS, PAIR*.
fn head_piece(status: u16, headers: &HeadFields) -> Result<Vec<u8>, SessionError> {
    let pairs: Vec<Pair<'_>> = headers
        .iter()
        .filter_map(|(name, value)| {
            let name = std::str::from_utf8(name).ok().filter(|n| !n.is_empty())?;
            Some(Pair {
                name: Str::new(name),
                value: Bytes::new(value),
            })
        })
        .collect();
    let mut head = Reply::new();
    encode_upstream_head(&mut head, status, &pairs, None, None)
        .map_err(|_| SessionError::Encode)?;
    Ok(head.as_bytes().to_vec())
}

/// The far end's trailing fields as the PAIR* a TRAILERS piece carries.
fn trailer_piece(block: &[u8]) -> Result<Vec<u8>, SessionError> {
    let mut out = Reply::new();
    for (name, value) in lines(block) {
        if let Some(name) = std::str::from_utf8(name).ok().filter(|n| !n.is_empty()) {
            out.put_pair(records::tag::PAIR, name, value)
                .map_err(|_| SessionError::Encode)?;
        }
    }
    Ok(out.as_bytes().to_vec())
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
}

fn failing(attempt: Option<&AttemptItem>) -> bool {
    attempt.is_some_and(|a| matches!(a.verdict, ATT_RETRY | ATT_HARD))
}

/// One `piece(FROM_UPSTREAM)`. `false` = stop reading: a failing verdict, or the client went away.
fn step<K: Calls + ?Sized>(
    task: &mut Task<'_, K>,
    fed: &mut Fed,
    flags: u32,
    bytes: &[u8],
    effects: &dyn Effects,
) -> Result<bool, SessionError> {
    let answer = task.piece(FROM_UPSTREAM, 0, flags, bytes, effects)?;
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
    if !hand_out(effects, &mut fed.client) {
        fed.gone = true;
        return Ok(false);
    }
    Ok(true)
}

/// Feeds the reply to exchange 0 as `piece(FROM_UPSTREAM)`: HEAD, then BODY and TRAILERS as they arrive, END.
/// Stops at the first failing verdict. A reply cut after the client's response began is `P_ERROR` (one REFUSAL
/// to render in-stream); cut before, the member fails over.
fn feed<K: Calls + ?Sized>(
    task: &mut Task<'_, K>,
    mut reply: UpOpen<'_>,
    effects: &dyn Effects,
) -> Result<Fed, SessionError> {
    let mut fed = Fed::default();
    let head = head_piece(reply.status, &reply.headers)?;
    if !step(task, &mut fed, P_HEAD, &head, effects)? {
        return Ok(fed);
    }
    loop {
        match reply.rest.next() {
            Ok(Some(Chunk::Body(bytes))) => {
                if !bytes.is_empty() && !step(task, &mut fed, P_BODY, &bytes, effects)? {
                    return Ok(fed);
                }
            }
            Ok(Some(Chunk::Trailers(block))) => {
                let bytes = trailer_piece(&block)?;
                if !step(task, &mut fed, P_TRAILERS, &bytes, effects)? {
                    return Ok(fed);
                }
            }
            Ok(None) => {
                step(task, &mut fed, P_END, &[], effects)?;
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
                    step(task, &mut fed, P_ERROR, refusal.as_bytes(), effects)?;
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

/// The attempt walk of one forwarded session (§8.6, §12.3).
pub fn run_attempts<K: Calls + ?Sized>(
    task: &mut Task<'_, K>,
    wants: &Wants,
    dialect: &str,
    model: &str,
    members: &mut dyn Members,
    send: &mut dyn UpSend,
    effects: &dyn Effects,
) -> Result<Attempted, SessionError> {
    let mut attempts = 0_u32;
    loop {
        let Some(member) = members.next(wants) else {
            return Ok(Attempted::Exhausted { attempts });
        };
        attempts += 1;
        let answer = member.with_target(attempts, dialect, model, |t| task.upstream(t, effects))?;
        if answer
            .attempt
            .as_ref()
            .is_some_and(|a| a.verdict == ATT_DECLINE)
        {
            members.declined(&member);
            continue;
        }
        let exchange = exchange_zero(answer.exchanges)?;
        let unsent = Failure {
            verdict: ATT_RETRY,
            class: FC_SERVER,
            retry_after_s: 0,
        };
        let Ok(reply) = send.open(&member, &exchange) else {
            members.failed(&member, &unsent);
            continue;
        };
        let fed = feed(task, reply, effects)?;
        if fed.broken {
            members.failed(&member, &unsent);
            continue;
        }
        if let Some(a) = fed
            .attempt
            .as_ref()
            .filter(|a| matches!(a.verdict, ATT_RETRY | ATT_HARD))
        {
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
pub fn probe_member<K: Calls + ?Sized>(
    calls: &K,
    member: &Candidate,
    dialect: &str,
    model: &str,
    send: &mut dyn UpSend,
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
    let Ok(reply) = send.open(member, &exchange) else {
        return Ok(ProbeOutcome::Unhealthy);
    };
    feed(&mut task, reply, effects)?;
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
