// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The session side of the channel carrier (IF §8.6 CHANNEL, DETACH, WAKE_AT, EX_MSG, §12.13, §12.19; PLANE-DRIVER.md
//! slice 7's left list; PLANE-CARRIER). The carrier itself (spawn, framing, demux, generations) is
//! [`crate::channels::carrier`]; this is how a plane session uses it.
//!
//! * [`ExchangeUpstreams`] is the map from an exchange to the configured upstream it was sent to: the egress walk's
//!   pick ([`Mapped`] wraps the walk's [`Members`] and records every pick), or the member a FORWARD pinned with
//!   `W_UPSTREAM`. A CHANNEL intent attaches "the current target's upstream" (§8.6), so the [`UpstreamHost`] of a
//!   session asks this map.
//! * [`write_channels`] applies an answer's EX_MSG items to the channels (and media bridges) the session holds. A
//!   write that fails ends that channel: the plane gets `P_ERROR` on its exchange.
//! * [`CarrierSession::pump`] is the session loop that runs after the request and its walk: while the session holds
//!   a channel or a media bridge, has a WAKE_AT, or is DETACHed, it waits for the next event and delivers it to the
//!   plane as the IF says: a channel message `piece(FROM_UPSTREAM, exchange, P_TEXT|P_FIN)`, a channel or media
//!   session that ended `piece(FROM_CORE, exchange, P_ERROR)`, a signal `piece(FROM_CORE, 0, P_SIGNAL[|P_TEXT])`,
//!   the wake time `P_TIMER`, and a client that went away while detached `P_CLIENT_GONE`. It ends at FINISH, at the
//!   DETACH `ttl_s` (clamped to [`HELD_MAX`]), when a non-detached session's client goes away, or when nothing is left
//!   to wait for. A media bridge needs no data pump of its own here: the transport session lives as long as the
//!   bridge is held, and the pump is what holds it (the session no longer ends the moment its response is out).
//!
//! The IF names no bound for a session that holds a channel and is not detached; [`HELD_MAX`] bounds it too (design
//! note in PLANE-DRIVER.md).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use busbar_plugin_abi::fail::failed::F_UNAVAILABLE;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{
    FROM_CORE, FROM_UPSTREAM, MSG_ASK, P_CLIENT_GONE, P_ERROR, P_FIN, P_TEXT, P_TIMER,
};
use busbar_plugin_abi::records::Reply;
use busbar_ports::codec::plane::encode_refusal;
use tokio::runtime::Handle;
use tokio::sync::mpsc;

use super::port_channels::{Channels, UpstreamHost};
use super::port_intents::{Detach, Namespace, Resolver};
use super::port_serve::{absorb, Books, Ran};
use super::port_session::{hand_out, Answer, Calls, Effects, SessionError, Task};
use super::port_upstream::{Candidate, Failure, Members, Wants};
use crate::channels::signals::{Registered, SignalRegistry, Signalled};
use crate::channels::{ChannelMsg, UpstreamChannels};
use crate::upstreams::{UpstreamDef, Upstreams};

/// The longest a session is held for channels, a media bridge, a wake time or a signal: a DETACH's `ttl_s` is
/// clamped to it, and a session that is not detached is released at it.
pub const HELD_MAX: Duration = Duration::from_secs(3600);

/// How many signals a detached session buffers (a full one drops, counted by the registry).
const SIGNAL_QUEUE: usize = 32;

/// The exchange to configured-upstream map of one session.
pub struct ExchangeUpstreams {
    table: Arc<dyn Upstreams>,
    names: Mutex<Names>,
}

#[derive(Default)]
struct Names {
    by_exchange: HashMap<u32, Box<str>>,
    /// The current target: the pinned or last picked member.
    current: Option<Box<str>>,
}

impl ExchangeUpstreams {
    #[must_use]
    pub fn new(table: Arc<dyn Upstreams>) -> Self {
        Self {
            table,
            names: Mutex::new(Names::default()),
        }
    }

    fn names(&self) -> std::sync::MutexGuard<'_, Names> {
        self.names.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The session's target is now `member` (the walk picked it, or a FORWARD pinned it).
    pub fn point(&self, member: &str) {
        self.names().current = Some(member.into());
    }

    /// A FORWARD that pins a member (`W_UPSTREAM`) names the target before any pick.
    pub fn point_wanted(&self, wants: &Wants) {
        if let Some(member) = &wants.upstream {
            self.point(member);
        }
    }

    /// `exchange` was sent to `member`.
    pub fn bind(&self, exchange: u32, member: &str) {
        self.names().by_exchange.insert(exchange, member.into());
    }

    /// The configured upstream `exchange` goes to: the one it was bound to, else the current target. `None` = no
    /// target yet, or a name the table does not know.
    #[must_use]
    pub fn of(&self, exchange: u32) -> Option<Arc<UpstreamDef>> {
        let name = {
            let names = self.names();
            names
                .by_exchange
                .get(&exchange)
                .or(names.current.as_ref())
                .cloned()?
        };
        self.table.get(&name)
    }
}

/// A [`Members`] that records every pick in an [`ExchangeUpstreams`] (exchange 0 goes to the picked member).
pub struct Mapped<'a> {
    inner: &'a mut dyn Members,
    map: &'a ExchangeUpstreams,
}

impl<'a> Mapped<'a> {
    #[must_use]
    pub fn new(inner: &'a mut dyn Members, map: &'a ExchangeUpstreams) -> Self {
        Self { inner, map }
    }
}

impl Members for Mapped<'_> {
    fn hook_remaining(&self) -> Option<usize> {
        self.inner.hook_remaining()
    }
    fn hook_failure(&self) -> Option<&str> {
        self.inner.hook_failure()
    }

    fn next(&mut self, wants: &Wants) -> Option<Candidate> {
        let picked = self.inner.next(wants)?;
        self.map.point(&picked.upstream);
        self.map.bind(0, &picked.upstream);
        Some(picked)
    }

    fn declined(&mut self, member: &Candidate) {
        self.inner.declined(member);
    }

    fn failed(&mut self, member: &Candidate, failure: &Failure) {
        self.inner.failed(member, failure);
    }

    fn served(&mut self, member: &Candidate) {
        self.inner.served(member);
    }

    fn retry_after(&self) -> Option<u32> {
        self.inner.retry_after()
    }
}

/// What a plane instance's sessions need of the carrier: its channels, the configured upstreams, the signal registry
/// DETACH registers in, and the node's monotonic clock (the one WAKE_AT is on).
pub struct PortCarrier {
    channels: Arc<dyn UpstreamChannels>,
    upstreams: Arc<dyn Upstreams>,
    registry: Arc<SignalRegistry>,
    who: Namespace,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    rt: Handle,
}

impl PortCarrier {
    #[must_use]
    pub fn new(
        channels: Arc<dyn UpstreamChannels>,
        upstreams: Arc<dyn Upstreams>,
        registry: Arc<SignalRegistry>,
        who: Namespace,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
        rt: Handle,
    ) -> Self {
        Self {
            channels,
            upstreams,
            registry,
            who,
            clock,
            rt,
        }
    }

    /// One request's carrier: its own exchange map and the host its CHANNEL intents attach through.
    #[must_use]
    pub fn session(&self) -> CarrierSession {
        self.session_with_budget(None)
    }

    pub fn session_with_budget(
        &self,
        budget: Option<crate::channels::budget::UnitBudget>,
    ) -> CarrierSession {
        let map = Arc::new(ExchangeUpstreams::new(Arc::clone(&self.upstreams)));
        let of = Arc::clone(&map);
        let host = UpstreamHost::new(
            Arc::clone(&self.channels),
            self.who.clone(),
            Box::new(move |exchange| of.of(exchange)),
            self.rt.clone(),
        )
        .with_budget(budget);
        CarrierSession {
            host,
            map,
            registry: Arc::clone(&self.registry),
            instance: self.who.instance,
            clock: Arc::clone(&self.clock),
            rt: self.rt.clone(),
        }
    }
}

/// One session's side of the carrier.
pub struct CarrierSession {
    /// The host of the session's CHANNEL intents.
    pub host: UpstreamHost,
    pub map: Arc<ExchangeUpstreams>,
    registry: Arc<SignalRegistry>,
    instance: u64,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    rt: Handle,
}

/// What a held session woke for.
enum Event {
    Channel(u32, Option<ChannelMsg>),
    Signal(Option<Signalled>),
    Timer,
    Expired,
}

/// The REFUSAL a plane reads on an exchange whose channel or media session is gone.
fn unavailable() -> Vec<u8> {
    let mut reply = Reply::new();
    let put = encode_refusal(&mut reply, 502, F_UNAVAILABLE, "the channel is unavailable");
    debug_assert!(put.is_ok(), "a REFUSAL fits a Reply");
    reply.as_bytes().to_vec()
}

/// Applies the EX_MSG items of `answers` to the channels the session holds, in answer order. An exchange that holds
/// nothing is dropped (debug); a write that fails ends that channel and the plane is told (`P_ERROR` on its exchange);
/// the answers to those pieces are returned.
///
/// # Errors
/// The plane failed or broke a once rule answering a `P_ERROR`.
pub(super) fn write_channels<K: Calls + ?Sized>(
    task: &mut Task<'_, K>,
    answers: &[Answer],
    resolver: &Resolver<'_>,
    effects: &dyn Effects,
) -> Result<Vec<Answer>, SessionError> {
    let mut more = Vec::new();
    for answer in answers {
        for message in &answer.ex_msgs {
            match task.send_channel(
                message.exchange,
                &message.bytes,
                message.flags & MSG_ASK != 0,
            ) {
                Ok(true) => {}
                Ok(false) => {
                    tracing::debug!(
                        exchange = message.exchange,
                        "an EX_MSG named an exchange that holds no channel"
                    );
                }
                Err(denied) => {
                    tracing::warn!(
                        ?denied,
                        exchange = message.exchange,
                        "a channel write failed"
                    );
                    task.held.remove(&message.exchange);
                    let piece = task.piece(
                        FROM_CORE,
                        message.exchange,
                        P_ERROR,
                        &unavailable(),
                        effects,
                    )?;
                    more.extend(task.resolve(piece, resolver, effects)?);
                }
            }
        }
    }
    Ok(more)
}

impl CarrierSession {
    fn register(
        &self,
        detach: &Detach,
        subject: Option<[u8; 32]>,
    ) -> (Registered, mpsc::Receiver<Signalled>) {
        let (tx, rx) = mpsc::channel(SIGNAL_QUEUE);
        (
            self.registry
                .register(self.instance, &detach.key, subject, tx),
            rx,
        )
    }

    /// The next event of a held session, blocking on the runtime.
    fn wait(
        &self,
        held: &mut Channels,
        signals: Option<&mut mpsc::Receiver<Signalled>>,
        wake_at: Option<u64>,
        expires: Instant,
    ) -> Event {
        let now = (self.clock)();
        self.rt.block_on(async move {
            let channels = async {
                if held.is_empty() {
                    return std::future::pending::<Event>().await;
                }
                let mut futures: Vec<BoxFut<'_, (u32, Option<ChannelMsg>)>> =
                    Vec::with_capacity(held.len());
                for (exchange, channel) in held.iter_mut() {
                    let exchange = *exchange;
                    futures.push(Box::pin(async move { (exchange, channel.recv().await) }));
                }
                let ((exchange, message), _, _) = futures::future::select_all(futures).await;
                Event::Channel(exchange, message)
            };
            let signal = async {
                match signals {
                    Some(rx) => Event::Signal(rx.recv().await),
                    None => std::future::pending::<Event>().await,
                }
            };
            let timer = async {
                match wake_at {
                    Some(at) => {
                        tokio::time::sleep(Duration::from_nanos(at.saturating_sub(now))).await;
                        Event::Timer
                    }
                    None => std::future::pending::<Event>().await,
                }
            };
            let expiry = async {
                tokio::time::sleep_until(tokio::time::Instant::from_std(expires)).await;
                Event::Expired
            };
            tokio::select! {
                event = channels => event,
                event = signal => event,
                event = timer => event,
                event = expiry => event,
            }
        })
    }

    fn apply<K: Calls + ?Sized>(
        task: &mut Task<'_, K>,
        answer: Answer,
        ran: &mut Ran,
        resolver: &Resolver<'_>,
        effects: &dyn Effects,
        books: &dyn Books,
    ) -> Result<(), SessionError> {
        let answers = task.resolve(answer, resolver, effects)?;
        let written = write_channels(task, &answers, resolver, effects)?;
        absorb(ran, &mut None, answers, books);
        absorb(ran, &mut None, written, books);
        Ok(())
    }

    /// The session loop of a held session (see the module docs). Runs on the blocking thread the session runs on.
    ///
    /// # Errors
    /// The plane refused, failed or faulted, or broke a once rule, answering a delivery.
    pub fn pump<K: Calls + ?Sized>(
        &self,
        task: &mut Task<'_, K>,
        ran: &mut Ran,
        resolver: &Resolver<'_>,
        effects: &dyn Effects,
        books: &dyn Books,
    ) -> Result<(), SessionError> {
        let started = Instant::now();
        let mut signals: Option<(Registered, mpsc::Receiver<Signalled>)> = None;
        let mut registered = false;
        let mut expires = started + HELD_MAX;
        let mut gone = false;
        loop {
            if ran.finished {
                return Ok(());
            }
            if let (false, Some(detach)) = (registered, ran.detach.clone()) {
                registered = true;
                expires = started + Duration::from_secs(detach.ttl_s).min(HELD_MAX);
                signals = Some(self.register(&detach, resolver.subject()));
            }
            if task.held.is_empty() && ran.wake_at.is_none() && signals.is_none() {
                return Ok(());
            }
            let event = self.wait(
                &mut task.held,
                signals.as_mut().map(|(_, rx)| rx),
                ran.wake_at,
                expires,
            );
            let answer = match event {
                Event::Expired => return Ok(()),
                Event::Channel(exchange, Some(ChannelMsg::Message(bytes))) => {
                    task.piece(FROM_UPSTREAM, exchange, P_TEXT | P_FIN, &bytes, effects)?
                }
                Event::Channel(exchange, _) => {
                    task.held.remove(&exchange);
                    task.piece(FROM_CORE, exchange, P_ERROR, &unavailable(), effects)?
                }
                Event::Signal(Some(signalled)) => {
                    task.piece(FROM_CORE, 0, signalled.flags, &signalled.bytes, effects)?
                }
                Event::Signal(None) => {
                    signals = None;
                    continue;
                }
                Event::Timer => {
                    ran.wake_at = None;
                    task.piece(FROM_CORE, 0, P_TIMER, &[], effects)?
                }
            };
            Self::apply(task, answer, ran, resolver, effects, books)?;
            effects.observed_usage(task.usage());
            if !hand_out(effects, &mut ran.client) {
                if ran.detach.is_none() {
                    return Ok(());
                }
                if !gone {
                    gone = true;
                    let answer = task.piece(FROM_CORE, 0, P_CLIENT_GONE, &[], effects)?;
                    Self::apply(task, answer, ran, resolver, effects, books)?;
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/port_carrier_tests.rs"]
mod tests;
