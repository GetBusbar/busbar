// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The channel carrier driver (IF §8.6 CHANNEL, §12.19; PLANE-DRIVER.md slice 7's left list, PLANE-CARRIER): the
//! production [`UpstreamChannels`] of one plane instance.
//!
//! One [`Channel`] per key (upstream, channel key, subject when `CH_PER_CALLER`) holds the live [`Generation`]: the
//! wire (a stdio child or a held request, opened through [`Wires`]), its [`Link`] (ask line, writer queue, greet) and
//! the slots attached to it. An attach joins the live generation, or opens one (a stdio child respawns on the
//! 100 ms doubling schedule and trips on the fifth end inside 60 s, [`Respawn`]). The first attach of a generation
//! greets; the others wait, bounded by the session deadline, until it answers CH_READY.
//!
//! The reader task frames what the wire delivers ([`Framer`]), asks the plane's sessionless `demux` where each
//! message goes ([`Demuxer`]) and routes it by the DEMUX it got: to a slot (DX_FINAL then releases the next serial
//! ask), to the head of the ask line (DX_OUTSTANDING, with the plane's fallback written when the line is empty and
//! counted when there is none), or to every detached session registered under a key (DX_BROADCAST, through
//! [`SessionSignals`]). Delivery is a `try_send` on the slot's bounded channel: the reader never waits on a session.
//! The writer task frames what sessions send and writes it in arrival order. A wire that ends (EOF, error, the
//! writer failing, an overlong message) ends the generation: every attached slot is told (its receiver closes, which
//! an attachment reads as [`ChannelMsg::Ended`]). A generation nothing is attached to for the upstream's idle time
//! is closed without counting as an end.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::plane::{
    CARRIER_HTTP, CARRIER_STDIO, CH_PER_CALLER, CH_SERIAL, DX_BROADCAST, DX_FINAL, DX_OUTSTANDING,
    DX_RESIGHT, P_SIGNAL, P_TEXT,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::{mpsc, Notify};

use super::budget::{Charge, Claim as BudgetClaim, InstanceBudget, UnitBudget};
use super::frame::{Framer, Framing};
use super::link::{Claim, Link};
use super::protected::GuardedWrite;
use super::respawn::{Respawn, Spawn};
use super::{Attachment, ChannelMsg, ChannelReq, SessionSignals, UpstreamChannels};
use crate::limits::output::OutputBuffer;
use crate::plane_driver::port_channels::Demuxed;
use crate::plugin_records::RecordsDenied;
use crate::upstreams::{UpstreamDef, DEFAULT_IDLE_S};

/// The longest channel key (§8.6 ChanRec).
pub const MAX_KEY: usize = 128;

/// How many inbound messages a slot buffers before delivery drops (counted).
pub(crate) const SLOT_QUEUE: usize = 64;

/// How an open wire reads and writes. Dropping `hold` stops the child or closes the request.
pub struct Wire {
    pub read: Box<dyn AsyncRead + Send + Unpin>,
    /// `None` = the far end takes no writes (a held HTTP request): a send on the channel is refused.
    pub write: Option<Box<dyn AsyncWrite + Send + Unpin>>,
    pub hold: Box<dyn Send>,
}

/// Opens the wire of one generation: spawns the child of a CARRIER_STDIO upstream (its argv, resolved env and
/// working directory, a `LocalProgram` pin checked before the first byte is written) or sends the held request of a
/// CARRIER_HTTP one (every dial judged by the connector's guard).
pub trait Wires: Send + Sync + 'static {
    fn open<'a>(
        &'a self,
        upstream: &'a UpstreamDef,
        req: &'a ChannelReq<'a>,
    ) -> BoxFut<'a, Result<Wire, RecordsDenied>>;
}

/// The plane's sessionless `demux` (§8.6 DemuxRec): where one framed inbound message goes. `None` = the plane wrote
/// no DEMUX (slot 0, dropped and audited at debug). A native port error ends this generation.
pub trait Demuxer: Send + Sync + 'static {
    fn demux(&self, key: &str, message: &[u8]) -> Result<Option<Demuxed>, busbar_ports::PortError>;
}

/// What the driver says happened, for the audit chain and the sighting scheduler.
pub trait Events: Send + Sync + 'static {
    /// The channel of `upstream` tripped: the fifth child end inside 60 s (`upstream_child_tripped`).
    fn tripped(&self, upstream: &str);
    /// A DEMUX with DX_RESIGHT: the counterparty announced a change; schedule a sighting probe of `upstream`.
    fn resight(&self, upstream: &str);
}

/// [`Events`] that only log.
pub struct LogEvents;

impl Events for LogEvents {
    fn tripped(&self, upstream: &str) {
        tracing::warn!(upstream, "upstream_child_tripped");
    }

    fn resight(&self, upstream: &str) {
        tracing::debug!(upstream, "a channel asked for a sighting");
    }
}

/// What the driver counts (`plane_channel_unattributed_total`, and the messages a full slot dropped).
#[derive(Debug, Default)]
pub struct Counts {
    unattributed: AtomicU64,
    slot_full: AtomicU64,
}

impl Counts {
    /// A DX_OUTSTANDING message with no ask open and no fallback.
    #[must_use]
    pub fn unattributed(&self) -> u64 {
        self.unattributed.load(Ordering::Relaxed)
    }

    /// Messages dropped because the slot's queue was full.
    #[must_use]
    pub fn slot_full(&self) -> u64 {
        self.slot_full.load(Ordering::Relaxed)
    }
}

/// What the generation tasks share with the driver.
struct Shared {
    instance: u64,
    owner: busbar_contract::services::Caller,
    budget: InstanceBudget,
    demuxer: Arc<dyn Demuxer>,
    signals: Arc<dyn SessionSignals>,
    events: Arc<dyn Events>,
    counts: Arc<Counts>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ChanKey {
    command: Option<super::authority::ChannelAuthority>,
    upstream: Box<str>,
    key: Box<str>,
    subject: Option<[u8; 32]>,
}

struct Channel {
    state: tokio::sync::Mutex<ChanState>,
    _key: Charge,
    policy: JoinPolicy,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct JoinPolicy {
    carrier: u32,
    flags: u32,
    framing: u32,
}

#[derive(Default)]
struct ChanState {
    respawn: Respawn,
    live: Option<Arc<Generation>>,
    generations: u64,
}

/// One incarnation of a channel: a child or a request, until it ends.
struct Generation {
    command: Option<super::authority::ChannelAuthority>,
    number: u64,
    link: Arc<Link>,
    slots: Mutex<HashMap<u64, mpsc::Sender<ChannelMsg>>>,
    next_slot: AtomicU64,
    alive: AtomicBool,
    stopping: AtomicBool,
    /// Ends the generation (the writer failed): one stored permit is enough.
    stop: Notify,
    upstream: Box<str>,
    key: Box<str>,
    framing: Framing,
    subject: Option<[u8; 32]>,
}

impl Generation {
    fn slots(&self) -> std::sync::MutexGuard<'_, HashMap<u64, mpsc::Sender<ChannelMsg>>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The production [`UpstreamChannels`] of one plane instance.
pub struct ChannelDriver {
    shared: Arc<Shared>,
    wires: Arc<dyn Wires>,
    channels: Mutex<HashMap<ChanKey, Arc<Channel>>>,
}

impl ChannelDriver {
    /// `instance` is the plane instance's runtime id (the signal registry's key); `demuxer` is that plane's `demux`.
    #[must_use]
    pub fn new(
        instance: u64,
        owner: busbar_contract::services::Caller,
        budget: InstanceBudget,
        wires: Arc<dyn Wires>,
        demuxer: Arc<dyn Demuxer>,
        signals: Arc<dyn SessionSignals>,
        events: Arc<dyn Events>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                instance,
                owner,
                budget,
                demuxer,
                signals,
                events,
                counts: Arc::new(Counts::default()),
            }),
            wires,
            channels: Mutex::new(HashMap::new()),
        }
    }

    /// The driver's counters.
    #[must_use]
    pub fn counts(&self) -> Arc<Counts> {
        Arc::clone(&self.shared.counts)
    }

    fn check_command(
        &self,
        req: &ChannelReq<'_>,
        upstream: &UpstreamDef,
    ) -> Result<(), RecordsDenied> {
        req.check_command(upstream)?;
        if req.carrier == CARRIER_STDIO
            && !req
                .command
                .is_some_and(|proof| proof.accepts(&self.shared.owner))
        {
            return Err(RecordsDenied::Invalid);
        }
        Ok(())
    }

    /// `upstream` was declared anew (config reload or admin reconfigure): a tripped channel of it may spawn again and
    /// its counted ends are forgotten (§12.19).
    pub async fn redeclared(&self, upstream: &str) {
        let channels: Vec<Arc<Channel>> = self
            .channels
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(key, _)| &*key.upstream == upstream)
            .map(|(_, channel)| Arc::clone(channel))
            .collect();
        for channel in channels {
            channel.state.lock().await.respawn.redeclared();
        }
    }

    fn channel(
        &self,
        key: ChanKey,
        budget: &UnitBudget,
        policy: JoinPolicy,
    ) -> Result<Arc<Channel>, RecordsDenied> {
        let mut channels = self.channels.lock().unwrap_or_else(PoisonError::into_inner);
        channels.retain(|key, _| key.command.as_ref().is_none_or(|proof| proof.is_live()));
        if let Some(channel) = channels.get(&key) {
            return if channel.policy == policy {
                Ok(channel.clone())
            } else {
                Err(RecordsDenied::Invalid)
            };
        }
        if channels.len() >= 64 {
            return Err(RecordsDenied::Unavailable);
        }
        let charge = budget
            .reserve(
                BudgetClaim {
                    keys: 1,
                    ..BudgetClaim::default()
                },
                None,
            )
            .map_err(|_| RecordsDenied::Unavailable)?;
        let channel = Arc::new(Channel {
            state: tokio::sync::Mutex::new(ChanState::default()),
            _key: charge,
            policy,
        });
        channels.insert(key, channel.clone());
        Ok(channel)
    }

    /// The live generation of `channel`, or a new one: a stdio child waits out its respawn delay and refuses
    /// (`Unavailable`) once tripped; a wire that cannot be opened is an end of it.
    async fn generation(
        &self,
        channel: &Arc<Channel>,
        upstream: &UpstreamDef,
        req: &ChannelReq<'_>,
        framing: Framing,
        key: &ChanKey,
    ) -> Result<Arc<Generation>, RecordsDenied> {
        let stdio = req.carrier == CARRIER_STDIO;
        let mut state = channel.state.lock().await;
        self.check_command(req, upstream)?;
        if let Some(live) = &state.live {
            if live.stopping.load(Ordering::Acquire) {
                return Err(RecordsDenied::Unavailable);
            }
            if live.alive.load(Ordering::Acquire) {
                return Ok(Arc::clone(live));
            }
        }
        state.live = None;
        if stdio {
            loop {
                match state.respawn.next(Instant::now()) {
                    Spawn::Now => break,
                    Spawn::After(wait) => tokio::time::sleep(wait).await,
                    Spawn::Tripped => return Err(RecordsDenied::Unavailable),
                }
            }
        }
        self.check_command(req, upstream)?;
        let source = req.budget.storage();
        let framer =
            Framer::new(framing, source.clone()).map_err(|_| RecordsDenied::Unavailable)?;
        let read_buffer = OutputBuffer::with_source(&source, 16 * 1024)
            .map_err(|_| RecordsDenied::Unavailable)?;
        let wire = match self.wires.open(upstream, req).await {
            Ok(wire) => wire,
            Err(denied) => {
                if stdio && state.respawn.ended(Instant::now()) {
                    self.shared.events.tripped(&upstream.name);
                }
                return Err(denied);
            }
        };
        self.check_command(req, upstream)?;
        let (link, queue) = Link::new(
            req.flags & CH_SERIAL != 0,
            framing,
            self.shared.budget.link(),
        );
        state.generations = state
            .generations
            .checked_add(1)
            .ok_or(RecordsDenied::Unavailable)?;
        let generation = Arc::new(Generation {
            command: key.command.clone(),
            number: state.generations,
            link,
            slots: Mutex::new(HashMap::new()),
            next_slot: AtomicU64::new(1),
            alive: AtomicBool::new(true),
            stopping: AtomicBool::new(false),
            stop: Notify::new(),
            upstream: key.upstream.clone(),
            key: req.key.into(),
            framing,
            subject: key.subject,
        });
        state.live = Some(Arc::clone(&generation));
        let idle = match (&upstream.command, stdio) {
            (Some(command), true) => Some(Duration::from_secs(if command.idle_s == 0 {
                DEFAULT_IDLE_S
            } else {
                command.idle_s
            })),
            _ => None,
        };
        let run = Run {
            shared: Arc::clone(&self.shared),
            channel: Arc::clone(channel),
            generation: Arc::clone(&generation),
            stdio,
            idle,
        };
        tokio::spawn(run.run(wire, queue, framer, read_buffer));
        Ok(generation)
    }

    async fn join(
        &self,
        channel: &Arc<Channel>,
        upstream: &UpstreamDef,
        req: &ChannelReq<'_>,
        framing: Framing,
        key: &ChanKey,
    ) -> Result<Attachment, RecordsDenied> {
        // Reserve before a child/request can open or a greeting can be claimed. The same actual
        // unit owns this lease while waiting and after publication; cancellation drops it.
        let lease = req
            .budget
            .reserve(
                BudgetClaim {
                    leases: 1,
                    ..BudgetClaim::default()
                },
                None,
            )
            .map_err(|_| RecordsDenied::Unavailable)?;
        'generations: loop {
            self.check_command(req, upstream)?;
            let generation = self
                .generation(channel, upstream, req, framing, key)
                .await?;
            let slot = generation
                .next_slot
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(1)
                })
                .map_err(|_| RecordsDenied::Unavailable)?;
            let (greet, ready_tail) = loop {
                if let Err(denied) = self.check_command(req, upstream) {
                    generation.link.release_greet(slot);
                    return Err(denied);
                }
                match generation.link.claim_greet(slot) {
                    Claim::Greeter => break (true, bytes::Bytes::new()),
                    Claim::Ready(tail) => {
                        generation.link.pass_on();
                        break (false, tail);
                    }
                    Claim::Wait => {
                        if !generation.alive.load(Ordering::Acquire) {
                            generation.link.pass_on();
                            continue 'generations;
                        }
                        generation.link.greet_released().await;
                        if !generation.alive.load(Ordering::Acquire) {
                            generation.link.pass_on();
                            continue 'generations;
                        }
                    }
                }
            };
            let (tx, rx) = mpsc::channel(SLOT_QUEUE);
            if let Err(denied) = self.check_command(req, upstream) {
                generation.link.release_greet(slot);
                return Err(denied);
            }
            {
                let mut slots = generation.slots();
                if !generation.alive.load(Ordering::Acquire) {
                    drop(slots);
                    generation.link.pass_on();
                    continue 'generations;
                }
                slots.retain(|_, tx| !tx.is_closed());
                if slots.len() >= 256 {
                    generation.link.release_greet(slot);
                    return Err(RecordsDenied::Unavailable);
                }
                slots.insert(slot, tx);
            }
            let attached = Attachment::linked_reserved(
                Arc::clone(&generation.link),
                req.budget.clone(),
                lease,
                super::AttachAt {
                    generation: generation.number,
                    slot,
                    greet,
                },
                ready_tail,
                rx,
            );
            if attached.is_err() {
                generation.slots().remove(&slot);
                generation.link.release_greet(slot);
            }
            return attached;
        }
    }
}

impl UpstreamChannels for ChannelDriver {
    fn attach<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        upstream: &'a UpstreamDef,
        req: ChannelReq<'a>,
    ) -> BoxFut<'a, Result<Attachment, RecordsDenied>> {
        let (deadline, instance) = (plane.deadline, plane.instance);
        Box::pin(async move {
            self.check_command(&req, upstream)?;
            if instance != self.shared.instance || !self.shared.budget.accepts_unit(req.budget) {
                return Err(RecordsDenied::Invalid);
            }
            let framing = Framing::of(req.framing).ok_or(RecordsDenied::Invalid)?;
            if !matches!(req.carrier, CARRIER_STDIO | CARRIER_HTTP) || req.key.len() > MAX_KEY {
                return Err(RecordsDenied::Invalid);
            }
            let subject = if req.flags & CH_PER_CALLER != 0 {
                Some(req.subject.ok_or(RecordsDenied::Invalid)?)
            } else {
                None
            };
            let key = ChanKey {
                command: (req.carrier == CARRIER_STDIO)
                    .then(|| req.command.cloned())
                    .flatten(),
                upstream: upstream.name.clone(),
                key: req.key.into(),
                subject,
            };
            let policy = JoinPolicy {
                carrier: req.carrier,
                flags: req.flags,
                framing: req.framing,
            };
            let channel = self.channel(key.clone(), req.budget, policy)?;
            let until = tokio::time::Instant::from_std(deadline);
            match tokio::time::timeout_at(until, self.join(&channel, upstream, &req, framing, &key))
                .await
            {
                Ok(attached) => attached,
                Err(_) => Err(RecordsDenied::Unavailable),
            }
        })
    }
}

/// How a generation's reader stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// The wire ended or failed: a child exit, a dropped request.
    Wire,
    /// Nothing was attached for the idle time: core closed it; not an end of the child.
    Idle,
}

/// The tasks of one generation.
struct Run {
    shared: Arc<Shared>,
    channel: Arc<Channel>,
    generation: Arc<Generation>,
    stdio: bool,
    idle: Option<Duration>,
}

impl Run {
    async fn run(
        self,
        wire: Wire,
        queue: mpsc::Receiver<GuardedWrite>,
        mut framer: Framer,
        mut buf: OutputBuffer,
    ) {
        let Wire {
            mut read,
            write,
            hold,
        } = wire;
        let writer = tokio::spawn(write_loop(Arc::clone(&self.generation), write, queue));
        let poll = self.idle.map_or(Duration::from_secs(3600), |idle| {
            (idle / 4).clamp(Duration::from_millis(10), Duration::from_secs(5))
        });
        let mut check = tokio::time::Instant::now() + poll;
        let mut discard_tail = false;
        let end = 'reads: loop {
            if self.generation.stopping.load(Ordering::Acquire) {
                break End::Wire;
            }
            let loan = match buf.read_loan() {
                Ok(loan) => loan,
                Err(_) => break End::Wire,
            };
            tokio::select! {
                got = read.read(loan) => match got {
                    Ok(0) | Err(_) => break End::Wire,
                    Ok(n) => {
                        buf.truncate(n);
                        let mut bytes = buf.as_ref();
                        loop {
                            match framer.feed(&mut bytes) {
                                Ok(Some(message)) => self.deliver(message).await,
                                Ok(None) => break,
                                Err(_) => { discard_tail = true; break 'reads End::Wire; }
                            }
                        }
                    },
                },
                () = self.generation.stop.notified() => break End::Wire,
                () = tokio::time::sleep_until(check) => {
                    check = tokio::time::Instant::now() + poll;
                    if self.idle.is_some_and(|idle| self.generation.link.idle() >= idle) {
                        break End::Idle;
                    }
                }
            }
        };
        if end == End::Wire && !discard_tail {
            if let Ok(Some(last)) = framer.finish() {
                self.deliver(last).await;
            }
        }
        drop(read);
        let mut state = self.channel.state.lock().await;
        if self.stdio && end == End::Wire && state.respawn.ended(Instant::now()) {
            self.shared.events.tripped(&self.generation.upstream);
        }
        self.generation.alive.store(false, Ordering::Release);
        self.generation.stopping.store(true, Ordering::Release);
        let _ = self.generation.link.ended();
        writer.abort();
        // The state lock prevents a replacement generation from opening until the writer's
        // actual future has dropped every queued/in-progress payload and its account guards.
        let _ = writer.await;
        self.generation.slots().clear();
        self.generation.link.pass_on();
        if state
            .live
            .as_ref()
            .is_some_and(|live| Arc::ptr_eq(live, &self.generation))
        {
            state.live = None;
        }
        // The wire goes last: whoever sees the child gone finds its generation already ended.
        drop(hold);
        drop(state);
    }

    /// One framed inbound message: asks the plane where it goes and routes it.
    async fn deliver(&self, message: bytes::Bytes) {
        let generation = &self.generation;
        if generation.stopping.load(Ordering::Acquire) {
            return;
        }
        let demuxer = Arc::clone(&self.shared.demuxer);
        let key = generation.key.clone();
        let routed = tokio::task::spawn_blocking(move || {
            let routed = demuxer.demux(&key, &message);
            (message, routed)
        })
        .await;
        let (message, routed) = match routed {
            Ok((message, Ok(routed))) => (message, routed),
            Ok((_, Err(_))) | Err(_) => {
                generation.stopping.store(true, Ordering::Release);
                generation.stop.notify_one();
                return;
            }
        };
        if !generation.alive.load(Ordering::Acquire) || generation.stopping.load(Ordering::Acquire)
        {
            return;
        }
        let Some(demuxed) = routed else {
            tracing::debug!(
                upstream = &*generation.upstream,
                "a channel message had no slot"
            );
            return;
        };
        if demuxed.flags & DX_RESIGHT != 0 {
            self.shared.events.resight(&generation.upstream);
        }
        if demuxed.slot != 0 {
            self.to_slot(demuxed.slot, message);
            if demuxed.flags & DX_FINAL != 0 {
                generation.link.finished(demuxed.slot);
            }
        } else if demuxed.flags & DX_OUTSTANDING != 0 {
            match generation.link.head() {
                Some(slot) => self.to_slot(slot, message),
                None if demuxed.tail.is_empty() => {
                    self.shared
                        .counts
                        .unattributed
                        .fetch_add(1, Ordering::Relaxed);
                }
                None => {
                    let sent = GuardedWrite::fallback(
                        &self.shared.budget,
                        generation.link.budget(),
                        generation.framing,
                        &demuxed.tail,
                    )
                    .ok()
                    .is_some_and(|message| generation.link.write(message).is_ok());
                    if !sent {
                        self.shared
                            .counts
                            .unattributed
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        } else if demuxed.flags & DX_BROADCAST != 0 {
            let reached = if let Some(authority) = &generation.command {
                self.shared.signals.signal_command(
                    self.shared.instance,
                    authority,
                    &demuxed.tail,
                    P_SIGNAL | P_TEXT,
                    &message,
                )
            } else {
                self.shared.signals.signal(
                    self.shared.instance,
                    &demuxed.tail,
                    generation.subject,
                    P_SIGNAL | P_TEXT,
                    &message,
                )
            };
            tracing::debug!(reached, "a channel message was broadcast");
        } else {
            tracing::debug!(
                upstream = &*generation.upstream,
                "a channel message was dropped"
            );
        }
    }

    fn to_slot(&self, slot: u64, message: bytes::Bytes) {
        let tx = self.generation.slots().get(&slot).cloned();
        match tx {
            Some(tx) => {
                if tx.try_send(ChannelMsg::Message(message)).is_err() {
                    self.shared.counts.slot_full.fetch_add(1, Ordering::Relaxed);
                }
            }
            None => tracing::debug!(slot, "a channel message named a slot that is gone"),
        }
    }
}

/// Writes what sessions send, framed, in arrival order. A wire with no write side refuses sends (the queue closes).
async fn write_loop(
    generation: Arc<Generation>,
    write: Option<Box<dyn AsyncWrite + Send + Unpin>>,
    mut queue: mpsc::Receiver<GuardedWrite>,
) {
    let Some(mut write) = write else {
        drop(queue);
        return;
    };
    while let Some(message) = queue.recv().await {
        if message.write(&mut write).await.is_err() {
            generation.stopping.store(true, Ordering::Release);
            generation.stop.notify_one();
            return;
        }
    }
}
