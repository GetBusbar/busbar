// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DATAGRAM SESSION, on the data listener.
//!
//! A door plane's claim whose carrier a DATAGRAM framer answers is an HTTP unit whose answer turns
//! it into a duplex session on a host carrier, as an upgrade does for a stream: the request body is
//! the far end's description; the host opens the accepting association over its CLAIM DOOR (the
//! datagram port the transport's inbound need binds) and the association becomes the unit's duplex
//! session, its caller side this file's [`DatagramCaller`] on the driver's one `SessionCaller`
//! path. The answer carries the framer's own description as its body.
//!
//! What the session carries is the association's CHANNELS: their messages are the session's
//! pieces, both ways. Its LINES never reach the session or the plane: the session's
//! [`Pairing`] bridges them with the upstream leg's, which the session's walk opens for the same
//! unit (the connector's session book, keyed by the unit). The session's cleanup closes the pairing
//! once, both legs with it.
//!
//! No noun of any protocol is spelled here: a claim door, an association, a description, lines and
//! channels.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Instant;

use busbar_core_connector::datagram::{
    Across, Answered, DatagramFraming, Leg, LegSink, LineStep, Pairing, PortAssociations,
    PublicationTask, SessionBatch,
};
use busbar_core_connector::framer::Got;
use busbar_core_connector::publication::{Custody, Message, Messages};
use busbar_core_connector::udp::{ReadyPort, MAX_DATAGRAM};
use busbar_kernel::detached::{self, DetachedTasks};
use busbar_kernel::plane_driver::{CallerEnd, HeadFields, SessionCaller};
use tokio::sync::{oneshot, Notify};

use super::Stated;

/// How many channel messages a session's caller side holds before the session ends, either way:
/// for the plane, and from it before the far end opens a channel.
const CALLER_QUEUE: usize = 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// THE CLAIM DOORS, by the claim their datagram framer answers: each one bound port.
#[derive(Debug, Default, Clone)]
pub struct ClaimDoors(HashMap<String, Arc<ClaimDoor>>);

impl ClaimDoors {
    /// Serve `claim`'s associations over `door`.
    pub fn insert(&mut self, claim: &str, door: Arc<ClaimDoor>) {
        self.0.insert(claim.to_owned(), door);
    }

    /// The claim door for `claim`.
    #[must_use]
    pub fn get(&self, claim: &str) -> Option<Arc<ClaimDoor>> {
        self.0.get(claim).cloned()
    }

    /// THE CLAIM DOORS BOOT BINDS: one for every inbound
    /// listener in the one list of listeners whose transport a DATAGRAM framer answers, bound on
    /// the address its `{listen}` block names, its task on the calling worker. A listener over any
    /// other transport is no claim door (the data listener and the stream listeners bind those);
    /// two claim doors for one claim are refused.
    ///
    /// # Errors
    ///
    /// The setting that names an address the port cannot bind (a wildcard included: a claim
    /// door's address is the one candidate its associations advertise), or a claim bound twice.
    pub fn bind(
        binds: &[crate::root::loader::boot::InboundBind],
        framer_for: impl Fn(&str) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>>,
    ) -> Result<Self, String> {
        let mut doors = ClaimDoors::default();
        for b in binds {
            if b.transport.is_empty()
                || !framer_for(&b.transport).is_some_and(|d| d.facts().datagram)
            {
                continue;
            }
            if doors.0.contains_key(&b.transport) {
                return Err(format!(
                    "{}: a second claim door for `{}`",
                    b.listen_setting(),
                    b.transport
                ));
            }
            let port = busbar_core_connector::udp::bind(&b.listen.to_string())
                .and_then(ReadyPort::open)
                .map_err(|e| {
                    format!("{}: {} cannot be bound: {e}", b.listen_setting(), b.listen)
                })?;
            doors.insert(&b.transport, ClaimDoor::serve(port));
        }
        Ok(doors)
    }
}

/// ONE CLAIM DOOR: one bound datagram port, every accepted association on it, and each one's
/// session leg.
pub struct ClaimDoor {
    port: ReadyPort,
    runtime: tokio::runtime::Handle,
    detached: Option<Arc<DetachedTasks>>,
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    closed: AtomicBool,
    assocs: PortAssociations,
    legs: Mutex<HashMap<u64, Arc<CallerLeg>>>,
    /// Woken when an association joins, or a writer ran what the port's task queued for an
    /// association it had out, so the port's task keeps its clock.
    joined: Notify,
}

struct Serving(Arc<ClaimDoor>);

impl Drop for Serving {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl std::fmt::Debug for ClaimDoor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimDoor")
            .field("local", &self.port.local_addr())
            .finish_non_exhaustive()
    }
}

impl ClaimDoor {
    /// A claim door over `port` (already on the worker's reactor), its task spawned on the current
    /// runtime.
    #[must_use]
    pub fn serve(port: ReadyPort) -> Arc<Self> {
        let door = Arc::new(ClaimDoor {
            port,
            runtime: tokio::runtime::Handle::current(),
            detached: detached::worker_detached(),
            shutdown: detached::worker_shutdown(),
            closed: AtomicBool::new(false),
            assocs: PortAssociations::new(),
            legs: Mutex::new(HashMap::new()),
            joined: Notify::new(),
        });
        door.spawn(Arc::clone(&door).run());
        door
    }

    fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match &self.detached {
            Some(tracker) => tracker.spawn_on(&self.runtime, future),
            None => self.runtime.spawn(future),
        }
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let raw_busy_dropped = self.assocs.raw_busy_dropped();
        if raw_busy_dropped != 0 {
            tracing::info!(
                raw_busy_dropped,
                "datagram claim door closed after raw ingress readiness drops"
            );
        }
        let legs = std::mem::take(&mut *lock(&self.legs));
        self.joined.notify_one();
        for leg in legs.into_values() {
            leg.failed();
        }
    }

    /// The port's own address: the one candidate every association on it advertises.
    #[must_use]
    pub fn local(&self) -> SocketAddr {
        self.port.local_addr()
    }

    /// Send one datagram an association owes the port; a send that would block drops it.
    fn send(&self, to: SocketAddr, d: &[u8]) {
        let _ = self.port.send_to(d, to);
    }

    /// What the port's associations answered, to each one's leg.
    fn answer(&self, answered: Answered, now: Instant) {
        for (id, answer) in answered {
            let leg = lock(&self.legs).get(&id).cloned();
            match (leg, answer) {
                (Some(leg), Ok(y)) => leg.yielded_batch(y, now),
                (Some(leg), Err(_)) => leg.failed(),
                (None, Ok(yielded)) => {
                    if let Some(pairing) = yielded.producer.pairing() {
                        pairing.close();
                        // A READY batch arriving after removal is explicit cancelled output;
                        // keep its original stream identity until that classification finishes.
                        let _cancelled = pairing.publish(Leg::Caller, yielded, now);
                    }
                }
                (None, _) => {}
            }
        }
    }

    /// THE PORT'S TASK: every datagram read and handed to the association it belongs to, the
    /// associations' clock kept, what each yields handed to its leg; until shutdown or cancellation.
    fn run(self: Arc<Self>) -> impl std::future::Future<Output = ()> + Send + 'static {
        // Ownership is captured before scheduling, including cancellation before first poll.
        let guard = Serving(self);
        async move {
            let serving = guard;
            serving.0.run_loop().await;
        }
    }

    async fn run_loop(&self) {
        let shutdown = detached::shutdown_fired(self.shutdown.clone());
        tokio::pin!(shutdown);
        let mut buf = vec![0_u8; MAX_DATAGRAM];
        loop {
            if self.closed.load(Ordering::Acquire) {
                return;
            }
            let deadline = self.assocs.deadline();
            let read = std::future::poll_fn(|cx| {
                self.port
                    .poll_recv_from(cx, &mut buf)
                    .map(|r| r.map(|(n, from)| (buf[..n].to_vec(), from)))
            });
            let sleep = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                    None => std::future::pending::<()>().await,
                }
            };
            enum Woke {
                Read(std::io::Result<(Vec<u8>, SocketAddr)>),
                Clock,
                Joined,
            }
            let woke = tokio::select! {
                () = &mut shutdown => return,
                got = read => Woke::Read(got),
                () = sleep => Woke::Clock,
                () = self.joined.notified() => Woke::Joined,
            };
            let now = Instant::now();
            let answered = match woke {
                Woke::Read(Ok((datagram, from))) => self
                    .assocs
                    .raw_datagram(from, &datagram, now, &|to, d| self.send(to, d))
                    .into_answered(),
                // A per-datagram error (an unreachable far end reported back): the port stands.
                Woke::Read(Err(_)) => Vec::new(),
                Woke::Joined => Vec::new(),
                Woke::Clock => self
                    .assocs
                    .timeout_incremental(now, &|to, d| self.send(to, d)),
            };
            self.answer(answered, now);
        }
    }

    /// Carry `framing` on this door as `leg`'s association; its number.
    fn join(
        &self,
        mut framing: DatagramFraming,
        leg: &Arc<CallerLeg>,
    ) -> Result<u64, busbar_core_connector::datagram::NotAdded> {
        if let Some(pairing) = lock(&leg.pairing).as_ref() {
            framing.memory(pairing.memory_account());
        }
        let id = self.assocs.add_with(framing, |id| {
            leg.bind(id);
            lock(&self.legs).insert(id, Arc::clone(leg));
        })?;
        // A shutdown can retire the existing legs while admission is publishing this one.
        // Once add_with releases the port map, retire a late association through its pairing.
        if self.closed.load(Ordering::Acquire) {
            leg.failed();
        }
        self.joined.notify_one();
        Ok(id)
    }

    /// Emit on association `id` and flush.
    fn emit(
        &self,
        id: u64,
        stream: u64,
        bytes: &[u8],
        end: bool,
        text: bool,
        now: Instant,
    ) -> bool {
        let (ok, answered) = self
            .assocs
            .emit(id, stream, bytes, end, text, now, &|to, d| self.send(to, d));
        if !answered.is_empty() {
            self.joined.notify_one();
        }
        self.answer(answered, now);
        ok
    }

    async fn emit_ready(&self, id: u64, stream: u64, bytes: &[u8], text: bool) -> bool {
        self.assocs
            .emit_ready(
                id,
                stream,
                bytes,
                true,
                text,
                &|to, d| self.send(to, d),
                &|answered| {
                    self.joined.notify_one();
                    self.answer(answered, Instant::now());
                },
            )
            .await
    }

    /// Stop carrying association `id`: its framing finishes as it drops.
    fn leave(&self, id: u64) {
        let gone = lock(&self.legs).remove(&id);
        self.assocs.remove(id);
        drop(gone);
    }
}

/// THE CALLER'S LEG of one datagram session: its association on the claim door, the session's
/// pairing, the channel the session's pieces ride, and the queue the plane reads them from.
pub struct CallerLeg {
    me: Weak<CallerLeg>,
    door: Weak<ClaimDoor>,
    id: Mutex<Option<u64>>,
    pairing: Mutex<Option<Arc<Pairing>>>,
    /// Channel selection, pending messages and the one writer draining them share a handoff.
    outbound: Mutex<Outbound>,
    writes: tokio::sync::Semaphore,
    released: Notify,
    to_session: Mutex<Option<Arc<Messages>>>,
}

#[derive(Default)]
struct Outbound {
    channel: Option<u64>,
    held: HeldInputs,
    draining: bool,
    closed: bool,
}

#[derive(Default)]
struct HeldInputs {
    head: Option<Box<HeldInput>>,
    len: usize,
}

struct HeldInput {
    input: (Vec<u8>, bool, Custody),
    next: Option<Box<HeldInput>>,
}

impl HeldInputs {
    fn len(&self) -> usize {
        self.len
    }
    fn is_empty(&self) -> bool {
        self.len == 0
    }
    fn push_back(&mut self, input: (Vec<u8>, bool, Custody)) {
        let mut tail = &mut self.head;
        while let Some(node) = tail {
            tail = &mut node.next;
        }
        *tail = Some(Box::new(HeldInput { input, next: None }));
        self.len += 1;
    }
    fn pop_front(&mut self) -> Option<(Vec<u8>, bool, Custody)> {
        let HeldInput { input, next } = *self.head.take()?;
        self.head = next;
        self.len -= 1;
        Some(input)
    }
}

impl Drop for HeldInputs {
    fn drop(&mut self) {
        while self.pop_front().is_some() {}
    }
}

struct Draining(Arc<CallerLeg>);

struct CallerPublication<'a> {
    leg: &'a CallerLeg,
    producer: Option<busbar_core_connector::publication::ProducerCustody>,
    custody: Option<Custody>,
    activity: Option<busbar_core_connector::publication::Transfer>,
}

impl Drop for CallerPublication<'_> {
    fn drop(&mut self) {
        drop(self.producer.take());
        drop(self.custody.take());
        drop(self.activity.take());
        let id = *lock(&self.leg.id);
        if let Some((door, id)) = self.leg.door.upgrade().zip(id) {
            door.assocs.published(id);
        }
    }
}

impl Drop for Draining {
    fn drop(&mut self) {
        let (unfinished, closed) = {
            let mut out = lock(&self.0.outbound);
            (std::mem::take(&mut out.draining), out.closed)
        };
        if closed {
            return;
        }
        if unfinished {
            self.0.failed();
        } else {
            self.0.released.notify_waiters();
        }
    }
}

impl CallerLeg {
    fn new(door: &Arc<ClaimDoor>, to_session: Arc<Messages>) -> Arc<Self> {
        Arc::new_cyclic(|me| CallerLeg {
            me: me.clone(),
            door: Arc::downgrade(door),
            id: Mutex::new(None),
            pairing: Mutex::new(None),
            outbound: Mutex::new(Outbound::default()),
            writes: tokio::sync::Semaphore::new(1),
            released: Notify::new(),
            to_session: Mutex::new(Some(to_session)),
        })
    }

    fn bind(&self, id: u64) {
        *lock(&self.id) = Some(id);
    }

    /// What the association yielded: through the pairing (its lines go across), then its channels'
    /// heads name the session's channel and their messages go to the session.
    fn yielded(self: &Arc<Self>, pieces: Vec<Got>, now: Instant) {
        self.yielded_batch(
            busbar_core_connector::framer::Yielded {
                pieces,
                ..Default::default()
            },
            now,
        );
    }

    fn yielded_batch(
        self: &Arc<Self>,
        yielded: busbar_core_connector::framer::Yielded,
        now: Instant,
    ) {
        let Some(pairing) = lock(&self.pairing).clone() else {
            self.failed();
            return;
        };
        let session = pairing.publish(Leg::Caller, yielded, now);
        if self.take_batch(session, now).is_err() {
            self.failed();
        }
    }

    fn take(self: &Arc<Self>, session: Vec<Got>, _now: Instant) {
        if self
            .take_batch(
                SessionBatch {
                    pieces: session,
                    custody: Custody::default(),
                    owners: Vec::new(),
                    producer: busbar_core_connector::publication::ProducerCustody::default(),
                },
                _now,
            )
            .is_err()
        {
            self.failed();
        }
    }

    fn take_batch(&self, session: SessionBatch, _now: Instant) -> Result<(), String> {
        let SessionBatch {
            pieces,
            custody,
            owners,
            producer,
        } = session;
        let activity = custody.publishing();
        let _publication = CallerPublication {
            leg: self,
            producer: Some(producer),
            custody: Some(custody),
            activity: Some(activity),
        };
        let fallback = _publication
            .custody
            .as_ref()
            .expect("publication owns its container")
            .clone();
        let mut owners = owners.into_iter();
        for g in pieces {
            let owner = owners.next().unwrap_or_else(|| fallback.clone());
            if g.fields {
                let release = {
                    let mut out = lock(&self.outbound);
                    if out.closed || out.channel.is_some() {
                        false
                    } else {
                        out.channel = Some(g.stream);
                        out.draining = !out.held.is_empty();
                        out.draining
                    }
                };
                if release {
                    match self.door.upgrade() {
                        Some(door) => {
                            let leg = self.me.upgrade();
                            if let Some(leg) = leg {
                                door.spawn(leg.release());
                            } else {
                                drop(g);
                                drop(owner);
                                return Err("the caller leg was not joined".into());
                            }
                        }
                        None => self.failed(),
                    }
                }
                drop(g);
                drop(owner);
                continue;
            }
            if g.failed && g.stream != 0 {
                drop(g);
                drop(owner);
                return Err("the caller's channel failed".into());
            }
            if g.stream == 0 || g.ends_stream() {
                drop(g);
                drop(owner);
                continue;
            }
            drop(g.reason);
            let to_session = lock(&self.to_session).clone();
            let sent = to_session.is_some_and(|tx| {
                tx.send(Message {
                    bytes: g.bytes,
                    end: g.end_of_frame,
                    consumed: 0,
                    custody: owner.reader_on(Leg::Caller),
                })
                .is_ok()
            });
            if !sent {
                // A plane that does not keep up with its caller ends the session.
                return Err("the caller's channel reader did not accept its output".into());
            }
        }
        Ok(())
    }

    /// Drain accepted early messages before later writers; no host lock crosses the framer
    /// or the pairing's callbacks.
    fn release(self: Arc<Self>) -> impl std::future::Future<Output = ()> + Send + 'static {
        let guard = Draining(self);
        let shutdown = guard
            .0
            .door
            .upgrade()
            .and_then(|door| door.shutdown.clone());
        async move {
            let draining = guard;
            tokio::select! {
                biased;
                () = detached::shutdown_fired(shutdown) => {},
                () = draining.0.release_held() => {},
            }
        }
    }

    async fn release_held(&self) {
        loop {
            let next = {
                let mut out = lock(&self.outbound);
                match out.held.pop_front() {
                    Some((bytes, text, custody)) => Some((
                        out.channel.expect("draining a channel"),
                        bytes,
                        text,
                        custody,
                    )),
                    None => {
                        out.draining = false;
                        None
                    }
                }
            };
            let Some((channel, bytes, text, custody)) = next else {
                return;
            };
            let pairing = lock(&self.pairing).clone();
            let sent = match pairing {
                Some(pairing) => {
                    let preaccepted = bytes.len();
                    let accepted = pairing
                        .submit_preaccepted_owned(
                            Leg::Caller,
                            Across {
                                stream: channel,
                                bytes,
                                end_of_frame: true,
                            },
                            text,
                            custody,
                            preaccepted,
                            None,
                        )
                        .is_ok();
                    accepted && pairing.published().await.failure.is_none() && !pairing.closed()
                }
                None => false,
            };
            if !sent {
                self.failed();
                return;
            }
        }
    }

    /// One piece toward the caller, on the session's channel.
    async fn write(&self, bytes: &[u8], text: bool) -> bool {
        let Ok(_order) = self.writes.acquire().await else {
            return false;
        };
        let pairing = lock(&self.pairing).clone();
        let Some(pairing) = pairing else {
            return false;
        };
        loop {
            let released = self.released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            enum Next {
                Closed,
                Full,
                Early,
                Ready(u64),
                Draining,
            }
            let next = {
                let out = lock(&self.outbound);
                if out.closed {
                    Next::Closed
                } else if out.channel.is_none() && out.held.len() == CALLER_QUEUE {
                    Next::Full
                } else if out.channel.is_none() {
                    Next::Early
                } else if out.draining {
                    Next::Draining
                } else {
                    Next::Ready(out.channel.expect("the channel was selected"))
                }
            };
            match next {
                Next::Closed => return false,
                Next::Full => {
                    self.failed();
                    return false;
                }
                Next::Early => {
                    let Some(capacity) = bytes.len().checked_add(std::mem::size_of::<HeldInput>())
                    else {
                        self.failed();
                        return false;
                    };
                    let Ok(credit) = pairing.input_credit_for(Leg::Caller, capacity).await else {
                        return false;
                    };
                    let mut credit = Some(credit);
                    let accepted = {
                        let mut out = lock(&self.outbound);
                        if out.closed {
                            return false;
                        }
                        if out.channel.is_none() {
                            if !pairing.retain_input(bytes.len()) {
                                return false;
                            }
                            out.held.push_back((
                                bytes.to_vec(),
                                text,
                                credit.take().expect("reserved input"),
                            ));
                            true
                        } else {
                            false
                        }
                    };
                    drop(credit);
                    if accepted {
                        return true;
                    }
                }
                Next::Ready(channel) => {
                    let id = *lock(&self.id);
                    let Some((door, id)) = self.door.upgrade().zip(id) else {
                        return false;
                    };
                    let Some(_admission) = door.assocs.emission_ready(id).await else {
                        return false;
                    };
                    return pairing.send(Leg::Caller, channel, bytes, text).await;
                }
                Next::Draining => released.await,
            }
        }
    }

    /// The association failed or the plane fell behind: the session's pairing closes, this leg
    /// with it.
    fn failed(&self) {
        let pairing = lock(&self.pairing).clone();
        match pairing {
            Some(p) => p.close(),
            None => self.close(),
        }
    }
}

impl LegSink for CallerLeg {
    fn poll_line(
        &self,
        cx: &mut std::task::Context<'_>,
        input: Option<&Across>,
        text: bool,
        now: Instant,
    ) -> std::task::Poll<Result<LineStep, busbar_core_connector::framer::Refused>> {
        let id = *lock(&self.id);
        match (self.door.upgrade(), id) {
            (Some(door), Some(id)) => {
                let result = door
                    .assocs
                    .poll_line(id, cx, input, text, now, &|to, bytes| door.send(to, bytes));
                door.joined.notify_one();
                result
            }
            _ => std::task::Poll::Ready(Err(busbar_core_connector::framer::Refused {
                outcome: busbar_contract::abi::mechanism::call::Outcome::Failed,
                error: "the caller leg is closed".into(),
            })),
        }
    }

    fn pairing(&self) -> Option<Arc<Pairing>> {
        lock(&self.pairing).clone()
    }

    fn channels(&self, batch: SessionBatch, now: Instant) -> Result<(), String> {
        self.take_batch(batch, now)
    }

    fn schedule(&self, task: PublicationTask) -> bool {
        let Some(door) = self.door.upgrade() else {
            return false;
        };
        let shutdown = door.shutdown.clone();
        door.spawn(async move {
            tokio::select! {
                biased;
                () = detached::shutdown_fired(shutdown) => {},
                () = task => {},
            }
        });
        true
    }

    fn line(&self, across: Across, now: Instant) {
        let _ = now;
        let pairing = lock(&self.pairing).clone();
        let Some(pairing) = pairing else {
            self.close();
            return;
        };
        match pairing.reserve_input_for(Leg::Caller, across.bytes.capacity()) {
            Ok(custody) => {
                let _ = pairing.submit_owned(Leg::Caller, across, false, custody);
            }
            Err(_) => self.failed(),
        }
    }

    fn close(&self) {
        let abandoned = {
            let mut out = lock(&self.outbound);
            if out.closed {
                return;
            }
            out.closed = true;
            out.draining = false;
            std::mem::take(&mut out.held)
        };
        let mut abandoned = abandoned;
        let mut cancelled = 0;
        while let Some((bytes, _, custody)) = abandoned.pop_front() {
            cancelled += bytes.len();
            drop(bytes);
            drop(custody);
        }
        if cancelled != 0 {
            if let Some(pairing) = lock(&self.pairing).clone() {
                pairing.cancel_retained_input(cancelled);
            }
        }
        self.writes.close();
        self.released.notify_waiters();
        let to_session = lock(&self.to_session).take();
        if let Some(to_session) = &to_session {
            to_session.close();
        }
        drop(to_session);
        let id = lock(&self.id).take();
        if let (Some(door), Some(id)) = (self.door.upgrade(), id) {
            door.leave(id);
        }
    }
}

/// THE CALLER'S SIDE OF A DATAGRAM SESSION (K6's one `SessionCaller`): its pieces are the
/// association's channel messages; every piece the plane writes is one message on that channel.
/// The plane's head is kept for the unit's answer.
pub(super) struct DatagramCaller {
    leg: Arc<CallerLeg>,
    from: Arc<Messages>,
    head: Mutex<Option<oneshot::Sender<(u32, HeadFields)>>>,
    stated: std::sync::atomic::AtomicU32,
    /// The session's opening piece was read: the association's open, one empty piece before the
    /// caller's first message, so the plane crosses the session once before the open is answered
    /// (the open waits for the head that crossing states).
    opened: std::sync::atomic::AtomicBool,
}

/// THE PLANE'S HEAD for a datagram session's open: the head the plane states on its session's first
/// crossing, waited for within `wait`; `None` when it states none in time (or the session ended
/// without one).
pub(super) async fn plane_head(
    head: oneshot::Receiver<(u32, HeadFields)>,
    wait: std::time::Duration,
) -> Option<(u32, HeadFields)> {
    tokio::time::timeout(wait, head).await.ok()?.ok()
}

impl CallerEnd for DatagramCaller {
    fn head(&self, status: u32, fields: HeadFields) {
        self.stated
            .store(status, std::sync::atomic::Ordering::Release);
        if let Some(tx) = lock(&self.head).take() {
            let _ = tx.send((status, fields));
        }
    }

    async fn write(&self, bytes: &[u8]) -> bool {
        self.leg.write(bytes, false).await
    }

    async fn write_text(&self, bytes: &[u8]) -> bool {
        self.leg.write(bytes, true).await
    }
}

impl SessionCaller for DatagramCaller {
    async fn read(&self) -> Option<Vec<u8>> {
        if !self.opened.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return Some(Vec::new());
        }
        self.from.recv().await.map(|message| message.bytes)
    }

    async fn read_owned(&self) -> Option<busbar_kernel::plane_driver::SessionInput> {
        if !self.opened.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return Some(busbar_kernel::plane_driver::SessionInput {
                bytes: Vec::new(),
                custody: None,
            });
        }
        let message = self.from.recv().await?;
        Some(busbar_kernel::plane_driver::SessionInput {
            bytes: message.bytes,
            custody: Some(Arc::new(message.custody)),
        })
    }
}

impl Stated for DatagramCaller {
    fn stated(&self) -> Option<u32> {
        Some(self.stated.load(std::sync::atomic::Ordering::Acquire)).filter(|s| *s != 0)
    }
}

/// ONE DATAGRAM SESSION'S OPENING, before its unit is admitted: the accepting association over the
/// claim door, settled by the far end's description; its own description (the unit's answer body),
/// the session's caller side, and what joins the door once the unit is admitted ([`Joining`]).
pub(super) struct Opened {
    /// The framer's own description: the unit's answer body.
    pub(super) description: Description,
    /// The session's caller side.
    pub(super) caller: DatagramCaller,
    /// The plane's head, once it states one.
    pub(super) head: oneshot::Receiver<(u32, HeadFields)>,
    /// What joins the door once the unit is admitted.
    pub(super) joining: Joining,
}

pub(super) struct Description {
    bytes: Vec<u8>,
    _custody: Custody,
}

impl Description {
    pub(super) fn into_body(self) -> axum::body::Body {
        struct Delivered {
            bytes: Vec<u8>,
            _custody: busbar_core_connector::publication::ReaderCustody,
            _transfer: busbar_core_connector::publication::Transfer,
        }
        impl AsRef<[u8]> for Delivered {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        // This becomes an independent HTTP transfer only after the plane's opening head is
        // available. Before then its allocation remains charged without promising progress.
        let custody = self._custody.reader();
        let transfer = custody.copying();
        axum::body::Body::from(bytes::Bytes::from_owner(Delivered {
            bytes: self.bytes,
            _custody: custody,
            _transfer: transfer,
        }))
    }
}

/// AN ASSOCIATION NOT YET ON ITS DOOR: it joins only once its unit is admitted (an association
/// exists only for a unit admitted at the description's accept). Dropped unjoined, its framing
/// finishes and nothing was ever registered.
pub(super) struct Joining {
    door: Arc<ClaimDoor>,
    framing: DatagramFraming,
    leg: Arc<CallerLeg>,
    pairing: Arc<Pairing>,
}

impl Opened {
    /// Open over `door`: the association `framer` answers, settled by the far end's `description`.
    ///
    /// # Errors
    ///
    /// The framer refused the far end's description (it does not parse, or settles no terms):
    /// the unit is refused before it is admitted.
    pub(super) fn open(
        door: &Arc<ClaimDoor>,
        framer: Arc<dyn busbar_core_connector::framer::FramerDoor>,
        description: &[u8],
    ) -> Result<Self, String> {
        let (mut framing, _) =
            DatagramFraming::accept_minted(framer, door.local()).map_err(|r| r.error)?;
        let from = Messages::new(CALLER_QUEUE);
        let to_session = Arc::clone(&from);
        let leg = CallerLeg::new(door, to_session);
        let limit = busbar_kernel::config::limits::installed()
            .and_then(|limits| limits.datagram_line_memory_bytes);
        let pairing =
            Pairing::with_memory_limit(Arc::clone(&leg) as Arc<dyn LegSink>, door.local(), limit);
        *lock(&leg.pairing) = Some(Arc::clone(&pairing));
        let prepared = (|| {
            framing.memory(pairing.memory_account());
            let now = Instant::now();
            let yielded = framing.rendezvous(description, now).map_err(|r| r.error)?;
            let mut session = pairing.publish(Leg::Caller, yielded, now);
            let index = session
                .pieces
                .iter()
                .position(|piece| piece.stream == 0 && !piece.fields)
                .ok_or("the framer answered no description of its own")?;
            let answer = session.pieces.remove(index).bytes;
            let custody = if index < session.owners.len() {
                session.owners.remove(index)
            } else {
                session.custody.clone()
            };
            // Bytes owns the original allocation and reservation through actual HTTP-body
            // consumption; no uncharged clone of the opening description is made.
            let answer = Description {
                bytes: answer,
                _custody: custody,
            };
            leg.take_batch(session, now)?;
            let (head_tx, head) = oneshot::channel();
            Ok(Opened {
                description: answer,
                caller: DatagramCaller {
                    leg: Arc::clone(&leg),
                    from,
                    head: Mutex::new(Some(head_tx)),
                    stated: std::sync::atomic::AtomicU32::new(0),
                    opened: std::sync::atomic::AtomicBool::new(false),
                },
                head,
                joining: Joining {
                    door: Arc::clone(door),
                    framing,
                    leg,
                    pairing: Arc::clone(&pairing),
                },
            })
        })();
        if prepared.is_err() {
            pairing.close();
        }
        prepared
    }
}

impl Joining {
    /// The unit was admitted: the association joins the claim door, and the session's pairing is
    /// registered under `unit` in the connector's session book before the session runs.
    ///
    /// # Errors
    ///
    /// The door refused the association (its user name is another's), or the book the unit; the
    /// pairing is closed either way.
    pub(super) fn admit(self, unit: u64) -> Result<(), String> {
        let Joining {
            door,
            framing,
            leg,
            pairing,
        } = self;
        if let Err(e) = door.join(framing, &leg) {
            pairing.close();
            return Err(format!("the claim door refused the association: {e:?}"));
        }
        crate::root::connector::the()
            .pair(unit, Arc::clone(&pairing))
            .map_err(|e| {
                pairing.close();
                format!("the session book refused the unit: {e:?}")
            })
    }
}

#[cfg(test)]
#[path = "tests/serve_datagram.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/datagram_line_budget.rs"]
mod line_budget_tests;

#[cfg(test)]
#[path = "tests/raw_udp_ingress.rs"]
mod raw_udp_ingress_tests;
