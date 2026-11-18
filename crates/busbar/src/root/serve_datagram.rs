// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use foldhash::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Instant;

use busbar_core_connector::datagram::{
    Across, Answered, DatagramFraming, Leg, LegSink, LineStep, Pairing, PortAssociations,
    PublicationTask, SessionBatch,
};
#[cfg(test)]
use busbar_core_connector::framer::Got;
use busbar_core_connector::framer::{instant_of, now_ns};
use busbar_core_connector::publication::{Custody, Message, Messages};
use busbar_core_connector::udp::{ReadyPort, MAX_DATAGRAM};
use busbar_kernel::detached::{self, DetachedTasks};
use busbar_kernel::limits::process_admission::RequestLease;
use busbar_kernel::plane_driver::{CallerEnd, HeadFields, SessionCaller};
use tokio::sync::{oneshot, Notify};

use super::Stated;

const CALLER_QUEUE: usize = 1024;

/// Fixed host limits, shared across listener generations; these are not configuration keys.
const DATAGRAM_ASSOCIATIONS_GLOBAL: usize = 1024;
const DATAGRAM_ASSOCIATIONS_PER_CLAIM: usize = 64;
const DATAGRAM_ASSOCIATION_LIFETIME: std::time::Duration = std::time::Duration::from_secs(300);
static DATAGRAM_CAPACITY: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| {
        Arc::new(tokio::sync::Semaphore::new(DATAGRAM_ASSOCIATIONS_GLOBAL))
    });

struct AssociationLease {
    _global: tokio::sync::OwnedSemaphorePermit,
    _claim: tokio::sync::OwnedSemaphorePermit,
    expires: Instant,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// THE CLAIM DOORS, by the claim their datagram framer answers: each one bound port.
#[derive(Debug, Default, Clone)]
pub(crate) struct ClaimDoors(pub(in crate::root) HashMap<String, Arc<ClaimDoor>>);

impl ClaimDoors {
    #[must_use]
    pub(crate) fn get(&self, claim: &str) -> Option<Arc<ClaimDoor>> {
        self.0.get(claim).cloned()
    }
}

/// What woke the port loop: a datagram read into its buffer (its length and sender), the
/// associations' deadline, or a joined association.
enum Woke {
    Read(std::io::Result<(usize, SocketAddr)>),
    Clock,
    Joined,
}

pub(crate) struct ClaimDoor {
    capacity: Arc<tokio::sync::Semaphore>,
    port: ReadyPort,
    runtime: tokio::runtime::Handle,
    detached: Option<Arc<DetachedTasks>>,
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    closed: AtomicBool,
    assocs: PortAssociations,
    legs: Mutex<HashMap<u64, Arc<CallerLeg>>>,
    /// The legs one wake found expired, kept so the next wake reuses its room.
    expiring: Mutex<Vec<Arc<CallerLeg>>>,

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
    #[must_use]
    pub(crate) fn serve(port: ReadyPort) -> Arc<Self> {
        let door = Arc::new(ClaimDoor {
            capacity: Arc::new(tokio::sync::Semaphore::new(DATAGRAM_ASSOCIATIONS_PER_CLAIM)),
            port,
            runtime: tokio::runtime::Handle::current(),
            detached: detached::worker_detached(),
            shutdown: detached::worker_shutdown(),
            closed: AtomicBool::new(false),
            assocs: PortAssociations::new(),
            legs: Mutex::new(HashMap::default()),
            expiring: Mutex::new(Vec::new()),
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

    #[must_use]
    pub(crate) fn local(&self) -> SocketAddr {
        self.port.local_addr()
    }

    fn send(&self, to: SocketAddr, d: &[u8]) {
        let _ = self.port.send_to(d, to);
    }

    fn answer(&self, answered: Answered, now: Instant) {
        for (id, answer) in answered {
            let leg = lock(&self.legs).get(&id).cloned();
            match &answer {
                Ok(yielded) => tracing::trace!(
                    leg_present = leg.is_some(),
                    pieces = yielded.pieces.len(),
                    field_pieces = yielded.pieces.iter().filter(|piece| piece.fields).count(),
                    continuing = yielded.continuing,
                    "datagram caller admission yielded"
                ),
                Err(error) => tracing::debug!(
                    leg_present = leg.is_some(),
                    outcome = ?error.outcome,
                    "datagram caller admission failed"
                ),
            }
            match (leg, answer) {
                (Some(leg), Ok(y)) => leg.yielded_batch(y, now),
                (Some(leg), Err(_)) => leg.failed(),
                (None, Ok(yielded)) => {
                    if let Some(pairing) = yielded.producer.pairing() {
                        pairing.close();

                        let _cancelled = pairing.publish(Leg::Caller, yielded, now);
                    }
                }
                (None, _) => {}
            }
        }
    }

    fn run(self: Arc<Self>) -> impl std::future::Future<Output = ()> + Send + 'static {
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
            let deadline = self
                .assocs
                .deadline()
                .into_iter()
                .chain(
                    lock(&self.legs)
                        .values()
                        .filter_map(|leg| lock(&leg.lease).as_ref().map(|lease| lease.expires)),
                )
                .min();
            let read = std::future::poll_fn(|cx| self.port.poll_recv_from(cx, &mut buf));
            let sleep = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                    None => std::future::pending::<()>().await,
                }
            };
            let woke = tokio::select! {
                () = &mut shutdown => return,
                got = read => Woke::Read(got),
                () = sleep => Woke::Clock,
                () = self.joined.notified() => Woke::Joined,
            };
            self.woke(&woke, &buf);
        }
    }

    /// One wake of the port loop, judged at one clock reading. A read datagram is served straight
    /// from the loop's receive buffer.
    fn woke(&self, woke: &Woke, buf: &[u8]) {
        let now = instant_of(now_ns());
        self.expire(now);
        let answered = match woke {
            Woke::Read(Ok((n, from))) => self
                .assocs
                .raw_datagram_with_publication(
                    *from,
                    &buf[..*n],
                    now,
                    &|to, d| self.send(to, d),
                    |answered| self.answer(answered, now),
                )
                .into_answered(),

            Woke::Read(Err(_)) => Vec::new(),
            Woke::Joined => Vec::new(),
            Woke::Clock => self
                .assocs
                .timeout_incremental(now, &|to, d| self.send(to, d)),
        };
        self.answer(answered, now);
    }

    fn join(
        &self,
        mut framing: DatagramFraming,
        leg: &Arc<CallerLeg>,
    ) -> Result<u64, busbar_core_connector::datagram::NotAdded> {
        self.reserve(leg)?;
        if let Some(pairing) = lock(&leg.pairing).as_ref() {
            framing.memory(pairing.memory_account());
        }
        let added = self.assocs.add_with(framing, |id| {
            leg.bind(id);
            lock(&self.legs).insert(id, Arc::clone(leg));
        });
        let id = match added {
            Ok(id) => id,
            Err(error) => {
                lock(&leg.lease).take();
                return Err(error);
            }
        };

        if self.closed.load(Ordering::Acquire) || lock(&leg.outbound).closed {
            leg.failed();
            self.leave(id);
            lock(&leg.lease).take();
            return Err(busbar_core_connector::datagram::NotAdded::Capacity);
        }
        self.joined.notify_one();
        Ok(id)
    }

    fn reserve(&self, leg: &CallerLeg) -> Result<(), busbar_core_connector::datagram::NotAdded> {
        use busbar_core_connector::datagram::NotAdded;
        let mut lease = lock(&leg.lease);
        if self.closed.load(Ordering::Acquire) || lease.is_some() {
            return Err(NotAdded::Capacity);
        }
        let global = Arc::clone(&DATAGRAM_CAPACITY)
            .try_acquire_owned()
            .map_err(|_| NotAdded::Capacity)?;
        let claim = Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_| NotAdded::Capacity)?;
        *lease = Some(AssociationLease {
            _global: global,
            _claim: claim,
            expires: Instant::now() + DATAGRAM_ASSOCIATION_LIFETIME,
        });
        Ok(())
    }

    fn expire(&self, now: Instant) {
        let mut expired = std::mem::take(&mut *lock(&self.expiring));
        expired.extend(
            lock(&self.legs)
                .values()
                .filter(|leg| {
                    lock(&leg.lease)
                        .as_ref()
                        .is_some_and(|lease| lease.expires <= now)
                })
                .cloned(),
        );
        for leg in expired.drain(..) {
            leg.failed();
        }
        *lock(&self.expiring) = expired;
    }

    fn leave(&self, id: u64) {
        let gone = lock(&self.legs).remove(&id);
        self.assocs.remove(id);
        drop(gone);
    }
}

pub(crate) struct CallerLeg {
    request: RequestLease,
    lease: Mutex<Option<AssociationLease>>,
    me: Weak<CallerLeg>,
    door: Weak<ClaimDoor>,
    id: Mutex<Option<u64>>,
    pairing: Mutex<Option<Arc<Pairing>>>,

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
    fn new(door: &Arc<ClaimDoor>, to_session: Arc<Messages>, request: RequestLease) -> Arc<Self> {
        Arc::new_cyclic(|me| CallerLeg {
            request,
            lease: Mutex::new(None),
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

    #[cfg(test)]
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

    fn take_batch(&self, session: SessionBatch, now: Instant) -> Result<(), String> {
        self.take_batch_keeping(session, now, None).map(drop)
    }

    /// Retain decoded caller payload only after obtaining its process credit. The kept opening
    /// description and queued messages inherit the same admitted request as this logical line.
    fn take_batch_keeping(
        &self,
        session: SessionBatch,
        _now: Instant,
        keep: Option<usize>,
    ) -> Result<Option<Description>, String> {
        let SessionBatch {
            pieces,
            custody,
            owners,
            producer,
        } = session;
        let mut kept = None;
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
        for (at, g) in pieces.into_iter().enumerate() {
            let owner = owners.next().unwrap_or_else(|| fallback.clone());
            if keep == Some(at) {
                let credit = self
                    .request
                    .try_reserve(g.bytes.len())
                    .map_err(|_| "the gateway is at input capacity".to_owned())?;
                let custody = owner
                    .reader_on(Leg::Caller)
                    .with_owner(Arc::new(credit))
                    .map_err(|_| "the caller's input already has an owner".to_owned())?;
                kept = Some(Description {
                    bytes: busbar_contract::secure::SecureVec::from(g.bytes),
                    custody,
                });
                continue;
            }
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
            let credit = self
                .request
                .try_reserve(g.bytes.len())
                .map_err(|_| "the gateway is at input capacity".to_owned())?;
            let custody = owner
                .reader_on(Leg::Caller)
                .with_owner(Arc::new(credit))
                .map_err(|_| "the caller's input already has an owner".to_owned())?;
            let to_session = lock(&self.to_session).clone();
            let message = Message {
                bytes: g.bytes,
                end: g.end_of_frame,
                consumed: 0,
                custody,
            };
            let sent = match to_session {
                Some(tx) => tx.send(message).is_ok(),
                None => {
                    drop(message);
                    false
                }
            };
            if !sent {
                return Err("the caller's channel reader did not accept its output".into());
            }
        }
        Ok(kept)
    }

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
                } else {
                    match out.channel {
                        None if out.held.len() == CALLER_QUEUE => Next::Full,
                        None => Next::Early,
                        Some(_) if out.draining => Next::Draining,
                        Some(channel) => Next::Ready(channel),
                    }
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
                                crate::root::cold::early_input(bytes),
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
        lock(&self.lease).take();
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

pub(super) struct DatagramCaller {
    leg: Arc<CallerLeg>,
    from: Arc<Messages>,
    head: Mutex<Option<oneshot::Sender<(u32, HeadFields)>>>,
    stated: std::sync::atomic::AtomicU32,

    opened: std::sync::atomic::AtomicBool,
}

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
    /// Budgeted input must be consumed through read_owned, retaining its payload custody.
    async fn read(&self) -> Option<Vec<u8>> {
        None
    }

    async fn read_owned(&self) -> Option<busbar_kernel::plane_driver::SessionInput> {
        if !self.opened.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return Some(busbar_kernel::plane_driver::SessionInput {
                bytes: Vec::new(),
                custody: Some(Arc::new(self.leg.request.clone())),
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

pub(super) struct Opened {
    pub(super) description: Description,

    pub(super) caller: DatagramCaller,

    pub(super) head: oneshot::Receiver<(u32, HeadFields)>,

    pub(super) joining: Joining,
}

pub(super) struct Description {
    bytes: busbar_contract::secure::SecureVec,
    custody: busbar_core_connector::publication::ReaderCustody,
}

impl Description {
    pub(super) fn into_bytes(self) -> bytes::Bytes {
        struct Delivered {
            bytes: busbar_contract::secure::SecureVec,
            _custody: busbar_core_connector::publication::ReaderCustody,
            _transfer: busbar_core_connector::publication::Transfer,
        }
        impl AsRef<[u8]> for Delivered {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        let Self { bytes, custody } = self;
        let transfer = custody.copying();
        bytes::Bytes::from_owner(Delivered {
            bytes,
            _custody: custody,
            _transfer: transfer,
        })
    }
}

pub(crate) struct Joining {
    door: Arc<ClaimDoor>,
    framing: DatagramFraming,
    leg: Arc<CallerLeg>,
    pairing: OpeningPairing,
}

struct OpeningPairing {
    pairing: Arc<Pairing>,
    admitted: bool,
}

impl Drop for OpeningPairing {
    fn drop(&mut self) {
        if !self.admitted {
            self.pairing.close();
        }
    }
}

impl Opened {
    pub(super) fn open(
        door: &Arc<ClaimDoor>,
        framer: Arc<dyn busbar_core_connector::framer::FramerDoor>,
        description: &[u8],
        request: RequestLease,
    ) -> Result<Self, String> {
        let (mut framing, _) =
            DatagramFraming::accept_minted(framer, door.local()).map_err(|r| r.error)?;
        let from = Messages::new(CALLER_QUEUE);
        let to_session = Arc::clone(&from);
        let leg = CallerLeg::new(door, to_session, request);
        let pairing = Pairing::new(Arc::clone(&leg) as Arc<dyn LegSink>, door.local());
        let pairing = OpeningPairing {
            pairing,
            admitted: false,
        };
        *lock(&leg.pairing) = Some(Arc::clone(&pairing.pairing));
        framing.memory(pairing.pairing.memory_account());
        let now = instant_of(now_ns());
        let yielded = framing.rendezvous(description, now).map_err(|r| r.error)?;
        let session = pairing.pairing.publish(Leg::Caller, yielded, now);
        let index = session
            .pieces
            .iter()
            .position(|piece| piece.stream == 0 && !piece.fields)
            .ok_or("the framer answered no description of its own")?;
        let answer = leg
            .take_batch_keeping(session, now, Some(index))?
            .ok_or("the framer answered no description of its own")?;
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
                pairing,
            },
        })
    }
}

impl Joining {
    pub(super) fn admit(self, unit: u64) -> Result<(), String> {
        self.admit_into(unit, crate::root::connector::the())
    }

    fn admit_into(
        self,
        unit: u64,
        connector: &busbar_core_connector::Connector,
    ) -> Result<(), String> {
        let Joining {
            door,
            framing,
            leg,
            mut pairing,
        } = self;
        if let Err(e) = door.join(framing, &leg) {
            return Err(crate::root::cold::association_refused(&e));
        }
        let paired = connector
            .pair(unit, Arc::clone(&pairing.pairing))
            .map_err(|e| crate::root::cold::session_book_refused(&e));
        paired?;
        pairing.admitted = true;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/serve_datagram.rs"]
mod tests;
