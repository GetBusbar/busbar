// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

const CALLER_QUEUE: usize = 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// THE CLAIM DOORS, by the claim their datagram framer answers: each one bound port.
#[derive(Debug, Default, Clone)]
pub struct ClaimDoors(HashMap<String, Arc<ClaimDoor>>);

impl ClaimDoors {
    pub fn insert(&mut self, claim: &str, door: Arc<ClaimDoor>) {
        self.0.insert(claim.to_owned(), door);
    }

    #[must_use]
    pub fn get(&self, claim: &str) -> Option<Arc<ClaimDoor>> {
        self.0.get(claim).cloned()
    }

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

pub struct ClaimDoor {
    port: ReadyPort,
    runtime: tokio::runtime::Handle,
    detached: Option<Arc<DetachedTasks>>,
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    closed: AtomicBool,
    assocs: PortAssociations,
    legs: Mutex<HashMap<u64, Arc<CallerLeg>>>,

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

    #[must_use]
    pub fn local(&self) -> SocketAddr {
        self.port.local_addr()
    }

    fn send(&self, to: SocketAddr, d: &[u8]) {
        let _ = self.port.send_to(d, to);
    }

    fn answer(&self, answered: Answered, now: Instant) {
        for (id, answer) in answered {
            let leg = lock(&self.legs).get(&id).cloned();
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

                Woke::Read(Err(_)) => Vec::new(),
                Woke::Joined => Vec::new(),
                Woke::Clock => self
                    .assocs
                    .timeout_incremental(now, &|to, d| self.send(to, d)),
            };
            self.answer(answered, now);
        }
    }

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

        if self.closed.load(Ordering::Acquire) {
            leg.failed();
        }
        self.joined.notify_one();
        Ok(id)
    }

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

    fn leave(&self, id: u64) {
        let gone = lock(&self.legs).remove(&id);
        self.assocs.remove(id);
        drop(gone);
    }
}

pub struct CallerLeg {
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

    fn yielded(self: &Arc<Self>, pieces: Vec<Got>, now: Instant) {
        let mut yielded = busbar_core_connector::framer::Yielded::default();
        yielded.pieces = pieces;
        self.yielded_batch(yielded, now);
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
                return Err("the caller's channel reader did not accept its output".into());
            }
        }
        Ok(())
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

pub(super) struct Opened {
    pub(super) description: Description,

    pub(super) caller: DatagramCaller,

    pub(super) head: oneshot::Receiver<(u32, HeadFields)>,

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

        let custody = self._custody.reader();
        let transfer = custody.copying();
        axum::body::Body::from(bytes::Bytes::from_owner(Delivered {
            bytes: self.bytes,
            _custody: custody,
            _transfer: transfer,
        }))
    }
}

pub(super) struct Joining {
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
        let pairing = OpeningPairing {
            pairing,
            admitted: false,
        };
        *lock(&leg.pairing) = Some(Arc::clone(&pairing.pairing));
        framing.memory(pairing.pairing.memory_account());
        let now = Instant::now();
        let yielded = framing.rendezvous(description, now).map_err(|r| r.error)?;
        let mut session = pairing.pairing.publish(Leg::Caller, yielded, now);
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
            return Err(format!("the claim door refused the association: {e:?}"));
        }
        connector
            .pair(unit, Arc::clone(&pairing.pairing))
            .map_err(|e| format!("the session book refused the unit: {e:?}"))?;
        pairing.admitted = true;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/serve_datagram.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "tests/datagram_opening_retirement.rs"]
mod opening_retirement_tests;

#[cfg(test)]
#[path = "tests/datagram_line_budget.rs"]
mod line_budget_tests;

#[cfg(test)]
#[path = "tests/raw_udp_ingress.rs"]
mod raw_udp_ingress_tests;
