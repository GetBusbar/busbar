// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Store futures driven through the host ticket over ordinary or retained native connections.

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Waker};

use zeroize::{Zeroize, Zeroizing};

use super::op::{Checkout, Op, Step};
use crate::abi::mechanism::ticket::Ticket;
use crate::abi::sdk::conn::{ConnFailure, Host, ProcessId};

#[path = "wire_input.rs"]
mod input;
pub use input::{Drain, Input};

/// How much one read asks the connector for.
pub const READ_CHUNK: usize = 16 * 1024;

/// THE REFUSAL OF AN UPGRADE OVER UNREAD INPUT: the far end sent bytes in the clear that the body
pub const UPGRADE_OVER_UNREAD_INPUT: &str =
    "bytes the far end sent in the clear are still unread; the upgrade is refused";

/// How long an op waiting for a kept connection, or re-offering a write the connector had no
const RETRY_NS: u64 = 5_000_000;

// A fast native peer can keep every service Ready. Bound one ticketed crossing
// even then, including partial writes inside a single wire request.
const READY_UNITS_PER_ENTRY: usize = 32;

/// A store op's body, as [`drive`] runs it.
pub type Body<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// What the body asked the wire for, not yet answered.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ask {
    Connect {
        need: u32,
        target: Option<String>,
        timeout_ms: u32,
    },
    Reconnect,
    Close,
    Identity,
    CodecWait {
        yielded: bool,
    },
    Write,
    Read,
    Upgrade {
        name: Option<String>,
        verify_off: bool,
    },
}

/// Owned output never leaves a wiping owner, including while crossing into the host. Consumed
/// bytes stay initialized and are wiped in place: draining would leave a duplicate in the tail.
#[derive(Default)]
struct Output {
    bytes: Zeroizing<Vec<u8>>,
    done: usize,
}

impl Output {
    fn append(&mut self, bytes: &[u8]) {
        let len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .expect("wire output length");
        if len > self.bytes.capacity() {
            let mut next = Zeroizing::new(Vec::with_capacity(len));
            next.extend_from_slice(&self.bytes);
            self.bytes = next;
        }
        self.bytes.extend_from_slice(bytes);
        #[cfg(test)]
        sealed_tests::watch(&self.bytes);
    }

    fn remaining(&self) -> &[u8] {
        &self.bytes[self.done..]
    }

    fn consume(&mut self, n: usize) {
        let end = self.done + n.min(self.bytes.len() - self.done);
        self.bytes[self.done..end].zeroize();
        self.done = end;
        if self.done == self.bytes.len() {
            self.clear();
        }
    }

    fn clear(&mut self) {
        self.bytes.zeroize();
        self.done = 0;
    }
}

#[derive(Default)]
struct State {
    ask: Option<Ask>,
    answer: Option<Result<usize, ConnFailure>>,
    /// The connection: its need, target and stream.
    conn: Option<Checkout>,
    /// What the op connected to (need, target, dial timeout), for a reconnect.
    last: Option<(u32, Option<String>, u32)>,
    /// The connection came from the pool (established by an earlier op).
    reused: bool,
    /// A wire call failed on it, or the body discarded it: never kept.
    unfit: bool,
    /// What the body keeps with the connection.
    session: Option<Box<dyn Any + Send>>,
    /// [`Wire::bound`]'s milliseconds, and the host-clock instant they run out at once anchored.
    bound_ms: u32,
    bound_at: Option<u64>,
    /// Bytes the body wrote that the connector has not taken yet.
    out: Output,
    /// Bytes read that the body has not consumed yet.
    input: Input,
    /// What [`Wire::os_user`] read off the host.
    identity: Option<ProcessId>,
    /// The pending write carries a credential that goes out only secured: the host connector
    /// confirms the stream secured before it is written.
    confirm_secure: bool,
    /// The stream was found in the clear: a sealed write on it refuses on every re-entry.
    insecure: bool,
}

/// THE BODY'S WIRE: its one connection's services, each an `async` call [`drive`] answers.
#[derive(Clone, Default)]
pub struct Wire {
    st: Arc<Mutex<State>>,
}

impl std::fmt::Debug for Wire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wire").finish_non_exhaustive()
    }
}

impl Wire {
    fn state(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ask(&self, ask: Ask) -> Asked<'_> {
        Asked {
            wire: self,
            writing: matches!(ask, Ask::Write),
            pending: false,
            ask: Some(ask),
        }
    }

    /// The op's connection: declared need `need` to `target` (`None` = the need's own target), a
    pub async fn connect(&self, need: u32, target: Option<&str>) -> Result<(), ConnFailure> {
        self.connect_timed(need, target, 0).await
    }

    /// [`Wire::connect`], a new connection's dial bounded by `timeout_ms` (`0` = the need's own
    pub async fn connect_timed(
        &self,
        need: u32,
        target: Option<&str>,
        timeout_ms: u32,
    ) -> Result<(), ConnFailure> {
        self.ask(Ask::Connect {
            need,
            target: target.map(str::to_owned),
            timeout_ms,
        })
        .await
        .map(|_| ())
    }

    /// Close the connection (it is not fit for reuse) and establish a FRESH one for the same need
    pub async fn reconnect(&self) -> Result<(), ConnFailure> {
        self.ask(Ask::Reconnect).await.map(|_| ())
    }

    /// CLOSE the op's connection now: it is never kept, and its unread input and unsent output go.
    pub async fn close(&self) {
        let _ = self.ask(Ask::Close).await;
    }

    /// THE OS USER the process runs as, off the host's IDENTITY service: what a store presents
    pub async fn os_user(&self) -> Result<String, ConnFailure> {
        self.ask(Ask::Identity).await?;
        Ok(self
            .state()
            .identity
            .as_ref()
            .map(|i| i.os_user.clone())
            .unwrap_or_default())
    }

    /// Yield this operation to its host timer while a retained pure codec worker
    /// produces its next bounded result. Check the worker's result slot before
    /// calling this, then check it again after the yield. This performs no native
    /// I/O and does not run a worker or another executor inside the wire driver.
    pub async fn wait_codec(&self) -> Result<(), ConnFailure> {
        self.ask(Ask::CodecWait { yielded: false })
            .await
            .map(|_| ())
    }

    /// BOUND every wire call from the next one on by `ms` milliseconds in all (`0` = unbound): once
    pub fn bound(&self, ms: u32) {
        let mut st = self.state();
        st.bound_ms = ms;
        st.bound_at = None;
    }

    /// Lift [`Wire::bound`].
    pub fn unbound(&self) {
        self.bound(0);
    }

    /// Whether the connection was established by an earlier op and kept: its handshake is done.
    #[must_use]
    pub fn reused(&self) -> bool {
        self.state().reused
    }

    /// Never keep this connection: it is closed when the op answers (a protocol state the body
    pub fn discard(&self) {
        self.state().unfit = true;
    }

    /// Keep `session` with the connection (what the handshake learned), for the op that reuses it.
    pub fn set_session<S: Send + 'static>(&self, session: S) {
        self.state().session = Some(Box::new(session));
    }

    /// What an earlier op kept with this connection ([`Wire::set_session`]), if it is an `S`.
    pub fn session<S: Clone + 'static>(&self) -> Option<S> {
        self.state()
            .session
            .as_ref()
            .and_then(|s| s.downcast_ref::<S>())
            .cloned()
    }

    /// Write all of `bytes`.
    pub async fn write_all(&self, bytes: &[u8]) -> Result<(), ConnFailure> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.state().out.append(bytes);
        self.ask(Ask::Write).await.map(|_| ())
    }

    /// Write a whole credential message without exposing its bytes to the plugin. The host's
    pub async fn write_sealed(&self, seal: crate::abi::sdk::cred::Seal) -> Result<(), ConnFailure> {
        {
            let mut st = self.state();
            st.confirm_secure |= seal.secure_required();
            st.out.append(seal.wire());
        }
        drop(seal);
        self.ask(Ask::Write).await.map(|_| ())
    }

    /// Read more bytes onto the input ([`Wire::input`]): how many arrived; `0` = the far end
    pub async fn fill(&self) -> Result<usize, ConnFailure> {
        self.ask(Ask::Read).await
    }

    /// Secure the connection from its next byte on (TLS from the first byte, or after the
    pub async fn upgrade_secure(&self, name: Option<&str>) -> Result<(), ConnFailure> {
        self.upgrade(name, false).await
    }

    /// [`Wire::upgrade_secure`] WITHOUT verifying the far end's certificate: the operator's
    pub async fn upgrade_secure_unverified(&self, name: Option<&str>) -> Result<(), ConnFailure> {
        self.upgrade(name, true).await
    }

    /// The upgrade, asked of the connector only over an input the body consumed whole: bytes the
    async fn upgrade(&self, name: Option<&str>, verify_off: bool) -> Result<(), ConnFailure> {
        {
            let mut st = self.state();
            if !st.input.is_empty() {
                st.unfit = true;
                return Err(ConnFailure::Refused(UPGRADE_OVER_UNREAD_INPUT.into()));
            }
        }
        self.ask(Ask::Upgrade {
            name: name.map(str::to_owned),
            verify_off,
        })
        .await
        .map(|_| ())
    }

    /// Borrow unread bytes for parsing and consumption. [`Input`] keeps erasure under its owner:
    /// clearing, draining and growth cannot retire an unwiped vector allocation. Bytes yielded by
    /// a drain become the caller's responsibility; a dropped drain erases its unconsumed bytes.
    pub fn input<R>(&self, f: impl FnOnce(&mut Input) -> R) -> R {
        f(&mut self.state().input)
    }
}

/// One wire call: it posts its ask on the first poll and answers when [`drive`] has.
struct Asked<'w> {
    wire: &'w Wire,
    ask: Option<Ask>,
    writing: bool,
    pending: bool,
}

impl Future for Asked<'_> {
    type Output = Result<usize, ConnFailure>;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let mut st = self.wire.state();
        if let Some(ask) = self.ask.take() {
            self.pending = true;
            st.ask = Some(ask);
            st.answer = None;
            return Poll::Pending;
        }
        match st.answer.take() {
            Some(a) => {
                self.pending = false;
                Poll::Ready(a)
            }
            None => Poll::Pending,
        }
    }
}

impl Drop for Asked<'_> {
    fn drop(&mut self) {
        if self.writing && self.pending {
            let mut st = self.wire.state();
            st.out.clear();
            st.confirm_secure = false;
            st.unfit = true;
            st.ask = None;
            st.answer = None;
        }
    }
}

/// One idle kept connection.
struct Idle {
    conn: Checkout,
    session: Option<Box<dyn Any + Send>>,
}

#[derive(Default)]
struct PoolState {
    idle: Vec<Idle>,
    /// Established connections: idle plus held by an op.
    live: usize,
    /// Ops waiting for a connection, woken when one comes back.
    waiters: Vec<Weak<Waiter>>,
    /// The host tables the idle connections are closed through when the set goes.
    host: Option<Host>,
}

#[derive(Default)]
struct Waiter(Mutex<Option<(Host, Ticket)>>);

impl Waiter {
    fn wake(&self) {
        let wake = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some((host, ticket)) = wake {
            host.wake(ticket);
        }
    }
}

impl PoolState {
    fn wait(&mut self, waiter: &Arc<Waiter>, host: Host, ticket: Ticket) {
        *waiter.0.lock().unwrap_or_else(PoisonError::into_inner) = Some((host, ticket));
        let weak = Arc::downgrade(waiter);
        if !self.waiters.iter().any(|w| w.ptr_eq(&weak)) {
            self.waiters.push(weak);
        }
    }

    fn unwait(&mut self, waiter: &Arc<Waiter>) {
        waiter
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let weak = Arc::downgrade(waiter);
        self.waiters.retain(|w| !w.ptr_eq(&weak));
    }
}

/// A STORE INSTANCE'S KEPT CONNECTIONS: at most `max` established at once (the store's 1.5.5
pub struct Pool {
    max: usize,
    st: Mutex<PoolState>,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("max", &self.max)
            .field("live", &self.live())
            .field("idle", &self.idle())
            .finish()
    }
}

impl Pool {
    /// A set of at most `max` connections (at least one).
    #[must_use]
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max: max.max(1),
            st: Mutex::new(PoolState::default()),
        })
    }

    fn state(&self) -> MutexGuard<'_, PoolState> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The bound.
    #[must_use]
    pub const fn max(&self) -> usize {
        self.max
    }

    /// Established connections now (idle or held).
    #[must_use]
    pub fn live(&self) -> usize {
        self.state().live
    }

    /// Idle connections now.
    #[must_use]
    pub fn idle(&self) -> usize {
        self.state().idle.len()
    }

    /// Wake every waiting op (outside the lock).
    fn wake_all(waiters: Vec<Weak<Waiter>>) {
        for waiter in waiters {
            if let Some(waiter) = waiter.upgrade() {
                waiter.wake();
            }
        }
    }

    /// A connection was closed: one fewer established.
    fn release(&self) {
        let waiters = {
            let mut st = self.state();
            st.live = st.live.saturating_sub(1);
            std::mem::take(&mut st.waiters)
        };
        Self::wake_all(waiters);
    }

    /// A held connection comes back idle.
    fn give_back(&self, idle: Idle, host: Option<Host>) {
        let waiters = {
            let mut st = self.state();
            if st.host.is_none() {
                st.host = host;
            }
            st.idle.push(idle);
            std::mem::take(&mut st.waiters)
        };
        Self::wake_all(waiters);
    }
}

impl Drop for Pool {
    /// The set goes with its instance: its idle connections are closed.
    fn drop(&mut self) {
        let st = self.st.get_mut().unwrap_or_else(PoisonError::into_inner);
        if let Some(h) = st.host {
            for idle in st.idle.drain(..) {
                let _ = h.connector(Ticket::NONE).close(idle.conn.stream);
            }
        }
    }
}

/// What a held connection owes its set: one established connection, released unless it went back.
struct Lease {
    pool: Arc<Pool>,
    kept: bool,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if !self.kept {
            self.pool.release();
        }
    }
}

/// THE INSTANCE'S READ BUFFERS: the [`READ_CHUNK`]-sized buffers its wire ops read into, made once
/// and reused, so an op's read allocates nothing once the instance has made one (THE DESIGN, the
/// plugin ABI: "no allocation and no blocking on the hot path"). An op takes one on its first read,
/// keeps it across a PENDING answer, and gives it back when it answers. The list holds at most as
/// many as ran at once, and never more than [`READ_BUFS_KEPT`].
#[derive(Debug, Default)]
pub(crate) struct ReadBufs(Mutex<Vec<Zeroizing<Vec<u8>>>>);

/// The most read buffers an instance keeps between ops.
const READ_BUFS_KEPT: usize = 64;

impl ReadBufs {
    /// A kept buffer, or a new one when none is free.
    fn take(&self) -> Zeroizing<Vec<u8>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .unwrap_or_else(Self::fresh)
    }

    /// A buffer for an op with no instance to keep it (a detached op).
    fn fresh() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(vec![0_u8; READ_CHUNK])
    }

    /// Keep `buf` for the next op (dropped past [`READ_BUFS_KEPT`]).
    fn give(&self, mut buf: Zeroizing<Vec<u8>>) {
        buf.as_mut_slice().zeroize();
        let mut kept = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if kept.len() < READ_BUFS_KEPT {
            kept.push(buf);
        }
    }
}

/// One independently scheduled connection in an operation.
struct Channel {
    wire: Wire,
    pool: Option<Arc<Pool>>,
    waiter: Mutex<Option<Arc<Waiter>>>,
    lease: Mutex<Option<Lease>>,
    checkout: Mutex<Option<Checkout>>,
    host: Option<Host>,
    persistent: bool,
}

impl Channel {
    fn new(pool: Option<Arc<Pool>>, host: Option<Host>) -> Self {
        Self {
            wire: Wire::default(),
            pool,
            host,
            persistent: false,
            waiter: Mutex::new(None),
            lease: Mutex::new(None),
            checkout: Mutex::new(None),
        }
    }

    fn take_waiter(&self) -> Option<Arc<Waiter>> {
        self.waiter
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    fn unwait(&self) {
        if let (Some(waiter), Some(pool)) = (self.take_waiter(), &self.pool) {
            pool.state().unwait(&waiter);
        }
    }

    fn unwait_in(&self, state: &mut PoolState) {
        if let Some(waiter) = self.take_waiter() {
            state.unwait(&waiter);
        }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        {
            let mut state = self.wire.state();
            let retained =
                self.persistent && self.pool.as_ref().is_some_and(|pool| pool.idle() > 0);
            if !retained {
                state.input.clear();
            }
            state.out.clear();
            state.conn = None;
            state.ask = None;
            state.answer = None;
        }
        self.unwait();
        if let (Some(conn), Some(host)) = (
            self.checkout
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
            self.host,
        ) {
            let _ = host.connector(Ticket::NONE).close(conn.stream);
        }
    }
}

/// Dedicated native connections retained by one backend lifecycle session.
/// Each position owns a distinct one-connection pool, including its protocol state.
#[derive(Debug)]
pub struct Channels {
    pools: Vec<Arc<Pool>>,
    wires: Vec<Wire>,
    active: Arc<AtomicBool>,
}

impl Channels {
    /// Reserve `count` independent channels. At least one is required.
    #[must_use]
    pub fn new(count: usize) -> Self {
        assert!(count > 0, "native channels require a connection slot");
        Self {
            pools: (0..count).map(|_| Pool::new(1)).collect(),
            wires: (0..count).map(|_| Wire::default()).collect(),
            active: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Run a lifecycle operation over its independent retained connections.
/// Await channel services sequentially within the body. All services use the operation's
/// existing host ticket; cloning an individual Wire still shares that one channel.
pub fn drive_channels<T: 'static>(
    cx: &mut Op<'_>,
    channels: &Channels,
    start: impl FnOnce(Vec<Wire>) -> Body<T>,
) -> Step<T> {
    let _ = cx.resume::<WaitingChannels>();
    // A resumed driver already holds the claim. A waiting request must acquire it.
    let resumed = cx.resume::<Running<T>>();
    if let Some(running) = resumed {
        cx.park(running);
    } else if channels.active.swap(true, Ordering::AcqRel) {
        cx.park(WaitingChannels);
        return Step::Pending {
            wake_at_ns: later(cx, RETRY_NS),
        };
    }
    run_channels(
        cx,
        channels.pools.iter().cloned().map(Some).collect(),
        Some(&channels.wires),
        Some(channels.active.clone()),
        start,
    )
}

struct WaitingChannels;

struct ChannelClaim(Arc<AtomicBool>);
impl Drop for ChannelClaim {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// What the host ticket retains across a pending operation.
struct Running<T> {
    body: Mutex<Body<T>>,
    channels: Vec<Channel>,
    active: usize,
    buf: Mutex<Option<Zeroizing<Vec<u8>>>>,
    _claim: Option<ChannelClaim>,
}

/// RUN `start`'s body over the op's own connection, across the op's entries: a fresh entry starts
pub fn drive<T: 'static>(cx: &mut Op<'_>, start: impl FnOnce(Wire) -> Body<T>) -> Step<T> {
    run(cx, None, start)
}

/// [`drive`] on the store's kept set `pool`: the op's connection is drawn from it and goes back to
pub fn drive_kept<T: 'static>(
    cx: &mut Op<'_>,
    pool: &Arc<Pool>,
    start: impl FnOnce(Wire) -> Body<T>,
) -> Step<T> {
    run(cx, Some(pool), start)
}

/// ONE STORE OP'S SESSION on a kept connection: what a wire store opens over the op's [`Wire`]
pub trait Kept: Sized + Send + 'static {
    /// What a session opens from: the instance's shared state, moved into the op.
    type Shared: Send + 'static;
    /// Why a session did not open, in the driver's words.
    type Error: Send + 'static;

    /// Open a session on `wire`.
    fn open(
        wire: Wire,
        from: Self::Shared,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send;

    /// Hand the session's connection back once the op's body has answered.
    fn done(self) -> impl Future<Output = ()> + Send;
}

/// What an op's body is handed: its open session, for the body's lifetime.
pub type OnKept<'s, T> = Pin<Box<dyn Future<Output = T> + Send + 's>>;

/// RUN ONE OP on a session of the store's kept set `pool` ([`drive_kept`]): open a [`Kept`]
pub fn on_kept<K: Kept, T: Send + 'static>(
    cx: &mut Op<'_>,
    pool: &Arc<Pool>,
    from: K::Shared,
    fail: impl FnOnce(K::Error) -> T + Send + 'static,
    body: impl for<'s> FnOnce(&'s mut K) -> OnKept<'s, T> + Send + 'static,
) -> Step<T> {
    drive_kept(cx, pool, move |wire| -> Body<T> {
        Box::pin(async move {
            let mut session = match K::open(wire, from).await {
                Ok(s) => s,
                Err(e) => return fail(e),
            };
            let answer = body(&mut session).await;
            session.done().await;
            answer
        })
    })
}

fn run<T: 'static>(
    cx: &mut Op<'_>,
    pool: Option<&Arc<Pool>>,
    start: impl FnOnce(Wire) -> Body<T>,
) -> Step<T> {
    run_channels(cx, vec![pool.cloned()], None, None, |mut wires| {
        start(wires.remove(0))
    })
}

fn run_channels<T: 'static>(
    cx: &mut Op<'_>,
    pools: Vec<Option<Arc<Pool>>>,
    wires: Option<&[Wire]>,
    claim: Option<Arc<AtomicBool>>,
    start: impl FnOnce(Vec<Wire>) -> Body<T>,
) -> Step<T> {
    let mut running = match cx.resume::<Running<T>>() {
        Some(r) => r,
        None if cx.resuming() && claim.is_none() => {
            panic!("a store op's RESUME found no parked wire body: it is never run afresh")
        }
        None => {
            let channels: Vec<_> = pools
                .into_iter()
                .enumerate()
                .map(|(index, pool)| {
                    let mut channel = Channel::new(pool, cx.host().copied());
                    if let Some(wires) = wires {
                        channel.wire = wires[index].clone();
                        channel.wire.state().bound_at = None;
                        channel.persistent = true;
                    }
                    channel
                })
                .collect();
            let wires = channels.iter().map(|c| c.wire.clone()).collect();
            Running {
                body: Mutex::new(start(wires)),
                _claim: claim.map(ChannelClaim),
                channels,
                active: 0,
                buf: Mutex::new(None),
            }
        }
    };
    let mut ready_units = 0;
    let waker = Waker::noop();
    let mut poll_cx = Context::from_waker(waker);
    let mut buf = running
        .buf
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    loop {
        let polled = running
            .body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
            .poll(&mut poll_cx);
        if let Poll::Ready(t) = polled {
            for index in 0..running.channels.len() {
                select_channel(cx, &mut running, index);
                let channel = &running.channels[index];
                channel.unwait();
                finish(cx, channel);
                // A connection not retained in its pool must close before selecting another.
                cx.close_checkout();
            }
            if let (Some(b), Some(reads)) = (buf.take(), cx.reads()) {
                reads.give(b);
            }
            return Step::Ready(t);
        }
        let selected = running
            .channels
            .iter()
            .position(|c| c.wire.state().ask.is_some());
        let Some(index) = selected else {
            panic!("a store op's wire body awaited something other than its wire");
        };
        select_channel(cx, &mut running, index);
        let channel = &running.channels[index];
        let ask = channel
            .wire
            .state()
            .ask
            .clone()
            .expect("selected wire request");
        let bound = bound_check(cx, &channel.wire);
        let served = match bound {
            Bound::Passed => {
                cx.abandon_pending_service();
                channel.unwait();
                Served::Answer(Err(ConnFailure::Failed(
                    crate::conn::ConnError::Timeout.text().to_owned(),
                )))
            }
            _ => {
                let read = if matches!(ask, Ask::Read) {
                    buf.get_or_insert_with(|| {
                        cx.reads().map_or_else(ReadBufs::fresh, ReadBufs::take)
                    })
                    .as_mut_slice()
                } else {
                    &mut []
                };
                serve(cx, channel, &ask, read, &mut ready_units)
            }
        };
        let served = match (served, bound) {
            (Served::Pending { wake_at_ns, replay }, Bound::Until(at))
                if wake_at_ns == 0 || wake_at_ns > at =>
            {
                Served::Pending {
                    wake_at_ns: at,
                    replay,
                }
            }
            (s, _) => s,
        };
        match served {
            Served::Answer(a) => {
                if a.is_err() {
                    cx.abandon_pending_service();
                }
                let mut st = channel.wire.state();
                if a.is_err() || matches!((&ask, &a), (Ask::Read, Ok(0))) {
                    st.unfit = true;
                }
                if a.is_err() {
                    st.out.clear();
                    st.confirm_secure = false;
                }
                st.ask = None;
                st.answer = Some(a);
                drop(st);
                if ready_quantum(
                    cx.can_pend() && cx.host().is_some_and(Host::can_wake),
                    &mut ready_units,
                ) {
                    return park_ready(cx, running, buf);
                }
            }
            Served::Cooperate => return park_ready(cx, running, buf),
            Served::Pending { wake_at_ns, replay } => {
                if replay {
                    cx.replay_last_service();
                }
                *running.buf.lock().unwrap_or_else(PoisonError::into_inner) = buf;
                cx.park(running);
                return Step::Pending { wake_at_ns };
            }
        }
    }
}

/// Count completed work without creating a new logical connector service.
fn ready_quantum(can_wake: bool, units: &mut usize) -> bool {
    *units += 1;
    if *units < READY_UNITS_PER_ENTRY {
        return false;
    }
    *units = 0;
    can_wake
}

fn park_ready<T: 'static>(
    cx: &mut Op<'_>,
    running: Running<T>,
    buf: Option<Zeroizing<Vec<u8>>>,
) -> Step<T> {
    let host = cx.host().copied().expect("cooperative wake was checked");
    let ticket = cx.ticket();
    *running.buf.lock().unwrap_or_else(PoisonError::into_inner) = buf;
    // Keep the exact body, completed answer, checkout and read loan before the
    // wake. The host latches it until this crossing returns Pending; no Ready I/O
    // is reissued and no extra clock service can alter its completion handle.
    cx.park(running);
    host.wake(ticket);
    Step::Pending {
        wake_at_ns: u64::MAX,
    }
}

/// Only one host service is in flight. Move connection custody when the body
/// switches channels, without changing its ticket or completion sequence.
fn select_channel<T>(cx: &mut Op<'_>, running: &mut Running<T>, index: usize) {
    if running.active == index {
        return;
    }
    *running.channels[running.active]
        .checkout
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = cx.take_checkout();
    if let Some(conn) = running.channels[index]
        .checkout
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
    {
        cx.adopt(conn);
    }
    running.active = index;
}

/// The body answered: a fit connection on a set goes back to it; any other is closed by the door.
fn finish(cx: &mut Op<'_>, running: &Channel) {
    let Some(pool) = &running.pool else { return };
    let mut lease = running.lease.lock().unwrap_or_else(PoisonError::into_inner);
    let (fit, session) = {
        let mut st = running.wire.state();
        (
            !st.unfit && st.conn.is_some(),
            if running.persistent {
                None
            } else {
                st.session.take()
            },
        )
    };
    if !fit {
        return;
    }
    if let (Some(mut l), Some(conn)) = (lease.take(), cx.take_checkout()) {
        l.kept = true;
        running.wire.state().conn = None;
        pool.give_back(Idle { conn, session }, cx.host().copied());
    }
}

/// Where the body's [`Wire::bound`] stands.
#[derive(Debug, Clone, Copy)]
enum Bound {
    None,
    Until(u64),
    Passed,
}

/// Anchor and check the wire's bound on the host's clock (no clock: unbounded).
fn bound_check(cx: &mut Op<'_>, wire: &Wire) -> Bound {
    let (ms, at) = {
        let st = wire.state();
        (st.bound_ms, st.bound_at)
    };
    if ms == 0 {
        return Bound::None;
    }
    let now = cx.connector().ok().and_then(|mut c| match c.clock_now() {
        Poll::Ready(Ok(r)) => Some(r.mono_ns),
        _ => None,
    });
    let Some(now) = now else { return Bound::None };
    let at = at.unwrap_or_else(|| {
        let at = now.saturating_add(u64::from(ms) * 1_000_000);
        wire.state().bound_at = Some(at);
        at
    });
    if now >= at {
        Bound::Passed
    } else {
        Bound::Until(at)
    }
}

/// What one service answered.
enum Served {
    Answer(Result<usize, ConnFailure>),
    /// Partial write progress is retained; continue on the same host ticket.
    Cooperate,
    Pending {
        wake_at_ns: u64,
        /// A real in-flight host service retries its handle. Timer/pool/no-progress waits do not.
        replay: bool,
    },
}

/// The host's monotonic clock plus `delta`, or "only on a wake" when the host offers no clock.
fn later(cx: &mut Op<'_>, delta: u64) -> u64 {
    let now = cx.connector().ok().and_then(|mut c| match c.clock_now() {
        Poll::Ready(Ok(r)) => Some(r.mono_ns),
        _ => None,
    });
    now.map_or(u64::MAX, |n| n.saturating_add(delta))
}

/// Draw the op's connection: an idle kept one, a new one under the bound, or wait.
fn connect(
    cx: &mut Op<'_>,
    running: &Channel,
    need: u32,
    target: Option<&str>,
    timeout_ms: u32,
    fresh: bool,
) -> Served {
    let mut lease = running.lease.lock().unwrap_or_else(PoisonError::into_inner);
    if let (Some(pool), None) = (&running.pool, lease.as_ref()) {
        let mut st = pool.state();
        let at = (!fresh)
            .then(|| {
                st.idle
                    .iter()
                    .position(|i| i.conn.need == need && i.conn.target.as_deref() == target)
            })
            .flatten();
        if let Some(at) = at {
            let idle = st.idle.swap_remove(at);
            running.unwait_in(&mut st);
            drop(st);
            *lease = Some(Lease {
                pool: pool.clone(),
                kept: false,
            });
            cx.adopt(idle.conn.clone());
            let mut w = running.wire.state();
            w.conn = Some(idle.conn);
            w.reused = true;
            w.unfit = false;
            w.insecure = false;
            if !running.persistent {
                w.session = idle.session;
            }
            return Served::Answer(Ok(0));
        }
        if st.live < pool.max {
            st.live += 1;
            running.unwait_in(&mut st);
            drop(st);
            *lease = Some(Lease {
                pool: pool.clone(),
                kept: false,
            });
        } else if st.live >= pool.max && !st.idle.is_empty() && st.live == st.idle.len() {
            let idle = st.idle.remove(0);
            running.unwait_in(&mut st);
            drop(st);
            cx.adopt(idle.conn);
            cx.close_checkout();
            *lease = Some(Lease {
                pool: pool.clone(),
                kept: false,
            });
        } else {
            if let Some(h) = cx.host().copied() {
                let mut waiter = running
                    .waiter
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                st.wait(waiter.get_or_insert_with(Arc::default), h, cx.ticket());
            }
            drop(st);
            drop(lease);
            return Served::Pending {
                wake_at_ns: later(cx, RETRY_NS),
                replay: false,
            };
        }
    }
    drop(lease);
    match cx.checkout_timed(need, target, timeout_ms) {
        Poll::Ready(Ok(stream)) => {
            let mut w = running.wire.state();
            w.conn = Some(Checkout {
                need,
                target: target.map(str::to_owned),
                stream,
            });
            w.reused = false;
            w.unfit = false;
            w.insecure = false;
            w.session = None;
            Served::Answer(Ok(0))
        }
        Poll::Ready(Err(e)) => {
            running
                .lease
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            Served::Answer(Err(e))
        }
        Poll::Pending => Served::Pending {
            wake_at_ns: 0,
            replay: true,
        },
    }
}

/// Make the connector service `ask` names: its answer, or PENDING (the ask stays posted and is
fn serve(
    cx: &mut Op<'_>,
    running: &Channel,
    ask: &Ask,
    buf: &mut [u8],
    ready_units: &mut usize,
) -> Served {
    let wire = &running.wire;
    match ask {
        Ask::Connect {
            need,
            target,
            timeout_ms,
        } => {
            {
                let mut w = wire.state();
                w.last = Some((*need, target.clone(), *timeout_ms));
                if w.conn.is_some() {
                    return Served::Answer(Ok(0));
                }
            }
            return connect(cx, running, *need, target.as_deref(), *timeout_ms, false);
        }
        Ask::Reconnect => {
            let (had, last) = {
                let mut w = wire.state();
                (w.conn.take().is_some(), w.last.clone())
            };
            let Some((need, target, timeout_ms)) = last else {
                return Served::Answer(Err(ConnFailure::Refused(
                    "the store's wire is not connected".into(),
                )));
            };
            if had {
                cx.close_checkout();
            }
            {
                let mut w = wire.state();
                w.input.clear();
                w.out.clear();
                w.confirm_secure = false;
                w.session = None;
                w.reused = false;
            }
            let held = running
                .lease
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_some();
            if !held && running.pool.is_some() {
                return connect(cx, running, need, target.as_deref(), timeout_ms, true);
            }
            return match cx.checkout_timed(need, target.as_deref(), timeout_ms) {
                Poll::Ready(Ok(stream)) => {
                    let mut w = wire.state();
                    w.conn = Some(Checkout {
                        need,
                        target,
                        stream,
                    });
                    w.unfit = false;
                    w.insecure = false;
                    Served::Answer(Ok(0))
                }
                Poll::Ready(Err(e)) => {
                    running
                        .lease
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take();
                    Served::Answer(Err(e))
                }

                Poll::Pending => Served::Pending {
                    wake_at_ns: 0,
                    replay: true,
                },
            };
        }
        Ask::Close => {
            // Closing a retained protocol client in a later call must close its
            // native stream even before that call performs any I/O.
            if running.persistent && wire.state().conn.is_none() {
                let last = wire.state().last.clone();
                if let Some((need, target, timeout_ms)) = last {
                    if running.pool.as_ref().is_some_and(|pool| pool.idle() > 0) {
                        match connect(cx, running, need, target.as_deref(), timeout_ms, false) {
                            Served::Answer(Ok(_)) => {}
                            other => return other,
                        }
                    }
                }
            }
            wire.state().conn.take();
            cx.close_checkout();
            let mut w = wire.state();
            w.input.clear();
            w.out.clear();
            w.session = None;
            w.reused = false;
            w.unfit = false;
            w.insecure = false;
            w.confirm_secure = false;
            w.last = None;
            return Served::Answer(Ok(0));
        }
        Ask::CodecWait { yielded } => {
            if *yielded {
                return Served::Answer(Ok(0));
            }
            if !cx.can_pend() {
                return Served::Answer(Err(ConnFailure::NoTicket));
            }
            let mut services = match cx.connector() {
                Ok(services) => services,
                Err(error) => return Served::Answer(Err(error)),
            };
            return match services.clock_now() {
                Poll::Ready(Ok(now)) => {
                    wire.state().ask = Some(Ask::CodecWait { yielded: true });
                    Served::Pending {
                        wake_at_ns: now.mono_ns.saturating_add(RETRY_NS / 5),
                        replay: false,
                    }
                }
                Poll::Ready(Err(error)) => Served::Answer(Err(error)),
                Poll::Pending => Served::Pending {
                    wake_at_ns: 0,
                    replay: true,
                },
            };
        }
        Ask::Identity => {
            let mut services = match cx.connector() {
                Ok(s) => s,
                Err(e) => return Served::Answer(Err(e)),
            };
            return match services.identity() {
                Poll::Ready(Ok(id)) => {
                    wire.state().identity = Some(id);
                    Served::Answer(Ok(0))
                }
                Poll::Ready(Err(e)) => Served::Answer(Err(e)),
                Poll::Pending => Served::Pending {
                    wake_at_ns: 0,
                    replay: true,
                },
            };
        }
        _ => {}
    }
    // A retained protocol client may post I/O directly on its persistent Wire in
    // the next lifecycle call. Reacquire that channel's exact idle native stream.
    if wire.state().conn.is_none() {
        let last = wire.state().last.clone();
        if let Some((need, target, timeout_ms)) = last {
            if running.persistent && running.pool.as_ref().is_none_or(|pool| pool.idle() == 0) {
                return Served::Answer(Err(ConnFailure::Refused(
                    "the retained native channel was lost".into(),
                )));
            }
            match connect(cx, running, need, target.as_deref(), timeout_ms, false) {
                Served::Answer(Ok(_)) => {}
                other => return other,
            }
        }
    }
    let Some(stream) = wire.state().conn.as_ref().map(|c| c.stream) else {
        return Served::Answer(Err(ConnFailure::Refused(
            "the store's wire is not connected".into(),
        )));
    };
    let can_cooperate = cx.can_pend() && cx.host().is_some_and(Host::can_wake);
    let mut services = match cx.connector() {
        Ok(s) => s,
        Err(e) => return Served::Answer(Err(e)),
    };
    match ask {
        Ask::Connect { .. }
        | Ask::Reconnect
        | Ask::Close
        | Ask::Identity
        | Ask::CodecWait { .. } => {
            unreachable!("answered above")
        }
        Ask::Write => loop {
            if wire.state().insecure {
                return Served::Answer(Err(ConnFailure::Refused(
                    crate::abi::sdk::cred::NOT_SECURE.into(),
                )));
            }
            if wire.state().confirm_secure {
                match crate::abi::sdk::cred::confirm_secure(&mut services, stream, false) {
                    Poll::Ready(Ok(())) => {
                        wire.state().confirm_secure = false;
                    }
                    Poll::Pending => {
                        return Served::Pending {
                            wake_at_ns: 0,
                            replay: true,
                        }
                    }
                    _ => {
                        let mut st = wire.state();
                        st.out.clear();
                        st.unfit = true;
                        st.insecure = true;
                        return Served::Answer(Err(ConnFailure::Refused(
                            crate::abi::sdk::cred::NOT_SECURE.into(),
                        )));
                    }
                }
            }

            let mut out = std::mem::take(&mut wire.state().out);
            if out.remaining().is_empty() {
                return Served::Answer(Ok(0));
            }
            let answer = services.write(stream, out.remaining());
            match answer {
                Poll::Ready(Ok(n)) => {
                    out.consume(n);
                    let finished = out.remaining().is_empty();
                    wire.state().out = out;
                    if finished {
                        return Served::Answer(Ok(0));
                    }
                    if n == 0 {
                        drop(services);

                        return Served::Pending {
                            wake_at_ns: later(cx, RETRY_NS / 5),
                            replay: false,
                        };
                    }
                    if ready_quantum(can_cooperate, ready_units) {
                        return Served::Cooperate;
                    }
                }
                Poll::Ready(Err(e)) => return Served::Answer(Err(e)),
                Poll::Pending => {
                    wire.state().out = out;
                    drop(services);
                    return Served::Pending {
                        wake_at_ns: later(cx, RETRY_NS / 5),
                        replay: true,
                    };
                }
            }
        },
        Ask::Read => {
            let answer = services.read(stream, buf);
            #[cfg(test)]
            crate::abi::sdk::secret_bytes::watch(buf);
            let served = match answer {
                Poll::Ready(Ok(n)) => {
                    wire.state().input.extend_from_slice(&buf[..n]);
                    Served::Answer(Ok(n))
                }
                Poll::Ready(Err(e)) => Served::Answer(Err(e)),
                Poll::Pending => Served::Pending {
                    wake_at_ns: 0,
                    replay: true,
                },
            };
            buf.zeroize();
            served
        }
        Ask::Upgrade { name, verify_off } => match services.upgrade_secure_flagged(
            stream,
            name.as_deref(),
            None,
            if *verify_off {
                crate::abi::host::conn::connector::UPGRADE_VERIFY_OFF
            } else {
                0
            },
        ) {
            Poll::Ready(r) => Served::Answer(r.map(|()| 0)),
            Poll::Pending => Served::Pending {
                wake_at_ns: 0,
                replay: true,
            },
        },
    }
}

#[cfg(test)]
#[path = "../tests/store_wire_kept_tests.rs"]
mod kept_tests;

#[cfg(test)]
#[path = "../tests/store_wire_sealed_tests.rs"]
mod sealed_tests;

#[cfg(test)]
#[path = "../tests/store_wire_output_wipe_tests.rs"]
mod output_wipe_tests;

#[cfg(test)]
#[path = "tests/loader_wire_contracts.rs"]
mod loader_wire_contracts;
