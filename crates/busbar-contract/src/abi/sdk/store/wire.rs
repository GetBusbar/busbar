// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STORE OP'S BODY AS A FUTURE OVER ITS ONE RAW CONNECTION (THE DESIGN, the plugin ABI: every
//! call is Ready or Pending(wake), never a blocking thread; the connections section: the host's
//! connector, no socket of the plugin's own). A store that speaks a wire protocol to a remote
//! backend (a database, a key-value server) writes each op once, as straight-line `async` code
//! over a [`Wire`] ([`Wire::connect`], [`Wire::write_all`], [`Wire::fill`],
//! [`Wire::upgrade_secure`], [`Wire::reconnect`]), and [`drive`] runs it across the op's entries:
//!
//! * each entry polls the body until it asks the wire for something, then makes that connector
//!   service on the op's ticket ([`Op::checkout`], [`Op::connector`]) and hands the answer back;
//! * a service that answers PENDING parks the body (with its buffers) on the op's ticket and the
//!   op answers PENDING on the connector's wake; the RESUME polls the same body on from where it
//!   stopped, so no request is sent twice and nothing runs afresh;
//! * the body's own failures are its own words: a connector failure reaches it as a
//!   [`ConnFailure`] from the wire call, and the body maps it (`"error connecting to server: …"`).
//!
//! KEPT CONNECTIONS (ARCHITECT ruling 2026-10-03, STORE-KEEP: a store keeps its connections across
//! ops, as 1.5.5's clients did). A store holds one [`Pool`], a bounded set of established
//! connections sized by its 1.5.5 connection settings, and runs its ops through [`drive_kept`]:
//! [`Wire::connect`] draws an idle connection of the same need and target from the set
//! ([`Wire::reused`] says so, and the body skips its handshake; [`Wire::session`] hands back what
//! the body kept with it), establishes a new one while the set is under its bound, and otherwise
//! waits, PENDING, until a connection comes back. When the body answers, its connection goes back
//! to the set, unless a wire call failed on it, the body called [`Wire::discard`], or the op ended
//! any other way (cancelled, faulted): then it is closed, and the next op establishes a fresh one.
//! Without a pool ([`drive`]) the op's connection is its own and closed when it answers.

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use super::op::{Checkout, Op, Step};
use crate::abi::mechanism::ticket::Ticket;
use crate::abi::sdk::conn::{ConnFailure, Host};

/// How much one read asks the connector for.
pub const READ_CHUNK: usize = 16 * 1024;

/// How long an op waiting for a kept connection, or re-offering a write the connector had no
/// room for, waits at most before it looks again (a returned connection wakes it sooner).
const RETRY_NS: u64 = 5_000_000;

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
    Write,
    Read,
    Upgrade {
        name: Option<String>,
    },
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
    /// Bytes the body wrote that the connector has not taken yet.
    out: Vec<u8>,
    /// Bytes read that the body has not consumed yet.
    input: Vec<u8>,
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
            ask: Some(ask),
        }
    }

    /// The op's connection: declared need `need` to `target` (`None` = the need's own target), a
    /// kept one when the op runs on a [`Pool`] and one is idle ([`Wire::reused`]).
    ///
    /// # Errors
    /// The connector's failure (the far end, the egress rules or the need said no).
    pub async fn connect(&self, need: u32, target: Option<&str>) -> Result<(), ConnFailure> {
        self.connect_timed(need, target, 0).await
    }

    /// [`Wire::connect`], a new connection's dial bounded by `timeout_ms` (`0` = the need's own
    /// timeout, else the host's default): an operator-set connect timeout.
    ///
    /// # Errors
    /// The connector's failure; a dial past `timeout_ms` fails with its timeout.
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
    /// and target, never a kept one: a store's retry on a new connection.
    ///
    /// # Errors
    /// The connector's failure.
    pub async fn reconnect(&self) -> Result<(), ConnFailure> {
        self.ask(Ask::Reconnect).await.map(|_| ())
    }

    /// Whether the connection was established by an earlier op and kept: its handshake is done.
    #[must_use]
    pub fn reused(&self) -> bool {
        self.state().reused
    }

    /// Never keep this connection: it is closed when the op answers (a protocol state the body
    /// cannot vouch for, a transaction left open).
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
    ///
    /// # Errors
    /// The connector's failure (the connection closed, its deadline passed).
    pub async fn write_all(&self, bytes: &[u8]) -> Result<(), ConnFailure> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.state().out.extend_from_slice(bytes);
        self.ask(Ask::Write).await.map(|_| ())
    }

    /// Read more bytes onto the input ([`Wire::input`]): how many arrived; `0` = the far end
    /// closed the connection.
    ///
    /// # Errors
    /// The connector's failure.
    pub async fn fill(&self) -> Result<usize, ConnFailure> {
        self.ask(Ask::Read).await
    }

    /// Secure the connection from its next byte on (TLS from the first byte, or after the
    /// protocol's own negotiation), offering `name` (`None` = the target's host).
    ///
    /// # Errors
    /// The connector's failure (the handshake or the trust refused).
    pub async fn upgrade_secure(&self, name: Option<&str>) -> Result<(), ConnFailure> {
        self.ask(Ask::Upgrade {
            name: name.map(str::to_owned),
        })
        .await
        .map(|_| ())
    }

    /// The bytes read and not yet consumed, to parse from and drain (a codec consumes a whole
    /// message and leaves the rest).
    pub fn input<R>(&self, f: impl FnOnce(&mut Vec<u8>) -> R) -> R {
        f(&mut self.state().input)
    }
}

/// One wire call: it posts its ask on the first poll and answers when [`drive`] has.
struct Asked<'w> {
    wire: &'w Wire,
    ask: Option<Ask>,
}

impl Future for Asked<'_> {
    type Output = Result<usize, ConnFailure>;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let mut st = self.wire.state();
        if let Some(ask) = self.ask.take() {
            st.ask = Some(ask);
            st.answer = None;
            return Poll::Pending;
        }
        match st.answer.take() {
            Some(a) => Poll::Ready(a),
            None => Poll::Pending,
        }
    }
}

// ── the kept set ──────────────────────────────────────────────────────────────────────────────

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
    waiters: Vec<(Host, Ticket)>,
    /// The host tables the idle connections are closed through when the set goes.
    host: Option<Host>,
}

/// A STORE INSTANCE'S KEPT CONNECTIONS: at most `max` established at once (the store's 1.5.5
/// connection settings), each held by one op at a time ([`drive_kept`]).
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
    fn wake_all(waiters: Vec<(Host, Ticket)>) {
        for (h, t) in waiters {
            h.wake(t);
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

/// What [`drive`] parks on the op's ticket across a PENDING answer.
struct Running<T> {
    body: Mutex<Body<T>>,
    wire: Wire,
    pool: Option<Arc<Pool>>,
    /// The op's claim on one of the set's connections.
    lease: Mutex<Option<Lease>>,
}

/// RUN `start`'s body over the op's own connection, across the op's entries: a fresh entry starts
/// it (`start` is called once per op, never on a RESUME), a RESUME polls the parked body on. The
/// op answers the body's output, or PENDING while a connector service is in flight; its connection
/// is closed when it answers.
///
/// # Panics
/// A RESUME with no body parked (the door answers FAULT: an op never runs afresh on its RESUME), or
/// a body that awaits something other than its [`Wire`] (nothing would wake it).
pub fn drive<T: 'static>(cx: &mut Op<'_>, start: impl FnOnce(Wire) -> Body<T>) -> Step<T> {
    run(cx, None, start)
}

/// [`drive`] on the store's kept set `pool`: the op's connection is drawn from it and goes back to
/// it when the body answers (unless it is unfit).
///
/// # Panics
/// As [`drive`].
pub fn drive_kept<T: 'static>(
    cx: &mut Op<'_>,
    pool: &Arc<Pool>,
    start: impl FnOnce(Wire) -> Body<T>,
) -> Step<T> {
    run(cx, Some(pool), start)
}

fn run<T: 'static>(
    cx: &mut Op<'_>,
    pool: Option<&Arc<Pool>>,
    start: impl FnOnce(Wire) -> Body<T>,
) -> Step<T> {
    let running = match cx.resume::<Running<T>>() {
        Some(r) => r,
        None if cx.resuming() => {
            panic!("a store op's RESUME found no parked wire body: it is never run afresh")
        }
        None => {
            let wire = Wire::default();
            Running {
                body: Mutex::new(start(wire.clone())),
                wire,
                pool: pool.cloned(),
                lease: Mutex::new(None),
            }
        }
    };
    let waker = Waker::noop();
    let mut poll_cx = Context::from_waker(waker);
    let mut buf = vec![0_u8; READ_CHUNK];
    loop {
        let polled = running
            .body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
            .poll(&mut poll_cx);
        if let Poll::Ready(t) = polled {
            finish(cx, &running);
            return Step::Ready(t);
        }
        let ask = running.wire.state().ask.clone();
        let Some(ask) = ask else {
            panic!("a store op's wire body awaited something other than its wire");
        };
        match serve(cx, &running, &ask, &mut buf) {
            Served::Answer(a) => {
                let mut st = running.wire.state();
                if a.is_err() || matches!((&ask, &a), (Ask::Read, Ok(0))) {
                    st.unfit = true;
                }
                st.ask = None;
                st.answer = Some(a);
            }
            Served::Pending { wake_at_ns } => {
                cx.park(running);
                return Step::Pending { wake_at_ns };
            }
        }
    }
}

/// The body answered: a fit connection on a set goes back to it; any other is closed by the door.
fn finish<T>(cx: &mut Op<'_>, running: &Running<T>) {
    let Some(pool) = &running.pool else { return };
    let mut lease = running.lease.lock().unwrap_or_else(PoisonError::into_inner);
    let (fit, session) = {
        let mut st = running.wire.state();
        (!st.unfit && st.conn.is_some(), st.session.take())
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

/// What one service answered.
enum Served {
    Answer(Result<usize, ConnFailure>),
    Pending { wake_at_ns: u64 },
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
fn connect<T>(
    cx: &mut Op<'_>,
    running: &Running<T>,
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
            w.session = idle.session;
            return Served::Answer(Ok(0));
        }
        if st.live < pool.max {
            st.live += 1;
            drop(st);
            *lease = Some(Lease {
                pool: pool.clone(),
                kept: false,
            });
        } else if st.live >= pool.max && !st.idle.is_empty() && st.live == st.idle.len() {
            // Every connection is idle but none for this need and target: make room.
            let idle = st.idle.remove(0);
            drop(st);
            cx.adopt(idle.conn);
            cx.close_checkout();
            *lease = Some(Lease {
                pool: pool.clone(),
                kept: false,
            });
        } else {
            if let Some(h) = cx.host().copied() {
                st.waiters.push((h, cx.ticket()));
            }
            drop(st);
            drop(lease);
            return Served::Pending {
                wake_at_ns: later(cx, RETRY_NS),
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
            w.session = None;
            Served::Answer(Ok(0))
        }
        Poll::Ready(Err(e)) => {
            // No connection: the claim on the set goes.
            running
                .lease
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            Served::Answer(Err(e))
        }
        Poll::Pending => Served::Pending { wake_at_ns: 0 },
    }
}

/// Make the connector service `ask` names: its answer, or PENDING (the ask stays posted and is
/// made again on the RESUME).
fn serve<T>(cx: &mut Op<'_>, running: &Running<T>, ask: &Ask, buf: &mut [u8]) -> Served {
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
                // The old connection closes now; a claim on the set carries over to the new one.
                cx.close_checkout();
                let mut w = wire.state();
                w.input.clear();
                w.out.clear();
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
                // Not connected yet: the RESUME establishes again from the same ask.
                Poll::Pending => Served::Pending { wake_at_ns: 0 },
            };
        }
        _ => {}
    }
    let Some(stream) = wire.state().conn.as_ref().map(|c| c.stream) else {
        return Served::Answer(Err(ConnFailure::Refused(
            "the store's wire is not connected".into(),
        )));
    };
    let mut services = match cx.connector() {
        Ok(s) => s,
        Err(e) => return Served::Answer(Err(e)),
    };
    match ask {
        Ask::Connect { .. } | Ask::Reconnect => unreachable!("answered above"),
        Ask::Write => loop {
            let out = std::mem::take(&mut wire.state().out);
            let answer = services.write(stream, &out);
            let mut st = wire.state();
            match answer {
                Poll::Ready(Ok(n)) => {
                    let mut out = out;
                    out.drain(..n.min(out.len()));
                    st.out = out;
                    if st.out.is_empty() {
                        return Served::Answer(Ok(0));
                    }
                    if n == 0 {
                        drop(st);
                        drop(services);
                        // No room: offer the rest again shortly (a pending write wakes nothing).
                        return Served::Pending {
                            wake_at_ns: later(cx, RETRY_NS / 5),
                        };
                    }
                }
                Poll::Ready(Err(e)) => {
                    st.out = out;
                    return Served::Answer(Err(e));
                }
                Poll::Pending => {
                    st.out = out;
                    drop(st);
                    drop(services);
                    return Served::Pending {
                        wake_at_ns: later(cx, RETRY_NS / 5),
                    };
                }
            }
        },
        Ask::Read => match services.read(stream, buf) {
            Poll::Ready(Ok(n)) => {
                wire.state().input.extend_from_slice(&buf[..n]);
                Served::Answer(Ok(n))
            }
            Poll::Ready(Err(e)) => Served::Answer(Err(e)),
            Poll::Pending => Served::Pending { wake_at_ns: 0 },
        },
        Ask::Upgrade { name } => match services.upgrade_secure(stream, name.as_deref(), None) {
            Poll::Ready(r) => Served::Answer(r.map(|()| 0)),
            Poll::Pending => Served::Pending { wake_at_ns: 0 },
        },
    }
}
