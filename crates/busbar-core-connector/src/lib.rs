// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-core-connector` — THE CONNECTOR (THE DESIGN: connections). The chain is kernel →

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod carrier;
pub mod compose;
pub mod datagram;
mod dialled;
pub mod doors;
pub mod dtls;
pub mod endpoint;
pub mod fetch;
pub mod framed_stream;
pub mod framer;
pub mod guard;
pub mod hostio;
pub mod io;
mod line;
pub mod listen;
pub mod pool;
pub mod process;
mod program;
pub mod proxy;
pub mod proxy_route;
pub mod publication;
pub mod registry;
pub(crate) mod seal;
pub mod socket;
pub mod spawn_env;
/// The TLS test kit (far ends, the recording TLS fixture server, a private test CA) for this crate's
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod tls;
pub mod udp;
pub mod wire;

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::host::service::{DEST_NO_ADDRESSES, DEST_UNRESOLVABLE};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::transport::{ROLE_CARRIER, ROLE_FRAMER};
use busbar_contract::conn::{
    Bytes, ConnCause, ConnError, ConnId, ConnSlab, Conns, DeclaredConns, HeadDefaults, InstanceId,
    NeedId, OpenDesc, Piece, PieceKind, PollConns, Ticket, NO_TICKET,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::{WireFault, WireStatusClass};
use busbar_contract::transport::ConnFacts;

use crate::compose::{
    Connection, Dial, Failure, Planned, Via, DEFAULT_OPEN_TIMEOUT, EXCHANGE_STREAM,
    WRITE_BUFFER_BYTES,
};
use crate::framer::FramerDoor;
use crate::hostio::HostIo;
use crate::line::{Line, EVERY};
use crate::listen::{AcceptLimits, Listening};
use crate::pool::{PoolKey, PoolPosture, Pools, Same};
use crate::registry::Transports;

/// How the host wakes a caller's ticket, naming the caller that handed it the ticket: the supplier
pub type WakeTicket = busbar_contract::conn::ConnWake;

/// A `DEST_*` verdict (`busbar_contract::abi::host::service`) refusing a dial.
pub type Verdict = u64;

/// Where a pended judgement goes: the address to dial, or the verdict refusing it. Called once,
pub type Judged = Box<dyn FnOnce(Result<SocketAddr, Verdict>) + Send>;

/// Where a pended judgement goes with the name's OTHER admitted addresses, in the resolver's order:
pub type JudgedAll = Box<dyn FnOnce(Result<SocketAddr, Verdict>, Vec<SocketAddr>) + Send>;

/// A need's `egress_class` `0`: the connector's default class (`busbar_contract::abi::host::conn::
pub const DEFAULT_CLASS: u32 = 0;

/// THE KERNEL'S DESTINATION JUDGE, as a dial reaches it (`dest.judge`, R-K): every authority the
pub trait DialJudge: Send + Sync {
    /// Replace the bootstrap listener-port metadata before the effective plugins open.
    fn own_ports_applied(&self, _ports: &[u16]) {}

    /// Judge `dest` (`host:port`) under egress class `class`.
    fn judge_dial(
        &self,
        dest: &str,
        class: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, Verdict>>;

    /// [`DialJudge::judge_dial`] for a destination the dialling need holds a PRIVATE REACH to (the
    fn judge_dial_reaching(
        &self,
        dest: &str,
        class: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, Verdict>> {
        self.judge_dial(dest, class, done)
    }

    /// [`DialJudge::judge_dial`] (with the need's private reach when `reach`) whose pended answer
    fn judge_dial_all(
        &self,
        dest: &str,
        class: u32,
        reach: bool,
        done: JudgedAll,
    ) -> Option<Result<SocketAddr, Verdict>> {
        let done: Judged = Box::new(move |v| done(v, Vec::new()));
        if reach {
            self.judge_dial_reaching(dest, class, done)
        } else {
            self.judge_dial(dest, class, done)
        }
    }

    /// THE STATIC ARM ALONE: the refusal `dest` (`host:port`) meets under class `class` before any
    fn judge_static(&self, dest: &str, class: u32) -> Option<Verdict> {
        let _ = (dest, class);
        None
    }
}

/// Any function of the judge's shape is a judge: [`process::judge`] joins the deployment's one
impl<F> DialJudge for F
where
    F: Fn(&str, u32, Judged) -> Option<Result<SocketAddr, Verdict>> + Send + Sync,
{
    fn judge_dial(
        &self,
        dest: &str,
        class: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, Verdict>> {
        self(dest, class, done)
    }
}

/// The judge a connector built with none holds: an IP literal is its own address, judged by the
pub(crate) struct LiteralsOnly(pub(crate) guard::Guard);

impl DialJudge for LiteralsOnly {
    fn judge_dial(&self, dest: &str, class: u32, _: Judged) -> Option<Result<SocketAddr, Verdict>> {
        let Some(at) = socket::address_of(dest) else {
            return Some(Err(busbar_contract::abi::host::service::DEST_UNRESOLVABLE));
        };
        Some(
            self.0
                .judge_answer(&at.ip().to_string(), &[at.ip()], class)
                .map(|()| at)
                .map_err(|r| r.verdict),
        )
    }

    fn judge_dial_reaching(
        &self,
        dest: &str,
        class: u32,
        _: Judged,
    ) -> Option<Result<SocketAddr, Verdict>> {
        let Some(at) = socket::address_of(dest) else {
            return Some(Err(busbar_contract::abi::host::service::DEST_UNRESOLVABLE));
        };
        Some(
            self.0
                .judge_answer_with(&at.ip().to_string(), &[at.ip()], class, false, true)
                .map(|()| at)
                .map_err(|r| r.verdict),
        )
    }
}

/// THE SCHEME RULE OF A NEED'S EGRESS CLASS (`abi::host::conn::connector`, `EGRESS_*`), held
fn scheme_admits(egress_class: u32, secure: bool) -> bool {
    egress_class != EGRESS_OPEN_WEB || secure
}

fn class_admits(
    egress_class: u32,
    secure: bool,
    within: &[IpAddr],
    authority: &str,
    addr: SocketAddr,
) -> bool {
    (within.is_empty() || within.contains(&addr.ip()))
        && match egress_class {
            EGRESS_OPEN_WEB => secure,
            EGRESS_LOOPBACK_ALLOWED => secure || guard::names_loopback(&host_of(authority)),
            _ => true,
        }
}

/// WHAT A JUDGEMENT THAT PENDED ON A RESOLUTION ANSWERS THE CONNECTION'S CALLER. A name that did
fn pended_verdict(v: Verdict) -> ConnError {
    match v {
        DEST_UNRESOLVABLE | DEST_NO_ADDRESSES => ConnError::Fault,
        _ => ConnError::Refused,
    }
}

/// THE HEAD A PLUGIN WROTE, held to 1.5.5's rule for a plugin-described request (v1.5.5
fn head_is_refused(desc: &OpenDesc<'_>, authority_held: bool) -> bool {
    const FRAMING: [&str; 2] = ["content-length", "transfer-encoding"];
    const AUTHORITY: &str = "host";
    let breaks = |b: &[u8]| b.iter().any(|c| matches!(c, b'\r' | b'\n' | b'\0'));
    breaks(desc.target.as_bytes())
        || breaks(desc.method)
        || breaks(desc.head_target)
        || desc.fields.iter().any(|(name, value)| {
            let name_is = |f: &str| name.trim().eq_ignore_ascii_case(f);
            breaks(name.as_bytes())
                || breaks(value)
                || FRAMING.iter().any(|f| name_is(f))
                || (authority_held && name_is(AUTHORITY))
        })
}

/// What the connector holds for one declared need: the entry serving its transport, resolved once
/// at declare (a need no entry serves is refused there, never at its open).
#[derive(Clone)]
struct DeclaredNeed {
    door: Arc<dyn FramerDoor>,
    /// The protocols the serving entry offers in the TLS handshake.
    alpn: Vec<Vec<u8>>,
    egress_class: u32,
    /// The target the need's `target_from` resolved to; `None` = the plugin names it per open.
    declared_target: Option<String>,
    /// The need's own client config, when its `trust_from` named an operator CA: the public roots
    /// with that CA added on top (spec section 5, the host connector: "an extra trusted root added
    /// on top of the public roots, as in 1.5.5"); `None` = the connector's default trust.
    tls: Option<Arc<rustls::ClientConfig>>,
    tls_policy: Option<busbar_contract::transport::trust::EgressTrust>,
    /// The program the need's `target_from` resolved to, its environment references held as its
    /// declaration resolved them: every open spawns it.
    program: Option<(busbar_contract::conn::Program, spawn_env::HeldEnv)>,
    /// A member-program need's members (`busbar_contract::section::MEMBER_PROGRAM`): every open
    /// names one and leases its one long-lived program connection.
    members: Option<Arc<program::Members>>,
    member_spec: Option<ReadNeed>,
}

/// A judgement's answer once it came, and the waker of the read or wait that found none.
type Answer = Arc<
    Mutex<(
        Option<Result<SocketAddr, Verdict>>,
        Option<Waker>,
        Vec<SocketAddr>,
    )>,
>;

/// The trust anchors sealed per destination (the transport pin), by the need's owner, the need and
type Anchored = Mutex<HashMap<(InstanceId, NeedId, String), Arc<tls::client::Sealed>>>;

/// THE REGISTRATIONS' SEALS AT ONE DESTINATION: each registration's seal at its authority, by name
/// (`None`: it holds no anchors), in name order. An open naming no registration sealed there is held
/// to the one answer they and the destination's own seal all give, and refused where they disagree:
/// a pin nobody enforces is refused, never dropped, and no registration's anchors are erased by
/// another's.
#[derive(Default)]
struct Registered {
    members: std::collections::BTreeMap<String, Option<Arc<tls::client::Sealed>>>,
}

impl Registered {
    /// What an open naming no registration is held to, with the destination's `own` seal: the one
    fn held(
        &self,
        own: Option<&Arc<tls::client::Sealed>>,
    ) -> Result<Option<Arc<tls::client::Sealed>>, ConnError> {
        let mut seals = own
            .into_iter()
            .map(Some)
            .chain(self.members.values().map(Option::as_ref));
        let Some(first) = seals.next() else {
            return Ok(None);
        };
        if seals.all(|other| same_anchors(first, other)) {
            Ok(first.cloned())
        } else {
            Err(ConnError::Refused)
        }
    }
}

/// Whether two seals hold a connection to the same: the same key pin and the same client identity
fn same_anchors(
    a: Option<&Arc<tls::client::Sealed>>,
    b: Option<&Arc<tls::client::Sealed>>,
) -> bool {
    let pins = a.and_then(|s| s.key_pin.as_deref()) == b.and_then(|s| s.key_pin.as_deref());
    let identities = match (
        a.and_then(|s| s.identity.as_deref()),
        b.and_then(|s| s.identity.as_deref()),
    ) {
        (None, None) => true,
        (Some(x), Some(y)) => x.cert == y.cert,
        _ => false,
    };
    let roots = a.map(|s| s.extra_anchors.as_slice()).unwrap_or_default()
        == b.map(|s| s.extra_anchors.as_slice()).unwrap_or_default();
    pins && identities && roots
}

/// The trust anchors sealed per REGISTRATION, by the need's owner, the need and the registration's
type MemberAnchored =
    Mutex<HashMap<(InstanceId, NeedId, String), (String, Option<Arc<tls::client::Sealed>>)>>;

/// What a member's auth binding is held under: the need's owner, the need, the registration's
type AuthKey = (InstanceId, NeedId, String, String);

/// The listeners, one per inbound need, by the need's owner and need.
type Listeners = Mutex<HashMap<(InstanceId, NeedId), Arc<Accepting>>>;

/// ONE INBOUND LISTENER, driven under no lock (`BUSBAR-1.6.0.md` §11: no plugin code runs under a
/// host lock): an accept takes the listener out, crosses the carrier's `accept` (and closes a
/// connection past the cap) with nothing held, and puts it back. An accept that finds it out
/// (another accept has it, or its bind is still crossing) answers PENDING, woken when it is back.
#[derive(Default)]
struct Accepting {
    /// The listener while no accept has it out, and the accepts that found it out.
    slot: Mutex<(Option<Listening>, Vec<Waker>)>,
}

impl Accepting {
    /// Take the listener out; `None` (with `waker` woken once it is back) while it is out.
    fn take(&self, waker: &Waker) -> Option<Listening> {
        let mut slot = self.slot.lock().expect("listener");
        let taken = slot.0.take();
        if taken.is_none() && !slot.1.iter().any(|w| w.will_wake(waker)) {
            slot.1.push(waker.clone());
        }
        taken
    }

    /// Put `listening` back (`None`: it is gone), waking every accept that found it out.
    fn put(&self, listening: Option<Listening>) {
        let waiting = {
            let mut slot = self.slot.lock().expect("listener");
            slot.0 = listening;
            std::mem::take(&mut slot.1)
        };
        for w in waiting {
            w.wake();
        }
    }
}

/// A listener an accept has out: put back however the accept ends, an unwind included.
struct AcceptingOut<'a> {
    home: &'a Accepting,
    listening: Option<Listening>,
}

impl Drop for AcceptingOut<'_> {
    fn drop(&mut self) {
        if let Some(l) = self.listening.take() {
            self.home.put(Some(l));
        }
    }
}

/// A dial whose judgement pended, retained until its accepted writes reach the line. `planned`
struct Judging {
    planned: Option<Planned>,
    /// A spent dial or replay's terminal error, retained for every poll until close.
    failed: Option<ConnError>,
    /// The need's egress class, whose scheme rule the pinned address is held to.
    egress_class: u32,
    /// The address set the pinned address must be in (`OpenDesc::within`); empty = any.
    within: Vec<IpAddr>,
    /// Writes the caller made before the dial, in order.
    early: VecDeque<(Bytes, bool, bool)>,
    answer: Answer,
    /// A dial through a proxy ([`proxy`]): the proxy, and whether the target's own judgement has
    proxied: Option<Proxied>,
}

/// A dial through a proxy, judged in two steps: the target (its name arm, and its own resolution
struct Proxied {
    spec: Arc<proxy::ProxyHop>,
    judged_class: u32,
    target_judged: bool,
}

/// Whether a target judgement's refusal is only that the name does not resolve HERE: behind a
fn unresolved_here(verdict: Verdict) -> bool {
    verdict == DEST_UNRESOLVABLE || verdict == DEST_NO_ADDRESSES
}

/// What an exchange lent a pooled line keeps to redial it ONCE on a fresh connection when that line
struct Redial {
    door: Arc<dyn FramerDoor>,
    dial: Dial,
    egress_class: u32,
    judged_class: u32,
    require_secure: bool,
    /// The need's private reach to the destination ([`DialJudge::judge_dial_reaching`]).
    reach: bool,
    /// The bytes the line's socket had taken when the exchange was lent it.
    mark: u64,
}

/// A HELD CONNECTION'S DIAL OR REPLAY, CROSSING WITH NO LOCK HELD (`BUSBAR-1.6.0.md` §11: no plugin code
struct Crossing<'h> {
    held: &'h Held,
}

impl<'h> Crossing<'h> {
    /// The dial of `held` begins crossing; `judging` (its spent judgement's lock) is let go.
    fn begin(held: &'h Held, judging: std::sync::MutexGuard<'_, Option<Judging>>) -> Self {
        *held.crossing.lock().expect("crossing") = Some(Vec::new());
        drop(judging);
        Self { held }
    }

    /// Keep the crossing's failure before releasing its callers to read it. A consumed plan
    fn finish(self, result: Result<bool, ConnError>) -> Result<bool, ConnError> {
        if let Err(error) = result {
            if error != ConnError::Pending {
                self.held
                    .fail(self.held.judging.lock().expect("judging"), error);
            }
        }
        result
    }
}

impl Drop for Crossing<'_> {
    fn drop(&mut self) {
        let waiting = self
            .held
            .crossing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .unwrap_or_default();
        for w in waiting {
            w.wake();
        }
    }
}

/// A piece a short caller buffer left, and its unread bytes.
type Left = (Piece, Vec<u8>);

/// What a short caller buffer left of a piece (the piece and its unread bytes), and whether the
/// end was answered.
#[derive(Default)]
struct Rest {
    piece: Option<Left>,
    ended: bool,
    /// A read (or an upgrade) has the rest out.
    reading: bool,
    /// The reads that found it out, woken when it is back.
    missed: Vec<Waker>,
}

/// ONE READ HAS THE REST (`BUSBAR-1.6.0.md` §11: no plugin code runs under a host lock): taken
struct Reading<'h> {
    rest: &'h Mutex<Rest>,
    /// The end was answered.
    ended: bool,
    /// What a short buffer left, for the next read.
    left: Option<Left>,
}

impl<'h> Reading<'h> {
    /// Take the rest for one read: what a short buffer left, and whether the end was answered.
    fn begin(rest: &'h Mutex<Rest>, waker: &Waker) -> Option<(Self, Option<Left>)> {
        let incoming = waker.clone();
        let mut r = rest.lock().expect("rest");
        if r.reading {
            if !r.missed.iter().any(|w| w.will_wake(waker)) {
                r.missed.push(incoming);
            }
            return None;
        }
        r.reading = true;
        let kept = r.piece.take();
        let ended = r.ended;
        Some((
            Self {
                rest,
                ended,
                left: None,
            },
            kept,
        ))
    }
}

impl Drop for Reading<'_> {
    fn drop(&mut self) {
        let missed = {
            let mut r = self
                .rest
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            r.reading = false;
            r.ended |= self.ended;
            if let Some(left) = self.left.take() {
                r.piece = Some(left);
            }
            std::mem::take(&mut r.missed)
        };
        for w in missed {
            w.wake();
        }
    }
}

/// One connection the connector holds for its owner: the line it rides and the stream it reads
struct Held {
    line: Mutex<Option<(Arc<Line>, u64)>>,
    /// Closed while a dial or replay may still have this state out. Published with `line` locked.
    retired: AtomicBool,
    /// The judgement the dial waits on; `None` once dialled.
    judging: Mutex<Option<Judging>>,
    /// THE DIAL IS CROSSING (`Some`, with the callers waiting on it): its judgement is spent and
    crossing: Mutex<Option<Vec<Waker>>>,
    /// The piece a short caller buffer left, and whether the end was answered: the reading
    rest: Mutex<Rest>,
    /// The far end's reason phrase, held until its head's last piece is read.
    reason: Mutex<Option<Vec<u8>>>,
    /// Where a dialled connection goes back to when its exchange finished whole: its pool shard
    pooled: Option<(usize, PoolKey)>,
    /// The dialled exchange ended WHOLE (its stream's end was read).
    whole: AtomicBool,
    /// The one redial an exchange lent a pooled line keeps.
    redial: Mutex<Option<Redial>>,
    /// A LEASE on a member's long-lived program connection, in place of a connection of its own.
    lease: Option<(Arc<program::Member>, u64)>,
    /// THE REQUEST'S WHOLE BOUND until its answer (`OpenDesc::timeout_ms`; `None` = unbounded
    due: Mutex<Option<Due>>,
    /// The dial's original bound, including a pended judgement, independent of the request.
    dial_due: Mutex<Option<Due>>,
    /// A held session's UPSTREAM LEG over a datagram framer's need ([`dialled`]): its exchange
    dialled: Option<dialled::Dialled>,
}

/// The instant a request's `timeout_ms` (the plugin's own number, unclamped: `RequestPiece` and
fn due_at(now: std::time::Instant, timeout_ms: u64) -> Option<std::time::Instant> {
    if timeout_ms == 0 {
        return None;
    }
    now.checked_add(Duration::from_millis(timeout_ms))
}

/// THE WHOLE REQUEST'S BOUND (`RequestPiece::timeout_ms`, BUSBAR-1.6.0.md:4890 "timeout clamped to
/// the deadline class"; the `call` class, :3496-3505): from the open, through the dial, the
/// judgement, the handshake and the send, until the far end's FIRST piece of its answer. Past it a
/// read is answered [`ConnError::Timeout`], and a reader waiting on the connection is woken to read
/// it. Once an answer has begun the bound is spent: what bounds a streamed answer is its own class,
/// as its reader keeps it, never this one (an answer cut mid-stream by a time-to-answer bound would
/// be a different outcome from the one the reader chose).
#[derive(Clone)]
struct Due {
    at: std::time::Instant,
    timer: Arc<std::sync::OnceLock<Mutex<Option<DeadlineTimer>>>>,
    wake: Arc<DeadlineWake>,
}

type DeadlineTimer = std::pin::Pin<Box<tokio::time::Sleep>>;

#[derive(Clone, Copy)]
enum DeadlineInterest {
    Ticket(Ticket),
    Task,
}

#[derive(Default)]
struct DeadlineWaiters {
    tickets: HashMap<Ticket, Waker>,
    tasks: Vec<Waker>,
}

#[derive(Default)]
struct DeadlineWake {
    cancelled: AtomicBool,
    waiters: Mutex<DeadlineWaiters>,
}

impl DeadlineWake {
    fn register(&self, interest: DeadlineInterest, waker: &Waker) {
        if matches!(interest, DeadlineInterest::Ticket(NO_TICKET)) {
            return;
        }

        let mut fresh = Some(waker.clone());
        let previous = {
            let mut waiters = self.waiters.lock().expect("deadline waiters");
            if self.cancelled.load(Ordering::Acquire) {
                None
            } else {
                match interest {
                    DeadlineInterest::Ticket(ticket) => {
                        waiters.tickets.insert(ticket, fresh.take().unwrap())
                    }
                    DeadlineInterest::Task => {
                        if !waiters.tasks.iter().any(|old| old.will_wake(waker)) {
                            waiters.tasks.push(fresh.take().unwrap());
                        }
                        None
                    }
                }
            }
        };
        drop(previous);
        drop(fresh);
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let waiters = std::mem::take(&mut *self.waiters.lock().expect("deadline waiters"));
        drop(waiters);
    }
}

impl Wake for DeadlineWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let waiters = std::mem::take(&mut *self.waiters.lock().expect("deadline waiters"));
        for waker in waiters.tickets.into_values().chain(waiters.tasks) {
            waker.wake();
        }
    }
}

impl Due {
    fn new(at: std::time::Instant) -> Self {
        Self {
            at,
            timer: Arc::default(),
            wake: Arc::default(),
        }
    }

    fn cancel(&self) {
        self.wake.cancel();
        let timer = self
            .timer
            .get()
            .and_then(|slot| slot.lock().expect("deadline timer").take());
        drop(timer);
    }

    /// Poll the one timer outside every host guard. Copies retain one clock across polls.
    fn check(&self) -> Result<(), ConnError> {
        if self.wake.cancelled.load(Ordering::Acquire) {
            return Ok(());
        }
        if std::time::Instant::now() >= self.at {
            return Err(ConnError::Timeout);
        }
        let _entered = crate::io::enter_process_runtime();
        if tokio::runtime::Handle::try_current().is_ok() {
            let slot = self.timer.get_or_init(|| {
                Mutex::new(Some(Box::pin(tokio::time::sleep_until(
                    tokio::time::Instant::from_std(self.at),
                ))))
            });
            let timer = slot.lock().expect("deadline timer").take();
            let Some(mut timer) = timer else {
                return Ok(());
            };
            let waker = Waker::from(self.wake.clone());
            let ready = std::pin::Pin::new(&mut timer)
                .poll(&mut Context::from_waker(&waker))
                .is_ready();
            let mut timer = Some(timer);
            let previous = {
                let mut slot = slot.lock().expect("deadline timer");
                if !self.wake.cancelled.load(Ordering::Acquire) {
                    slot.replace(timer.take().expect("the polled timer"))
                } else {
                    None
                }
            };
            drop(previous);
            drop(timer);
            if ready {
                return Err(ConnError::Timeout);
            }
        }
        Ok(())
    }
}

impl Held {
    fn over(
        line: Option<(Arc<Line>, u64)>,
        judging: Option<Judging>,
        pooled: Option<(usize, PoolKey)>,
    ) -> Self {
        Held {
            line: Mutex::new(line),
            retired: AtomicBool::new(false),
            judging: Mutex::new(judging),
            crossing: Mutex::new(None),
            rest: Mutex::new(Rest::default()),
            reason: Mutex::new(None),
            pooled,
            whole: AtomicBool::new(false),
            redial: Mutex::new(None),
            lease: None,
            due: Mutex::new(None),
            dial_due: Mutex::new(None),
            dialled: None,
        }
    }

    /// This connection carries a held session's upstream leg (`d`).
    fn dialling(mut self, d: dialled::Dialled) -> Self {
        self.dialled = Some(d);
        self
    }

    fn line(&self) -> Option<(Arc<Line>, u64)> {
        self.line.lock().expect("line").clone()
    }

    /// Bounded by `timeout_ms` from now until its answer begins; `0`, or a bound no instant can
    fn bounded(self, timeout_ms: u64) -> Self {
        if let Some(at) = due_at(std::time::Instant::now(), timeout_ms) {
            *self.due.lock().expect("due") = Some(Due::new(at));
        }
        self
    }

    fn watch_deadlines(&self, interest: DeadlineInterest, waker: &Waker) {
        let due = self.due.lock().expect("due").clone();
        let dial_due = self.dial_due.lock().expect("dial due").clone();
        for due in due.into_iter().chain(dial_due) {
            if std::time::Instant::now() < due.at {
                due.wake.register(interest, waker);
            }
        }
    }

    /// [`ConnError::Timeout`] once the bound has passed; subscribers are woken when it passes.
    fn within_due(&self) -> Result<(), ConnError> {
        let due = self.due.lock().expect("due").clone();
        due.map_or(Ok(()), |d| d.check())
    }

    fn dial_bounded(self, timeout: Duration) -> Self {
        if let Some(at) = std::time::Instant::now().checked_add(timeout) {
            *self.dial_due.lock().expect("dial due") = Some(Due::new(at));
        }
        self
    }

    fn within_dial_due(&self) -> Result<(), ConnError> {
        let due = self.dial_due.lock().expect("dial due").clone();
        due.map_or(Ok(()), |d| d.check())
    }

    fn landed(&self) {
        let due = self.dial_due.lock().expect("dial due").take();
        if let Some(due) = &due {
            due.cancel();
        }
        drop(due);
    }

    /// The answer began: the bound is spent.
    fn answered(&self) {
        let due = self.due.lock().expect("due").take();
        if let Some(due) = &due {
            due.cancel();
        }
        drop(due);
        self.landed();
    }

    /// A terminal judgement, dial or replay spends the bound too: a later deadline cannot
    fn fail(
        &self,
        mut judging: std::sync::MutexGuard<'_, Option<Judging>>,
        error: ConnError,
    ) -> ConnError {
        if let Some(j) = judging.as_mut() {
            j.failed = Some(error);
        }
        drop(judging);
        self.answered();
        error
    }
}

impl Drop for Held {
    /// A lease no one closed (its owner dropped it) is closed as it goes: the member's program does
    fn drop(&mut self) {
        if let Some((member, lease)) = self.lease.take() {
            member.close(lease);
        }

        if let Some(d) = &self.dialled {
            d.close();
        }
    }
}

impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Held").finish_non_exhaustive()
    }
}

/// A need as an instance declared it, whole, and the answer its declaration got.
type Declared = (ReadNeed, Result<(), ConnError>);

type TlsPolicy = (
    Arc<rustls::ClientConfig>,
    busbar_contract::transport::trust::EgressTrust,
);

/// THE CONNECTOR: the host side of the connection table.
pub struct Connector {
    slab: ConnSlab<Held>,
    /// The transport each declared need names, the egress class its dials are judged under, and
    over: Mutex<HashMap<(InstanceId, NeedId), DeclaredNeed>>,
    /// Every need an instance declared through [`DeclaredConns::declare`], whole, and the answer
    declared: Mutex<HashMap<(InstanceId, NeedId), Declared>>,
    transports: RwLock<Transports>,
    tls: Option<Arc<rustls::ClientConfig>>,
    tls_policy: Option<busbar_contract::transport::trust::EgressTrust>,
    wake: WakeTicket,
    judge: Arc<dyn DialJudge>,
    /// One listener per inbound need.
    listeners: Listeners,
    /// The per-worker pools of dialled connections.
    pools: Pools,
    /// The trust anchors each sealed destination's connections are held to.
    anchored: Anchored,
    /// The trust anchors each sealed REGISTRATION's own connections are held to: two registrations
    member_anchored: MemberAnchored,
    /// The registrations' seals at each destination, by the need's owner, the need and the
    registered: Mutex<HashMap<(InstanceId, NeedId, String), Registered>>,
    /// The REGISTRATIONS holding a PRIVATE REACH (`abi::plane::TRUST_PRIVATE_REACH`), by the need's
    reaching: Mutex<HashMap<(InstanceId, NeedId, String), String>>,
    /// Each member's auth binding: what a plugin's own request naming that member is authenticated
    auths: Mutex<HashMap<AuthKey, busbar_contract::conn::ConnAuth>>,
    /// The instances whose connections' authority the host writes
    authority_held: Mutex<HashSet<InstanceId>>,
    /// THE HOST'S I/O every carrier is served from ([`hostio`]): the one holder of OS handles.
    io: Arc<HostIo>,
    /// THE PROXY ENVIRONMENT every framed dial honours ([`proxy`]); `None` = every dial direct.
    proxy: Option<Arc<proxy::ProxyChoice>>,
    /// THE SESSION BOOK: each held session's [`datagram::Pairing`], by its kernel-minted unit key
    pairs: Mutex<HashMap<u64, Arc<datagram::Pairing>>>,
    /// HOW A PROGRAM'S ENVIRONMENT REFERENCES RESOLVE ([`spawn_env`]): the resolver the composition
    spawn_secrets: Option<spawn_env::SpawnSecretFn>,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector").finish_non_exhaustive()
    }
}

impl Default for Connector {
    fn default() -> Self {
        Self {
            slab: ConnSlab::default(),
            over: Mutex::new(HashMap::new()),
            declared: Mutex::new(HashMap::new()),
            transports: RwLock::new(Transports::default()),
            tls: None,
            tls_policy: None,
            wake: Arc::new(|_, _| {}),
            judge: Arc::new(LiteralsOnly(guard::Guard::default())),
            listeners: Mutex::new(HashMap::new()),
            pools: Pools::new(PoolPosture::NONE),
            anchored: Mutex::new(HashMap::new()),
            member_anchored: Mutex::new(HashMap::new()),
            registered: Mutex::new(HashMap::new()),
            reaching: Mutex::new(HashMap::new()),
            auths: Mutex::new(HashMap::new()),
            authority_held: Mutex::new(HashSet::new()),
            io: hostio::process(),
            proxy: None,
            pairs: Mutex::new(HashMap::new()),
            spawn_secrets: None,
        }
    }
}

struct TicketWake {
    wake: WakeTicket,
    /// The caller whose ticket this is.
    owner: InstanceId,
    ticket: Ticket,
}

impl Wake for TicketWake {
    fn wake(self: Arc<Self>) {
        (self.wake)(self.owner, self.ticket);
    }
}

pub(crate) fn map(f: &Failure) -> ConnError {
    match f {
        Failure::Pending => ConnError::Pending,
        Failure::Refused(_) => ConnError::Refused,
        Failure::Timeout => ConnError::Timeout,
        Failure::Closed => ConnError::Closed,
        Failure::Failed(_) => ConnError::Fault,
    }
}

fn class(code: u8) -> Option<WireStatusClass> {
    use busbar_contract::abi::transport::{
        STATUS_CALLER_FAULT, STATUS_FAR_END_FAULT, STATUS_OTHER, STATUS_SUCCESS,
    };
    match code {
        STATUS_SUCCESS => Some(WireStatusClass::Success),
        STATUS_CALLER_FAULT => Some(WireStatusClass::CallerFault),
        STATUS_FAR_END_FAULT => Some(WireStatusClass::FarEndFault),
        STATUS_OTHER => Some(WireStatusClass::Other),
        _ => None,
    }
}

impl Connector {
    /// A connector holding no connection, no declared need and no transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The same connector serving `transports`, judging every dial's address through `judge`,
    #[must_use]
    pub fn serving(
        transports: Transports,
        judge: Arc<dyn DialJudge>,
        tls: Option<Arc<rustls::ClientConfig>>,
        wake: WakeTicket,
    ) -> Self {
        Self {
            transports: RwLock::new(transports),
            tls,
            wake,
            judge,
            ..Self::default()
        }
    }

    /// A connector with explicit TLS policy provenance, permitting member-local CA additions.
    pub fn serving_with_trust(
        transports: Transports,
        judge: Arc<dyn DialJudge>,
        trust: busbar_contract::transport::trust::EgressTrust,
        wake: WakeTicket,
    ) -> Result<Self, tls::client::BadClientIdentity> {
        let config = Arc::new(tls::client::build_client_config(&trust)?);
        let mut connector = Self::serving(transports, judge, Some(config), wake);
        connector.tls_policy = Some(trust);
        Ok(connector)
    }

    /// The same connector resolving its programs' environment references through `secrets`, at
    #[must_use]
    pub fn resolving_spawn_secrets(mut self, secrets: spawn_env::SpawnSecretFn) -> Self {
        self.spawn_secrets = Some(secrets);
        self
    }

    /// The host I/O this connector's carriers are served from.
    #[must_use]
    pub fn io(&self) -> &Arc<HostIo> {
        &self.io
    }

    /// THE CARRIER OF A NETWORK ADDRESS, as a connection rides it: the first loaded carrier whose
    #[must_use]
    pub fn address_via(&self) -> Option<Via> {
        let view = self.transports.read().expect("transports");
        view.address_carrier().map(|e| Via {
            door: Arc::clone(&e.door),
            io: Arc::clone(&self.io),
        })
    }

    /// What a need served by `door` rides: a CARRIER is carried as itself (no framer); a FRAMER
    fn ride_on(&self, door: &Arc<dyn FramerDoor>) -> Option<(Option<Arc<dyn FramerDoor>>, Via)> {
        if door.facts().role == ROLE_CARRIER {
            return Some((
                None,
                Via {
                    door: Arc::clone(door),
                    io: Arc::clone(&self.io),
                },
            ));
        }
        self.address_via().map(|via| (Some(Arc::clone(door)), via))
    }

    /// A dial of `dial` over the entry `door` serves, located: the framer's `locate`, or a carrier
    fn plan(&self, door: &Arc<dyn FramerDoor>, dial: Dial) -> Result<Planned, Failure> {
        match self.ride_on(door) {
            Some((Some(framer), via)) => Planned::locate(framer, via, dial),
            Some((None, via)) => Planned::carried(via, dial),
            None => Err(Failure::Refused(
                "no carrier is loaded to reach an address".into(),
            )),
        }
    }

    /// The framer `owner`'s `need` rides, located at `target` (empty = the need's own, as an open
    fn framer_head(&self, owner: InstanceId, need: NeedId, target: &str) -> HeadDefaults {
        let need = self
            .over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .map(|n| {
                (
                    Arc::clone(&n.door),
                    n.declared_target.clone().filter(|_| target.is_empty()),
                )
            });
        need.and_then(|(door, declared)| self.located(&door, declared.as_deref().unwrap_or(target)))
            .map(|located| HeadDefaults {
                lines: located.defaults,
                states_length: located.states_length,
            })
            .unwrap_or_default()
    }

    /// Where `target` goes, per the entry `door` serves: its authority, security and name.
    fn located(&self, door: &Arc<dyn FramerDoor>, target: &str) -> Option<framer::Located> {
        if door.facts().role == ROLE_CARRIER {
            let claim = door.facts().claims.first().copied().unwrap_or_default();
            return compose::carried_at(claim, target).ok();
        }
        framer::locate(door.as_ref(), target).ok()
    }

    /// The same connector dialling every framed connection through the proxy `config` selects for
    #[must_use]
    pub fn proxying(mut self, config: Option<Arc<proxy::ProxyChoice>>) -> Self {
        self.proxy = config;
        self
    }

    /// Publish the effective boot's validated transport view, listener ports and pool posture
    pub fn finalize_boot_metadata(
        &self,
        transports: Transports,
        own_ports: &[u16],
        posture: PoolPosture,
    ) {
        self.judge.own_ports_applied(own_ports);
        self.pools.reconfigure(posture);
        let previous = std::mem::replace(
            &mut *self.transports.write().expect("transports"),
            transports,
        );
        drop(previous);
    }

    /// The proxy a dial of `planned` goes through: a framed dial (never a carrier carried as
    fn tunnel_for(&self, planned: &Planned, within: &[IpAddr]) -> Option<Arc<proxy::ProxyHop>> {
        if !planned.framed() || !within.is_empty() {
            return None;
        }
        self.proxy
            .as_ref()?
            .select(planned.secure(), proxy::host_of(planned.authority()))
    }

    /// Judge `dest` under `class` (with the need's private reach when `reach`), the pended answer
    fn judge_into(
        &self,
        dest: &str,
        class: u32,
        reach: bool,
        answer: &Answer,
    ) -> Option<Result<SocketAddr, Verdict>> {
        let answering = Arc::clone(answer);
        let done: JudgedAll = Box::new(move |v, also| {
            let waiting = {
                let mut a = answering.lock().expect("judgement");
                a.0 = Some(v);
                a.2 = also;
                a.1.take()
            };
            if let Some(w) = waiting {
                w.wake();
            }
        });
        self.judge.judge_dial_all(dest, class, reach, done)
    }

    /// The same connector keeping dialled connections under `posture` (the deployment's
    #[must_use]
    pub fn pooling(mut self, posture: PoolPosture) -> Self {
        self.pools = Pools::new(posture);
        self
    }

    /// The need `owner` declared as `need`, whole, as [`DeclaredConns::declare`] received it.
    #[must_use]
    pub fn declared_spec(&self, owner: InstanceId, need: NeedId) -> Option<ReadNeed> {
        let declared = self.declared.lock().expect("declared needs");
        declared.get(&(owner, need)).map(|(spec, _)| spec.clone())
    }

    /// Record that `owner` declared `need` — the only needs it may open. A need declared without a
    pub fn declare(&self, owner: InstanceId, need: NeedId) {
        self.slab.declare(owner, need);
    }

    /// Whether a loaded transport entry serves `transport` (a scheme).
    #[must_use]
    pub fn serves_scheme(&self, transport: &str) -> bool {
        self.transports
            .read()
            .expect("transports")
            .serving(transport)
            .is_some()
    }

    /// The framer entry that answers `scheme`, where a loaded one does: what frames a stream that
    #[must_use]
    pub fn framer_for(&self, scheme: &str) -> Option<Arc<dyn framer::FramerDoor>> {
        self.transports
            .read()
            .expect("transports")
            .serving(scheme)
            .map(|s| Arc::clone(&s.entry.door))
    }

    /// Record that `owner` declared `need` over `transport` (a scheme the registry view serves), in
    pub fn declare_over(
        &self,
        owner: InstanceId,
        need: NeedId,
        transport: &str,
    ) -> Result<(), ConnError> {
        self.declare_need(owner, need, transport, DEFAULT_CLASS)
    }

    /// Record that `owner` declared `need` over `transport`, its dials judged under the need's own
    pub fn declare_need(
        &self,
        owner: InstanceId,
        need: NeedId,
        transport: &str,
        egress_class: u32,
    ) -> Result<(), ConnError> {
        self.record(owner, need, transport, egress_class, None, None)
    }

    /// Record that `owner` declared `need` over `transport` in `egress_class`, its target named by
    pub fn declare_need_to(
        &self,
        owner: InstanceId,
        need: NeedId,
        transport: &str,
        egress_class: u32,
        declared_target: &str,
    ) -> Result<(), ConnError> {
        self.record(
            owner,
            need,
            transport,
            egress_class,
            Some(declared_target),
            None,
        )
    }

    /// THE SCHEME MATCH: the need is recorded over the entry serving `transport`, resolved here
    fn record(
        &self,
        owner: InstanceId,
        need: NeedId,
        transport: &str,
        egress_class: u32,
        declared_target: Option<&str>,
        security: Option<TlsPolicy>,
    ) -> Result<(), ConnError> {
        let (tls, tls_policy) = security.map_or((None, None), |(config, policy)| {
            (Some(config), Some(policy))
        });
        let served = {
            let view = self.transports.read().expect("transports");
            view.serving(transport)
                .map(|served| (Arc::clone(&served.entry.door), served.entry.alpn.clone()))
        };
        let Some((door, alpn)) = served else {
            self.set_need(owner, need, None);
            return Err(ConnError::Refused);
        };
        self.slab.declare(owner, need);
        self.set_need(
            owner,
            need,
            Some(DeclaredNeed {
                door,
                alpn,
                egress_class,
                declared_target: declared_target.map(str::to_owned),
                tls,
                tls_policy,
                program: None,
                members: None,
                member_spec: None,
            }),
        );
        Ok(())
    }

    /// THE ADMISSION OF A PINNED TARGET (FAIL-CLOSED: the verdict `need_admit` reports is the one
    fn admits_pinned(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        egress_class: u32,
    ) -> Result<(), ConnError> {
        let door = self
            .over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .map(|n| Arc::clone(&n.door))
            .ok_or(ConnError::Refused)?;
        endpoint::named(target).map_err(|_| ConnError::Refused)?;
        let located = self.located(&door, target).ok_or(ConnError::Refused)?;
        endpoint::named(&located.authority).map_err(|_| ConnError::Refused)?;
        if !scheme_admits(egress_class, located.secure) {
            return Err(ConnError::Refused);
        }
        let judged_class = guard::judged_class(egress_class, true);
        if self
            .judge
            .judge_static(&located.authority, judged_class)
            .is_some()
        {
            return Err(ConnError::Refused);
        }
        if socket::address_of(&located.authority).is_some() {
            match self
                .judge
                .judge_dial(&located.authority, judged_class, Box::new(|_| {}))
            {
                Some(Ok(addr))
                    if class_admits(
                        egress_class,
                        located.secure,
                        &[],
                        &located.authority,
                        addr,
                    ) => {}
                Some(_) => return Err(ConnError::Refused),
                None => {}
            }
        }
        Ok(())
    }

    /// Record (or, with `None`, drop) what the connector holds for `owner`'s `need`: a member of an
    fn set_need(&self, owner: InstanceId, need: NeedId, record: Option<DeclaredNeed>) {
        let before = {
            let mut over = self.over.lock().expect("needs");
            match record {
                Some(r) => over.insert((owner, need), r),
                None => over.remove(&(owner, need)),
            }
        };
        // Final declaration custody can retire a child and invoke the carrier. Never do so
        // while holding the connector's declaration map lock.
        drop(before);
    }

    /// THE MEMBER-PROGRAM NEED (`busbar_contract::section::MEMBER_PROGRAM`): `owner`'s outbound
    fn record_members(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        programs: &[(String, busbar_contract::conn::Program)],
        scope: &busbar_contract::config_time::ConfigScope,
        predecessor: Option<InstanceId>,
    ) -> Result<(), ConnError> {
        let served = {
            let view = self.transports.read().expect("transports");
            view.serving(&spec.transport)
                .filter(|served| served.entry.door.facts().role == ROLE_CARRIER)
                .map(|served| (Arc::clone(&served.entry.door), served.entry.alpn.clone()))
        };
        let carried = spec.direction == DIRECTION_OUTBOUND
            && spec.egress_class == EGRESS_OPERATOR_INFRASTRUCTURE
            && spec.auth.is_empty()
            && busbar_contract::section::member_program(&spec.target_from)
            && programs
                .iter()
                .all(|(_, p)| std::path::Path::new(&p.command).is_absolute());
        let Some((door, alpn)) = served.filter(|_| carried) else {
            self.set_need(owner, need, None);
            return Err(ConnError::Refused);
        };
        let before = {
            let over = self.over.lock().expect("needs");
            // An existing successor can only redeclare its own members, never select a
            // different predecessor. Provenance is used once for a fresh generation.
            let source = over.get(&(owner, need)).or_else(|| {
                predecessor
                    .filter(|previous| *previous != owner)
                    .and_then(|previous| over.get(&(previous, need)))
            });
            source
                .filter(|d| d.member_spec.as_ref() == Some(spec))
                .and_then(|d| d.members.clone())
        };
        let members: program::Members = programs
            .iter()
            .map(|(name, p)| {
                let kept = before
                    .as_ref()
                    .and_then(|b| b.get(name))
                    .filter(|m| m.program() == p)
                    .cloned();

                if let Some(kept) = &kept {
                    kept.env().reload(scope);
                }
                let member = match kept {
                    Some(kept) => kept,
                    None => Arc::new(program::Declaration::new(program::Member::new(
                        p.clone(),
                        spawn_env::HeldEnv::load(&p.env_refs, self.spawn_secrets, scope),
                        Via {
                            door: Arc::clone(&door),
                            io: Arc::clone(&self.io),
                        },
                        alpn.clone(),
                    )?)),
                };
                Ok((name.clone(), member))
            })
            .collect::<Result<_, ConnError>>()?;
        self.slab.declare(owner, need);
        self.set_need(
            owner,
            need,
            Some(DeclaredNeed {
                door,
                alpn,
                egress_class: spec.egress_class,
                declared_target: None,
                tls: None,
                tls_policy: None,
                program: None,
                members: Some(Arc::new(members)),
                member_spec: Some(spec.clone()),
            }),
        );
        Ok(())
    }

    /// THE PROGRAM NEED: `owner`'s outbound `need` dials `program` (its pipes, framed by the entry
    fn record_program(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        program: &busbar_contract::conn::Program,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<(), ConnError> {
        let served = {
            let view = self.transports.read().expect("transports");
            view.serving(&spec.transport)
                .filter(|served| served.entry.door.facts().role == ROLE_CARRIER)
                .map(|served| (Arc::clone(&served.entry.door), served.entry.alpn.clone()))
        };
        let carried = spec.direction == DIRECTION_OUTBOUND
            && spec.egress_class == EGRESS_OPERATOR_INFRASTRUCTURE
            && spec.auth.is_empty()
            && std::path::Path::new(&program.command).is_absolute();
        let Some((door, alpn)) = served.filter(|_| carried) else {
            self.set_need(owner, need, None);
            return Err(ConnError::Refused);
        };
        self.slab.declare(owner, need);
        self.set_need(
            owner,
            need,
            Some(DeclaredNeed {
                door,
                alpn,
                egress_class: spec.egress_class,
                declared_target: None,
                tls: None,
                tls_policy: None,
                program: Some((
                    program.clone(),
                    spawn_env::HeldEnv::load(&program.env_refs, self.spawn_secrets, scope),
                )),
                members: None,
                member_spec: None,
            }),
        );
        Ok(())
    }

    /// Bind the one listener for `owner`'s INBOUND `need` on `bind` (`ip:port`), over the transport
    pub fn listen(
        &self,
        owner: InstanceId,
        need: NeedId,
        bind: &str,
        tls: Option<Arc<rustls::ServerConfig>>,
        limits: AcceptLimits,
    ) -> Result<SocketAddr, ConnError> {
        self.slab.check_need(owner, need)?;

        let (door, registered) = self
            .over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .map(|d| (Arc::clone(&d.door), d.alpn.clone()))
            .ok_or(ConnError::Refused)?;

        let alpn = match framer::accept_offer(door.as_ref()) {
            Ok(offer) if !offer.is_empty() => offer,
            Ok(_) => registered,
            Err(refused) => {
                tracing::warn!(
                    owner = owner.0,
                    need = need.0,
                    error = %refused,
                    "inbound listener: the entry's locate refused the accepting-side protocol \
                     offer; the listener binds with the transport's registered protocol list"
                );
                registered
            }
        };

        let held = Arc::new(Accepting::default());
        {
            let mut listeners = self.listeners.lock().expect("listeners");
            if listeners.contains_key(&(owner, need)) {
                return Err(ConnError::Refused);
            }
            listeners.insert((owner, need), Arc::clone(&held));
        }
        let bound = self
            .ride_on(&door)
            .ok_or(ConnError::Refused)
            .and_then(|(framer, via)| {
                Listening::bind(framer, &via, bind, tls, alpn, limits).map_err(|error| {
                    tracing::warn!(
                        owner = owner.0,
                        need = need.0,
                        kind = ?error.kind(),
                        "inbound listener bind failed"
                    );
                    ConnError::Fault
                })
            });
        match bound {
            Ok(l) => {
                let addr = l.local_addr();
                held.put(Some(l));
                Ok(addr)
            }
            Err(e) => {
                let gone = {
                    let mut listeners = self.listeners.lock().expect("listeners");
                    let ours = listeners
                        .get(&(owner, need))
                        .is_some_and(|a| Arc::ptr_eq(a, &held));
                    ours.then(|| listeners.remove(&(owner, need))).flatten()
                };
                drop(gone);
                held.put(None);
                Err(e)
            }
        }
    }

    /// The next connection `owner`'s inbound `need` admitted, held for `owner` like one it
    pub fn accept(
        &self,
        owner: InstanceId,
        need: NeedId,
        ticket: Ticket,
    ) -> Result<(ConnId, SocketAddr), ConnError> {
        self.slab.check_need(owner, need)?;
        let l = self
            .listeners
            .lock()
            .expect("listeners")
            .get(&(owner, need))
            .cloned()
            .ok_or(ConnError::Refused)?;
        let waker = self.waker(owner, ticket);
        let Some(listening) = l.take(&waker) else {
            return Err(ConnError::Pending);
        };
        let mut out = AcceptingOut {
            home: &l,
            listening: Some(listening),
        };
        let got = out
            .listening
            .as_mut()
            .expect("the listener is out")
            .poll_accept(&mut Context::from_waker(&waker));
        drop(out);
        match got {
            Poll::Pending => Err(ConnError::Pending),
            Poll::Ready(Err(f)) => Err(map(&f)),
            Poll::Ready(Ok(a)) => {
                let line = Line::new(a.conn);
                let id =
                    self.slab
                        .insert(owner, need, Held::over(Some((line, EVERY)), None, None))?;
                Ok((id, a.peer))
            }
        }
    }

    /// Offer `bytes` on `stream` of `caller`'s connection `conn` (`end` = the stream's message is
    pub fn emit(
        &self,
        caller: InstanceId,
        conn: ConnId,
        stream: u64,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        if !self.settle(&held, None)? {
            return Err(ConnError::Pending);
        }
        let (line, _) = held.line().ok_or(ConnError::Closed)?;
        line.emit(stream, bytes, end, text).map_err(|f| map(&f))
    }

    /// Dial a held connection whose judgement has answered and replay its accepted writes.
    fn settle(&self, held: &Held, waker: Option<&Waker>) -> Result<bool, ConnError> {
        let ready = self.settle_dial(held, waker)?;

        if self.observe_landing(held, waker.unwrap_or_else(|| Waker::noop()))? && !ready {
            if let Some(waker) = waker {
                waker.wake_by_ref();
            }
        }
        Ok(ready)
    }

    fn settle_dial(&self, held: &Held, waker: Option<&Waker>) -> Result<bool, ConnError> {
        if held.retired.load(Ordering::Acquire) {
            return Err(ConnError::Closed);
        }
        held.within_dial_due()?;
        let mut wake = waker.cloned();
        let mut judging = held.judging.lock().expect("judging");
        if held.retired.load(Ordering::Acquire) {
            return Err(ConnError::Closed);
        }
        {
            let mut crossing = held.crossing.lock().expect("crossing");
            if let Some(waiting) = crossing.as_mut() {
                if wake
                    .as_ref()
                    .is_some_and(|w| !waiting.iter().any(|x| x.will_wake(w)))
                {
                    waiting.push(wake.take().expect("the waiting caller"));
                }
                return Ok(false);
            }
        }
        let Some(j) = judging.as_mut() else {
            return Ok(true);
        };
        if let Some(error) = j.failed {
            return Err(error);
        }
        if j.planned.is_none() {
            let crossing = Crossing::begin(held, judging);
            return crossing.finish(self.replay_early(held, waker));
        }
        let (got, also) = {
            let mut a = j.answer.lock().expect("judgement");
            match a.0 {
                None => {
                    let previous = if wake.is_some() {
                        std::mem::replace(&mut a.1, wake.take())
                    } else {
                        None
                    };
                    drop(a);
                    drop(judging);
                    drop(previous);
                    return Ok(false);
                }
                Some(got) => (got, std::mem::take(&mut a.2)),
            }
        };
        let secure = j.planned.as_ref().is_some_and(Planned::secure);
        let target = j
            .planned
            .as_ref()
            .map_or_else(String::new, |p| p.authority().to_owned());
        if let Some(p) = j.proxied.as_mut() {
            if !p.target_judged {
                match got {
                    Err(v) if !unresolved_here(v) => {
                        return Err(held.fail(judging, pended_verdict(v)));
                    }
                    Ok(at) if !class_admits(j.egress_class, secure, &[], &target, at) => {
                        return Err(held.fail(judging, ConnError::Refused));
                    }
                    _ => {}
                }
                p.target_judged = true;
                let spec = Arc::clone(&p.spec);
                let class = p.judged_class;
                let answer = Arc::clone(&j.answer);
                let previous = {
                    let mut a = j.answer.lock().expect("judgement");
                    a.0 = None;
                    if wake.is_some() {
                        std::mem::replace(&mut a.1, wake.take())
                    } else {
                        None
                    }
                };
                let crossing = Crossing::begin(held, judging);
                return crossing.finish((|| {
                    drop(previous);
                    if held.retired.load(Ordering::Acquire) {
                        return Err(ConnError::Closed);
                    }
                    let proxy_judged = self.judge_into(&spec.endpoint(), class, true, &answer);
                    if held.retired.load(Ordering::Acquire) {
                        return Err(ConnError::Closed);
                    }
                    let proxy_addr = match proxy_judged {
                        None => return Ok(false),
                        Some(Err(v)) => return Err(pended_verdict(v)),
                        Some(Ok(at)) => at,
                    };
                    let planned = {
                        let mut judging = held.judging.lock().expect("judging");
                        if held.retired.load(Ordering::Acquire) {
                            return Err(ConnError::Closed);
                        }
                        judging
                            .as_mut()
                            .and_then(|j| j.planned.take())
                            .ok_or(ConnError::Closed)?
                    };
                    self.settle_proxy(held, planned, &spec, proxy_addr, waker)
                })());
            }
            let proxy_addr = match got {
                Ok(at) => at,
                Err(v) => return Err(held.fail(judging, pended_verdict(v))),
            };
            let spec = Arc::clone(&p.spec);
            let planned = j.planned.take().ok_or(ConnError::Refused)?;
            let crossing = Crossing::begin(held, judging);
            return crossing.finish(self.settle_proxy(held, planned, &spec, proxy_addr, waker));
        }
        let addr = match got {
            Ok(at) => at,
            Err(v) => return Err(held.fail(judging, pended_verdict(v))),
        };
        if !class_admits(j.egress_class, secure, &j.within, &target, addr) {
            return Err(held.fail(judging, ConnError::Refused));
        }

        let also: Vec<SocketAddr> = also
            .into_iter()
            .filter(|&at| class_admits(j.egress_class, secure, &j.within, &target, at))
            .collect();
        let planned = j.planned.take().ok_or(ConnError::Refused)?;
        let crossing = Crossing::begin(held, judging);
        crossing.finish((|| {
            let conn = planned.dial_at_any(addr, also).map_err(|f| map(&f))?;
            self.ride(held, conn)?;
            self.replay_early(held, waker)
        })())
    }

    /// Complete a proxy dial while the crossing owns its plan and no judgement guard is held.
    fn settle_proxy(
        &self,
        held: &Held,
        planned: Planned,
        spec: &proxy::ProxyHop,
        proxy_addr: SocketAddr,
        waker: Option<&Waker>,
    ) -> Result<bool, ConnError> {
        let connect = proxy::connect_request(planned.authority(), spec);
        let conn = planned
            .dial_through(proxy_addr, connect)
            .map_err(|f| map(&f))?;
        self.ride(held, conn)?;
        self.replay_early(held, waker)
    }

    /// Replay accepted writes in order, retaining each unaccepted suffix across backpressure.
    fn replay_early(&self, held: &Held, waker: Option<&Waker>) -> Result<bool, ConnError> {
        let (line, stream) = held.line().ok_or(ConnError::Closed)?;
        let mut remaining = held
            .judging
            .lock()
            .expect("judging")
            .as_ref()
            .map_or(0, |j| j.early.len());
        loop {
            if held.retired.load(Ordering::Acquire) {
                return Err(ConnError::Closed);
            }
            if remaining == 0 {
                let mut judging = held.judging.lock().expect("judging");
                if judging.as_ref().is_none_or(|j| j.early.is_empty()) {
                    let finished = judging.take();
                    drop(judging);
                    drop(finished);
                    return Ok(true);
                }

                drop(judging);
                if let Some(waker) = waker {
                    waker.wake_by_ref();
                }
                return Ok(false);
            }
            let next = {
                let mut judging = held.judging.lock().expect("judging");
                let Some(j) = judging.as_ref() else {
                    return Ok(true);
                };
                match j.early.front().cloned() {
                    Some(next) => next,
                    None => {
                        let finished = judging.take();
                        drop(judging);
                        drop(finished);
                        return Ok(true);
                    }
                }
            };
            let (bytes, end, text) = next;
            let emitted = line.emit_waking(stream, &bytes, end, text, waker);
            if held.retired.load(Ordering::Acquire) {
                return Err(ConnError::Closed);
            }
            let took = match emitted {
                Err(Failure::Pending) => return Ok(false),
                Err(f) => return Err(map(&f)),
                Ok(0) if !bytes.is_empty() => return Ok(false),
                Ok(took) => took,
            };
            let mut judging = held.judging.lock().expect("judging");
            let j = judging.as_mut().expect("the crossing owns replay");
            if took == bytes.len() {
                j.early.pop_front();
                remaining -= 1;
            } else {
                j.early.front_mut().expect("the replayed write").0 = bytes.slice(took..);
            }
        }
    }

    /// `held` rides `conn`, just dialled, as its first exchange; a pooled exchange's line is held
    fn ride(&self, held: &Held, mut conn: Connection) -> Result<Arc<Line>, ConnError> {
        let at = held
            .dial_due
            .lock()
            .expect("dial due")
            .as_ref()
            .map(|due| due.at);
        if let Some(at) = at {
            conn.bound_open(at);
        }
        let line = Line::new(conn);
        let mut home = held.line.lock().expect("line");
        if held.retired.load(Ordering::Acquire) {
            drop(home);
            line.close();
            return Err(ConnError::Closed);
        }
        if let Some((shard, key)) = &held.pooled {
            self.pools.hold(*shard, key.clone(), &line);
        }
        *home = Some((Arc::clone(&line), EXCHANGE_STREAM));
        Ok(line)
    }

    /// Judge `planned`'s authority under `judged_class` and dial the pinned address, held to the
    fn dial_judged(
        &self,
        planned: Planned,
        egress_class: u32,
        judged_class: u32,
        within: &[IpAddr],
        reach: bool,
    ) -> Result<(Option<Connection>, Option<Judging>), ConnError> {
        let answer: Answer = Arc::new(Mutex::new((None, None, Vec::new())));

        let judged = self.judge_into(planned.authority(), judged_class, reach, &answer);

        if let Some(spec) = self.tunnel_for(&planned, within) {
            let mut proxied = Proxied {
                spec,
                judged_class,
                target_judged: false,
            };
            match judged {
                None => {
                    return Ok((
                        None,
                        Some(Judging {
                            planned: Some(planned),
                            failed: None,
                            egress_class,
                            within: Vec::new(),
                            early: VecDeque::new(),
                            answer,
                            proxied: Some(proxied),
                        }),
                    ));
                }
                Some(Err(v)) if !unresolved_here(v) => return Err(ConnError::Refused),
                Some(Ok(at))
                    if !class_admits(
                        egress_class,
                        planned.secure(),
                        &[],
                        planned.authority(),
                        at,
                    ) =>
                {
                    return Err(ConnError::Refused);
                }
                Some(_) => {}
            }
            proxied.target_judged = true;
            let answer: Answer = Arc::new(Mutex::new((None, None, Vec::new())));
            let proxy_authority = proxied.spec.endpoint();
            return match self.judge_into(&proxy_authority, judged_class, true, &answer) {
                None => Ok((
                    None,
                    Some(Judging {
                        planned: Some(planned),
                        failed: None,
                        egress_class,
                        within: Vec::new(),
                        early: VecDeque::new(),
                        answer,
                        proxied: Some(proxied),
                    }),
                )),
                Some(Err(_)) => Err(ConnError::Refused),
                Some(Ok(at)) => {
                    let connect = proxy::connect_request(planned.authority(), &proxied.spec);
                    let conn = planned.dial_through(at, connect).map_err(|f| map(&f))?;
                    Ok((Some(conn), None))
                }
            };
        }
        Ok(match judged {
            Some(Err(_)) => return Err(ConnError::Refused),
            Some(Ok(addr))
                if !class_admits(
                    egress_class,
                    planned.secure(),
                    within,
                    planned.authority(),
                    addr,
                ) =>
            {
                return Err(ConnError::Refused);
            }
            Some(Ok(addr)) => (Some(planned.dial_at(addr).map_err(|f| map(&f))?), None),
            None => (
                None,
                Some(Judging {
                    planned: Some(planned),
                    failed: None,
                    egress_class,
                    within: within.to_vec(),
                    early: VecDeque::new(),
                    answer,
                    proxied: None,
                }),
            ),
        })
    }

    /// THE ONE REDIAL: `held` was lent a pooled line that failed before any byte of its exchange
    fn redial(&self, held: &Held) -> Result<bool, ConnError> {
        let mut kept = held.redial.lock().expect("redial");
        let mut home = held.line.lock().expect("line");
        if held.retired.load(Ordering::Acquire) {
            return Err(ConnError::Closed);
        }
        let Some((line, _)) = home.as_ref() else {
            return Ok(false);
        };
        if kept.as_ref().is_none_or(|r| line.flushed() != r.mark) {
            let spent = kept.take();
            drop(home);
            drop(kept);
            drop(spent);
            return Ok(false);
        }
        let Some(r) = kept.take() else {
            return Ok(false);
        };
        let (line, stream) = home.take().expect("the redial takes its old line once");
        drop(home);
        drop(kept);
        self.let_go(held, &line, stream, false);
        let at = std::time::Instant::now()
            .checked_add(r.dial.open_timeout)
            .map(Due::new);
        let previous = std::mem::replace(&mut *held.dial_due.lock().expect("dial due"), at);
        drop(previous);
        let planned = self.plan(&r.door, r.dial).map_err(|f| map(&f))?;
        if r.require_secure && !planned.secure() {
            return Err(ConnError::AuthRefused);
        }
        match self.dial_judged(planned, r.egress_class, r.judged_class, &[], r.reach)? {
            (Some(conn), _) => {
                self.ride(held, conn)?;
            }
            (None, judging) => *held.judging.lock().expect("judging") = judging,
        }
        Ok(true)
    }

    /// `held`'s exchange leaves `line` (`whole` = its answer was read to its end): the line goes
    fn let_go(&self, held: &Held, line: &Arc<Line>, stream: u64, whole: bool) {
        let left = line.leave(stream, whole);
        if left > 0 {
            return;
        }
        match &held.pooled {
            Some((shard, key)) if whole => self.pools.release(*shard, key, line),
            Some((shard, key)) => self.pools.drop_line(*shard, key, line),
            None => line.close(),
        }
    }

    /// One read of `conn`, waking `waker` when nothing is ready yet: the body [`Conns::read`] (a
    fn read_waking(
        &self,
        caller: InstanceId,
        conn: ConnId,
        waker: &Waker,
        interest: DeadlineInterest,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        held.watch_deadlines(interest, waker);

        held.within_due()?;
        let mut read = match &held.dialled {
            Some(d) => self.read_dialled(&held, d, waker, buf),
            None => self.read_held(&held, waker, buf),
        };
        if matches!(read, Err(ConnError::Pending)) {
            match self.observe_landing(&held, waker) {
                Ok(true) => waker.wake_by_ref(),
                Ok(false) => {}
                Err(error) => read = Err(error),
            }
        }

        if read
            .as_ref()
            .is_ok_and(|p| held.lease.is_none() || p.kind != PieceKind::Fields)
        {
            held.answered();
        }
        read
    }

    /// A read may finish the connect before any reply arrives. Retire its dial bound then,
    fn observe_landing(&self, held: &Held, waker: &Waker) -> Result<bool, ConnError> {
        if held.dial_due.lock().expect("dial due").is_none() {
            return Ok(false);
        }
        let Some((line, stream)) = held.line() else {
            return Ok(false);
        };
        match line.poll_landed(stream, &mut Context::from_waker(waker)) {
            Poll::Ready(Ok(())) => {
                held.landed();
                Ok(true)
            }
            Poll::Ready(Err(f)) => {
                held.answered();
                Err(map(&f))
            }
            Poll::Pending => Ok(false),
        }
    }

    /// One read of a held session's upstream leg: its exchange's pieces, judged (the far end's
    fn read_dialled(
        &self,
        held: &Held,
        d: &dialled::Dialled,
        waker: &Waker,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        while d.exchanging() {
            let piece = self.read_held(held, waker, buf)?;
            let len = piece.len.min(buf.len());
            if let Some(piece) = d.exchanged(piece, &buf[..len])? {
                return Ok(piece);
            }
        }
        d.read(waker, buf)
    }

    /// One read of `held`'s answer (see [`Self::read_waking`]).
    fn read_held(&self, held: &Held, waker: &Waker, buf: &mut [u8]) -> Result<Piece, ConnError> {
        if let Some((member, lease)) = &held.lease {
            return member.read(*lease, waker, buf);
        }
        let Some((mut reading, kept)) = Reading::begin(&held.rest, waker) else {
            return Err(ConnError::Pending);
        };
        let (piece, bytes) = match kept {
            Some(kept) => kept,
            None => {
                if reading.ended {
                    return Err(ConnError::Closed);
                }
                let got = loop {
                    if !self.settle(held, Some(waker))? {
                        return Err(ConnError::Pending);
                    }
                    let (line, stream) = held.line().ok_or(ConnError::Closed)?;
                    match line.poll_piece(stream, &mut Context::from_waker(waker)) {
                        Poll::Pending => return Err(ConnError::Pending),

                        Poll::Ready(Err(_) | Ok(None)) if self.redial(held)? => {}
                        Poll::Ready(Err(f)) => return Err(map(&f)),
                        Poll::Ready(Ok(None)) => {
                            reading.ended = true;
                            return Ok(completion(0));
                        }
                        Poll::Ready(Ok(Some(got))) => break (got, stream),
                    }
                };
                let (got, stream) = got;
                let dialled = stream != EVERY;

                *held.redial.lock().expect("redial") = None;
                if dialled && got.stream == stream && got.ends_stream() {
                    reading.ended = true;
                    held.whole.store(true, Ordering::Release);
                    return Ok(completion(got.stream));
                }
                if dialled && got.stream == stream && got.failed {
                    reading.ended = true;
                    return Err(ConnError::Fault);
                }

                if got.reason.is_some() {
                    held.reason.lock().expect("reason").clone_from(&got.reason);
                }
                (
                    Piece {
                        kind: if got.fields {
                            PieceKind::Fields
                        } else {
                            PieceKind::Body
                        },
                        stream: StreamId(got.stream),
                        len: 0,
                        end: got.end_of_frame,
                        status: class(got.status_class),
                        status_code: got.status_code,

                        status_namespace: got.handoff.then(|| {
                            busbar_contract::transport::registry::status_ns::HTTP.to_owned()
                        }),
                        retry_after_secs: got.retry_after_secs,
                        fault: WireFault::from_code(got.fault),
                        reason: None,
                        declared_len: got.declared_len,
                    },
                    got.bytes,
                )
            }
        };
        let n = bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        let mut out = piece.clone();
        out.len = n;
        if n < bytes.len() {
            out.end = false;
            reading.left = Some((piece, bytes[n..].to_vec()));
        } else if out.kind == PieceKind::Fields && out.end {
            if let Some(reason) = held.reason.lock().expect("reason").take() {
                if let Some(to) = buf.get_mut(n..n + reason.len()) {
                    to.copy_from_slice(&reason);
                    out.reason = Some(n..n + reason.len());
                }
            }
        }
        Ok(out)
    }

    /// The waker of `owner`'s `ticket`: it names `owner` when it wakes.
    fn waker(&self, owner: InstanceId, ticket: Ticket) -> Waker {
        if ticket == NO_TICKET {
            return Waker::noop().clone();
        }
        Waker::from(Arc::new(TicketWake {
            wake: Arc::clone(&self.wake),
            owner,
            ticket,
        }))
    }
}

/// The host name a dial target names: a URL's host, or a bare `host:port`'s host, unbracketed.
fn host_of(target: &str) -> String {
    if target.contains("://") {
        if let Ok(parts) = busbar_contract::net::parse_url(target) {
            return parts.host;
        }
    }
    let authority = target.split(['/', '?', '#']).next().unwrap_or(target);
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if !port.contains(']') => h,
        _ => authority,
    };
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned()
}

/// The piece that says the exchange finished.
fn completion(stream: u64) -> Piece {
    Piece {
        kind: PieceKind::Completion,
        stream: StreamId(stream),
        len: 0,
        end: true,
        status: None,
        status_code: None,
        status_namespace: None,
        retry_after_secs: None,
        fault: None,
        reason: None,
        declared_len: None,
    }
}

/// Whether a dial target carries a userinfo (`user:pass@`): a URL by the contract's one reader, a
fn carries_userinfo(target: &str) -> bool {
    match busbar_contract::net::parse_url(target) {
        Ok(parts) => parts.userinfo,
        Err(_) => target
            .split(['/', '?', '#'])
            .next()
            .is_some_and(|authority| authority.contains('@')),
    }
}

/// Whether a need's `target_from` reads its target from the plugin's OWN settings: one
fn settings_derived(target_from: &str) -> bool {
    target_from
        .strip_prefix("settings.")
        .is_some_and(|keys| keys.split('.').all(|k| !k.is_empty() && k != "*"))
}

/// `target` without its userinfo: the authority's text up to and including its last `@` left out,
fn without_userinfo(target: &str) -> Option<String> {
    let parts = busbar_contract::net::url_authority(target);
    parts.userinfo?;
    let scheme = parts.scheme.map(|s| format!("{s}://")).unwrap_or_default();
    Some(format!("{scheme}{}{}", parts.host_port, parts.tail))
}

impl DeclaredConns for Connector {
    fn open_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.open_timed(caller, need, desc, require_secure, Some(dial_timeout_ms))
    }

    fn hold_authority(&self, owner: InstanceId) {
        self.authority_held
            .lock()
            .expect("authority held")
            .insert(owner);
    }

    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        let outbound = spec.direction == DIRECTION_OUTBOUND;

        let per_member = |path: &str| busbar_contract::section::member_target(path).is_some();

        let optional_trust = busbar_contract::section::owned_path(&spec.trust_from).is_some()
            || spec.trust_from.starts_with("settings.");
        let unresolved =
            (!spec.target_from.is_empty() && !per_member(&spec.target_from) && target.is_none())
                || (!spec.trust_from.is_empty()
                    && !per_member(&spec.trust_from)
                    && !optional_trust
                    && trust.is_none());

        let cleared = target
            .filter(|t| settings_derived(&spec.target_from) && carries_userinfo(t))
            .and_then(without_userinfo);
        let target = cleared.as_deref().or(target);
        let credentialed = target.is_some_and(carries_userinfo);
        let anchored = match trust.filter(|_| outbound) {
            None => Ok(None),
            Some(pem) => tls::client::operator_ca_anchors(pem.as_bytes()).and_then(|roots| {
                let policy = busbar_contract::transport::trust::EgressTrust {
                    extra_anchors: roots,
                    ..Default::default()
                };
                tls::client::build_client_config(&policy)
                    .map(|config| Some((Arc::new(config), policy)))
                    .map_err(|e| e.to_string())
            }),
        };
        let answer = match anchored {
            Ok(_) if !outbound => {
                if !spec.transport.is_empty() && !self.serves_scheme(&spec.transport) {
                    Err(ConnError::Refused)
                } else {
                    self.slab.declare(owner, need);
                    Ok(())
                }
            }
            Ok(tls) if !(spec.transport.is_empty() || unresolved || credentialed) => self
                .record(owner, need, &spec.transport, spec.egress_class, target, tls)
                .and_then(|()| match target {
                    Some(pinned) => self
                        .admits_pinned(owner, need, pinned, spec.egress_class)
                        .inspect_err(|_| self.set_need(owner, need, None)),
                    None => Ok(()),
                }),
            _ => {
                self.set_need(owner, need, None);
                Err(ConnError::Refused)
            }
        };
        self.declared
            .lock()
            .expect("declared needs")
            .insert((owner, need), (spec.clone(), answer));
        answer
    }

    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        let declared = self.declared.lock().expect("declared needs");
        declared.get(&(owner, need)).map(|(_, answer)| *answer)
    }

    /// THE MID-STREAM UPGRADE: the connection, once dialled, is secured with the need's own client
    fn upgrade_secure(
        &self,
        caller: InstanceId,
        conn: ConnId,
        name: Option<&str>,
        trust: Option<&str>,
        verify_off: bool,
        ticket: Ticket,
    ) -> Result<(), ConnError> {
        let (need, held) = self.slab.get(caller, conn)?;
        if self.framed(caller, need) {
            return Err(ConnError::Refused);
        }
        let config = if verify_off {
            let class = self
                .over
                .lock()
                .expect("needs")
                .get(&(caller, need))
                .map(|d| d.egress_class);
            if class != Some(EGRESS_OPERATOR_INFRASTRUCTURE) {
                return Err(ConnError::Refused);
            }
            Arc::new(crate::tls::client::unverified_client_config())
        } else {
            let declared = self.declared.lock().expect("declared needs");
            let trust_from = declared
                .get(&(caller, need))
                .map(|(spec, _)| spec.trust_from.as_str());
            if trust.is_some_and(|t| Some(t) != trust_from) {
                return Err(ConnError::Refused);
            }
            let over = self.over.lock().expect("needs");
            over.get(&(caller, need))
                .and_then(|d| d.tls.clone())
                .or_else(|| self.tls.clone())
                .ok_or(ConnError::Refused)?
        };
        let waker = self.waker(caller, ticket);
        held.watch_deadlines(DeadlineInterest::Ticket(ticket), &waker);
        if !self.settle(&held, Some(&waker))? {
            return Err(ConnError::Pending);
        }
        let (line, _) = held.line().ok_or(ConnError::Closed)?;
        let name = match name {
            Some(n) => n.to_owned(),
            None => host_of(&line.target().ok_or(ConnError::Closed)?),
        };

        let Some((mut reading, kept)) = Reading::begin(&held.rest, &waker) else {
            return Err(ConnError::Pending);
        };
        let answer = line.upgrade_secure(
            &config,
            &name,
            DEFAULT_OPEN_TIMEOUT,
            kept.is_some(),
            &mut Context::from_waker(&waker),
        );
        let over_clear = matches!(
            &answer,
            Poll::Ready(Err(Failure::Refused(t))) if t == compose::UPGRADE_OVER_CLEAR_BYTES
        );
        if !over_clear {
            reading.left = kept;
        }
        match answer {
            Poll::Ready(Ok(())) => Ok(()),
            Poll::Ready(Err(f)) => Err(map(&f)),
            Poll::Pending => Err(ConnError::Pending),
        }
    }

    /// THE DIAL HAS LANDED: its judgement answered and the far end took the connect (a name's
    fn landed(&self, caller: InstanceId, conn: ConnId, ticket: Ticket) -> Result<(), ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        if held.lease.is_some() || held.dialled.is_some() {
            return Ok(());
        }
        let waker = self.waker(caller, ticket);
        held.watch_deadlines(DeadlineInterest::Ticket(ticket), &waker);
        if !self.settle(&held, Some(&waker))? {
            return Err(ConnError::Pending);
        }
        let (line, stream) = held.line().ok_or(ConnError::Closed)?;
        match line.poll_landed(stream, &mut Context::from_waker(&waker)) {
            Poll::Ready(Ok(())) => {
                held.landed();
                Ok(())
            }
            Poll::Ready(Err(f)) => Err(map(&f)),
            Poll::Pending => Err(ConnError::Pending),
        }
    }

    /// A need is framed when the entry serving its transport is a FRAMER (http's kind, over the
    fn request_head(&self, owner: InstanceId, need: NeedId, target: &str) -> HeadDefaults {
        self.framer_head(owner, need, target)
    }

    fn framed(&self, owner: InstanceId, need: NeedId) -> bool {
        self.over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .is_some_and(|d| d.door.facts().role == ROLE_FRAMER)
    }

    fn serves_scheme(&self, transport: &str) -> bool {
        Connector::serves_scheme(self, transport)
    }

    fn declare_program(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        program: &busbar_contract::conn::Program,
    ) -> Result<(), ConnError> {
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        let answer = self.record_program(owner, need, spec, program, &scope);
        self.declared
            .lock()
            .expect("declared needs")
            .insert((owner, need), (spec.clone(), answer));
        answer
    }

    fn cause(&self, owner: InstanceId, conn: ConnId) -> Option<ConnCause> {
        let (_, held) = self.slab.get(owner, conn).ok()?;
        let (line, _) = held.line()?;
        line.cause()
    }

    fn bind_auth(
        &self,
        owner: InstanceId,
        need: NeedId,
        member: &str,
        origin: &str,
        binding: busbar_contract::conn::ConnAuth,
    ) {
        self.auths.lock().expect("auth bindings").insert(
            (owner, need, member.to_string(), origin.to_string()),
            binding,
        );
    }

    fn auth_of(
        &self,
        owner: InstanceId,
        need: NeedId,
        member: &str,
        target: &str,
    ) -> Option<busbar_contract::conn::ConnAuth> {
        if member.is_empty() {
            return None;
        }
        let origin = busbar_contract::conn::origin_of(target);
        self.auths
            .lock()
            .expect("auth bindings")
            .get(&(owner, need, member.to_string(), origin.to_string()))
            .cloned()
    }

    fn declare_member_programs(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        programs: &[(String, busbar_contract::conn::Program)],
    ) -> Result<(), ConnError> {
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        let answer = self.record_members(owner, need, spec, programs, &scope, None);
        self.declared
            .lock()
            .expect("declared needs")
            .insert((owner, need), (spec.clone(), answer));
        answer
    }

    fn declare_member_programs_from(
        &self,
        predecessor: InstanceId,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        programs: &[(String, busbar_contract::conn::Program)],
    ) -> Result<(), ConnError> {
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        let fresh = !self
            .declared
            .lock()
            .expect("declared needs")
            .contains_key(&(owner, need));
        let previous = (fresh && predecessor != owner).then_some(predecessor);
        let answer = self.record_members(owner, need, spec, programs, &scope, previous);
        self.declared
            .lock()
            .expect("declared needs")
            .insert((owner, need), (spec.clone(), answer));
        answer
    }

    /// THE INSTANCE IS GONE: its connections close (a member lease among them ends), then every
    fn forget(&self, owner: InstanceId) {
        for conn in self.slab.forget(owner) {
            let _ = self.close(owner, conn);
        }
        self.pools.forget(owner);

        let gone: Vec<Arc<Accepting>> = {
            let mut listeners = self.listeners.lock().expect("listeners");
            let keys: Vec<(InstanceId, NeedId)> = listeners
                .keys()
                .filter(|(o, _)| *o == owner)
                .copied()
                .collect();
            keys.iter().filter_map(|k| listeners.remove(k)).collect()
        };
        drop(gone);
        let needs: Vec<NeedId> = self
            .over
            .lock()
            .expect("needs")
            .keys()
            .filter(|(o, _)| *o == owner)
            .map(|(_, n)| *n)
            .collect();
        for need in needs {
            self.set_need(owner, need, None);
        }
        self.declared
            .lock()
            .expect("declared needs")
            .retain(|(o, _), _| *o != owner);
        self.anchored
            .lock()
            .expect("anchored")
            .retain(|(o, _, _), _| *o != owner);
        self.member_anchored
            .lock()
            .expect("member anchored")
            .retain(|(o, _, _), _| *o != owner);
        self.registered
            .lock()
            .expect("registered")
            .retain(|(o, _, _), _| *o != owner);
        self.reaching
            .lock()
            .expect("reaching")
            .retain(|(o, _, _), _| *o != owner);
        self.auths
            .lock()
            .expect("auths")
            .retain(|(o, _, _, _), _| *o != owner);
        self.authority_held
            .lock()
            .expect("authority held")
            .remove(&owner);
    }
}

impl Connector {
    /// Register a held session's `pairing` under its kernel-minted `unit` key, before the session
    pub fn pair(&self, unit: u64, pairing: Arc<datagram::Pairing>) -> Result<(), ConnError> {
        if unit == 0 {
            return Err(ConnError::Refused);
        }
        let mut pairs = self.pairs.lock().expect("pairs");
        if pairs.contains_key(&unit) {
            return Err(ConnError::Refused);
        }
        pairs.insert(unit, pairing);
        Ok(())
    }

    /// THE SESSION'S CLEANUP (once): its pairing leaves the book and closes, both legs with it, so
    pub fn unpair(&self, unit: u64) {
        let gone = self.pairs.lock().expect("pairs").remove(&unit);
        if let Some(p) = gone {
            p.close();
        }
    }

    /// THE COMPOSED OPEN of a held session's upstream leg over a datagram framer's need ([`dialled`]):
    #[allow(clippy::too_many_arguments)]
    fn open_dialled(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        door: &Arc<dyn FramerDoor>,
        target: &str,
        open_timeout: Duration,
        (egress_class, declared_target, tls): (
            u32,
            Option<String>,
            Option<Arc<rustls::ClientConfig>>,
        ),
        require_secure: bool,
    ) -> Result<Held, ConnError> {
        if desc.unit == 0 {
            return Err(ConnError::Refused);
        }
        let pairing = self
            .pairs
            .lock()
            .expect("pairs")
            .get(&desc.unit)
            .cloned()
            .ok_or(ConnError::Refused)?;
        if pairing.closed() {
            return Err(ConnError::Refused);
        }
        let scheme = target
            .split_once("://")
            .map(|(s, _)| s)
            .ok_or(ConnError::Refused)?;
        let (exchange, alpn) = {
            let view = self.transports.read().expect("transports");
            let served = view.serving(scheme).ok_or(ConnError::Refused)?;
            (Arc::clone(&served.entry.door), served.entry.alpn.clone())
        };
        if exchange.facts().datagram {
            return Err(ConnError::Refused);
        }

        let port = udp::bind(&SocketAddr::new(pairing.local().ip(), 0).to_string())
            .and_then(udp::ReadyPort::open)
            .map_err(|_| ConnError::Fault)?;
        let cert = Arc::new(dtls::SessionCert::mint().map_err(|_| ConnError::Fault)?);
        let judged_class = guard::judged_class(egress_class, declared_target.is_some());
        let (framing, began) = datagram::DatagramFraming::dial(
            Arc::clone(door),
            cert,
            port.local_addr(),
            &pairing.opening(),
            Arc::clone(&self.judge),
            judged_class,
        )
        .map_err(|_| ConnError::Refused)?;
        let description = began
            .pieces
            .iter()
            .find(|g| g.stream == 0 && !g.fields)
            .map(|g| g.bytes.as_slice())
            .ok_or(ConnError::Fault)?;
        let due = due_at(std::time::Instant::now(), desc.timeout_ms);

        let body = dialled::composed_body(desc.fields, &desc.body, description)?;
        let held = self.dial_exchange(
            caller,
            need,
            &OpenDesc {
                body: body.into(),
                ..desc.clone()
            },
            (exchange, alpn),
            target,
            open_timeout,
            (egress_class, declared_target, tls),
            false,
            require_secure,
        )?;
        let dialled = dialled::Dialled::new(framing, port, pairing, due).begun(began)?;
        Ok(held.dialling(dialled))
    }

    /// THE DIALLED EXCHANGE over `door` (a framer of a stream, or a carrier carried as itself):
    #[allow(clippy::too_many_arguments)]
    fn dial_exchange(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        (door, alpn): (Arc<dyn FramerDoor>, Vec<Vec<u8>>),
        target: &str,
        open_timeout: Duration,
        (egress_class, declared_target, tls): (
            u32,
            Option<String>,
            Option<Arc<rustls::ClientConfig>>,
        ),
        poolable: bool,
        require_secure: bool,
    ) -> Result<Held, ConnError> {
        endpoint::named(target).map_err(|_| ConnError::Refused)?;
        let dial = Dial {
            target: target.to_owned(),
            tls: tls.or_else(|| self.tls.clone()),
            alpn,
            open_timeout,
            opening: Some((
                desc.fields
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), v.to_vec()))
                    .collect(),
                desc.body.clone(),
            )),
            head_words: (desc.method.to_vec(), desc.head_target.to_vec()),
            anchors: None,
        };

        let trust = dial.tls.clone().map(Same);
        let planned = self.plan(&door, dial).map_err(|f| map(&f))?;
        if require_secure && !planned.secure() {
            return Err(ConnError::AuthRefused);
        }

        let authority = planned.authority().to_ascii_lowercase();
        let own = (!desc.member.is_empty())
            .then(|| {
                self.member_anchored
                    .lock()
                    .expect("anchors")
                    .get(&(caller, need, desc.member.to_owned()))
                    .filter(|(at, _)| *at == authority)
                    .map(|(_, sealed)| sealed.clone())
            })
            .flatten();

        let anchored_as = own.is_some().then(|| desc.member.to_owned());

        let anchors = match own {
            Some(sealed) => sealed,
            None => {
                let at = (caller, need, authority);
                let anchored = self.anchored.lock().expect("anchors");
                let own = anchored.get(&at);
                match self.registered.lock().expect("anchors").get(&at) {
                    Some(registered) => registered.held(own)?,
                    None => own.cloned(),
                }
            }
        };

        let anchors = if let Some(sealed) = anchors.as_ref().filter(|s| !s.extra_anchors.is_empty())
        {
            let needs = self.over.lock().expect("needs");
            let current = match needs.get(&(caller, need)) {
                Some(d) if d.tls.is_some() => d.tls_policy.as_ref(),
                _ => self.tls_policy.as_ref(),
            };
            if sealed.policy.as_ref() != current {
                Some(tls::client::rebase(sealed, current).map_err(|_| ConnError::Refused)?)
            } else {
                anchors
            }
        } else {
            anchors
        };

        let sealed = anchors.clone().map(Same);
        if anchors.as_ref().is_some_and(|a| {
            (a.key_pin.is_some() || !a.extra_anchors.is_empty()) && !planned.secure()
        }) {
            return Err(ConnError::Refused);
        }
        let planned = planned.anchored(anchors);

        let reach = !desc.member.is_empty()
            && self
                .reaching
                .lock()
                .expect("reach")
                .get(&(caller, need, desc.member.to_owned()))
                .is_some_and(|at| at.eq_ignore_ascii_case(planned.authority()));

        let judged_class = guard::judged_class(egress_class, declared_target.is_some());

        if let Some(declared) = declared_target {
            let located = self.located(&door, &declared).ok_or(ConnError::Refused)?;
            if !located.authority.eq_ignore_ascii_case(planned.authority())
                || located.secure != planned.secure()
            {
                return Err(ConnError::Refused);
            }
        }

        if !scheme_admits(egress_class, planned.secure()) {
            return Err(ConnError::Refused);
        }

        let pooled = (poolable && self.pools.keeps() && desc.within.is_empty()).then(|| {
            (
                self.pools.shard(),
                PoolKey {
                    owner: caller,
                    need,
                    door: Arc::as_ptr(&door).cast::<()>() as usize,
                    authority: planned.authority().to_ascii_lowercase(),
                    secure: planned.secure(),
                    name: planned.name().map(str::to_owned),
                    class: (judged_class, egress_class),
                    reach,
                    anchored_as,
                    trust,
                    sealed,
                },
            )
        });
        let mut planned = planned;
        if let Some((shard, key)) = &pooled {
            if let Some(line) = self.pools.lend(*shard, key) {
                let redial = Redial {
                    door: Arc::clone(&door),
                    dial: planned.dial().clone(),
                    egress_class,
                    judged_class,
                    require_secure,
                    reach,
                    mark: line.flushed(),
                };
                let (opening, words) = planned.into_opening();
                match line.attach(opening, words) {
                    Ok(stream) => {
                        let held =
                            Held::over(Some((line, stream)), None, pooled).bounded(desc.timeout_ms);
                        *held.redial.lock().expect("redial") = Some(redial);
                        return Ok(held);
                    }

                    Err((stream, _)) if line.flushed() != redial.mark => {
                        let held = Held::over(Some((line, stream)), None, pooled);
                        return Ok(held);
                    }

                    Err((stream, _)) => {
                        line.leave(stream, false);
                        self.pools.drop_line(*shard, key, &line);
                        planned = self.plan(&redial.door, redial.dial).map_err(|f| map(&f))?;
                    }
                }
            }
        }
        if require_secure && !planned.secure() {
            return Err(ConnError::AuthRefused);
        }
        let (conn, judging) =
            self.dial_judged(planned, egress_class, judged_class, desc.within, reach)?;
        let held = Held::over(None, judging, pooled)
            .bounded(desc.timeout_ms)
            .dial_bounded(open_timeout);
        if let Some(conn) = conn {
            self.ride(&held, conn)?;
        }
        Ok(held)
    }
}

impl Connector {
    fn open_timed(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: Option<u64>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need)?;
        let declared_timeout_ms = self
            .declared
            .lock()
            .expect("declared needs")
            .get(&(caller, need))
            .map_or(0, |(spec, _)| spec.timeout_ms);
        let dial_timeout_ms = dial_timeout_ms.unwrap_or(desc.timeout_ms);
        let dial_timeout_ms = if dial_timeout_ms == 0 {
            declared_timeout_ms
        } else {
            dial_timeout_ms
        };
        let open_timeout = if dial_timeout_ms == 0 {
            DEFAULT_OPEN_TIMEOUT
        } else {
            Duration::from_millis(dial_timeout_ms)
        };
        let authority_held = self
            .authority_held
            .lock()
            .expect("authority held")
            .contains(&caller);
        if head_is_refused(desc, authority_held) {
            return Err(ConnError::Refused);
        }

        let DeclaredNeed {
            door,
            alpn,
            egress_class,
            declared_target,
            tls,
            tls_policy: _,
            program,
            members,
            member_spec: _,
        } = self
            .over
            .lock()
            .expect("needs")
            .get(&(caller, need))
            .cloned()
            .ok_or(ConnError::Refused)?;
        if members.is_none()
            && desc
                .fields
                .iter()
                .any(|(name, _)| program::is_expected_field(name))
        {
            return Err(ConnError::Refused);
        }

        if let Some(members) = members {
            if require_secure {
                return Err(ConnError::AuthRefused);
            }
            let expected = program::Expected::of(desc.fields)?;
            let member = members
                .get(program::member_of(desc.target))
                .map(|declaration| declaration.member())
                .ok_or(ConnError::Refused)?;
            let lease = member.lease(&desc.body, expected)?;
            let mut held = Held::over(None, None, None).bounded(desc.timeout_ms);
            held.lease = Some((member, lease));

            return self.slab.insert(caller, need, held);
        }

        if let Some((program, env)) = program {
            if require_secure {
                return Err(ConnError::AuthRefused);
            }
            if !desc.target.is_empty() {
                return Err(ConnError::Refused);
            }
            let dial = Dial {
                anchors: None,
                target: program.command.clone(),
                tls: None,
                alpn,
                open_timeout,
                opening: Some((
                    desc.fields
                        .iter()
                        .map(|(n, v)| ((*n).to_owned(), v.to_vec()))
                        .collect(),
                    desc.body.clone(),
                )),
                head_words: (desc.method.to_vec(), desc.head_target.to_vec()),
            };
            let via = Via {
                door,
                io: Arc::clone(&self.io),
            };

            let conn = Connection::spawn(&via, &program, &env, dial, 0).map_err(|f| map(&f))?;

            let line = Line::new(conn);
            return self.slab.insert(
                caller,
                need,
                Held::over(Some((line, EXCHANGE_STREAM)), None, None)
                    .bounded(desc.timeout_ms)
                    .dial_bounded(open_timeout),
            );
        }

        let named = match (desc.target, declared_target.as_deref()) {
            ("", Some(declared)) => declared,
            (named, _) => named,
        }
        .to_owned();
        let target = named.as_str();

        if door.facts().datagram {
            let held = self.open_dialled(
                caller,
                need,
                desc,
                &door,
                target,
                open_timeout,
                (egress_class, declared_target, tls),
                require_secure,
            )?;
            return self.slab.insert(caller, need, held);
        }

        if let Some(path) = socket::unix_path(target) {
            if require_secure {
                return Err(ConnError::AuthRefused);
            }
            if egress_class != EGRESS_OPERATOR_INFRASTRUCTURE
                || declared_target.as_deref().is_some_and(|d| d != target)
            {
                return Err(ConnError::Refused);
            }
            let dial = Dial {
                anchors: None,
                target: target.to_owned(),
                tls: None,
                alpn,
                open_timeout,
                opening: Some((
                    desc.fields
                        .iter()
                        .map(|(n, v)| ((*n).to_owned(), v.to_vec()))
                        .collect(),
                    desc.body.clone(),
                )),
                head_words: (desc.method.to_vec(), desc.head_target.to_vec()),
            };
            let (framer, via) = self.ride_on(&door).ok_or(ConnError::Refused)?;
            let conn = Connection::dial_unix(framer, &via, dial, path).map_err(|f| map(&f))?;

            let line = Line::new(conn);
            return self.slab.insert(
                caller,
                need,
                Held::over(Some((line, EXCHANGE_STREAM)), None, None)
                    .bounded(desc.timeout_ms)
                    .dial_bounded(open_timeout),
            );
        }
        let held = self.dial_exchange(
            caller,
            need,
            desc,
            (door, alpn),
            target,
            open_timeout,
            (egress_class, declared_target, tls),
            true,
            require_secure,
        )?;
        let rejected = held
            .line()
            .map(|(line, stream)| (line, stream, held.pooled.clone()));
        let inserted = self.slab.insert(caller, need, held);
        if inserted.is_err() {
            if let Some((line, stream, pooled)) = rejected {
                line.leave(stream, false);
                match pooled {
                    Some((shard, key)) => self.pools.drop_line(shard, &key, &line),
                    None => line.close(),
                }
            }
        }
        inserted
    }
}

impl Conns for Connector {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.open_with_security(caller, need, desc, false)
    }

    fn open_with_security(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
    ) -> Result<ConnId, ConnError> {
        self.open_timed(caller, need, desc, require_secure, None)
    }

    /// A write is taken whole, short, or (no room under
    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        if let Some((member, lease)) = &held.lease {
            return member.write(*lease, bytes);
        }
        if let Some(d) = held.dialled.as_ref().filter(|d| !d.exchanging()) {
            return d.write(bytes, end, text);
        }
        if !self.settle(&held, None)? {
            let mut judging = held.judging.lock().expect("judging");

            if held.crossing.lock().expect("crossing").is_some() {
                return Err(ConnError::Pending);
            }
            if let Some(j) = judging.as_mut() {
                if let Some(error) = j.failed {
                    return Err(error);
                }

                if j.early.back().is_some_and(|(bytes, _, _)| bytes.is_empty()) {
                    return Err(ConnError::Pending);
                }
                let held_bytes: usize = j.early.iter().map(|(b, _, _)| b.len()).sum();
                let take = bytes
                    .len()
                    .min(WRITE_BUFFER_BYTES.saturating_sub(held_bytes));
                if take == 0 && !bytes.is_empty() {
                    return Err(ConnError::Pending);
                }
                j.early.push_back((
                    Bytes::copy_from_slice(&bytes[..take]),
                    end && take == bytes.len(),
                    text,
                ));
                return Ok(take);
            }

            return Err(ConnError::Pending);
        }
        let (line, stream) = held.line().ok_or(ConnError::Closed)?;
        let got = line.emit(stream, bytes, end, text);
        if got.is_ok() {
            let _ = self.observe_landing(&held, Waker::noop());
        }
        match got {
            Ok(0) if !bytes.is_empty() => Err(ConnError::Pending),
            got => got.map_err(|f| map(&f)),
        }
    }

    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        ticket: Ticket,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.read_waking(
            caller,
            conn,
            &self.waker(caller, ticket),
            DeadlineInterest::Ticket(ticket),
            buf,
        )
    }

    fn wait(&self, caller: InstanceId, set: &[ConnId], ticket: Ticket) -> Result<usize, ConnError> {
        let waker = self.waker(caller, ticket);
        let mut cx = Context::from_waker(&waker);
        for (at, conn) in set.iter().enumerate() {
            let (_, held) = self.slab.get(caller, *conn)?;
            held.watch_deadlines(DeadlineInterest::Ticket(ticket), &waker);

            if held.within_due().is_err() {
                return Ok(at);
            }
            if let Some((member, lease)) = &held.lease {
                match member.ready(*lease, &waker) {
                    Ok(false) => continue,
                    _ => return Ok(at),
                }
            }
            if let Some(d) = held.dialled.as_ref().filter(|d| !d.exchanging()) {
                if d.ready(&waker) {
                    return Ok(at);
                }
                continue;
            }
            if held.rest.lock().expect("rest").piece.is_some() {
                return Ok(at);
            }
            match self.settle(&held, Some(&waker)) {
                Ok(false) => continue,
                Err(_) => return Ok(at),
                Ok(true) => {}
            }
            let Some((line, stream)) = held.line() else {
                return Ok(at);
            };
            if line.poll_ready(stream, &mut cx).is_ready() {
                let _ = self.observe_landing(&held, &waker);
                return Ok(at);
            }
            match self.observe_landing(&held, &waker) {
                Ok(true) => waker.wake_by_ref(),
                Err(_) => return Ok(at),
                Ok(false) => {}
            }
        }
        Err(ConnError::Pending)
    }

    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        if let Some((member, lease)) = &held.lease {
            return member.facts(*lease);
        }
        if !self.settle(&held, None)? {
            return Err(ConnError::Pending);
        }
        let (line, _) = held.line().ok_or(ConnError::Closed)?;
        let e = line.established().ok_or(ConnError::Closed)?;
        Ok(ConnFacts {
            sni: e.offered_name.clone(),
            alpn: e
                .agreed_protocol
                .as_ref()
                .map(|p| String::from_utf8_lossy(p).into_owned()),
            peer_cert: line.peer_cert_hash().map(|fingerprint| {
                busbar_contract::transport::wire::CertFacts {
                    subject: String::new(),
                    issuer: String::new(),
                    fingerprint,
                }
            }),
            claim: e.claim.clone(),
            peer_key_pin: e.peer_key_pin.clone(),
            client_identity: e.client_identity,
        })
    }

    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        let held = self.slab.remove(caller, conn)?;
        let line = {
            let mut home = held.line.lock().expect("line");
            held.retired.store(true, Ordering::Release);
            home.take()
        };
        held.answered();
        if let Some((member, lease)) = &held.lease {
            member.close(*lease);
        }
        if let Some(d) = &held.dialled {
            d.close();
        }
        if let Some((line, stream)) = line {
            self.let_go(&held, &line, stream, held.whole.load(Ordering::Acquire));
        }
        Ok(())
    }
}

impl PollConns for Connector {
    /// The framer the need rides, located at `target`: its own head lines, and whether its head
    fn head_defaults(&self, owner: InstanceId, need: NeedId, target: &str) -> HeadDefaults {
        self.framer_head(owner, need, target)
    }

    fn poll_read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Piece, ConnError>> {
        match self.read_waking(caller, conn, cx.waker(), DeadlineInterest::Task, buf) {
            Err(ConnError::Pending) => Poll::Pending,
            done => Poll::Ready(done),
        }
    }

    /// The anchors are sealed against the authority the need's own entry locates `target` at, the
    fn anchor(
        &self,
        owner: InstanceId,
        need: NeedId,
        member: &str,
        target: &str,
        anchors: &busbar_contract::transport::trust::Anchors,
    ) -> Result<(), ConnError> {
        let declared = self
            .over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .cloned();
        let door = declared.as_ref().map(|d| Arc::clone(&d.door));
        let base = declared
            .as_ref()
            .and_then(|d| d.tls.as_deref())
            .or(self.tls.as_deref());
        let policy = match declared.as_ref() {
            Some(d) if d.tls.is_some() => d.tls_policy.as_ref(),
            _ => self.tls_policy.as_ref(),
        };
        let located = door.as_ref().and_then(|door| self.located(door, target));
        let at = located.map(|l| (owner, need, l.authority.to_ascii_lowercase()));
        let sealed = match (&at, anchors.is_empty()) {
            (_, true) => None,
            (None, false) => return Err(ConnError::Refused),
            (Some(_), false) => Some(Arc::new(
                tls::client::seal_with_policy(base, policy, anchors)
                    .map_err(|_| ConnError::Refused)?,
            )),
        };

        if member.is_empty() {
            let Some(at) = at else {
                return Ok(());
            };
            let mut anchored = self.anchored.lock().expect("anchors");
            match sealed {
                Some(sealed) => {
                    anchored.insert(at, sealed);
                }

                None => {
                    anchored.remove(&at);
                }
            }
            return Ok(());
        }
        let key = (owner, need, member.to_owned());
        let mut by_member = self.member_anchored.lock().expect("anchors");
        let mut registered = self.registered.lock().expect("anchors");
        let before = match &at {
            Some((_, _, authority)) => by_member.insert(key, (authority.clone(), sealed.clone())),
            None => by_member.remove(&key),
        };
        if let Some((was, _)) = before {
            let was = (owner, need, was);
            if let Some(at_was) = registered.get_mut(&was) {
                at_was.members.remove(member);
                if at_was.members.is_empty() {
                    registered.remove(&was);
                }
            }
        }
        if let Some(at) = at {
            registered
                .entry(at)
                .or_default()
                .members
                .insert(member.to_owned(), sealed);
        }
        Ok(())
    }

    /// The registration's own target's authority is read by the need's entry, as a dial reads it;
    fn seal_reach(
        &self,
        owner: InstanceId,
        need: NeedId,
        member: &str,
        target: &str,
        reach: bool,
    ) -> Result<(), ConnError> {
        let key = (owner, need, member.to_owned());
        if !reach {
            self.reaching.lock().expect("reach").remove(&key);
            return Ok(());
        }
        let door = self
            .over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .map(|d| Arc::clone(&d.door))
            .ok_or(ConnError::Refused)?;
        let located = self.located(&door, target).ok_or(ConnError::Refused)?;
        if member.is_empty() {
            return Err(ConnError::Refused);
        }
        self.reaching
            .lock()
            .expect("reach")
            .insert(key, located.authority.to_ascii_lowercase());
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/connector_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/real_tcp_tests.rs"]
mod real_tcp_tests;

#[cfg(test)]
#[path = "tests/callback_waker.rs"]
#[allow(unsafe_code)]
mod callback_waker;

#[cfg(test)]
#[path = "tests/rest_callback_tests.rs"]
mod rest_callback_tests;

#[cfg(test)]
#[path = "tests/settled_dial_error_tests.rs"]
mod settled_dial_error_tests;

#[cfg(test)]
#[path = "tests/trust_from_tests.rs"]
mod trust_from_tests;

#[cfg(test)]
#[path = "tests/upgrade_tests.rs"]
mod upgrade_tests;

#[cfg(test)]
#[path = "tests/unix_target_tests.rs"]
mod unix_target_tests;

#[cfg(test)]
#[allow(unsafe_code, dead_code)]
#[path = "tests/support.rs"]
mod support;

#[cfg(test)]
#[path = "tests/refresh_binding_tests.rs"]
mod refresh_binding_tests;
