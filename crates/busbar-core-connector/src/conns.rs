// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTION TABLE ([`Connector`]) and every module the connector serves a request through: the
//! connector's request-path tree (its marker is on `mod conns` in lib.rs). What it needs off the
//! request path lives beside it, in `crate::cold` (refusal text) and `crate::off_path` (once per
//! configuration or process).

#[expect(
    unsafe_code,
    reason = "the child job's OS calls (process groups, job objects) are FFI"
)]
pub mod child_job;
pub mod clock;
pub mod egress_audit;
pub mod endpoint;
pub mod fetch;
pub mod framed_stream;
pub mod guard;
pub mod io;
pub mod listen;
pub(crate) mod native_conns;
pub mod native_dial;
pub mod pool;
pub mod process;
pub mod proxy;
pub mod proxy_route;
pub mod raw_progress;
pub mod secure_vec;
pub mod socket;
pub mod spawn_env;
#[cfg(any(test, feature = "test-support"))]
pub use crate::off_path::conns::test_support;
pub mod tls;

use foldhash::{HashMap, HashMapExt as _, HashSet, HashSetExt as _};
use std::future::Future as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use busbar_contract::conn::codes::{
    DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::conn::{
    ConnCause, ConnId, ConnSlab, Conns, DeclaredConns, HeadDefaults, InstanceId, LocatedTarget,
    NeedId, NeedRefusal, OpenDesc, OwnedHead, Piece, PollConns, Ticket, NO_TICKET,
};
use busbar_contract::rendering::ReadNeed;
use busbar_contract::services::codes::{DEST_NO_ADDRESSES, DEST_UNRESOLVABLE};
// Named by tests as `crate::ConnError`.
pub(crate) use busbar_contract::conn::ConnError;
use busbar_contract::transport::ConnFacts;

use crate::cold::conns::verdict_reason;
use crate::pool::{PoolPosture, Pools};

/// How the host wakes a caller's ticket, naming the caller that handed it the ticket: the supplier
pub type WakeTicket = busbar_contract::conn::ConnWake;

/// A `DEST_*` verdict (`busbar_contract::services::codes::service`) refusing a dial.
pub type Verdict = u64;

/// Where a pended judgement goes: the address to dial, or the verdict refusing it. Called once,
pub type Judged = Box<dyn FnOnce(Result<SocketAddr, Verdict>) + Send>;

/// Where a pended judgement goes with the name's OTHER admitted addresses, in the resolver's order:
pub type JudgedAll = Box<dyn FnOnce(Result<SocketAddr, Verdict>, Vec<SocketAddr>) + Send>;

/// A need's `egress_class` `0`: the connector's default class (`busbar_contract::abi::host::conn::
pub const DEFAULT_CLASS: u32 = 0;

/// THE KERNEL'S DESTINATION JUDGE, as a dial reaches it (`dest.judge`, R-K): every authority the
pub trait DialJudge: Send + Sync {
    /// Judge a transport-located authority with independent security intent and egress class.
    fn judge_target_all(
        &self,
        target: busbar_kernel::host_services::Destination<'_>,
        reach: bool,
        done: JudgedAll,
    ) -> Option<Result<SocketAddr, Verdict>> {
        if !scheme_admits(target.egress_class, target.secure) {
            return Some(Err(busbar_contract::services::codes::DEST_PLAINTEXT));
        }
        self.judge_dial_all(target.authority, target.egress_class, reach, done)
    }

    /// Static policy for an explicit transport destination.
    fn judge_target_static(
        &self,
        target: busbar_kernel::host_services::Destination<'_>,
    ) -> Option<Verdict> {
        if !scheme_admits(target.egress_class, target.secure) {
            return Some(busbar_contract::services::codes::DEST_PLAINTEXT);
        }
        self.judge_static(target.authority, target.egress_class)
    }

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

/// The longest text an [`IpAddr`] displays as (an IPv6 address with an embedded IPv4 tail).
pub(crate) const IP_TEXT: usize = 46;

/// The longest text a [`SocketAddr`] displays as (`[` IPv6 `%` scope `]:` port).
pub(crate) const SOCKET_TEXT: usize = 64;

/// A value's display text, written into a fixed buffer on the stack: the text of an address the
/// connector hands on as `&str`, without a `String` per call. Text past `N` bytes is cut short
/// (the address texts it is sized for never are).
#[derive(Clone, Copy)]
pub(crate) struct StackText<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> std::fmt::Debug for StackText<N> {
    /// As the text's own `str` shows.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl<const N: usize> StackText<N> {
    /// `value`'s display text.
    pub(crate) fn of(value: &dyn std::fmt::Display) -> Self {
        use std::fmt::Write as _;
        let mut text = Self {
            buf: [0; N],
            len: 0,
        };
        let _ = write!(text, "{value}");
        text
    }

    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or_default()
    }
}

impl<const N: usize> std::fmt::Write for StackText<N> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let end = self.len + s.len();
        let into = self.buf.get_mut(self.len..end).ok_or(std::fmt::Error)?;
        into.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// The judge a connector built with none holds: an IP literal is its own address, judged by the
pub(crate) struct LiteralsOnly(pub(crate) guard::Guard);

impl DialJudge for LiteralsOnly {
    fn judge_dial(&self, dest: &str, class: u32, _: Judged) -> Option<Result<SocketAddr, Verdict>> {
        let Some(at) = socket::address_of(dest) else {
            return Some(Err(busbar_contract::services::codes::DEST_UNRESOLVABLE));
        };
        let host = StackText::<IP_TEXT>::of(&at.ip());
        Some(
            self.0
                .judge_answer(host.as_str(), &[at.ip()], class)
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
            return Some(Err(busbar_contract::services::codes::DEST_UNRESOLVABLE));
        };
        let host = StackText::<IP_TEXT>::of(&at.ip());
        Some(
            self.0
                .judge_answer_with(host.as_str(), &[at.ip()], class, false, true)
                .map(|()| at)
                .map_err(|r| r.verdict),
        )
    }
}

/// THE SCHEME RULE OF A NEED'S EGRESS CLASS (`abi::host::conn::connector`, `EGRESS_*`), held
fn scheme_admits(egress_class: u32, secure: bool) -> bool {
    egress_class != EGRESS_OPEN_WEB || secure
}

///
/// WHETHER A CARRIER'S CLEARTEXT WINDOW ([`compose::Connection::hold_clear_window`]) may stand in
/// for the plaintext rule in `egress_class`: never in `loopback-allowed`, whose ABI contract
/// (`EGRESS_LOOPBACK_ALLOWED`) is a secure connection or plaintext to loopback, so a carrier there
/// is refused at its dial unless it is secure or its owner's acceptance admits plaintext to loopback.
fn carrier_window_admits(egress_class: u32) -> bool {
    egress_class != EGRESS_LOOPBACK_ALLOWED
}

///
/// THE ONE PLAINTEXT RULE (every class; SEC-2: nothing hard-coded exempt, not loopback): a dial
/// that is not secured from its first byte is admitted only when its opener's core-held
/// `insecure_transport.accept` admits plaintext to it ([`Planned::plaintext_accepted`], #297 model
/// A) or an exact `advanced.tls.destinations` entry admits plaintext to it (`plain_admitted`, which a carrier that
/// upgrades later also carries: its cleartext window is held on the connection instead,
/// [`compose::Connection::hold_clear_window`]). `open-web` never admits plaintext.
pub(crate) fn class_admits(
    egress_class: u32,
    secure: bool,
    plain_admitted: bool,
    within: &[IpAddr],
    addr: SocketAddr,
) -> bool {
    (within.is_empty() || within.contains(&addr.ip()))
        && match egress_class {
            EGRESS_OPEN_WEB => secure,
            // The class's ABI contract narrows (never widens) the rule: plaintext only to loopback.
            EGRESS_LOOPBACK_ALLOWED => secure || (plain_admitted && guard::is_loopback(addr.ip())),
            _ => secure || plain_admitted,
        }
}

/// WHAT A JUDGEMENT THAT PENDED ON A RESOLUTION ANSWERS THE CONNECTION'S CALLER. A name that did
fn pended_verdict(v: Verdict) -> ConnError {
    match v {
        DEST_UNRESOLVABLE | DEST_NO_ADDRESSES => ConnError::Fault,
        _ => ConnError::Refused,
    }
}

/// THE REFUSAL TEXTS (host-only, [`NeedRefusal`]): static, naming no hop (the renderer names it)
/// and only keys the operator can set.
mod refusal_text {
    /// The URL carries userinfo.
    pub(crate) const CREDENTIALED: &str =
        "the URL carries userinfo; busbar never sends credentials embedded in a URL";
    /// No loaded transport serves the need's scheme.
    pub(crate) const UNSERVED: &str = "busbar serves no transport for the URL's scheme";
    /// The target is malformed or not located by its transport.
    pub(crate) const UNLOCATED: &str = "the target is not a host busbar can dial";
    /// The need names a target or trust the configuration does not provide.
    pub(crate) const UNRESOLVED: &str =
        "the need names a target or trust anchors the configuration does not provide";
    /// The operator's trust anchors for the target could not be loaded.
    pub(crate) const TRUST: &str =
        "the trust anchors configured for the target could not be loaded";
    /// Plaintext to a destination whose class asks for connection security.
    pub(crate) const PLAINTEXT: &str = "plaintext is not admitted to this destination";
    /// None of the above.
    pub(crate) const CHECKS: &str = "the connector's own checks refused the target";
    /// The build assigns no transport image the destination's carrier.
    pub(crate) const NO_CARRIER: &str =
        "no transport image carries this destination's protocol in this build";
    /// The operator's egress proxy selects the destination, and a natively carried dial does not go through a
    /// proxy: it is refused, never dialled around the proxy.
    pub(crate) const NATIVE_PROXY: &str =
        "the egress proxy selects this destination and its dial cannot go through a proxy yet";
}

/// A guard verdict in words (never `guard::Refusal`'s Display: its catch-all and the operator's
/// blocked list would be misnamed).
pub(crate) const fn verdict_text(v: Verdict) -> &'static str {
    use busbar_contract::services::codes::{
        DEST_INTERNAL, DEST_METADATA, DEST_NO_HOST, DEST_OBFUSCATED, DEST_PLAINTEXT, DEST_SCHEME,
    };
    match v {
        DEST_METADATA => {
            "the destination guard refuses a cloud-metadata host or a host listed in \
             security.blocked_metadata_hosts"
        }
        DEST_INTERNAL => {
            "the destination guard refuses an internal or loopback address (enable allow_private on its upstream registration to allow it)"
        }
        DEST_OBFUSCATED => {
            "the destination guard refuses an alternate IPv4 spelling; write the address in \
             dotted-quad form"
        }
        DEST_NO_HOST => "the destination guard cannot judge the host, so it refuses it",
        DEST_PLAINTEXT => refusal_text::PLAINTEXT,
        DEST_SCHEME => "the destination guard does not admit the scheme",
        DEST_UNRESOLVABLE => "the name did not resolve",
        DEST_NO_ADDRESSES => "the name resolved to no addresses",
        _ => refusal_text::CHECKS,
    }
}

/// Caller-owned request fields cannot set framing or override host-held authority.
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

/// The opening's fields: the head the opener built and moved in ([`Conns::open_owned`]), kept as
/// it is; else a copy of the borrowed head an opener lent.
fn opening_fields(fields: &[(&str, &[u8])], owned: Option<OwnedHead>) -> Vec<(String, Vec<u8>)> {
    if let Some(owned) = owned {
        return owned.into_fields();
    }
    busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::OutboundHead);
    crate::off_path::conns::copied_fields(fields)
}

/// Host defaults remain in the signed wire head, but cannot authorize caller framing fields.
fn request_head_is_refused(
    caller: InstanceId,
    need: NeedId,
    desc: &OpenDesc<'_>,
    authority_held: bool,
) -> bool {
    let Some(completed) = desc.completed_head else {
        return head_is_refused(desc, authority_held);
    };
    let Some(count) = completed.caller_field_count(caller, need, desc) else {
        return true;
    };
    let caller_head = OpenDesc {
        fields: &desc.fields[..count],
        completed_head: None,
        ..desc.clone()
    };
    head_is_refused(&caller_head, authority_held)
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
pub(crate) type Anchored = Mutex<HashMap<(InstanceId, NeedId, String), Arc<tls::client::Sealed>>>;

/// THE REGISTRATIONS' SEALS AT ONE DESTINATION: each registration's seal at its authority, by name
/// (`None`: it holds no anchors), in name order. An open naming no registration sealed there is held
/// to the one answer they and the destination's own seal all give, and refused where they disagree:
/// a pin nobody enforces is refused, never dropped, and no registration's anchors are erased by
/// another's.
#[derive(Default)]
pub(crate) struct Registered {
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
pub(crate) type MemberAnchored = Mutex<ByMember<(String, Option<Arc<tls::client::Sealed>>)>>;

/// What is held per registration: by the need's owner, then the need, then the registration's
/// name, so a lookup borrows the name and an owner's entries go with it in one removal.
pub(crate) struct ByMember<V>(HashMap<InstanceId, HashMap<NeedId, HashMap<String, V>>>);

impl<V> Default for ByMember<V> {
    fn default() -> Self {
        Self(HashMap::default())
    }
}

impl<V> ByMember<V> {
    fn get(&self, owner: InstanceId, need: NeedId, member: &str) -> Option<&V> {
        self.0.get(&owner)?.get(&need)?.get(member)
    }

    /// Hold `value` for `member` (its name is kept: a registration is sealed at declaration).
    fn insert(&mut self, owner: InstanceId, need: NeedId, member: &str, value: V) -> Option<V> {
        let members = self.0.entry(owner).or_default().entry(need).or_default();
        crate::off_path::conns::hold_member(members, member, value)
    }

    fn remove(&mut self, owner: InstanceId, need: NeedId, member: &str) -> Option<V> {
        self.0.get_mut(&owner)?.get_mut(&need)?.remove(member)
    }

    /// Every entry `owner` holds goes.
    pub(crate) fn forget(&mut self, owner: InstanceId) {
        self.0.remove(&owner);
    }
}

/// What a member's auth binding is held under: the need's owner, the need, the registration's
/// key and origin: by owner, then need, then member, then origin, so a lookup borrows its names and
/// an owner's bindings go with it in one removal.
pub(crate) type Auths = HashMap<
    InstanceId,
    HashMap<NeedId, HashMap<String, HashMap<String, busbar_contract::conn::ConnAuth>>>,
>;

/// Wakers held once each, in the order they first registered (woken first registered, first
/// woken): a repeat registration is found by its [`waker_key`] in `held`, never by a scan of those
/// held.
#[derive(Default)]
struct Wakers {
    held: HashSet<(usize, usize)>,
    order: Vec<Waker>,
}

impl Wakers {
    /// Wake every held waker, in registration order.
    fn wake_all(self) {
        for waker in self.order {
            waker.wake();
        }
    }
}

/// What [`Waker::will_wake`] compares two wakers by: their data pointer and their vtable.
fn waker_key(waker: &Waker) -> (usize, usize) {
    (
        waker.data().addr(),
        std::ptr::from_ref(waker.vtable()).addr(),
    )
}

/// The address set a pended dial's pinned address must be in, held inline for the usual few.
type Within = smallvec::SmallVec<[IpAddr; 4]>;

/// Whether a target judgement's refusal is only that the name does not resolve HERE: behind a
pub(crate) fn unresolved_here(verdict: Verdict) -> bool {
    verdict == DEST_UNRESOLVABLE || verdict == DEST_NO_ADDRESSES
}

/// One connection the connector holds for its owner: the line it rides and the stream it reads
pub(crate) struct Held {
    /// THE REQUEST'S WHOLE BOUND until its answer (`OpenDesc::timeout_ms`; `None` = unbounded
    due: Mutex<Option<Due>>,
    /// The exchange, dialled natively ([`native_conns`]); `None` only while its open builds it.
    native: Option<native_conns::NativeHeld>,
}

/// The open's bound when the caller states none.
pub const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether `name` is a field only a member program reads (its expected instance or generation).
fn is_expected_field(name: &str) -> bool {
    name.trim()
        .eq_ignore_ascii_case(busbar_contract::conn::PROGRAM_EXPECT_INSTANCE_FIELD)
        || name
            .trim()
            .eq_ignore_ascii_case(busbar_contract::conn::PROGRAM_EXPECT_GENERATION_FIELD)
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
pub(crate) struct Due {
    at: std::time::Instant,
    timer: Arc<std::sync::OnceLock<Mutex<Option<DeadlineTimer>>>>,
    wake: Arc<DeadlineWake>,
}

type DeadlineTimer = std::pin::Pin<Box<tokio::time::Sleep>>;

#[derive(Clone, Copy)]
pub(crate) enum DeadlineInterest {
    Ticket(Ticket),
    Task,
}

#[derive(Default)]
struct DeadlineWaiters {
    tickets: HashMap<Ticket, Waker>,
    tasks: Wakers,
}

#[derive(Default)]
pub(crate) struct DeadlineWake {
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
                        if waiters.tasks.held.insert(waker_key(waker)) {
                            waiters.tasks.order.push(fresh.take().unwrap());
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
        for waker in waiters.tickets.into_values() {
            waker.wake();
        }
        waiters.tasks.wake_all();
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
        if crate::clock::now() >= self.at {
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
    /// An entry with no bound and no exchange yet.
    pub(crate) fn new() -> Self {
        Held {
            due: Mutex::new(None),
            native: None,
        }
    }

    /// Bounded by `timeout_ms` from `now` (the op's one clock reading) until its answer begins;
    /// `0`, or a bound no instant can
    fn bounded(self, now: std::time::Instant, timeout_ms: u64) -> Self {
        if let Some(at) = due_at(now, timeout_ms) {
            *self.due.lock().expect("due") = Some(Due::new(at));
        }
        self
    }

    fn watch_deadlines(&self, interest: DeadlineInterest, waker: &Waker) {
        let due = self.due.lock().expect("due").clone();
        let now = crate::clock::now();
        if let Some(due) = due.filter(|due| now < due.at) {
            due.wake.register(interest, waker);
        }
    }

    /// [`ConnError::Timeout`] once the bound has passed; subscribers are woken when it passes.
    fn within_due(&self) -> Result<(), ConnError> {
        let due = self.due.lock().expect("due").clone();
        due.map_or(Ok(()), |d| d.check())
    }

    /// The answer began: the bound is spent.
    fn answered(&self) {
        let due = self.due.lock().expect("due").take();
        if let Some(due) = &due {
            due.cancel();
        }
        drop(due);
    }
}

impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Held").finish_non_exhaustive()
    }
}

/// A need as an instance declared it, whole, the answer its declaration got, and why its latest
/// `declare` or `open` failed before any connection existed (host-only, [`NeedRefusal`]).
pub(crate) type Declared = (ReadNeed, Result<(), ConnError>, Option<NeedRefusal>);

type TlsPolicy = (
    Arc<rustls::ClientConfig>,
    busbar_contract::transport::trust::EgressTrust,
);

/// THE CONNECTOR: the host side of the connection table.
pub struct Connector {
    pub(crate) slab: ConnSlab<Held>,
    /// Every need an instance declared through [`DeclaredConns::declare`], whole, and the answer
    pub(crate) declared: Mutex<HashMap<(InstanceId, NeedId), Declared>>,
    tls: Option<Arc<rustls::ClientConfig>>,
    tls_policy: Option<busbar_contract::transport::trust::EgressTrust>,
    wake: WakeTicket,
    judge: Arc<dyn DialJudge>,
    /// One listener per inbound need.
    /// The per-worker pools of dialled connections.
    pub(crate) pools: Pools,
    /// The trust anchors each sealed destination's connections are held to.
    pub(crate) anchored: Anchored,
    /// The trust anchors each sealed REGISTRATION's own connections are held to: two registrations
    pub(crate) member_anchored: MemberAnchored,
    /// The registrations' seals at each destination, by the need's owner, the need and the
    pub(crate) registered: Mutex<HashMap<(InstanceId, NeedId, String), Registered>>,
    /// The core-selected registrations holding private reach, by the need's
    pub(crate) reaching: Mutex<ByMember<(String, bool)>>,
    /// Each member's auth binding: what a plugin's own request naming that member is authenticated
    pub(crate) auths: Mutex<Auths>,
    /// The instances whose connections' authority the host writes
    pub(crate) authority_held: Mutex<HashSet<InstanceId>>,
    /// The instances whose core-held `insecure_transport.accept` holds `plaintext`
    /// ([`DeclaredConns::accept_plaintext`], #297 model A): every open they make may dial plaintext.
    pub(crate) plaintext_owners: Mutex<HashSet<InstanceId>>,
    /// THE ABI RULES FLAGGED, once per instance and code ([`Connector::flag_once`]): BUSBAR-6017 (a
    /// retired need shape), 6014 (a refused call) and 6015 (an honoured deprecated value), each
    /// logged and audited the first time an instance meets it.
    flagged: Mutex<HashSet<(InstanceId, u16)>>,
    /// THE PROXY ENVIRONMENT ([`proxy`]); `None` = every dial direct.
    proxy: Option<Arc<proxy::ProxyChoice>>,
    /// HOW A PROGRAM'S ENVIRONMENT REFERENCES RESOLVE ([`spawn_env`]): the resolver the composition
    spawn_secrets: Option<spawn_env::SpawnSecretFn>,
    /// THE OUTBOUND TLS TRUST STORE (`advanced.tls`), selected by the guard-judged dial host;
    /// empty = the connector's own config (`tls`) for every dial.
    trust: arc_swap::ArcSwapOption<tls::store::TrustStore>,
    /// `advanced.proxy_resolution: local` (the default, `true`): behind a proxy the target must
    /// resolve here, every address it answers is judged, and the CONNECT names the judged
    /// address; `proxy` (`false`): a name that does not resolve here is CONNECTed by name and its
    /// address check is the proxy's (BUSBAR-3149 at boot).
    proxy_by_address: std::sync::atomic::AtomicBool,
    /// THE NATIVE CARRIERS ([`Connector::carry_natively`]): the transport instance the build assigned each
    /// outbound carrier, and the account their sessions are charged to; set once at boot, held for the process.
    pub(crate) native: std::sync::OnceLock<native_conns::Natives>,
    /// The needs served natively ([`native_conns::NativeNeed`]), beside `over` (the framed ones).
    pub(crate) native_needs: Mutex<HashMap<(InstanceId, NeedId), Arc<native_conns::NativeNeed>>>,
    /// The idle native connections, per core ([`native_conns::Idle`]).
    pub(crate) native_idle: native_conns::Idle,
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
            declared: Mutex::new(HashMap::new()),
            tls: None,
            tls_policy: None,
            wake: Arc::new(|_, _| {}),
            judge: Arc::new(LiteralsOnly(guard::Guard::default())),
            pools: Pools::new(PoolPosture::NONE),
            anchored: Mutex::new(HashMap::new()),
            member_anchored: Mutex::default(),
            registered: Mutex::new(HashMap::new()),
            reaching: Mutex::default(),
            auths: Mutex::new(HashMap::new()),
            authority_held: Mutex::new(HashSet::new()),
            plaintext_owners: Mutex::new(HashSet::new()),
            flagged: Mutex::new(HashSet::new()),
            proxy: None,
            spawn_secrets: None,
            trust: arc_swap::ArcSwapOption::empty(),
            proxy_by_address: std::sync::atomic::AtomicBool::new(true),
            native: std::sync::OnceLock::new(),
            native_needs: Mutex::new(HashMap::new()),
            native_idle: native_conns::Idle::default(),
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

impl Connector {
    /// A connector holding no connection, no declared need and no transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A connector judging every dial's address through `judge`,
    #[must_use]
    pub fn serving(
        judge: Arc<dyn DialJudge>,
        tls: Option<Arc<rustls::ClientConfig>>,
        wake: WakeTicket,
    ) -> Self {
        Self {
            tls,
            wake,
            judge,
            ..Self::default()
        }
    }

    /// A connector with explicit TLS policy provenance, permitting member-local CA additions.
    pub fn serving_with_trust(
        judge: Arc<dyn DialJudge>,
        trust: busbar_contract::transport::trust::EgressTrust,
        wake: WakeTicket,
    ) -> Result<Self, tls::client::BadClientIdentity> {
        let config = Arc::new(tls::client::build_client_config(&trust)?);
        let mut connector = Self::serving(judge, Some(config), wake);
        connector.tls_policy = Some(trust);
        Ok(connector)
    }

    /// The same connector resolving its programs' environment references through `secrets`, at
    #[must_use]
    pub fn resolving_spawn_secrets(mut self, secrets: spawn_env::SpawnSecretFn) -> Self {
        self.spawn_secrets = Some(secrets);
        self
    }

    /// INSTALL THE TRUST STORE every later dial selects its TLS configuration from (boot-time; a
    /// second install replaces the first, as the effective configuration replaces the bootstrap
    /// one).
    pub fn install_trust_store(&self, store: Arc<tls::store::TrustStore>) {
        egress_audit::install_store(Arc::clone(&store));
        self.trust.store(Some(store));
    }

    /// THE CLIENT TLS CONFIG for a dial of `target` (the guard-judged target, `host:port` or a
    /// URL): the trust store's selection for its host, else the connector's own. A destination no
    /// anchor applies to is refused, coded and audited.
    fn tls_for(&self, target: &str) -> Result<Option<Arc<rustls::ClientConfig>>, ConnError> {
        let Some(store) = self.trust.load_full() else {
            return Ok(self.tls.clone());
        };
        match store.config_for(&host_of(target)) {
            Ok(Some(config)) => Ok(Some(config)),
            Ok(None) => Ok(self.tls.clone()),
            Err(refusal) => {
                crate::cold::conns::trust_refused(target, &refusal);
                Err(ConnError::Refused)
            }
        }
    }

    /// Set `advanced.proxy_resolution`: `true` = `local` (judge and CONNECT by address), `false`
    /// = `proxy` (CONNECT by name; the proxy resolves a name busbar cannot).
    pub fn set_proxy_by_address(&self, by_address: bool) {
        self.proxy_by_address.store(by_address, Ordering::Relaxed);
    }

    /// Whether `caller`'s open of `desc` carries its owner's core-held plaintext acceptance: the
    /// opener stated it ([`OpenDesc::plaintext_accepted`]) or the host registered the owner's
    /// acceptance ([`DeclaredConns::accept_plaintext`]). SEC-2 (#297 model A): nothing else does.
    fn plaintext_accepted(&self, caller: InstanceId, desc: &OpenDesc<'_>) -> bool {
        desc.plaintext_accepted || self.owner_accepts_plaintext(caller)
    }

    /// Whether the host registered `owner`'s core-held plaintext acceptance
    /// ([`DeclaredConns::accept_plaintext`]).
    fn owner_accepts_plaintext(&self, owner: InstanceId) -> bool {
        self.plaintext_owners
            .lock()
            .expect("plaintext owners")
            .contains(&owner)
    }

    /// Whether an exact `advanced.tls.destinations` entry admits plaintext to `authority`'s host.
    fn plaintext_admitted(&self, authority: &str) -> bool {
        self.trust
            .load()
            .as_ref()
            .is_some_and(|s| s.plaintext_admitted(&host_of(authority)))
    }

    /// The framer `owner`'s `need` rides, located at `target` (empty = the need's own, as an open
    fn framer_head(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
    ) -> Result<HeadDefaults, ConnError> {
        self.framer_located(owner, need, target)
            .map(|(head, _)| head)
    }

    /// [`Connector::framer_head`], keeping the framer's whole locate answer for the open that
    /// dials it ([`Conns::open_located`]). Only a framer's own locate is carried: a carrier's
    /// answer and a datagram's rendezvous are worked out again at the open, as before.
    fn framer_located(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
    ) -> Result<(HeadDefaults, Option<Arc<LocatedTarget>>), ConnError> {
        let native = self.native_need(owner, need).ok_or(ConnError::Refused)?;
        self.native_head(&native, target).map(|head| (head, None))
    }

    /// Where `target` goes per the entry serving `owner`'s `need`, framed or native: `None` = no such need;
    /// `Some(None)` = its entry does not locate the target; else the place and whether a carrier (carried as
    /// itself) serves it.
    fn place_of(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
    ) -> Option<Option<(native_conns::Placed, bool)>> {
        self.native_need(owner, need)?;
        Some(native_dial::locate(target).ok().map(|located| {
            (
                native_conns::Placed {
                    authority: located.authority,
                    secure: located.secure,
                },
                false,
            )
        }))
    }

    /// The same connector dialling every framed connection through the proxy `config` selects for
    #[must_use]
    pub fn proxying(mut self, config: Option<Arc<proxy::ProxyChoice>>) -> Self {
        self.proxy = config;
        self
    }

    /// Publish the effective boot's validated transport view, listener ports and pool posture
    pub fn finalize_boot_metadata(&self, own_ports: &[u16], posture: PoolPosture) {
        self.judge.own_ports_applied(own_ports);
        self.pools.reconfigure(posture);
        crate::off_path::conns::flush_native_idle(&self.native_idle, None);
    }

    /// Judge `dest` under `class` (with the need's private reach when `reach`), the pended answer
    fn judge_into(
        &self,
        dest: &str,
        secure: bool,
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
        self.judge.judge_target_all(
            busbar_kernel::host_services::Destination {
                authority: dest,
                secure,
                egress_class: class,
            },
            reach,
            done,
        )
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
        declared
            .get(&(owner, need))
            .map(|(spec, _, _)| spec.clone())
    }

    /// Record that `owner` declared `need` — the only needs it may open. A need declared without a
    pub fn declare(&self, owner: InstanceId, need: NeedId) {
        self.slab.declare(owner, need);
    }

    /// Whether a loaded transport entry serves `transport` (a scheme).
    #[must_use]
    pub fn serves_scheme(&self, transport: &str) -> bool {
        Self::dials_natively(transport)
    }

    /// Flag `diag` for `owner` once: the first time an instance meets an ABI rule, one coded line
    /// and one audit record; `false` (nothing written) every time after.
    fn flag_once(
        &self,
        owner: InstanceId,
        diag: &busbar_contract::diagnostic::Diagnostic,
        refusal: busbar_kernel::audit::auditlog::PluginRefusal,
        what: &str,
    ) -> bool {
        let first = self
            .flagged
            .lock()
            .expect("flagged")
            .insert((owner, diag.code));
        if first {
            crate::cold::conns::flag_first(owner, diag, refusal, what);
        }
        first
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
        // Made once at declaration and shared by every open (an `Arc` clone, not a copy).
        let declared_target: Option<Arc<str>> = declared_target.map(Arc::from);
        // Core's scheme table dials the scheme natively, through the transport the build assigns its
        // carrier (looked up at each open: a carrier no image carries is refused there).
        if !Self::dials_natively(transport) {
            self.set_native_need(owner, need, None);
            return Err(ConnError::Refused);
        }
        self.slab.declare(owner, need);
        self.set_native_need(
            owner,
            need,
            Some(native_conns::NativeNeed {
                egress_class,
                declared_target,
                tls,
                tls_policy,
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
    ) -> Result<(), NeedRefusal> {
        let unlocated = |_| NeedRefusal::Policy(refusal_text::UNLOCATED);
        endpoint::named(target).map_err(unlocated)?;
        let (located, carried) = self
            .place_of(owner, need, target)
            .ok_or(NeedRefusal::Policy(refusal_text::CHECKS))?
            .ok_or(NeedRefusal::Policy(refusal_text::UNLOCATED))?;
        endpoint::named(&located.authority).map_err(unlocated)?;
        if !scheme_admits(egress_class, located.secure) {
            return Err(NeedRefusal::Policy(refusal_text::PLAINTEXT));
        }
        let judged_class = guard::judged_class(egress_class, true);
        if let Some(v) = self
            .judge
            .judge_target_static(busbar_kernel::host_services::Destination {
                authority: &located.authority,
                secure: located.secure,
                egress_class: judged_class,
            })
        {
            return Err(verdict_reason(v, false));
        }
        if socket::address_of(&located.authority).is_some() {
            // The admission's clock memo: either refusal below is its one reading.
            let mut now = None;
            match self.judge.judge_target_all(
                busbar_kernel::host_services::Destination {
                    authority: &located.authority,
                    secure: located.secure,
                    egress_class: judged_class,
                },
                false,
                Box::new(|_, _| {}),
            ) {
                Some(Ok(addr))
                    if class_admits(
                        egress_class,
                        located.secure,
                        (carried && carrier_window_admits(egress_class))
                            || self.plaintext_admitted(&located.authority)
                            || self.owner_accepts_plaintext(owner),
                        &[],
                        addr,
                    ) => {}
                Some(Ok(_)) => {
                    egress_audit::dial_refused(
                        &located.authority,
                        Some(egress_class),
                        "plaintext",
                        Some((owner.0, need.0)),
                        &mut now,
                    );
                    return Err(NeedRefusal::Policy(refusal_text::PLAINTEXT));
                }
                Some(Err(v)) => {
                    egress_audit::dial_refused(
                        &located.authority,
                        Some(egress_class),
                        egress_audit::verdict_name(v),
                        Some((owner.0, need.0)),
                        &mut now,
                    );
                    return Err(verdict_reason(v, false));
                }
                None => {}
            }
        }
        Ok(())
    }

    /// Record (or, with `None`, drop) the native need `owner` declared as `need`.
    pub(crate) fn set_native_need(
        &self,
        owner: InstanceId,
        need: NeedId,
        record: Option<native_conns::NativeNeed>,
    ) {
        let before = {
            let mut needs = self.native_needs.lock().expect("native needs");
            match record {
                Some(r) => needs.insert((owner, need), Arc::new(r)),
                None => needs.remove(&(owner, need)),
            }
        };
        drop(before);
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
        let native = held.native.as_ref().ok_or(ConnError::Closed)?;
        let read = self.read_native(native, waker, buf);
        if read.is_ok() {
            held.answered();
        }
        read
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
fn host_of(target: &str) -> std::borrow::Cow<'_, str> {
    if target.contains("://") {
        if let Ok(parts) = busbar_contract::net::parse_url(target) {
            return std::borrow::Cow::Owned(parts.host);
        }
    }
    let authority = target.split(['/', '?', '#']).next().unwrap_or(target);
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if !port.contains(']') => h,
        _ => authority,
    };
    std::borrow::Cow::Borrowed(host.trim_start_matches('[').trim_end_matches(']'))
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

impl DeclaredConns for Connector {
    fn open_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.open_timed(
            caller,
            need,
            desc,
            (require_secure, Some(dial_timeout_ms), false),
            (None, None),
        )
    }

    fn prepare_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.open_timed(
            caller,
            need,
            desc,
            (false, Some(dial_timeout_ms), true),
            (None, None),
        )
    }

    fn hold_authority(&self, owner: InstanceId) {
        self.authority_held
            .lock()
            .expect("authority held")
            .insert(owner);
    }

    fn accept_plaintext(&self, owner: InstanceId) {
        self.plaintext_owners
            .lock()
            .expect("plaintext owners")
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
            .and_then(crate::off_path::conns::without_userinfo);
        let target = cleared.as_deref().or(target);
        let credentialed = target.is_some_and(carries_userinfo);
        let untargeted_infrastructure = outbound
            && spec.egress_class == EGRESS_OPERATOR_INFRASTRUCTURE
            && spec.target_from.is_empty()
            && Self::dials_natively(&spec.transport);
        let anchored = match trust.filter(|_| outbound) {
            None => Ok(None),
            Some(pem) => {
                crate::off_path::conns::operator_anchors(owner, need, &spec.trust_from, pem)
            }
        };
        let untrusted = anchored.is_err();
        let mut why = None;
        let answer = match anchored {
            Ok(_) if !outbound => {
                if !spec.transport.is_empty() && !self.serves_scheme(&spec.transport) {
                    why = Some(NeedRefusal::Policy(refusal_text::UNSERVED));
                    Err(ConnError::Refused)
                } else {
                    self.slab.declare(owner, need);
                    Ok(())
                }
            }
            Ok(_) if untargeted_infrastructure => {
                self.flag_once(
                    owner,
                    &busbar_kernel::diagnostics::PLUGIN_DECLARES_RETIRED_ABI_VALUE,
                    busbar_kernel::audit::auditlog::PluginRefusal::Need,
                    &crate::cold::conns::untargeted_infrastructure(&spec.transport),
                );
                self.set_native_need(owner, need, None);
                Err(ConnError::Refused)
            }
            Ok(tls) if !(spec.transport.is_empty() || unresolved || credentialed) => self
                .record(owner, need, &spec.transport, spec.egress_class, target, tls)
                .inspect_err(|_| {
                    why = Some(NeedRefusal::Policy(
                        if self.serves_scheme(&spec.transport) {
                            refusal_text::CHECKS
                        } else {
                            refusal_text::UNSERVED
                        },
                    ));
                })
                .and_then(|()| match target {
                    Some(pinned) => self
                        .admits_pinned(owner, need, pinned, spec.egress_class)
                        .map_err(|refused| {
                            self.set_native_need(owner, need, None);
                            why = Some(refused);
                            ConnError::Refused
                        }),
                    None => Ok(()),
                }),
            _ => {
                why = Some(NeedRefusal::Policy(if credentialed {
                    refusal_text::CREDENTIALED
                } else if unresolved {
                    refusal_text::UNRESOLVED
                } else if untrusted {
                    refusal_text::TRUST
                } else {
                    refusal_text::CHECKS
                }));
                self.set_native_need(owner, need, None);
                Err(ConnError::Refused)
            }
        };
        self.declared
            .lock()
            .expect("declared needs")
            .insert((owner, need), (spec.clone(), answer, why));
        answer
    }

    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        let declared = self.declared.lock().expect("declared needs");
        declared.get(&(owner, need)).map(|(_, answer, _)| *answer)
    }

    /// THE DIAL HAS LANDED: its judgement answered and the far end took the connect (a name's
    fn landed(&self, caller: InstanceId, conn: ConnId, ticket: Ticket) -> Result<(), ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        let native = held.native.as_ref().ok_or(ConnError::Closed)?;
        let waker = self.waker(caller, ticket);
        held.watch_deadlines(DeadlineInterest::Ticket(ticket), &waker);
        self.landed_native(native, &waker)
    }

    /// A need is framed when the entry serving its transport is a FRAMER (http's kind, over the
    fn request_head(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        _timeout_ms: u64,
    ) -> Result<HeadDefaults, ConnError> {
        self.framer_head(owner, need, target)
    }

    fn framed(&self, owner: InstanceId, need: NeedId) -> bool {
        self.native_need(owner, need).is_some()
    }

    fn serves_scheme(&self, transport: &str) -> bool {
        Connector::serves_scheme(self, transport)
    }

    fn declare_program(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        _program: &busbar_contract::conn::Program,
    ) -> Result<(), ConnError> {
        self.program_unserved(owner, need, spec)
    }

    fn cause(&self, owner: InstanceId, conn: ConnId) -> Option<ConnCause> {
        let (_, held) = self.slab.get(owner, conn).ok()?;
        Self::native_cause(held.native.as_ref()?)
    }

    fn refusal(&self, owner: InstanceId, need: NeedId) -> Option<NeedRefusal> {
        let declared = self.declared.lock().expect("declared needs");
        declared
            .get(&(owner, need))
            .and_then(|(_, _, why)| why.clone())
    }

    fn bind_auth(
        &self,
        owner: InstanceId,
        need: NeedId,
        member: &str,
        origin: &str,
        binding: busbar_contract::conn::ConnAuth,
    ) {
        crate::off_path::conns::bind_auth(
            &mut self.auths.lock().expect("auth bindings"),
            (owner, need),
            member,
            origin,
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
            .get(&owner)
            .and_then(|needs| needs.get(&need))
            .and_then(|members| members.get(member))
            .and_then(|origins| origins.get(origin))
            .cloned()
    }

    fn declare_member_programs(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        _programs: &[(String, busbar_contract::conn::Program)],
    ) -> Result<(), ConnError> {
        self.program_unserved(owner, need, spec)
    }

    fn declare_member_programs_from(
        &self,
        _predecessor: InstanceId,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        _programs: &[(String, busbar_contract::conn::Program)],
    ) -> Result<(), ConnError> {
        self.program_unserved(owner, need, spec)
    }

    /// THE INSTANCE IS GONE: its connections close (a member lease among them ends), then every
    fn forget(&self, owner: InstanceId) {
        // Retirement is lifecycle work, built off the request path.
        self.retire(owner);
    }
}

impl Connector {
    /// A PROGRAM NEED IS NOT SERVED: no transport on the new interface spawns a program, so its
    /// declaration is refused and the refusal kept, as an unserved scheme's is.
    fn program_unserved(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
    ) -> Result<(), ConnError> {
        let answer = Err(ConnError::Refused);
        self.declared.lock().expect("declared needs").insert(
            (owner, need),
            (
                spec.clone(),
                answer,
                Some(NeedRefusal::Policy(refusal_text::UNSERVED)),
            ),
        );
        answer
    }
}

impl Connector {
    /// Open `desc` on `caller`'s `need`, holding why the open failed before any connection existed
    /// as the need's refusal ([`DeclaredConns::refusal`]); an open that succeeds clears it. `how`:
    /// whether the line must be secure, the dial's own timeout, whether the open is only prepared.
    fn open_timed(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        how: (bool, Option<u64>, bool),
        head: (Option<&Arc<LocatedTarget>>, Option<OwnedHead>),
    ) -> Result<ConnId, ConnError> {
        let mut why = None;
        let opened = self.open_timed_reasoned(caller, need, desc, how, head, &mut why);
        if let Some(held) = self
            .declared
            .lock()
            .expect("declared needs")
            .get_mut(&(caller, need))
        {
            held.2 = if opened.is_ok() { None } else { why };
        }
        opened
    }

    fn open_timed_reasoned(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        (require_secure, dial_timeout_ms, prepare): (bool, Option<u64>, bool),
        (_, owned): (Option<&Arc<LocatedTarget>>, Option<OwnedHead>),
        why: &mut Option<NeedRefusal>,
    ) -> Result<ConnId, ConnError> {
        let started = crate::clock::now();
        self.slab.check_need(caller, need)?;
        let declared_timeout_ms = self
            .declared
            .lock()
            .expect("declared needs")
            .get(&(caller, need))
            .map_or(0, |(spec, _, _)| spec.timeout_ms);
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
        // The head the opener built and moved in, where it did: every check below reads it as the
        // borrowed fields an opener lending it would have passed, and the dial keeps it uncopied.
        let lent = owned.as_ref().map(OwnedHead::view);
        let viewed = lent.as_deref().map(|fields| OpenDesc {
            fields,
            ..desc.clone()
        });
        let read = viewed.as_ref().unwrap_or(desc);
        if request_head_is_refused(caller, need, read, authority_held) {
            return Err(ConnError::Refused);
        }

        let native = self.native_need(caller, need).ok_or(ConnError::Refused)?;
        // A natively served need has no member programs: a field only a program reads is refused.
        if prepare || read.fields.iter().any(|(name, _)| is_expected_field(name)) {
            return Err(ConnError::Refused);
        }
        drop(viewed);
        drop(lent);
        let held = self.open_native(
            (caller, need),
            desc,
            &native,
            (started, open_timeout),
            require_secure,
            owned,
            why,
        )?;
        self.slab.insert(caller, need, held)
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
        self.open_timed(
            caller,
            need,
            desc,
            (require_secure, None, false),
            (None, None),
        )
    }

    fn open_located(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        located: Option<&Arc<LocatedTarget>>,
    ) -> Result<ConnId, ConnError> {
        self.open_timed(
            caller,
            need,
            desc,
            (require_secure, None, false),
            (located, None),
        )
    }

    fn open_owned(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        head: OwnedHead,
        require_secure: bool,
        located: Option<&Arc<LocatedTarget>>,
    ) -> Result<ConnId, ConnError> {
        self.open_timed(
            caller,
            need,
            desc,
            (require_secure, None, false),
            (located, Some(head)),
        )
    }

    /// A write is taken whole, short, or (no room under
    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        _end: bool,
        _text: bool,
    ) -> Result<usize, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        let native = held.native.as_ref().ok_or(ConnError::Closed)?;
        self.write_native(native, bytes)
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
        // A native entry has no look-ahead of its answer: the first is named ready, and its read
        // answers Pending (with the ticket's waker kept) when nothing has arrived.
        let Some(conn) = set.first() else {
            return Err(ConnError::Pending);
        };
        let waker = self.waker(caller, ticket);
        let (_, held) = self.slab.get(caller, *conn)?;
        held.watch_deadlines(DeadlineInterest::Ticket(ticket), &waker);
        Ok(0)
    }

    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        held.within_due()?;
        let native = held.native.as_ref().ok_or(ConnError::Closed)?;
        Self::native_facts(native)
    }

    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        let held = self.slab.remove(caller, conn)?;
        held.answered();
        if let Some(native) = &held.native {
            self.close_native(native);
        }
        Ok(())
    }
}

impl PollConns for Connector {
    fn failure_cause(&self, caller: InstanceId, conn: ConnId) -> Option<ConnCause> {
        DeclaredConns::cause(self, caller, conn)
    }

    /// The framer the need rides, located at `target`: its own head lines, and whether its head
    fn head_defaults(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        _timeout_ms: u64,
    ) -> Result<HeadDefaults, ConnError> {
        self.framer_head(owner, need, target)
    }

    fn locate_head(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        _timeout_ms: u64,
    ) -> Result<(HeadDefaults, Option<Arc<LocatedTarget>>), ConnError> {
        self.framer_located(owner, need, target)
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
        let native = self.native_need(owner, need);
        // The need's own client config and its policy; else the connector's.
        let own = native
            .as_ref()
            .map(|n| (n.tls.as_deref(), n.tls_policy.as_ref()));
        let base = own.and_then(|(tls, _)| tls).or(self.tls.as_deref());
        let policy = match own {
            Some((Some(_), policy)) => policy,
            _ => self.tls_policy.as_ref(),
        };
        let located = self
            .place_of(owner, need, target)
            .flatten()
            .map(|(placed, _)| placed);
        if anchors.private_reach && (member.is_empty() || located.is_none()) {
            return Err(ConnError::Refused);
        }
        let located_secure = located.as_ref().is_some_and(|l| l.secure);
        let at = located.map(|mut l| {
            l.authority.make_ascii_lowercase();
            (owner, need, l.authority)
        });
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
        let mut by_member = self.member_anchored.lock().expect("anchors");
        let mut registered = self.registered.lock().expect("anchors");
        let before = match &at {
            Some((_, _, authority)) => {
                by_member.insert(owner, need, member, (authority.clone(), sealed.clone()))
            }
            None => by_member.remove(owner, need, member),
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
        if at.is_none() {
            self.reaching
                .lock()
                .expect("reach")
                .remove(owner, need, member);
        }
        if let Some(at) = at {
            let mut reaching = self.reaching.lock().expect("reach");
            if anchors.private_reach {
                reaching.insert(owner, need, member, (at.2.clone(), located_secure));
            } else {
                reaching.remove(owner, need, member);
            }
            crate::off_path::conns::seal_registration(
                &mut registered.entry(at).or_default().members,
                member,
                sealed,
            );
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
        if !reach {
            self.reaching
                .lock()
                .expect("reach")
                .remove(owner, need, member);
            return Ok(());
        }
        let (mut located, _) = self
            .place_of(owner, need, target)
            .flatten()
            .ok_or(ConnError::Refused)?;
        if member.is_empty() {
            return Err(ConnError::Refused);
        }
        located.authority.make_ascii_lowercase();
        self.reaching.lock().expect("reach").insert(
            owner,
            need,
            member,
            (located.authority, located.secure),
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/native_conns_tests.rs"]
mod native_conns_tests;

#[cfg(test)]
#[path = "tests/explain_tests.rs"]
mod explain_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/support_lib.rs"]
pub(crate) mod support;

#[cfg(test)]
#[path = "tests/waiter_order_tests.rs"]
mod waiter_order_tests;
