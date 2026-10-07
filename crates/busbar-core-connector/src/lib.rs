// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-core-connector` — THE CONNECTOR (THE DESIGN: connections). The chain is kernel →
//! connector → transport plugins: every plugin that needs an external connection declares a need,
//! and the kernel instantiates the transport through this crate. The kernel knows nothing about
//! transport; this crate is where everything below the framer lives.
//!
//! * [`Connector`] is the host side of the one connection table every kind reaches the network
//!   through ([`busbar_contract::conn::Conns`]): a plugin opens a connection for a need it declared,
//!   then writes, reads, waits and closes it. Ownership is the shared book
//!   ([`busbar_contract::conn::ConnSlab`]): a connection another instance owns, a closed one and a
//!   need nobody declared are refused.
//! * [`endpoint`] is the pure check an open's target passes before any dial: a cloud metadata host,
//!   in any spelling, is refused by name.
//! * [`guard`] is THE DESTINATION GUARD, the one check deciding which addresses any outbound
//!   connection may be dialled at (private refused unless allowlisted, metadata always).
//! * [`tls`] is connection security — core-only, never a plugin, never crossing the ABI.
//! * [`dtls`] is its datagram sibling — the DTLS engine a WebRTC association runs on (the RFC 7983
//!   demux, the ICE-gated bind, the SRTP exporter), on ring like [`tls`].
//! * [`udp`] is the host's datagram socket: one bound port, a peer per datagram.
//!
//! * [`hostio`] is THE HOST'S I/O (`io.*`): the one place that holds an OS handle (a stream, a
//!   listener, a program's pipes) and moves bytes over it, admitting only what the destination
//!   guard judged; [`io`] is readiness on the per-worker reactor (`io.{register, poll_ready,
//!   clear_ready, deregister}`) and [`socket`] the OS sockets, both its tools.
//! * [`carrier`] drives one carrier entry's slots (listen, accept, dial, read, write, flush, shut,
//!   arrival) inline on a connection's two sides: the bottom of every connection, and this crate's
//!   only way to the wire.
//! * [`framer`] drives one transport entry's framer table host-side; [`compose`] builds a
//!   connection as carrier -> \[TLS\] -> framer; [`pool`] keeps a dialled connection whose exchange
//!   finished whole for the next open to the same place; [`listen`] has the carrier listen for each
//!   inbound need and composes each accepted connection the same way, begun on the accept side;
//!   [`registry`] is the view of which entry serves which scheme; [`wire`] presents an entry over
//!   carried connections to the kernel's transport seam.
//! * [`process`] builds the process's one connector for the root: the deployment's one destination
//!   guard behind the one dial judge, and the default outbound trust.
//!
//! No `unsafe` is written here outside the tests' framer entry, which writes a host sink through its
//! raw pointers as a plugin does.
//!
//! No thread is started here, per connection or otherwise: every socket's readiness is the
//! registering worker's reactor's, and every wait is not-ready with a wake.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod carrier;
pub mod compose;
pub mod dtls;
pub mod endpoint;
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
pub mod registry;
pub mod socket;
/// The TLS test kit (far ends, the recording TLS fixture server, a private test CA) for this crate's
/// tests that need a real handshake, and (feature `test-support`) a plugin repo's conformance test:
/// TLS stays in the connector, even in a test.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod tls;
pub mod udp;
pub mod wire;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::host::service::{DEST_NO_ADDRESSES, DEST_PLAINTEXT, DEST_UNRESOLVABLE};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::transport::{ROLE_CARRIER, ROLE_FRAMER};
use busbar_contract::conn::{
    ConnCause, ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc,
    Piece, PieceKind, PollConns, Ticket, NO_TICKET,
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
use crate::pool::{PoolKey, PoolPosture, Pools};
use crate::registry::Transports;

/// How the host wakes a caller's ticket.
pub type WakeTicket = Arc<dyn Fn(Ticket) + Send + Sync>;

/// A `DEST_*` verdict (`busbar_contract::abi::host::service`) refusing a dial.
pub type Verdict = u64;

/// Where a pended judgement goes: the address to dial, or the verdict refusing it. Called once,
/// from any thread.
pub type Judged = Box<dyn FnOnce(Result<SocketAddr, Verdict>) + Send>;

/// A need's `egress_class` `0`: the connector's default class (`busbar_contract::abi::host::conn::
/// Need::egress_class`). A need declared in another class is judged under that class, never this.
pub const DEFAULT_CLASS: u32 = 0;

/// THE KERNEL'S DESTINATION JUDGE, as a dial reaches it (`dest.judge`, R-K): every authority the
/// connector dials is judged here and the connector dials EXACTLY the address the judgement pinned,
/// so a name is resolved once, by the judge, and never again. A refusal the name decides (and an IP
/// literal) answers at once, `Some`, before any resolution; a name that must resolve answers `None`
/// and `done` gets the pin or the refusal later, from any thread.
pub trait DialJudge: Send + Sync {
    /// Judge `dest` (`host:port`) under egress class `class`.
    fn judge_dial(
        &self,
        dest: &str,
        class: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, Verdict>>;

    /// [`DialJudge::judge_dial`] for a destination the dialling need holds a PRIVATE REACH to (the
    /// registration's `abi::plane::TRUST_PRIVATE_REACH`, sealed by [`PollConns::anchor`]): a
    /// private address is admitted as an allowlist entry naming the host would; cloud metadata
    /// never is; the class is unchanged. The default honours no reach (fail-closed).
    fn judge_dial_reaching(
        &self,
        dest: &str,
        class: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, Verdict>> {
        self.judge_dial(dest, class, done)
    }
}

/// Any function of the judge's shape is a judge: [`process::judge`] joins the deployment's one
/// destination guard here, so the connection table itself names no kernel type.
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
/// guard it holds (the strict default for [`Connector::new`]), and a name is refused, because
/// nothing here resolves one.
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
/// against the address the judge pinned: open-web dials over connection security only;
/// loopback-allowed over connection security, or in plaintext to loopback only; every other
/// class takes the scheme its target names (operator-infrastructure's plaintext included). Which
/// addresses may be dialled at all is the destination guard's ([`guard`]), the same in every class.
/// THE LANDING RULE rides with it: a dial stated `within` an address set (`EstablishIn::within`)
/// lands only on an address in it, so a name that resolves elsewhere since the plugin judged it
/// is refused at the connect, before any byte is written; an empty set states no pin.
fn class_admits(egress_class: u32, secure: bool, within: &[IpAddr], addr: SocketAddr) -> bool {
    (within.is_empty() || within.contains(&addr.ip()))
        && match egress_class {
            EGRESS_OPEN_WEB => secure,
            EGRESS_LOOPBACK_ALLOWED => secure || guard::is_loopback(addr.ip()),
            _ => true,
        }
}

/// WHAT A JUDGEMENT THAT PENDED ON A RESOLUTION ANSWERS THE CONNECTION'S CALLER (ARCHITECT parity
/// ruling A1). A name that did not resolve ([`DEST_UNRESOLVABLE`]), or resolved to no address
/// ([`DEST_NO_ADDRESSES`]), is a FAILED connection, the same failure a dial that found no far end
/// is ([`ConnError::Fault`], a FAILED outcome to a plugin): 1.5.5 held "a resolution FAILURE is not
/// a rejection. A collector whose DNS is briefly down is an availability event, not a security one"
/// (v1.5.5 `crates/busbar/src/observability.rs:588-590`, `otlp_resolves_to_internal`; its test
/// `otlp_resolve_check_allows_a_name_that_does_not_resolve`, `:1482-1490`), and its exporter
/// failed that batch and sent the next. Every other verdict is the guard's refusal
/// ([`ConnError::Refused`], a REFUSED outcome, which a sink reads as the run's answer). A verdict
/// decided at once is never a resolution's ([`DialJudge::judge_dial`]), so only a pended one is
/// read here.
fn pended_verdict(v: Verdict) -> ConnError {
    match v {
        DEST_UNRESOLVABLE | DEST_NO_ADDRESSES => ConnError::Fault,
        _ => ConnError::Refused,
    }
}

/// THE HEAD A PLUGIN WROTE, held to 1.5.5's rule for a plugin-described request (ARCHITECT parity
/// ruling A5; v1.5.5 `crates/busbar/src/auth/token.rs:805` `FORBIDDEN_HOP_HEADERS`, `:893-907`
/// `sanitize_hop_header`): a CR, LF or NUL in the target, a head word, a field name or a field
/// value, or a field that states the message's own framing (`content-length`,
/// `transfer-encoding`, any case), refuses the whole open before anything is dialled or sent. The
/// framer writes the framing for the bytes it sends; a plugin's own would describe another wire.
fn head_is_refused(desc: &OpenDesc<'_>) -> bool {
    const FRAMING: [&str; 2] = ["content-length", "transfer-encoding"];
    let breaks = |b: &[u8]| b.iter().any(|c| matches!(c, b'\r' | b'\n' | b'\0'));
    breaks(desc.target.as_bytes())
        || breaks(desc.method)
        || breaks(desc.head_target)
        || desc.fields.iter().any(|(name, value)| {
            breaks(name.as_bytes())
                || breaks(value)
                || FRAMING.iter().any(|f| name.trim().eq_ignore_ascii_case(f))
        })
}

/// What the connector holds for one declared need: the entry serving its transport, resolved once
/// at declare (a need no entry serves is refused there, never at its open; spec Part 2 #50).
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
    /// The program the need's `target_from` resolved to: every open spawns it.
    program: Option<busbar_contract::conn::Program>,
    /// A member-program need's members (`busbar_contract::section::MEMBER_PROGRAM`): every open
    /// names one and leases its one long-lived program connection.
    members: Option<Arc<program::Members>>,
}

/// A judgement's answer once it came, and the waker of the read or wait that found none.
type Answer = Arc<Mutex<(Option<Result<SocketAddr, Verdict>>, Option<Waker>)>>;

/// The trust anchors sealed per destination (the transport pin, ARCHITECT 2026-10-03), by the need's owner, the need and
/// the destination's authority (lower-case, `host:port`).
type Anchored = Mutex<HashMap<(InstanceId, NeedId, String), Arc<tls::client::Sealed>>>;

/// The listeners, one per inbound need, by the need's owner and need.
type Listeners = Mutex<HashMap<(InstanceId, NeedId), Arc<Mutex<Listening>>>>;

/// A dial whose judgement pended: what to dial once it answers, the answer, and the waker of the
/// read or wait that found it unanswered.
struct Judging {
    planned: Option<Planned>,
    /// The need's egress class, whose scheme rule the pinned address is held to.
    egress_class: u32,
    /// The address set the pinned address must be in (`OpenDesc::within`); empty = any.
    within: Vec<IpAddr>,
    /// Writes the caller made before the dial, in order.
    early: Vec<(Vec<u8>, bool, bool)>,
    answer: Answer,
}

/// What an exchange lent a pooled line keeps to redial it ONCE on a fresh connection when that line
/// fails before any byte of the exchange left (ARCHITECT ruling Q-L18-RETRY, 1.5.5's pooled client
/// re-sending a request its pooled connection closed under before it was written; never once a byte
/// left, so nothing is sent twice, and no failover: the caller sees one exchange).
struct Redial {
    door: Arc<dyn FramerDoor>,
    dial: Dial,
    egress_class: u32,
    judged_class: u32,
    /// The need's private reach to the destination ([`DialJudge::judge_dial_reaching`]).
    reach: bool,
    /// The bytes the line's socket had taken when the exchange was lent it.
    mark: u64,
}

/// One connection the connector holds for its owner: the line it rides and the stream it reads
/// there (a dialled exchange's own; an accepted connection's every stream).
struct Held {
    line: Mutex<Option<(Arc<Line>, u64)>>,
    /// The judgement the dial waits on; `None` once dialled.
    judging: Mutex<Option<Judging>>,
    /// The piece a short caller buffer left, and whether the end was answered.
    rest: Mutex<(Option<Piece>, Vec<u8>, bool)>,
    /// The far end's reason phrase, held until its head's last piece is read.
    reason: Mutex<Option<Vec<u8>>>,
    /// Where a dialled connection goes back to when its exchange finished whole: its pool shard
    /// and key (`None` = never pooled).
    pooled: Option<(usize, PoolKey)>,
    /// The dialled exchange ended WHOLE (its stream's end was read).
    whole: AtomicBool,
    /// The one redial an exchange lent a pooled line keeps.
    redial: Mutex<Option<Redial>>,
    /// A LEASE on a member's long-lived program connection, in place of a connection of its own.
    lease: Option<(Arc<program::Member>, u64)>,
}

impl Held {
    fn over(
        line: Option<(Arc<Line>, u64)>,
        judging: Option<Judging>,
        pooled: Option<(usize, PoolKey)>,
    ) -> Self {
        Held {
            line: Mutex::new(line),
            judging: Mutex::new(judging),
            rest: Mutex::new((None, Vec::new(), false)),
            reason: Mutex::new(None),
            pooled,
            whole: AtomicBool::new(false),
            redial: Mutex::new(None),
            lease: None,
        }
    }

    fn line(&self) -> Option<(Arc<Line>, u64)> {
        self.line.lock().expect("line").clone()
    }
}

impl Drop for Held {
    /// A lease no one closed (its owner dropped it) is closed as it goes: the member's program does
    /// not keep frames for a reader that is gone.
    fn drop(&mut self) {
        if let Some((member, lease)) = self.lease.take() {
            member.close(lease);
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

/// THE CONNECTOR: the host side of the connection table.
pub struct Connector {
    slab: ConnSlab<Held>,
    /// The transport each declared need names, the egress class its dials are judged under, and
    /// the target its config names (`target_from`), when it names one.
    over: Mutex<HashMap<(InstanceId, NeedId), DeclaredNeed>>,
    /// Every need an instance declared through [`DeclaredConns::declare`], whole, and the answer
    /// it got.
    declared: Mutex<HashMap<(InstanceId, NeedId), Declared>>,
    transports: RwLock<Transports>,
    tls: Option<Arc<rustls::ClientConfig>>,
    wake: WakeTicket,
    judge: Arc<dyn DialJudge>,
    /// One listener per inbound need.
    listeners: Listeners,
    /// The per-worker pools of dialled connections.
    pools: Pools,
    /// The trust anchors each sealed destination's connections are held to.
    anchored: Anchored,
    /// The REGISTRATIONS holding a PRIVATE REACH (`abi::plane::TRUST_PRIVATE_REACH`), by the need's
    /// owner, the need and the registration's name, each with the authority (lower-case,
    /// `host:port`) of its own target ([`PollConns::seal_reach`]).
    reaching: Mutex<HashMap<(InstanceId, NeedId, String), String>>,
    /// Each member's auth binding, by (instance, need, target origin): what a plugin's own request
    /// to that member is authenticated with ([`DeclaredConns::bind_auth`]).
    auths: Mutex<HashMap<(InstanceId, NeedId, String), busbar_contract::conn::ConnAuth>>,
    /// THE HOST'S I/O every carrier is served from ([`hostio`]): the one holder of OS handles.
    io: Arc<HostIo>,
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
            wake: Arc::new(|_| {}),
            judge: Arc::new(LiteralsOnly(guard::Guard::default())),
            listeners: Mutex::new(HashMap::new()),
            pools: Pools::new(PoolPosture::NONE),
            anchored: Mutex::new(HashMap::new()),
            reaching: Mutex::new(HashMap::new()),
            auths: Mutex::new(HashMap::new()),
            io: hostio::process(),
        }
    }
}

struct TicketWake {
    wake: WakeTicket,
    ticket: Ticket,
}

impl Wake for TicketWake {
    fn wake(self: Arc<Self>) {
        (self.wake)(self.ticket);
    }
}

fn map(f: &Failure) -> ConnError {
    match f {
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
    /// securing connections with `tls` where a target asks for it, and waking a caller's ticket
    /// through `wake`.
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

    /// The same connector serving its carriers from `io`: the host I/O the process's dispatcher serves
    /// every carrier instance (`io.*`), so what the connector admits is what the carriers reach.
    #[must_use]
    pub fn with_io(mut self, io: Arc<HostIo>) -> Self {
        self.io = io;
        self
    }

    /// The host I/O this connector's carriers are served from.
    #[must_use]
    pub fn io(&self) -> &Arc<HostIo> {
        &self.io
    }

    /// THE CARRIER OF A NETWORK ADDRESS, as a connection rides it: the first loaded carrier whose
    /// own claim selects on the local port ([`registry::Transports::address_carrier`]); `None` =
    /// none is loaded.
    #[must_use]
    pub fn address_via(&self) -> Option<Via> {
        let view = self.transports.read().expect("transports");
        view.address_carrier().map(|e| Via {
            door: Arc::clone(&e.door),
            io: Arc::clone(&self.io),
        })
    }

    /// What a need served by `door` rides: a CARRIER is carried as itself (no framer); a FRAMER
    /// rides the address carrier ([`Connector::address_via`]).
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
    /// carried as itself reading its target as an authority.
    fn plan(&self, door: &Arc<dyn FramerDoor>, dial: Dial) -> Result<Planned, Failure> {
        match self.ride_on(door) {
            Some((Some(framer), via)) => Planned::locate(framer, via, dial),
            Some((None, via)) => Planned::carried(via, dial),
            None => Err(Failure::Refused(
                "no carrier is loaded to reach an address".into(),
            )),
        }
    }

    /// Where `target` goes, per the entry `door` serves: its authority, security and name.
    fn located(&self, door: &Arc<dyn FramerDoor>, target: &str) -> Option<framer::Located> {
        if door.facts().role == ROLE_CARRIER {
            let claim = door.facts().claims.first().copied().unwrap_or_default();
            return compose::carried_at(claim, target).ok();
        }
        framer::locate(door.as_ref(), target).ok()
    }

    /// The same connector keeping dialled connections under `posture` (the deployment's
    /// `limits.pool_max_idle_per_host` / `limits.pool_idle_timeout_secs`): an open to a place a
    /// finished exchange's connection went back to rides that connection ([`pool`]).
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
    /// transport (an inbound need: it listens and accepts) dials nothing, and an open on it is
    /// refused.
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
    /// arrived on that claim (ARCHITECT 4l, [`framed_stream`]).
    #[must_use]
    pub fn framer_for(&self, scheme: &str) -> Option<Arc<dyn framer::FramerDoor>> {
        self.transports
            .read()
            .expect("transports")
            .serving(scheme)
            .map(|s| Arc::clone(&s.entry.door))
    }

    /// Record that `owner` declared `need` over `transport` (a scheme the registry view serves), in
    /// the default egress class ([`DEFAULT_CLASS`]).
    ///
    /// # Errors
    ///
    /// No loaded transport serves `transport` ([`ConnError::Refused`]); nothing is recorded.
    pub fn declare_over(
        &self,
        owner: InstanceId,
        need: NeedId,
        transport: &str,
    ) -> Result<(), ConnError> {
        self.declare_need(owner, need, transport, DEFAULT_CLASS)
    }

    /// Record that `owner` declared `need` over `transport`, its dials judged under the need's own
    /// `egress_class` (`Need::egress_class`).
    ///
    /// # Errors
    ///
    /// No loaded transport serves `transport` ([`ConnError::Refused`]); nothing is recorded.
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
    /// the need's config (`target_from`) and resolved to `declared_target`. Every open on the need
    /// must dial that target: another authority, or the same one under another security, is
    /// refused before any judgement or dial.
    ///
    /// # Errors
    ///
    /// No loaded transport serves `transport` ([`ConnError::Refused`]); nothing is recorded.
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

    /// THE SCHEME MATCH (spec Part 2 #50: "no match => fail closed"): the need is recorded over the
    /// entry serving `transport`, resolved here once, or refused here; an open never meets an
    /// unserved scheme. `tls` is the need's own client config when its `trust_from` named an
    /// operator CA.
    fn record(
        &self,
        owner: InstanceId,
        need: NeedId,
        transport: &str,
        egress_class: u32,
        declared_target: Option<&str>,
        tls: Option<Arc<rustls::ClientConfig>>,
    ) -> Result<(), ConnError> {
        let served = {
            let view = self.transports.read().expect("transports");
            view.serving(transport)
                .map(|served| (Arc::clone(&served.entry.door), served.entry.alpn.clone()))
        };
        let Some((door, alpn)) = served else {
            // Any earlier record of the need is dropped with it.
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
                program: None,
                members: None,
            }),
        );
        Ok(())
    }

    /// Record (or, with `None`, drop) what the connector holds for `owner`'s `need`: a member of an
    /// earlier record that the new one does not keep is RETIRED (no open reaches it again; its
    /// program is killed once its last open closes).
    fn set_need(&self, owner: InstanceId, need: NeedId, record: Option<DeclaredNeed>) {
        let kept = record.as_ref().and_then(|r| r.members.clone());
        let before = {
            let mut over = self.over.lock().expect("needs");
            match record {
                Some(r) => over.insert((owner, need), r),
                None => over.remove(&(owner, need)),
            }
        };
        for (name, member) in before.and_then(|b| b.members).iter().flat_map(|m| m.iter()) {
            if !kept
                .as_ref()
                .and_then(|k| k.get(name))
                .is_some_and(|k| Arc::ptr_eq(k, member))
            {
                member.retire();
            }
        }
    }

    /// THE MEMBER-PROGRAM NEED (`busbar_contract::section::MEMBER_PROGRAM`): `owner`'s outbound
    /// `need` reaches each member's own program (its pipes framed by the entry serving
    /// `transport`), ONE long-lived connection per member, carried as a program need is
    /// ([`Connector::record_program`]: operator-infrastructure only, no auth style, a CARRIER
    /// entry). A member whose program is unchanged keeps its running
    /// program across the re-declaration; one that is gone or changed is retired.
    ///
    /// # Errors
    ///
    /// [`ConnError::Refused`] for anything else; any earlier record of the need is dropped (its
    /// members retired).
    fn record_members(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        programs: &[(String, busbar_contract::conn::Program)],
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
            && programs.iter().all(|(_, p)| p.command.starts_with('/'));
        let Some((door, alpn)) = served.filter(|_| carried) else {
            self.set_need(owner, need, None);
            return Err(ConnError::Refused);
        };
        let before = self
            .over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .and_then(|d| d.members.clone());
        let members: program::Members = programs
            .iter()
            .map(|(name, p)| {
                let kept = before
                    .as_ref()
                    .and_then(|b| b.get(name))
                    .filter(|m| m.program() == p)
                    .cloned();
                let member = kept.unwrap_or_else(|| {
                    Arc::new(program::Member::new(
                        p.clone(),
                        Via {
                            door: Arc::clone(&door),
                            io: Arc::clone(&self.io),
                        },
                        alpn.clone(),
                    ))
                });
                (name.clone(), member)
            })
            .collect();
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
                program: None,
                members: Some(Arc::new(members)),
            }),
        );
        Ok(())
    }

    /// THE PROGRAM NEED: `owner`'s outbound `need` dials `program` (its pipes, framed by the entry
    /// serving `transport`). Carried only in the operator-infrastructure class (the operator wrote
    /// the program into config), with no auth style (no credential rides a pipe), over an entry
    /// that is a CARRIER (its tail's role: a byte stream carried as itself).
    ///
    /// # Errors
    ///
    /// [`ConnError::Refused`] for anything else; any earlier record of the need is dropped.
    fn record_program(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        program: &busbar_contract::conn::Program,
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
            && program.command.starts_with('/');
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
                program: Some(program.clone()),
                members: None,
            }),
        );
        Ok(())
    }

    /// Bind the one listener for `owner`'s INBOUND `need` on `bind` (`ip:port`), over the transport
    /// the need was declared over, secured by `tls` where set (the protocols agreed off the entry's
    /// registered offer), bounded by `limits`. Answers the address bound. Called on a worker.
    ///
    /// # Errors
    ///
    /// The need is not `owner`'s or names no transport served here ([`ConnError::Refused`]), it
    /// already listens, or the address cannot be bound ([`ConnError::Fault`]).
    pub fn listen(
        &self,
        owner: InstanceId,
        need: NeedId,
        bind: &str,
        tls: Option<Arc<rustls::ServerConfig>>,
        limits: AcceptLimits,
    ) -> Result<SocketAddr, ConnError> {
        self.slab.check_need(owner, need)?;
        // A need declared without a transport binds nothing.
        let (door, alpn) = self
            .over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .map(|d| (Arc::clone(&d.door), d.alpn.clone()))
            .ok_or(ConnError::Refused)?;
        let mut listeners = self.listeners.lock().expect("listeners");
        if listeners.contains_key(&(owner, need)) {
            return Err(ConnError::Refused);
        }
        let (framer, via) = self.ride_on(&door).ok_or(ConnError::Refused)?;
        let l =
            Listening::bind(framer, &via, bind, tls, alpn, limits).map_err(|_| ConnError::Fault)?;
        let addr = l.local_addr();
        listeners.insert((owner, need), Arc::new(Mutex::new(l)));
        Ok(addr)
    }

    /// The next connection `owner`'s inbound `need` admitted, held for `owner` like one it
    /// opened: read, written (`emit` on the piece's stream), waited and closed through the same
    /// table. [`ConnError::Pending`] wakes `ticket` when one arrives.
    ///
    /// # Errors
    ///
    /// The need does not listen for `owner` ([`ConnError::Refused`]); an accepted socket that could
    /// not be composed ([`ConnError::Fault`]; the listener stays up).
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
        let waker = self.waker(ticket);
        let got = l
            .lock()
            .expect("listener")
            .poll_accept(&mut Context::from_waker(&waker));
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
    /// complete, `text` = it is a text message): an accepted connection answers each piece on the
    /// stream it came on.
    ///
    /// # Errors
    ///
    /// The connection is not `caller`'s, is closed or failed, or the framer refused the bytes.
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

    /// Dial a held connection whose judgement has answered. `Ok(false)`: still judging, `waker`
    /// (where given) registered for the answer. A refusal stays the connection's answer.
    fn settle(&self, held: &Held, waker: Option<&Waker>) -> Result<bool, ConnError> {
        let mut judging = held.judging.lock().expect("judging");
        let Some(j) = judging.as_mut() else {
            return Ok(true);
        };
        let got = {
            let mut a = j.answer.lock().expect("judgement");
            match a.0 {
                None => {
                    if let Some(w) = waker {
                        a.1 = Some(w.clone());
                    }
                    return Ok(false);
                }
                Some(got) => got,
            }
        };
        let addr = got.map_err(pended_verdict)?;
        let secure = j.planned.as_ref().is_some_and(Planned::secure);
        if !class_admits(j.egress_class, secure, &j.within, addr) {
            // The refusal stays the connection's answer.
            j.answer.lock().expect("judgement").0 = Some(Err(DEST_PLAINTEXT));
            return Err(ConnError::Refused);
        }
        let planned = j.planned.take().ok_or(ConnError::Refused)?;
        let early = std::mem::take(&mut j.early);
        *judging = None;
        let conn = planned.dial_at(addr).map_err(|f| map(&f))?;
        let line = self.ride(held, conn);
        for (bytes, end, text) in early {
            line.emit(EXCHANGE_STREAM, &bytes, end, text)
                .map_err(|f| map(&f))?;
        }
        Ok(true)
    }

    /// `held` rides `conn`, just dialled, as its first exchange; a pooled exchange's line is held
    /// in its shard's pool from now on (shared once it multiplexes).
    fn ride(&self, held: &Held, conn: Connection) -> Arc<Line> {
        let line = Line::new(conn);
        if let Some((shard, key)) = &held.pooled {
            self.pools.hold(*shard, key.clone(), &line);
        }
        *held.line.lock().expect("line") = Some((Arc::clone(&line), EXCHANGE_STREAM));
        line
    }

    /// Judge `planned`'s authority under `judged_class` and dial the pinned address, held to the
    /// need's egress class and `within`: the connection at once when the judgement answered at
    /// once, else the judgement in flight (an address refusal answers the read or wait that finds
    /// it).
    ///
    /// # Errors
    ///
    /// A judgement that refused at once, or a dial that could not start.
    fn dial_judged(
        &self,
        planned: Planned,
        egress_class: u32,
        judged_class: u32,
        within: &[IpAddr],
        reach: bool,
    ) -> Result<(Option<Connection>, Option<Judging>), ConnError> {
        let answer: Answer = Arc::new(Mutex::new((None, None)));
        let answering = Arc::clone(&answer);
        let done: Judged = Box::new(move |v| {
            let mut a = answering.lock().expect("judgement");
            a.0 = Some(v);
            if let Some(w) = a.1.take() {
                w.wake();
            }
        });
        // A destination the need holds a private reach to is judged with it (the one guard, as an
        // allowlist entry naming it; the class unchanged).
        let judged = if reach {
            self.judge
                .judge_dial_reaching(planned.authority(), judged_class, done)
        } else {
            self.judge
                .judge_dial(planned.authority(), judged_class, done)
        };
        Ok(match judged {
            // Decided at once: a refusal answers the open, as 1.5.5 answered it.
            Some(Err(_)) => return Err(ConnError::Refused),
            Some(Ok(addr)) if !class_admits(egress_class, planned.secure(), within, addr) => {
                return Err(ConnError::Refused)
            }
            Some(Ok(addr)) => (Some(planned.dial_at(addr).map_err(|f| map(&f))?), None),
            None => (
                None,
                Some(Judging {
                    planned: Some(planned),
                    egress_class,
                    within: within.to_vec(),
                    early: Vec::new(),
                    answer,
                }),
            ),
        })
    }

    /// THE ONE REDIAL (ARCHITECT ruling Q-L18-RETRY): `held` was lent a pooled line that failed
    /// before any byte of its exchange left. The line is let go and the exchange's opening is
    /// dialled afresh, judged as any dial is. `Ok(false)`: no redial is owed (none kept, already
    /// spent, or a byte had left).
    fn redial(&self, held: &Held) -> Result<bool, ConnError> {
        let mut kept = held.redial.lock().expect("redial");
        let Some((line, stream)) = held.line() else {
            return Ok(false);
        };
        if kept.as_ref().is_none_or(|r| line.flushed() != r.mark) {
            *kept = None;
            return Ok(false);
        }
        let Some(r) = kept.take() else {
            return Ok(false);
        };
        drop(kept);
        *held.line.lock().expect("line") = None;
        self.let_go(held, &line, stream, false);
        let planned = self.plan(&r.door, r.dial).map_err(|f| map(&f))?;
        match self.dial_judged(planned, r.egress_class, r.judged_class, &[], r.reach)? {
            (Some(conn), _) => {
                self.ride(held, conn);
            }
            (None, judging) => *held.judging.lock().expect("judging") = judging,
        }
        Ok(true)
    }

    /// `held`'s exchange leaves `line` (`whole` = its answer was read to its end): the line goes
    /// back to its pool, or is closed, once nobody holds it.
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
    /// plugin's ticket) and [`Conns::poll_read`] (a host-side reader's waker) share.
    fn read_waking(
        &self,
        caller: InstanceId,
        conn: ConnId,
        waker: &Waker,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        if let Some((member, lease)) = &held.lease {
            return member.read(*lease, waker, buf);
        }
        let mut rest = held.rest.lock().expect("rest");
        let (piece, bytes) = match rest.0.take() {
            Some(p) => (p, std::mem::take(&mut rest.1)),
            None => {
                if rest.2 {
                    return Err(ConnError::Closed);
                }
                let got = loop {
                    if !self.settle(&held, Some(waker))? {
                        return Err(ConnError::Pending);
                    }
                    let (line, stream) = held.line().ok_or(ConnError::Closed)?;
                    match line.poll_piece(stream, &mut Context::from_waker(waker)) {
                        Poll::Pending => return Err(ConnError::Pending),
                        // A lent pooled line that ended or failed before any byte of this
                        // exchange left: redialled once, fresh, and read again.
                        Poll::Ready(Err(_) | Ok(None)) if self.redial(&held)? => {}
                        Poll::Ready(Err(f)) => return Err(map(&f)),
                        Poll::Ready(Ok(None)) => {
                            rest.2 = true;
                            return Ok(completion(0));
                        }
                        Poll::Ready(Ok(Some(got))) => break (got, stream),
                    }
                };
                let (got, stream) = got;
                let dialled = stream != EVERY;
                // An answer arrived: a byte of the exchange had left, so no redial is owed.
                *held.redial.lock().expect("redial") = None;
                if dialled && got.stream == stream && got.ends_stream() {
                    // A DIALLED exchange's stream ending whole is the exchange's completion
                    // (`busbar_contract::abi::transport`, "streams end by flag"): the caller
                    // has the whole answer, and the line may carry the next one.
                    rest.2 = true;
                    held.whole.store(true, Ordering::Release);
                    return Ok(completion(got.stream));
                }
                if dialled && got.stream == stream && got.failed {
                    // Its stream FAILED (the framer's reason is never the caller's payload): the
                    // exchange fails, and the line is not kept.
                    rest.2 = true;
                    return Err(ConnError::Fault);
                }
                // The far end's head (and its trailers) arrive as the framer's field block: a
                // Fields piece, the head ahead of the first Body piece.
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
                        status_namespace: None,
                        retry_after_secs: got.retry_after_secs,
                        fault: WireFault::from_code(got.fault),
                        reason: None,
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
            // The caller's buffer is short: this piece does not end its frame yet, and the rest
            // is the next read's.
            out.end = false;
            rest.0 = Some(piece);
            rest.1 = bytes[n..].to_vec();
        } else if out.kind == PieceKind::Fields && out.end {
            // The head's last piece: its reason phrase follows the field block in the caller's
            // buffer, where the buffer holds it too.
            if let Some(reason) = held.reason.lock().expect("reason").take() {
                if let Some(to) = buf.get_mut(n..n + reason.len()) {
                    to.copy_from_slice(&reason);
                    out.reason = Some(n..n + reason.len());
                }
            }
        }
        Ok(out)
    }

    fn waker(&self, ticket: Ticket) -> Waker {
        if ticket == NO_TICKET {
            return Waker::noop().clone();
        }
        Waker::from(Arc::new(TicketWake {
            wake: Arc::clone(&self.wake),
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
    }
}

/// Whether a dial target carries a userinfo (`user:pass@`): a URL by the contract's one reader, a
/// bare `host:port` by its authority.
fn carries_userinfo(target: &str) -> bool {
    match busbar_contract::net::parse_url(target) {
        Ok(parts) => parts.userinfo,
        Err(_) => target
            .split(['/', '?', '#'])
            .next()
            .is_some_and(|authority| authority.contains('@')),
    }
}

impl DeclaredConns for Connector {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        // An outbound need is carried over the transport its claim names, its dials judged in its
        // own egress class, and pinned to the target its config names when it names one (a
        // `target_from` that resolved to nothing is refused, and so is a target carrying a
        // userinfo: a credential never rides a dial target, it travels in the request's own
        // headers — FAIL-CLOSED, ARCHITECT ruling 2026-10-02; any earlier pin is dropped), and
        // refused when no loaded transport serves its scheme (spec Part 2 #50; the loader fails
        // the boot on it, naming the plugin and the scheme). Its connections are secured with the
        // operator CA its `trust_from` names added on top of the public roots (ARCHITECT ruling
        // 2026-10-02): a `trust_from` that resolved to nothing, or to a PEM that does not parse
        // into a trust anchor, refuses the need here, at declaration. An inbound need is recorded
        // (the listener binds it), and refused on an unserved scheme alike.
        let outbound = spec.direction == DIRECTION_OUTBOUND;
        // A member-target need (`settings.*.<key>`) is pinned by no one target: each member's route
        // is sealed at its own, and dials it like any need the plugin names per open.
        let per_member = |path: &str| busbar_contract::section::member_target(path).is_some();
        let unresolved = (!spec.target_from.is_empty()
            && !per_member(&spec.target_from)
            && target.is_none())
            || (!spec.trust_from.is_empty() && !per_member(&spec.trust_from) && trust.is_none());
        let credentialed = target.is_some_and(carries_userinfo);
        let anchored = match trust.filter(|_| outbound) {
            None => Ok(None),
            Some(pem) => tls::client::operator_ca_config(pem.as_bytes()).map(|c| Some(Arc::new(c))),
        };
        let answer = match anchored {
            // An inbound need over a scheme no loaded transport serves is refused the same way.
            Ok(_) if !outbound => {
                if !spec.transport.is_empty() && !self.serves_scheme(&spec.transport) {
                    Err(ConnError::Refused)
                } else {
                    self.slab.declare(owner, need);
                    Ok(())
                }
            }
            Ok(tls) if !(spec.transport.is_empty() || unresolved || credentialed) => {
                self.record(owner, need, &spec.transport, spec.egress_class, target, tls)
            }
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
    /// config (the public roots and the operator CA its `trust_from` named, on top), or the
    /// connector's default trust for a need that names none, offering `name` or the endpoint's
    /// host name, bounded by the open's default timeout. A framed need's stream is refused (its
    /// framer, not the plugin, speaks on it), and so is a `trust` reference other than the need's
    /// own `trust_from`.
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
            // The operator's opt-in to an unverified handshake: an operator-infrastructure need's
            // only (ARCHITECT ruling 2026-10-03 on Q-L16-4).
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
        let waker = self.waker(ticket);
        if !self.settle(&held, Some(&waker))? {
            return Err(ConnError::Pending);
        }
        let (line, _) = held.line().ok_or(ConnError::Closed)?;
        let name = match name {
            Some(n) => n.to_owned(),
            None => host_of(&line.target().ok_or(ConnError::Closed)?),
        };
        match line.upgrade_secure(
            &config,
            &name,
            DEFAULT_OPEN_TIMEOUT,
            &mut Context::from_waker(&waker),
        ) {
            Poll::Ready(Ok(())) => Ok(()),
            Poll::Ready(Err(f)) => Err(map(&f)),
            Poll::Pending => Err(ConnError::Pending),
        }
    }

    /// A need is framed when the entry serving its transport is a FRAMER (its tail's role, ARCHITECT
    /// ruling Q128 U7: http's kind, over the carrier the connector chose); a CARRIER entry is a raw
    /// stream.
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
        let answer = self.record_program(owner, need, spec, program);
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
        origin: &str,
        binding: busbar_contract::conn::ConnAuth,
    ) {
        self.auths
            .lock()
            .expect("auth bindings")
            .insert((owner, need, origin.to_string()), binding);
    }

    fn auth_of(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
    ) -> Option<busbar_contract::conn::ConnAuth> {
        let origin = busbar_contract::conn::origin_of(target);
        self.auths
            .lock()
            .expect("auth bindings")
            .get(&(owner, need, origin.to_string()))
            .cloned()
    }

    fn declare_member_programs(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        programs: &[(String, busbar_contract::conn::Program)],
    ) -> Result<(), ConnError> {
        let answer = self.record_members(owner, need, spec, programs);
        self.declared
            .lock()
            .expect("declared needs")
            .insert((owner, need), (spec.clone(), answer));
        answer
    }
}

impl Conns for Connector {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need)?;
        if head_is_refused(desc) {
            return Err(ConnError::Refused);
        }
        // A need declared without a transport (an inbound need) dials nothing.
        let DeclaredNeed {
            door,
            alpn,
            egress_class,
            declared_target,
            tls,
            program,
            members,
        } = self
            .over
            .lock()
            .expect("needs")
            .get(&(caller, need))
            .cloned()
            .ok_or(ConnError::Refused)?;
        // A MEMBER-PROGRAM NEED leases the long-lived program of the member the target names (a
        // member its config does not name is refused); the open's body is the lease's first
        // message. No address is judged: no network is dialled.
        if let Some(members) = members {
            if !desc.fields.is_empty() {
                return Err(ConnError::Refused);
            }
            let member = members
                .get(program::member_of(desc.target))
                .cloned()
                .ok_or(ConnError::Refused)?;
            let lease = member.lease(desc.body)?;
            let mut held = Held::over(None, None, None);
            held.lease = Some((member, lease));
            // A refused insert drops the held lease, which closes it.
            return self.slab.insert(caller, need, held);
        }
        // A PROGRAM NEED spawns the program its config names, and nothing else: an open naming a
        // target of its own is refused. No address is judged: no network is dialled.
        if let Some(program) = program {
            if !desc.target.is_empty() {
                return Err(ConnError::Refused);
            }
            let dial = Dial {
                anchors: None,
                target: program.command.clone(),
                tls: None,
                alpn,
                open_timeout: DEFAULT_OPEN_TIMEOUT,
                opening: Some((
                    desc.fields
                        .iter()
                        .map(|(n, v)| ((*n).to_owned(), v.to_vec()))
                        .collect(),
                    desc.body.to_vec(),
                )),
                head_words: (desc.method.to_vec(), desc.head_target.to_vec()),
            };
            let via = Via {
                door,
                io: Arc::clone(&self.io),
            };
            let conn = Connection::spawn(&via, &program, dial).map_err(|f| map(&f))?;
            // A program is a dialled, single-use line (no pool, no judgement): its one exchange
            // rides EXCHANGE_STREAM, as a freshly dialled connection's does.
            let line = Line::new(conn);
            return self.slab.insert(
                caller,
                need,
                Held::over(Some((line, EXCHANGE_STREAM)), None, None),
            );
        }
        // No target named: the need's own, its config's (`EstablishIn.target` absent = the need's
        // `target_from`).
        let target = match (desc.target, declared_target.as_deref()) {
            ("", Some(declared)) => declared,
            (named, _) => named,
        };
        let open_timeout = if desc.timeout_ms == 0 {
            DEFAULT_OPEN_TIMEOUT
        } else {
            Duration::from_millis(desc.timeout_ms)
        };
        // A UNIX-DOMAIN TARGET (`unix:/path`; ARCHITECT ruling 2026-10-03 12:10Z, VALKEY-UNIX):
        // served to an operator-infrastructure (or loopback-allowed) need as a raw stream, every
        // other class refused; there is no address to resolve or judge. A need whose config names
        // its target dials that path and no other.
        if let Some(path) = socket::unix_path(target) {
            if !matches!(
                egress_class,
                EGRESS_OPERATOR_INFRASTRUCTURE | EGRESS_LOOPBACK_ALLOWED
            ) || declared_target.as_deref().is_some_and(|d| d != target)
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
                    desc.body.to_vec(),
                )),
                head_words: (desc.method.to_vec(), desc.head_target.to_vec()),
            };
            let (framer, via) = self.ride_on(&door).ok_or(ConnError::Refused)?;
            let conn = Connection::dial_unix(framer, &via, dial, path).map_err(|f| map(&f))?;
            // A unix-domain dial is a dialled, single-use line (no pool, no judgement), as a
            // program's is: its one exchange rides EXCHANGE_STREAM.
            let line = Line::new(conn);
            return self.slab.insert(
                caller,
                need,
                Held::over(Some((line, EXCHANGE_STREAM)), None, None),
            );
        }
        endpoint::check(target).map_err(|_| ConnError::Refused)?;
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
                desc.body.to_vec(),
            )),
            head_words: (desc.method.to_vec(), desc.head_target.to_vec()),
            anchors: None,
        };
        let planned = self.plan(&door, dial).map_err(|f| map(&f))?;
        // THE DESTINATION'S TRUST ANCHORS (the transport pin, ARCHITECT 2026-10-03): every connection to a sealed
        // destination is held to them; one that pins the far end's key and is not secured has no
        // key to hold, and is refused before any judgement or dial.
        let anchors = self
            .anchored
            .lock()
            .expect("anchors")
            .get(&(caller, need, planned.authority().to_ascii_lowercase()))
            .cloned();
        if anchors
            .as_ref()
            .is_some_and(|a| a.key_pin.is_some() && !planned.secure())
        {
            return Err(ConnError::Refused);
        }
        let planned = planned.anchored(anchors);
        // THE REGISTRATION'S PRIVATE REACH (`abi::plane::TRUST_PRIVATE_REACH`, sealed per
        // registration): an open that names a registration holding one, to that registration's own
        // authority, is judged with it; no other open is.
        let reach = !desc.member.is_empty()
            && self
                .reaching
                .lock()
                .expect("reach")
                .get(&(caller, need, desc.member.to_owned()))
                .is_some_and(|at| at.eq_ignore_ascii_case(planned.authority()));
        // A TARGET THE NEED'S CONFIG NAMES IS THE OPERATOR'S OWN (THE DESIGN §5 egress-class
        // table, owner-signed 2026-09-27): in a request-data class its address is judged as
        // operator infrastructure. A provider need keeps its class: it is refused a private
        // address unless allowlisted (ARCHITECT ruling CRATES-14, `guard::judged_class`).
        let judged_class = guard::judged_class(egress_class, declared_target.is_some());
        // THE DECLARED TARGET (1.5.5's per-module target guarantee, on every need): a need whose
        // config names its target dials that target and no other.
        if let Some(declared) = declared_target {
            let located = self.located(&door, &declared).ok_or(ConnError::Refused)?;
            if !located.authority.eq_ignore_ascii_case(planned.authority())
                || located.secure != planned.secure()
            {
                return Err(ConnError::Refused);
            }
        }
        // SCHEME BY EGRESS CLASS: open-web is secure-only, decided by the target before any
        // judgement; loopback-allowed's plaintext-to-loopback rule is held against the pinned
        // address below.
        if egress_class == EGRESS_OPEN_WEB && !planned.secure() {
            return Err(ConnError::Refused);
        }
        // THE POOL: on this worker's shard, a live h2 line to the same place carries this
        // exchange as its next stream, or a line an earlier exchange finished on carries it
        // (judged, pinned and secured when it was dialled, under the same class); a dial pinned
        // `within` an address set is never pooled.
        let pooled = (self.pools.keeps() && desc.within.is_empty()).then(|| {
            (
                self.pools.shard(),
                PoolKey {
                    door: Arc::as_ptr(&door).cast::<()>() as usize,
                    authority: planned.authority().to_ascii_lowercase(),
                    secure: planned.secure(),
                    name: planned.name().map(str::to_owned),
                    class: (judged_class, egress_class),
                    reach,
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
                    reach,
                    mark: line.flushed(),
                };
                let (opening, words) = planned.into_opening();
                match line.attach(opening, words) {
                    Ok(stream) => {
                        let held = Held::over(Some((line, stream)), None, pooled);
                        *held.redial.lock().expect("redial") = Some(redial);
                        return self.slab.insert(caller, need, held);
                    }
                    // The attach wrote the opening and THEN found the line failed (the far end's
                    // close met in the same drive that flushed it): a byte of the exchange left,
                    // so it is never re-sent (Q-L18-RETRY). It holds the failed line and its read
                    // answers the failure, as a failure met at the first read does; the line is
                    // let go when it closes. Whether the failure is met here or at that read is
                    // the far end's timing; the verdict is the socket's count either way.
                    Err((stream, _)) if line.flushed() != redial.mark => {
                        let held = Held::over(Some((line, stream)), None, pooled);
                        return self.slab.insert(caller, need, held);
                    }
                    // The lent line failed before the exchange left (ARCHITECT ruling
                    // Q-L18-RETRY): it is let go, and the exchange dials a fresh connection.
                    Err((stream, _)) => {
                        line.leave(stream, false);
                        self.pools.drop_line(*shard, key, &line);
                        planned = self.plan(&redial.door, redial.dial).map_err(|f| map(&f))?;
                    }
                }
            }
        }
        let (conn, judging) =
            self.dial_judged(planned, egress_class, judged_class, desc.within, reach)?;
        let held = Held::over(None, judging, pooled);
        if let Some(conn) = conn {
            self.ride(&held, conn);
        }
        self.slab.insert(caller, need, held)
    }

    /// A write is taken whole, short, or (no room under
    /// [`WRITE_BUFFER_BYTES`](crate::compose::WRITE_BUFFER_BYTES)) not at all: `Pending`. A pending
    /// write registers no ticket of its own; the bytes already held are flushed whenever the
    /// connection is driven (every `read` and `wait` on it drives the socket and drains the buffer),
    /// so a caller that got `Pending` re-offers the bytes after its next read or wait.
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
        if !self.settle(&held, None)? {
            if let Some(j) = held.judging.lock().expect("judging").as_mut() {
                // Held until the judgement answers, under the same cap a connection's buffer has.
                let held_bytes: usize = j.early.iter().map(|(b, _, _)| b.len()).sum();
                let take = bytes
                    .len()
                    .min(WRITE_BUFFER_BYTES.saturating_sub(held_bytes));
                if take == 0 && !bytes.is_empty() {
                    return Err(ConnError::Pending);
                }
                j.early
                    .push((bytes[..take].to_vec(), end && take == bytes.len(), text));
                return Ok(take);
            }
        }
        let (line, stream) = held.line().ok_or(ConnError::Closed)?;
        match line.emit(stream, bytes, end, text) {
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
        self.read_waking(caller, conn, &self.waker(ticket), buf)
    }

    fn wait(&self, caller: InstanceId, set: &[ConnId], ticket: Ticket) -> Result<usize, ConnError> {
        let waker = self.waker(ticket);
        let mut cx = Context::from_waker(&waker);
        for (at, conn) in set.iter().enumerate() {
            let (_, held) = self.slab.get(caller, *conn)?;
            if let Some((member, lease)) = &held.lease {
                match member.ready(*lease, &waker) {
                    Ok(false) => continue,
                    _ => return Ok(at),
                }
            }
            if held.rest.lock().expect("rest").0.is_some() {
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
                return Ok(at);
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
        if let Some((member, lease)) = &held.lease {
            // The lease ends here; the member's program runs on for the next open.
            member.close(*lease);
        }
        let line = held.line.lock().expect("line").take();
        if let Some((line, stream)) = line {
            // An exchange that finished whole hands its line back to the pool it came from once
            // nobody else rides it; any other close lets the line go.
            self.let_go(&held, &line, stream, held.whole.load(Ordering::Acquire));
        }
        Ok(())
    }
}

impl PollConns for Connector {
    fn poll_read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Piece, ConnError>> {
        match self.read_waking(caller, conn, cx.waker(), buf) {
            Err(ConnError::Pending) => Poll::Pending,
            done => Poll::Ready(done),
        }
    }

    /// The anchors are sealed against the authority the need's own entry locates `target` at, the
    /// identity parsed once under the connector's client config; every open on the need to that
    /// authority is then held to them ([`Conns::open`]: a pinned key over no connection security is
    /// refused there, and [`compose`] refuses a far end serving another key after its handshake).
    fn anchor(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        anchors: &busbar_contract::transport::trust::Anchors,
    ) -> Result<(), ConnError> {
        let door = self
            .over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .map(|d| Arc::clone(&d.door));
        let located = door.as_ref().and_then(|door| self.located(door, target));
        let at = located.map(|l| (owner, need, l.authority.to_ascii_lowercase()));
        if anchors.is_empty() {
            // Nothing to hold: any earlier seal for the destination is dropped.
            if let Some(at) = at {
                self.anchored.lock().expect("anchors").remove(&at);
            }
            return Ok(());
        }
        let at = at.ok_or(ConnError::Refused)?;
        let sealed =
            tls::client::seal(self.tls.as_deref(), anchors).map_err(|_| ConnError::Refused)?;
        self.anchored
            .lock()
            .expect("anchors")
            .insert(at, Arc::new(sealed));
        Ok(())
    }

    /// The registration's own target's authority is read by the need's entry, as a dial reads it;
    /// the reach is kept under the registration's name, so two registrations at one authority hold
    /// their own answers.
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
