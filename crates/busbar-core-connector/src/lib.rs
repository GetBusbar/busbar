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
//! * [`endpoint`] is the pure check an open's target passes before any dial: it names a host. A
//!   dial no judge judges also refuses a cloud metadata or link-local host there, by name.
//! * [`guard`] is THE DESTINATION GUARD, the one check deciding which addresses any judged
//!   outbound connection may be dialled at (private refused unless allowlisted; cloud metadata and
//!   link-local refused unless an IP or CIDR allowlist entry, or a provider's 1.5.5 carve-out,
//!   names them).
//! * [`tls`] is connection security — core-only, never a plugin, never crossing the ABI.
//! * [`dtls`] is its datagram sibling — the DTLS engine a media association runs on (the RFC 7983
//!   demux, the ICE-gated bind, the SRTP exporter), on ring like [`tls`].
//! * [`udp`] is the host's datagram socket: one bound port, a peer per datagram.
//! * [`datagram`] drives one association's datagram framer over the port and the dtls engine: the
//!   datagram lane on every call, the keying-material item presented once, routes and path
//!   requests only where the secure layer allows them.
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
//!   [`registry`] is the view of which entry serves which scheme; [`wire`] is the boot fold's
//!   admission of an entry (its key, and no layer it composes over).
//! * [`process`] builds the process's one connector for the root: the deployment's one destination
//!   guard behind the one dial judge, the default outbound trust, and the proxy environment.
//! * [`fetch`] is the `plugins.fetch` download over the connection table, the root's own need.
//! * [`proxy`] is the proxy environment every framed dial honours (`HTTPS_PROXY`, `HTTP_PROXY`,
//!   `ALL_PROXY`, `NO_PROXY`), the CONNECT tunnel 1.5.5's clients ran.
//!
//! No `unsafe` is written here outside two places: the reactor registration in [`io::register`],
//! one call to tokio's `AsyncFd::register_with_interest` on a descriptor the registration owns
//! (RUSTSEC-2026-0386), and the tests' framer entry, which writes a host sink through its raw
//! pointers as a plugin does.
//!
//! No thread is started per connection: every socket's readiness is the registering worker's
//! reactor's, and every wait is not-ready with a wake. The threads that are started: a name lookup
//! runs on one of its own (the system resolver blocks), at most [`compose::MAX_PENDING_LOOKUPS`]
//! at once; the spawn environment keeps one refresher ([`spawn_env`]); a plugin download runs on a
//! scoped one of its own ([`fetch`]).

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod carrier;
pub mod compose;
pub mod datagram;
mod dialled;
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
pub mod registry;
pub mod socket;
pub mod spawn_env;
/// The TLS test kit (far ends, the recording TLS fixture server, a private test CA) for this crate's
/// tests that need a real handshake, and (feature `test-support`) a plugin repo's conformance test:
/// TLS stays in the connector, even in a test.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod tls;
pub mod udp;
pub mod wire;

use std::collections::{HashMap, HashSet};
use std::future::Future as _;
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
use crate::pool::{PoolKey, PoolPosture, Pools, SealRef};
use crate::registry::Transports;

/// How the host wakes a caller's ticket, naming the caller that handed it the ticket: the supplier
/// the host blames for a ticket it never minted (#74).
pub type WakeTicket = busbar_contract::conn::ConnWake;

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

    /// THE STATIC ARM ALONE: the refusal `dest` (`host:port`) meets under class `class` before any
    /// resolution (the guard's name arm: a metadata name, an obfuscated literal, ...), or `None`
    /// when nothing static refuses it. Never resolves. A pinned need's admission at declare asks
    /// it ([`Connector::admits_pinned`]); every dial still meets the whole judgement. The default
    /// knows no static refusal.
    fn judge_static(&self, dest: &str, class: u32) -> Option<Verdict> {
        let _ = (dest, class);
        None
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
/// loopback-allowed over connection security, or in plaintext only to a target whose host is
/// WRITTEN as loopback ([`guard::names_loopback`]: a loopback literal in any spelling, `localhost`,
/// `*.localhost`), as 1.5.5's collector and webrequest guards ruled on the URL's host and never on
/// what a name resolved to (ARCHITECT parity ruling A3); every other
/// class takes the scheme its target names (operator-infrastructure's plaintext included). Which
/// addresses may be dialled at all is the destination guard's ([`guard`]), the same in every class.
/// THE LANDING RULE rides with it: a dial stated `within` an address set (`EstablishIn::within`)
/// lands only on an address in it, so a name that resolves elsewhere since the plugin judged it
/// is refused at the connect, before any byte is written; an empty set states no pin.
/// THE SCHEME RULE THE TARGET DECIDES ALONE, before any judgement: open-web dials over connection
/// security only. An open holds its target to it ([`Conns::open`]), and so does a pinned need's
/// admission at declare ([`Connector::admits_pinned`]); loopback-allowed's plaintext-to-loopback
/// rule needs the pinned address and is [`class_admits`]'s.
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
/// Where the host writes the opener's authority (`authority_held`,
/// [`DeclaredConns::hold_authority`]: every instance of the auth kind), a `host` field of the
/// plugin's own refuses the open too, as 1.5.5 refused it on an auth module's request; every other
/// opener (a plane's upstream, which may sign its `host`) keeps the field it wrote.
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
    /// The program the need's `target_from` resolved to, its environment references held as its
    /// declaration resolved them: every open spawns it.
    program: Option<(busbar_contract::conn::Program, spawn_env::HeldEnv)>,
    /// A member-program need's members (`busbar_contract::section::MEMBER_PROGRAM`): every open
    /// names one and leases its one long-lived program connection.
    members: Option<Arc<program::Members>>,
}

/// A judgement's answer once it came, and the waker of the read or wait that found none.
type Answer = Arc<Mutex<(Option<Result<SocketAddr, Verdict>>, Option<Waker>)>>;

/// The trust anchors sealed per destination (the transport pin, ARCHITECT 2026-10-03), by the need's owner, the need and
/// the destination's authority (lower-case, `host:port`).
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
    /// answer every seal gives (the destination's own first, then the registrations' in name order,
    /// so the same seal answers every open), or `Err` where two disagree.
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
/// (its certificate chain), `None` and a seal holding nothing alike.
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
    pins && identities
}

/// The trust anchors sealed per REGISTRATION, by the need's owner, the need and the registration's
/// name: the authority (lower-case, `host:port`) of its own target and what it is held to there
/// (`None`: the registration holds no anchors, and borrows none of another registration's).
type MemberAnchored =
    Mutex<HashMap<(InstanceId, NeedId, String), (String, Option<Arc<tls::client::Sealed>>)>>;

/// What a member's auth binding is held under: the need's owner, the need, the registration's
/// name and its target's origin (`scheme://authority`).
type AuthKey = (InstanceId, NeedId, String, String);

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
    /// A dial through a proxy ([`proxy`]): the proxy, and whether the target's own judgement has
    /// answered (the pended answer is then the proxy's).
    proxied: Option<Proxied>,
}

/// A dial through a proxy, judged in two steps: the target (its name arm, and its own resolution
/// when it resolves here; a name that does not resolve here goes to the proxy, which resolves it),
/// then the proxy's own address (a private proxy admitted, cloud metadata never).
struct Proxied {
    spec: Arc<proxy::ProxyHop>,
    judged_class: u32,
    target_judged: bool,
}

/// Whether a target judgement's refusal is only that the name does not resolve HERE: behind a
/// proxy, the proxy resolves it (the engine's tunnelled arm; reach behind the proxy is the proxy's
/// boundary).
fn unresolved_here(verdict: Verdict) -> bool {
    verdict == DEST_UNRESOLVABLE || verdict == DEST_NO_ADDRESSES
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
    /// THE REQUEST'S WHOLE BOUND until its answer (`OpenDesc::timeout_ms`; `None` = unbounded
    /// here): see [`Due`].
    due: Mutex<Option<Due>>,
    /// A held session's UPSTREAM LEG over a datagram framer's need ([`dialled`]): its exchange
    /// rides this connection's line, then its reads and writes are the leg's.
    dialled: Option<dialled::Dialled>,
}

/// THE WHOLE REQUEST'S BOUND (`RequestPiece::timeout_ms`, BUSBAR-1.6.0.md:4890 "timeout clamped to
/// the deadline class"; the `call` class, :3496-3505): from the open, through the dial, the
/// judgement, the handshake and the send, until the far end's FIRST piece of its answer. Past it a
/// read is answered [`ConnError::Timeout`], and a reader waiting on the connection is woken to read
/// it. Once an answer has begun the bound is spent: what bounds a streamed answer is its own class,
/// as its reader keeps it, never this one (an answer cut mid-stream by a time-to-answer bound would
/// be a different outcome from the one the reader chose).
struct Due {
    at: std::time::Instant,
    timer: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
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
            due: Mutex::new(None),
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

    /// Bounded by `timeout_ms` from now until its answer begins; `0` = no bound of its own.
    fn bounded(self, timeout_ms: u64) -> Self {
        if timeout_ms != 0 {
            *self.due.lock().expect("due") = Some(Due {
                at: std::time::Instant::now() + Duration::from_millis(timeout_ms),
                timer: None,
            });
        }
        self
    }

    /// [`ConnError::Timeout`] once the bound has passed; otherwise `waker` is woken when it passes.
    fn within_due(&self, waker: &Waker) -> Result<(), ConnError> {
        let mut due = self.due.lock().expect("due");
        let Some(d) = due.as_mut() else {
            return Ok(());
        };
        if std::time::Instant::now() >= d.at {
            return Err(ConnError::Timeout);
        }
        if d.timer.is_none() {
            // A conn read from a dispatcher worker arms its bound on the process's runtime timer,
            // as its socket is on that runtime's reactor; with no runtime to arm it on, the bound
            // is still held at every read.
            let _entered = crate::io::enter_process_runtime();
            if tokio::runtime::Handle::try_current().is_ok() {
                d.timer = Some(Box::pin(tokio::time::sleep_until(
                    tokio::time::Instant::from_std(d.at),
                )));
            }
        }
        if let Some(timer) = d.timer.as_mut() {
            if timer
                .as_mut()
                .poll(&mut Context::from_waker(waker))
                .is_ready()
            {
                return Err(ConnError::Timeout);
            }
        }
        Ok(())
    }

    /// The answer began: the bound is spent.
    fn answered(&self) {
        *self.due.lock().expect("due") = None;
    }
}

impl Drop for Held {
    /// A lease no one closed (its owner dropped it) is closed as it goes: the member's program does
    /// not keep frames for a reader that is gone.
    fn drop(&mut self) {
        if let Some((member, lease)) = self.lease.take() {
            member.close(lease);
        }
        // A held session's leg no one closed closes its pairing as it goes, both legs with it.
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
    /// The trust anchors each sealed REGISTRATION's own connections are held to: two registrations
    /// at one authority each present their own client identity and hold their own pin.
    member_anchored: MemberAnchored,
    /// The registrations' seals at each destination, by the need's owner, the need and the
    /// authority (lower-case, `host:port`): what an open naming none is held to with the
    /// destination's own.
    registered: Mutex<HashMap<(InstanceId, NeedId, String), Registered>>,
    /// The REGISTRATIONS holding a PRIVATE REACH (`abi::plane::TRUST_PRIVATE_REACH`), by the need's
    /// owner, the need and the registration's name, each with the authority (lower-case,
    /// `host:port`) of its own target ([`PollConns::seal_reach`]).
    reaching: Mutex<HashMap<(InstanceId, NeedId, String), String>>,
    /// Each member's auth binding: what a plugin's own request naming that member is authenticated
    /// with ([`DeclaredConns::bind_auth`]). The connector keys a binding by (instance, need,
    /// member, target origin); a request naming no member gets no binding. Two members at one
    /// origin each hold their own.
    auths: Mutex<HashMap<AuthKey, busbar_contract::conn::ConnAuth>>,
    /// The instances whose connections' authority the host writes
    /// ([`DeclaredConns::hold_authority`]): their opens are refused a `host` field of their own.
    authority_held: Mutex<HashSet<InstanceId>>,
    /// THE HOST'S I/O every carrier is served from ([`hostio`]): the one holder of OS handles.
    io: Arc<HostIo>,
    /// THE PROXY ENVIRONMENT every framed dial honours ([`proxy`]); `None` = every dial direct.
    proxy: Option<Arc<proxy::ProxyChoice>>,
    /// THE SESSION BOOK: each held session's [`datagram::Pairing`], by its kernel-minted unit key
    /// ([`Connector::pair`]): what an open serving that unit (`OpenDesc::unit`) over a datagram
    /// framer's need bridges with.
    pairs: Mutex<HashMap<u64, Arc<datagram::Pairing>>>,
    /// WHERE EACH DIAL'S BINDING COMES FROM ([`framer::BindingRefs`]): the composition root's;
    /// `None` = every dial begins with no auth.
    bindings: RwLock<Option<Arc<dyn framer::BindingRefs>>>,
    /// HOW A PROGRAM'S ENVIRONMENT REFERENCES RESOLVE ([`spawn_env`]): the resolver the composition
    /// root handed this connector ([`Connector::resolving_spawn_secrets`]), handed on to every
    /// environment a declaration loads. `None` = no reference resolves, and a program that states
    /// one is not spawned (fail-closed).
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
            bindings: RwLock::new(None),
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

    /// The same connector resolving its programs' environment references through `secrets`, at
    /// config time: the need's declaration and the refresher's lease, never a spawn
    /// ([`spawn_env`]).
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

    /// The same connector dialling every framed connection through the proxy `config` selects for
    /// it ([`proxy`]: the process's `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY`, as
    /// 1.5.5's clients honoured them); `None` = every dial direct.
    #[must_use]
    pub fn proxying(mut self, config: Option<Arc<proxy::ProxyChoice>>) -> Self {
        self.proxy = config;
        self
    }

    /// The proxy choice this connector's dials honour (the process's environment, read once), for
    /// the composition root to hand the kernel's remaining egress engine.
    #[must_use]
    pub fn proxy(&self) -> Option<Arc<proxy::ProxyChoice>> {
        self.proxy.clone()
    }

    /// The proxy a dial of `planned` goes through: a framed dial (never a carrier carried as
    /// itself) not pinned `within` an address set, to a host the scheme's slot has a proxy for and
    /// `NO_PROXY` does not exclude.
    fn tunnel_for(&self, planned: &Planned, within: &[IpAddr]) -> Option<Arc<proxy::ProxyHop>> {
        if !planned.framed() || !within.is_empty() {
            return None;
        }
        self.proxy
            .as_ref()?
            .select(planned.secure(), proxy::host_of(planned.authority()))
    }

    /// Judge `dest` under `class` (with the need's private reach when `reach`), the pended answer
    /// written to `answer` and its waker woken.
    fn judge_into(
        &self,
        dest: &str,
        class: u32,
        reach: bool,
        answer: &Answer,
    ) -> Option<Result<SocketAddr, Verdict>> {
        let answering = Arc::clone(answer);
        let done: Judged = Box::new(move |v| {
            let mut a = answering.lock().expect("judgement");
            a.0 = Some(v);
            if let Some(w) = a.1.take() {
                w.wake();
            }
        });
        if reach {
            self.judge.judge_dial_reaching(dest, class, done)
        } else {
            self.judge.judge_dial(dest, class, done)
        }
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

    /// THE ADMISSION OF A PINNED TARGET (FAIL-CLOSED: the verdict `need_admit` reports is the one
    /// every dial of the need meets). A need whose config names its target is judged at declare on
    /// the facts that need no resolution, by the same rules an open and a dial apply: the entry's
    /// endpoint checks ([`Planned::locate`]'s), the scheme by class ([`scheme_admits`]), the guard's
    /// static arm under the class the dial is judged in ([`guard::judged_class`],
    /// [`DialJudge::judge_static`]), and, for an IP literal, the whole judgement and
    /// [`class_admits`] on the address it pins. A name is resolved by no one here: its addresses
    /// stay the dial's to judge.
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
        let located = framer::locate(door.as_ref(), target).map_err(|_| ConnError::Refused)?;
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
            // A literal answers at once: nothing resolves, and nothing is left pending.
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
                // A kept member's environment resolves again at this declaration (a config apply):
                // its next child is handed what the apply resolved.
                if let Some(kept) = &kept {
                    kept.env().reload(scope);
                }
                let member = kept.unwrap_or_else(|| {
                    Arc::new(program::Member::new(
                        p.clone(),
                        spawn_env::HeldEnv::load(&p.env_refs, self.spawn_secrets, scope),
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
                program: Some((
                    program.clone(),
                    spawn_env::HeldEnv::load(&program.env_refs, self.spawn_secrets, scope),
                )),
                members: None,
            }),
        );
        Ok(())
    }

    /// Bind the one listener for `owner`'s INBOUND `need` on `bind` (`ip:port`), over the transport
    /// the need was declared over, secured by `tls` where set (the protocols agreed off the offer
    /// the entry states for an ACCEPTING listener, [`framer::accept_offer`], else off the
    /// transport's registered list), bounded by `limits`.
    /// Answers the address bound. Called on a worker.
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
        let (door, registered) = self
            .over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .map(|d| (Arc::clone(&d.door), d.alpn.clone()))
            .ok_or(ConnError::Refused)?;
        // The listener's offer is the entry's own for its ACCEPTING side, never its dial offer;
        // the transport's registered list stands only for an entry that states none (it answers
        // no offer, or refuses the question), as it stands for a dial whose `locate` answers none
        // (`compose`). A TLS listener never goes out with no protocol to agree where its
        // transport registered one. An entry that refuses the question is logged: its listener
        // binds without an offer of its own.
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
        let waker = self.waker(owner, ticket);
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
        let secure = j.planned.as_ref().is_some_and(Planned::secure);
        let target = j
            .planned
            .as_ref()
            .map_or_else(String::new, |p| p.authority().to_owned());
        if let Some(p) = j.proxied.as_mut() {
            let proxy_addr = if p.target_judged {
                got.map_err(pended_verdict)?
            } else {
                match got {
                    Err(v) if !unresolved_here(v) => return Err(pended_verdict(v)),
                    Ok(at) if !class_admits(j.egress_class, secure, &[], &target, at) => {
                        j.answer.lock().expect("judgement").0 = Some(Err(DEST_PLAINTEXT));
                        return Err(ConnError::Refused);
                    }
                    _ => {}
                }
                p.target_judged = true;
                {
                    let mut a = j.answer.lock().expect("judgement");
                    a.0 = None;
                    if let Some(w) = waker {
                        a.1 = Some(w.clone());
                    }
                }
                match self.judge_into(&p.spec.endpoint(), p.judged_class, true, &j.answer) {
                    None => return Ok(false),
                    Some(Err(v)) => {
                        j.answer.lock().expect("judgement").0 = Some(Err(v));
                        return Err(pended_verdict(v));
                    }
                    Some(Ok(at)) => at,
                }
            };
            let spec = Arc::clone(&p.spec);
            let planned = j.planned.take().ok_or(ConnError::Refused)?;
            let early = std::mem::take(&mut j.early);
            *judging = None;
            let connect = proxy::connect_request(planned.authority(), &spec);
            let conn = planned
                .dial_through(proxy_addr, connect)
                .map_err(|f| map(&f))?;
            let line = self.ride(held, conn);
            for (bytes, end, text) in early {
                line.emit(EXCHANGE_STREAM, &bytes, end, text)
                    .map_err(|f| map(&f))?;
            }
            return Ok(true);
        }
        let addr = got.map_err(pended_verdict)?;
        if !class_admits(j.egress_class, secure, &j.within, &target, addr) {
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
        // A destination the need holds a private reach to is judged with it (the one guard, as an
        // allowlist entry naming it; the class unchanged).
        let judged = self.judge_into(planned.authority(), judged_class, reach, &answer);
        // THROUGH A PROXY ([`proxy`]): the target judged first, then the proxy's own address.
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
                            egress_class,
                            within: Vec::new(),
                            early: Vec::new(),
                            answer,
                            proxied: Some(proxied),
                        }),
                    ))
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
                    return Err(ConnError::Refused)
                }
                Some(_) => {}
            }
            proxied.target_judged = true;
            let answer: Answer = Arc::new(Mutex::new((None, None)));
            let proxy_authority = proxied.spec.endpoint();
            return match self.judge_into(&proxy_authority, judged_class, true, &answer) {
                None => Ok((
                    None,
                    Some(Judging {
                        planned: Some(planned),
                        egress_class,
                        within: Vec::new(),
                        early: Vec::new(),
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
            // Decided at once: a refusal answers the open, as 1.5.5 answered it.
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
                    proxied: None,
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
        // THE WHOLE REQUEST'S BOUND, held before anything is read: past it the read is a timeout,
        // and short of it the reader is woken when it passes.
        held.within_due(waker)?;
        let read = match &held.dialled {
            Some(d) => self.read_dialled(&held, d, waker, buf),
            None => self.read_held(&held, waker, buf),
        };
        // A LEASE'S HEAD is the host's own (the generation of the program it reaches), served the
        // instant the lease opens: the far end's answer begins with the program's first bytes.
        if read
            .as_ref()
            .is_ok_and(|p| held.lease.is_none() || p.kind != PieceKind::Fields)
        {
            held.answered();
        }
        read
    }

    /// One read of a held session's upstream leg: its exchange's pieces, judged (the far end's
    /// description is the host's, never the reader's), then the leg's channel messages.
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
        let mut rest = held.rest.lock().expect("rest");
        let (piece, bytes) = match rest.0.take() {
            Some(p) => (p, std::mem::take(&mut rest.1)),
            None => {
                if rest.2 {
                    return Err(ConnError::Closed);
                }
                let got = loop {
                    if !self.settle(held, Some(waker))? {
                        return Err(ConnError::Pending);
                    }
                    let (line, stream) = held.line().ok_or(ConnError::Closed)?;
                    match line.poll_piece(stream, &mut Context::from_waker(waker)) {
                        Poll::Pending => return Err(ConnError::Pending),
                        // A lent pooled line that ended or failed before any byte of this
                        // exchange left: redialled once, fresh, and read again.
                        Poll::Ready(Err(_) | Ok(None)) if self.redial(held)? => {}
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

/// Whether a need's `target_from` reads its target from the plugin's OWN settings: one
/// `settings.<key>[.<key>...]` path, each key named (a member path, `settings.*…`, names no one
/// target). Any other target a need is declared with did not come from its own settings.
fn settings_derived(target_from: &str) -> bool {
    target_from
        .strip_prefix("settings.")
        .is_some_and(|keys| keys.split('.').all(|k| !k.is_empty() && k != "*"))
}

/// `target` without its userinfo: the authority's text up to and including its last `@` left out,
/// everything else as written. `None` when no userinfo is found to leave out. The text left out is
/// never kept, returned or repeated.
fn without_userinfo(target: &str) -> Option<String> {
    // The authority the one split reads ([`busbar_contract::net::url_authority`]).
    let parts = busbar_contract::net::url_authority(target);
    parts.userinfo?;
    let scheme = parts.scheme.map(|s| format!("{s}://")).unwrap_or_default();
    Some(format!("{scheme}{}{}", parts.host_port, parts.tail))
}

impl DeclaredConns for Connector {
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
        // An outbound need is carried over the transport its claim names, its dials judged in its
        // own egress class, and pinned to the target its config names when it names one (a
        // `target_from` that resolved to nothing is refused, and so is a target carrying a
        // userinfo its own settings did not give it: a credential never rides a dial target, it
        // travels in the request's own headers — FAIL-CLOSED, ARCHITECT ruling 2026-10-02; any
        // earlier pin is dropped), and refused when no loaded transport serves its scheme (spec
        // Part 2 #50; the loader fails the boot on it, naming the plugin and the scheme). Its
        // connections are secured with the operator CA its `trust_from` names added on top of the
        // public roots (ARCHITECT ruling 2026-10-02): a `trust_from` that resolved to nothing, or to a PEM that does not parse
        // into a trust anchor, refuses the need here, at declaration. An inbound need is recorded
        // (the listener binds it), and refused on an unserved scheme alike.
        let outbound = spec.direction == DIRECTION_OUTBOUND;
        // A member-target need (`settings.*.<key>`) is pinned by no one target: each member's route
        // is sealed at its own, and dials it like any need the plugin names per open.
        let per_member = |path: &str| busbar_contract::section::member_target(path).is_some();
        // A trust anchor in an OWNED section (`owned.<section>.<key>`) is optional by definition
        // (the section is the operator's to write or not; ARCHITECT ruling 2026-10-14): absent, the
        // need's connections trust the public roots alone, as one naming no anchor does; present, it
        // is parsed below and refused when it is no trust anchor, exactly as a `settings.` one is.
        let optional_trust = busbar_contract::section::owned_path(&spec.trust_from).is_some();
        let unresolved =
            (!spec.target_from.is_empty() && !per_member(&spec.target_from) && target.is_none())
                || (!spec.trust_from.is_empty()
                    && !per_member(&spec.trust_from)
                    && !optional_trust
                    && trust.is_none());
        // USERINFO IS NOT PART OF A SETTINGS-DERIVED TARGET (ARCHITECT ruling, row 159 audit,
        // the settings-URL userinfo finding): a target read from the plugin's own settings through `target_from`
        // is declared without its userinfo, which is dropped here — never recorded, judged or
        // repeated; a credential the plugin means to send rides its request's own fields. Every
        // other target carrying a userinfo is refused, and so is one this reading cannot clear.
        let cleared = target
            .filter(|t| settings_derived(&spec.target_from) && carries_userinfo(t))
            .and_then(without_userinfo);
        let target = cleared.as_deref().or(target);
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
    /// config (the public roots and the operator CA its `trust_from` named, on top), or the
    /// connector's default trust for a need that names none, offering `name` or the endpoint's
    /// host name, bounded by the open's default timeout. A framed need's stream is refused (its
    /// framer, not the plugin, speaks on it), and so is a `trust` reference other than the need's
    /// own `trust_from`. So is an upgrade asked for while bytes the far end sent in the clear are
    /// still unread at any layer (a short read's rest, a piece parked on the line, the
    /// connection's inbox): read after it they would pass as the verified far end's (STARTTLS
    /// response injection), so the connection fails, closed.
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
        let waker = self.waker(caller, ticket);
        if !self.settle(&held, Some(&waker))? {
            return Err(ConnError::Pending);
        }
        let (line, _) = held.line().ok_or(ConnError::Closed)?;
        let name = match name {
            Some(n) => n.to_owned(),
            None => host_of(&line.target().ok_or(ConnError::Closed)?),
        };
        // What a short read left of a clear piece is the far end's clear bytes, unread: the line
        // refuses the upgrade over it and fails the connection, and the rest is never read, the
        // failure is. Held across the upgrade, so no read takes a piece meanwhile.
        let mut rest = held.rest.lock().expect("rest");
        let answer = line.upgrade_secure(
            &config,
            &name,
            DEFAULT_OPEN_TIMEOUT,
            rest.0.is_some(),
            &mut Context::from_waker(&waker),
        );
        match answer {
            Poll::Ready(Ok(())) => Ok(()),
            Poll::Ready(Err(f)) => {
                if matches!(&f, Failure::Refused(t) if t == compose::UPGRADE_OVER_CLEAR_BYTES) {
                    rest.0 = None;
                    rest.1.clear();
                }
                Err(map(&f))
            }
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
        // A need is declared at a plane's load or a config apply: config time, so the program's
        // environment references resolve here, never at a spawn (`spawn_env`).
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
        // A request that names no member is no member's: it presents none.
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
        // A need is declared at a plane's load or a config apply: config time, so each member's
        // environment references resolve here, never at a spawn (`spawn_env`).
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        let answer = self.record_members(owner, need, spec, programs, &scope);
        self.declared
            .lock()
            .expect("declared needs")
            .insert((owner, need), (spec.clone(), answer));
        answer
    }
}

impl Connector {
    /// Arm WHERE EACH DIAL'S BINDING COMES FROM (the composition root's
    /// [`framer::BindingRefs`]): from now on an open naming a registration begins its framing with
    /// that registration's auth handle. Re-arming replaces it.
    pub fn arm_bindings(&self, bindings: Arc<dyn framer::BindingRefs>) {
        *self.bindings.write().expect("bindings") = Some(bindings);
    }

    /// The binding a dial by `caller` on `need` to `member` begins with over `door`: none for an
    /// open naming no registration, an entry the host mints no handle for, or no armed source.
    fn binding_of(
        &self,
        door: &Arc<dyn FramerDoor>,
        caller: InstanceId,
        need: NeedId,
        member: &str,
    ) -> Option<framer::AuthBinding> {
        let owner = door.owner();
        if member.is_empty() || owner == 0 {
            return None;
        }
        let refs = self.bindings.read().expect("bindings").clone()?;
        refs.binding(owner, caller, need, member)
            .filter(|b| !b.auth.is_none() && b.points != 0)
    }

    /// The ref of request unit `unit` for `door`'s entry: none for no unit, a dial with no binding
    /// (the framer calls no auth), an entry the host mints nothing for, or no armed source.
    fn unit_of(
        &self,
        door: &Arc<dyn FramerDoor>,
        unit: u64,
        bound: bool,
    ) -> busbar_contract::abi::host::service::UnitRef {
        let none = busbar_contract::abi::host::service::UnitRef::NONE;
        let owner = door.owner();
        if unit == 0 || owner == 0 || !bound {
            return none;
        }
        let refs = self.bindings.read().expect("bindings").clone();
        refs.and_then(|r| r.unit_ref(owner, unit)).unwrap_or(none)
    }

    /// Register a held session's `pairing` under its kernel-minted `unit` key, before the session
    /// runs: the upstream leg its walk opens for that unit is bridged with its caller leg.
    ///
    /// # Errors
    ///
    /// [`ConnError::Refused`] for unit `0`, or a unit already registered.
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

    /// THE SESSION'S CLEANUP (once, K6): its pairing leaves the book and closes, both legs with it,
    /// so a unit key the slot is given again never finds a stale leg.
    pub fn unpair(&self, unit: u64) {
        let gone = self.pairs.lock().expect("pairs").remove(&unit);
        if let Some(p) = gone {
            p.close();
        }
    }

    /// THE COMPOSED OPEN of a held session's upstream leg over a datagram framer's need ([`dialled`]):
    /// refused with no unit, or for a unit no session registered; its exchange is one dial over the
    /// framer serving the target's scheme, never pooled, its body the leg's own description.
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
        // The leg's own port, on the host address the caller's leg is served at.
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
            .into_iter()
            .find(|g| g.stream == 0 && !g.fields)
            .map(|g| g.bytes)
            .ok_or(ConnError::Fault)?;
        let due = (desc.timeout_ms != 0)
            .then(|| std::time::Instant::now() + Duration::from_millis(desc.timeout_ms));
        // The exchange body: the description alone, or framed into the opener's form.
        let body = dialled::composed_body(desc.fields, desc.body, &description)?;
        let held = self.dial_exchange(
            caller,
            need,
            &OpenDesc {
                body: &body,
                ..*desc
            },
            (exchange, alpn),
            target,
            open_timeout,
            (egress_class, declared_target, tls),
            false,
        )?;
        Ok(held.dialling(dialled::Dialled::new(framing, port, pairing, due)))
    }

    /// THE DIALLED EXCHANGE over `door` (a framer of a stream, or a carrier carried as itself):
    /// judged and pinned, its connection security, the pool where `poolable`, the dial.
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
    ) -> Result<Held, ConnError> {
        endpoint::named(target).map_err(|_| ConnError::Refused)?;
        // THE MEMBER'S BINDING (THE DESIGN §6, "Auth points and guest lists", item 5): an open
        // naming a registration begins its framing with that registration's auth handle, minted
        // for this entry; the framer calls the auth itself at the binding's points.
        let binding = self.binding_of(&door, caller, need, desc.member);
        // THE EXCHANGE'S REQUEST UNIT, minted for this entry: what the framer presents on its
        // `auth.call` at the opening's emit (`EmitIn::unit`).
        let unit = self.unit_of(&door, desc.unit, binding.is_some());
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
            binding: binding.unwrap_or(framer::AuthBinding::NONE),
            unit,
        };
        let planned = self.plan(&door, dial).map_err(|f| map(&f))?;
        // THE DESTINATION'S TRUST ANCHORS (the transport pin, ARCHITECT 2026-10-03): every connection to a sealed
        // destination is held to them; one that pins the far end's key and is not secured has no
        // key to hold, and is refused before any judgement or dial. An open naming a registration
        // sealed at this authority is held to THAT registration's anchors alone (or none, where it
        // holds none), never to another registration's at the same `host:port`.
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
        // The registration whose own anchors the dial is held to, if any: a pooled line is lent
        // only to an open held to the same.
        let anchored_as = own.is_some().then(|| desc.member.to_owned());
        // Naming none, the open is held to the destination's anchors: the one answer every seal at
        // its authority gives, and refused where they disagree.
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
        // The very seal the dial is held to: a pooled line is lent only to an open held to it.
        let sealed = anchors.clone().map(SealRef);
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
        // table, owner-signed 2026-09-27) in the egress default class only: its address is judged
        // as operator infrastructure. An open-web need keeps its class (public https only, Q128
        // ruling 14), and a provider need is refused a private address unless allowlisted
        // (ARCHITECT ruling CRATES-14, `guard::judged_class`).
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
        if !scheme_admits(egress_class, planned.secure()) {
            return Err(ConnError::Refused);
        }
        // THE POOL: on this worker's shard, a live h2 line to the same place carries this
        // exchange as its next stream, or a line an earlier exchange finished on carries it
        // (judged, pinned and secured when it was dialled, under the same class); a dial pinned
        // `within` an address set is never pooled.
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
                    binding: binding.map(|b| (b.auth.id, b.auth.mac)),
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
                    reach,
                    mark: line.flushed(),
                };
                let (opening, words) = planned.into_opening();
                match line.attach(opening, words, unit) {
                    Ok(stream) => {
                        let held =
                            Held::over(Some((line, stream)), None, pooled).bounded(desc.timeout_ms);
                        *held.redial.lock().expect("redial") = Some(redial);
                        return Ok(held);
                    }
                    // The attach wrote the opening and THEN found the line failed (the far end's
                    // close met in the same drive that flushed it): a byte of the exchange left,
                    // so it is never re-sent (Q-L18-RETRY). It holds the failed line and its read
                    // answers the failure, as a failure met at the first read does; the line is
                    // let go when it closes. Whether the failure is met here or at that read is
                    // the far end's timing; the verdict is the socket's count either way.
                    Err((stream, _)) if line.flushed() != redial.mark => {
                        let held = Held::over(Some((line, stream)), None, pooled);
                        return Ok(held);
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
        let held = Held::over(None, judging, pooled).bounded(desc.timeout_ms);
        if let Some(conn) = conn {
            self.ride(&held, conn);
        }
        Ok(held)
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
        let authority_held = self
            .authority_held
            .lock()
            .expect("authority held")
            .contains(&caller);
        if head_is_refused(desc, authority_held) {
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
            let mut held = Held::over(None, None, None).bounded(desc.timeout_ms);
            held.lease = Some((member, lease));
            // A refused insert drops the held lease, which closes it.
            return self.slab.insert(caller, need, held);
        }
        // A PROGRAM NEED spawns the program its config names, and nothing else: an open naming a
        // target of its own is refused. No address is judged: no network is dialled.
        if let Some((program, env)) = program {
            if !desc.target.is_empty() {
                return Err(ConnError::Refused);
            }
            let dial = Dial {
                anchors: None,
                binding: crate::framer::AuthBinding::NONE,
                unit: busbar_contract::abi::host::service::UnitRef::NONE,
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
            // A one-shot line is no member: it carries no supervision key.
            let conn = Connection::spawn(&via, &program, &env, dial, 0).map_err(|f| map(&f))?;
            // A program is a dialled, single-use line (no pool, no judgement): its one exchange
            // rides EXCHANGE_STREAM, as a freshly dialled connection's does.
            let line = Line::new(conn);
            return self.slab.insert(
                caller,
                need,
                Held::over(Some((line, EXCHANGE_STREAM)), None, None).bounded(desc.timeout_ms),
            );
        }
        // No target named: the need's own, its config's (`EstablishIn.target` absent = the need's
        // `target_from`).
        let named = match (desc.target, declared_target.as_deref()) {
            ("", Some(declared)) => declared,
            (named, _) => named,
        }
        .to_owned();
        let target = named.as_str();
        let open_timeout = if desc.timeout_ms == 0 {
            DEFAULT_OPEN_TIMEOUT
        } else {
            Duration::from_millis(desc.timeout_ms)
        };
        // A DATAGRAM FRAMER'S NEED: the composed open of a held session's upstream leg.
        if door.facts().datagram {
            let held = self.open_dialled(
                caller,
                need,
                desc,
                &door,
                target,
                open_timeout,
                (egress_class, declared_target, tls),
            )?;
            return self.slab.insert(caller, need, held);
        }
        // A UNIX-DOMAIN TARGET (`unix:/path`; ARCHITECT ruling 2026-10-03 12:10Z, VALKEY-UNIX):
        // served to an operator-infrastructure need as a raw stream, every other class refused
        // (loopback-allowed included: there is no address to judge, so its loopback rule and
        // the node's own ports could not hold). A need whose config names its target dials that
        // path and no other.
        if let Some(path) = socket::unix_path(target) {
            if egress_class != EGRESS_OPERATOR_INFRASTRUCTURE
                || declared_target.as_deref().is_some_and(|d| d != target)
            {
                return Err(ConnError::Refused);
            }
            let dial = Dial {
                anchors: None,
                binding: crate::framer::AuthBinding::NONE,
                unit: busbar_contract::abi::host::service::UnitRef::NONE,
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
                Held::over(Some((line, EXCHANGE_STREAM)), None, None).bounded(desc.timeout_ms),
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
        )?;
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
        if let Some(d) = held.dialled.as_ref().filter(|d| !d.exchanging()) {
            return d.write(bytes, end, text);
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
        self.read_waking(caller, conn, &self.waker(caller, ticket), buf)
    }

    fn wait(&self, caller: InstanceId, set: &[ConnId], ticket: Ticket) -> Result<usize, ConnError> {
        let waker = self.waker(caller, ticket);
        let mut cx = Context::from_waker(&waker);
        for (at, conn) in set.iter().enumerate() {
            let (_, held) = self.slab.get(caller, *conn)?;
            // A request past its bound is ready: its read answers the timeout.
            if held.within_due(&waker).is_err() {
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
        if let Some(d) = &held.dialled {
            // A held session's leg: its pairing closes, both legs with it, once.
            d.close();
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
        member: &str,
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
        let sealed = match (&at, anchors.is_empty()) {
            (_, true) => None,
            (None, false) => return Err(ConnError::Refused),
            (Some(_), false) => Some(Arc::new(
                tls::client::seal(self.tls.as_deref(), anchors).map_err(|_| ConnError::Refused)?,
            )),
        };
        // A REGISTRATION'S anchors are kept under its name too: an open naming it, at its own
        // authority, is held to what it holds there (or to nothing, where it holds nothing), apart
        // from every other registration at that `host:port`.
        // The destination's seals are kept apart too: its own (sealed naming no registration), and
        // each registration's among those at its authority (leaving the ones at any authority it
        // was sealed at before); an open naming none is held to what they all agree on. No seal
        // ever drops or overwrites another's.
        if member.is_empty() {
            let Some(at) = at else {
                return Ok(());
            };
            let mut anchored = self.anchored.lock().expect("anchors");
            match sealed {
                Some(sealed) => {
                    anchored.insert(at, sealed);
                }
                // Nothing to hold: the destination's own earlier seal is dropped.
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
