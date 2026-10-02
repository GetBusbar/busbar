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
//! * [`io`] is readiness on the per-worker reactor (`io.{register, poll_ready, clear_ready,
//!   deregister}`); [`socket`] the host's OS sockets; [`stream`] a host socket as a byte stream.
//! * [`framer`] drives one transport entry's framer table host-side; [`compose`] builds a dialled
//!   connection as socket -> \[TLS\] -> framer; [`listen`] binds one listener per inbound need and
//!   composes each accepted connection the same way, begun on the accept side; [`registry`] is the
//!   view of which entry serves which scheme; [`wire`] presents a framer entry over host sockets to
//!   the kernel's transport seam.
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

pub mod compose;
pub mod dtls;
pub mod endpoint;
pub mod framer;
pub mod guard;
pub mod io;
pub mod listen;
pub mod process;
pub mod registry;
pub mod socket;
pub mod stream;
pub mod tls;
pub mod udp;
pub mod wire;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB,
};
use busbar_contract::abi::host::service::DEST_PLAINTEXT;
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    PieceKind, PollConns, Ticket, NO_TICKET,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::WireStatusClass;
use busbar_contract::transport::ConnFacts;

use crate::compose::{
    Connection, Dial, Failure, Planned, DEFAULT_OPEN_TIMEOUT, WRITE_BUFFER_BYTES,
};
use crate::framer::FramerDoor;
use crate::listen::{AcceptLimits, Listening};
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
            EGRESS_LOOPBACK_ALLOWED => secure || addr.ip().is_loopback(),
            _ => true,
        }
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
}

/// A judgement's answer once it came, and the waker of the read or wait that found none.
type Answer = Arc<Mutex<(Option<Result<SocketAddr, Verdict>>, Option<Waker>)>>;

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
    early: Vec<(Vec<u8>, bool)>,
    answer: Answer,
}

/// One connection the connector holds for its owner.
struct Held {
    conn: Mutex<Option<Connection>>,
    /// The judgement the dial waits on; `None` once dialled.
    judging: Mutex<Option<Judging>>,
    /// The piece a short caller buffer left, and whether the end was answered.
    rest: Mutex<(Option<Piece>, Vec<u8>, bool)>,
    /// The far end's reason phrase, held until its head's last piece is read.
    reason: Mutex<Option<Vec<u8>>>,
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
        self.record(owner, need, transport, egress_class, None)
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
        self.record(owner, need, transport, egress_class, Some(declared_target))
    }

    /// THE SCHEME MATCH (spec Part 2 #50: "no match ⇒ fail closed"): the need is recorded over the
    /// entry serving `transport`, resolved here once, or refused here; an open never meets an
    /// unserved scheme.
    fn record(
        &self,
        owner: InstanceId,
        need: NeedId,
        transport: &str,
        egress_class: u32,
        declared_target: Option<&str>,
    ) -> Result<(), ConnError> {
        let served = {
            let view = self.transports.read().expect("transports");
            view.serving(transport)
                .map(|served| (Arc::clone(&served.entry.door), served.entry.alpn.clone()))
        };
        let Some((door, alpn)) = served else {
            // Any earlier record of the need is dropped with it.
            self.over.lock().expect("needs").remove(&(owner, need));
            return Err(ConnError::Refused);
        };
        self.slab.declare(owner, need);
        self.over.lock().expect("needs").insert(
            (owner, need),
            DeclaredNeed {
                door,
                alpn,
                egress_class,
                declared_target: declared_target.map(str::to_owned),
            },
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
        let l = Listening::bind(door, bind, tls, alpn, limits).map_err(|_| ConnError::Fault)?;
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
                let id = self.slab.insert(
                    owner,
                    need,
                    Held {
                        conn: Mutex::new(Some(a.conn)),
                        judging: Mutex::new(None),
                        rest: Mutex::new((None, Vec::new(), false)),
                        reason: Mutex::new(None),
                    },
                )?;
                Ok((id, a.peer))
            }
        }
    }

    /// Offer `bytes` on `stream` of `caller`'s connection `conn` (`end` = the stream's message is
    /// complete): an accepted connection answers each piece on the stream it came on.
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
    ) -> Result<usize, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        if !Self::settle(&held, None)? {
            return Err(ConnError::Pending);
        }
        let mut c = held.conn.lock().expect("connection");
        let c = c.as_mut().ok_or(ConnError::Closed)?;
        c.emit(stream, bytes, end, &mut Context::from_waker(Waker::noop()))
            .map_err(|f| map(&f))
    }

    /// Dial a held connection whose judgement has answered. `Ok(false)`: still judging, `waker`
    /// (where given) registered for the answer. A refusal stays the connection's answer.
    fn settle(held: &Held, waker: Option<&Waker>) -> Result<bool, ConnError> {
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
        let addr = got.map_err(|_| ConnError::Refused)?;
        let secure = j.planned.as_ref().is_some_and(Planned::secure);
        if !class_admits(j.egress_class, secure, &j.within, addr) {
            // The refusal stays the connection's answer.
            j.answer.lock().expect("judgement").0 = Some(Err(DEST_PLAINTEXT));
            return Err(ConnError::Refused);
        }
        let planned = j.planned.take().ok_or(ConnError::Refused)?;
        let early = std::mem::take(&mut j.early);
        *judging = None;
        let mut conn = planned.dial_at(addr).map_err(|f| map(&f))?;
        for (bytes, end) in early {
            conn.write(&bytes, end, &mut Context::from_waker(Waker::noop()))
                .map_err(|f| map(&f))?;
        }
        *held.conn.lock().expect("connection") = Some(conn);
        Ok(true)
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
        let mut rest = held.rest.lock().expect("rest");
        let (piece, bytes) = match rest.0.take() {
            Some(p) => (p, std::mem::take(&mut rest.1)),
            None => {
                if rest.2 {
                    return Err(ConnError::Closed);
                }
                if !Self::settle(&held, Some(waker))? {
                    return Err(ConnError::Pending);
                }
                let mut c = held.conn.lock().expect("connection");
                let c = c.as_mut().ok_or(ConnError::Closed)?;
                match c.poll_piece(&mut Context::from_waker(waker)) {
                    Poll::Pending => return Err(ConnError::Pending),
                    Poll::Ready(Err(f)) => return Err(map(&f)),
                    Poll::Ready(Ok(None)) => {
                        rest.2 = true;
                        return Ok(Piece {
                            kind: PieceKind::Completion,
                            stream: StreamId(0),
                            len: 0,
                            end: true,
                            status: None,
                            status_code: None,
                            status_namespace: None,
                            retry_after_secs: None,
                            reason: None,
                        });
                    }
                    // The far end's head (and its trailers) arrive as the framer's field block:
                    // a Fields piece, the head ahead of the first Body piece.
                    Poll::Ready(Ok(Some(got))) => {
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
                                reason: None,
                            },
                            got.bytes,
                        )
                    }
                }
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
    ) -> Result<(), ConnError> {
        // An outbound need is carried over the transport its claim names, its dials judged in its
        // own egress class, and pinned to the target its config names when it names one (a
        // `target_from` that resolved to nothing is refused, and so is a target carrying a
        // userinfo: a credential never rides a dial target, it travels in the request's own
        // headers — FAIL-CLOSED, ARCHITECT ruling 2026-10-02; any earlier pin is dropped), and
        // refused when no loaded transport serves its scheme (spec Part 2 #50; the loader fails
        // the boot on it, naming the plugin and the scheme); an inbound need is recorded (the
        // listener binds it), and refused on an unserved scheme alike.
        let outbound = spec.direction == DIRECTION_OUTBOUND;
        let unresolved = !spec.target_from.is_empty() && target.is_none();
        let credentialed = target.is_some_and(carries_userinfo);
        let answer = if outbound && (spec.transport.is_empty() || unresolved || credentialed) {
            self.over.lock().expect("needs").remove(&(owner, need));
            Err(ConnError::Refused)
        } else {
            match (outbound, target) {
                (true, Some(t)) => {
                    self.declare_need_to(owner, need, &spec.transport, spec.egress_class, t)
                }
                (true, None) => self.declare_need(owner, need, &spec.transport, spec.egress_class),
                // An inbound need over a scheme no loaded transport serves is refused the same way.
                (false, _)
                    if !spec.transport.is_empty() && !self.serves_scheme(&spec.transport) =>
                {
                    Err(ConnError::Refused)
                }
                (false, _) => {
                    self.slab.declare(owner, need);
                    Ok(())
                }
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

    /// A need is framed when the entry serving its transport composes over another claim (a framer
    /// above a carrier, http's kind); an entry directly over the host's socket is a raw stream.
    fn framed(&self, owner: InstanceId, need: NeedId) -> bool {
        self.over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .is_some_and(|d| !d.door.facts().composes_over.is_empty())
    }

    fn serves_scheme(&self, transport: &str) -> bool {
        Connector::serves_scheme(self, transport)
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
        // A need declared without a transport (an inbound need) dials nothing.
        let DeclaredNeed {
            door,
            alpn,
            egress_class,
            declared_target,
        } = self
            .over
            .lock()
            .expect("needs")
            .get(&(caller, need))
            .cloned()
            .ok_or(ConnError::Refused)?;
        // No target named: the need's own, its config's (`EstablishIn.target` absent = the need's
        // `target_from`).
        let target = match (desc.target, declared_target.as_deref()) {
            ("", Some(declared)) => declared,
            (named, _) => named,
        };
        endpoint::check(target).map_err(|_| ConnError::Refused)?;
        let dial = Dial {
            target: target.to_owned(),
            tls: self.tls.clone(),
            alpn,
            open_timeout: if desc.timeout_ms == 0 {
                DEFAULT_OPEN_TIMEOUT
            } else {
                Duration::from_millis(desc.timeout_ms)
            },
            opening: Some((
                desc.fields
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), v.to_vec()))
                    .collect(),
                desc.body.to_vec(),
            )),
            head_words: (desc.method.to_vec(), desc.head_target.to_vec()),
        };
        let planned = Planned::locate(Arc::clone(&door), dial).map_err(|f| map(&f))?;
        // A TARGET THE NEED'S CONFIG NAMES IS THE OPERATOR'S OWN (OWNER Q7: a destination the
        // operator writes into config is trusted): its address is judged as operator
        // infrastructure, never under a class that refuses request-data destinations.
        let judged_class = guard::judged_class(egress_class, declared_target.is_some());
        // THE DECLARED TARGET (1.5.5's per-module target guarantee, on every need): a need whose
        // config names its target dials that target and no other.
        if let Some(declared) = declared_target {
            let located =
                framer::locate(door.as_ref(), &declared).map_err(|_| ConnError::Refused)?;
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
        let answer: Answer = Arc::new(Mutex::new((None, None)));
        let later = Arc::clone(&answer);
        let judged = self.judge.judge_dial(
            planned.authority(),
            judged_class,
            Box::new(move |v| {
                let mut a = later.lock().expect("judgement");
                a.0 = Some(v);
                if let Some(w) = a.1.take() {
                    w.wake();
                }
            }),
        );
        let (conn, judging) = match judged {
            // Decided at once: a refusal answers the open, as 1.5.5 answered it.
            Some(Err(_)) => return Err(ConnError::Refused),
            Some(Ok(addr)) if !class_admits(egress_class, planned.secure(), desc.within, addr) => {
                return Err(ConnError::Refused)
            }
            Some(Ok(addr)) => (Some(planned.dial_at(addr).map_err(|f| map(&f))?), None),
            // The name resolves off this thread: the open is in flight, and an address refusal
            // answers the read or wait that finds it.
            None => (
                None,
                Some(Judging {
                    planned: Some(planned),
                    egress_class,
                    within: desc.within.to_vec(),
                    early: Vec::new(),
                    answer,
                }),
            ),
        };
        self.slab.insert(
            caller,
            need,
            Held {
                conn: Mutex::new(conn),
                judging: Mutex::new(judging),
                rest: Mutex::new((None, Vec::new(), false)),
                reason: Mutex::new(None),
            },
        )
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
    ) -> Result<usize, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        if !Self::settle(&held, None)? {
            if let Some(j) = held.judging.lock().expect("judging").as_mut() {
                // Held until the judgement answers, under the same cap a connection's buffer has.
                let held_bytes: usize = j.early.iter().map(|(b, _)| b.len()).sum();
                let take = bytes
                    .len()
                    .min(WRITE_BUFFER_BYTES.saturating_sub(held_bytes));
                if take == 0 && !bytes.is_empty() {
                    return Err(ConnError::Pending);
                }
                j.early
                    .push((bytes[..take].to_vec(), end && take == bytes.len()));
                return Ok(take);
            }
        }
        let mut c = held.conn.lock().expect("connection");
        let c = c.as_mut().ok_or(ConnError::Closed)?;
        let waker = Waker::noop();
        match c.write(bytes, end, &mut Context::from_waker(waker)) {
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
            if held.rest.lock().expect("rest").0.is_some() {
                return Ok(at);
            }
            match Self::settle(&held, Some(&waker)) {
                Ok(false) => continue,
                Err(_) => return Ok(at),
                Ok(true) => {}
            }
            let mut c = held.conn.lock().expect("connection");
            let Some(c) = c.as_mut() else {
                return Ok(at);
            };
            if c.poll_ready(&mut cx).is_ready() {
                return Ok(at);
            }
        }
        Err(ConnError::Pending)
    }

    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        if !Self::settle(&held, None)? {
            return Err(ConnError::Pending);
        }
        let c = held.conn.lock().expect("connection");
        let e = c.as_ref().ok_or(ConnError::Closed)?.established();
        Ok(ConnFacts {
            sni: e.offered_name.clone(),
            alpn: e
                .agreed_protocol
                .as_ref()
                .map(|p| String::from_utf8_lossy(p).into_owned()),
            peer_cert: None,
            claim: e.claim.clone(),
        })
    }

    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        let held = self.slab.remove(caller, conn)?;
        if let Some(c) = held.conn.lock().expect("connection").take() {
            c.close();
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
}

#[cfg(test)]
#[path = "tests/connector_tests.rs"]
mod tests;

#[cfg(test)]
#[allow(unsafe_code, dead_code)]
#[path = "tests/support.rs"]
mod support;
