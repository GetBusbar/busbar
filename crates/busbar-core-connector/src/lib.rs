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
//! * [`tls`] is connection security — core-only, never a plugin, never crossing the ABI.
//! * [`dtls`] is its datagram sibling — the DTLS engine a WebRTC association runs on (the RFC 7983
//!   demux, the ICE-gated bind, the SRTP exporter), on ring like [`tls`].
//! * [`udp`] is the host's datagram socket: one bound port, a peer per datagram.
//!
//! * [`io`] is readiness on the per-worker reactor (`io.{register, poll_ready, clear_ready,
//!   deregister}`); [`socket`] the host's OS sockets; [`stream`] a host socket as a byte stream.
//! * [`framer`] drives one transport entry's framer table host-side; [`compose`] builds a dialled
//!   connection as socket -> \[TLS\] -> framer; [`registry`] is the view of which entry serves which
//!   scheme; [`wire`] presents a framer entry over host sockets to the kernel's transport seam.
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
pub mod io;
pub mod registry;
pub mod socket;
pub mod stream;
pub mod tls;
pub mod udp;
pub mod wire;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
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
use crate::registry::Transports;

/// What an open for a DECLARED need answers while no transport serves it: refused, never a silent
/// success.
pub const NO_TRANSPORT_YET: ConnError = ConnError::Refused;

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

/// Any function of the judge's shape is a judge: the root joins the kernel's one judge
/// (`KernelServices::judge_dial`) here without the connector naming a kernel type.
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

/// The judge a connector built with none holds: an IP literal is its own address and a name is
/// refused, because nothing here resolves one.
struct LiteralsOnly;

impl DialJudge for LiteralsOnly {
    fn judge_dial(&self, dest: &str, _: u32, _: Judged) -> Option<Result<SocketAddr, Verdict>> {
        Some(socket::address_of(dest).ok_or(busbar_contract::abi::host::service::DEST_UNRESOLVABLE))
    }
}

/// What the connector holds for one declared need.
#[derive(Debug, Clone)]
struct DeclaredNeed {
    transport: String,
    egress_class: u32,
    /// The target the need's `target_from` resolved to; `None` = the plugin names it per open.
    declared_target: Option<String>,
}

/// A judgement's answer once it came, and the waker of the read or wait that found none.
type Answer = Arc<Mutex<(Option<Result<SocketAddr, Verdict>>, Option<Waker>)>>;

/// A dial whose judgement pended: what to dial once it answers, the answer, and the waker of the
/// read or wait that found it unanswered.
struct Judging {
    planned: Option<Planned>,
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
}

impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Held").finish_non_exhaustive()
    }
}

/// THE CONNECTOR: the host side of the connection table.
pub struct Connector {
    slab: ConnSlab<Held>,
    /// The transport each declared need names, the egress class its dials are judged under, and
    /// the target its config names (`target_from`), when it names one.
    over: Mutex<HashMap<(InstanceId, NeedId), DeclaredNeed>>,
    /// Every need an instance declared through [`Conns::declare`], whole, and the answer it got.
    declared: Mutex<HashMap<(InstanceId, NeedId), (ReadNeed, Result<(), ConnError>)>>,
    transports: RwLock<Transports>,
    tls: Option<Arc<rustls::ClientConfig>>,
    wake: WakeTicket,
    judge: Arc<dyn DialJudge>,
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
            judge: Arc::new(LiteralsOnly),
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

    /// The need `owner` declared as `need`, whole, as [`Conns::declare`] received it.
    #[must_use]
    pub fn declared_spec(&self, owner: InstanceId, need: NeedId) -> Option<ReadNeed> {
        let declared = self.declared.lock().expect("declared needs");
        declared.get(&(owner, need)).map(|(spec, _)| spec.clone())
    }

    /// Record that `owner` declared `need` — the only needs it may open. A need declared without a
    /// transport opens nothing ([`NO_TRANSPORT_YET`]).
    pub fn declare(&self, owner: InstanceId, need: NeedId) {
        self.slab.declare(owner, need);
    }

    /// Record that `owner` declared `need` over `transport` (a scheme the registry view serves), in
    /// the default egress class ([`DEFAULT_CLASS`]).
    pub fn declare_over(&self, owner: InstanceId, need: NeedId, transport: &str) {
        self.declare_need(owner, need, transport, DEFAULT_CLASS);
    }

    /// Record that `owner` declared `need` over `transport`, its dials judged under the need's own
    /// `egress_class` (`Need::egress_class`).
    pub fn declare_need(
        &self,
        owner: InstanceId,
        need: NeedId,
        transport: &str,
        egress_class: u32,
    ) {
        self.record(owner, need, transport, egress_class, None);
    }

    /// Record that `owner` declared `need` over `transport` in `egress_class`, its target named by
    /// the need's config (`target_from`) and resolved to `declared_target`. Every open on the need
    /// must dial that target: another authority, or the same one under another security, is
    /// refused before any judgement or dial.
    pub fn declare_need_to(
        &self,
        owner: InstanceId,
        need: NeedId,
        transport: &str,
        egress_class: u32,
        declared_target: &str,
    ) {
        self.record(owner, need, transport, egress_class, Some(declared_target));
    }

    fn record(
        &self,
        owner: InstanceId,
        need: NeedId,
        transport: &str,
        egress_class: u32,
        declared_target: Option<&str>,
    ) {
        self.slab.declare(owner, need);
        self.over.lock().expect("needs").insert(
            (owner, need),
            DeclaredNeed {
                transport: transport.to_owned(),
                egress_class,
                declared_target: declared_target.map(str::to_owned),
            },
        );
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
                        });
                    }
                    Poll::Ready(Ok(Some(got))) => (
                        Piece {
                            kind: PieceKind::Body,
                            stream: StreamId(got.stream),
                            len: 0,
                            end: got.end_of_frame,
                            status: class(got.status_class),
                            status_code: got.status_code,
                            status_namespace: None,
                            retry_after_secs: got.retry_after_secs,
                        },
                        got.bytes,
                    ),
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

impl DeclaredConns for Connector {
    fn declare(&self, owner: InstanceId, need: NeedId, spec: &ReadNeed) -> Result<(), ConnError> {
        // An outbound need is carried over the transport its claim names, its dials judged in its
        // own egress class; an inbound need is recorded (the listener binds it).
        let answer = if spec.direction == DIRECTION_OUTBOUND && spec.transport.is_empty() {
            Err(ConnError::Refused)
        } else {
            if spec.direction == DIRECTION_OUTBOUND {
                self.declare_need(owner, need, &spec.transport, spec.egress_class);
            } else {
                self.slab.declare(owner, need);
            }
            Ok(())
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
}

impl Conns for Connector {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need)?;
        endpoint::check(desc.target).map_err(|_| ConnError::Refused)?;
        let DeclaredNeed {
            transport: scheme,
            egress_class,
            declared_target,
        } = self
            .over
            .lock()
            .expect("needs")
            .get(&(caller, need))
            .cloned()
            .ok_or(NO_TRANSPORT_YET)?;
        let (door, alpn) = {
            let view = self.transports.read().expect("transports");
            let served = view.serving(&scheme).ok_or(NO_TRANSPORT_YET)?;
            (Arc::clone(&served.entry.door), served.entry.alpn.clone())
        };
        let dial = Dial {
            target: desc.target.to_owned(),
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
        };
        let planned = Planned::locate(Arc::clone(&door), dial).map_err(|f| map(&f))?;
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
        let answer: Answer = Arc::new(Mutex::new((None, None)));
        let later = Arc::clone(&answer);
        let judged = self.judge.judge_dial(
            planned.authority(),
            egress_class,
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
            Some(Ok(addr)) => (Some(planned.dial_at(addr).map_err(|f| map(&f))?), None),
            // The name resolves off this thread: the open is in flight, and an address refusal
            // answers the read or wait that finds it.
            None => (
                None,
                Some(Judging {
                    planned: Some(planned),
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
