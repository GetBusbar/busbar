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
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, InstanceId, NeedId, OpenDesc, Piece, PieceKind, Ticket,
    NO_TICKET,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::WireStatusClass;
use busbar_contract::transport::ConnFacts;

use crate::compose::{Connection, Dial, Failure, DEFAULT_OPEN_TIMEOUT};
use crate::registry::Transports;

/// What an open for a DECLARED need answers while no transport serves it: refused, never a silent
/// success.
pub const NO_TRANSPORT_YET: ConnError = ConnError::Refused;

/// How the host wakes a caller's ticket.
pub type WakeTicket = Arc<dyn Fn(Ticket) + Send + Sync>;

/// One connection the connector holds for its owner.
struct Held {
    conn: Mutex<Option<Connection>>,
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
    /// The transport each declared need names.
    over: Mutex<HashMap<(InstanceId, NeedId), String>>,
    transports: RwLock<Transports>,
    tls: Option<Arc<rustls::ClientConfig>>,
    wake: WakeTicket,
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
            transports: RwLock::new(Transports::default()),
            tls: None,
            wake: Arc::new(|_| {}),
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

    /// The same connector serving `transports`, securing connections with `tls` where a target
    /// asks for it, and waking a caller's ticket through `wake`.
    #[must_use]
    pub fn serving(
        transports: Transports,
        tls: Option<Arc<rustls::ClientConfig>>,
        wake: WakeTicket,
    ) -> Self {
        Self {
            transports: RwLock::new(transports),
            tls,
            wake,
            ..Self::default()
        }
    }

    /// Record that `owner` declared `need` — the only needs it may open. A need declared without a
    /// transport opens nothing ([`NO_TRANSPORT_YET`]).
    pub fn declare(&self, owner: InstanceId, need: NeedId) {
        self.slab.declare(owner, need);
    }

    /// Record that `owner` declared `need` over `transport` (a scheme the registry view serves).
    pub fn declare_over(&self, owner: InstanceId, need: NeedId, transport: &str) {
        self.slab.declare(owner, need);
        self.over
            .lock()
            .expect("needs")
            .insert((owner, need), transport.to_owned());
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

impl Conns for Connector {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need)?;
        endpoint::check(desc.target).map_err(|_| ConnError::Refused)?;
        let scheme = self
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
        let conn = Connection::dial(door, dial).map_err(|f| map(&f))?;
        self.slab.insert(
            caller,
            need,
            Held {
                conn: Mutex::new(Some(conn)),
                rest: Mutex::new((None, Vec::new(), false)),
            },
        )
    }

    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        end: bool,
    ) -> Result<usize, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        let mut c = held.conn.lock().expect("connection");
        let c = c.as_mut().ok_or(ConnError::Closed)?;
        let waker = Waker::noop();
        c.write(bytes, end, &mut Context::from_waker(waker))
            .map_err(|f| map(&f))
    }

    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        ticket: Ticket,
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
                let mut c = held.conn.lock().expect("connection");
                let c = c.as_mut().ok_or(ConnError::Closed)?;
                let waker = self.waker(ticket);
                match c.poll_piece(&mut Context::from_waker(&waker)) {
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

    fn wait(&self, caller: InstanceId, set: &[ConnId], ticket: Ticket) -> Result<usize, ConnError> {
        let waker = self.waker(ticket);
        let mut cx = Context::from_waker(&waker);
        for (at, conn) in set.iter().enumerate() {
            let (_, held) = self.slab.get(caller, *conn)?;
            if held.rest.lock().expect("rest").0.is_some() {
                return Ok(at);
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

#[cfg(test)]
#[path = "tests/connector_tests.rs"]
mod tests;

#[cfg(test)]
#[allow(unsafe_code, dead_code)]
#[path = "tests/support.rs"]
mod support;
