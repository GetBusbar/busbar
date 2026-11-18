// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DATAGRAM CARRIERS (IF §12.13, §13): the connector's `MediaCarrier`, which `busbar_kernel::media::Media`
//! puts core's rules in front of. It owns the UDP ports and the demux between them and the sessions:
//! * `accept` binds the route's configured media listener (one port shared by every accepted call on it) and
//!   begins `ROLE_DATAGRAM, CONN_ACCEPT` with the offer; a ufrag already live on that port is refused, so
//!   concurrent calls never collide;
//! * `dial` binds an ephemeral port on the listener's address of its own (two calls to one far end would share
//!   every address of the 5-tuple) and begins `ROLE_DATAGRAM, CONN_DIAL` with the opening as `ConnIn.head`;
//! * one session per rendezvous, never one per far-end address. A STUN check is routed by its USERNAME's local
//!   ufrag and verified by that session's association before its source becomes a path; every other datagram
//!   by the address a session numbered. A datagram neither finds is dropped here, before any session sees it.
//!
//! One certificate serves the process (minted through `busbar-crypto` when the carrier is built, so it is
//! rotated on restart); its fingerprint is each session's `ConnIn.local_fingerprint`.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

use busbar_kernel::media::{Carried, Lines, MediaCarrier, MediaLeg};
use busbar_kernel::plugin_records::RecordsDenied;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_ports::transport::TransportPort;
use foldhash::HashMap;

use super::session::{MediaAudit, Opener, Params, Ported, Session};
use super::{stun, Failure, SessionCert};
use crate::udp::{self, ReadyPort};
use crate::DialJudge;

/// How often a port's sessions are checked for a due DTLS retransmission, probe retry or consent.
const TICK: Duration = Duration::from_millis(20);

/// One route's media listener: where its accepted rendezvous share a port, and the egress class every
/// candidate of its sessions is judged under.
#[derive(Clone, Copy, Debug)]
pub struct MediaRoute {
    /// The concrete `ip:port` the listener binds (a wildcard is refused: a port binds one address).
    pub bind: SocketAddr,
    /// The egress class (`DialJudge`) of the route's rendezvous.
    pub class: u32,
}

/// Core's route config, as the carrier reads it: `routes.<id>.media` (CORE_CFG(ROUTE_MEDIA), IF §12.10).
pub trait MediaListeners: Send + Sync + 'static {
    /// The media listener of `route`; `None` when the route has none.
    fn listener(&self, route: u32) -> Option<MediaRoute>;
}

/// An audit sink that writes the record as a WARN line: for a process whose audit chain is not wired in.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogAudit;

impl MediaAudit for LogAudit {
    fn record(&self, event: &'static str, detail: &str) {
        tracing::warn!(event, detail, "media audit");
    }
}

/// A session and what the port routes to it.
struct Inner {
    session: Session,
    /// The demux key registered for the session.
    ufrag: Option<Box<[u8]>>,
    /// The addresses registered for the session.
    addrs: Vec<SocketAddr>,
}

/// One session as the port holds it.
struct Cell {
    inner: Mutex<Inner>,
    /// Woken after every call into the session: a waiter re-reads its lines and its closed bit.
    changed: tokio::sync::Notify,
}

impl Cell {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A port's routes: by the local ufrag a check names, by the address a session numbered.
#[derive(Default)]
struct Table {
    by_ufrag: HashMap<Box<[u8]>, Arc<Cell>>,
    by_addr: HashMap<SocketAddr, Arc<Cell>>,
}

/// One bound UDP port and its sessions.
struct Port {
    socket: ReadyPort,
    table: Mutex<Table>,
    /// The reader's snapshot of the sessions it visits (its timers, a socket failure), taken so no session is
    /// locked under the table's lock: cleared per visit, kept for the next.
    visiting: Mutex<Vec<Arc<Cell>>>,
}

impl Port {
    /// Bind `bind` and start its reader. The reader holds the port weakly: when the last session and the
    /// carrier let go, it ends and the socket closes.
    fn open(bind: SocketAddr) -> io::Result<Arc<Port>> {
        let text = crate::StackText::<{ crate::SOCKET_TEXT }>::of(&bind);
        let socket = ReadyPort::open(udp::bind(text.as_str())?)?;
        let port = Arc::new(Port {
            socket,
            table: Mutex::new(Table::default()),
            visiting: Mutex::new(Vec::new()),
        });
        tokio::spawn(run(Arc::downgrade(&port)));
        Ok(port)
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The reader's visiting list, empty.
    fn visiting(&self) -> MutexGuard<'_, Vec<Arc<Cell>>> {
        let mut cells = self.visiting.lock().unwrap_or_else(PoisonError::into_inner);
        cells.clear();
        cells
    }

    /// Register `session` under its local ufrag. A ufrag already live on this port is refused (the session is
    /// closed and nothing of it stays routed).
    fn admit(&self, mut session: Session) -> Result<Arc<Cell>, RecordsDenied> {
        let Some((_, ufrag)) = session.take_ufrag_move() else {
            session.close();
            return Err(RecordsDenied::Invalid);
        };
        let key: Box<[u8]> = ufrag.into_boxed_bytes();
        let cell = Arc::new(Cell {
            inner: Mutex::new(Inner {
                session,
                ufrag: None,
                addrs: Vec::new(),
            }),
            changed: tokio::sync::Notify::new(),
        });
        {
            let mut table = self.table();
            if table.by_ufrag.contains_key(&key[..]) {
                drop(table);
                let mut inner = cell.lock();
                inner.session.close();
                return Err(RecordsDenied::Unavailable);
            }
            let held: Box<[u8]> = Box::from(&key[..]);
            table.by_ufrag.insert(held, Arc::clone(&cell));
        }
        let mut inner = cell.lock();
        inner.ufrag = Some(key);
        self.after(&cell, &mut inner);
        drop(inner);
        Ok(cell)
    }

    /// After every call into `inner`'s session: send what it queued, re-key a changed ufrag (refusing one live
    /// elsewhere on this port), route the addresses it numbered, forget it once closed, wake its waiters.
    fn after(&self, cell: &Arc<Cell>, inner: &mut Inner) {
        let socket = &self.socket;
        inner.session.send_out(&mut |to, bytes| {
            // A full send buffer drops the datagram: the far end's own retransmission is the recovery.
            let _ = socket.send_to(bytes, to);
        });
        if let Some((_, new)) = inner.session.take_ufrag_move() {
            let new: Box<[u8]> = new.into_boxed_bytes();
            let mut table = self.table();
            let taken = table
                .by_ufrag
                .get(&new[..])
                .is_some_and(|other| !Arc::ptr_eq(other, cell));
            if taken {
                drop(table);
                inner.session.close();
            } else {
                if let Some(old) = inner.ufrag.take() {
                    if table
                        .by_ufrag
                        .get(&old[..])
                        .is_some_and(|c| Arc::ptr_eq(c, cell))
                    {
                        table.by_ufrag.remove(&old[..]);
                    }
                }
                let held: Box<[u8]> = Box::from(&new[..]);
                table.by_ufrag.insert(held, Arc::clone(cell));
                inner.ufrag = Some(new);
            }
        }
        let numbered = inner.session.take_new_addrs();
        if !numbered.is_empty() {
            let mut table = self.table();
            for addr in numbered {
                table.by_addr.insert(addr, Arc::clone(cell));
                inner.addrs.push(addr);
            }
        }
        if inner.session.is_closed() {
            self.forget(cell, inner);
        }
        cell.changed.notify_waiters();
    }

    /// Drop every route to `cell` (only the ones that still lead to it).
    fn forget(&self, cell: &Arc<Cell>, inner: &mut Inner) {
        if inner.ufrag.is_none() && inner.addrs.is_empty() {
            return;
        }
        let mut table = self.table();
        if let Some(key) = inner.ufrag.take() {
            if table
                .by_ufrag
                .get(&key[..])
                .is_some_and(|c| Arc::ptr_eq(c, cell))
            {
                table.by_ufrag.remove(&key[..]);
            }
        }
        for addr in inner.addrs.drain(..) {
            if table
                .by_addr
                .get(&addr)
                .is_some_and(|c| Arc::ptr_eq(c, cell))
            {
                table.by_addr.remove(&addr);
            }
        }
    }

    /// One datagram off the wire: a check goes to the session its USERNAME's local ufrag names, anything else
    /// to the session that numbered its source address. Neither found: dropped.
    fn ingest(&self, from: SocketAddr, bytes: &[u8], now: Instant) {
        let cell = {
            let table = self.table();
            match stun::local_ufrag(bytes) {
                Some(ufrag) => table.by_ufrag.get(ufrag).map(Arc::clone),
                None => table.by_addr.get(&from).map(Arc::clone),
            }
        };
        let Some(cell) = cell else {
            return;
        };
        let mut inner = cell.lock();
        inner.session.on_datagram(from, bytes, now);
        self.after(&cell, &mut inner);
    }

    /// The timers of every session on the port.
    fn tick(&self, now: Instant) {
        let mut cells = self.visiting();
        cells.extend(self.table().by_ufrag.values().map(Arc::clone));
        for cell in cells.drain(..) {
            let mut inner = cell.lock();
            if inner.session.deadline().is_some_and(|due| due <= now) {
                inner.session.on_timer(now);
                self.after(&cell, &mut inner);
            }
        }
    }

    /// The socket failed: every session on it ends.
    fn close_all(&self) {
        let mut cells = self.visiting();
        cells.extend(self.table().by_ufrag.values().map(Arc::clone));
        for cell in cells.drain(..) {
            let mut inner = cell.lock();
            inner.session.close();
            self.after(&cell, &mut inner);
        }
    }
}

/// A port's reader: datagrams in, timers on a short tick. It holds the port only while it works.
async fn run(weak: Weak<Port>) {
    let mut buf = vec![0_u8; udp::MAX_DATAGRAM];
    // The first wake ticks: no reading is taken before it.
    let mut next_tick: Option<Instant> = None;
    loop {
        let Some(port) = weak.upgrade() else {
            return;
        };
        let got = tokio::time::timeout(
            TICK,
            std::future::poll_fn(|cx| port.socket.poll_recv_from(cx, &mut buf)),
        )
        .await;
        let now = crate::framer::now();
        match got {
            Ok(Ok((n, from))) => {
                if let Some(datagram) = buf.get(..n) {
                    port.ingest(from, datagram, now);
                }
            }
            Ok(Err(_)) => {
                port.close_all();
                return;
            }
            Err(_) => {}
        }
        if next_tick.is_none_or(|at| now >= at) {
            port.tick(now);
            next_tick = Some(now + TICK);
        }
    }
}

/// One media session as `MediaBridge` holds it (dropping it closes the session and drops the transport's).
struct Leg {
    cell: Arc<Cell>,
    port: Arc<Port>,
}

impl Leg {
    fn close_now(&self) {
        let mut inner = self.cell.lock();
        let (dropped, denied) = inner.session.counts();
        inner.session.close();
        self.port.after(&self.cell, &mut inner);
        tracing::debug!(dropped, denied, "media session closed");
    }
}

impl Drop for Leg {
    fn drop(&mut self) {
        self.close_now();
    }
}

impl MediaLeg for Leg {
    fn settled(&self) -> BoxFut<'_, Result<Lines, RecordsDenied>> {
        Box::pin(async move {
            loop {
                let mut changed = std::pin::pin!(self.cell.changed.notified());
                changed.as_mut().enable();
                {
                    let inner = self.cell.lock();
                    if inner.session.is_closed() {
                        return Err(RecordsDenied::Unavailable);
                    }
                    if !inner.session.lines().is_empty() {
                        return Ok(inner.session.lines().clone());
                    }
                }
                changed.await;
            }
        })
    }

    fn answer<'a>(&'a self, description: &'a str) -> BoxFut<'a, Result<Lines, RecordsDenied>> {
        Box::pin(async move {
            let now = crate::framer::now();
            let mut inner = self.cell.lock();
            let taken = inner.session.rendezvous(description, now);
            self.port.after(&self.cell, &mut inner);
            if !taken {
                return Err(RecordsDenied::Invalid);
            }
            Ok(inner.session.lines().clone())
        })
    }

    fn close(&self) {
        self.close_now();
    }

    fn closed(&self) -> BoxFut<'_, ()> {
        Box::pin(async move {
            loop {
                let mut changed = std::pin::pin!(self.cell.changed.notified());
                changed.as_mut().enable();
                if self.cell.lock().session.is_closed() {
                    return;
                }
                changed.await;
            }
        })
    }
}

/// The connector's datagram carriers over one datagram transport (the instance serving protocol "webrtc").
pub struct DatagramCarrier {
    opener: Arc<dyn Opener>,
    listeners: Arc<dyn MediaListeners>,
    judge: Arc<dyn DialJudge>,
    audit: Arc<dyn MediaAudit>,
    cert: Arc<SessionCert>,
    /// The accepted listeners' ports by bind address, held for the carrier's life.
    ports: Mutex<HashMap<SocketAddr, Arc<Port>>>,
}

impl DatagramCarrier {
    /// A carrier over `transport`. Mints the process's DTLS certificate; that it cannot is a host fault.
    pub fn new(
        transport: Arc<dyn TransportPort>,
        listeners: Arc<dyn MediaListeners>,
        judge: Arc<dyn DialJudge>,
        audit: Arc<dyn MediaAudit>,
    ) -> Result<Self, Failure> {
        Self::over(Arc::new(Ported(transport)), listeners, judge, audit)
    }

    /// A carrier over any opener of live sessions.
    fn over(
        opener: Arc<dyn Opener>,
        listeners: Arc<dyn MediaListeners>,
        judge: Arc<dyn DialJudge>,
        audit: Arc<dyn MediaAudit>,
    ) -> Result<Self, Failure> {
        Ok(DatagramCarrier {
            opener,
            listeners,
            judge,
            audit,
            cert: Arc::new(SessionCert::mint()?),
            ports: Mutex::new(HashMap::default()),
        })
    }

    /// The port of an accepted listener, bound on first use.
    fn listener_port(&self, bind: SocketAddr) -> Result<Arc<Port>, RecordsDenied> {
        let mut ports = self.ports.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(port) = ports.get(&bind) {
            return Ok(Arc::clone(port));
        }
        let port = Port::open(bind).map_err(|_| RecordsDenied::Unavailable)?;
        ports.insert(bind, Arc::clone(&port));
        Ok(port)
    }

    fn begin(
        &self,
        port: &Port,
        route: MediaRoute,
        dial: bool,
        opening: &[u8],
        now: Instant,
    ) -> Result<Session, RecordsDenied> {
        Session::begin(
            &*self.opener,
            Arc::clone(&self.cert),
            Arc::clone(&self.audit),
            Params {
                dial,
                local: port.socket.local_addr(),
                opening,
                judge: Some((Arc::clone(&self.judge), route.class)),
            },
            now,
        )
    }
}

impl MediaCarrier for DatagramCarrier {
    fn accept<'a>(
        &'a self,
        route: u32,
        offer: &'a str,
    ) -> BoxFut<'a, Result<Carried, RecordsDenied>> {
        Box::pin(async move {
            let media = self
                .listeners
                .listener(route)
                .ok_or(RecordsDenied::Unavailable)?;
            let port = self.listener_port(media.bind)?;
            // The accept's one reading: its session begins and takes the offer at it.
            let now = crate::framer::now();
            let session = self.begin(&port, media, false, &[], now)?;
            let cell = port.admit(session)?;
            let answer = {
                let mut inner = cell.lock();
                let taken = inner.session.rendezvous(offer, now);
                port.after(&cell, &mut inner);
                if !taken {
                    return Err(RecordsDenied::Invalid);
                }
                inner.session.take_rendezvous()
            };
            let Some(answer) = answer else {
                cell.lock().session.close();
                return Err(RecordsDenied::Invalid);
            };
            let leg: Box<dyn MediaLeg> = Box::new(Leg { cell, port });
            Ok((answer, leg))
        })
    }

    fn dial<'a>(
        &'a self,
        route: u32,
        opening: &'a [u8],
    ) -> BoxFut<'a, Result<Carried, RecordsDenied>> {
        Box::pin(async move {
            let media = self
                .listeners
                .listener(route)
                .ok_or(RecordsDenied::Unavailable)?;
            // A port of its own, on the listener's address: two calls to one far end would share the 5-tuple.
            let own = SocketAddr::new(media.bind.ip(), 0);
            let port = Port::open(own).map_err(|_| RecordsDenied::Unavailable)?;
            let session = self.begin(&port, media, true, opening, crate::framer::now())?;
            let cell = port.admit(session)?;
            let offer = cell.lock().session.take_rendezvous();
            let Some(offer) = offer else {
                cell.lock().session.close();
                return Err(RecordsDenied::Invalid);
            };
            let leg: Box<dyn MediaLeg> = Box::new(Leg { cell, port });
            Ok((offer, leg))
        })
    }
}

#[cfg(test)]
#[path = "carrier_tests.rs"]
mod tests;
