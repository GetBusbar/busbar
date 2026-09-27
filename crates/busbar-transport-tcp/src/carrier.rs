// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARRIER (TRANSPORT-STACK; #3, #30): `tcp` as the contract's [`Carrier`] — the one
//! implementation both doors drive. A build that links this crate holds a [`TcpCarrier`] as its
//! `Arc<dyn Carrier>` (`crate::linked::build`); the `cdylib` built with the `dropped-in` feature
//! lowers the same type to the HOT decl through the contract's `export_carrier!` ([`exports`]), and
//! the host drives it through the loader's decl-backed carrier — the same methods, one crossing each.
//!
//! No method blocks: `listen` and `dial` answer at once, and the `poll_*` methods answer Ready |
//! Pending | Error, registering the caller's waker. The sockets' readiness and the dial clock are
//! driven by this carrier's own I/O reactor (one thread per built instance), which wakes the waker
//! the caller registered; the caller polls again on its own thread and the bytes move there.
//!
//! `listen` binds SO_REUSEPORT on unix: the host listens once per acceptor on one address (its
//! per-core fan-out, the same model as its own data listeners).

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use busbar_contract::transport::wire::{CloseReason, TransportError};
use busbar_contract::transport::{Carrier, CarrierFacts, CarrierPoll, Dest};
use busbar_contract::{AbiVersion, Kind, Plugin, Transport};
use tokio::net::TcpStream;

use crate::TcpTransport;

/// The `tcp` carrier: the transport's own connection registry, the listeners it bound, the dials
/// still opening, the wakers parked on each connection, and the I/O reactor its sockets are
/// registered with (declared last, so it stops after everything that holds a socket).
pub struct TcpCarrier {
    tcp: TcpTransport,
    wakers: Mutex<HashMap<u64, Parked>>,
    listeners: Mutex<HashMap<u64, Arc<tokio::net::TcpListener>>>,
    next_listener: AtomicU64,
    dialing: Mutex<HashMap<u64, Dialing>>,
    reactor: Reactor,
}

impl std::fmt::Debug for TcpCarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpCarrier").finish_non_exhaustive()
    }
}

/// A dial `dial` began: its connection's handle is out, its socket not yet open.
type Dialing =
    Pin<Box<dyn Future<Output = Result<(TcpStream, SocketAddr), TransportError>> + Send>>;

/// The wakers a connection's parked reading and writing hold — so a close wakes both, and each sees
/// the connection closed.
#[derive(Default)]
struct Parked {
    reading: Option<Waker>,
    writing: Option<Waker>,
}

/// This carrier's I/O reactor: a single-threaded runtime on a thread of its own, driving the
/// readiness of every socket this carrier registers and the clock that bounds its dials. It runs no
/// task of the caller's: it only delivers readiness, by waking the caller's waker.
struct Reactor {
    handle: tokio::runtime::Handle,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Reactor {
    fn start() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let handle = runtime.handle().clone();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("busbar-wire-io".into())
            .spawn(move || {
                runtime.block_on(async {
                    let _ = stopped.await;
                });
            })?;
        Ok(Self {
            handle,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for Reactor {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl TcpCarrier {
    /// A carrier with an empty registry and its own reactor.
    ///
    /// # Panics
    ///
    /// The reactor thread cannot be started (the process is out of threads).
    #[must_use]
    pub fn new() -> Self {
        Self {
            tcp: TcpTransport::new(),
            wakers: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            next_listener: AtomicU64::new(1),
            dialing: Mutex::new(HashMap::new()),
            reactor: Reactor::start().expect("the tcp carrier's reactor thread starts"),
        }
    }

    /// Remember `cx`'s waker as the one parked on `conn`'s reading or writing.
    fn park(&self, conn: u64, reading: bool, cx: &Context<'_>) {
        let mut wakers = self.wakers.lock().expect("waker registry poisoned");
        let parked = wakers.entry(conn).or_default();
        let slot = if reading {
            &mut parked.reading
        } else {
            &mut parked.writing
        };
        match slot {
            Some(w) if w.will_wake(cx.waker()) => {}
            _ => *slot = Some(cx.waker().clone()),
        }
    }

    /// Drive the dial `dial` began for `conn`, if it is still opening: the connection is held once
    /// its socket is open, and forgotten if the dial failed.
    fn settle(&self, conn: u64, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        let mut dialing = self.dialing.lock().expect("dial registry poisoned");
        let Some(dial) = dialing.get_mut(&conn) else {
            return Poll::Ready(Ok(()));
        };
        let opened = std::task::ready!(dial.as_mut().poll(cx));
        dialing.remove(&conn);
        drop(dialing);
        let (stream, addr) = opened?;
        self.tcp
            .register_as(conn, stream, addr)
            .map_err(|e| TcpTransport::map_io_err(&e))?;
        Poll::Ready(Ok(()))
    }

    /// Poll one direction of `conn` once its dial settled, parking `cx`'s waker on it.
    fn poll_conn<T>(
        &self,
        conn: u64,
        reading: bool,
        cx: &mut Context<'_>,
        op: impl FnOnce(&TcpTransport, &mut Context<'_>) -> Poll<Result<T, TransportError>>,
    ) -> Poll<Result<T, TransportError>> {
        let _in = self.reactor.handle.enter();
        std::task::ready!(self.settle(conn, cx))?;
        self.park(conn, reading, cx);
        op(&self.tcp, cx)
    }
}

impl Default for TcpCarrier {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for TcpCarrier {
    fn key(&self) -> &'static str {
        crate::linked::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        busbar_contract::transport::TRANSPORT_ABI
    }
}

impl Carrier for TcpCarrier {
    fn listen(&self, bind: &str) -> Result<(u64, String), TransportError> {
        let _in = self.reactor.handle.enter();
        let (listener, addr) = TcpTransport::bind_shared(bind)?;
        let id = self.next_listener.fetch_add(1, Ordering::Relaxed);
        self.listeners
            .lock()
            .expect("listener registry poisoned")
            .insert(id, Arc::new(listener));
        Ok((id, addr))
    }

    fn poll_accept(&self, listener: u64, cx: &mut Context<'_>) -> CarrierPoll<(u64, String)> {
        let Some(listening) = self
            .listeners
            .lock()
            .expect("listener registry poisoned")
            .get(&listener)
            .cloned()
        else {
            return Poll::Ready(Err(TransportError::Closed));
        };
        let _in = self.reactor.handle.enter();
        let (stream, peer) = std::task::ready!(listening.poll_accept(cx))
            .map_err(|e| TcpTransport::map_io_err(&e))?;
        let conn = self
            .tcp
            .register(stream, peer)
            .map_err(|e| TcpTransport::map_io_err(&e))?;
        Poll::Ready(Ok((conn.id(), conn.peer())))
    }

    fn dial(&self, dest: &Dest<'_>) -> Result<u64, TransportError> {
        // A byte stream reaches an authority; a program is not a place this carrier can dial.
        let Dest::Authority(authority) = dest else {
            return Err(TransportError::AddressRefused);
        };
        let _in = self.reactor.handle.enter();
        let dial = self.tcp.dialing(authority)?;
        let id = self.tcp.next_conn_id();
        self.dialing
            .lock()
            .expect("dial registry poisoned")
            .insert(id, Box::pin(dial));
        Ok(id)
    }

    fn poll_read(&self, conn: u64, cx: &mut Context<'_>, buf: &mut [u8]) -> CarrierPoll<usize> {
        self.poll_conn(conn, true, cx, |tcp, cx| tcp.poll_read_into(conn, cx, buf))
    }

    fn poll_write(&self, conn: u64, cx: &mut Context<'_>, bytes: &[u8]) -> CarrierPoll<usize> {
        self.poll_conn(conn, false, cx, |tcp, cx| {
            tcp.poll_write_on(conn, cx, bytes)
        })
    }

    fn poll_flush(&self, conn: u64, cx: &mut Context<'_>) -> CarrierPoll<()> {
        self.poll_conn(conn, false, cx, |tcp, cx| tcp.poll_flush_on(conn, cx))
    }

    /// Forget the connection and close it the way the transport closes one, waking whatever was
    /// parked on it; a dial still opening is dropped where it stood. Idempotent.
    fn poll_close(&self, conn: u64, _cx: &mut Context<'_>, reason: CloseReason) -> CarrierPoll<()> {
        let _in = self.reactor.handle.enter();
        drop(
            self.dialing
                .lock()
                .expect("dial registry poisoned")
                .remove(&conn),
        );
        let parked = self
            .wakers
            .lock()
            .expect("waker registry poisoned")
            .remove(&conn);
        if let Some(handle) = self.tcp.conn_handle(conn) {
            self.tcp.close(handle, reason);
        }
        if let Some(parked) = parked {
            parked
                .reading
                .into_iter()
                .chain(parked.writing)
                .for_each(Waker::wake);
        }
        Poll::Ready(Ok(()))
    }

    fn arrival(&self, conn: u64) -> Option<CarrierFacts> {
        let (peer, local_port) = self.tcp.facts(conn)?;
        Some(CarrierFacts { peer, local_port })
    }
}

/// The dropped-in door, compiled only into the dropped-in build (feature `dropped-in`): [`TcpCarrier`]
/// lowered to the HOT decl and registered as this image's ONE door through the contract's
/// `export_carrier!` — so `busbar_abi`, `busbar_plugin_kind() == "transport"` and
/// `busbar_transport_decl` are the contract's frozen symbols, defined once. The one module this
/// crate's `#![deny(unsafe_code)]` allows: every line of it is the macro's.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)]
pub mod exports {
    busbar_contract::export_carrier!(super::TcpCarrier, super::build);
}

/// The linked row's constructor, as the lowering calls it: this wire takes no setting.
#[cfg(feature = "dropped-in")]
fn build(_: &busbar_contract::transport::TransportSettings) -> TcpCarrier {
    TcpCarrier::new()
}
