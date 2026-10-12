// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEST-ONLY HOT CARRIER, `mem`: connections are in-process byte pipes, found by the address a
//! listener bound (`mem:<port>`) in one process-wide table. It is the subject the transport
//! conformance and stack witnesses drive now that no shipped carrier speaks over a socket in this
//! crate's test graph.
//!
//! It is held two ways, as a shipped carrier is: LINKED ([`carrier`], the contract's [`Carrier`]
//! driven directly) and as its DECL ([`decl`], lowered by the contract's own sdk exactly as
//! `export_carrier!` lowers one), which the loader admits through `link_transport`. A pipe holds at
//! most [`CAPACITY`] bytes, so a long write parks until the far end reads, and every park is woken
//! through the waker it was polled with — across the lowering, the host's `wake(token)`.
//!
//! The far end of a test is a [`Peer`]: a separate linked instance, driven to completion on the
//! calling thread. A peer has no half-close (a carrier closes a connection whole).

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::task::{Context, Poll, Wake, Waker};

use busbar_contract::abi::hot::decl::{DeclStr, OpaqueHandle};
use busbar_contract::abi::hot::transport::{
    CarrierSlots, DeclClaim, RawWireOutcome, TransportDecl, WireSettings, WireWaker,
};
use busbar_contract::abi::sdk::transport as sdk;
use busbar_contract::grammar::SelectorForm;
use busbar_contract::transport::wire::{
    CloseReason, Framing, StatusAt, TransportError, Unit0Trigger,
};
use busbar_contract::transport::{
    Carrier, CarrierFacts, CarrierPoll, Chunk, Dest, TransportMeta, TransportRow, TransportSettings,
};
use busbar_contract::{AbiVersion, Kind, Plugin};

/// The carrier's key.
pub(crate) const KEY: &str = "mem";

/// What one pipe holds before a write parks.
pub(crate) const CAPACITY: usize = 4096;

/// An address nobody listens on: a dial to it is refused when its opening settles.
pub(crate) const NOBODY: &str = "mem:0";

/// One direction of a connection.
#[derive(Default)]
struct Pipe {
    bytes: VecDeque<u8>,
    /// Either end closed the connection: the reader sees the end once the bytes run out, and the
    /// writer is refused.
    shut: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

type Shared = Arc<Mutex<Pipe>>;

fn pipe() -> Shared {
    Arc::new(Mutex::new(Pipe::default()))
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A connection end: what it reads, what it writes, and its far end.
#[derive(Clone)]
struct End {
    rx: Shared,
    tx: Shared,
    peer: String,
    local_port: u16,
    /// A dial that reached nobody: every use answers the refusal.
    refused: bool,
}

/// A bound address: the dials waiting to be accepted, and the accept parked on them.
#[derive(Default)]
struct Port {
    waiting: VecDeque<End>,
    accept: Option<Waker>,
}

/// Every bound address in the process.
static NET: LazyLock<Mutex<HashMap<String, Port>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// The next port handed out, to a listener or a dialler's own end.
static PORT: AtomicU16 = AtomicU16::new(1);

fn next_port() -> u16 {
    PORT.fetch_add(1, Ordering::Relaxed)
}

/// THE CARRIER: its connections and listeners, by handle.
pub(crate) struct Mem {
    conns: Mutex<HashMap<u64, End>>,
    listeners: Mutex<HashMap<u64, String>>,
    next: AtomicU64,
}

impl Mem {
    fn new() -> Self {
        Self {
            conns: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        }
    }

    fn end(&self, conn: u64) -> Result<End, TransportError> {
        let end = lock(&self.conns)
            .get(&conn)
            .cloned()
            .ok_or(TransportError::Closed)?;
        if end.refused {
            return Err(TransportError::Refused);
        }
        Ok(end)
    }

    fn hold(&self, end: End) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        lock(&self.conns).insert(id, end);
        id
    }
}

/// The linked carrier's constructor: what `init` builds on the decl's side.
fn build(_: &TransportSettings) -> Mem {
    Mem::new()
}

/// A fresh LINKED instance.
pub(crate) fn carrier() -> Arc<dyn Carrier> {
    Arc::new(Mem::new())
}

impl Plugin for Mem {
    fn key(&self) -> &'static str {
        KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        busbar_contract::transport::TRANSPORT_ABI
    }
}

impl TransportMeta for Mem {
    const KEY: &'static str = KEY;
    const SELECTOR_FORMS: &'static [SelectorForm] = &[SelectorForm::Sni];
    const EGRESS_SELECTOR_FORMS: &'static [SelectorForm] = &[SelectorForm::ExactPath];
    const COMPOSES_OVER: &'static [&'static str] = &[];
    const HANDOFF: Option<busbar_contract::transport::wire::Handoff> = None;
    const FRAMING: Framing = Framing::Stream;
    const SESSION: bool = false;
    const SESSION_BOUND: bool = false;
    const UNIT0_TRIGGER: Option<Unit0Trigger> = Some(Unit0Trigger::FirstBytes);
    const UPGRADES_TO: &'static [&'static str] = &["lines"];
    const HANDSHAKE_TRIGGER: Option<busbar_contract::transport::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &["mem.port"];
    const DECODES_PAYLOAD: bool = false;
    const STATUS_CLASS: Option<StatusAt> = None;
    const STATUS_NAMESPACE: Option<&'static str> = None;
}

/// The linked carrier's row.
pub(crate) const ROW: TransportRow = TransportRow::of::<Mem>();

impl Carrier for Mem {
    fn listen(&self, bind: &str) -> Result<(u64, String), TransportError> {
        if bind != "mem:0" {
            return Err(TransportError::AddressRefused);
        }
        let addr = format!("mem:{}", next_port());
        lock(&NET).insert(addr.clone(), Port::default());
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        lock(&self.listeners).insert(id, addr.clone());
        Ok((id, addr))
    }

    fn poll_accept(&self, listener: u64, cx: &mut Context<'_>) -> CarrierPoll<(u64, String)> {
        let Some(addr) = lock(&self.listeners).get(&listener).cloned() else {
            return Poll::Ready(Err(TransportError::Closed));
        };
        let mut net = lock(&NET);
        let Some(port) = net.get_mut(&addr) else {
            return Poll::Ready(Err(TransportError::Closed));
        };
        match port.waiting.pop_front() {
            Some(end) => {
                drop(net);
                let peer = end.peer.clone();
                Poll::Ready(Ok((self.hold(end), peer)))
            }
            None => {
                port.accept = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn dial(&self, dest: &Dest<'_>) -> Result<u64, TransportError> {
        let Dest::Authority(authority) = dest else {
            return Err(TransportError::AddressRefused);
        };
        if !authority.starts_with("mem:") {
            return Err(TransportError::AddressRefused);
        }
        let mut net = lock(&NET);
        let Some(port) = net.get_mut(*authority) else {
            drop(net);
            return Ok(self.hold(End {
                rx: pipe(),
                tx: pipe(),
                peer: (*authority).to_string(),
                local_port: 0,
                refused: true,
            }));
        };
        let local_port = authority
            .strip_prefix("mem:")
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        let (up, down) = (pipe(), pipe());
        port.waiting.push_back(End {
            rx: Arc::clone(&up),
            tx: Arc::clone(&down),
            peer: format!("mem:{}", next_port()),
            local_port,
            refused: false,
        });
        if let Some(w) = port.accept.take() {
            w.wake();
        }
        drop(net);
        Ok(self.hold(End {
            rx: down,
            tx: up,
            peer: (*authority).to_string(),
            local_port: 0,
            refused: false,
        }))
    }

    fn poll_read(&self, conn: u64, cx: &mut Context<'_>, buf: &mut [u8]) -> CarrierPoll<Chunk> {
        let end = match self.end(conn) {
            Ok(end) => end,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let mut rx = lock(&end.rx);
        if rx.bytes.is_empty() {
            if rx.shut {
                return Poll::Ready(Ok(Chunk::stream(0)));
            }
            rx.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.len().min(rx.bytes.len());
        for (to, from) in buf.iter_mut().zip(rx.bytes.drain(..n)) {
            *to = from;
        }
        if let Some(w) = rx.writer.take() {
            w.wake();
        }
        Poll::Ready(Ok(Chunk::stream(n)))
    }

    fn poll_write(
        &self,
        conn: u64,
        cx: &mut Context<'_>,
        bytes: &[u8],
        _: bool,
    ) -> CarrierPoll<usize> {
        let end = match self.end(conn) {
            Ok(end) => end,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let mut tx = lock(&end.tx);
        if tx.shut {
            return Poll::Ready(Err(TransportError::Closed));
        }
        let room = CAPACITY - tx.bytes.len();
        if room == 0 {
            tx.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(bytes.len());
        tx.bytes.extend(&bytes[..n]);
        if let Some(w) = tx.reader.take() {
            w.wake();
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(&self, conn: u64, _: &mut Context<'_>) -> CarrierPoll<()> {
        Poll::Ready(self.end(conn).map(|_| ()))
    }

    fn poll_close(&self, conn: u64, _: &mut Context<'_>, _: CloseReason) -> CarrierPoll<()> {
        if let Some(end) = lock(&self.conns).remove(&conn) {
            for side in [&end.tx, &end.rx] {
                let mut p = lock(side);
                p.shut = true;
                for w in [p.reader.take(), p.writer.take()].into_iter().flatten() {
                    w.wake();
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn arrival(&self, conn: u64) -> Option<CarrierFacts> {
        let end = self.end(conn).ok()?;
        Some(CarrierFacts {
            peer: end.peer,
            local_port: end.local_port,
        })
    }
}

// ── the decl ────────────────────────────────────────────────────────────────────────────────────

extern "C-unwind" fn init(
    settings: *const WireSettings,
    waker: *const WireWaker,
    out_state: *mut core::mem::MaybeUninit<OpaqueHandle>,
) -> RawWireOutcome {
    // SAFETY: the host calls `init` with its own live settings, waker handle and out slot.
    unsafe { sdk::init::<Mem>(settings, waker, out_state, build) }
}

static SLOTS: CarrierSlots = sdk::carrier_slots::<Mem>();
static SELECTOR_FORMS: [u8; 1] = sdk::form_codes(<Mem as TransportMeta>::SELECTOR_FORMS);
static EGRESS_SELECTOR_FORMS: [u8; 1] =
    sdk::form_codes(<Mem as TransportMeta>::EGRESS_SELECTOR_FORMS);
static UPGRADES_TO: [DeclStr; 1] = sdk::decl_strs(<Mem as TransportMeta>::UPGRADES_TO);
static TRANSPORT_FACTS: [DeclStr; 1] = sdk::decl_strs(<Mem as TransportMeta>::TRANSPORT_FACTS);
static CLAIM_FORMS: [u8; sdk::claim_forms_len(<Mem as TransportMeta>::CLAIMS)] =
    sdk::claim_form_pool(<Mem as TransportMeta>::CLAIMS);
static CLAIM_FACTS: [DeclStr; sdk::claim_facts_len(<Mem as TransportMeta>::CLAIMS)] =
    sdk::claim_fact_pool(<Mem as TransportMeta>::CLAIMS);
static CLAIMS: [DeclClaim; 1] =
    sdk::decl_claims(<Mem as TransportMeta>::CLAIMS, &CLAIM_FORMS, &CLAIM_FACTS);

/// The carrier's HOT decl, lowered by the sdk exactly as `export_carrier!` lowers one.
pub(crate) fn decl() -> &'static TransportDecl {
    static DECL: OnceLock<TransportDecl> = OnceLock::new();
    DECL.get_or_init(|| {
        sdk::decl::<Mem>(
            sdk::RowLists {
                composes_over: &[],
                selector_forms: &SELECTOR_FORMS,
                egress_selector_forms: &EGRESS_SELECTOR_FORMS,
                upgrades_to: &UPGRADES_TO,
                transport_facts: &TRANSPORT_FACTS,
                claims: &CLAIMS,
            },
            init,
            Some(&SLOTS),
            None,
        )
    })
}

/// The decl's own carrier slot table.
pub(crate) fn slots() -> &'static CarrierSlots {
    &SLOTS
}

/// A copy of the decl, to alter one field of.
pub(crate) fn decl_copy() -> TransportDecl {
    // SAFETY: a byte copy of the live decl; every pointer in it is `'static` data.
    unsafe { core::ptr::read(decl()) }
}

// ── driving a carrier on this thread ────────────────────────────────────────────────────────────

/// Wakes the thread that parked on a poll.
struct Unpark(std::thread::Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Drive one future on this thread, parking between polls.
pub(crate) fn block_on<F: Future>(f: F) -> F::Output {
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut f = std::pin::pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::park();
    }
}

/// Poll one carrier method to its answer on this thread.
pub(crate) fn wait<T>(
    mut method: impl FnMut(&mut Context<'_>) -> CarrierPoll<T>,
) -> Result<T, TransportError> {
    block_on(std::future::poll_fn(|cx| method(cx)))
}

// ── the far end ─────────────────────────────────────────────────────────────────────────────────

/// One connection of a peer's own carrier.
pub(crate) struct Peer {
    carrier: Arc<dyn Carrier>,
    conn: u64,
}

/// A listener of a peer's own carrier, and the address it bound.
pub(crate) struct PeerListener {
    carrier: Arc<dyn Carrier>,
    listener: u64,
    /// The bound address.
    pub(crate) addr: String,
}

/// Listen on a fresh address.
pub(crate) fn listen() -> PeerListener {
    let carrier = carrier();
    let (listener, addr) = carrier.listen("mem:0").expect("the peer listens");
    PeerListener {
        carrier,
        listener,
        addr,
    }
}

impl PeerListener {
    /// The next connection, and its far end.
    pub(crate) fn accept(&self) -> (Peer, String) {
        let (conn, peer) =
            wait(|cx| self.carrier.poll_accept(self.listener, cx)).expect("the peer accepts");
        (
            Peer {
                carrier: Arc::clone(&self.carrier),
                conn,
            },
            peer,
        )
    }
}

/// Dial `addr`, and wait for it to open.
pub(crate) fn dial(addr: &str) -> Peer {
    let carrier = carrier();
    let conn = carrier
        .dial(&Dest::Authority(addr))
        .expect("the peer dials");
    wait(|cx| carrier.poll_flush(conn, cx)).expect("the peer's dial opens");
    Peer { carrier, conn }
}

impl Peer {
    /// Write every one of `bytes`, then flush.
    pub(crate) fn write_all(&self, bytes: &[u8]) {
        let mut at = 0;
        while at < bytes.len() {
            at += wait(|cx| self.carrier.poll_write(self.conn, cx, &bytes[at..], false))
                .expect("the peer writes");
        }
        wait(|cx| self.carrier.poll_flush(self.conn, cx)).expect("the peer flushes");
    }

    /// Read exactly `n` bytes.
    pub(crate) fn read_exact(&self, n: usize) -> Vec<u8> {
        let mut all = Vec::with_capacity(n);
        let mut buf = vec![0_u8; 1000];
        while all.len() < n {
            let want = (n - all.len()).min(buf.len());
            match wait(|cx| {
                self.carrier
                    .poll_read(self.conn, cx, &mut buf[..want])
                    .map_ok(|c| c.len)
            }) {
                Ok(0) => panic!("the stack closed after {} of {n} bytes", all.len()),
                Ok(got) => all.extend_from_slice(&buf[..got]),
                Err(e) => panic!("the peer's read failed: {e:?}"),
            }
        }
        all
    }

    /// Read to the clean end the far side's close makes.
    pub(crate) fn read_to_end(&self) -> Vec<u8> {
        let mut all = Vec::new();
        let mut buf = vec![0_u8; 1000];
        loop {
            match wait(|cx| {
                self.carrier
                    .poll_read(self.conn, cx, &mut buf)
                    .map_ok(|c| c.len)
            }) {
                Ok(0) => return all,
                Ok(n) => all.extend_from_slice(&buf[..n]),
                Err(e) => panic!("the peer's read failed: {e:?}"),
            }
        }
    }

    /// Close the connection.
    pub(crate) fn close(&self) {
        let _ = wait(|cx| self.carrier.poll_close(self.conn, cx, CloseReason::Normal));
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.close();
    }
}
