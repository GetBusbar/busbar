// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STACK'S WITNESS (#2 rule (1), #3; TRANSPORT-STACK): a carrier — linked, or admitted over the
//! HOT-tier ABI through either door — stacked as the host's connection, speaks exactly as the same
//! carrier linked as Rust does.
//!
//! One script runs against three stacks over the both-ways fixture carrier: the linked Rust carrier
//! itself, the loader's decl-backed carrier over its linked decl, and the decl-backed carrier over its
//! dropped-in cdylib. It listens and accepts a peer through busbar's own linked carrier (a separate
//! instance, `carrier_peer`), drains the frame pump, answers
//! and closes; dials a plain peer, writes, drains, closes; and accepts once more and DETACHES the
//! connection, moving bytes over the detached stream (the path a served listener takes). The three
//! records must be equal, and equal to what the script sent.
//!
//! THE RED ARM, kept: [`a_stack_over_a_divergent_carrier_is_seen_by_the_script`] runs the script over
//! a decl whose `poll_write` slot flips one byte, and requires the record to DIFFER.
//!
//! INLINE, NO HOP (#30): [`the_stack_polls_the_carrier_on_the_callers_thread`] runs the script on a
//! single-threaded runtime over a decl whose poll slots record the thread they ran on, and requires
//! every crossing to have run on the runtime's own thread.
//!
//! A FRAMER OVER THE CARRIER: [`a_framer_stacks_over_a_carrier_and_the_upgrade_moves_its_bytes`] stacks
//! a line framer over the fixture carrier, and moves a connection's byte stream — with the half line
//! the framer held — to a second stack that adopts it.

use super::*;
use crate::both_ways::{cdylib, dropped, statement, transport_fixture, HOT_FIXTURES};
use crate::carrier_peer;
use crate::transport::link_transport;
use busbar_contract::abi::hot::transport::{CarrierSlots, RawWireOutcome, TransportDecl, NO_WAKER};
use busbar_contract::plugin::TestKernelSeal;
use busbar_contract::transport::{CarrierPoll, ConnFacts, Located, Side, TransportRow};
use busbar_contract::{AbiVersion, ConfigView, LaneId, StreamId};
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use std::sync::OnceLock;

struct Bind;

impl ConfigView for Bind {
    fn get_str(&self, _: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _: &str) -> Option<bool> {
        None
    }
}

impl TransportConfigView for Bind {
    fn bind(&self) -> Option<&str> {
        Some("127.0.0.1:0")
    }
}

/// The fixture carrier's decl.
fn fixture_decl() -> &'static TransportDecl {
    &transport_fixture::exports::TRANSPORT_DECL
}

/// The fixture carrier's own slot table.
fn real() -> &'static CarrierSlots {
    // SAFETY: the fixture is a carrier, so its decl's carrier table is its `'static` table.
    unsafe { &*fixture_decl().carrier }
}

/// The fixture carrier through the LINKED decl, admitted once for the process.
fn linked_row() -> &'static DynTransport {
    static ROW: OnceLock<DynTransport> = OnceLock::new();
    ROW.get_or_init(|| {
        // SAFETY: the fixture's decl is `'static` and laid out as `TransportDecl`.
        unsafe { link_transport(fixture_decl(), "linked-wire") }.expect("the linked door admits")
    })
}

/// The fixture carrier through the DROPPED-IN door (its cdylib signed into a fresh `plugins/`),
/// admitted once for the process. `None` when the artifact is not built (never under CI).
fn dropped_row() -> Option<&'static DynTransport> {
    static ROW: OnceLock<Option<DynTransport>> = OnceLock::new();
    ROW.get_or_init(|| {
        let krate = HOT_FIXTURES
            .iter()
            .find(|(kind, _)| *kind == "transport")
            .map(|&(_, krate)| krate)?;
        let lib = std::fs::read(cdylib(krate)?).expect("read the transport cdylib");
        let manifest = statement("transport", "wire", "wire", busbar_contract::abi::ABI_MINOR);
        Some(
            dropped("transport-adapter", manifest, &lib)
                .open_transport("wire")
                .expect("the dropped-in door opens the transport"),
        )
    })
    .as_ref()
}

fn settings() -> TransportSettings {
    TransportSettings::default()
}

/// The stack over a decl-backed carrier `row` builds.
fn adapter(row: &'static DynTransport) -> Arc<WireTransport> {
    Arc::new(WireTransport::build(row, None, &settings()).expect("the carrier builds"))
}

/// The stack over the linked Rust carrier.
fn rust() -> Arc<WireTransport> {
    Arc::new(WireTransport::stack(
        transport_fixture::linked::ROW,
        Some(transport_fixture::linked::carrier(&settings())),
        None,
        None,
    ))
}

fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// A destination sealed as the egress unit would seal one, for `addr`.
fn upstream(addr: &str) -> VerifiedDestination {
    VerifiedDestination::seal(
        &TestKernelSeal,
        DestinationFacts::Upstream {
            transport: "wire",
            address: UpstreamAddress::socket(crate::intern_name(addr)),
            lane: LaneId::new("test"),
        },
        "wire",
        None,
    )
}

/// Everything one stack declared and put on / took off the wire.
#[derive(Debug, PartialEq, Eq)]
struct Record {
    key: &'static str,
    kind: Kind,
    abi: AbiVersion,
    composed_over: Option<&'static str>,
    /// Listened: what the pump drained from the peer, and what the peer received back.
    pumped: Vec<u8>,
    answered: Vec<u8>,
    /// The accepted connection's arrival: its chain, and whether it named a local port.
    chain: Vec<&'static str>,
    has_port: bool,
    /// Dialled: what the peer received, and what the pump drained back.
    dialled: Vec<u8>,
    dial_pumped: Vec<u8>,
    /// Detached: what the stream read from the peer, and what the peer received back.
    detached_read: Vec<u8>,
    detached_answered: Vec<u8>,
    /// A write on a connection the stack closed.
    write_after_close: Option<TransportError>,
}

const SENT: (u8, usize) = (7, 40_000);
const REPLY: (u8, usize) = (91, 20_001);

/// The frame pump of `conn`, drained until `upto` bytes (or to its end when `None`).
async fn pump(t: &WireTransport, conn: &Conn, upto: Option<usize>) -> Vec<u8> {
    let mut frames = t.frames(conn.clone());
    let mut all = Vec::new();
    while upto.is_none_or(|n| all.len() < n) {
        let Some(frame) = frames.next().await else {
            break;
        };
        let (_, frame) = frame.expect("a frame");
        assert_eq!(frame.meta.bytes as usize, frame.bytes.as_slice().len());
        all.extend_from_slice(frame.bytes.as_slice());
    }
    all
}

/// A peer that dials `addr`, sends `sent`, and reads to the clean end the stack's close makes.
fn near(addr: String, sent: Vec<u8>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let peer = carrier_peer::dial(&addr);
        peer.write_all(&sent);
        peer.read_to_end()
    })
}

/// THE SCRIPT, run identically against every stack.
async fn script(t: Arc<WireTransport>) -> Record {
    let keys = TransportKeyHandle::keyless();

    // ── listen, accept, drain the pump, answer, close ──
    let listener = t.listen(&Bind, &keys).await.expect("listen");
    let peer = near(listener.local_addr(), payload(SENT.0, SENT.1));
    let conn = t.accept(&listener).await.expect("accept");
    assert!(conn.peer().starts_with("127.0.0.1:"), "{}", conn.peer());
    let arrival = t.arrival(&conn);
    let pumped = pump(&t, &conn, Some(SENT.1)).await;
    let reply = payload(REPLY.0, REPLY.1);
    let n = t
        .write(&conn, StreamId(0), ScratchBytes::new(&reply))
        .await
        .expect("write the answer");
    assert_eq!(n, reply.len());
    t.close(conn.clone(), CloseReason::Normal);
    let write_after_close = t
        .write(&conn, StreamId(0), ScratchBytes::new(b"x"))
        .await
        .err();
    let answered = peer.join().unwrap();

    // ── dial the peer, write, drain what it answers to the end its close makes, close ──
    let far = carrier_peer::listen();
    let dest = upstream(&far.addr);
    let far = std::thread::spawn(move || {
        let (peer, _) = far.accept();
        let got = peer.read_exact(SENT.1);
        peer.write_all(&payload(REPLY.0 ^ 0x5a, REPLY.1));
        peer.close();
        got
    });
    let conn = t.dial(&dest, &keys).await.expect("dial");
    let sent = payload(SENT.0 ^ 0x5a, SENT.1);
    t.write(&conn, StreamId(0), ScratchBytes::new(&sent))
        .await
        .expect("write the request");
    let dial_pumped = pump(&t, &conn, None).await;
    t.close(conn, CloseReason::Normal);
    let dialled = far.join().unwrap();

    // ── accept once more and DETACH: the served listener's path ──
    let listener = t.listen(&Bind, &keys).await.expect("listen again");
    let peer = near(listener.local_addr(), payload(SENT.0 ^ 0xff, SENT.1));
    let conn = t.accept(&listener).await.expect("accept again");
    let stream = t.detach(&conn).expect("the connection detaches");
    assert_eq!(stream.from(), t.key());
    assert!(t.detach(&conn).is_none(), "a detached connection is gone");
    let mut io = stream.into_io();
    let mut detached_read = vec![0_u8; SENT.1];
    io.read_exact(&mut detached_read).await.expect("read");
    io.write_all(&payload(REPLY.0 ^ 0xff, REPLY.1))
        .await
        .expect("write");
    io.close().await.expect("close");
    drop(io);
    let detached_answered = peer.join().unwrap();

    Record {
        key: t.key(),
        kind: t.kind(),
        abi: t.abi(),
        composed_over: t.composed_over(),
        pumped,
        answered,
        chain: arrival.transport_chain,
        has_port: arrival.port != 0,
        dialled,
        dial_pumped,
        detached_read,
        detached_answered,
        write_after_close,
    }
}

/// What the script sent on each leg.
fn expected() -> Record {
    Record {
        key: transport_fixture::linked::KEY,
        kind: Kind::Transport,
        abi: busbar_contract::transport::TRANSPORT_ABI,
        composed_over: None,
        pumped: payload(SENT.0, SENT.1),
        answered: payload(REPLY.0, REPLY.1),
        chain: vec![transport_fixture::linked::KEY],
        has_port: true,
        dialled: payload(SENT.0 ^ 0x5a, SENT.1),
        dial_pumped: payload(REPLY.0 ^ 0x5a, REPLY.1),
        detached_read: payload(SENT.0 ^ 0xff, SENT.1),
        detached_answered: payload(REPLY.0 ^ 0xff, REPLY.1),
        write_after_close: Some(TransportError::Closed),
    }
}

/// THE WITNESS: the linked Rust carrier, the decl-backed carrier over its linked decl and over its
/// dropped-in cdylib, each stacked, run the script to ONE record, and it is the bytes the script sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_door_speaks_alike_through_the_stack() {
    let rust = script(rust()).await;
    assert_eq!(
        rust,
        expected(),
        "the linked carrier moves the bytes it is given"
    );
    let linked = script(adapter(linked_row())).await;
    assert_eq!(
        linked, rust,
        "the carrier over its linked decl is the linked carrier"
    );
    let Some(row) = dropped_row() else {
        return;
    };
    let dropped = script(adapter(row)).await;
    assert_eq!(
        dropped, rust,
        "the dropped-in carrier is the linked carrier"
    );
}

/// The decl-backed carrier's row is the linked carrier's row, constant for constant.
#[test]
fn a_decl_backed_carrier_presents_the_linked_row() {
    let wire = WireTransport::build(linked_row(), None, &settings()).unwrap();
    assert_eq!(*wire.row(), transport_fixture::linked::ROW);
    assert_eq!(wire.key(), transport_fixture::linked::KEY);
}

// ── THE RED ARM ─────────────────────────────────────────────────────────────────────────────────

/// A `poll_write` slot that flips the first byte of every offer, then writes through the real slot.
extern "C-unwind" fn altering_write(
    state: *mut std::os::raw::c_void,
    conn: u64,
    token: u64,
    buf: *const u8,
    len: usize,
    out: *mut usize,
) -> RawWireOutcome {
    let real = real().poll_write.expect("the fixture writes");
    if buf.is_null() || len == 0 {
        return real(state, conn, token, buf, len, out);
    }
    // SAFETY: the host's live `len`-byte range for this call.
    let mut bytes = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
    bytes[0] ^= 0x01;
    real(state, conn, token, bytes.as_ptr(), bytes.len(), out)
}

/// A `'static` copy of the fixture decl whose carrier table is `slots`.
fn decl_with(slots: &'static CarrierSlots) -> TransportDecl {
    // SAFETY: a byte copy of the live fixture decl; every pointer in it is `'static` image data.
    let mut decl = unsafe { core::ptr::read(fixture_decl()) };
    decl.carrier = slots;
    decl
}

/// THE RED ARM, kept: the stack over a carrier whose `poll_write` alters one byte runs the script to
/// a DIFFERENT record, on exactly the legs it wrote — the equality above is one a wrong carrier fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stack_over_a_divergent_carrier_is_seen_by_the_script() {
    static SLOTS: OnceLock<CarrierSlots> = OnceLock::new();
    static ALTERED: OnceLock<TransportDecl> = OnceLock::new();
    static ROW: OnceLock<DynTransport> = OnceLock::new();
    let slots = SLOTS.get_or_init(|| CarrierSlots {
        poll_write: Some(altering_write),
        ..*real()
    });
    let altered = ALTERED.get_or_init(|| decl_with(slots));
    // SAFETY: `altered` is `'static`, and every range it borrows is the fixture's `'static` data.
    let row = ROW.get_or_init(|| unsafe { link_transport(altered, "altered-wire") }.unwrap());
    let seen = script(adapter(row)).await;
    let honest = expected();
    assert_ne!(
        seen, honest,
        "the script must see a carrier that changed a byte"
    );
    assert_ne!(seen.answered, honest.answered);
    assert_ne!(seen.dialled, honest.dialled);
    assert_ne!(seen.detached_answered, honest.detached_answered);
    // What the altered carrier only READ is untouched: the difference is where the bytes changed.
    assert_eq!(seen.pumped, honest.pumped);
    assert_eq!(seen.detached_read, honest.detached_read);
}

// ── INLINE, NO HOP ──────────────────────────────────────────────────────────────────────────────

/// Every thread a recording slot below ran on.
static CROSSED_ON: Mutex<Vec<std::thread::ThreadId>> = Mutex::new(Vec::new());

fn crossed() {
    CROSSED_ON.lock().unwrap().push(std::thread::current().id());
}

extern "C-unwind" fn recording_accept(
    state: *mut std::os::raw::c_void,
    listener: u64,
    token: u64,
    peer: *mut u8,
    cap: usize,
    peer_len: *mut usize,
    conn: *mut u64,
) -> RawWireOutcome {
    crossed();
    real().poll_accept.unwrap()(state, listener, token, peer, cap, peer_len, conn)
}

extern "C-unwind" fn recording_read(
    state: *mut std::os::raw::c_void,
    conn: u64,
    token: u64,
    buf: *mut u8,
    cap: usize,
    out: *mut usize,
) -> RawWireOutcome {
    crossed();
    real().poll_read.unwrap()(state, conn, token, buf, cap, out)
}

extern "C-unwind" fn recording_write(
    state: *mut std::os::raw::c_void,
    conn: u64,
    token: u64,
    buf: *const u8,
    len: usize,
    out: *mut usize,
) -> RawWireOutcome {
    crossed();
    real().poll_write.unwrap()(state, conn, token, buf, len, out)
}

extern "C-unwind" fn recording_flush(
    state: *mut std::os::raw::c_void,
    conn: u64,
    token: u64,
) -> RawWireOutcome {
    crossed();
    real().poll_flush.unwrap()(state, conn, token)
}

/// NO BLOCKING-POOL HOP (#30): on a single-threaded runtime, every poll crossing the script makes —
/// accept, read, write, flush — runs on the runtime's own thread, the one that awaits the stack; and
/// the script still moves exactly the bytes it was given.
#[test]
fn the_stack_polls_the_carrier_on_the_callers_thread() {
    static SLOTS: OnceLock<CarrierSlots> = OnceLock::new();
    static RECORDING: OnceLock<TransportDecl> = OnceLock::new();
    static ROW: OnceLock<DynTransport> = OnceLock::new();
    let slots = SLOTS.get_or_init(|| CarrierSlots {
        poll_accept: Some(recording_accept),
        poll_read: Some(recording_read),
        poll_write: Some(recording_write),
        poll_flush: Some(recording_flush),
        ..*real()
    });
    let recording = RECORDING.get_or_init(|| decl_with(slots));
    // SAFETY: `recording` is `'static`, and every range it borrows is the fixture's `'static` data.
    let row = ROW.get_or_init(|| unsafe { link_transport(recording, "recording-wire") }.unwrap());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let record = runtime.block_on(script(adapter(row)));
    assert_eq!(record, expected());
    let here = std::thread::current().id();
    let crossings = CROSSED_ON.lock().unwrap().clone();
    assert!(crossings.len() > 10, "{} crossings", crossings.len());
    assert!(
        crossings.iter().all(|t| *t == here),
        "a poll slot ran off the awaiting thread: {} of {} crossings",
        crossings.iter().filter(|t| **t != here).count(),
        crossings.len()
    );
}

/// A token is resolved in the host's own table: waking one wakes the task registered with it; a
/// stale token (its registration dropped) and [`NO_WAKER`] wake nothing and do not fault.
#[test]
fn a_token_wakes_only_its_own_live_task() {
    struct Count(std::sync::atomic::AtomicUsize);
    impl std::task::Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let count = Arc::new(Count(std::sync::atomic::AtomicUsize::new(0)));
    let waker = std::task::Waker::from(Arc::clone(&count));
    let token = crate::transport::WakeToken::new();
    token.register(&waker);
    crate::transport::host_wake(token.id());
    assert_eq!(count.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    let stale = token.id();
    drop(token);
    let reused = crate::transport::WakeToken::new();
    reused.register(&waker);
    assert_ne!(reused.id(), stale, "a reused slot is a new token");
    crate::transport::host_wake(stale);
    crate::transport::host_wake(NO_WAKER);
    crate::transport::host_wake(u64::MAX);
    assert_eq!(count.0.load(std::sync::atomic::Ordering::SeqCst), 1);
}

// ── A FRAMER OVER THE CARRIER ───────────────────────────────────────────────────────────────────

/// A linked framer whose frame is one line — enough framing to see the stack ingest, emit, and move
/// a connection's bytes on an upgrade. Each framing state keeps the bytes of its unfinished line.
struct Lines {
    held: Mutex<HashMap<u64, Vec<u8>>>,
    next: std::sync::atomic::AtomicU64,
}

impl Lines {
    fn new() -> Self {
        Self {
            held: Mutex::new(HashMap::new()),
            next: std::sync::atomic::AtomicU64::new(1),
        }
    }
}

impl Plugin for Lines {
    fn key(&self) -> &'static str {
        "lines"
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        busbar_contract::transport::TRANSPORT_ABI
    }
}

impl busbar_contract::transport::Framer for Lines {
    fn locate(&self, target: &str) -> Result<Located, TransportError> {
        Ok(Located {
            authority: target.to_string(),
            secure: false,
            server_name: None,
        })
    }
    fn open(
        &self,
        _: Side,
        _: &str,
        _: &ConnFacts,
        _: &mut dyn busbar_contract::transport::FramerOut,
    ) -> Result<u64, TransportError> {
        let id = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.held.lock().unwrap().insert(id, Vec::new());
        Ok(id)
    }
    fn ingest(
        &self,
        state: u64,
        bytes: &[u8],
        end: bool,
        out: &mut dyn busbar_contract::transport::FramerOut,
    ) -> Result<(), TransportError> {
        let mut all = self.held.lock().unwrap();
        let held = all.get_mut(&state).ok_or(TransportError::Closed)?;
        held.extend_from_slice(bytes);
        while let Some(at) = held.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = held.drain(..=at).collect();
            out.frame(busbar_contract::transport::Framed::plain(
                StreamId(0),
                &line[..at],
                true,
            ));
        }
        if end {
            out.end();
        }
        Ok(())
    }
    fn emit(
        &self,
        _: u64,
        _: StreamId,
        bytes: &[u8],
        end_of_frame: bool,
        out: &mut dyn busbar_contract::transport::FramerOut,
    ) -> Result<(), TransportError> {
        out.send(bytes);
        if end_of_frame {
            out.send(b"\n");
        }
        Ok(())
    }
    fn encode_envelope(
        &self,
        _: &[(&str, &[u8])],
        body: &[u8],
        out: &mut dyn busbar_contract::transport::BytesOut,
    ) -> Result<(), busbar_contract::transport::wire::Encode> {
        out.put(body);
        out.put(b"\n");
        Ok(())
    }
    fn refusal(
        &self,
        state: u64,
        _: Option<StreamId>,
        bytes: &[u8],
        out: &mut dyn busbar_contract::transport::FramerOut,
    ) -> Result<(), TransportError> {
        self.emit(state, StreamId(0), bytes, true, out)
    }
    fn close(
        &self,
        state: u64,
        _: CloseReason,
        out: &mut dyn busbar_contract::transport::FramerOut,
    ) {
        if self.held.lock().unwrap().remove(&state).is_some() {
            out.send(b"bye\n");
        }
    }
    fn detach(
        &self,
        state: u64,
        out: &mut dyn busbar_contract::transport::BytesOut,
    ) -> Result<(), TransportError> {
        let held = self
            .held
            .lock()
            .unwrap()
            .remove(&state)
            .ok_or(TransportError::Closed)?;
        out.put(&held);
        Ok(())
    }
    fn adopt(
        &self,
        side: Side,
        facts: &ConnFacts,
        leftover: &[u8],
        out: &mut dyn busbar_contract::transport::FramerOut,
    ) -> Result<u64, TransportError> {
        let state = self.open(side, "", facts, out)?;
        self.ingest(state, leftover, false, out)?;
        Ok(state)
    }
}

/// The row of a framer composed over the fixture carrier.
fn lines_row() -> TransportRow {
    TransportRow {
        key: "lines",
        composes_over: &[transport_fixture::linked::KEY],
        ..transport_fixture::linked::ROW
    }
}

/// A framer stacked over a carrier frames its bytes (a line per frame, what the framer answers going
/// out), names the layer it stands on, and closes with the framer's own close bytes. On an upgrade
/// the byte stream MOVES: the source stack gives up the connection with the half line its framer
/// held in front of it, and the stack that adopts it frames that half line as the start of its first
/// frame — nothing lost, nothing read twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_framer_stacks_over_a_carrier_and_the_upgrade_moves_its_bytes() {
    let carrier = transport_fixture::linked::carrier(&settings());
    let stack = WireTransport::stack(
        lines_row(),
        Some(Arc::clone(&carrier)),
        Some(Arc::new(Lines::new())),
        None,
    );
    let moved_to = WireTransport::stack(
        lines_row(),
        Some(carrier),
        Some(Arc::new(Lines::new())),
        None,
    );
    assert_eq!(stack.composed_over(), Some(transport_fixture::linked::KEY));
    let keys = TransportKeyHandle::keyless();
    let listener = stack.listen(&Bind, &keys).await.unwrap();
    let addr = listener.local_addr();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let peer = std::thread::spawn(move || {
        let peer = carrier_peer::dial(&addr);
        peer.write_all(b"one\ntw");
        ready_rx.recv().unwrap();
        peer.write_all(b"o\n");
        peer.read_to_end()
    });
    let conn = stack.accept(&listener).await.unwrap();
    assert_eq!(
        stack.arrival(&conn).transport_chain,
        [transport_fixture::linked::KEY, "lines"]
    );
    // The first line is a frame; the half line after it stays with the framer.
    let mut frames = stack.frames(conn.clone());
    let (_, first) = frames.next().await.unwrap().unwrap();
    assert_eq!(first.bytes.as_slice(), b"one");
    drop(frames);
    stack
        .write(&conn, StreamId(0), ScratchBytes::new(b"hi"))
        .await
        .unwrap();
    // THE UPGRADE: the connection moves, with the half line in front of its stream.
    let adopted = moved_to
        .adopt(&stack, conn.clone(), &keys)
        .await
        .expect("the stream moves");
    assert!(
        stack.detach(&conn).is_none(),
        "the source gave the connection up"
    );
    ready_tx.send(()).unwrap();
    let mut frames = moved_to.frames(adopted.clone());
    let (_, second) = frames.next().await.unwrap().unwrap();
    assert_eq!(
        second.bytes.as_slice(),
        b"two",
        "the held half line moved with the stream"
    );
    moved_to.close(adopted, CloseReason::Normal);
    assert!(
        frames.next().await.is_none(),
        "a closed connection's frames end"
    );
    drop(frames);
    let back = peer.join().unwrap();
    assert_eq!(back, b"hi\nbye\n", "the framer's bytes out, then its close");
}

// ── THE #30 MEASUREMENT ─────────────────────────────────────────────────────────────────────────

fn percentiles(mut samples: Vec<u128>) -> (u128, u128) {
    samples.sort_unstable();
    (
        samples[samples.len() / 2],
        samples[samples.len() * 99 / 100],
    )
}

/// A detached stream on `t` whose far end is an echo peer, and the peer's thread.
async fn echoing(t: &WireTransport) -> (RawStreamIo, std::thread::JoinHandle<()>) {
    let listener = t
        .listen(&Bind, &TransportKeyHandle::keyless())
        .await
        .unwrap();
    let addr = listener.local_addr();
    let echo = std::thread::spawn(move || {
        let peer = carrier_peer::dial(&addr);
        loop {
            let b = peer.read_some(1);
            if b.is_empty() {
                break;
            }
            peer.write_all(&b);
        }
    });
    let conn = t.accept(&listener).await.unwrap();
    (t.detach(&conn).unwrap().into_io(), echo)
}

/// A detached stream's byte-stream half, as `RawStream::into_io` hands it.
type RawStreamIo = Box<dyn busbar_contract::transport::wire::RawIo>;

/// One one-byte round trip over `io`, in nanoseconds.
async fn round_trip(io: &mut RawStreamIo) -> u128 {
    let mut b = [0_u8; 1];
    let t0 = std::time::Instant::now();
    io.write_all(&[42]).await.unwrap();
    io.flush().await.unwrap();
    io.read_exact(&mut b).await.unwrap();
    t0.elapsed().as_nanos()
}

/// One-byte ping-pong against an echo peer over a detached stream of EACH stack, INTERLEAVED round by
/// round, so the two samples see the same machine: nanoseconds per round trip, `(a, b)`.
async fn echo_rtt(
    a: Arc<WireTransport>,
    b: Arc<WireTransport>,
    rounds: usize,
) -> (Vec<u128>, Vec<u128>) {
    let ((mut io_a, echo_a), (mut io_b, echo_b)) = (echoing(&a).await, echoing(&b).await);
    let (mut out_a, mut out_b) = (Vec::with_capacity(rounds), Vec::with_capacity(rounds));
    for _ in 0..rounds {
        out_a.push(round_trip(&mut io_a).await);
        out_b.push(round_trip(&mut io_b).await);
    }
    drop((io_a, io_b));
    echo_a.join().unwrap();
    echo_b.join().unwrap();
    (out_a, out_b)
}

/// #30 (HOT lane, < 1 µs per crossing): the DROPPED-IN carrier's added latency, measured at three
/// depths, printed, and held to the budget. Release build: `cargo test --release -p
/// busbar-plugin-loader transport_adapter -- --ignored --nocapture`.
///
/// 1. the ABI crossing itself — a poll slot of the dropped-in image answered without I/O;
/// 2. one trait method of the decl-backed carrier around that crossing (the waker registration, the
///    guarded indirect call, the answer's decode), polled inline on the calling task;
/// 3. a one-byte echo round trip over a detached stream, the dropped-in carrier's stack against the
///    linked Rust carrier's (a write, a flush and a read crossing each), interleaved round by round —
///    the dropped-in p99 within twice the linked one's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "perf measurement; run in release with --ignored --nocapture"]
async fn the_adapters_added_latency_per_crossing_is_measured() {
    let Some(row) = dropped_row() else {
        return;
    };
    let decl_carrier = row.decl_carrier(&crate::wire_settings(&settings()));
    let carrier: &dyn Carrier = &decl_carrier;
    let crossing = percentiles(
        (0..20_000)
            .map(|_| {
                let t0 = std::time::Instant::now();
                let _ = std::hint::black_box(
                    decl_carrier.raw_poll_flush(std::hint::black_box(u64::MAX)),
                );
                t0.elapsed().as_nanos()
            })
            .collect(),
    );
    let waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let bridged = percentiles(
        (0..20_000)
            .map(|_| {
                let t0 = std::time::Instant::now();
                let _: CarrierPoll<()> = std::hint::black_box(
                    carrier.poll_flush(std::hint::black_box(u64::MAX), &mut cx),
                );
                t0.elapsed().as_nanos()
            })
            .collect(),
    );
    let (linked, dropped) = echo_rtt(rust(), adapter(row), 20_000).await;
    let (linked, dropped) = (percentiles(linked), percentiles(dropped));
    println!(
        "#30 transport, dropped-in carrier (budget {} ns per crossing):",
        1_000
    );
    println!(
        "  ABI crossing alone:            p50 {:>7} ns  p99 {:>7} ns",
        crossing.0, crossing.1
    );
    println!(
        "  carrier method + crossing:     p50 {:>7} ns  p99 {:>7} ns",
        bridged.0, bridged.1
    );
    println!(
        "  echo RTT, linked carrier:      p50 {:>7} ns  p99 {:>7} ns",
        linked.0, linked.1
    );
    println!(
        "  echo RTT, dropped-in carrier:  p50 {:>7} ns  p99 {:>7} ns",
        dropped.0, dropped.1
    );
    println!(
        "  added per round trip:          p50 {:>7} ns  p99 {:>7} ns  (dropped-in p99 / linked p99 = {:.2})",
        dropped.0.saturating_sub(linked.0),
        dropped.1.saturating_sub(linked.1),
        dropped.1 as f64 / linked.1 as f64
    );
    assert!(
        crossing.0 < 1_000 && crossing.1 < 1_000,
        "the ABI crossing itself is over the #30 budget: {crossing:?}"
    );
    assert!(
        bridged.0 < 1_000 && bridged.1 < 1_000,
        "one carrier method around a crossing is over the #30 budget: {bridged:?}"
    );
    assert!(
        dropped.1 <= 2 * linked.1,
        "the dropped-in echo p99 {} ns is over twice the linked carrier's {} ns",
        dropped.1,
        linked.1
    );
}
