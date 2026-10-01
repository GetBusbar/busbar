// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STACK'S WITNESS (#2 rule (1), #3; TRANSPORT-STACK): a carrier — linked, or admitted over the
//! HOT-tier ABI — stacked as the host's connection by [`WireTransport`], speaks exactly as the same
//! carrier linked as Rust does. The subject is the test-only `mem` carrier ([`super::mem_carrier`]).
//!
//! One script runs against two stacks: the linked Rust carrier itself, and the loader's decl-backed
//! carrier over its decl — built by [`WireTransport::build`], the composition root's path for a
//! dropped-in row. It listens and accepts a peer through a separate linked instance, drains the frame
//! pump, answers and closes; dials a peer, writes, drains, closes; and accepts once more and DETACHES
//! the connection, moving bytes over the detached stream (the path a served listener takes). The two
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
//! a line framer over the carrier, and moves a connection's byte stream — with the half line the
//! framer held — to a second stack that adopts it.

use super::mem_carrier::{self, decl, decl_copy, slots, KEY};
use crate::transport::{host_wake, link_transport, DynTransport, WakeToken};
use crate::transport_adapter::WireTransport;
use busbar_contract::abi::hot::transport::{CarrierSlots, RawWireOutcome, TransportDecl, NO_WAKER};
use busbar_contract::plugin::TestKernelSeal;
use busbar_contract::transport::wire::{CloseReason, TransportError};
use busbar_contract::transport::{
    BytesOut, ConnFacts, Framed, Framer, FramerOut, Located, Side, Transport, TransportRow,
    TransportSettings, UpstreamAddress,
};
use busbar_contract::{
    AbiVersion, ConfigView, DestinationFacts, Kind, LaneId, Plugin, ScratchBytes, StreamId,
    TransportConfigView, TransportKeyHandle, VerifiedDestination,
};
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// How long one script may take before the test fails instead of hanging.
const PATIENCE: Duration = Duration::from_secs(60);

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
        Some("mem:0")
    }
}

/// The carrier through its decl, admitted once for the process.
fn linked_row() -> &'static DynTransport {
    static ROW: OnceLock<DynTransport> = OnceLock::new();
    ROW.get_or_init(|| {
        // SAFETY: the decl is `'static` and laid out as `TransportDecl`.
        unsafe { link_transport(decl(), "linked-mem") }.expect("the linked door admits")
    })
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
        mem_carrier::ROW,
        Some(mem_carrier::carrier()),
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
            transport: KEY,
            address: UpstreamAddress::socket(crate::intern_name(addr)),
            lane: LaneId::new("test"),
        },
        KEY,
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
async fn pump(
    t: &WireTransport,
    conn: &busbar_contract::transport::Conn,
    upto: Option<usize>,
) -> Vec<u8> {
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
        let peer = mem_carrier::dial(&addr);
        peer.write_all(&sent);
        peer.read_to_end()
    })
}

/// THE SCRIPT, run identically against every stack, failing rather than hanging.
async fn script(t: Arc<WireTransport>) -> Record {
    tokio::time::timeout(PATIENCE, script_body(t))
        .await
        .expect("the script finishes")
}

async fn script_body(t: Arc<WireTransport>) -> Record {
    let keys = TransportKeyHandle::keyless();

    // ── listen, accept, drain the pump, answer, close ──
    let listener = t.listen(&Bind, &keys).await.expect("listen");
    let peer = near(listener.local_addr(), payload(SENT.0, SENT.1));
    let conn = t.accept(&listener).await.expect("accept");
    assert!(conn.peer().starts_with("mem:"), "{}", conn.peer());
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
    let far = mem_carrier::listen();
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
        key: KEY,
        kind: Kind::Transport,
        abi: busbar_contract::transport::TRANSPORT_ABI,
        composed_over: None,
        pumped: payload(SENT.0, SENT.1),
        answered: payload(REPLY.0, REPLY.1),
        chain: vec![KEY],
        has_port: true,
        dialled: payload(SENT.0 ^ 0x5a, SENT.1),
        dial_pumped: payload(REPLY.0 ^ 0x5a, REPLY.1),
        detached_read: payload(SENT.0 ^ 0xff, SENT.1),
        detached_answered: payload(REPLY.0 ^ 0xff, REPLY.1),
        write_after_close: Some(TransportError::Closed),
    }
}

/// THE WITNESS: the linked Rust carrier and the decl-backed carrier over its decl, each stacked, run
/// the script to ONE record, and it is the bytes the script sent.
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
        "the carrier over its decl is the linked carrier"
    );
}

/// The decl-backed carrier's row is the linked carrier's row, constant for constant.
#[test]
fn a_decl_backed_carrier_presents_the_linked_row() {
    let wire = WireTransport::build(linked_row(), None, &settings()).unwrap();
    assert_eq!(*wire.row(), mem_carrier::ROW);
    assert_eq!(wire.key(), KEY);
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
    let real = slots().poll_write.expect("the carrier writes");
    if buf.is_null() || len == 0 {
        return real(state, conn, token, buf, len, out);
    }
    // SAFETY: the host's live `len`-byte range for this call.
    let mut bytes = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
    bytes[0] ^= 0x01;
    real(state, conn, token, bytes.as_ptr(), bytes.len(), out)
}

/// A `'static` copy of the decl whose carrier table is `slots`.
fn decl_with(slots: &'static CarrierSlots) -> TransportDecl {
    TransportDecl {
        carrier: slots,
        ..decl_copy()
    }
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
        ..*slots()
    });
    let altered = ALTERED.get_or_init(|| decl_with(slots));
    // SAFETY: `altered` is `'static`, and every range it borrows is `'static` data.
    let row = ROW.get_or_init(|| unsafe { link_transport(altered, "altered-mem") }.unwrap());
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
    slots().poll_accept.unwrap()(state, listener, token, peer, cap, peer_len, conn)
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
    slots().poll_read.unwrap()(state, conn, token, buf, cap, out)
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
    slots().poll_write.unwrap()(state, conn, token, buf, len, out)
}

extern "C-unwind" fn recording_flush(
    state: *mut std::os::raw::c_void,
    conn: u64,
    token: u64,
) -> RawWireOutcome {
    crossed();
    slots().poll_flush.unwrap()(state, conn, token)
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
        ..*slots()
    });
    let recording = RECORDING.get_or_init(|| decl_with(slots));
    // SAFETY: `recording` is `'static`, and every range it borrows is `'static` data.
    let row = ROW.get_or_init(|| unsafe { link_transport(recording, "recording-mem") }.unwrap());
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
    let token = WakeToken::new();
    token.register(&waker);
    host_wake(token.id());
    assert_eq!(count.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    let stale = token.id();
    drop(token);
    let reused = WakeToken::new();
    reused.register(&waker);
    assert_ne!(reused.id(), stale, "a reused slot is a new token");
    host_wake(stale);
    host_wake(NO_WAKER);
    host_wake(u64::MAX);
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

impl Framer for Lines {
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
        _: &mut dyn FramerOut,
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
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        let mut all = self.held.lock().unwrap();
        let held = all.get_mut(&state).ok_or(TransportError::Closed)?;
        held.extend_from_slice(bytes);
        while let Some(at) = held.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = held.drain(..=at).collect();
            out.frame(Framed::plain(StreamId(0), &line[..at], true));
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
        out: &mut dyn FramerOut,
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
        out: &mut dyn BytesOut,
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
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        self.emit(state, StreamId(0), bytes, true, out)
    }
    fn close(&self, state: u64, _: CloseReason, out: &mut dyn FramerOut) {
        if self.held.lock().unwrap().remove(&state).is_some() {
            out.send(b"bye\n");
        }
    }
    fn detach(&self, state: u64, out: &mut dyn BytesOut) -> Result<(), TransportError> {
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
        out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError> {
        let state = self.open(side, "", facts, out)?;
        self.ingest(state, leftover, false, out)?;
        Ok(state)
    }
    fn tick(&self, _: u64, _: &mut dyn FramerOut) -> Result<(), TransportError> {
        Ok(())
    }
}

/// The row of a framer composed over the carrier.
fn lines_row() -> TransportRow {
    TransportRow {
        key: "lines",
        composes_over: &[KEY],
        ..mem_carrier::ROW
    }
}

/// A framer stacked over a carrier frames its bytes (a line per frame, what the framer answers going
/// out), names the layer it stands on, and closes with the framer's own close bytes. On an upgrade
/// the byte stream MOVES: the source stack gives up the connection with the half line its framer
/// held in front of it, and the stack that adopts it frames that half line as the start of its first
/// frame — nothing lost, nothing read twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_framer_stacks_over_a_carrier_and_the_upgrade_moves_its_bytes() {
    tokio::time::timeout(PATIENCE, framer_over_carrier())
        .await
        .expect("the upgrade finishes");
}

async fn framer_over_carrier() {
    let carrier = mem_carrier::carrier();
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
    assert_eq!(stack.composed_over(), Some(KEY));
    let keys = TransportKeyHandle::keyless();
    let listener = stack.listen(&Bind, &keys).await.unwrap();
    let addr = listener.local_addr();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let peer = std::thread::spawn(move || {
        let peer = mem_carrier::dial(&addr);
        peer.write_all(b"one\ntw");
        ready_rx.recv().unwrap();
        peer.write_all(b"o\n");
        peer.read_to_end()
    });
    let conn = stack.accept(&listener).await.unwrap();
    assert_eq!(stack.arrival(&conn).transport_chain, [KEY, "lines"]);
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
