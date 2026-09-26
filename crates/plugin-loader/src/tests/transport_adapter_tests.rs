// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADAPTER'S WITNESS (#2 rule (1), #3 OWNER-LOCKED): a transport admitted over the HOT-tier ABI
//! — linked door or dropped-in door — is, through [`WireTransport`], the host's own
//! [`Transport`], and speaks it exactly as the same wire linked as Rust does.
//!
//! One script runs through the TRAIT against three instances of the both-ways fixture wire: the
//! linked row's own `build` (the Rust transport the root folds today), the adapter over its linked
//! decl, and the adapter over its dropped-in cdylib. It listens and accepts a plain `std::net` peer,
//! drains the frame pump, answers and closes; dials a plain peer, writes, drains, closes; and
//! accepts once more and DETACHES the connection, moving bytes over the detached stream (the path a
//! served listener takes). The three records must be equal, and equal to what the script sent.
//!
//! THE RED ARM, kept: [`an_adapter_over_a_divergent_wire_is_seen_by_the_script`] runs the script over
//! the adapter of a decl whose `write` flips one byte, and requires the record to DIFFER.

use super::*;
use crate::both_ways::{cdylib, dropped, statement, transport_fixture, HOT_FIXTURES};
use crate::transport::link_transport;
use busbar_contract::plugin::TestKernelSeal;
use busbar_contract::transport::dest::UpstreamAddress;
use busbar_contract::{ConfigView, LaneId};
use busbar_plugin::hot::transport::{RawWireOutcome, TransportDecl};
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
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

/// The fixture's decl, as the host's type.
fn fixture_decl() -> *const TransportDecl {
    core::ptr::addr_of!(transport_fixture::hot::TRANSPORT_DECL).cast::<TransportDecl>()
}

/// The fixture wire through the LINKED door, admitted once for the process.
fn linked_row() -> &'static DynTransport {
    static ROW: OnceLock<DynTransport> = OnceLock::new();
    ROW.get_or_init(|| {
        // SAFETY: the fixture's decl is `'static` and laid out as `TransportDecl` (the conformance
        // test pins every offset).
        unsafe { link_transport(fixture_decl(), "linked-wire") }.expect("the linked door admits")
    })
}

/// The fixture wire through the DROPPED-IN door (its cdylib signed into a fresh `plugins/`), admitted
/// once for the process. `None` when the artifact is not built (never under CI).
fn dropped_row() -> Option<&'static DynTransport> {
    static ROW: OnceLock<Option<DynTransport>> = OnceLock::new();
    ROW.get_or_init(|| {
        let krate = HOT_FIXTURES
            .iter()
            .find(|(kind, _)| *kind == "transport")
            .map(|&(_, krate)| krate)?;
        let lib = std::fs::read(cdylib(krate)?).expect("read the transport cdylib");
        let manifest = statement("transport", "wire", "wire", busbar_plugin::ABI_MINOR);
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

fn adapter(row: &'static DynTransport) -> Arc<dyn Transport> {
    Arc::new(WireTransport::build(row, None, &settings()).expect("the wire builds"))
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

/// Everything one instance declared and put on / took off the wire, through the trait.
#[derive(Debug, PartialEq, Eq)]
struct Record {
    key: &'static str,
    kind: Kind,
    composed_over: Option<&'static str>,
    /// Listened: what the pump drained from the peer, and what the peer received back.
    pumped: Vec<u8>,
    answered: Vec<u8>,
    /// Dialled: what the peer received, and what the pump drained back.
    dialled: Vec<u8>,
    dial_pumped: Vec<u8>,
    /// Detached: what the stream read from the peer, and what the peer received back.
    detached_read: Vec<u8>,
    detached_answered: Vec<u8>,
    /// A write on a connection the transport closed.
    write_after_close: Option<TransportError>,
}

const SENT: (u8, usize) = (7, 40_000);
const REPLY: (u8, usize) = (91, 20_001);

async fn pump(t: &dyn Transport, conn: &Conn) -> Vec<u8> {
    let mut frames = t.frames(conn.clone());
    let mut all = Vec::new();
    while let Some(frame) = frames.next().await {
        let (_, frame) = frame.expect("a frame");
        assert_eq!(frame.meta.bytes as usize, frame.bytes.as_slice().len());
        all.extend_from_slice(frame.bytes.as_slice());
    }
    all
}

/// A plain peer that connects to `addr`, sends `sent`, half-closes and reads to the end.
fn near(addr: String, sent: Vec<u8>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&sent).unwrap();
        s.shutdown(Shutdown::Write).unwrap();
        let mut back = Vec::new();
        s.read_to_end(&mut back).unwrap();
        back
    })
}

/// THE SCRIPT, run identically through the trait against every instance.
async fn script(t: Arc<dyn Transport>) -> Record {
    let keys = TransportKeyHandle::keyless();

    // ── listen, accept, drain the pump, answer, close ──
    let listener = t.listen(&Bind, &keys).await.expect("listen");
    let peer = near(listener.local_addr(), payload(SENT.0, SENT.1));
    let conn = t.accept(&listener).await.expect("accept");
    assert!(conn.peer().starts_with("127.0.0.1:"), "{}", conn.peer());
    let pumped = pump(&*t, &conn).await;
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

    // ── dial a plain peer, write, drain what it answers, close ──
    let far = TcpListener::bind("127.0.0.1:0").unwrap();
    let dest = upstream(&far.local_addr().unwrap().to_string());
    let far = std::thread::spawn(move || {
        let (mut s, _) = far.accept().unwrap();
        let mut got = vec![0_u8; SENT.1];
        s.read_exact(&mut got).unwrap();
        s.write_all(&payload(REPLY.0 ^ 0x5a, REPLY.1)).unwrap();
        s.shutdown(Shutdown::Write).unwrap();
        got
    });
    let conn = t.dial(&dest, &keys).await.expect("dial");
    let sent = payload(SENT.0 ^ 0x5a, SENT.1);
    t.write(&conn, StreamId(0), ScratchBytes::new(&sent))
        .await
        .expect("write the request");
    let dial_pumped = pump(&*t, &conn).await;
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
    let mut detached_read = Vec::new();
    io.read_to_end(&mut detached_read).await.expect("read");
    io.write_all(&payload(REPLY.0 ^ 0xff, REPLY.1))
        .await
        .expect("write");
    io.close().await.expect("close");
    drop(io);
    let detached_answered = peer.join().unwrap();

    Record {
        key: t.key(),
        kind: t.kind(),
        composed_over: t.composed_over(),
        pumped,
        answered,
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
        composed_over: None,
        pumped: payload(SENT.0, SENT.1),
        answered: payload(REPLY.0, REPLY.1),
        dialled: payload(SENT.0 ^ 0x5a, SENT.1),
        dial_pumped: payload(REPLY.0 ^ 0x5a, REPLY.1),
        detached_read: payload(SENT.0 ^ 0xff, SENT.1),
        detached_answered: payload(REPLY.0 ^ 0xff, REPLY.1),
        write_after_close: Some(TransportError::Closed),
    }
}

/// THE WITNESS: the linked Rust wire, the adapter over its linked decl and the adapter over its
/// dropped-in cdylib run the script to ONE record, and it is the bytes the script sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_door_speaks_the_trait_alike() {
    let rust = script((transport_fixture::linked::build)(None, &settings())).await;
    assert_eq!(
        rust,
        expected(),
        "the linked Rust wire moves the bytes it is given"
    );
    let linked = script(adapter(linked_row())).await;
    assert_eq!(
        linked, rust,
        "the adapter over the linked decl is the linked wire"
    );
    let Some(row) = dropped_row() else {
        return;
    };
    let dropped = script(adapter(row)).await;
    assert_eq!(
        dropped, rust,
        "the adapter over the dropped-in wire is the linked wire"
    );
}

/// The adapter registers as the linked wire does: the same key, kind and generation, from the row
/// the decl declared.
#[test]
fn the_adapter_is_the_rows_plugin() {
    let rust = (transport_fixture::linked::build)(None, &settings());
    let wire = WireTransport::build(linked_row(), None, &settings()).unwrap();
    assert_eq!(
        (wire.key(), wire.kind(), wire.abi()),
        (rust.key(), rust.kind(), rust.abi())
    );
    assert_eq!(wire.wire().key(), transport_fixture::linked::KEY);
    assert_eq!(
        wire.wire().composes_over(),
        transport_fixture::linked::COMPOSES_OVER
    );
}

/// A wire built over another adapter answers it was composed over that layer, and its arrivals
/// report the stack bottom-first.
#[test]
fn a_wire_built_over_a_wire_names_it() {
    let lower = WireTransport::build(linked_row(), None, &settings()).unwrap();
    let upper = WireTransport::build(linked_row(), Some(&lower), &settings()).unwrap();
    assert_eq!(upper.composed_over(), Some(transport_fixture::linked::KEY));
    let conn = Conn::new(Arc::new(WireConn {
        id: 1,
        peer: "p".into(),
    }));
    assert_eq!(
        upper.arrival(&conn).transport_chain,
        [transport_fixture::linked::KEY; 2]
    );
}

// ── THE RED ARM ─────────────────────────────────────────────────────────────────────────────────

static REAL_WRITE: OnceLock<busbar_plugin::hot::transport::WireWriteFn> = OnceLock::new();

/// A `write` slot that flips the first byte of every write, then writes through the real slot.
extern "C-unwind" fn altering_write(
    state: *mut std::os::raw::c_void,
    conn: u64,
    buf: *const u8,
    len: usize,
) -> RawWireOutcome {
    let real = REAL_WRITE.get().expect("the real write is recorded");
    if buf.is_null() || len == 0 {
        return real(state, conn, buf, len);
    }
    // SAFETY: the host's live `len`-byte range for this call.
    let mut bytes = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
    bytes[0] ^= 0x01;
    real(state, conn, bytes.as_ptr(), bytes.len())
}

/// THE RED ARM, kept: the adapter over a wire whose `write` alters one byte runs the script to a
/// DIFFERENT record, on exactly the legs it wrote — the equality above is one a wrong wire fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_adapter_over_a_divergent_wire_is_seen_by_the_script() {
    static ALTERED: OnceLock<TransportDecl> = OnceLock::new();
    static ROW: OnceLock<DynTransport> = OnceLock::new();
    // SAFETY: the fixture's decl is live; its `write` slot is set.
    let real = unsafe { (*fixture_decl()).write }.expect("the fixture writes");
    let _ = REAL_WRITE.set(real);
    let altered = ALTERED.get_or_init(|| {
        // SAFETY: a byte copy of a live `TransportDecl`-layout value whose every pointer is to the
        // fixture's `'static` data.
        let mut decl = unsafe { core::ptr::read(fixture_decl()) };
        decl.write = Some(altering_write);
        decl
    });
    // SAFETY: `altered` is `'static`, and every range it borrows is the fixture's `'static` data.
    let row = ROW.get_or_init(|| unsafe { link_transport(altered, "altered-wire") }.unwrap());
    let seen = script(adapter(row)).await;
    let honest = expected();
    assert_ne!(
        seen, honest,
        "the script must see a wire that changed a byte"
    );
    assert_ne!(seen.answered, honest.answered);
    assert_ne!(seen.dialled, honest.dialled);
    assert_ne!(seen.detached_answered, honest.detached_answered);
    // What the altered wire only READ is untouched: the difference is where the bytes changed.
    assert_eq!(seen.pumped, honest.pumped);
    assert_eq!(seen.detached_read, honest.detached_read);
}

// ── THE #30 MEASUREMENT ─────────────────────────────────────────────────────────────────────────

fn percentiles(mut samples: Vec<u128>) -> (u128, u128) {
    samples.sort_unstable();
    (
        samples[samples.len() / 2],
        samples[samples.len() * 99 / 100],
    )
}

/// One-byte ping-pong over a detached stream against an echo peer: nanoseconds per round trip.
async fn echo_rtt(t: Arc<dyn Transport>, rounds: usize) -> Vec<u128> {
    let listener = t
        .listen(&Bind, &TransportKeyHandle::keyless())
        .await
        .unwrap();
    let addr = listener.local_addr();
    let echo = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_nodelay(true).unwrap();
        let mut b = [0_u8; 1];
        while s.read_exact(&mut b).is_ok() {
            if s.write_all(&b).is_err() {
                break;
            }
        }
    });
    let conn = t.accept(&listener).await.unwrap();
    let mut io = t.detach(&conn).unwrap().into_io();
    let mut b = [0_u8; 1];
    let mut out = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let t0 = std::time::Instant::now();
        io.write_all(&[42]).await.unwrap();
        io.flush().await.unwrap();
        io.read_exact(&mut b).await.unwrap();
        out.push(t0.elapsed().as_nanos());
    }
    drop(io);
    echo.join().unwrap();
    out
}

/// #30 (HOT lane, < 1 µs per crossing): the DROPPED-IN path's added latency, measured at three
/// depths and printed. Release build: `cargo test --release -p busbar-plugin-loader
/// transport_adapter -- --ignored --nocapture`.
///
/// 1. the ABI crossing itself (a slot call answered without I/O) — asserted under the budget;
/// 2. the adapter's async bridge around one crossing (the blocking-pool handoff every trait method
///    pays for a BLOCKING slot) — reported;
/// 3. a one-byte echo round trip over a detached stream, adapter over the dropped-in cdylib against
///    the linked Rust wire (one write and one read crossing each) — reported as the difference.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "perf measurement; run in release with --ignored --nocapture"]
async fn the_adapters_added_latency_per_crossing_is_measured() {
    let Some(row) = dropped_row() else {
        return;
    };
    let wire = WireTransport::build(row, None, &settings()).unwrap();
    let hosted = Arc::clone(&wire.hosted);

    let crossing = percentiles(
        (0..20_000)
            .map(|_| {
                let t0 = std::time::Instant::now();
                let _ = std::hint::black_box(hosted.built.close(std::hint::black_box(u64::MAX)));
                t0.elapsed().as_nanos()
            })
            .collect(),
    );
    let mut bridged = Vec::with_capacity(20_000);
    for _ in 0..20_000 {
        let t0 = std::time::Instant::now();
        let _ = off(&hosted, |b| b.close(u64::MAX)).await;
        bridged.push(t0.elapsed().as_nanos());
    }
    let bridged = percentiles(bridged);
    let rust =
        percentiles(echo_rtt((transport_fixture::linked::build)(None, &settings()), 5_000).await);
    let dropped = percentiles(echo_rtt(adapter(row), 5_000).await);
    println!(
        "#30 transport, dropped-in path (budget {} ns per crossing):",
        1_000
    );
    println!(
        "  ABI crossing alone:           p50 {:>7} ns  p99 {:>7} ns",
        crossing.0, crossing.1
    );
    println!(
        "  adapter bridge + crossing:    p50 {:>7} ns  p99 {:>7} ns",
        bridged.0, bridged.1
    );
    println!(
        "  echo RTT, linked Rust wire:   p50 {:>7} ns  p99 {:>7} ns",
        rust.0, rust.1
    );
    println!(
        "  echo RTT, dropped-in adapter: p50 {:>7} ns  p99 {:>7} ns",
        dropped.0, dropped.1
    );
    println!(
        "  added per round trip:         p50 {:>7} ns  (two crossings: one write, one read)",
        dropped.0.saturating_sub(rust.0)
    );
    assert!(
        crossing.0 < 1_000 && crossing.1 < 1_000,
        "the ABI crossing itself is over the #30 budget: {crossing:?}"
    );
}
