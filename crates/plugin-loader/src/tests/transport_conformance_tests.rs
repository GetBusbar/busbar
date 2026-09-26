// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BOTH-WAYS CONFORMANCE for `kind: transport` (#3, OWNER-LOCKED: a transport is swappable, compiled
//! in OR dropped in over the ABI; #30: it rides the HOT lane; #2 rule (1): one contract, one loading
//! path). This replaces the old refusal that called a transport "in-tree only".
//!
//! The fixture is a REAL shipped wire, reached by KIND (`[package.metadata.busbar.both-ways]`),
//! built `["rlib", "cdylib"]`. Its rlib's decl is admitted through [`link_transport`] (the linked
//! door); its cdylib is signed first-party into a fresh `plugins/` directory, scanned, and opened
//! through [`PluginRegistry::open_transport`](crate::PluginRegistry::open_transport) (the dropped-in
//! door). Both rows run ONE admission ([`assemble`]).
//!
//! THE FOLD. Each door then runs the same script against real sockets whose far end is a plain
//! `std::net` peer — dial it and exchange bytes, listen for it and exchange bytes — and records what
//! the transport declared and what crossed the wire in each direction. The two folds must be equal,
//! and each must equal the bytes the script sent: the bytes on the wire are identical whichever door
//! the transport came in by, and identical to what was asked for.
//!
//! THE RED ARM, kept: [`a_divergent_wire_is_seen_by_the_fold`] runs the fold over a decl whose `write`
//! slot alters one byte and requires the fold to DIFFER — the comparison above is one that can fail.

use super::*;
use crate::both_ways::{cdylib, dropped, statement, transport_fixture, HOT_FIXTURES};
use crate::sign::{validate_structure, HookNeeds, Manifest};
use busbar_plugin::hot::transport::{RawWireOutcome, WireOutcome, WireSettings};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};

/// The fixture's decl, as the host's type: the address its `busbar_transport_decl` returns.
fn linked_decl() -> *const TransportDecl {
    core::ptr::addr_of!(transport_fixture::hot::TRANSPORT_DECL).cast::<TransportDecl>()
}

/// THE LINKED DOOR.
fn linked(display: &str) -> DynTransport {
    // SAFETY: the fixture's decl is a `'static` image-owned decl laid out as `TransportDecl`
    // (`the_fixture_restates_the_host_layout` pins every offset).
    unsafe { link_transport(linked_decl(), display) }.expect("the linked door admits the transport")
}

/// The fixture's cdylib crate name.
fn fixture_crate() -> &'static str {
    HOT_FIXTURES
        .iter()
        .find(|(kind, _)| *kind == "transport")
        .map(|&(_, krate)| krate)
        .expect("a `transport` row in [package.metadata.busbar.both-ways]")
}

/// THE DROPPED-IN DOOR: the cdylib signed first-party, scanned and opened by name. `None` when the
/// artifact is not built (never under CI — `cdylib` refuses to skip there).
fn dropped_in(tag: &str) -> Option<DynTransport> {
    let lib = std::fs::read(cdylib(fixture_crate())?).expect("read the transport cdylib");
    let manifest = statement("transport", "wire", "wire", busbar_plugin::ABI_MINOR);
    let registry = dropped(tag, manifest, &lib);
    Some(
        registry
            .open_transport("wire")
            .expect("the dropped-in door opens the transport"),
    )
}

/// The deployment's settings, as the linked row takes them, handed to the decl's `build`.
fn settings() -> WireSettings {
    wire_settings(&busbar_contract::transport::TransportSettings::default())
}

/// Bytes that exercise every value and outrun both the fixture's read chunk and the read buffer
/// below, so a frame is handed out across several reads.
fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Read `conn` to its clean end through `built`, in reads no longer than `chunk`.
fn drain(built: &BuiltTransport<'_>, conn: u64, chunk: usize) -> Vec<u8> {
    let mut all = Vec::new();
    let mut buf = vec![0_u8; chunk];
    loop {
        match built.read(conn, &mut buf) {
            Ok(0) => return all,
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(e) => panic!("read failed mid-stream: {e:?}"),
        }
    }
}

/// Everything one door's transport declared and put on / took off the wire.
#[derive(Debug, PartialEq, Eq)]
struct Fold {
    key: String,
    composes_over: Vec<String>,
    /// Dialled out: what the peer received, and what the transport read back.
    dial_peer_saw: Vec<u8>,
    dial_read_back: Vec<u8>,
    /// Listened: what the transport read from the peer, and what the peer received back.
    accept_read: Vec<u8>,
    accept_peer_saw: Vec<u8>,
    /// What an unknown connection answers on write and close.
    unknown_write: WireOutcome,
    unknown_close: WireOutcome,
}

const SENT: (u8, usize) = (7, 40_000);
const REPLY: (u8, usize) = (91, 20_001);

/// THE SCRIPT, run identically against either door.
fn fold(t: &DynTransport) -> Fold {
    let built = t.build(None, &settings()).expect("the transport builds");

    // ── dial a plain peer, send, read its reply to the end ──
    let peer = TcpListener::bind("127.0.0.1:0").unwrap();
    let authority = peer.local_addr().unwrap().to_string();
    let far = std::thread::spawn(move || {
        let (mut s, _) = peer.accept().unwrap();
        let mut got = vec![0_u8; SENT.1];
        s.read_exact(&mut got).unwrap();
        s.write_all(&payload(REPLY.0, REPLY.1)).unwrap();
        s.shutdown(Shutdown::Write).unwrap();
        got
    });
    let conn = built.dial(&authority, None).expect("dial");
    built
        .write(conn, &payload(SENT.0, SENT.1))
        .expect("write the request");
    let dial_read_back = drain(&built, conn, 1000);
    built.close(conn).expect("close");
    let dial_peer_saw = far.join().unwrap();

    // ── listen, take a plain peer's bytes to their end, answer, close ──
    let (listener, addr) = built.listen("127.0.0.1:0", None).expect("listen");
    let near = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&payload(SENT.0 ^ 0xff, SENT.1)).unwrap();
        s.shutdown(Shutdown::Write).unwrap();
        let mut back = Vec::new();
        s.read_to_end(&mut back).unwrap();
        back
    });
    let (conn, peer_addr) = built.accept(listener).expect("accept");
    assert!(peer_addr.starts_with("127.0.0.1:"), "{peer_addr}");
    let accept_read = drain(&built, conn, 777);
    built
        .write(conn, &payload(REPLY.0 ^ 0xff, REPLY.1))
        .expect("write the answer");
    built.close(conn).expect("close");
    let accept_peer_saw = near.join().unwrap();

    Fold {
        key: t.key().to_string(),
        composes_over: t.composes_over().to_vec(),
        dial_peer_saw,
        dial_read_back,
        accept_read,
        accept_peer_saw,
        unknown_write: built.write(u64::MAX, b"x").unwrap_err(),
        unknown_close: built
            .close(u64::MAX)
            .map_or_else(|e| e, |()| WireOutcome::Ok),
    }
}

/// What the script sent, byte for byte, on each leg.
fn expected(key: &str, composes_over: &[String]) -> Fold {
    Fold {
        key: key.to_string(),
        composes_over: composes_over.to_vec(),
        dial_peer_saw: payload(SENT.0, SENT.1),
        dial_read_back: payload(REPLY.0, REPLY.1),
        accept_read: payload(SENT.0 ^ 0xff, SENT.1),
        accept_peer_saw: payload(REPLY.0 ^ 0xff, REPLY.1),
        unknown_write: WireOutcome::Closed,
        unknown_close: WireOutcome::Ok,
    }
}

/// ONE ROW, WHICHEVER DOOR: the key and the layers it composes over, as the linked row declares
/// them, are what both doors admit.
#[test]
fn a_linked_and_a_dropped_in_transport_are_one_row() {
    let linked = linked("linked-wire");
    // The decl's row IS the linked row the composition root folds (K2e's `linked` module): the same
    // key, the same layers in the same order.
    assert_eq!(linked.key(), transport_fixture::linked::KEY);
    assert_eq!(
        linked.composes_over(),
        transport_fixture::linked::COMPOSES_OVER
    );
    assert_eq!(linked.session(), transport_fixture::linked::SESSION);
    let Some(dropped) = dropped_in("transport-row") else {
        return;
    };
    assert_eq!(dropped.key(), linked.key());
    assert_eq!(dropped.composes_over(), linked.composes_over());
    assert_eq!(dropped.session(), linked.session());
    // Two images, two decls: the dropped-in one is not the linked one read twice.
    assert_ne!(dropped.decl(), linked.decl());
}

/// THE WITNESS: both doors run the script and fold to the SAME record, and that record is the bytes
/// the script put on the wire — identical on the wire, whichever door.
#[test]
fn both_doors_put_the_same_bytes_on_the_wire() {
    let linked = linked("linked-wire");
    let linked_fold = fold(&linked);
    assert_eq!(
        linked_fold,
        expected(linked.key(), linked.composes_over()),
        "the linked transport moves exactly the bytes it was given"
    );
    let Some(dropped) = dropped_in("transport-fold") else {
        return;
    };
    let dropped_fold = fold(&dropped);
    assert_eq!(
        dropped_fold, linked_fold,
        "a dropped-in transport and the same transport linked are observationally one transport"
    );
}

// ── THE RED ARM ─────────────────────────────────────────────────────────────────────────────────

/// The fixture's real `write`, for the altering slot below to forward to.
static REAL_WRITE: std::sync::OnceLock<busbar_plugin::hot::transport::WireWriteFn> =
    std::sync::OnceLock::new();

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

/// A copy of the fixture's decl, to alter one field of.
fn decl_copy() -> TransportDecl {
    // SAFETY: the fixture's decl is a live `TransportDecl`-layout value; copying its bytes out
    // takes nothing it owns (every pointer in it is to `'static` image data).
    unsafe { core::ptr::read(linked_decl()) }
}

/// THE RED ARM, kept: a transport whose `write` alters one byte folds DIFFERENTLY, on exactly the
/// legs that write — so the equality the witness asserts is one a wrong wire fails.
#[test]
fn a_divergent_wire_is_seen_by_the_fold() {
    // SAFETY: the fixture's decl is live; its `write` slot is set.
    let real = unsafe { (*linked_decl()).write }.expect("the fixture writes");
    let _ = REAL_WRITE.set(real);
    let mut altered = decl_copy();
    altered.write = Some(altering_write);
    // SAFETY: `altered` is a copy of a valid decl that outlives `divergent` (both live to the end of
    // this test), and every range it borrows is the fixture's `'static` data.
    let divergent = unsafe { link_transport(&altered, "altered-wire") }.unwrap();
    let honest = fold(&linked("linked-wire"));
    let seen = fold(&divergent);
    assert_ne!(seen, honest, "the fold must see a wire that changed a byte");
    assert_ne!(seen.dial_peer_saw, honest.dial_peer_saw);
    assert_ne!(seen.accept_peer_saw, honest.accept_peer_saw);
    // What the altered wire only READ is untouched: the difference is where the bytes changed.
    assert_eq!(seen.accept_read, honest.accept_read);
    assert_eq!(seen.key, honest.key);
}

// ── THE ADMISSION ───────────────────────────────────────────────────────────────────────────────

fn manifest(kind: &str) -> Manifest {
    Manifest {
        name: "my-transport".to_string(),
        alias: "my-transport".to_string(),
        kind: kind.to_string(),
        version: "1.0.0".to_string(),
        publisher: "acme".to_string(),
        abi_version: busbar_plugin::ABI_MINOR,
        sha256: crate::sign::sha256_hex(b"lib"),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: HookNeeds::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
    }
}

/// A `kind: transport` manifest passes the structural gate on the airlock-minor axis, floored at
/// the first minor with a transport decl; an unknown kind is still refused with the established
/// prefix.
#[test]
fn a_transport_manifest_is_admitted_on_the_airlock_axis() {
    assert_eq!(
        crate::supported_abi("transport"),
        &[
            busbar_plugin::hot::TRANSPORT_DECL_MINOR,
            busbar_plugin::ABI_MINOR
        ]
    );
    validate_structure(&manifest("transport"), b"lib", &crate::supported_abi, "")
        .expect("a transport is a kind the loader admits");
    let mut old = manifest("transport");
    old.abi_version = busbar_plugin::hot::TRANSPORT_DECL_MINOR - 1;
    assert!(
        validate_structure(&old, b"lib", &crate::supported_abi, "").is_err(),
        "a minor with no transport decl has no transport surface to speak"
    );
    let err = validate_structure(&manifest("gizmo"), b"lib", &crate::supported_abi, "")
        .expect_err("an unknown kind is refused");
    assert!(
        err.starts_with("manifest kind 'gizmo' is not one of"),
        "{err}"
    );
}

/// The admission refuses a decl it cannot trust, on either door: null, a foreign preamble, a minor
/// that predates the transport decl, a size that does not reach its own slots and declaration, a
/// size past this build's, a session flag that is neither 0 nor 1, and a keyless row.
#[test]
fn the_admission_refuses_a_decl_it_cannot_trust() {
    // SAFETY (every `link_transport` below): null is refused before any read; each other decl is
    // a live local copy of the valid fixture decl with one header field altered, refused before
    // anything outlives it; its borrowed ranges are the fixture's own `'static` data.
    let null = unsafe { link_transport(core::ptr::null(), "null") }.unwrap_err();
    assert!(null.contains("null decl"), "{null}");

    let refuse = |edit: fn(&mut TransportDecl), needle: &str| {
        let mut copy = decl_copy();
        edit(&mut copy);
        let err = unsafe { link_transport(&copy, "edited") }.unwrap_err();
        assert!(err.contains(needle), "expected `{needle}` in: {err}");
    };
    refuse(|d| d.abi.magic ^= 1, "BadMagic");
    refuse(|d| d.abi.abi_major += 1, "MajorMismatch");
    refuse(
        |d| d.abi.abi_minor = busbar_plugin::hot::TRANSPORT_DECL_MINOR - 1,
        "before the transport decl existed",
    );
    refuse(
        |d| d.size = core::mem::offset_of!(TransportDecl, session) as u32,
        "does not reach its own slots and declaration",
    );
    refuse(
        |d| d.size = core::mem::offset_of!(TransportDecl, close) as u32,
        "does not reach its own slots and declaration",
    );
    refuse(|d| d.session = 2, "declares session flag 2");
    refuse(|d| d.size += 8, "exceeding this build's own");
    refuse(|d| d.key = DeclStr::NONE, "declares no key");
    refuse(
        |d| {
            d.composes_over_ptr = core::ptr::null();
            d.composes_over_len = 1;
        },
        "cannot back",
    );
}

/// A LAYOUT, NOT A CRATE (#84): the fixture restates the published layout instead of linking the
/// crate that defines it, so this pins the restatement to the host's own — every offset, the size,
/// the airlock constants, the handshake and every outcome byte. A drift here is a misread there.
#[test]
fn the_fixture_restates_the_host_layout() {
    use busbar_plugin::hot::transport::TransportDecl as Host;
    use transport_fixture::hot::layout::{self, TransportDecl as Restated};
    macro_rules! same {
        ($($f:ident),*) => {$(
            assert_eq!(
                core::mem::offset_of!(Restated, $f),
                core::mem::offset_of!(Host, $f),
                stringify!($f)
            );
        )*};
    }
    same!(
        abi,
        size,
        version,
        key,
        composes_over_ptr,
        composes_over_len,
        build,
        listen,
        accept,
        dial,
        read,
        write,
        close,
        session
    );
    assert_eq!(
        core::mem::size_of::<Restated>(),
        core::mem::size_of::<Host>()
    );
    assert_eq!(layout::ABI_MAGIC, busbar_plugin::ABI_MAGIC);
    assert_eq!(layout::ABI_MAJOR, busbar_plugin::ABI_MAJOR);
    assert!(
        (busbar_plugin::hot::TRANSPORT_DECL_MINOR..=busbar_plugin::ABI_MINOR)
            .contains(&layout::ABI_MINOR)
    );
    assert_eq!(
        layout::HANDSHAKE_VERSION,
        busbar_plugin::cold::TRANSPORT_VERSION
    );
    for (byte, outcome) in [
        (layout::outcome::OK, WireOutcome::Ok),
        (layout::outcome::REFUSED, WireOutcome::Refused),
        (layout::outcome::TIMEOUT, WireOutcome::Timeout),
        (layout::outcome::RESET, WireOutcome::Reset),
        (layout::outcome::CLOSED, WireOutcome::Closed),
        (
            layout::outcome::HANDSHAKE_FAILED,
            WireOutcome::HandshakeFailed,
        ),
        (
            layout::outcome::KEY_UNAVAILABLE,
            WireOutcome::KeyUnavailable,
        ),
        (
            layout::outcome::ADDRESS_REFUSED,
            WireOutcome::AddressRefused,
        ),
        (layout::outcome::BACKPRESSURE, WireOutcome::Backpressure),
        (layout::outcome::FRAMING, WireOutcome::Framing),
        (
            layout::outcome::HANDOFF_MISMATCH,
            WireOutcome::HandoffMismatch,
        ),
        (layout::outcome::FAULT, WireOutcome::Fault),
    ] {
        assert_eq!(RawWireOutcome(byte).outcome(), outcome);
    }
}

/// THE HOT-LANE BUDGET (#30: < 1 µs per dispatch), measured on the dropped-in door: one crossing
/// into the dlopened image and back — the sized slot read, the guarded indirect call, the
/// transport's own handle lookup — timed against the budget at the median and the 99th percentile.
/// Ignored by default (a timing claim belongs to an optimised build on a quiet machine); run with
/// `cargo test --release -p busbar-plugin-loader transport -- --ignored --nocapture`.
#[test]
#[ignore = "timing: run under --release on a quiet machine"]
fn a_hot_lane_crossing_is_under_a_microsecond() {
    let Some(dropped) = dropped_in("transport-perf") else {
        return;
    };
    let built = dropped.build(None, &settings()).unwrap();
    let mut samples: Vec<u128> = (0..20_000)
        .map(|_| {
            let t = std::time::Instant::now();
            let _ = std::hint::black_box(built.close(std::hint::black_box(u64::MAX)));
            t.elapsed().as_nanos()
        })
        .collect();
    samples.sort_unstable();
    let (p50, p99) = (
        samples[samples.len() / 2],
        samples[samples.len() * 99 / 100],
    );
    println!("transport HOT-lane crossing: p50 {p50} ns, p99 {p99} ns");
    assert!(p50 < 1_000 && p99 < 1_000, "p50 {p50} ns, p99 {p99} ns");
}

/// ONE RESOLUTION OF THE LIMITS, BOTH DOORS: every field of the `TransportSettings` a linked row's
/// `build` reads reaches the decl's `build` as the same value (distinct values, so a swapped pair
/// cannot pass).
#[test]
fn the_linked_rows_settings_reach_the_decl_field_for_field() {
    let s = busbar_contract::transport::TransportSettings {
        pool_max_idle_per_host: 3,
        pool_idle_timeout_secs: 5,
        upstream_http1_only: true,
        upstream_h2_prior_knowledge: false,
        request_body_max_bytes: 7,
        response_body_max_bytes: 11,
        request_timeout_secs: 13,
    };
    let w = wire_settings(&s);
    assert_eq!(w.size as usize, core::mem::size_of::<WireSettings>());
    assert_eq!(
        (
            w.pool_max_idle_per_host,
            w.pool_idle_timeout_secs,
            w.upstream_http1_only,
            w.upstream_h2_prior_knowledge,
            w.request_body_max_bytes,
            w.response_body_max_bytes,
            w.request_timeout_secs,
        ),
        (3, 5, 1, 0, 7, 11, 13)
    );
}
