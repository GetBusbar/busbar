// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BOTH-WAYS CONFORMANCE for `kind: transport` (#3: a transport is swappable, compiled in OR dropped
//! in over the ABI; #30: it rides the HOT lane; #2 rule (1): one contract, one loading path;
//! TRANSPORT-STACK: the HOT decl is the carrier/framer traits lowered one slot per method).
//!
//! The fixture is a REAL shipped carrier, reached by KIND (`[package.metadata.busbar.both-ways]`),
//! built `["rlib", "cdylib"]`. Its rlib's carrier (`linked::carrier`) is the LINKED carrier, driven as the contract's
//! [`Carrier`] directly; its decl (the contract's `export_carrier!` lowering of the same type) is
//! admitted through [`link_transport`]; and its cdylib is signed first-party into a fresh `plugins/`
//! directory, scanned, and opened through
//! [`PluginRegistry::open_transport`](crate::PluginRegistry::open_transport) (the dropped-in door).
//! Every decl runs ONE admission ([`assemble`]).
//!
//! THE FOLD. Each carrier runs the same script through the SAME trait methods, against real
//! connections whose far end is a peer through busbar's own linked carrier (a separate instance) —
//! dial it and exchange bytes, listen for it and exchange bytes — and records what crossed the wire in each direction. The folds must be equal, and each
//! must equal the bytes the script sent: the bytes on the wire are identical whichever door the
//! carrier came in by, and identical to what was asked for.
//!
//! THE RED ARM, kept: [`a_divergent_carrier_is_seen_by_the_fold`] runs the fold over a decl whose
//! `poll_write` slot alters one byte and requires the fold to DIFFER.

use super::*;
use crate::both_ways::{cdylib, dropped, statement, transport_fixture, HOT_FIXTURES};
use crate::carrier_peer::{self, wait};
use crate::sign::{validate_structure, HookNeeds, Manifest};
use busbar_contract::abi::hot::transport::{CarrierSlots, DeclClaim, FramerSlots};
use busbar_contract::transport::wire::StatusAt;
use std::sync::OnceLock;

/// Offer every one of `bytes` to `conn`, then flush.
fn write_all(c: &dyn Carrier, conn: u64, bytes: &[u8]) -> Result<(), TransportError> {
    let mut at = 0;
    while at < bytes.len() {
        at += wait(|cx| c.poll_write(conn, cx, &bytes[at..]))?;
    }
    wait(|cx| c.poll_flush(conn, cx))
}

/// The fixture carrier's decl.
fn fixture_decl() -> &'static TransportDecl {
    &transport_fixture::exports::TRANSPORT_DECL
}

/// The fixture's cdylib crate name.
fn fixture_crate() -> &'static str {
    HOT_FIXTURES
        .iter()
        .find(|(kind, _)| *kind == "transport")
        .map(|&(_, krate)| krate)
        .expect("a `transport` row in [package.metadata.busbar.both-ways]")
}

/// A decl admitted through the linked door, once for the process per decl.
fn admitted(decl: &'static TransportDecl, display: &str) -> &'static DynTransport {
    static ROWS: Mutex<Vec<(usize, &'static DynTransport)>> = Mutex::new(Vec::new());
    let key = decl as *const TransportDecl as usize;
    let mut rows = ROWS.lock().unwrap();
    if let Some((_, row)) = rows.iter().find(|(k, _)| *k == key) {
        return row;
    }
    // SAFETY: `decl` is `'static` and laid out as `TransportDecl`, borrowing `'static` data.
    let row: &'static DynTransport = Box::leak(Box::new(
        unsafe { link_transport(decl, display) }.expect("admitted"),
    ));
    rows.push((key, row));
    row
}

/// The dropped-in door's row: the cdylib signed first-party, scanned and opened by name, once for the
/// process. `None` when the artifact is not built (never under CI — `cdylib` refuses to skip there).
fn dropped_in() -> Option<&'static DynTransport> {
    static ROW: OnceLock<Option<DynTransport>> = OnceLock::new();
    ROW.get_or_init(|| {
        let lib = std::fs::read(cdylib(fixture_crate())?).expect("read the transport cdylib");
        let manifest = statement("transport", "wire", "wire", busbar_contract::abi::ABI_MINOR);
        Some(
            dropped("transport-row", manifest, &lib)
                .open_transport("wire")
                .expect("the dropped-in door opens the transport"),
        )
    })
    .as_ref()
}

/// A decl row's carrier, built.
fn carrier_of(row: &'static DynTransport) -> Arc<dyn Carrier> {
    match row
        .build(&wire_settings(&TransportSettings::default()))
        .expect("the carrier builds")
    {
        Built::Carrier(c) => c,
        Built::Framer(_) => panic!("the fixture is a carrier"),
    }
}

/// Bytes that exercise every value and outrun both the fixture's read chunk and the read buffer
/// below, so a stream is handed out across several reads.
fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Read exactly `n` bytes of `conn`, in reads no longer than `chunk`.
fn read_exact(c: &dyn Carrier, conn: u64, n: usize, chunk: usize) -> Vec<u8> {
    let mut all = Vec::with_capacity(n);
    let mut buf = vec![0_u8; chunk];
    while all.len() < n {
        let want = (n - all.len()).min(chunk);
        match wait(|cx| c.poll_read(conn, cx, &mut buf[..want])) {
            Ok(0) => panic!("the peer closed after {} of {n} bytes", all.len()),
            Ok(got) => all.extend_from_slice(&buf[..got]),
            Err(e) => panic!("read failed mid-stream: {e:?}"),
        }
    }
    all
}

/// Read `conn` to its clean end, in reads no longer than `chunk`.
fn drain(c: &dyn Carrier, conn: u64, chunk: usize) -> Vec<u8> {
    let mut all = Vec::new();
    let mut buf = vec![0_u8; chunk];
    loop {
        match wait(|cx| c.poll_read(conn, cx, &mut buf)) {
            Ok(0) => return all,
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(e) => panic!("read failed mid-stream: {e:?}"),
        }
    }
}

/// Everything one carrier put on / took off the wire, and what it answered at the edges.
#[derive(Debug, PartialEq, Eq)]
struct Fold {
    key: &'static str,
    /// Dialled out: what the peer received, and what the carrier read back.
    dial_peer_saw: Vec<u8>,
    dial_read_back: Vec<u8>,
    /// Listened: what the carrier read from the peer, what the peer received back, and whether the
    /// accepted connection's arrival named its far end as the accept did and a local port.
    accept_read: Vec<u8>,
    accept_peer_saw: Vec<u8>,
    arrival_agrees: bool,
    /// What an unknown connection answers on write and close, a dial to a port nobody listens on
    /// once it settles, and a program destination.
    unknown_write: TransportError,
    unknown_close: Result<(), TransportError>,
    refused_dial: TransportError,
    program_dial: TransportError,
}

const SENT: (u8, usize) = (7, 40_000);
const REPLY: (u8, usize) = (91, 20_001);

/// THE SCRIPT, run identically against every carrier. The far end of every leg is a peer through
/// busbar's own linked carrier (a separate instance: [`carrier_peer`]).
fn fold(c: &dyn Carrier) -> Fold {
    // ── dial the peer, send, read its reply to the clean end its close makes ──
    let far = carrier_peer::listen();
    let authority = far.addr.clone();
    let far = std::thread::spawn(move || {
        let (peer, _) = far.accept();
        let got = peer.read_exact(SENT.1);
        peer.write_all(&payload(REPLY.0, REPLY.1));
        peer.close();
        got
    });
    let conn = c.dial(&Dest::Authority(&authority)).expect("dial");
    write_all(c, conn, &payload(SENT.0, SENT.1)).expect("write the request");
    let dial_read_back = drain(c, conn, 1000);
    wait(|cx| c.poll_close(conn, cx, CloseReason::Normal)).expect("close");
    let dial_peer_saw = far.join().unwrap();

    // ── listen, take the peer's bytes, answer, close; the peer reads to the clean end ──
    let (listener, addr) = c.listen("127.0.0.1:0").expect("listen");
    let near = std::thread::spawn(move || {
        let peer = carrier_peer::dial(&addr);
        peer.write_all(&payload(SENT.0 ^ 0xff, SENT.1));
        peer.read_to_end()
    });
    let (conn, peer_addr) = wait(|cx| c.poll_accept(listener, cx)).expect("accept");
    assert!(peer_addr.starts_with("127.0.0.1:"), "{peer_addr}");
    let arrival = c.arrival(conn).expect("an accepted connection's arrival");
    let arrival_agrees = arrival.peer == peer_addr && arrival.local_port != 0;
    let accept_read = read_exact(c, conn, SENT.1, 777);
    write_all(c, conn, &payload(REPLY.0 ^ 0xff, REPLY.1)).expect("write the answer");
    wait(|cx| c.poll_close(conn, cx, CloseReason::Normal)).expect("close");
    let accept_peer_saw = near.join().unwrap();

    // ── a dial nobody answers is refused when its opening settles ──
    let conn = c
        .dial(&Dest::Authority(carrier_peer::NOBODY))
        .expect("dial answers at once");
    let refused_dial = wait(|cx| c.poll_flush(conn, cx)).unwrap_err();
    let _ = wait(|cx| c.poll_close(conn, cx, CloseReason::Normal));

    Fold {
        key: c.key(),
        dial_peer_saw,
        dial_read_back,
        accept_read,
        accept_peer_saw,
        arrival_agrees,
        unknown_write: wait(|cx| c.poll_write(u64::MAX, cx, b"x")).unwrap_err(),
        unknown_close: wait(|cx| c.poll_close(u64::MAX, cx, CloseReason::Normal)),
        refused_dial,
        program_dial: c
            .dial(&Dest::Program {
                program: "/bin/true",
                args: &[],
                env: &[],
            })
            .unwrap_err(),
    }
}

/// What the script sent, byte for byte, on each leg.
fn expected() -> Fold {
    Fold {
        key: transport_fixture::linked::KEY,
        dial_peer_saw: payload(SENT.0, SENT.1),
        dial_read_back: payload(REPLY.0, REPLY.1),
        accept_read: payload(SENT.0 ^ 0xff, SENT.1),
        accept_peer_saw: payload(REPLY.0 ^ 0xff, REPLY.1),
        arrival_agrees: true,
        unknown_write: TransportError::Closed,
        unknown_close: Ok(()),
        refused_dial: TransportError::Refused,
        program_dial: TransportError::AddressRefused,
    }
}

/// ONE ROW, WHICHEVER DOOR: every constant the carrier declares — read off its decl through the
/// linked door and through the dropped-in door — is the linked type's own row.
#[test]
fn a_linked_and_a_dropped_in_carrier_are_one_row() {
    let linked = admitted(fixture_decl(), "linked-wire");
    let row = transport_fixture::linked::ROW;
    assert_eq!(*linked.row(), row);
    assert_eq!(linked.role(), Role::Carrier);
    let Some(dropped) = dropped_in() else {
        return;
    };
    assert_eq!(*dropped.row(), row);
    // Two images, two decls: the dropped-in one is not the linked one read twice.
    assert_ne!(dropped.decl(), linked.decl());
}

/// THE WITNESS: the linked carrier and the decl-backed carrier over each door run the script to the
/// SAME record, and that record is the bytes the script put on the wire.
#[test]
fn both_doors_put_the_same_bytes_on_the_wire() {
    let linked = transport_fixture::linked::carrier(&TransportSettings::default());
    let linked_fold = fold(&*linked);
    assert_eq!(
        linked_fold,
        expected(),
        "the linked carrier moves exactly the bytes it was given"
    );
    let decl_fold = fold(&*carrier_of(admitted(fixture_decl(), "linked-wire")));
    assert_eq!(
        decl_fold, linked_fold,
        "the carrier over its own decl is the linked carrier"
    );
    let Some(row) = dropped_in() else {
        return;
    };
    assert_eq!(
        fold(&*carrier_of(row)),
        linked_fold,
        "a dropped-in carrier and the same carrier linked are observationally one carrier"
    );
}

// ── THE RED ARM ─────────────────────────────────────────────────────────────────────────────────

/// The fixture carrier's real slot table.
fn real() -> &'static CarrierSlots {
    // SAFETY: the fixture is a carrier, so its decl's carrier table is its `'static` table.
    unsafe { &*fixture_decl().carrier }
}

/// A `poll_write` slot that flips the first byte of every offer, then writes through the real slot.
extern "C-unwind" fn altering_write(
    state: *mut std::os::raw::c_void,
    conn: u64,
    token: u64,
    buf: *const u8,
    len: usize,
    out_written: *mut usize,
) -> RawWireOutcome {
    let real = real().poll_write.expect("the fixture writes");
    if buf.is_null() || len == 0 {
        return real(state, conn, token, buf, len, out_written);
    }
    // SAFETY: the host's live `len`-byte range for this call.
    let mut bytes = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
    bytes[0] ^= 0x01;
    real(state, conn, token, bytes.as_ptr(), bytes.len(), out_written)
}

/// A copy of the fixture's decl, to alter one field of.
fn decl_copy() -> TransportDecl {
    // SAFETY: a byte copy of the live fixture decl; every pointer in it is `'static` image data.
    unsafe { core::ptr::read(fixture_decl()) }
}

/// THE RED ARM, kept: a carrier whose `poll_write` alters one byte folds DIFFERENTLY, on exactly the
/// legs that write — so the equality the witness asserts is one a wrong carrier fails.
#[test]
fn a_divergent_carrier_is_seen_by_the_fold() {
    static SLOTS: OnceLock<CarrierSlots> = OnceLock::new();
    static ALTERED: OnceLock<TransportDecl> = OnceLock::new();
    let slots = SLOTS.get_or_init(|| CarrierSlots {
        poll_write: Some(altering_write),
        ..*real()
    });
    let altered = ALTERED.get_or_init(|| TransportDecl {
        carrier: slots,
        ..decl_copy()
    });
    let seen = fold(&*carrier_of(admitted(altered, "altered-wire")));
    let honest = expected();
    assert_ne!(
        seen, honest,
        "the fold must see a carrier that changed a byte"
    );
    assert_ne!(seen.dial_peer_saw, honest.dial_peer_saw);
    assert_ne!(seen.accept_peer_saw, honest.accept_peer_saw);
    // What the altered carrier only READ is untouched: the difference is where the bytes changed.
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
        abi_version: busbar_contract::abi::ABI_MINOR,
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

/// A `kind: transport` manifest passes the structural gate on the airlock-minor axis, floored at the
/// first minor with the carrier/framer decl; an unknown kind is still refused with the established
/// prefix.
#[test]
fn a_transport_manifest_is_admitted_on_the_airlock_axis() {
    assert_eq!(
        crate::supported_abi("transport"),
        &[
            busbar_contract::abi::hot::TRANSPORT_DECL_MINOR,
            busbar_contract::abi::ABI_MINOR
        ]
    );
    validate_structure(&manifest("transport"), b"lib", &crate::supported_abi, "")
        .expect("a transport is a kind the loader admits");
    let mut old = manifest("transport");
    old.abi_version = busbar_contract::abi::hot::TRANSPORT_DECL_MINOR - 1;
    assert!(
        validate_structure(&old, b"lib", &crate::supported_abi, "").is_err(),
        "a minor with the retired byte-stream decl has no carrier or framer to speak"
    );
    let err = validate_structure(&manifest("gizmo"), b"lib", &crate::supported_abi, "")
        .expect_err("an unknown kind is refused");
    assert!(
        err.starts_with("manifest kind 'gizmo' is not one of"),
        "{err}"
    );
}

static NO_FRAMER: FramerSlots = FramerSlots {
    size: core::mem::size_of::<FramerSlots>() as u32,
    _reserved: 0,
    locate: None,
    open: None,
    ingest: None,
    emit: None,
    encode_envelope: None,
    refusal: None,
    close: None,
    detach: None,
    adopt: None,
    tick: None,
};

static SHORT_CARRIER: OnceLock<CarrierSlots> = OnceLock::new();

static COMPOSED: [DeclStr; 1] = [DeclStr::new("below")];
static BAD_FORM: [u8; 1] = [99];

/// The admission refuses a decl it cannot trust, on either door, naming why: null, a foreign
/// preamble, the RETIRED byte-stream decl (its generation field held its airlock minor), a minor
/// before the carrier/framer decl, a size that is not this build's, a keyless row, a flag that is
/// neither 0 nor 1, an unknown selector-form byte, a list it cannot back, a role whose slots are
/// missing or doubled, a slot table of the wrong size, and no `init`.
#[test]
fn the_admission_refuses_a_decl_it_cannot_trust() {
    // SAFETY (every `link_transport` below): null is refused before any read; each other decl is a
    // live local copy of the valid fixture decl with one field altered, refused before anything
    // outlives it; its borrowed ranges are `'static` data.
    let null = unsafe { link_transport(core::ptr::null(), "null") }.unwrap_err();
    assert!(null.contains("null decl"), "{null}");

    let refuse = |edit: &dyn Fn(&mut TransportDecl), needle: &str| {
        let mut copy = decl_copy();
        edit(&mut copy);
        let err = unsafe { link_transport(&copy, "edited") }.unwrap_err();
        assert!(err.contains(needle), "expected `{needle}` in: {err}");
    };
    refuse(&|d| d.abi.magic ^= 1, "BadMagic");
    refuse(&|d| d.abi.abi_major += 1, "MajorMismatch");
    refuse(&|d| d.version = 28, "states transport-decl generation 28");
    refuse(
        &|d| d.abi.abi_minor = busbar_contract::abi::hot::TRANSPORT_DECL_MINOR - 1,
        "this build admits generation 2",
    );
    let tail = core::mem::offset_of!(TransportDecl, claims_ptr) as u32;
    refuse(
        &|d| d.size = tail - 8,
        "does not reach its own row and slots",
    );
    refuse(&|d| d.size += 8, "exceeding this build's own");
    refuse(&|d| d.key = DeclStr::NONE, "declares no key");
    refuse(&|d| d.session = 2, "declares session flag 2");
    refuse(
        &|d| d.decodes_payload = 7,
        "declares decodes-payload flag 7",
    );
    refuse(&|d| d.framing = 9, "declares framing byte 9");
    refuse(&|d| d.status_at = 3, "declares status position byte 3");
    refuse(
        &|d| d.unit0_trigger = 7,
        "declares first-unit trigger byte 7",
    );
    refuse(
        &|d| {
            d.selector_forms = DeclByteList {
                ptr: BAD_FORM.as_ptr(),
                len: 1,
            }
        },
        "declares selector-form byte 99",
    );
    refuse(
        &|d| {
            d.upgrades_to = DeclStrList {
                ptr: core::ptr::null(),
                len: 1,
            }
        },
        "cannot back",
    );
    refuse(&|d| d.init = None, "declares no `init`");
    // THE ROLE IS DERIVED: a carrier states only carrier slots, a framer only framer slots.
    refuse(&|d| d.carrier = core::ptr::null(), "so it is a Carrier");
    refuse(&|d| d.framer = &NO_FRAMER, "so it is a Carrier");
    refuse(
        &|d| {
            d.composes_over = DeclStrList {
                ptr: COMPOSED.as_ptr(),
                len: 1,
            }
        },
        "so it is a Framer",
    );
    let short = SHORT_CARRIER.get_or_init(|| CarrierSlots { size: 8, ..*real() });
    refuse(&|d| d.carrier = short, "slot table attests size 8");
    // THE CLAIMS (minor 33): each is read as strictly as the row.
    refuse(
        &|d| {
            d.claims_ptr = TWICE.as_ptr();
            d.claims_len = TWICE.len();
        },
        &format!("claims '{OWN}' twice; one entry claims a scheme once"),
    );
    refuse(
        &|d| {
            d.claims_ptr = ELSEWHERE.as_ptr();
            d.claims_len = 1;
        },
        &format!("is keyed '{OWN}' and its first claim is 'elsewhere'"),
    );
    refuse(
        &|d| {
            d.claims_ptr = BAD_LEG.as_ptr();
            d.claims_len = 1;
        },
        "claims with status position byte 9",
    );
    refuse(
        &|d| {
            d.claims_ptr = core::ptr::null();
            d.claims_len = 1;
        },
        "claims list it cannot back",
    );
}

/// A claim of `key` whose status-position byte is `status_at`.
const fn claim(key: &'static str, status_at: u8) -> DeclClaim {
    DeclClaim {
        key: DeclStr::new(key),
        selector_forms: DeclByteList {
            ptr: core::ptr::null(),
            len: 0,
        },
        transport_facts: DeclStrList {
            ptr: core::ptr::null(),
            len: 0,
        },
        status_namespace: DeclStr::NONE,
        session: 0,
        session_bound: 0,
        unit0_trigger: 0,
        status_at,
        _reserved: 0,
    }
}
/// The fixture's own key: its first claim.
const OWN: &str = transport_fixture::linked::KEY;
static TWICE: [DeclClaim; 2] = [claim(OWN, 0), claim(OWN, 0)];
static ELSEWHERE: [DeclClaim; 1] = [claim("elsewhere", 0)];
static BAD_LEG: [DeclClaim; 1] = [claim(OWN, 9)];

/// A decl that ends before the claims tail (a transport built before minor 33) is admitted, and makes
/// the one claim its row describes; the fixture's own lowering states that same one claim.
#[test]
fn a_decl_before_the_claims_tail_makes_its_rows_one_claim() {
    let own = admitted(fixture_decl(), "linked-wire").row();
    assert_eq!(own.claims.len(), 1);
    assert_eq!(own.claims[0].key, OWN);
    let mut older = decl_copy();
    older.size = core::mem::offset_of!(TransportDecl, claims_ptr) as u32;
    // SAFETY: a live local copy of the valid fixture decl, attesting a shorter prefix; the row is
    // copied out before the copy goes.
    let row = *unsafe { link_transport(&older, "older") }
        .expect("a pre-claims decl is admitted")
        .row();
    assert_eq!(
        row.claims, own.claims,
        "the row's one claim, read either way"
    );
}

/// A decl that states several claims is read claim for claim, each with its OWN status leg.
#[test]
fn every_claim_is_read_with_its_own_status_leg() {
    static SEVERAL: [DeclClaim; 2] = [claim(OWN, 1), claim("second", 2)];
    let mut copy = decl_copy();
    copy.claims_ptr = SEVERAL.as_ptr();
    copy.claims_len = SEVERAL.len();
    // SAFETY: a live local copy of the valid fixture decl, its claims list `'static`.
    let row = *unsafe { link_transport(&copy, "several") }
        .expect("admitted")
        .row();
    let legs: Vec<_> = row.claims.iter().map(|c| (c.key, c.status_at)).collect();
    assert_eq!(
        legs,
        [
            (OWN, Some(StatusAt::FirstFrame)),
            ("second", Some(StatusAt::Terminal))
        ]
    );
}

/// Every constant the fixture declares reaches the host through its lowered decl — an admission that
/// dropped or crossed one would read a different row than the linked type's.
#[test]
fn the_lowered_decl_carries_the_whole_row() {
    let row = admitted(fixture_decl(), "linked-wire").row();
    assert_eq!(*row, transport_fixture::linked::ROW);
    // The lowering names every slot of its role and none of the other's.
    let d = fixture_decl();
    assert!(d.framer.is_null());
    let slots = real();
    assert!(
        slots.listen.is_some()
            && slots.poll_accept.is_some()
            && slots.dial.is_some()
            && slots.poll_read.is_some()
            && slots.poll_write.is_some()
            && slots.poll_flush.is_some()
            && slots.poll_close.is_some()
            && slots.arrival.is_some()
    );
}
