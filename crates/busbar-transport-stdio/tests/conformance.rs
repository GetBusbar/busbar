// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE CARRIER, BOTH DOORS, ONE WIRE** — the `stdio` carrier's linked + dropped-in conformance
//! (#3: a transport is swappable, compiled in OR dropped in over the ABI; #30: it rides the HOT
//! lane; #2 rule (1): one contract, one loading path; TRANSPORT-STACK: the HOT decl is the
//! Carrier/Framer traits lowered one slot per method).
//!
//! The carrier is held three ways at once: LINKED (`linked::carrier`, driven as the contract's
//! [`Carrier`] directly — what a busbar build that compiles the wire in holds), its DECL (the
//! contract's `export_carrier!` lowering of the same type, `exports::TRANSPORT_DECL`, admitted
//! through the loader's `link_transport`), and DROPPED IN (this crate's own cdylib, built with its
//! `dropped-in` door by this crate's dev-dependency on itself, signed first-party into a fresh
//! `plugins/` directory, found by the loader's scan and opened by `open_transport`). Every decl runs
//! the loader's ONE admission.
//!
//! THE FOLD. Each carrier runs the same script through the SAME trait methods: it dials real
//! programs — one that echoes its pipe, one that prints the argument vector and environment it was
//! started with — and records what crossed in each direction, takes the process's own standard
//! input and output from its one listener, and states what it refuses. The folds must be equal, and
//! each must equal what the script sent: the bytes, the arguments and the environment are identical
//! whichever door the carrier came in by, and identical to what was asked for.
//!
//! THE RED ARM, kept: [`a_divergent_carrier_is_seen_by_the_fold`] runs the fold over a decl whose
//! `poll_write` slot alters one byte and requires the fold to DIFFER.

use busbar_contract::abi::hot::transport::{CarrierSlots, RawWireOutcome, TransportDecl};
use busbar_contract::transport::wire::{CloseReason, TransportError};
use busbar_contract::transport::{Carrier, CarrierPoll, Dest, Role, TransportSettings};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::transport::{link_transport, wire_settings, Built, DynTransport};
use busbar_transport_stdio::{exports, linked};
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Wake, Waker};

/// The version both doors state (a linked row states its binary's version; here, this crate's).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[13u8; 32])
}

// ── DRIVING A CARRIER ON THIS THREAD ────────────────────────────────────────────────────────────

/// Wakes the thread that parked on a poll.
struct Unpark(std::thread::Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Drive one future on this thread, parking between polls.
fn block_on<F: Future>(f: F) -> F::Output {
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
fn wait<T>(
    mut method: impl FnMut(&mut Context<'_>) -> CarrierPoll<T>,
) -> Result<T, TransportError> {
    block_on(std::future::poll_fn(|cx| method(cx)))
}

/// Offer every one of `bytes` to `conn`, then flush.
fn write_all(c: &dyn Carrier, conn: u64, bytes: &[u8]) -> Result<(), TransportError> {
    let mut at = 0;
    while at < bytes.len() {
        at += wait(|cx| c.poll_write(conn, cx, &bytes[at..]))?;
    }
    wait(|cx| c.poll_flush(conn, cx))
}

/// Read exactly `n` bytes of `conn`, in reads no longer than `chunk`.
fn read_exact(c: &dyn Carrier, conn: u64, n: usize, chunk: usize) -> Vec<u8> {
    let mut all = Vec::with_capacity(n);
    let mut buf = vec![0_u8; chunk];
    while all.len() < n {
        let want = (n - all.len()).min(chunk);
        match wait(|cx| c.poll_read(conn, cx, &mut buf[..want])) {
            Ok(0) => panic!("the pipe ended after {} of {n} bytes", all.len()),
            Ok(got) => all.extend_from_slice(&buf[..got]),
            Err(e) => panic!("read failed mid-stream: {e:?}"),
        }
    }
    all
}

/// Read `conn` to its clean end (or its error), in reads no longer than `chunk`.
fn drain(c: &dyn Carrier, conn: u64, chunk: usize) -> Vec<u8> {
    let mut all = Vec::new();
    let mut buf = vec![0_u8; chunk];
    loop {
        match wait(|cx| c.poll_read(conn, cx, &mut buf)) {
            Ok(0) | Err(_) => return all,
            Ok(n) => all.extend_from_slice(&buf[..n]),
        }
    }
}

// ── THE DOORS ───────────────────────────────────────────────────────────────────────────────────

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
        unsafe { link_transport(decl, display) }.expect("the linked door admits the carrier"),
    ));
    rows.push((key, row));
    row
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip: this test IS the dropped-in door's proof.
fn cdylib() -> Vec<u8> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_transport_stdio");
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-transport-stdio cdylib ({file}) is not built"));
    std::fs::read(found).expect("read the cdylib")
}

/// THE DROPPED-IN DOOR: the cdylib signed first-party into a fresh `plugins/` directory, scanned
/// under a policy holding the release key, and opened by name — once for the process.
fn dropped_in() -> &'static DynTransport {
    static ROW: OnceLock<DynTransport> = OnceLock::new();
    ROW.get_or_init(|| {
        let lib = cdylib();
        let dir = std::env::temp_dir().join(format!("transport-stdio-conf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the plugins dir");
        let manifest = Manifest {
            name: "pipes".into(),
            alias: "pipes".into(),
            kind: "transport".into(),
            version: VERSION.into(),
            publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
            abi_version: busbar_contract::abi::transport::ABI_VERSION,
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
            needs: Default::default(),
            settings_schema: None,
            schema_derived: false,
            host: None,
            declares: Default::default(),
            statement: None,
            former_names: Vec::new(),
        };
        let signed = sign(&release(), manifest, &lib);
        let tarball =
            busbar_plugin_loader::tarball::package(&signed, "libpipes.so", &lib).expect("package");
        std::fs::write(dir.join("pipes.tar.gz"), tarball).expect("write the tarball");
        let policy = TrustPolicy {
            first_party_key: Some(release().verifying_key()),
            binary_version: VERSION.into(),
            first_party_floors: Default::default(),
            first_party_high_water: Default::default(),
            publishers: Default::default(),
            allow_unsigned: false,
            allow_third_party: false,
            min_versions: Default::default(),
        };
        let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy)
            .unwrap_or_else(|e| panic!("the signed carrier scans: {e:?}"));
        let row = registry
            .open_transport("pipes")
            .expect("the dropped-in door opens the carrier");
        let _ = std::fs::remove_dir_all(&dir);
        row
    })
}

/// A decl row's carrier, built.
fn carrier_of(row: &'static DynTransport) -> Arc<dyn Carrier> {
    match row
        .build(&wire_settings(&TransportSettings::default()))
        .expect("the carrier builds")
    {
        Built::Carrier(c) => c,
        Built::Framer(_) => panic!("stdio is a carrier"),
    }
}

// ── THE FOLD ────────────────────────────────────────────────────────────────────────────────────

/// Bytes that exercise every value — newlines and carriage returns included, because a carrier
/// frames nothing — and outrun the read buffers below, so the pipe hands them over in several reads.
fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
        .collect()
}

/// A variable the test process carries and a child must never see.
const INHERITED: &str = "BUSBAR_STDIO_CONFORMANCE_INHERITED";

/// Everything one carrier put on / took off its pipes, and what it answered at the edges.
#[derive(Debug, PartialEq, Eq)]
struct Fold {
    key: &'static str,
    /// Dialled `/bin/cat`: what came back through its pipe, and its arrival.
    echoed: Vec<u8>,
    echo_arrival: Option<(String, u16)>,
    /// Dialled `/bin/sh` printing its `$0`, a declared variable and an inherited one.
    started_with: Vec<u8>,
    /// The listener's address, the first accept's far end, and what a second accept answers.
    listened: String,
    accepted: String,
    second_accept: TransportError,
    /// What a bare program name, an address, an unknown connection's write and close answer.
    relative_dial: TransportError,
    authority_dial: TransportError,
    unknown_write: TransportError,
    unknown_close: Result<(), TransportError>,
    /// What a closed connection answers on write, and its arrival once closed.
    closed_write: TransportError,
    closed_arrival: bool,
}

const SENT: (u8, usize) = (7, 40_000);

/// THE SCRIPT, run identically against every carrier.
fn fold(c: &dyn Carrier) -> Fold {
    // ── a program that echoes its pipe: send, read the same bytes back, close ──
    let conn = c
        .dial(&Dest::Program {
            program: "/bin/cat",
            args: &[],
            env: &[],
        })
        .expect("spawn /bin/cat");
    let sent = payload(SENT.0, SENT.1);
    let echoed = std::thread::scope(|s| {
        let reader = s.spawn(|| read_exact(c, conn, SENT.1, 777));
        write_all(c, conn, &sent).expect("write the payload");
        reader.join().unwrap()
    });
    let echo_arrival = c.arrival(conn).map(|f| (f.peer, f.local_port));
    wait(|cx| c.poll_close(conn, cx, CloseReason::Normal)).expect("close");
    let closed_write = wait(|cx| c.poll_write(conn, cx, b"x")).unwrap_err();
    let closed_arrival = c.arrival(conn).is_some();

    // ── a program that prints what it was started with ──
    let conn = c
        .dial(&Dest::Program {
            program: "/bin/sh",
            args: &[
                "-c",
                "printf '%s|%s|%s' \"$0\" \"$DECLARED\" \"$BUSBAR_STDIO_CONFORMANCE_INHERITED\"",
                "first-arg",
            ],
            env: &[("DECLARED", "declared value")],
        })
        .expect("spawn /bin/sh");
    let started_with = drain(c, conn, 64);
    let _ = wait(|cx| c.poll_close(conn, cx, CloseReason::Normal));

    // ── the process's own standard input and output, handed out once ──
    let (listener, listened) = c.listen("ignored").expect("listen");
    let (own, accepted) = wait(|cx| c.poll_accept(listener, cx)).expect("accept");
    let second_accept = wait(|cx| c.poll_accept(listener, cx)).unwrap_err();
    wait(|cx| c.poll_close(own, cx, CloseReason::Normal)).expect("close the own pipes");

    Fold {
        key: c.key(),
        echoed,
        echo_arrival,
        started_with,
        listened,
        accepted,
        second_accept,
        relative_dial: c
            .dial(&Dest::Program {
                program: "cat",
                args: &[],
                env: &[],
            })
            .unwrap_err(),
        authority_dial: c.dial(&Dest::Authority("127.0.0.1:1")).unwrap_err(),
        unknown_write: wait(|cx| c.poll_write(u64::MAX, cx, b"x")).unwrap_err(),
        unknown_close: wait(|cx| c.poll_close(u64::MAX, cx, CloseReason::Normal)),
        closed_write,
        closed_arrival,
    }
}

/// What the script sent and asked for, exactly.
fn expected() -> Fold {
    Fold {
        key: linked::KEY,
        echoed: payload(SENT.0, SENT.1),
        echo_arrival: Some(("/bin/cat".to_string(), 0)),
        started_with: b"first-arg|declared value|".to_vec(),
        listened: "stdio:own-process".to_string(),
        accepted: "stdio:own-process".to_string(),
        second_accept: TransportError::Closed,
        relative_dial: TransportError::AddressRefused,
        authority_dial: TransportError::AddressRefused,
        unknown_write: TransportError::Closed,
        unknown_close: Ok(()),
        closed_write: TransportError::Closed,
        closed_arrival: false,
    }
}

/// The test process carries a variable no child may inherit, from before the first carrier runs.
fn arm_the_inherited_variable() {
    static ARMED: OnceLock<()> = OnceLock::new();
    ARMED.get_or_init(|| std::env::set_var(INHERITED, "leaked"));
}

/// ONE ROW, WHICHEVER DOOR: every constant the carrier declares — read off its decl through the
/// linked door and through the dropped-in door — is the linked type's own row.
#[test]
fn a_linked_and_a_dropped_in_carrier_are_one_row() {
    let linked_row = admitted(&exports::TRANSPORT_DECL, "linked-pipes");
    assert_eq!(*linked_row.row(), linked::ROW);
    assert_eq!(linked_row.role(), Role::Carrier);
    assert_eq!(linked_row.key(), "stdio");
    let dropped = dropped_in();
    assert_eq!(*dropped.row(), linked::ROW);
    assert_eq!(dropped.role(), Role::Carrier);
    // Two images, two decls: the dropped-in one is not the linked one read twice.
    assert_ne!(dropped.decl(), linked_row.decl());
}

/// THE WITNESS: the linked carrier, the carrier over its own decl, and the dropped-in carrier run
/// the script to the SAME record, and that record is what the script sent and asked for.
#[test]
fn both_doors_move_the_same_bytes_and_start_the_same_programs() {
    arm_the_inherited_variable();
    let linked_fold = fold(&*linked::carrier(&TransportSettings::default()));
    assert_eq!(
        linked_fold,
        expected(),
        "the linked carrier moves exactly the bytes and declarations it was given"
    );
    let decl_fold = fold(&*carrier_of(admitted(
        &exports::TRANSPORT_DECL,
        "linked-pipes",
    )));
    assert_eq!(
        decl_fold, linked_fold,
        "the carrier over its own decl is the linked carrier"
    );
    assert_eq!(
        fold(&*carrier_of(dropped_in())),
        linked_fold,
        "a dropped-in carrier and the same carrier linked are observationally one carrier"
    );
}

/// The lowering names every slot of the carrier role and none of the framer's.
#[test]
fn the_lowered_decl_is_a_whole_carrier() {
    let d = &exports::TRANSPORT_DECL;
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

// ── THE RED ARM ─────────────────────────────────────────────────────────────────────────────────

/// The carrier's real slot table.
fn real() -> &'static CarrierSlots {
    // SAFETY: stdio is a carrier, so its decl's carrier table is its `'static` table.
    unsafe { &*exports::TRANSPORT_DECL.carrier }
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
    let real = real().poll_write.expect("the carrier writes");
    if buf.is_null() || len == 0 {
        return real(state, conn, token, buf, len, out_written);
    }
    // SAFETY: the host's live `len`-byte range for this call.
    let mut bytes = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
    bytes[0] ^= 0x01;
    real(state, conn, token, bytes.as_ptr(), bytes.len(), out_written)
}

/// THE RED ARM, kept: a carrier whose `poll_write` alters one byte folds DIFFERENTLY, on exactly the
/// leg that writes — so the equality the witness asserts is one a wrong carrier fails.
#[test]
fn a_divergent_carrier_is_seen_by_the_fold() {
    arm_the_inherited_variable();
    static SLOTS: OnceLock<CarrierSlots> = OnceLock::new();
    static ALTERED: OnceLock<TransportDecl> = OnceLock::new();
    let slots = SLOTS.get_or_init(|| CarrierSlots {
        poll_write: Some(altering_write),
        ..*real()
    });
    let altered = ALTERED.get_or_init(|| TransportDecl {
        carrier: slots,
        // SAFETY: a byte copy of the live decl; every pointer in it is `'static` image data.
        ..unsafe { core::ptr::read(&exports::TRANSPORT_DECL) }
    });
    let seen = fold(&*carrier_of(admitted(altered, "altered-pipes")));
    let honest = expected();
    assert_ne!(
        seen, honest,
        "the fold must see a carrier that changed a byte"
    );
    assert_ne!(seen.echoed, honest.echoed);
    // What the altered carrier did not write is untouched: the difference is where the bytes changed.
    assert_eq!(seen.started_with, honest.started_with);
    assert_eq!(seen.key, honest.key);
}

// ── #30: THE CROSSING ───────────────────────────────────────────────────────────────────────────

/// `(p50, p99)` of `samples`, in nanoseconds.
fn percentiles(mut samples: Vec<u128>) -> (u128, u128) {
    samples.sort_unstable();
    let at = |q: usize| samples[(samples.len() * q / 100).min(samples.len() - 1)];
    (at(50), at(99))
}

/// `(p50, p99)` of one call, timed `n` times.
fn timed(n: usize, mut call: impl FnMut()) -> (u128, u128) {
    percentiles(
        (0..n)
            .map(|_| {
                let t0 = std::time::Instant::now();
                call();
                t0.elapsed().as_nanos()
            })
            .collect(),
    )
}

/// #30 (HOT lane, < 1 µs per crossing): the same carrier method — a flush of a connection the
/// carrier does not hold, which answers without I/O — called on the linked carrier and on the
/// dropped-in one; the difference is the crossing (the waker registration, the guarded indirect
/// call, the answer's decode), held to the budget at p50 and p99. Release build:
/// `cargo test --release -p busbar-transport-stdio --test conformance -- --ignored --nocapture`.
#[test]
#[ignore = "perf measurement; run in release with --ignored --nocapture"]
fn the_dropped_in_crossing_is_under_a_microsecond() {
    let linked_carrier = linked::carrier(&TransportSettings::default());
    let dropped = carrier_of(dropped_in());
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut call = |c: &dyn Carrier| {
        let _: CarrierPoll<()> =
            std::hint::black_box(c.poll_flush(std::hint::black_box(u64::MAX), &mut cx));
    };
    for _ in 0..2_000 {
        call(&*linked_carrier);
        call(&*dropped);
    }
    let direct = timed(50_000, || call(&*linked_carrier));
    let crossed = timed(50_000, || call(&*dropped));
    let delta = (
        crossed.0.saturating_sub(direct.0),
        crossed.1.saturating_sub(direct.1),
    );
    println!("#30 transport, stdio carrier (budget 1000 ns per crossing):");
    println!(
        "  linked:     p50 {:>6} ns  p99 {:>6} ns",
        direct.0, direct.1
    );
    println!(
        "  dropped in: p50 {:>6} ns  p99 {:>6} ns",
        crossed.0, crossed.1
    );
    println!("  crossing:   p50 {:>6} ns  p99 {:>6} ns", delta.0, delta.1);
    assert!(delta.0 < 1_000 && delta.1 < 1_000, "{delta:?}");
}
