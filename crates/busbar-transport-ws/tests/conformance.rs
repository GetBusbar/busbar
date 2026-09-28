// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE FRAMER, BOTH DOORS, ONE WIRE** — the `ws` framer's linked + dropped-in conformance (#3: a
//! transport is swappable, compiled in OR dropped in over the ABI; #30: it rides the HOT lane; #2
//! rule (1): one contract, one loading path; TRANSPORT-STACK: the HOT decl is the Carrier/Framer
//! traits lowered one slot per method).
//!
//! The framer is held three ways at once: LINKED (`linked::framer`, driven as the contract's
//! [`Framer`] directly), its DECL (the contract's `export_framer!` lowering of the same type,
//! `exports::TRANSPORT_DECL`, admitted through the loader's `link_transport`), and DROPPED IN (this
//! crate's own cdylib, built with its `dropped-in` door by this crate's dev-dependency on itself,
//! signed first-party into a fresh `plugins/` directory, found by the loader's scan and opened by
//! `open_transport`). Every decl runs the loader's ONE admission.
//!
//! A framer is sans-IO, so its proof needs no socket: a framer talks to ITSELF — a dialling state
//! and an accepting state, the bytes each sends ingested by the other. The dialling side's bytes
//! are random by design (the handshake key, every frame's mask), so byte identity is proven where
//! the protocol makes it provable: the accepting side of EVERY door is fed the SAME dialling
//! transcript — captured once from the linked framer talking to itself — and must answer it byte
//! for byte. The dialling side of every door then runs against the linked accepting side, and what
//! each side handed up must be the same.
//!
//! THE RED ARM, kept: [`a_divergent_framer_is_seen_by_the_fold`] runs the fold over a decl whose
//! `emit` slot alters one byte and requires the fold to DIFFER.

use busbar_contract::abi::hot::transport::{
    FramerEmitFn, FramerSlots, RawWireOutcome, TransportDecl, WireFramerOut,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::{CloseReason, Encode, TransportError, WireStatusClass};
use busbar_contract::transport::{
    ConnFacts, Framed, Framer, FramerOut, HostTime, Located, Role, Side, TransportSettings,
};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::transport::{link_transport, wire_settings, Built, DynTransport};
use busbar_transport_ws::{exports, linked};
use std::sync::{Arc, Mutex, OnceLock};

/// The version both doors state (a linked row states its binary's version; here, this crate's).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[17u8; 32])
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
        unsafe { link_transport(decl, display) }.expect("the linked door admits the framer"),
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
    let file = busbar_plugin_loader::plugin_library_filename("busbar_transport_ws");
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-transport-ws cdylib ({file}) is not built"));
    std::fs::read(found).expect("read the cdylib")
}

/// THE DROPPED-IN DOOR: the cdylib signed first-party into a fresh `plugins/` directory, scanned
/// under a policy holding the release key, and opened by name — once for the process.
fn dropped_in() -> &'static DynTransport {
    static ROW: OnceLock<DynTransport> = OnceLock::new();
    ROW.get_or_init(|| {
        let lib = cdylib();
        let dir = std::env::temp_dir().join(format!("transport-ws-conf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the plugins dir");
        let manifest = Manifest {
            name: "frames".into(),
            alias: "frames".into(),
            kind: "transport".into(),
            version: VERSION.into(),
            publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
            abi_version: busbar_contract::abi::ABI_MINOR,
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
        };
        let signed = sign(&release(), manifest, &lib);
        let tarball =
            busbar_plugin_loader::tarball::package(&signed, "libframes.so", &lib).expect("package");
        std::fs::write(dir.join("frames.tar.gz"), tarball).expect("write the tarball");
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
            .unwrap_or_else(|e| panic!("the signed framer scans: {e:?}"));
        let row = registry
            .open_transport("frames")
            .expect("the dropped-in door opens the framer");
        let _ = std::fs::remove_dir_all(&dir);
        row
    })
}

/// A decl row's framer, built.
fn framer_of(row: &'static DynTransport) -> Arc<dyn Framer> {
    match row
        .build(&wire_settings(&TransportSettings::default()))
        .expect("the framer builds")
    {
        Built::Framer(f) => f,
        Built::Carrier(_) => panic!("ws is a framer"),
    }
}

/// The linked framer, built as a build that links this crate builds it.
fn linked_framer() -> Arc<dyn Framer> {
    linked::framer(&TransportSettings::default())
}

// ── THE FOLD ────────────────────────────────────────────────────────────────────────────────────

/// Bytes that exercise every value.
fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// One frame piece a framer handed up: stream, bytes, end of frame, status class, code, retry.
type Piece = (
    u64,
    Vec<u8>,
    bool,
    Option<WireStatusClass>,
    Option<u32>,
    Option<u64>,
);

/// Everything a framer call produced, and whether the connection's frames ended.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Heard {
    sent: Vec<u8>,
    frames: Vec<Piece>,
    ended: bool,
}

impl FramerOut for Heard {
    fn send(&mut self, bytes: &[u8]) {
        self.sent.extend_from_slice(bytes);
    }
    fn frame(&mut self, p: Framed<'_>) {
        self.frames.push((
            p.stream.0,
            p.bytes.to_vec(),
            p.end_of_frame,
            p.status,
            p.status_code,
            p.retry_after_secs,
        ));
    }
    fn end(&mut self) {
        self.ended = true;
    }
    fn now(&self) -> HostTime {
        HostTime::default()
    }
    fn wake_at(&mut self, _: Option<u64>) {}
}

impl Heard {
    fn take_sent(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.sent)
    }
}

/// The address every dialling side opens toward.
const TARGET: &str = "ws://framed.test:9000/p";

/// Pump bytes between two framing states until neither owes any; answers the dialling side's
/// chunks, in order.
fn pump(
    (df, d, dh): (&dyn Framer, u64, &mut Heard),
    (af, a, ah): (&dyn Framer, u64, &mut Heard),
) -> Vec<Vec<u8>> {
    let mut dial_chunks = Vec::new();
    for _ in 0..16 {
        let to_accept = dh.take_sent();
        let to_dial = ah.take_sent();
        if to_accept.is_empty() && to_dial.is_empty() {
            break;
        }
        if !to_accept.is_empty() {
            dial_chunks.push(to_accept.clone());
            let _ = af.ingest(a, &to_accept, false, ah);
        }
        if !to_dial.is_empty() {
            let _ = df.ingest(d, &to_dial, false, dh);
        }
    }
    dial_chunks
}

/// The dialling transcript: every chunk the LINKED framer's dialling side sends talking to its own
/// accepting side — the upgrade request, one message emitted in two pieces, and a close.
fn dial_transcript(linked: &dyn Framer) -> Vec<Vec<u8>> {
    let facts = ConnFacts::default();
    let (mut dh, mut ah) = (Heard::default(), Heard::default());
    let d = linked
        .open(Side::Dial, TARGET, &facts, &mut dh)
        .expect("dial");
    let a = linked
        .open(Side::Accept, "", &facts, &mut ah)
        .expect("accept");
    let mut chunks = pump((linked, d, &mut dh), (linked, a, &mut ah));
    let message = payload(3, 5_000);
    let (first, second) = message.split_at(message.len() / 2);
    let _ = linked.emit(d, StreamId(0), first, false, &mut dh);
    let _ = linked.emit(d, StreamId(0), second, true, &mut dh);
    chunks.extend(pump((linked, d, &mut dh), (linked, a, &mut ah)));
    linked.close(d, CloseReason::CapacityExhausted, &mut dh);
    chunks.extend(pump((linked, d, &mut dh), (linked, a, &mut ah)));
    linked.close(a, CloseReason::Normal, &mut ah);
    chunks
}

/// What one framer did, both ways.
#[derive(Debug, PartialEq, Eq)]
struct Fold {
    located: Result<Located, TransportError>,
    secure: Result<Located, TransportError>,
    envelope: Result<Vec<u8>, Encode>,
    /// The accepting side fed the fixed dialling transcript: every byte it answered and every
    /// frame it handed up, after each chunk and after its own emit and close — BYTE FOR BYTE.
    accepting: Vec<Heard>,
    /// The same upgrade request, adopted from another framer instead of opened.
    adopted: Heard,
    detach: TransportError,
    /// This framer's dialling side against the linked accepting side: what each side handed up.
    dialled_frames: Vec<Piece>,
    accepted_frames: Vec<Piece>,
    /// A refusal: the bytes it answers, and that the state is gone after it.
    refused: Heard,
    after_refusal: TransportError,
    /// What an unknown framing state answers.
    unknown_emit: TransportError,
}

/// THE SCRIPT, run identically against every door.
fn fold(x: &dyn Framer, linked: &dyn Framer, transcript: &[Vec<u8>]) -> Fold {
    let facts = ConnFacts::default();
    // ── the accepting side, fed the fixed transcript ──
    let mut accepting = Vec::new();
    let mut ah = Heard::default();
    let a = x.open(Side::Accept, "", &facts, &mut ah).expect("accept");
    accepting.push(std::mem::take(&mut ah));
    for (i, chunk) in transcript.iter().enumerate() {
        let _ = x.ingest(a, chunk, false, &mut ah);
        if i == 0 {
            // After the opening: the accepting side sends a frame of its own.
            let _ = x.emit(a, StreamId(0), &payload(9, 3_000), true, &mut ah);
        }
        accepting.push(std::mem::take(&mut ah));
    }
    x.close(a, CloseReason::Drain, &mut ah);
    accepting.push(std::mem::take(&mut ah));

    // ── the upgrade into this framer: the same request, adopted ──
    let mut adopted = Heard::default();
    let s = x
        .adopt(Side::Accept, &facts, &transcript[0], &mut adopted)
        .expect("adopt the upgrade");
    let detach = x.detach(s, &mut Vec::new()).unwrap_err();
    x.close(s, CloseReason::Normal, &mut adopted);

    // ── this framer's dialling side, against the linked accepting side ──
    let (mut dh, mut lh) = (Heard::default(), Heard::default());
    let d = x.open(Side::Dial, TARGET, &facts, &mut dh).expect("dial");
    let l = linked
        .open(Side::Accept, "", &facts, &mut lh)
        .expect("accept");
    pump((x, d, &mut dh), (linked, l, &mut lh));
    let _ = x.emit(d, StreamId(0), &payload(5, 4_000), true, &mut dh);
    pump((x, d, &mut dh), (linked, l, &mut lh));
    let _ = linked.emit(l, StreamId(0), &payload(11, 2_000), true, &mut lh);
    pump((x, d, &mut dh), (linked, l, &mut lh));
    x.close(d, CloseReason::Normal, &mut dh);
    pump((x, d, &mut dh), (linked, l, &mut lh));
    linked.close(l, CloseReason::Normal, &mut lh);

    // ── a refusal on an opened accepting state closes it ──
    let mut refused = Heard::default();
    let r = x
        .open(Side::Accept, "", &facts, &mut refused)
        .expect("accept");
    let _ = x.ingest(r, &transcript[0], false, &mut refused);
    let _ = x.refusal(r, None, b"refused", &mut refused);
    let after_refusal = x
        .emit(r, StreamId(0), b"x", true, &mut Heard::default())
        .unwrap_err();

    let mut envelope = Vec::new();
    Fold {
        located: x.locate(TARGET),
        secure: x.locate("wss://framed.test/p"),
        envelope: x
            .encode_envelope(&[("a", b"1".as_slice())], b"body", &mut envelope)
            .map(|()| envelope),
        accepting,
        adopted,
        detach,
        dialled_frames: dh.frames,
        accepted_frames: lh.frames,
        refused,
        after_refusal,
        unknown_emit: x
            .emit(u64::MAX, StreamId(0), b"x", true, &mut Heard::default())
            .unwrap_err(),
    }
}

/// ONE ROW, WHICHEVER DOOR: every constant the framer declares — read off its decl through the
/// linked door and through the dropped-in door — is the linked type's own row.
#[test]
fn a_linked_and_a_dropped_in_framer_are_one_row() {
    let linked_row = admitted(&exports::TRANSPORT_DECL, "linked-frames");
    assert_eq!(*linked_row.row(), linked::ROW);
    assert_eq!(linked_row.role(), Role::Framer);
    assert_eq!(linked_row.key(), "ws");
    let d = &exports::TRANSPORT_DECL;
    assert!(d.carrier.is_null() && !d.framer.is_null());
    let dropped = dropped_in();
    assert_eq!(*dropped.row(), linked::ROW);
    assert_eq!(dropped.role(), Role::Framer);
    // Two images, two decls: the dropped-in one is not the linked one read twice.
    assert_ne!(dropped.decl(), linked_row.decl());
}

/// THE WITNESS: the linked framer, the framer over its own decl and the dropped-in framer run the
/// script to the SAME record — the accepting side's answer to one fixed transcript byte for byte,
/// and what each side of a real exchange handed up.
#[test]
fn both_doors_frame_alike() {
    let linked = linked_framer();
    let transcript = dial_transcript(&*linked);
    assert!(
        transcript.len() >= 3,
        "the upgrade, the message and the close each crossed: {transcript:?}"
    );
    let honest = fold(&*linked, &*linked, &transcript);
    // The exchange carried both messages whole, each as one frame.
    assert_eq!(
        honest.accepted_frames,
        vec![(0, payload(5, 4_000), true, None, None, None)],
        "the accepting side handed up the dialled message whole"
    );
    assert_eq!(
        honest.dialled_frames,
        vec![(0, payload(11, 2_000), true, None, None, None)],
        "the dialling side handed up the answer whole"
    );
    assert_eq!(honest.detach, TransportError::HandoffMismatch);
    assert_eq!(honest.unknown_emit, TransportError::Closed);
    assert_eq!(honest.after_refusal, TransportError::Closed);
    // A `wss://` target locates as a SECURE authority: the encryption is core's connection
    // security under this framer, never the framer's own.
    assert_eq!(
        honest.secure,
        Ok(Located {
            authority: "framed.test:443".into(),
            secure: true,
            server_name: Some("framed.test".into()),
        })
    );
    assert_eq!(
        honest.located,
        Ok(Located {
            authority: "framed.test:9000".into(),
            secure: false,
            server_name: None,
        })
    );
    assert_eq!(
        fold(
            &*framer_of(admitted(&exports::TRANSPORT_DECL, "linked-frames")),
            &*linked,
            &transcript
        ),
        honest,
        "the framer over its own decl is the linked framer"
    );
    assert_eq!(
        fold(&*framer_of(dropped_in()), &*linked, &transcript),
        honest,
        "a dropped-in framer and the same framer linked frame alike"
    );
}

// ── THE RED ARM ─────────────────────────────────────────────────────────────────────────────────

/// The framer's real slot table.
fn real() -> &'static FramerSlots {
    // SAFETY: ws is a framer, so its decl's framer table is its `'static` table.
    unsafe { &*exports::TRANSPORT_DECL.framer }
}

/// An `emit` slot that flips the first byte of every frame piece, then emits through the real slot.
extern "C-unwind" fn altering_emit(
    state: *mut std::os::raw::c_void,
    framing: u64,
    stream: u64,
    buf: *const u8,
    len: usize,
    end_of_frame: u8,
    out: *const WireFramerOut,
) -> RawWireOutcome {
    let real: FramerEmitFn = real().emit.expect("the framer emits");
    if buf.is_null() || len == 0 {
        return real(state, framing, stream, buf, len, end_of_frame, out);
    }
    // SAFETY: the host's live `len`-byte range for this call.
    let mut bytes = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
    bytes[0] ^= 0x01;
    real(
        state,
        framing,
        stream,
        bytes.as_ptr(),
        bytes.len(),
        end_of_frame,
        out,
    )
}

/// THE RED ARM, kept: the same framer with an `emit` that alters one byte folds DIFFERENTLY — the
/// accepting side's answer to the fixed transcript is no longer the linked framer's.
#[test]
fn a_divergent_framer_is_seen_by_the_fold() {
    static SLOTS: OnceLock<FramerSlots> = OnceLock::new();
    static ALTERED: OnceLock<TransportDecl> = OnceLock::new();
    let slots = SLOTS.get_or_init(|| FramerSlots {
        emit: Some(altering_emit),
        ..*real()
    });
    let altered = ALTERED.get_or_init(|| TransportDecl {
        framer: slots,
        // SAFETY: a byte copy of the live decl; every pointer in it is `'static` image data.
        ..unsafe { core::ptr::read(&exports::TRANSPORT_DECL) }
    });
    let linked = linked_framer();
    let transcript = dial_transcript(&*linked);
    let honest = fold(&*linked, &*linked, &transcript);
    let seen = fold(
        &*framer_of(admitted(altered, "altered-frames")),
        &*linked,
        &transcript,
    );
    assert_ne!(
        seen, honest,
        "the fold must see a framer that changed a byte"
    );
    assert_ne!(
        seen.accepting, honest.accepting,
        "the answered bytes differ"
    );
    // What the altered framer did not emit is untouched: the difference is where the bytes changed.
    assert_eq!(seen.located, honest.located);
    assert_eq!(seen.adopted, honest.adopted);
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

/// #30 (HOT lane, < 1 µs per crossing): the same framer method — an emit on a framing state the
/// framer does not hold, which answers without framing anything — called on the linked framer and
/// on the dropped-in one; the difference is the crossing (the guarded indirect call, the output
/// sink's callbacks, the answer's decode), held to the budget at p50 and p99. Release build:
/// `cargo test --release -p busbar-transport-ws --test conformance -- --ignored --nocapture`.
#[test]
#[ignore = "perf measurement; run in release with --ignored --nocapture"]
fn the_dropped_in_crossing_is_under_a_microsecond() {
    let linked = linked_framer();
    let dropped = framer_of(dropped_in());
    let mut out = Heard::default();
    let mut call = |f: &dyn Framer| {
        let _ = std::hint::black_box(f.emit(
            std::hint::black_box(u64::MAX),
            StreamId(0),
            b"x",
            true,
            &mut out,
        ));
    };
    for _ in 0..2_000 {
        call(&*linked);
        call(&*dropped);
    }
    let direct = timed(50_000, || call(&*linked));
    let crossed = timed(50_000, || call(&*dropped));
    let delta = (
        crossed.0.saturating_sub(direct.0),
        crossed.1.saturating_sub(direct.1),
    );
    println!("#30 transport, ws framer (budget 1000 ns per crossing):");
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
