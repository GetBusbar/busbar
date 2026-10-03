// TRANSITIONAL (NO-TEST-PLUGINS, QUESTIONS CONF-SUITE-DEL): the HOT door's latency rides the example plane's decl (an in-tree plugin) and the plane door's mechanics ride the `plane_door_plugin` fixture door; a hand-built in-test decl/door replaces each, or the published suite's plane script carries it.
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE LOADER'S OWN MECHANICS (`kind: plane`): the decl vocabulary cap over a hand-built
//! decl, the registry's kind gate and ABI window, the HOT door's added latency (`hot_door_latency`,
//! `#[ignore]`d timing), and the plane door through the one dispatcher (`door`).
//!
//! OWNER 2026-10-03 (NO TEST PLUGINS): the example plane's both-ways proof (its compiled-in decl
//! against its dropped-in `cdylib`) is gone from here; a plane proves itself against the published
//! suite (`busbar-plugin-loader`'s `conformance` feature) in its own repo.

use crate::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_example_plane::PLANE_DECL as COMPILED_IN;

/// Locate the `busbar-plane-example` cdylib built into this workspace's target dir (uplifted or
/// under `deps`, newest wins): the DROPPED door `hot_door_latency` times beside the linked one.
fn plane_example_cdylib() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = crate::plugin_library_filename("busbar_plugin_example_plane");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the plane example plugin cdylib is not built under CI: `cargo test --workspace` must \
             build busbar_plane_example (checked both the uplifted target dir and target/deps). \
             Refusing to silently skip the dropped-in door's latency."
        );
    }
    candidate
}

// THE TEST HOST `hot_door_latency` times the door over: `EMPTY` plus the four slots the example
// plane calls, each a counting shim that answers at once, so what is timed is the door and the
// plane, not a host.
mod test_host {
    use busbar_contract::abi::hot::host::{HostCtx, PlaneHostVtable};
    use busbar_contract::abi::hot::pod::{Decision, Facts, FramingDesc, MeterOutcome, Seq, Usage};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Per-slot call counts. `dispatch` is REQUIRED to move all four; `start` moves `CLOCK_NOW` once
    /// more.
    pub static CLOCK_NOW: AtomicU64 = AtomicU64::new(0);
    /// See [`CLOCK_NOW`].
    pub static GOVERN_ADMIT: AtomicU64 = AtomicU64::new(0);
    /// See [`CLOCK_NOW`].
    pub static METER_CHARGE: AtomicU64 = AtomicU64::new(0);
    /// See [`CLOCK_NOW`].
    pub static JOURNAL_APPEND: AtomicU64 = AtomicU64::new(0);

    /// THE MONEY BYTES, READ OFF THE WIRE. What the plane actually wrote into the `Usage`, captured
    /// verbatim so a test can assert the PRICING-BLIND posture (DECISIONS #43/#71/#77(3)) rather
    /// than take the plane's word for it. The `Usage` carries no price field at all (item 577).
    pub static LAST_AMOUNT: AtomicU64 = AtomicU64::new(u64::MAX);

    /// A Unix-nanosecond reading a plane can tell apart from the slot's fail-closed `0`. Fixed rather
    /// than sampled so the shim adds no ambient clock of its own.
    pub const CLOCK_READING: u64 = 1_700_000_000_000_000_000;
    extern "C-unwind" fn clock_now(_host: HostCtx) -> u64 {
        CLOCK_NOW.fetch_add(1, Ordering::SeqCst);
        CLOCK_READING
    }

    extern "C-unwind" fn govern_admit(_host: HostCtx, facts: *const Facts) -> Decision {
        GOVERN_ADMIT.fetch_add(1, Ordering::SeqCst);
        if facts.is_null() {
            return Decision::Deny; // fail-closed, exactly as the real host does
        }
        Decision::Admit
    }

    extern "C-unwind" fn meter_charge(_host: HostCtx, usage: *const Usage) -> MeterOutcome {
        METER_CHARGE.fetch_add(1, Ordering::SeqCst);
        if usage.is_null() {
            return MeterOutcome::Rejected;
        }
        // SAFETY: a non-null `usage` is a live, initialized `Usage` for the call (ABI discipline).
        let u = unsafe { &*usage };
        LAST_AMOUNT.store(u.amount, Ordering::SeqCst);
        MeterOutcome::Charged
    }

    extern "C-unwind" fn journal_append(
        _host: HostCtx,
        _scope: u32,
        content_ptr: *const u8,
        _content_len: usize,
        framing: *const FramingDesc,
    ) -> Seq {
        let n = JOURNAL_APPEND.fetch_add(1, Ordering::SeqCst);
        if content_ptr.is_null() || framing.is_null() {
            return Seq::NONE; // fail-closed, as the real host does
        }
        Seq(n + 1)
    }

    /// The instrumented host: `EMPTY` (every capability withheld) plus exactly the four slots the
    /// example plane requires. Granting only what is needed is the point — a plane that called a
    /// fifth would hit a `None` and refuse, which is the behaviour, not a bug.
    pub fn vtable() -> PlaneHostVtable {
        PlaneHostVtable {
            clock_now: Some(clock_now),
            govern_admit: Some(govern_admit),
            meter_charge: Some(meter_charge),
            journal_append: Some(journal_append),
            ..PlaneHostVtable::EMPTY
        }
    }
}

/// A plane that declares a vocabulary length far larger than its real buffer must be REFUSED at load,
/// never sliced: `read_vocab` reads each `*_len` verbatim from the (third-party) decl, so an
/// unbounded `from_raw_parts` would over-read past the real allocation — an OOB read in the HOST's
/// address space. Exercises `read_vocab` directly with the hostile short-buffer/huge-length shape.
#[test]
fn oversize_plane_vocab_length_is_refused_not_over_read() {
    use busbar_contract::abi::hot::PlaneDecl;
    use busbar_contract::abi::AbiPreamble;

    // A one-byte real buffer paired with a length past the cap — the hostile shape a lying decl uses.
    let small = b"x";
    let decl = PlaneDecl {
        abi: AbiPreamble::CURRENT,
        size: core::mem::size_of::<PlaneDecl>() as u32,
        version: busbar_contract::abi::ABI_MINOR,
        name_ptr: small.as_ptr(),
        name_len: super::MAX_PLANE_VOCAB_LEN + 1,
        section_key_ptr: core::ptr::null(),
        section_key_len: 0,
        scope_ptr: core::ptr::null(),
        scope_len: 0,
        label_ptr: core::ptr::null(),
        label_len: 0,
        provided_carriers: 0,
        _reserved: 0,
        config_validate: None,
        build: None,
        hydrate: None,
        start: None,
        admin_routes: None,
        openapi: None,
        dispatch: None,
        ..PlaneDecl::STUB
    };
    let honoured =
        busbar_contract::abi::honoured_size(decl.size, core::mem::size_of::<PlaneDecl>());
    let decl_ptr: *const PlaneDecl = &decl;
    let err = super::read_vocab(decl_ptr, honoured, super::Vocab::Name, "hostile")
        .expect_err("an oversize vocabulary length must be refused, never sliced");
    assert!(
        err.contains("exceeding") && err.contains(&super::MAX_PLANE_VOCAB_LEN.to_string()),
        "expected a cap-refusal naming the limit, got: {err}"
    );

    // A within-cap vocabulary still reads back correctly — the fix is a cap, not a blanket refusal.
    let ok = PlaneDecl {
        name_len: small.len(),
        ..decl
    };
    let ok_ptr: *const PlaneDecl = &ok;
    let name = super::read_vocab(ok_ptr, honoured, super::Vocab::Name, "ok")
        .expect("a within-cap vocabulary reads back");
    assert_eq!(name, "x");
}

// ── THE REGISTRY'S PLANE GATES (DECISIONS #26 S4): the kind gate and the ABI window, over a signed
// tarball whose bytes are never loaded.

/// A `kind: plane` manifest, with `abi_version` on the airlock-minor axis `supported_abi("plane")`
/// gates against (`[1, ABI_MINOR]`). `sha256`/`signature` are filled by the caller (via `sign`).
fn plane_manifest(name: &str, alias: &str, publisher: &str) -> Manifest {
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "plane".into(),
        version: "1.6.0".into(),
        publisher: publisher.into(),
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
        statement: None,
    }
}

/// The DEFAULT posture-A policy: a first-party release key is held; NO unsigned/third-party opt-in.
fn first_party_only_policy(release: &SigningKey) -> TrustPolicy {
    TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: "1.6.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    }
}

fn plane_tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-plane-trust-{}-{tag}-{}",
        std::process::id(),
        crate::stage::next_seq()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_plane_tarball(dir: &std::path::Path, file: &str, m: &Manifest, lib: &[u8]) {
    let bytes = crate::tarball::package(m, "libbusbar_plugin_example_plane.so", lib).unwrap();
    std::fs::write(dir.join(file), bytes).unwrap();
}

/// Kind gating over the pipeline: a signed NON-plane artifact resolves but cannot serve as a plane —
/// `open_plane` rejects on the KIND gate before ever attempting the HOT-ABI load. Mirrors
/// `open_store_refuses_non_store_kind`.
#[test]
fn open_plane_refuses_non_plane_kind() {
    let release = SigningKey::from_bytes(&[1u8; 32]);
    let dir = plane_tmpdir("kind-gate");
    let mut m = plane_manifest("busbar-store-gamma-plugin", "gamma", "busbar");
    m.kind = "store".into();
    m.abi_version = busbar_contract::abi::cold::ABI_VERSION; // store-admissible so the KIND gate is what fires
    let m = sign(&release, m, b"store lib");
    write_plane_tarball(&dir, "store.tar.gz", &m, b"store lib");

    let reg =
        crate::registry::scan_and_validate(&dir, &first_party_only_policy(&release)).expect("scan");
    let err = reg.open_plane("gamma").map(|_| ()).unwrap_err();
    assert!(
        err.contains("kind 'store'") && err.contains("not 'plane'"),
        "the kind gate must fire before any load: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `supported_abi("plane")` gates a plane's manifest `abi_version` against the airlock-minor axis.
#[test]
fn plane_supported_abi_covers_the_airlock_minor() {
    let range = crate::registry::supported_abi("plane");
    assert_eq!(range, &[1, busbar_contract::abi::ABI_MINOR]);
    // The five cold kinds still resolve; an unknown kind is still empty.
    assert!(!crate::registry::supported_abi("store").is_empty());
    assert!(crate::registry::supported_abi("nonsense").is_empty());
}

mod hot_door_latency {
    //! THE HOT DOOR'S ADDED LATENCY, MEASURED (#30: the HOT lane's per-request crossing stays under
    //! 1 µs). Per request, for the example plane LINKED and DROPPED IN:
    //!
    //! * `plane` — the plane's own `dispatch` over a work item built once (head, reply channel, the
    //!   dispatch's handles current): the plane's work and its four host calls, nothing of the door;
    //! * `door` — [`ServedPlane::answer`], the whole door: the work item, the reply channel, the emit
    //!   sink, the current-dispatch handles and the reply read back. `door - plane` is the #30 crossing;
    //! * `inline` / `hop` — the door driven from a tokio worker, inline on the worker or through
    //!   `spawn_blocking` (the thread hop the root's answer took before the plane stated whether its
    //!   dispatch blocks). `hop - inline` is what the hop adds.
    //!
    //! Timing is meaningful only in an optimized build, so the measurement is `#[ignore]`d and run as
    //! `cargo test --release -p busbar-plugin-loader --lib hot_door_latency -- --ignored --nocapture`;
    //! it asserts the crossing's p50 is under 1µs and prints every figure.

    use crate::carrier::{Current, RequestHead};
    use busbar_contract::abi::hot::host::{HostCtx, PlaneHostVtable};
    use busbar_contract::abi::hot::pod::StatusClass;
    use busbar_contract::abi::hot::{EmitHandle, EmitKind, InboundHandle, WorkItem};
    use std::time::Instant;

    /// The conformance suite's host: `EMPTY` plus the four slots the example plane calls, each answering
    /// at once (a counter bump), so what is timed is the door and the plane, not a host.
    fn instant_host() -> &'static PlaneHostVtable {
        Box::leak(Box::new(super::test_host::vtable()))
    }

    const WARM: usize = 2_000;
    const SAMPLES: usize = 50_000;

    /// p50 and p99 of `samples`, in nanoseconds.
    fn percentiles(mut samples: Vec<u64>) -> (u64, u64) {
        samples.sort_unstable();
        (
            samples[samples.len() / 2],
            samples[samples.len() * 99 / 100],
        )
    }

    /// Time `f` once per sample, after a warm-up.
    fn timed(mut f: impl FnMut()) -> (u64, u64) {
        for _ in 0..WARM {
            f();
        }
        let samples = (0..SAMPLES)
            .map(|_| {
                let at = Instant::now();
                f();
                at.elapsed().as_nanos() as u64
            })
            .collect();
        percentiles(samples)
    }

    const HEADERS: [(&[u8], &[u8]); 3] = [
        (b"content-type", b"application/json"),
        (b"accept", b"*/*"),
        (b"user-agent", b"bench"),
    ];

    fn head() -> RequestHead<'static> {
        RequestHead {
            method: b"POST",
            path: b"/example",
            query: b"",
            headers: &HEADERS,
        }
    }

    /// The figures for one door: `(plane, door, inline, hop)`, each `(p50, p99)` ns.
    type Figures = [(u64, u64); 4];

    fn measure(plane: &'static crate::DynPlane, host: &'static PlaneHostVtable) -> Figures {
        let served: &'static crate::ServedPlane = Box::leak(Box::new(
            plane
                .serve(
                    host,
                    br#"{"greeting":"hi"}"#,
                    Some("https://gw.example.com"),
                )
                .expect("builds"),
        ));
        let inbound = b"{\"ping\":1}";
        let head = head();

        // The plane alone: one work item, built once, its handles current for every call.
        let mut reply = vec![0u8; crate::MAX_PLANE_REPLY_LEN];
        let mut written = 0usize;
        let mut work = WorkItem::new(
            InboundHandle::finite_buffer(inbound),
            EmitHandle::new(EmitKind::Reply, 1),
        )
        .with_host(host, HostCtx::NULL)
        .with_reply(&mut reply, &mut written);
        work.head = core::ptr::from_ref(&head).cast();
        work.head_read = Some(crate::carrier::head_read);
        let current = Current::enter(work.head, 1);
        let alone = timed(|| {
            // SAFETY: the state `serve` built, and a work item whose borrows outlive the call.
            let class = unsafe { plane.dispatch(served.raw.ptr, &work) };
            assert_eq!(class, StatusClass::Ok);
        });
        drop(current);

        let door = timed(|| {
            let reply = served.answer(host, HostCtx::NULL, Some(&head), inbound, None);
            assert_eq!(reply.class, StatusClass::Ok);
        });

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        let run = |hop: bool| -> (u64, u64) {
            rt.block_on(async move {
                let one = || async move {
                    let at = Instant::now();
                    let class = if hop {
                        tokio::task::spawn_blocking(move || {
                            served
                                .answer(host, HostCtx::NULL, Some(&self::head()), inbound, None)
                                .class
                        })
                        .await
                        .expect("joins")
                    } else {
                        served
                            .answer(host, HostCtx::NULL, Some(&self::head()), inbound, None)
                            .class
                    };
                    assert_eq!(class, StatusClass::Ok);
                    at.elapsed().as_nanos() as u64
                };
                for _ in 0..WARM {
                    one().await;
                }
                let mut samples = Vec::with_capacity(SAMPLES);
                for _ in 0..SAMPLES {
                    samples.push(one().await);
                }
                percentiles(samples)
            })
        };
        let inline = run(false);
        let hop = run(true);
        [alone, door, inline, hop]
    }

    #[test]
    #[ignore = "timing: run in release with --ignored (see the module docs)"]
    fn hot_door_latency() {
        let host = instant_host();
        let linked: &'static crate::DynPlane = Box::leak(Box::new(
            crate::link_plane(&super::COMPILED_IN, "linked").expect("links"),
        ));
        let mut rows = vec![("linked", measure(linked, host))];
        if let Some(lib) = super::plane_example_cdylib() {
            let dropped: &'static crate::DynPlane =
                Box::leak(Box::new(crate::load_plane(&lib).expect("loads")));
            rows.push(("dropped", measure(dropped, host)));
        }
        for (door, [plane, answer, inline, hop]) in &rows {
            eprintln!(
                "{door:8} plane p50/p99 {}/{} ns · door {}/{} · crossing (door-plane) {}/{} · \
                 inline {}/{} · hop {}/{} · hop added {}/{}",
                plane.0,
                plane.1,
                answer.0,
                answer.1,
                answer.0.saturating_sub(plane.0),
                answer.1.saturating_sub(plane.1),
                inline.0,
                inline.1,
                hop.0,
                hop.1,
                hop.0.saturating_sub(inline.0),
                hop.1.saturating_sub(inline.1),
            );
            assert!(
                answer.0.saturating_sub(plane.0) < 1_000,
                "{door}: the #30 crossing's p50 is {} ns, over 1µs",
                answer.0.saturating_sub(plane.0)
            );
        }
    }
}

/// **THE PLANE DOOR, BOTH WAYS.** A minimal plane built with the SDK's `plugin_door!`
/// (`tests/fixtures/plane_door_plugin.rs`) is loaded LINKED (its `door` function, through
/// [`load_linked`](crate::dispatch::load_linked)) and DROPPED (the `plane_door_plugin` example
/// `cdylib`, through [`load_dropped`](crate::dispatch::load_dropped)), and ONE script drives every
/// plane op through the loader's plane kind, each answer judged by the kind's own check: `open`
/// and `refresh` publish a snapshot, `arrive`, `on_piece` (caller, ATTEMPT, far end, a session's
/// unsolicited output), `refusal`, `serve` and `project` fill the host's buffers, `drive` names the
/// ready session, `cancel` answers a disposition and `tick` its next tick. The two transcripts must
/// be identical.
///
/// RED ARM, kept: the same plane with the door shape the macro used to build — an `open` over the
/// lifecycle's own `OpenIn`/`OpenOut` — publishes no snapshot, and the loader FAULTs its `open`.
mod door {
    use std::mem::zeroed;
    use std::sync::Arc;

    use busbar_contract::abi::hook::{SignalEntry, SIGNAL_TAG_U64};
    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, Span, BLOB_OCTETS};
    use busbar_contract::abi::mechanism::door::Door;
    use busbar_contract::abi::mechanism::lifecycle::{
        slot as life, CancelIn, CancelOut, GenIn, OpenIn, OpenOut, RefreshIn, TickIn, TickOut,
        ValidateIn,
    };
    use busbar_contract::abi::plane::{
        self, slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneDriveIn,
        PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot, ProjectIn,
        ProjectOut, RecordWrite, RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount,
        CANCEL_ABORTED, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL,
        MARK_GATE_REJECTED, PIECE_LAST, REFUSAL_GATE, UNITS_REPORTED, VERDICT_OK,
    };
    use busbar_contract::abi::sdk::door::{kind_op, Lifecycle, Slot};

    use crate::dispatch::kinds::plane::Plane;
    use crate::dispatch::{
        in_head, load_dropped, load_linked, out_head, rendering_of, Adopter, Bind, Frame,
        LinkedRow, NoSink, Plugin,
    };
    use crate::plane_door_plugin as plug;

    fn z<T>() -> T {
        // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
        unsafe { zeroed() }
    }

    fn bind() -> Bind {
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: Adopter::unwatched(),
            conns: None,
        }
    }

    fn octets(b: &'static [u8]) -> Blob {
        Blob {
            ptr: b.as_ptr(),
            len: b.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        }
    }

    fn text(b: &'static [u8]) -> AbiStr {
        AbiStr {
            ptr: b.as_ptr(),
            len: b.len(),
        }
    }

    /// `len` bytes of a host buffer, as text.
    fn at(buf: &[u8], offset: usize, len: usize) -> String {
        String::from_utf8_lossy(&buf[offset..offset + len]).into_owned()
    }

    fn arena(buf: &[u8], s: Span) -> String {
        at(buf, s.offset as usize, s.len as usize)
    }

    /// A published snapshot, read while its generation is live.
    fn snapshot(p: *const PlaneSnapshot) -> String {
        assert!(!p.is_null(), "a READY open/refresh publishes a snapshot");
        // SAFETY: the plugin's generation data, valid until `retire` of its generation.
        let s = unsafe { &*p };
        // SAFETY: the snapshot names `claims_len` claims.
        let claim = unsafe { &*s.claims };
        // SAFETY: the claim's target is `'static` plugin text.
        let target = unsafe { std::slice::from_raw_parts(claim.target.ptr, claim.target.len) };
        format!(
            "gen={} claims={} target={} routes={}",
            s.generation,
            s.claims_len,
            String::from_utf8_lossy(target),
            s.admin_routes_len
        )
    }

    fn linked() -> Plugin<Plane> {
        let row = LinkedRow::of(plug::door).expect("the linked plane states its Statement");
        load_linked::<Plane>(&row, bind()).expect("the linked plane door loads")
    }

    /// The example `cdylib` in this target dir (`cargo test` builds examples). Under CI a missing
    /// artifact is a failure, never a skip.
    fn dropped() -> Option<Plugin<Plane>> {
        let exe = std::env::current_exe().ok()?;
        let path = exe.parent()?.parent()?.join("examples").join(format!(
            "{}plane_door_plugin{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        ));
        assert!(
            path.exists() || std::env::var_os("CI").is_none(),
            "the plane_door_plugin example cdylib is not built under CI; a both-ways proof must not skip"
        );
        // The signed manifest's rendering: the linked rlib's door, the same crate.
        let stated = rendering_of(plug::door).expect("the plane renders its Statement");
        path.exists().then(|| {
            load_dropped::<Plane>(&path, &stated, bind()).expect("the dropped plane door loads")
        })
    }

    fn open_frame(generation: u64) -> Frame<PlaneOpenIn, PlaneOpenOut> {
        let mut i: PlaneOpenIn = z();
        i.open.head = in_head();
        i.open.generation = generation;
        let mut o: PlaneOpenOut = z();
        o.open.head = out_head();
        Frame::new(i, o)
    }

    /// A zeroed `on_piece` frame over the host's buffers.
    struct Piece {
        reply: [u8; 64],
        units: [UnitCount; 2],
        records: [RecordWrite; 2],
        fields: [OutField; 2],
        arena: [u8; 64],
    }

    impl Piece {
        fn new() -> Box<Self> {
            Box::new(Self {
                reply: [0; 64],
                units: [z(); 2],
                records: [z(); 2],
                fields: [z(); 2],
                arena: [0; 64],
            })
        }

        fn call(
            &mut self,
            p: &Plugin<Plane>,
            from: u32,
            bytes: &'static [u8],
            attempt: (u32, &'static [u8]),
        ) -> (Outcome, OnPieceOut) {
            let mut i: OnPieceIn = z();
            i.head = in_head();
            i.from = from;
            i.flags = PIECE_LAST;
            i.stream = 5;
            i.bytes = octets(bytes);
            (i.reply_buf, i.reply_cap) = (self.reply.as_mut_ptr(), self.reply.len());
            (i.units_buf, i.units_cap) = (self.units.as_mut_ptr(), self.units.len());
            (i.records_buf, i.records_cap) = (self.records.as_mut_ptr(), self.records.len());
            (i.fields_buf, i.fields_cap) = (self.fields.as_mut_ptr(), self.fields.len());
            (i.arena_buf, i.arena_cap) = (self.arena.as_mut_ptr(), self.arena.len());
            (i.attempt_no, i.member) = (attempt.0, text(attempt.1));
            let mut o: OnPieceOut = z();
            o.head = out_head();
            let mut f = Frame::new(i, o);
            let c = p.call(slot::ON_PIECE, &mut f);
            (c.outcome, f.out)
        }
    }

    /// THE SCRIPT: every plane op once (arrive's short answer twice), each answer read back.
    fn script(p: &Plugin<Plane>) -> Vec<String> {
        let mut t = Vec::new();

        let mut v = Frame::new(
            ValidateIn {
                head: in_head(),
                settings: octets(plug::BAD_SETTINGS),
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            out_head(),
        );
        t.push(format!(
            "validate bad {:?}",
            p.call(life::VALIDATE, &mut v).outcome
        ));
        v.input.settings = octets(b"{}");
        t.push(format!(
            "validate {:?}",
            p.call(life::VALIDATE, &mut v).outcome
        ));

        let mut o = open_frame(1);
        let c = p.call(life::OPEN, &mut o);
        t.push(format!("open {:?} {}", c.outcome, snapshot(o.out.snapshot)));

        for s in [slot::HYDRATE, slot::START] {
            let mut g = Frame::new(
                GenIn {
                    head: in_head(),
                    generation: 1,
                },
                out_head(),
            );
            t.push(format!("{s} {:?}", p.call(s, &mut g).outcome));
        }

        // `arrive`: the admission estimate, then the short answer on a zero-capacity buffer.
        let mut units = [z::<UnitCount>(); 2];
        let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
        (a.input.head, a.out.head) = (in_head(), out_head());
        a.input.body = octets(b"hello");
        (a.input.units_buf, a.input.units_cap) = (units.as_mut_ptr(), units.len());
        let c = p.call(slot::ARRIVE, &mut a);
        t.push(format!(
            "arrive {:?} units={} amount={} op_class={}",
            c.outcome, a.out.units_written, units[0].amount, a.out.op_class
        ));
        a.input.units_cap = 0;
        let c = p.call(slot::ARRIVE, &mut a);
        t.push(format!(
            "arrive short {:?} needed={} recall={}",
            c.outcome,
            a.out.units_needed,
            c.recall.is_some()
        ));

        // `on_piece` from the caller opens a session; `drive` names it; the kernel collects it.
        let mut piece = Piece::new();
        let (c, _) = piece.call(p, FROM_CALLER, b"hi", (0, b""));
        t.push(format!("on_piece caller {c:?}"));
        let mut sessions = [0_u64; 4];
        let mut d: Frame<PlaneDriveIn, PlaneDriveOut> = Frame::new(z(), z());
        (d.input.drive.head, d.out.head) = (in_head(), out_head());
        (d.input.sessions_buf, d.input.sessions_cap) = (sessions.as_mut_ptr(), sessions.len());
        let c = p.call(life::DRIVE, &mut d);
        t.push(format!(
            "drive {:?} sessions={} first={}",
            c.outcome, d.out.sessions_written, sessions[0]
        ));
        let (c, out) = piece.call(p, FROM_KERNEL, b"", (0, b""));
        t.push(format!(
            "on_piece session {c:?} {}",
            at(&piece.reply, 0, out.emitted as usize)
        ));

        // An ATTEMPT piece: the request bound for the member, verb and target in the arena.
        let (c, out) = piece.call(p, FROM_KERNEL, b"", (1, b"m1"));
        t.push(format!(
            "on_piece attempt {c:?} {} {} {} to_far_end={}",
            arena(&piece.arena, out.verb),
            arena(&piece.arena, out.target),
            at(&piece.reply, 0, out.emitted as usize),
            out.flags & EMIT_TO_FAR_END != 0
        ));

        // The far end's answer: echoed, with a count, a record and a field.
        let (c, out) = piece.call(p, FROM_FAR_END, b"answer", (0, b""));
        t.push(format!(
            "on_piece far_end {c:?} {} status={} done={} verdict_ok={} units={}:{}:{} \
             record={}={} field={}={}",
            at(&piece.reply, 0, out.emitted as usize),
            out.reply_status,
            out.flags & EMIT_DONE != 0,
            out.verdict == VERDICT_OK,
            out.units_written,
            piece.units[0].amount,
            piece.units[0].source == UNITS_REPORTED,
            arena(&piece.arena, piece.records[0].key),
            arena(&piece.arena, piece.records[0].value),
            arena(&piece.arena, piece.fields[0].name),
            arena(&piece.arena, piece.fields[0].value),
        ));

        // `refusal` in the plane's dialect.
        let (mut reply, mut fields, mut buf) = ([0_u8; 16], [z::<OutField>(); 1], [0_u8; 32]);
        let mut r: Frame<RefusalIn, RefusalOut> = Frame::new(z(), z());
        (r.input.head, r.out.head) = (in_head(), out_head());
        (r.input.cause, r.input.status, r.input.text) = (REFUSAL_GATE, 403, text(b"denied"));
        (r.input.reply_buf, r.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (r.input.fields_buf, r.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (r.input.arena_buf, r.input.arena_cap) = (buf.as_mut_ptr(), buf.len());
        let c = p.call(slot::REFUSAL, &mut r);
        t.push(format!(
            "refusal {:?} {} gate={} field={}",
            c.outcome,
            at(&reply, 0, r.out.reply_written as usize),
            r.out.marker == MARK_GATE_REJECTED,
            arena(&buf, fields[0].name)
        ));

        // `serve` one admin route.
        let mut reply = [0_u8; 16];
        let mut s: Frame<ServeIn, ServeOut> = Frame::new(z(), z());
        (s.input.head, s.out.head) = (in_head(), out_head());
        (s.input.reply_buf, s.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        let c = p.call(slot::SERVE, &mut s);
        t.push(format!(
            "serve {:?} {} {}",
            c.outcome,
            s.out.status,
            at(&reply, 0, s.out.reply_written as usize)
        ));

        // `project` into the hook kind's request view.
        let (mut signals, mut buf) = ([z::<SignalEntry>(); 2], [0_u8; 32]);
        let mut j: Frame<ProjectIn, ProjectOut> = Frame::new(z(), z());
        (j.input.head, j.out.head) = (in_head(), out_head());
        j.input.body = octets(b"abc");
        (j.input.signals_buf, j.input.signals_cap) = (signals.as_mut_ptr(), signals.len());
        (j.input.arena_buf, j.input.arena_cap) = (buf.as_mut_ptr(), buf.len());
        let c = p.call(slot::PROJECT, &mut j);
        // SAFETY: the signal's tag is checked to name `u64_` first.
        let value = (signals[0].tag == SIGNAL_TAG_U64).then(|| unsafe { signals[0].value.u64_ });
        t.push(format!(
            "project {:?} signals={} value={value:?} body={}",
            c.outcome,
            j.out.view.signals_len,
            arena(&buf, j.out.body)
        ));

        let mut k = Frame::new(
            TickIn {
                head: in_head(),
                now_ns: 1_000,
            },
            TickOut {
                head: out_head(),
                next_tick_ns: 0,
            },
        );
        let c = p.call(life::TICK, &mut k);
        t.push(format!("tick {:?} next={}", c.outcome, k.out.next_tick_ns));

        let mut x: Frame<CancelIn, CancelOut> = Frame::new(z(), z());
        (x.input.head, x.out.head) = (in_head(), out_head());
        let c = p.call(life::CANCEL, &mut x);
        t.push(format!(
            "cancel {:?} aborted={}",
            c.outcome,
            x.out.disposition == CANCEL_ABORTED
        ));

        let mut f: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
        (f.input.head, f.out.head) = (in_head(), out_head());
        f.input.generation = 2;
        let c = p.call(life::REFRESH, &mut f);
        t.push(format!(
            "refresh {:?} {}",
            c.outcome,
            snapshot(f.out.snapshot)
        ));

        let mut g = Frame::new(
            GenIn {
                head: in_head(),
                generation: 1,
            },
            out_head(),
        );
        t.push(format!("retire {:?}", p.call(life::RETIRE, &mut g).outcome));
        let mut e = Frame::new(in_head(), out_head());
        t.push(format!("close {:?}", p.call(life::CLOSE, &mut e).outcome));
        t
    }

    /// The transcript every rule requires, linked or dropped.
    const EXPECTED: &[&str] = &[
        "validate bad Refused",
        "validate Ready",
        "open Ready gen=1 claims=1 target=/echo routes=0",
        "13 Ready",
        "14 Ready",
        "arrive Ready units=1 amount=5 op_class=0",
        "arrive short Failed needed=1 recall=true",
        "on_piece caller Ready",
        "drive Ready sessions=1 first=5",
        "on_piece session Ready ping",
        "on_piece attempt Ready POST /up m1 to_far_end=true",
        "on_piece far_end Ready answer status=200 done=true verdict_ok=true units=1:6:true \
         record=k=v field=x-plane=door",
        "refusal Ready denied gate=false field=x-refusal",
        "serve Ready 200 ok",
        "project Ready signals=1 value=Some(3) body=abc",
        "tick Ready next=1001000",
        "cancel Ready aborted=true",
        "refresh Ready gen=2 claims=1 target=/echo routes=1",
        "retire Ready",
        "close Ready",
    ];

    #[test]
    fn a_macro_built_plane_answers_every_op_the_same_linked_and_dropped() {
        let linked = script(&linked());
        assert_eq!(linked, EXPECTED, "the linked plane door");
        if let Some(p) = dropped() {
            assert_eq!(script(&p), linked, "the dropped plane door");
        }
    }

    /// The lifecycle's own `open`: an `OpenOut` with an instance and nowhere to put a snapshot.
    struct LifecycleOpen;
    impl Slot for LifecycleOpen {
        type In = OpenIn;
        type Out = OpenOut;
        fn call(_: *mut std::ffi::c_void, _: &OpenIn, out: &mut OpenOut) -> Outcome {
            out.instance = std::ptr::NonNull::<u8>::dangling().as_ptr().cast();
            Outcome::Ready
        }
    }

    /// A call capture for the hand-built table entry below: one slot per thread, as `plugin_door!`
    /// expands for a plugin's own image.
    struct TestCapture;
    impl busbar_contract::abi::sdk::capture::CaptureHome for TestCapture {
        fn with<R>(f: impl FnOnce(&mut busbar_contract::abi::sdk::capture::CaptureSlot) -> R) -> R {
            thread_local! {
                static SLOT: std::cell::RefCell<busbar_contract::abi::sdk::capture::CaptureSlot> =
                    std::cell::RefCell::new(busbar_contract::abi::sdk::capture::CaptureSlot::new());
            }
            SLOT.with(|s| f(&mut s.borrow_mut()))
        }
    }

    /// The plane door with `open` over the lifecycle's own structs: the shape `plugin_door!` gave
    /// every plane before the kind stated its lifecycle.
    extern "C" fn lifecycle_open_door() -> *const Door {
        // SAFETY: the macro's `'static` door and its plane table.
        let (d, ops) = unsafe {
            let d = &*plug::door();
            (d, *d.ops.cast::<plane::Ops>())
        };
        let mut ops = ops;
        ops.head.open = kind_op::<Lifecycle, LifecycleOpen, TestCapture, { life::OPEN }>();
        let ops: &'static plane::Ops = Box::leak(Box::new(ops));
        Box::leak(Box::new(Door {
            ops: std::ptr::from_ref(ops).cast(),
            ..*d
        }))
    }

    #[test]
    fn red_a_plane_open_over_the_lifecycle_structs_publishes_no_snapshot_and_faults() {
        let row = LinkedRow::of(lifecycle_open_door).expect("the door states its Statement");
        let red = load_linked::<Plane>(&row, bind()).expect("the door loads");
        let mut o = open_frame(1);
        assert_eq!(red.call(life::OPEN, &mut o).outcome, Outcome::Fault);
        assert!(o.out.snapshot.is_null(), "no snapshot reached the host");

        let green = linked();
        let mut o = open_frame(1);
        assert_eq!(green.call(life::OPEN, &mut o).outcome, Outcome::Ready);
        assert!(!o.out.snapshot.is_null());
        let mut e = Frame::new(in_head(), out_head());
        assert_eq!(green.call(life::CLOSE, &mut e).outcome, Outcome::Ready);
    }

    /// RED: the host's copy of a generation snapshot survives the plugin's next refresh and the
    /// retire of its generation. The copy is taken inside the READY crossing that published it
    /// (`Plugin<Plane>::open`/`refresh`), so after the plugin has published generation 2 and
    /// dropped generation 1's memory, the host still reads generation 1 exactly as it was published.
    #[test]
    fn red_the_hosts_snapshot_copy_survives_the_plugins_next_refresh() {
        for p in [Some(linked()), dropped()].into_iter().flatten() {
            let mut o = open_frame(1);
            let (c, first) = p.open(&mut o);
            assert_eq!(c.outcome, Outcome::Ready);
            let first = first.expect("a READY open's snapshot is copied");
            let published = first.clone();
            assert_eq!(first.generation, 1);
            assert_eq!(first.claims.len(), 1);
            assert_eq!(first.claims[0].target, "/echo");
            assert!(first.admin_routes.is_empty());

            let mut r: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
            (r.input.head, r.out.head) = (in_head(), out_head());
            r.input.generation = 2;
            let (c, second) = p.refresh(&mut r);
            assert_eq!(c.outcome, Outcome::Ready);
            let second = second.expect("a READY refresh's snapshot is copied");
            assert_eq!((second.generation, second.admin_routes.len()), (2, 1));

            let mut g = Frame::new(
                GenIn {
                    head: in_head(),
                    generation: 1,
                },
                out_head(),
            );
            assert_eq!(p.call(life::RETIRE, &mut g).outcome, Outcome::Ready);
            assert_eq!(first, published, "generation 1's copy outlives its retire");
        }
    }
}
