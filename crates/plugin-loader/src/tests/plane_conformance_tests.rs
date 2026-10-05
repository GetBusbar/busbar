// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DROP-IN CONFORMANCE for `kind: plane` — the plane analogue of the store proof's over-the-ABI
//! round trips (`DECISIONS #2/#11/#26 S4`: a plugin is a plugin, both-ways for EVERY kind incl. plane).
//!
//! `busbar-plane-example` is a `["cdylib", "rlib"]` crate, so these tests hold BOTH forms of the SAME
//! plane at once: the COMPILED-IN reference (`busbar_plane_example::PLANE_DECL`, linked via the rlib)
//! and the DROPPED-IN artifact (the `cdylib` on disk, loaded through [`crate::load_plane`] over the
//! HOT-tier ABI). The first test proves the two decls are byte-identical at the vocabulary / carrier /
//! preamble surface — "loads identically compiled-in vs dropped-in". The rest drive the dropped-in
//! plane end to end (build → hydrate → start → dispatch) to prove it is a LIVE plane, not just a decl.
//!
//! ## THE SEAM IS CROSSED IN BOTH DIRECTIONS, AND THE TESTS CAN TELL
//!
//! These drives hand the plane a REAL, non-EMPTY [`PlaneHostVtable`] (see `test_host`) and then assert
//! HOW MANY TIMES the plane called back through it. That is deliberate: the plane ABI's whole claim is
//! that a dropped-in plane and a compiled-in one are the same thing, and a test that only checked
//! `dispatch` returned `Ok` could not tell a plane that RIDES the host from one that merely HOLDS the
//! pointer. Three shapes make the difference observable, and each of them FAILS if the crossing stops
//! happening:
//!
//! * the POSITIVE drive asserts exact per-slot call counts (`assert_eq!(…, 1)`, not `> 0`);
//! * the EMPTY-host drive asserts the plane REFUSES when the table grants nothing;
//! * the PER-SLOT drive withdraws exactly one of the four granted slots at a time and asserts the
//!   plane refuses each time, naming the withdrawn slot — which is what proves it calls each one.
//!
//! This lane retires with the old loader; the door lane's crossing into the kernel's own host
//! services is proven by the composition root (`crates/busbar/src/root/tests/plane_rider.rs`).
//! It cannot be crossed from here: this crate may not name `busbar-kernel` (that edge is the
//! core→loader→kernel cycle the 1.6.0 W4.a chunk-0 split broke), so the two halves of the proof live on
//! the two sides of that seam, on purpose.

use crate::sign::{sha256_hex, sign, Manifest, SigningKey, TrustPolicy};
use busbar_contract::abi::hot::host::HostCtx;
use busbar_contract::abi::hot::pod::StatusClass;
use busbar_contract::abi::hot::{
    EmitHandle, InboundHandle, IngressCarrier, PlaneHostVtable, WorkItem,
};
use busbar_contract::abi::AbiPreamble;
use busbar_plugin_example_plane::PLANE_DECL as COMPILED_IN;

/// Locate the REAL `busbar-plane-example` cdylib built into this workspace's target dir (uplifted or
/// under `deps`, newest wins). Mirrors `store_proof_plugin_path()` in `test_support.rs`.
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
             Refusing to silently skip the ONLY both-ways proof for kind:plane."
        );
    }
    candidate
}

/// Read one borrowed vocabulary range from the COMPILED-IN decl into an owned string (the same shape
/// `wire_up_plane` materialises the dropped-in side to, so the two are directly comparable).
fn vocab(ptr: *const u8, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    // SAFETY: the const's vocabulary points at this crate's own `'static` byte strings.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes).unwrap().to_string()
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE TEST HOST — a REAL, non-EMPTY `PlaneHostVtable` that COUNTS what the plane calls.
//
// `busbar-plugin-loader` cannot name `busbar-kernel` (that edge is the core→loader→kernel cycle the
// 1.6.0 W4.a chunk-0 split exists to break); the door lane's real-host crossing is the composition
// root's (`crates/busbar/src/root/tests/plane_rider.rs`). What belongs HERE is the
// half the loader owns: that the artifact the LOADER produced — dlopened, trust-verified, resolved
// through the registry — actually calls back through the table it was handed, and how many times.
//
// So every slot below is a counting shim. It is not a stand-in for the host: it is an INSTRUMENT on
// the seam. A `dispatch` that returned `Ok` without touching the table would leave every counter at
// zero and red these tests, which is the property that makes them worth running.
// ─────────────────────────────────────────────────────────────────────────────────────────────
mod test_host {
    use busbar_contract::abi::hot::host::{HostCtx, PlaneHostVtable};
    use busbar_contract::abi::hot::pod::{Decision, Facts, FramingDesc, MeterOutcome, Seq, Usage};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};

    /// The counters are process-global (an `extern "C-unwind"` fn can capture nothing), so every test
    /// that reads them holds this first. Poison is stepped over: a panicking test must not silently
    /// disable every later one.
    static SERIALIZE: Mutex<()> = Mutex::new(());

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

    /// Take the serialization lock and zero every counter. Returns the guard — hold it for the test.
    pub fn reset() -> MutexGuard<'static, ()> {
        let g = SERIALIZE.lock().unwrap_or_else(|p| p.into_inner());
        for c in [&CLOCK_NOW, &GOVERN_ADMIT, &METER_CHARGE, &JOURNAL_APPEND] {
            c.store(0, Ordering::SeqCst);
        }
        LAST_AMOUNT.store(u64::MAX, Ordering::SeqCst);
        g
    }

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

    /// One granted slot's name, paired with a withdrawer that nulls exactly that slot.
    pub type Withdrawal = (&'static str, fn(&mut PlaneHostVtable));

    /// The four slot names this host grants, paired with a withdrawer that nulls exactly that one.
    /// Drives the per-slot negative control: the plane must REFUSE when any single one is absent,
    /// which is what proves it CALLS each of them rather than merely holding the table.
    pub const WITHDRAWABLE: [Withdrawal; 4] = [
        ("clock_now", |vt| vt.clock_now = None),
        ("govern_admit", |vt| vt.govern_admit = None),
        ("meter_charge", |vt| vt.meter_charge = None),
        ("journal_append", |vt| vt.journal_append = None),
    ];
}

/// Drive a dropped-in plane end to end over `host`, returning the `dispatch` status. Every hop before
/// `dispatch` is asserted `Ok` unless `host` is degenerate, in which case the caller reads the status
/// it cares about from the returned pair.
///
/// # Safety
/// `host` must outlive the whole drive (the built plane holds the pointer).
unsafe fn drive_over_host(
    plane: &crate::DynPlane,
    host: &PlaneHostVtable,
    inbound: &[u8],
) -> (StatusClass, StatusClass, StatusClass) {
    let host_ptr: *const PlaneHostVtable = host;
    // SAFETY: the caller guarantees `host` outlives the built plane; the example plane never
    // dereferences `host_ctx`, so the NULL handle is sound for a loader-side drive.
    let (build_status, handle) = unsafe { plane.build(host_ptr, HostCtx::NULL, b"{}", &[]) };
    if build_status != StatusClass::Ok {
        return (
            build_status,
            StatusClass::Unsupported,
            StatusClass::Unsupported,
        );
    }
    let handle = handle.expect("build yields an opaque plane handle on Ok");
    assert!(!handle.ptr.is_null());
    // SAFETY: `handle.ptr` is the live state `build` just produced.
    assert_eq!(unsafe { plane.hydrate(handle.ptr) }, StatusClass::Ok);
    // SAFETY: as above.
    let start_status = unsafe { plane.start(handle.ptr) };
    let work = WorkItem::new(InboundHandle::finite_buffer(inbound), EmitHandle::absent());
    // SAFETY: as above; `inbound` outlives the dispatch call.
    let dispatch_status = unsafe { plane.dispatch(handle.ptr, &work) };
    if let Some(free) = handle.free {
        free(handle.ptr);
    }
    (build_status, start_status, dispatch_status)
}

/// The dropped-in decl the loader reads is byte-identical to the compiled-in `PLANE_DECL` at the
/// vocabulary / carrier surface — a plane loads the SAME whether compiled in or dropped in.
#[test]
fn example_plane_loads_identically_compiled_in_and_dropped_in() {
    let Some(lib) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let dropped = crate::load_plane(&lib).expect("load the example plane over the HOT-tier ABI");

    assert_eq!(
        dropped.name(),
        vocab(COMPILED_IN.name_ptr, COMPILED_IN.name_len)
    );
    assert_eq!(
        dropped.section_key(),
        vocab(COMPILED_IN.section_key_ptr, COMPILED_IN.section_key_len)
    );
    assert_eq!(
        dropped.scope(),
        vocab(COMPILED_IN.scope_ptr, COMPILED_IN.scope_len)
    );
    assert_eq!(
        dropped.label(),
        vocab(COMPILED_IN.label_ptr, COMPILED_IN.label_len)
    );
    assert_eq!(dropped.provided_carriers(), COMPILED_IN.provided_carriers);
    // The wired carrier the example declares.
    assert!(dropped.provides(IngressCarrier::RequestResponse));
    assert!(!dropped.provides(IngressCarrier::DuplexSession));
    // Non-empty vocabulary — a decl that lost its name/section-key at the crossing would fail here.
    assert_eq!(dropped.name(), "example");
    assert_eq!(dropped.section_key(), "example");

    // THE FULL DECLARATION, both ways: what the dropped-in artifact states equals what the linked
    // decl states, field for field — read off the compiled-in decl HERE, independently of the
    // loader's own tail reader, so a reader that dropped or defaulted a field cannot agree with it.
    let stated = compiled_in_declaration();
    assert_eq!(dropped.declaration(), &stated);
    assert_eq!(
        crate::link_plane(&COMPILED_IN, "linked")
            .expect("the linked door admits the same decl")
            .declaration(),
        &stated
    );
    // Not vacuous: the example states every optional fact and a non-empty list of each kind.
    assert!(stated.signing_domain.is_some() && stated.signing_kid_prefix.is_some());
    assert!(!stated.owned_sections.is_empty() && !stated.billable_classes.is_empty());
    assert!(!stated.fee_units.is_empty() && stated.scope_kinds.len() > 1);
    assert!(stated
        .metric_families
        .iter()
        .any(|f| f.label_keys.len() > 1));
    assert!(!stated.served_op_classes.is_empty());
}

/// The compiled-in `PLANE_DECL`'s declaration tail, decoded straight off the static (NOT through the
/// loader), for the both-ways comparison above.
fn compiled_in_declaration() -> crate::HotDeclaration {
    use busbar_contract::abi::hot::DeclStr;
    let text = |d: DeclStr| (!d.ptr.is_null()).then(|| vocab(d.ptr, d.len));
    let list = |ptr: *const DeclStr, len: usize| -> Vec<String> {
        // SAFETY: the static's lists point at this build's own `'static` arrays of `len` entries.
        unsafe { std::slice::from_raw_parts(ptr, len) }
            .iter()
            .map(|d| vocab(d.ptr, d.len))
            .collect()
    };
    let d = &COMPILED_IN;
    crate::HotDeclaration {
        fallback: d.fallback == 1,
        subject_noun: vocab(d.subject_noun.ptr, d.subject_noun.len),
        admin_noun: vocab(d.admin_noun.ptr, d.admin_noun.len),
        audit_kind: vocab(d.audit_kind.ptr, d.audit_kind.len),
        signing_domain: text(d.signing_domain),
        signing_kid_prefix: text(d.signing_kid_prefix),
        scope_kinds: list(d.scope_kinds_ptr, d.scope_kinds_len),
        owned_sections: list(d.owned_sections_ptr, d.owned_sections_len),
        // SAFETY: as `list`.
        billable_classes: unsafe {
            std::slice::from_raw_parts(d.billable_classes_ptr, d.billable_classes_len)
        }
        .iter()
        .map(|c| {
            (
                vocab(c.class.ptr, c.class.len),
                vocab(c.family.ptr, c.family.len),
            )
        })
        .collect(),
        fee_units: list(d.fee_units_ptr, d.fee_units_len),
        // SAFETY: as `list`.
        metric_families: unsafe {
            std::slice::from_raw_parts(d.metric_families_ptr, d.metric_families_len)
        }
        .iter()
        .map(|f| crate::plane::HotMetricFamily {
            name: vocab(f.name.ptr, f.name.len),
            kind: vocab(f.kind.ptr, f.kind.len),
            label_keys: list(f.label_keys_ptr, f.label_keys_len),
        })
        .collect(),
        // SAFETY: as `list`.
        served_op_classes: unsafe {
            std::slice::from_raw_parts(d.served_op_classes_ptr, d.served_op_classes_len)
        }
        .iter()
        .map(|c| (vocab(c.op.ptr, c.op.len), vocab(c.name.ptr, c.name.len)))
        .collect(),
        record_kinds: list(d.record_kinds_ptr, d.record_kinds_len),
        required_sections: list(d.required_sections_ptr, d.required_sections_len),
    }
}

/// THE CROSS-ABI RIDER PROOF, loader half. The dropped-in plane is a LIVE plane AND a REAL RIDER:
/// `config_validate` → `build` → `hydrate` → `start` → `dispatch` all cross the ABI, and the plane
/// calls back through the host table it was handed — `clock_now` at `start`, then
/// `clock_now`/`govern_admit`/`meter_charge`/`journal_append` at `dispatch`.
///
/// The counts are asserted EXACTLY (`== 1`, `== 2`), not loosely: an exact count is the only assertion
/// a plane that stopped crossing, or one that started crossing twice, cannot both satisfy.
#[test]
fn dropped_in_example_plane_rides_the_host_vtable_end_to_end() {
    let Some(lib) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let plane = crate::load_plane(&lib).expect("load the example plane over the HOT-tier ABI");

    // config_validate produces a parsed handle; free it.
    let (cv_status, parsed) = plane.config_validate(b"{}");
    assert_eq!(cv_status, StatusClass::Ok);
    if let Some(p) = parsed {
        if let Some(free) = p.free {
            free(p.ptr);
        }
    }

    let _guard = test_host::reset();
    let host = test_host::vtable();
    // SAFETY: `host` is a live vtable on this frame; it outlives the whole drive below.
    let (build_status, start_status, dispatch_status) =
        unsafe { drive_over_host(&plane, &host, b"ping") };
    assert_eq!(build_status, StatusClass::Ok);
    assert_eq!(start_status, StatusClass::Ok);
    assert_eq!(dispatch_status, StatusClass::Ok);

    use std::sync::atomic::Ordering;
    // `start` reads the clock once; `dispatch` reads it once more.
    assert_eq!(
        test_host::CLOCK_NOW.load(Ordering::SeqCst),
        2,
        "the plane must take its start instant AND its arrival instant from the host clock"
    );
    for (name, counter) in [
        ("govern_admit", &test_host::GOVERN_ADMIT),
        ("meter_charge", &test_host::METER_CHARGE),
        ("journal_append", &test_host::JOURNAL_APPEND),
    ] {
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "one dispatch must cross `{name}` exactly once — a zero here is a 0-caller ABI"
        );
    }
}

/// THE MONEY BYTES, READ OFF THE WIRE. The plane is PRICING-BLIND (DECISIONS #43/#71): what crosses
/// the seam is a RAW COUNT and nothing else. This reads what the plane actually wrote into the
/// `Usage`, rather than believing the plane's documentation about it.
///
/// * `amount` == the inbound byte count it was handed — a count, in the unit it declared.
/// * there is no price to read: the `Usage` has no price field (KERNEL<>PLUGINS step 16, item 577),
///   and the host table offers no slot that takes a figure.
#[test]
fn dropped_in_example_plane_reports_a_raw_count_and_never_a_price() {
    let Some(lib) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let plane = crate::load_plane(&lib).expect("load the example plane");

    let _guard = test_host::reset();
    let host = test_host::vtable();
    let inbound = b"eleven-byte";
    assert_eq!(inbound.len(), 11);
    // SAFETY: `host` outlives the drive.
    let (_, _, dispatch_status) = unsafe { drive_over_host(&plane, &host, inbound) };
    assert_eq!(dispatch_status, StatusClass::Ok);

    use std::sync::atomic::Ordering;
    assert_eq!(
        test_host::LAST_AMOUNT.load(Ordering::SeqCst),
        11,
        "the plane must report the RAW COUNT it was handed"
    );
}

/// THE NEGATIVE CONTROL, WHOLE-TABLE. Handed a table that grants NOTHING
/// ([`PlaneHostVtable::EMPTY`]), the plane must REFUSE — it cannot serve a work item without the
/// capabilities the host withheld. `build` still succeeds, because an EMPTY table is a well-formed
/// one (correct preamble, correct size, every capability honestly absent); it is the WORK that
/// refuses, which is the right place for the refusal.
///
/// This is the test that makes the positive drive above mean something. If the example plane ever
/// stopped riding the vtable, the positive drive would still pass on a lucky `Ok` — this one would
/// turn green where it must be a refusal, and go red.
#[test]
fn dropped_in_example_plane_refuses_when_the_host_grants_nothing() {
    let Some(lib) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let plane = crate::load_plane(&lib).expect("load the example plane");

    let empty = PlaneHostVtable::EMPTY;
    // SAFETY: `empty` is a live vtable on this frame; it outlives the drive.
    let (build_status, start_status, dispatch_status) =
        unsafe { drive_over_host(&plane, &empty, b"ping") };
    assert_eq!(
        build_status,
        StatusClass::Ok,
        "an EMPTY table is well-formed: it is a host that grants nothing, not a broken host"
    );
    assert_eq!(
        start_status,
        StatusClass::Refused,
        "a plane that takes no ambient clock cannot start without the host's `clock_now`"
    );
    assert_eq!(
        dispatch_status,
        StatusClass::Refused,
        "a plane granted no capability must refuse the work, never serve it anyway"
    );
}

/// THE NEGATIVE CONTROL, PER SLOT — the sharpest form of the same question. Withdraw EXACTLY ONE of
/// the four granted slots and drive again: the plane must refuse, every time, for every slot. A slot
/// whose withdrawal changes nothing is a slot the plane never called, and this is the assertion that
/// says so by name.
#[test]
fn dropped_in_example_plane_refuses_when_any_single_host_slot_is_withdrawn() {
    let Some(lib) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let plane = crate::load_plane(&lib).expect("load the example plane");

    // The instrumented table's counters are process-global, so hold the serialization lock for the
    // whole loop even though this test reads none of them: driving the shims without it perturbs a
    // CONCURRENT test's counts, which is a flake in the other test rather than in this one.
    let _guard = test_host::reset();
    for (slot, withdraw) in test_host::WITHDRAWABLE {
        let mut host = test_host::vtable();
        withdraw(&mut host);
        // SAFETY: `host` is a live vtable on this frame; it outlives the drive.
        let (build_status, start_status, dispatch_status) =
            unsafe { drive_over_host(&plane, &host, b"ping") };
        assert_eq!(build_status, StatusClass::Ok, "withdrawing `{slot}`");
        // Only `clock_now` is reached by `start`; the other four are dispatch-only.
        let reached_at_start = slot == "clock_now";
        assert_eq!(
            start_status == StatusClass::Refused,
            reached_at_start,
            "`start` reaches `clock_now` and nothing else; withdrawing `{slot}` said otherwise"
        );
        assert_eq!(
            dispatch_status,
            StatusClass::Refused,
            "withdrawing `{slot}` must refuse the dispatch — a slot whose absence changes nothing \
             is a slot the plane never calls, and this ABI would have no rider"
        );
    }
}

/// FAIL-CLOSED, HOST SIDE. The airlock is symmetric: the loader checks the PLANE's decl preamble
/// before it calls a slot, and the plane checks the HOST's table preamble before it holds a pointer it
/// will later call through. A host stamped with an ABI MAJOR this plane does not speak is REFUSED at
/// `build` — the plane never comes into existence, so there is no state from which a mismatched slot
/// could be called.
#[test]
fn dropped_in_example_plane_refuses_a_host_whose_abi_major_does_not_match() {
    let Some(lib) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let plane = crate::load_plane(&lib).expect("load the example plane");

    // Hold the serialization lock: see the note in the per-slot withdrawal test above.
    let _guard = test_host::reset();
    let mut foreign = test_host::vtable();
    foreign.abi = AbiPreamble {
        abi_major: busbar_contract::abi::ABI_MAJOR + 1,
        ..AbiPreamble::CURRENT
    };
    // SAFETY: `foreign` is a live, correctly-sized table; only its declared MAJOR is wrong.
    let (build_status, _, _) = unsafe { drive_over_host(&plane, &foreign, b"ping") };
    assert_eq!(
        build_status,
        StatusClass::Refused,
        "a MAJOR mismatch is a no-turning-back linker event: the plane must not build against it"
    );

    // And the same table with a differing MINOR builds fine — append-only compatibility is the whole
    // reason MAJOR is the refusal axis and MINOR is not.
    let mut older_minor = test_host::vtable();
    older_minor.abi = AbiPreamble {
        abi_minor: busbar_contract::abi::ABI_MINOR.saturating_sub(1),
        ..AbiPreamble::CURRENT
    };
    // SAFETY: as above.
    let (build_status, _, _) = unsafe { drive_over_host(&plane, &older_minor, b"ping") };
    assert_eq!(
        build_status,
        StatusClass::Ok,
        "an older MINOR is compatible by the sized-struct discipline, never a refusal"
    );
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

// ── SIGNED DROP-IN over the FULL registry pipeline (DECISIONS #26 S4, #55/#70/#75 posture A) ─────
//
// The tests above drive `crate::load_plane` on a bare path — the operator-placed, inherently-trusted
// case. These prove the OTHER half of #11's both-ways contract for `kind: plane`: a plane cdylib
// packaged into a SIGNED tarball rides the EXACT same three-phase discovery/trust/conflict pipeline
// as the five cold kinds (`scan_and_validate` → `PluginRegistry::open_plane`), and posture A holds —
// signed first-party loads by default; unsigned/third-party is REFUSED unless an admin opts in.

/// A `kind: plane` manifest for the example plane, with `abi_version` on the airlock-minor axis
/// `supported_abi("plane")` gates against (`[1, ABI_MINOR]`). `sha256`/`signature` are filled by the
/// caller (via `sign`, or by hand for the unsigned case).
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

/// Drive an opened `DynPlane` end to end (config_validate → build → hydrate → start → dispatch) over
/// the instrumented `test_host`, asserting every hop returns `Ok` AND that the plane crossed each of
/// the four granted host slots.
///
/// The counter assertions are what make this a proof about the SEAM rather than about the loader. A
/// `DynPlane` the registry produced that returned `Ok` without ever calling back would be a plane the
/// composition root could install and never actually serve through; the counts are the difference
/// between "the handle resolved" and "the ABI is ridden".
fn drive_opened_plane(plane: &crate::DynPlane) {
    let (cv_status, parsed) = plane.config_validate(b"{}");
    assert_eq!(cv_status, StatusClass::Ok);
    if let Some(p) = parsed {
        if let Some(free) = p.free {
            free(p.ptr);
        }
    }

    let _guard = test_host::reset();
    let host = test_host::vtable();
    // SAFETY: `host` is a live vtable on this frame; it outlives the whole drive.
    let (build_status, start_status, dispatch_status) =
        unsafe { drive_over_host(plane, &host, b"ping") };
    assert_eq!(build_status, StatusClass::Ok);
    assert_eq!(start_status, StatusClass::Ok);
    assert_eq!(dispatch_status, StatusClass::Ok);

    use std::sync::atomic::Ordering;
    assert_eq!(test_host::CLOCK_NOW.load(Ordering::SeqCst), 2);
    assert_eq!(test_host::GOVERN_ADMIT.load(Ordering::SeqCst), 1);
    assert_eq!(test_host::METER_CHARGE.load(Ordering::SeqCst), 1);
    assert_eq!(test_host::JOURNAL_APPEND.load(Ordering::SeqCst), 1);
    // The money bytes, on the registry path too: a raw count.
    assert_eq!(test_host::LAST_AMOUNT.load(Ordering::SeqCst), 4);
}

/// THE GREEN PROOF for W1.d: package the REAL example-plane cdylib into a SIGNED FIRST-PARTY tarball,
/// run the full three-phase pipeline, resolve by ALIAS, and `open_plane` a LIVE `DynPlane` — the exact
/// seam the composition root sees, indistinguishable from a compiled-in plane. The plane analogue of
/// `end_to_end_open_store_from_signed_tarball`.
#[test]
fn end_to_end_open_plane_from_signed_first_party_tarball() {
    let Some(path) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let lib = std::fs::read(&path).expect("read the example-plane cdylib");
    let release = SigningKey::from_bytes(&[1u8; 32]);
    let dir = plane_tmpdir("e2e-first-party");
    let m = sign(
        &release,
        plane_manifest("busbar-plane-example", "example-plane", "busbar"),
        &lib,
    );
    // Filename deliberately unrelated — identity comes from the signed manifest, never the file.
    write_plane_tarball(&dir, "totally-not-a-plane.tar.gz", &m, &lib);

    let reg = crate::registry::scan_and_validate(&dir, &first_party_only_policy(&release))
        .expect("a signed first-party plane must scan cleanly");
    assert_eq!(reg.loadable().len(), 1, "the signed plane is loadable");
    assert!(reg.skipped().is_empty(), "nothing skipped: {reg:?}");

    // Resolves by BOTH alias and canonical name, from the manifest.
    let plane = reg
        .open_plane("example-plane")
        .expect("open the signed plane over the HOT-tier ABI through the registry");
    assert_eq!(plane.name(), "example");
    assert_eq!(plane.section_key(), "example");
    assert!(plane.provides(IngressCarrier::RequestResponse));
    drive_opened_plane(&plane);

    // The canonical name resolves to the same loadable plane too.
    assert!(reg.open_plane("busbar-plane-example").is_ok());

    let _ = std::fs::remove_dir_all(&dir);
}

/// POSTURE A, unsigned lever: an UNSIGNED plane (valid sha256, empty signature) is REFUSED by default
/// — skipped, never `dlopen`ed, and `open_plane` fails loud with the trust reason — but the SAME
/// artifact loads and drives once an admin sets `allow_unsigned` (DECISIONS #55/#70/#75).
#[test]
fn unsigned_plane_refused_by_default_accepted_under_allow_unsigned() {
    let Some(path) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let lib = std::fs::read(&path).expect("read the example-plane cdylib");
    let release = SigningKey::from_bytes(&[1u8; 32]);
    let dir = plane_tmpdir("unsigned");
    let mut m = plane_manifest("busbar-plane-example", "example-plane", "busbar");
    m.sha256 = sha256_hex(&lib); // structurally valid…
    m.signature = String::new(); // …but UNSIGNED.
    write_plane_tarball(&dir, "unsigned.tar.gz", &m, &lib);

    // Default posture: refused (skipped); referencing it fails loud with the opt-in named.
    let reg = crate::registry::scan_and_validate(&dir, &first_party_only_policy(&release))
        .expect("an unsigned artifact is a SKIP, not a scan failure");
    assert!(reg.loadable().is_empty(), "unsigned must not be loadable");
    assert_eq!(reg.skipped().len(), 1);
    let err = reg.open_plane("example-plane").map(|_| ()).unwrap_err();
    assert!(err.contains("was not loaded"), "got {err}");
    assert!(err.contains("allow_unsigned"), "names the opt-in: {err}");

    // Admin opt-in: allow_unsigned makes the exact same artifact loadable and drivable.
    let mut pol = first_party_only_policy(&release);
    pol.allow_unsigned = true;
    let reg = crate::registry::scan_and_validate(&dir, &pol).expect("scan");
    assert_eq!(reg.loadable().len(), 1, "allow_unsigned admits it");
    let plane = reg
        .open_plane("example-plane")
        .expect("the unsigned plane loads once explicitly permitted");
    drive_opened_plane(&plane);

    let _ = std::fs::remove_dir_all(&dir);
}

/// POSTURE A, third-party lever: a plane VALIDLY signed by a NON-first-party publisher is REFUSED by
/// default (unknown publisher, not allowlisted) — skipped, `open_plane` fails loud — but loads and
/// drives once an admin sets `allow_third_party` (DECISIONS #55/#70/#75).
#[test]
fn third_party_plane_refused_by_default_accepted_under_allow_third_party() {
    let Some(path) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let lib = std::fs::read(&path).expect("read the example-plane cdylib");
    let release = SigningKey::from_bytes(&[1u8; 32]);
    let acme = SigningKey::from_bytes(&[2u8; 32]); // a NON-first-party publisher key
    let dir = plane_tmpdir("third-party");
    let m = sign(
        &acme,
        plane_manifest("acme-plane-widget", "widget", "acme"),
        &lib,
    );
    write_plane_tarball(&dir, "acme.tar.gz", &m, &lib);

    // Default posture: refused as an unknown publisher; the opt-in is named.
    let reg = crate::registry::scan_and_validate(&dir, &first_party_only_policy(&release))
        .expect("a third-party artifact is a SKIP, not a scan failure");
    assert!(
        reg.loadable().is_empty(),
        "third-party must not be loadable"
    );
    let err = reg.open_plane("widget").map(|_| ()).unwrap_err();
    assert!(err.contains("was not loaded"), "got {err}");
    assert!(err.contains("allow_third_party"), "names the opt-in: {err}");

    // Admin opt-in: allow_third_party admits it; it loads and drives.
    let mut pol = first_party_only_policy(&release);
    pol.allow_third_party = true;
    let reg = crate::registry::scan_and_validate(&dir, &pol).expect("scan");
    assert_eq!(reg.loadable().len(), 1, "allow_third_party admits it");
    let plane = reg
        .open_plane("widget")
        .expect("the third-party plane loads once explicitly permitted");
    drive_opened_plane(&plane);

    let _ = std::fs::remove_dir_all(&dir);
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

/// FAIL-CLOSED, PLANE SIDE, THROUGH THE WHOLE PIPELINE. A plane whose `PlaneDecl` preamble carries an
/// ABI MAJOR this engine does not speak must be REFUSED at `open_plane` — after the tarball verified,
/// after the signature verified, after the kind gate passed, at the AIRLOCK. Trust is not
/// compatibility: a correctly-signed first-party artifact built against a foreign major is still an
/// artifact whose `#[repr(C)]` layout this build cannot interpret, and interpreting it anyway is how a
/// fn-pointer read from the wrong offset gets called.
///
/// The mismatch is stamped into the REAL artifact rather than into a hand-built decl: the
/// [`AbiPreamble`] is a frozen 16-byte record (`magic` at 0, `abi_major` at 8, `abi_minor` at 12), so
/// the bytes the plane's `PLANE_DECL` stamped are findable in its own image and the MAJOR field is
/// editable in place. That keeps the test on the path an operator's plugin actually takes — dlopen and
/// all — instead of on a synthetic struct that never crossed a file.
#[test]
fn open_plane_refuses_an_artifact_whose_decl_preamble_carries_a_foreign_abi_major() {
    let Some(path) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let lib = std::fs::read(&path).expect("read the example-plane cdylib");

    // The frozen preamble, exactly as this build stamps it: magic ‖ MAJOR ‖ MINOR, little-endian.
    let mut needle = Vec::with_capacity(16);
    needle.extend_from_slice(&busbar_contract::abi::ABI_MAGIC.to_le_bytes());
    needle.extend_from_slice(&busbar_contract::abi::ABI_MAJOR.to_le_bytes());
    needle.extend_from_slice(&busbar_contract::abi::ABI_MINOR.to_le_bytes());
    let foreign_major = (busbar_contract::abi::ABI_MAJOR + 1).to_le_bytes();

    // Rewrite EVERY stamped preamble in the image: the plane may hold more than one (its decl's, and
    // whatever its linked ABI crate stamped), and a plugin built against a foreign major would carry
    // the foreign major in all of them. Patching one and leaving another would be testing a half-state
    // nothing produces.
    let mut patched = lib.clone();
    let mut hits = 0usize;
    let mut i = 0usize;
    while i + needle.len() <= patched.len() {
        if patched[i..i + needle.len()] == needle[..] {
            patched[i + 8..i + 12].copy_from_slice(&foreign_major);
            hits += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    assert!(
        hits > 0,
        "the plane's own `AbiPreamble::CURRENT` bytes must be findable in its image — if this \
         assertion trips, the preamble layout moved and this test is measuring nothing. It is \
         asserted rather than assumed precisely because a plant that silently fails to plant is \
         indistinguishable from a gate that cannot see."
    );
    assert_ne!(patched, lib, "the patch must actually change the bytes");
    let Some(patched) = relink_for_this_platform(&patched, "foreign-major") else {
        return; // the platform needs a re-link this environment cannot perform; see the helper
    };

    // Package the PATCHED bytes as a properly signed, first-party, correctly-manifested plane: every
    // gate before the airlock passes, so the airlock is provably the one that refuses.
    let release = SigningKey::from_bytes(&[1u8; 32]);
    let dir = plane_tmpdir("foreign-abi-major");
    let m = sign(
        &release,
        plane_manifest("busbar-plane-example", "example-plane", "busbar"),
        &patched,
    );
    write_plane_tarball(&dir, "foreign-major.tar.gz", &m, &patched);

    let reg = crate::registry::scan_and_validate(&dir, &first_party_only_policy(&release))
        .expect("a signed first-party artifact scans cleanly whatever ABI it targets");
    assert_eq!(
        reg.loadable().len(),
        1,
        "the artifact is TRUSTED — the refusal below is about compatibility, not trust"
    );

    let err = reg
        .open_plane("example-plane")
        .expect_err("a foreign ABI MAJOR must be refused, never loaded");
    assert!(
        err.contains("preamble refused") && err.contains("MajorMismatch"),
        "the refusal must name the airlock and the mismatch so an operator can act on it, got: {err}"
    );

    // Vice versa on the same path: the UNPATCHED artifact, packaged identically, opens and drives.
    // Without this the test could pass because `open_plane` refuses everything.
    let dir_ok = plane_tmpdir("native-abi-major");
    let m_ok = sign(
        &release,
        plane_manifest("busbar-plane-example", "example-plane", "busbar"),
        &lib,
    );
    write_plane_tarball(&dir_ok, "native-major.tar.gz", &m_ok, &lib);
    let reg_ok = crate::registry::scan_and_validate(&dir_ok, &first_party_only_policy(&release))
        .expect("the unpatched artifact scans cleanly");
    let plane = reg_ok
        .open_plane("example-plane")
        .expect("the unpatched artifact opens over the HOT-tier ABI");
    drive_opened_plane(&plane);
}

/// Make an EDITED `cdylib` image loadable again on platforms whose loader authenticates it.
///
/// Editing bytes inside a Mach-O invalidates its code-signature, and macOS does not answer that with
/// a `dlopen` error — the kernel SIGKILLs the loading process outright, so the airlock never gets to
/// refuse anything and the test dies instead of failing. An ad-hoc re-signature (`codesign --sign -`)
/// restores a valid signature over the EDITED bytes, which is exactly the artifact the scenario
/// describes: a real, properly-delivered plugin that was built against an ABI this engine does not
/// speak. It changes nothing the airlock reads. On every other platform the image is returned
/// untouched.
///
/// `None` means this environment cannot produce a loadable edited image (no `codesign`, or it
/// refused). The caller SKIPS rather than asserts — but never under CI, where the toolchain is known
/// and a silent skip would hide the loss of the ONLY fail-closed proof on this path.
// Off macOS the first cfg block is the whole body, so its `return` is the tail; the macOS block
// below needs it to be a statement. One body, two platforms: the lint is wrong on one of them.
#[cfg_attr(not(target_os = "macos"), allow(clippy::needless_return))]
fn relink_for_this_platform(bytes: &[u8], tag: &str) -> Option<Vec<u8>> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = tag;
        return Some(bytes.to_vec());
    }
    #[cfg(target_os = "macos")]
    {
        let dir = plane_tmpdir(&format!("relink-{tag}"));
        let file = dir.join(crate::plugin_library_filename("edited_plane"));
        std::fs::write(&file, bytes).expect("stage the edited image for re-signing");
        let signed = std::process::Command::new("codesign")
            .args(["--force", "--sign", "-"])
            .arg(&file)
            .output();
        let ok = matches!(&signed, Ok(o) if o.status.success());
        if !ok {
            assert!(
                std::env::var_os("CI").is_none(),
                "`codesign --sign -` is unavailable or refused under CI, so the foreign-ABI-MAJOR \
                 refusal cannot be proven on the real load path. Refusing to skip the only \
                 fail-closed proof this path has: {signed:?}"
            );
            eprintln!("skip: `codesign --sign -` unavailable; cannot re-link an edited image");
            return None;
        }
        Some(std::fs::read(&file).expect("read the re-signed image back"))
    }
}

/// ONE PLANE SERVES THE SAME, LINKED OR DROPPED IN (minor 23). The example plane is admitted both
/// ways — [`crate::link_plane`] over the rlib's `PLANE_DECL`, [`crate::load_plane`] over the cdylib —
/// and each is BUILT to serve through [`crate::DynPlane::serve`] with the same section bytes and public
/// URL. The two must state the same door (`claims`), bind the same audience (`admission`) and answer
/// one work item with the same status and the same reply bytes — a reply that quotes the section, so
/// the section demonstrably crossed `build`. Without a public URL the plane has no audience and claims
/// no path.
#[test]
fn a_linked_and_a_dropped_in_plane_serve_identically_over_the_abi() {
    let Some(lib) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let linked: &'static crate::DynPlane = Box::leak(Box::new(
        crate::link_plane(&COMPILED_IN, "linked").expect("links"),
    ));
    let dropped: &'static crate::DynPlane =
        Box::leak(Box::new(crate::load_plane(&lib).expect("loads")));
    let host: &'static PlaneHostVtable = Box::leak(Box::new(test_host::vtable()));
    let section = br#"{"greeting":"hi"}"#;
    let url = Some("https://gw.example.com");
    // The example plane's dispatch does not block (minor 32), and both doors read it so.
    assert!(!linked.dispatch_blocks() && !dropped.dispatch_blocks());

    let _guard = test_host::reset();
    let serve = |plane: &'static crate::DynPlane| {
        let served = plane.serve(host, section, url).expect("builds");
        let (status, reply) = served.dispatch(host, HostCtx::NULL, b"ping");
        (
            served.claims().expect("claims"),
            served.admission().expect("admission"),
            status,
            String::from_utf8(reply).expect("utf-8 reply"),
        )
    };
    let (a, b) = (serve(linked), serve(dropped));
    assert_eq!(a, b, "the two doors must serve byte-identically");
    assert_eq!(
        a.0,
        vec![crate::HotClaim {
            method: "POST".into(),
            path: "/example".into(),
            wire: "http+json".into(),
        }]
    );
    assert_eq!(
        a.1,
        Some((
            "https://gw.example.com/example".to_string(),
            "https://gw.example.com/.well-known/oauth-protected-resource/example".to_string(),
        ))
    );
    assert_eq!(a.2, StatusClass::Ok);
    assert_eq!(
        a.3, r#"{"plane":"example","bytes":4,"section":{"greeting":"hi"}}"#,
        "the reply quotes the section the plane was built with"
    );

    // No public URL: no audience to be admitted under, so no door either.
    let bare = dropped.serve(host, section, None).expect("builds");
    assert_eq!(bare.claims().expect("claims"), Vec::new());
    assert_eq!(bare.admission().expect("admission"), None);
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
            conns: crate::dispatch::ConnTable::NoNeeds,
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
