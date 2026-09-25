// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DROP-IN CONFORMANCE for `kind: plane` — the plane analogue of the store example's over-the-ABI
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
//! * the PER-SLOT drive withdraws exactly one of the five granted slots at a time and asserts the
//!   plane refuses each time, naming the withdrawn slot — which is what proves it calls each one.
//!
//! The REAL host — `busbar_kernel::plane_host::build_plane_host_vtable()`, 44 of 44 slots over live
//! core primitives — is crossed by the SAME artifact in `crates/busbar-kernel/tests/plane_abi_rider.rs`.
//! It cannot be crossed from here: this crate may not name `busbar-kernel` (that edge is the
//! core→loader→kernel cycle the 1.6.0 W4.a chunk-0 split broke), so the two halves of the proof live on
//! the two sides of that seam, on purpose.

use crate::sign::{sha256_hex, sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::pod::StatusClass;
use busbar_plugin::hot::{EmitHandle, InboundHandle, IngressCarrier, PlaneHostVtable, WorkItem};
use busbar_plugin::AbiPreamble;
use busbar_plugin_example_plane::PLANE_DECL as COMPILED_IN;

/// Locate the REAL `busbar-plane-example` cdylib built into this workspace's target dir (uplifted or
/// under `deps`, newest wins). Mirrors `store_example_plugin_path()` in `lib_tests.rs`.
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
// 1.6.0 W4.a chunk-0 split exists to break), so the REAL `build_plane_host_vtable()` crossing lives in
// the kernel's own suite (`crates/busbar-kernel/tests/plane_abi_rider.rs`). What belongs HERE is the
// half the loader owns: that the artifact the LOADER produced — dlopened, trust-verified, resolved
// through the registry — actually calls back through the table it was handed, and how many times.
//
// So every slot below is a counting shim. It is not a stand-in for the host: it is an INSTRUMENT on
// the seam. A `dispatch` that returned `Ok` without touching the table would leave every counter at
// zero and red these tests, which is the property that makes them worth running.
// ─────────────────────────────────────────────────────────────────────────────────────────────
mod test_host {
    use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
    use busbar_plugin::hot::pod::{
        CostLeaseId, CostSettleOut, Decision, Facts, MeterOutcome, StatusClass, Usage, POD_VERSION,
    };
    use core::mem::MaybeUninit;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};

    /// The counters are process-global (an `extern "C-unwind"` fn can capture nothing), so every test
    /// that reads them holds this first. Poison is stepped over: a panicking test must not silently
    /// disable every later one.
    static SERIALIZE: Mutex<()> = Mutex::new(());

    /// Per-slot call counts. `dispatch` is REQUIRED to move all five; `start` moves `CLOCK_NOW` once
    /// more.
    pub static CLOCK_NOW: AtomicU64 = AtomicU64::new(0);
    /// See [`CLOCK_NOW`].
    pub static GOVERN_ADMIT: AtomicU64 = AtomicU64::new(0);
    /// See [`CLOCK_NOW`].
    pub static METER_CHARGE: AtomicU64 = AtomicU64::new(0);
    /// See [`CLOCK_NOW`].
    pub static COST_RESERVE: AtomicU64 = AtomicU64::new(0);
    /// See [`CLOCK_NOW`].
    pub static COST_SETTLE: AtomicU64 = AtomicU64::new(0);

    /// THE MONEY BYTES, READ OFF THE WIRE. What the plane actually wrote into the `Usage` /
    /// `cost_reserve` / `cost_settle` arguments, captured verbatim so a test can assert the
    /// PRICING-BLIND posture (DECISIONS #43/#71/#77(3)) rather than take the plane's word for it.
    pub static LAST_AMOUNT: AtomicU64 = AtomicU64::new(u64::MAX);
    /// See [`LAST_AMOUNT`]. MUST be `0` — a plane that priced would put a rate here.
    pub static LAST_UNIT_COST_MICROS: AtomicU64 = AtomicU64::new(u64::MAX);
    /// See [`LAST_AMOUNT`]. The sum of every nanodollar field the plane handed the lease slots
    /// (reserve + flat fee + cap + settle). MUST be `0`.
    pub static LAST_MONEY_NANOS: AtomicU64 = AtomicU64::new(u64::MAX);

    /// Take the serialization lock and zero every counter. Returns the guard — hold it for the test.
    pub fn reset() -> MutexGuard<'static, ()> {
        let g = SERIALIZE.lock().unwrap_or_else(|p| p.into_inner());
        for c in [
            &CLOCK_NOW,
            &GOVERN_ADMIT,
            &METER_CHARGE,
            &COST_RESERVE,
            &COST_SETTLE,
        ] {
            c.store(0, Ordering::SeqCst);
        }
        for c in [&LAST_AMOUNT, &LAST_UNIT_COST_MICROS, &LAST_MONEY_NANOS] {
            c.store(u64::MAX, Ordering::SeqCst);
        }
        g
    }

    /// A Unix-nanosecond reading a plane can tell apart from the slot's fail-closed `0`. Fixed rather
    /// than sampled so the shim adds no ambient clock of its own.
    pub const CLOCK_READING: u64 = 1_700_000_000_000_000_000;
    /// The lease id this host mints. Non-zero, so it is never the reserved `CostLeaseId::NONE`.
    pub const LEASE: u64 = 7;

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
        LAST_UNIT_COST_MICROS.store(u.unit_cost_micros, Ordering::SeqCst);
        MeterOutcome::Charged
    }

    extern "C-unwind" fn cost_reserve(
        _host: HostCtx,
        reserve_nanos: u64,
        flat_fee_nanos: u64,
        cap_nanos: u64,
        _cap_present: bool,
        out: *mut MaybeUninit<CostLeaseId>,
    ) -> StatusClass {
        COST_RESERVE.fetch_add(1, Ordering::SeqCst);
        let seen = reserve_nanos
            .saturating_add(flat_fee_nanos)
            .saturating_add(cap_nanos);
        LAST_MONEY_NANOS.store(seen, Ordering::SeqCst);
        // SAFETY: `out` is a writable, aligned `MaybeUninit<CostLeaseId>` for the call (or null,
        // tolerated); published ONLY on the Ok path (init-only-on-Ok).
        unsafe { busbar_plugin::write_out(out, CostLeaseId(LEASE)) };
        StatusClass::Ok
    }

    extern "C-unwind" fn cost_settle(
        _host: HostCtx,
        lease: CostLeaseId,
        settle_nanos: u64,
        _breakdown_ptr: *const u8,
        _breakdown_len: usize,
        out: *mut MaybeUninit<CostSettleOut>,
    ) -> StatusClass {
        COST_SETTLE.fetch_add(1, Ordering::SeqCst);
        if lease.0 != LEASE {
            return StatusClass::Refused; // an unknown lease fails closed, as the real host does
        }
        LAST_MONEY_NANOS.fetch_add(settle_nanos, Ordering::SeqCst);
        // SAFETY: as `cost_reserve` above.
        unsafe {
            busbar_plugin::write_out(
                out,
                CostSettleOut {
                    size: core::mem::size_of::<CostSettleOut>() as u32,
                    version: POD_VERSION,
                    exhausted: 0,
                    _reserved: 0,
                },
            )
        };
        StatusClass::Ok
    }

    /// The instrumented host: `EMPTY` (every capability withheld) plus exactly the five slots the
    /// example plane requires. Granting only what is needed is the point — a plane that called a
    /// sixth would hit a `None` and refuse, which is the behaviour, not a bug.
    pub fn vtable() -> PlaneHostVtable {
        PlaneHostVtable {
            clock_now: Some(clock_now),
            govern_admit: Some(govern_admit),
            meter_charge: Some(meter_charge),
            cost_reserve: Some(cost_reserve),
            cost_settle: Some(cost_settle),
            ..PlaneHostVtable::EMPTY
        }
    }

    /// One granted slot's name, paired with a withdrawer that nulls exactly that slot.
    pub type Withdrawal = (&'static str, fn(&mut PlaneHostVtable));

    /// The five slot names this host grants, paired with a withdrawer that nulls exactly that one.
    /// Drives the per-slot negative control: the plane must REFUSE when any single one is absent,
    /// which is what proves it CALLS each of them rather than merely holding the table.
    pub const WITHDRAWABLE: [Withdrawal; 5] = [
        ("clock_now", |vt| vt.clock_now = None),
        ("govern_admit", |vt| vt.govern_admit = None),
        ("meter_charge", |vt| vt.meter_charge = None),
        ("cost_reserve", |vt| vt.cost_reserve = None),
        ("cost_settle", |vt| vt.cost_settle = None),
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
}

/// The compiled-in `PLANE_DECL`'s declaration tail, decoded straight off the static (NOT through the
/// loader), for the both-ways comparison above.
fn compiled_in_declaration() -> crate::HotDeclaration {
    use busbar_plugin::hot::DeclStr;
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
    }
}

/// THE CROSS-ABI RIDER PROOF, loader half. The dropped-in plane is a LIVE plane AND a REAL RIDER:
/// `config_validate` → `build` → `hydrate` → `start` → `dispatch` all cross the ABI, and the plane
/// calls back through the host table it was handed — `clock_now` at `start`, then
/// `clock_now`/`govern_admit`/`meter_charge`/`cost_reserve`/`cost_settle` at `dispatch`.
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
        ("cost_reserve", &test_host::COST_RESERVE),
        ("cost_settle", &test_host::COST_SETTLE),
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
/// `Usage` and into the two lease slots, rather than believing the plane's documentation about it.
///
/// * `amount` == the inbound byte count it was handed — a count, in the unit it declared.
/// * `unit_cost_micros` == 0 — the plane carries no rate, so it can compute no price (#77(3): a price
///   is NEVER stored, and a plane could not store one it never had).
/// * every nanodollar field of `cost_reserve`/`cost_settle` == 0 — the lease LIFECYCLE is the plane's
///   obligation; the AMOUNT is the host's. A non-zero here would be a plane that had priced.
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
    assert_eq!(
        test_host::LAST_UNIT_COST_MICROS.load(Ordering::SeqCst),
        0,
        "a pricing-blind plane carries no rate: `unit_cost_micros` must be 0"
    );
    assert_eq!(
        test_host::LAST_MONEY_NANOS.load(Ordering::SeqCst),
        0,
        "every nanodollar the plane handed the lease slots must be 0 — a plane that priced is a \
         plane that violated #43/#71"
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
/// the five granted slots and drive again: the plane must refuse, every time, for every slot. A slot
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
        abi_major: busbar_plugin::ABI_MAJOR + 1,
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
        abi_minor: busbar_plugin::ABI_MINOR.saturating_sub(1),
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
    use busbar_plugin::hot::PlaneDecl;
    use busbar_plugin::AbiPreamble;

    // A one-byte real buffer paired with a length past the cap — the hostile shape a lying decl uses.
    let small = b"x";
    let decl = PlaneDecl {
        abi: AbiPreamble::CURRENT,
        size: core::mem::size_of::<PlaneDecl>() as u32,
        version: busbar_plugin::ABI_MINOR,
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
    let honoured = busbar_plugin::honoured_size(decl.size, core::mem::size_of::<PlaneDecl>());
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
        abi_version: busbar_plugin::ABI_MINOR,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
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
/// the five granted host slots.
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
    assert_eq!(test_host::COST_RESERVE.load(Ordering::SeqCst), 1);
    assert_eq!(test_host::COST_SETTLE.load(Ordering::SeqCst), 1);
    // The money bytes, on the registry path too: a raw count, and not one priced nanodollar.
    assert_eq!(test_host::LAST_AMOUNT.load(Ordering::SeqCst), 4);
    assert_eq!(test_host::LAST_UNIT_COST_MICROS.load(Ordering::SeqCst), 0);
    assert_eq!(test_host::LAST_MONEY_NANOS.load(Ordering::SeqCst), 0);
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
    m.abi_version = busbar_plugin::cold::ABI_VERSION; // store-admissible so the KIND gate is what fires
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
    assert_eq!(range, &[1, busbar_plugin::ABI_MINOR]);
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
    needle.extend_from_slice(&busbar_plugin::ABI_MAGIC.to_le_bytes());
    needle.extend_from_slice(&busbar_plugin::ABI_MAJOR.to_le_bytes());
    needle.extend_from_slice(&busbar_plugin::ABI_MINOR.to_le_bytes());
    let foreign_major = (busbar_plugin::ABI_MAJOR + 1).to_le_bytes();

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
