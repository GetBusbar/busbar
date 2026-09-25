// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PLANE-ABI RIDER PROOF** — a DROPPED-IN plane cdylib, dlopened over the HOT-tier C ABI, driven
//! against the REAL host vtable (`busbar_kernel::plane_host::build_plane_host_vtable()`, 44 of 44 slots
//! over live core primitives), calling core's own host slots back from the plugin side of the seam.
//!
//! ## WHY THIS FILE EXISTS
//!
//! `docs/design/BUSBAR-1.6.0.md` §11a gates the cut on *"`PlaneHost` (+ cost carrier) has REAL production riders
//! (dogfooded) — no '0-caller ABI'"*. Both ends of that seam were built and neither crossed: the host
//! table was exercised only host-to-itself inside `plane_host`, and the loader half was exercised only
//! against a hand-built test table. A capability nothing calls is a capability nobody has checked, and
//! an ABI with no caller is an ABI whose first caller discovers its bugs in production.
//!
//! This is the crossing. `crates/plugin-loader/src/tests/plane_conformance_tests.rs` owns the other
//! half — the loader's — because `busbar-plugin-loader` may not name `busbar-kernel` (that edge is the
//! core→loader→kernel cycle the 1.6.0 W4.a chunk-0 split broke), so the REAL host vtable is
//! unreachable from there. It is reachable from here, and here is the only place it is.
//!
//! ## WHAT IS ACTUALLY PROVEN, AND HOW EACH CLAIM COULD FAIL
//!
//! | test | claim | how it goes red |
//! | --- | --- | --- |
//! | [`dropped_in_plane_rides_the_real_host_vtable`] | a dlopened plane serves a work item over the real table, unmodified | any host slot refusing, or the plane refusing |
//! | [`the_real_host_vtable_is_crossed_once_per_slot_per_dispatch`] | it crosses each of five slots EXACTLY once, and the real host answers | a count that is not 1, i.e. a plane that stopped calling, or called twice |
//! | [`withdrawing_one_real_host_slot_refuses_the_dispatch`] | each crossing is LOAD-BEARING | a slot whose withdrawal changes nothing — the signature of a decorative reference |
//! | [`the_plane_reads_the_hosts_own_clock`] | the value the plane got is the HOST's, not one it made up | a clock reading unrelated to core's own |
//! | [`the_metering_lease_round_trips_through_the_real_registry`] | a lease a PLUGIN opened is settleable in core's own registry | the real `cost_settle` refusing the id the plugin handed back |
//! | [`the_plane_hands_the_real_host_a_raw_count_and_never_a_price`] | PRICING-BLINDNESS, read off the wire | any non-zero money field crossing from the plane |
//! | [`registry_open_plane_yields_a_plane_that_rides_the_real_host_vtable`] | the whole delivery path — signed tarball → trust → registry → airlock → rider | any hop |
//!
//! ## MONEY (DECISIONS #43/#71/#77(3)/#77(8))
//!
//! The plane is PRICING-BLIND: it emits RAW COUNTS and no price. This file ASSERTS that rather than
//! assuming it — [`the_plane_hands_the_real_host_a_raw_count_and_never_a_price`] reads the exact
//! `Usage.unit_cost_micros` and the exact `cost_reserve`/`cost_settle` nanodollar arguments the plugin
//! wrote, on their way INTO real kernel money code, and requires every one of them to be zero. No
//! `f32`/`f64` appears in this file or in the plane it drives (#77(8)/#81).

#![allow(clippy::items_after_statements)]

use busbar_kernel::plane_host::with_dispatch_scope;
use busbar_kernel::test_support::TestApp;
use busbar_plugin::hot::host::{
    ClockNowFn, CostReserveFn, CostSettleFn, GovernAdmitFn, HostCtx, MeterChargeFn, PlaneHostVtable,
};
use busbar_plugin::hot::pod::{
    CostLeaseId, CostSettleOut, Decision, Facts, MeterOutcome, StatusClass, Usage,
};
use busbar_plugin::hot::{EmitHandle, InboundHandle, WorkItem};
use busbar_plugin_loader::DynPlane;
use core::mem::MaybeUninit;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Locating the artifact
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Locate the REAL `busbar-plugin-example-plane` cdylib in this workspace's target dir (uplifted or
/// under `deps`, newest wins). Mirrors the loader suite's `plane_example_cdylib()`.
///
/// REFUSES TO SKIP UNDER CI. A dropped artifact would make every test in this file pass vacuously,
/// and a vacuous pass on the ONE file that proves `docs/design/BUSBAR-1.6.0.md` §11a's rider is worse than a red: it is a green that
/// says the opposite of the truth. `.github/workflows/ci.yml` builds this cdylib by name for exactly
/// that reason.
fn plane_example_cdylib() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_plugin_example_plane");
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
            "the plane example plugin cdylib is not built under CI: `cargo build -p \
             busbar-plugin-example-plane` must run before this suite (checked both the uplifted \
             target dir and target/deps). Refusing to silently skip the ONLY proof that the 1.6.0 \
             plane ABI has a real rider."
        );
    }
    candidate
}

/// Load the dropped-in example plane, or `None` when the artifact is absent (see the note above).
fn dropped_in_plane() -> Option<DynPlane> {
    let path = plane_example_cdylib()?;
    Some(
        busbar_plugin_loader::load_plane(&path)
            .expect("load the example plane over the HOT-tier ABI"),
    )
}

/// The work item every drive here dispatches: a finite request buffer, no emit channel.
const INBOUND: &[u8] = b"a-work-item";

/// Drive `plane` through its whole lifecycle over `host`/`host_ctx`, returning
/// `(build, start, dispatch)` statuses. Frees the plane state before returning.
///
/// # Safety
/// `host` must point at a live [`PlaneHostVtable`] and `host_ctx` must be a handle minted for a
/// CURRENTLY-LIVE dispatch on THIS thread — both of which hold inside a `with_dispatch_scope` closure.
unsafe fn drive(
    plane: &DynPlane,
    host: *const PlaneHostVtable,
    host_ctx: HostCtx,
) -> (StatusClass, StatusClass, StatusClass) {
    // SAFETY: forwarded from this fn's own contract.
    let (build_status, handle) = unsafe { plane.build(host, host_ctx, b"{}", &[]) };
    let Some(handle) = handle else {
        return (
            build_status,
            StatusClass::Unsupported,
            StatusClass::Unsupported,
        );
    };
    // SAFETY: `handle.ptr` is the live state `build` just produced.
    assert_eq!(unsafe { plane.hydrate(handle.ptr) }, StatusClass::Ok);
    // SAFETY: as above.
    let start_status = unsafe { plane.start(handle.ptr) };
    let work = WorkItem::new(InboundHandle::finite_buffer(INBOUND), EmitHandle::absent());
    // SAFETY: as above; `INBOUND` is `'static`.
    let dispatch_status = unsafe { plane.dispatch(handle.ptr, &work) };
    if let Some(free) = handle.free {
        free(handle.ptr);
    }
    (build_status, start_status, dispatch_status)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE TAP — a forwarding instrument on five REAL host slots
//
// Each shim below records what crossed and then CALLS THE REAL HOST FN, returning whatever the real
// host returned. It replaces no behaviour: the kernel's own `govern_admit` still runs its limit
// chain, its own `meter_charge` still reaches `plane_host::govern::charge`, its own `cost_reserve`
// still mints into the process-global lease registry. What the tap adds is the ability to say HOW
// MANY TIMES and WITH WHAT ARGUMENTS the plugin crossed — the two questions "`dispatch` returned Ok"
// cannot answer, and the two questions `docs/design/BUSBAR-1.6.0.md` §11a's "no 0-caller ABI" is actually about.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The tap's state is process-global (an `extern "C-unwind"` fn captures nothing), so every test that
/// arms it holds this lock first. Poison is stepped over — one panicking test must not disable the rest.
static TAP_LOCK: Mutex<()> = Mutex::new(());

/// The REAL host slots the tap forwards into, captured from `build_plane_host_vtable()`'s own table at
/// arm time. `None` means the tap is not armed, and every shim fails closed on that.
static REAL: Mutex<Option<RealSlots>> = Mutex::new(None);

/// The five real fn-pointers the tap forwards to. Fn pointers are `Send`/`Sync` and `Copy`.
#[derive(Clone, Copy)]
struct RealSlots {
    clock_now: ClockNowFn,
    govern_admit: GovernAdmitFn,
    meter_charge: MeterChargeFn,
    cost_reserve: CostReserveFn,
    cost_settle: CostSettleFn,
}

fn real() -> Option<RealSlots> {
    *REAL.lock().unwrap_or_else(|p| p.into_inner())
}

/// Per-slot crossing counts.
static N_CLOCK: AtomicU64 = AtomicU64::new(0);
/// See [`N_CLOCK`].
static N_ADMIT: AtomicU64 = AtomicU64::new(0);
/// See [`N_CLOCK`].
static N_METER: AtomicU64 = AtomicU64::new(0);
/// See [`N_CLOCK`].
static N_RESERVE: AtomicU64 = AtomicU64::new(0);
/// See [`N_CLOCK`].
static N_SETTLE: AtomicU64 = AtomicU64::new(0);

/// The last clock reading the REAL host handed back to the plugin.
static SEEN_CLOCK: AtomicU64 = AtomicU64::new(0);
/// The `Usage.amount` the plugin wrote — a RAW COUNT.
static SEEN_AMOUNT: AtomicU64 = AtomicU64::new(u64::MAX);
/// The `Usage.unit_cost_micros` the plugin wrote. MUST be 0 (#43/#71: a plane counts, it never values).
static SEEN_UNIT_COST: AtomicU64 = AtomicU64::new(u64::MAX);
/// The sum of every nanodollar field the plugin handed `cost_reserve`/`cost_settle`. MUST be 0.
static SEEN_MONEY_NANOS: AtomicU64 = AtomicU64::new(u64::MAX);
/// The lease id the REAL `cost_reserve` minted for the plugin, and the real `cost_settle` then found.
static SEEN_LEASE: AtomicU64 = AtomicU64::new(0);
/// `1` once the REAL `cost_settle` answered `Ok` for that lease — the round trip through core's own
/// registry, closed.
static LEASE_SETTLED_BY_REAL_HOST: AtomicU64 = AtomicU64::new(0);

/// THE DIAGNOSTIC THAT NAMES THE BROKEN SLOT. Every tap shim records here when the REAL host answered
/// its call with a fail-closed value (`Deny`, `Rejected`, a non-`Ok` status, a `0` clock).
///
/// Without it, a host slot whose implementation breaks shows up only as the plane's own
/// `Refused` — correct, fail-closed, and completely silent about WHICH capability stopped working.
/// A suite that says "the dispatch refused" sends its reader into a 13,000-line host to guess; a suite
/// that says "`meter_charge` answered Rejected" does not. The plane cannot name it (it is on the far
/// side of a `dlopen` and holds only statuses), so the tap does.
static REFUSING_SLOT: Mutex<Option<&'static str>> = Mutex::new(None);

fn note_refusal(slot: &'static str) {
    let mut g = REFUSING_SLOT.lock().unwrap_or_else(|p| p.into_inner());
    if g.is_none() {
        *g = Some(slot);
    }
}

/// What the real host refused, rendered for an assertion message.
fn refusal_diagnosis() -> String {
    match *REFUSING_SLOT.lock().unwrap_or_else(|p| p.into_inner()) {
        Some(slot) => format!(
            "the REAL host slot `{slot}` answered its fail-closed value, so the plane refused the \
             work. Fix that slot's implementation"
        ),
        None => "no host slot reported a fail-closed answer, so the refusal came from the PLANE \
                 side of the seam (its own guards, or a slot it found absent)"
            .to_string(),
    }
}

/// Drive `plane` under the tap purely to find out WHICH host slot refused, and render it. Used by the
/// untapped headline test so a break in core still names itself.
fn diagnose(plane: &DynPlane, vt: &PlaneHostVtable, host_ctx: HostCtx) -> String {
    let (_guard, tapped) = arm(vt);
    let host: *const PlaneHostVtable = &tapped;
    // SAFETY: `tapped` is a live table on this frame; `host_ctx` is the live handle for this dispatch.
    let _ = unsafe { drive(plane, host, host_ctx) };
    refusal_diagnosis()
}

/// Arm the tap over `vt` (the REAL table) and return an instrumented COPY of it plus the lock. Every
/// slot not tapped is carried over from the real table verbatim — the copy is the real host with five
/// listening posts on it, not a substitute for it.
fn arm(vt: &PlaneHostVtable) -> (MutexGuard<'static, ()>, PlaneHostVtable) {
    let guard = TAP_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    for c in [&N_CLOCK, &N_ADMIT, &N_METER, &N_RESERVE, &N_SETTLE] {
        c.store(0, Ordering::SeqCst);
    }
    for c in [&SEEN_AMOUNT, &SEEN_UNIT_COST, &SEEN_MONEY_NANOS] {
        c.store(u64::MAX, Ordering::SeqCst);
    }
    for c in [&SEEN_CLOCK, &SEEN_LEASE, &LEASE_SETTLED_BY_REAL_HOST] {
        c.store(0, Ordering::SeqCst);
    }
    *REFUSING_SLOT.lock().unwrap_or_else(|p| p.into_inner()) = None;
    let slots = RealSlots {
        clock_now: vt.clock_now.expect("the real host wires `clock_now`"),
        govern_admit: vt.govern_admit.expect("the real host wires `govern_admit`"),
        meter_charge: vt.meter_charge.expect("the real host wires `meter_charge`"),
        cost_reserve: vt.cost_reserve.expect("the real host wires `cost_reserve`"),
        cost_settle: vt.cost_settle.expect("the real host wires `cost_settle`"),
    };
    *REAL.lock().unwrap_or_else(|p| p.into_inner()) = Some(slots);
    let tapped = PlaneHostVtable {
        clock_now: Some(tap_clock_now),
        govern_admit: Some(tap_govern_admit),
        meter_charge: Some(tap_meter_charge),
        cost_reserve: Some(tap_cost_reserve),
        cost_settle: Some(tap_cost_settle),
        ..copy_of(vt)
    };
    (guard, tapped)
}

/// A field-by-field copy of the real table. `PlaneHostVtable` is a plain `#[repr(C)]` record of
/// `Option<fn>` slots plus its frozen header, so a copy is total and carries no state.
fn copy_of(vt: &PlaneHostVtable) -> PlaneHostVtable {
    // SAFETY: `PlaneHostVtable` is `#[repr(C)]` and every field is a `Copy` POD (the frozen preamble,
    // two integers, and `Option<fn>` slots). A bitwise read produces an independent, valid table.
    unsafe { core::ptr::read(vt as *const PlaneHostVtable) }
}

extern "C-unwind" fn tap_clock_now(host: HostCtx) -> u64 {
    N_CLOCK.fetch_add(1, Ordering::SeqCst);
    let Some(r) = real() else { return 0 };
    let v = (r.clock_now)(host);
    SEEN_CLOCK.store(v, Ordering::SeqCst);
    if v == 0 {
        note_refusal("clock_now");
    }
    v
}

extern "C-unwind" fn tap_govern_admit(host: HostCtx, facts: *const Facts) -> Decision {
    N_ADMIT.fetch_add(1, Ordering::SeqCst);
    let Some(r) = real() else {
        return Decision::Deny;
    };
    let d = (r.govern_admit)(host, facts);
    if d == Decision::Deny {
        note_refusal("govern_admit");
    }
    d
}

extern "C-unwind" fn tap_meter_charge(host: HostCtx, usage: *const Usage) -> MeterOutcome {
    N_METER.fetch_add(1, Ordering::SeqCst);
    let Some(r) = real() else {
        return MeterOutcome::Rejected;
    };
    if !usage.is_null() {
        // SAFETY: a non-null `usage` is a live, initialized `Usage` for the call (ABI discipline).
        let u = unsafe { &*usage };
        SEEN_AMOUNT.store(u.amount, Ordering::SeqCst);
        SEEN_UNIT_COST.store(u.unit_cost_micros, Ordering::SeqCst);
    }
    let outcome = (r.meter_charge)(host, usage);
    if outcome != MeterOutcome::Charged {
        note_refusal("meter_charge");
    }
    outcome
}

extern "C-unwind" fn tap_cost_reserve(
    host: HostCtx,
    reserve_nanos: u64,
    flat_fee_nanos: u64,
    cap_nanos: u64,
    cap_present: bool,
    out: *mut MaybeUninit<CostLeaseId>,
) -> StatusClass {
    N_RESERVE.fetch_add(1, Ordering::SeqCst);
    SEEN_MONEY_NANOS.store(
        reserve_nanos
            .saturating_add(flat_fee_nanos)
            .saturating_add(cap_nanos),
        Ordering::SeqCst,
    );
    let Some(r) = real() else {
        return StatusClass::Refused;
    };
    let status = (r.cost_reserve)(
        host,
        reserve_nanos,
        flat_fee_nanos,
        cap_nanos,
        cap_present,
        out,
    );
    if status == StatusClass::Ok && !out.is_null() {
        // SAFETY: init-only-on-Ok — the REAL host wrote `out` before returning `Ok`, and `out` is the
        // plugin's own live slot for the call.
        SEEN_LEASE.store(unsafe { (*out).assume_init() }.0, Ordering::SeqCst);
    } else if status != StatusClass::Ok {
        note_refusal("cost_reserve");
    }
    status
}

extern "C-unwind" fn tap_cost_settle(
    host: HostCtx,
    lease: CostLeaseId,
    settle_nanos: u64,
    breakdown_ptr: *const u8,
    breakdown_len: usize,
    out: *mut MaybeUninit<CostSettleOut>,
) -> StatusClass {
    N_SETTLE.fetch_add(1, Ordering::SeqCst);
    SEEN_MONEY_NANOS.fetch_add(settle_nanos, Ordering::SeqCst);
    let Some(r) = real() else {
        return StatusClass::Refused;
    };
    let status = (r.cost_settle)(host, lease, settle_nanos, breakdown_ptr, breakdown_len, out);
    if status == StatusClass::Ok && lease.0 == SEEN_LEASE.load(Ordering::SeqCst) && lease.0 != 0 {
        LEASE_SETTLED_BY_REAL_HOST.store(1, Ordering::SeqCst);
    } else if status != StatusClass::Ok {
        note_refusal("cost_settle");
    }
    status
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The proofs
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// THE HEADLINE. A plane cdylib — dlopened, its decl read through the airlock, its vocabulary
/// materialised — is handed the UNMODIFIED `build_plane_host_vtable()` and serves a work item end to
/// end. No tap, no substitute, no hand-built table: core's own 44 slots, and a plugin calling six of
/// them from the far side of a `dlopen`.
#[test]
fn dropped_in_plane_rides_the_real_host_vtable() {
    let Some(plane) = dropped_in_plane() else {
        eprintln!("skip: plane example cdylib not built");
        return;
    };
    let app = TestApp::new().build();
    with_dispatch_scope(&app, |host_ctx, vt| {
        let host: *const PlaneHostVtable = vt;
        // SAFETY: `vt` is core's own live table for this scope and `host_ctx` is the handle it minted
        // for THIS dispatch on THIS thread — exactly `recover`'s invariant.
        let (build, start, dispatch) = unsafe { drive(&plane, host, host_ctx) };
        assert_eq!(
            build,
            StatusClass::Ok,
            "the plane builds against the real host"
        );
        if start != StatusClass::Ok || dispatch != StatusClass::Ok {
            // Re-drive under the tap so the failure NAMES the host slot that broke, instead of
            // reporting the plane's (correct, fail-closed, uninformative) `Refused`.
            panic!(
                "the dropped-in plane did not serve over the real host vtable \
                 (start={start:?}, dispatch={dispatch:?}): {}",
                diagnose(&plane, vt, host_ctx)
            );
        }
    });
}

/// EXACT CROSSING COUNTS. One dispatch crosses `govern_admit`, `meter_charge`, `cost_reserve` and
/// `cost_settle` exactly ONCE each, and `clock_now` twice (once at `start`, once at `dispatch`) — and
/// every one of those calls reached the REAL host fn and got the real host's answer, because the tap
/// forwards rather than replaces.
///
/// `assert_eq!(…, 1)` rather than `> 0` on purpose: an exact count is the assertion a plane that
/// stopped crossing and a plane that started crossing twice cannot both satisfy.
#[test]
fn the_real_host_vtable_is_crossed_once_per_slot_per_dispatch() {
    let Some(plane) = dropped_in_plane() else {
        eprintln!("skip: plane example cdylib not built");
        return;
    };
    let app = TestApp::new().build();
    with_dispatch_scope(&app, |host_ctx, vt| {
        let (_guard, tapped) = arm(vt);
        let host: *const PlaneHostVtable = &tapped;
        // SAFETY: `tapped` is a live table on this frame carrying core's own slots behind the tap;
        // `host_ctx` is the live handle for this dispatch.
        let (_, start, dispatch) = unsafe { drive(&plane, host, host_ctx) };
        assert_eq!(start, StatusClass::Ok, "{}", refusal_diagnosis());
        assert_eq!(dispatch, StatusClass::Ok, "{}", refusal_diagnosis());

        assert_eq!(
            N_CLOCK.load(Ordering::SeqCst),
            2,
            "`start` and `dispatch` each take the host's clock — the plane holds none of its own"
        );
        for (slot, n) in [
            ("govern_admit", &N_ADMIT),
            ("meter_charge", &N_METER),
            ("cost_reserve", &N_RESERVE),
            ("cost_settle", &N_SETTLE),
        ] {
            assert_eq!(
                n.load(Ordering::SeqCst),
                1,
                "one dispatch must cross `{slot}` exactly once. A zero here is literally the \
                 '0-caller ABI' docs/design/BUSBAR-1.6.0.md §11a forbids."
            );
        }
    });
}

/// THE NEGATIVE CONTROL, PER SLOT, AGAINST THE REAL HOST. Withdraw exactly ONE slot from a copy of
/// core's own table and drive again: the dispatch must refuse, for every slot, every time.
///
/// This is the test that makes the counts above mean something. A reference to `PlaneHostVtable` that
/// nothing calls satisfies any grep and every `Ok`; it cannot satisfy this. If a slot's withdrawal
/// leaves the dispatch green, that slot has no rider — and this says which one by name.
#[test]
fn withdrawing_one_real_host_slot_refuses_the_dispatch() {
    let Some(plane) = dropped_in_plane() else {
        eprintln!("skip: plane example cdylib not built");
        return;
    };
    type Withdraw = (&'static str, fn(&mut PlaneHostVtable));
    const WITHDRAWABLE: [Withdraw; 6] = [
        ("clock_now", |vt| vt.clock_now = None),
        ("govern_admit", |vt| vt.govern_admit = None),
        ("meter_charge", |vt| vt.meter_charge = None),
        ("cost_reserve", |vt| vt.cost_reserve = None),
        ("cost_settle", |vt| vt.cost_settle = None),
        ("journal_append", |vt| vt.journal_append = None),
    ];

    let app = TestApp::new().build();
    with_dispatch_scope(&app, |host_ctx, vt| {
        // The baseline, first: the untouched table serves. Without this the loop below could pass
        // because the plane refuses everything.
        let base: *const PlaneHostVtable = vt;
        // SAFETY: core's own live table and live handle for this dispatch.
        let (_, _, baseline) = unsafe { drive(&plane, base, host_ctx) };
        if baseline != StatusClass::Ok {
            panic!(
                "the UNTOUCHED real host must serve, or the withdrawals below prove nothing: {}",
                diagnose(&plane, vt, host_ctx)
            );
        }

        for (slot, withdraw) in WITHDRAWABLE {
            let mut degraded = copy_of(vt);
            withdraw(&mut degraded);
            let host: *const PlaneHostVtable = &degraded;
            // SAFETY: `degraded` is a live, well-formed table on this frame; only one slot is null.
            let (build, start, dispatch) = unsafe { drive(&plane, host, host_ctx) };
            assert_eq!(
                build,
                StatusClass::Ok,
                "withdrawing `{slot}` leaves a well-formed table — an absent capability is not a \
                 broken host, so `build` still succeeds and the WORK is what refuses"
            );
            assert_eq!(
                start == StatusClass::Refused,
                slot == "clock_now",
                "`start` reaches `clock_now` and nothing else; withdrawing `{slot}` said otherwise"
            );
            assert_eq!(
                dispatch,
                StatusClass::Refused,
                "withdrawing `{slot}` must refuse the dispatch. A slot whose absence changes \
                 nothing is a slot the plane never calls — and an ABI with no callers is what \
                 docs/design/BUSBAR-1.6.0.md §11a's cut gate is about."
            );
        }
    });
}

/// THE VALUE, NOT JUST THE CALL. The clock reading the plugin received is the HOST's — it brackets
/// core's own `store::now_ms()` across the call. A plane that fabricated a plausible constant would
/// satisfy "crossed the slot"; it would not satisfy this.
#[test]
fn the_plane_reads_the_hosts_own_clock() {
    let Some(plane) = dropped_in_plane() else {
        eprintln!("skip: plane example cdylib not built");
        return;
    };
    let app = TestApp::new().build();
    with_dispatch_scope(&app, |host_ctx, vt| {
        let before_nanos = busbar_kernel::store::now_ms().saturating_mul(1_000_000);
        let (_guard, tapped) = arm(vt);
        let host: *const PlaneHostVtable = &tapped;
        // SAFETY: live table on this frame, live handle for this dispatch.
        let (_, start, dispatch) = unsafe { drive(&plane, host, host_ctx) };
        assert_eq!(start, StatusClass::Ok, "{}", refusal_diagnosis());
        assert_eq!(dispatch, StatusClass::Ok, "{}", refusal_diagnosis());
        let after_nanos = busbar_kernel::store::now_ms().saturating_mul(1_000_000);

        let seen = SEEN_CLOCK.load(Ordering::SeqCst);
        assert_ne!(
            seen, 0,
            "`0` is the slot's fail-closed reading, never a time"
        );
        assert!(
            seen >= before_nanos && seen <= after_nanos,
            "the plane must have read the HOST's clock: got {seen}, host bracket \
             [{before_nanos}, {after_nanos}]"
        );
    });
}

/// THE MONEY LEASE, THROUGH CORE'S OWN REGISTRY. `cost_reserve` mints into the process-global
/// `CostHold` registry `plane_host::cost_host` owns; the plugin carries the opaque `CostLeaseId` back
/// across the seam and settles against it. The settle succeeding is the proof that the id the PLUGIN
/// held named a lease in the REAL registry — the reserve-then-settle carrier `docs/design/BUSBAR-1.6.0.md` §11a names by name,
/// closed end to end by a dropped-in plugin.
#[test]
fn the_metering_lease_round_trips_through_the_real_registry() {
    let Some(plane) = dropped_in_plane() else {
        eprintln!("skip: plane example cdylib not built");
        return;
    };
    let app = TestApp::new().build();
    with_dispatch_scope(&app, |host_ctx, vt| {
        let (_guard, tapped) = arm(vt);
        let host: *const PlaneHostVtable = &tapped;
        // SAFETY: live table on this frame, live handle for this dispatch.
        let (_, _, dispatch) = unsafe { drive(&plane, host, host_ctx) };
        assert_eq!(dispatch, StatusClass::Ok, "{}", refusal_diagnosis());

        let lease = SEEN_LEASE.load(Ordering::SeqCst);
        assert_ne!(
            lease, 0,
            "the real host must mint a non-`NONE` lease id for the plugin"
        );
        assert_eq!(
            LEASE_SETTLED_BY_REAL_HOST.load(Ordering::SeqCst),
            1,
            "the REAL `cost_settle` must have found and settled the lease the plugin carried back \
             — an id that does not resolve in core's own registry is a seam that does not close"
        );
    });
}

/// PRICING-BLINDNESS, READ OFF THE WIRE, ON THE WAY INTO REAL KERNEL MONEY CODE (#43/#71/#77(3)).
///
/// The plane's whole money obligation is ONE fact per unit: a raw count under a declared class. So:
/// `Usage.amount` is the inbound byte count it was handed, `Usage.unit_cost_micros` is `0` (it holds
/// no rate, so it can compute no price), and every nanodollar field it hands the lease slots is `0`
/// (the lease LIFECYCLE is the plane's; the AMOUNT is the host's). Asserted on the arguments
/// themselves, so a plane that started pricing would red this whatever its documentation claimed.
#[test]
fn the_plane_hands_the_real_host_a_raw_count_and_never_a_price() {
    let Some(plane) = dropped_in_plane() else {
        eprintln!("skip: plane example cdylib not built");
        return;
    };
    let app = TestApp::new().build();
    with_dispatch_scope(&app, |host_ctx, vt| {
        let (_guard, tapped) = arm(vt);
        let host: *const PlaneHostVtable = &tapped;
        // SAFETY: live table on this frame, live handle for this dispatch.
        let (_, _, dispatch) = unsafe { drive(&plane, host, host_ctx) };
        assert_eq!(dispatch, StatusClass::Ok, "{}", refusal_diagnosis());

        assert_eq!(
            SEEN_AMOUNT.load(Ordering::SeqCst),
            INBOUND.len() as u64,
            "the plane reports the RAW COUNT it was handed"
        );
        assert_eq!(
            SEEN_UNIT_COST.load(Ordering::SeqCst),
            0,
            "a PRICING-BLIND plane carries no rate, so `unit_cost_micros` must cross as 0"
        );
        assert_eq!(
            SEEN_MONEY_NANOS.load(Ordering::SeqCst),
            0,
            "every nanodollar the plane handed `cost_reserve`/`cost_settle` must be 0 — a plane \
             that put a figure there would be a plane that priced"
        );
    });
}

/// THE WHOLE DELIVERY PATH. Package the real artifact into a SIGNED first-party tarball, run the
/// three-phase scan, resolve it by alias through `Registry::open_plane` — the exact seam a composition
/// root sees for a dropped-in plane — and then ride core's own host vtable with what comes back.
///
/// The per-hop trust/kind/airlock refusals are the loader suite's to prove; what this adds is that the
/// handle the REGISTRY produces is the one that rides the REAL host, so nothing between the tarball
/// and the vtable quietly degrades it.
#[test]
fn registry_open_plane_yields_a_plane_that_rides_the_real_host_vtable() {
    use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};

    let Some(path) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built");
        return;
    };
    let lib = std::fs::read(&path).expect("read the example-plane cdylib");
    let release = SigningKey::from_bytes(&[1u8; 32]);

    let manifest = Manifest {
        name: "busbar-plane-example".into(),
        alias: "example-plane".into(),
        kind: "plane".into(),
        version: "1.6.0".into(),
        publisher: "busbar".into(),
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
        declares: Default::default(),
    };
    // `sign` fills the digest AND the signature, binding the manifest to these exact bytes.
    let signed = sign(&release, manifest, &lib);

    let dir = std::env::temp_dir().join(format!(
        "busbar-plane-rider-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the plugins dir");
    let tarball =
        busbar_plugin_loader::tarball::package(&signed, "libbusbar_plugin_example_plane.so", &lib)
            .expect("package the signed plane tarball");
    std::fs::write(dir.join("a-plane.tar.gz"), tarball).expect("write the plane tarball");

    // POSTURE A: a first-party release key is held, and NOTHING else is opted into.
    let policy = TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: "1.6.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    let reg = busbar_plugin_loader::registry::scan_and_validate(&dir, &policy)
        .expect("a signed first-party plane scans cleanly");
    assert_eq!(reg.loadable().len(), 1, "the signed plane is loadable");
    let plane = reg
        .open_plane("example-plane")
        .expect("the registry opens the plane over the HOT-tier ABI");
    assert_eq!(plane.name(), "example");

    let app = TestApp::new().build();
    with_dispatch_scope(&app, |host_ctx, vt| {
        let (_guard, tapped) = arm(vt);
        let host: *const PlaneHostVtable = &tapped;
        // SAFETY: live table on this frame, live handle for this dispatch.
        let (build, start, dispatch) = unsafe { drive(&plane, host, host_ctx) };
        assert_eq!(build, StatusClass::Ok);
        assert_eq!(start, StatusClass::Ok, "{}", refusal_diagnosis());
        assert_eq!(dispatch, StatusClass::Ok, "{}", refusal_diagnosis());
        assert_eq!(N_METER.load(Ordering::SeqCst), 1);
        assert_eq!(N_RESERVE.load(Ordering::SeqCst), 1);
        assert_eq!(N_SETTLE.load(Ordering::SeqCst), 1);
    });

    let _ = std::fs::remove_dir_all(&dir);
}
