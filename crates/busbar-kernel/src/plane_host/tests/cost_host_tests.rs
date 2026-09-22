// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/cost_host.rs` — the host side of the metering-lease
//! seam. Each drives the real `extern "C-unwind"` shim over a live `HostState` recovered through the
//! same `with_dispatch_scope` path a plane's host call takes.

use super::*;
use crate::plane_host::{with_dispatch_scope, PlaneHostVtable};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::{CostLeaseId, CostSettleOut, StatusClass};
use core::mem::MaybeUninit;

/// Drive `f` with a live `HostCtx` minted by `with_dispatch_scope` over a minimal `TestApp` — the
/// cost shims recover the `HostState` (validating the live pointer) but read nothing off `app`.
fn with_host<R>(f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, f)
}

/// Open a lease over `(reserve, fee, cap)` and return its id, asserting the reserve was `Ok`.
fn reserve(
    host: HostCtx,
    reserve_nanos: u64,
    flat_fee_nanos: u64,
    cap: Option<u64>,
) -> CostLeaseId {
    let mut out = MaybeUninit::<CostLeaseId>::uninit();
    let status = cost_reserve(
        host,
        reserve_nanos,
        flat_fee_nanos,
        cap.unwrap_or(0),
        cap.is_some(),
        std::ptr::from_mut(&mut out),
    );
    assert_eq!(status, StatusClass::Ok, "reserve should admit");
    // SAFETY: an `Ok` reserve published the out-param (init-only-on-Ok).
    let lease = unsafe { out.assume_init() };
    assert!(!lease.is_none(), "a minted lease id is never NONE");
    lease
}

/// Settle `settle_nanos` against `lease` (no breakdown tap) and return the reported exhaustion flag,
/// asserting the settle was `Ok`.
fn settle_ok(host: HostCtx, lease: CostLeaseId, settle_nanos: u64) -> bool {
    let mut out = MaybeUninit::<CostSettleOut>::uninit();
    let status = cost_settle(
        host,
        lease,
        settle_nanos,
        core::ptr::null(),
        0,
        std::ptr::from_mut(&mut out),
    );
    assert_eq!(
        status,
        StatusClass::Ok,
        "settle of an open lease should be Ok"
    );
    // SAFETY: an `Ok` settle published the out-param (init-only-on-Ok).
    let settled = unsafe { out.assume_init() };
    settled.exhausted == 1
}

#[test]
fn reserve_then_settle_reaches_exhaustion_at_the_cap() {
    with_host(|host, _vt| {
        // Cap is the TRUE ceiling (1000), independent of the coarse reserve (500 + 0 fee).
        let lease = reserve(host, 500, 0, Some(1_000));
        // Below the cap: budget remains.
        assert!(!settle_ok(host, lease, 400), "400 < 1000 → not exhausted");
        // The running sum crosses the cap (400 + 700 = 1100 ≥ 1000): now dry.
        assert!(settle_ok(host, lease, 700), "1100 ≥ 1000 → exhausted");
        // A further settle keeps reporting exhausted (the lease stays open, still dry).
        assert!(settle_ok(host, lease, 1), "still ≥ cap → still exhausted");
    });
}

#[test]
fn uncapped_lease_never_exhausts() {
    with_host(|host, _vt| {
        let lease = reserve(host, 10, 5, None); // cap_present == false ⇒ uncapped.
        assert!(
            !settle_ok(host, lease, u64::MAX),
            "an uncapped lease is never exhausted, whatever the settle"
        );
    });
}

#[test]
fn refuse_all_cap_denies_the_reserve_and_leaves_out_untouched() {
    with_host(|host, _vt| {
        // A poisoned sentinel: an `Ok` path would OVERWRITE it; a Refused path must leave it as-is.
        let mut out = MaybeUninit::<CostLeaseId>::uninit();
        out.write(CostLeaseId(0xDEAD_BEEF));
        let status = cost_reserve(
            host,
            100,  // reserve
            0,    // fee
            0,    // cap_nanos == 0 …
            true, // … with cap_present ⇒ refuse-all.
            std::ptr::from_mut(&mut out),
        );
        assert_eq!(
            status,
            StatusClass::Refused,
            "a refuse-all cap denies the reserve"
        );
        // SAFETY: `out` was initialized by the poisoned `write` above; a Refused reserve must not have
        // touched it, so the sentinel is intact (the plane would read NONE off its own uninit slot).
        assert_eq!(
            unsafe { out.assume_init() },
            CostLeaseId(0xDEAD_BEEF),
            "a refused reserve leaves out untouched"
        );
    });
}

#[test]
fn settle_of_an_unknown_lease_refuses() {
    with_host(|host, _vt| {
        let mut out = MaybeUninit::<CostSettleOut>::uninit();
        // An id that was never minted (and the NONE sentinel) name no open lease.
        for bogus in [CostLeaseId::NONE, CostLeaseId(u64::MAX)] {
            let status = cost_settle(
                host,
                bogus,
                10,
                core::ptr::null(),
                0,
                std::ptr::from_mut(&mut out),
            );
            assert_eq!(
                status,
                StatusClass::Refused,
                "settling an unknown lease fails closed"
            );
        }
    });
}

#[test]
fn breakdown_bytes_are_an_opaque_tap_the_host_never_parses() {
    with_host(|host, _vt| {
        let lease = reserve(host, 0, 0, Some(1_000));
        // Garbage "breakdown" bytes must not affect the scalar accrual: only `settle_nanos` counts.
        let breakdown = [0xFFu8; 8];
        let mut out = MaybeUninit::<CostSettleOut>::uninit();
        let status = cost_settle(
            host,
            lease,
            250,
            breakdown.as_ptr(),
            breakdown.len(),
            std::ptr::from_mut(&mut out),
        );
        assert_eq!(status, StatusClass::Ok);
        // SAFETY: Ok published the out-param.
        assert_eq!(
            unsafe { out.assume_init() }.exhausted,
            0,
            "250 < 1000 → not exhausted"
        );
    });
}

// ── THE NEUTRAL-SEAM (`MeteringHost`) SHIMS — the same host-owned `CostHold` registry, reached by a
//    statically-linked plane through the plain-Rust trait rather than the C-ABI vtable ──────────────

#[test]
fn neutral_reserve_then_settle_reaches_exhaustion_at_the_real_cap() {
    // Cap is the TRUE ceiling (1000), independent of the coarse reserve (500 + 10 fee).
    let id = reserve_lease(500, 10, Some(1_000)).expect("a non-refuse-all cap opens a lease");
    // Below the cap: not exhausted, and the settled tap tracks the exact running sum.
    assert_eq!(settle_lease(id, 400), Some(false), "400 < 1000 → live");
    assert_eq!(settled_of(id), Some(400), "settled tap = exact running sum");
    // The running sum crosses the cap (400 + 700 = 1100 ≥ 1000): now dry.
    assert_eq!(settle_lease(id, 700), Some(true), "1100 ≥ 1000 → exhausted");
    assert_eq!(settled_of(id), Some(1_100));
    // close returns the ledgered total (the exact settled sum) and FORGETS the lease (idempotent after).
    assert_eq!(
        close_lease(id),
        Some(1_100),
        "close ledgers the exact settled sum"
    );
    assert_eq!(close_lease(id), None, "a second close is a harmless None");
    assert_eq!(
        settle_lease(id, 1),
        None,
        "a settled-closed lease is unknown"
    );
    assert_eq!(settled_of(id), None);
}

#[test]
fn close_lease_applies_the_refund_of_the_unspent_reserve() {
    // A coarse OVER-estimate (reserve 1000 + fee 200 = 1200 debited up front) with an exact settled sum
    // of 700 leaves 500 unspent. `close_lease` ledgers the EXACT settled sum (700, never the coarse
    // reserve), and the refund it reconciles is `reserved − settled` = 1200 − 700 = 500 — the amount that
    // returns to the budget cell (computed, never silently discarded).
    let id = reserve_lease(1_000, 200, Some(10_000)).expect("opens");
    assert_eq!(settle_lease(id, 700), Some(false), "700 < 10_000 → live");
    assert_eq!(
        close_lease(id),
        Some(700),
        "close ledgers the EXACT settled sum, not the coarse reserve"
    );
    // The refund is `reserved − settled`, saturating at zero — asserted on the underlying `CostHold`
    // (the same `finalize()` `close_lease` drives), so the reconciled refund is exact and testable.
    let refunded = CostHold::reserve(CostAmount(1_000), CostAmount(200), Some(CostAmount(10_000)));
    let mut refunded = refunded;
    refunded.settle_partial(CostAmount(700));
    assert_eq!(
        refunded.finalize().refund,
        CostAmount(500),
        "refund = reserved(1200) − settled(700) = 500"
    );
    // An OVER-settle (exact charge above the coarse reserve) refunds ZERO, never a negative.
    let mut over = CostHold::reserve(CostAmount(100), CostAmount(0), Some(CostAmount(10_000)));
    over.settle_partial(CostAmount(400));
    let s = over.finalize();
    assert_eq!(s.ledgered_total, CostAmount(400), "ledgers the true charge");
    assert_eq!(
        s.refund,
        CostAmount(0),
        "an over-settle refunds zero, never negative"
    );
    // A second close is a harmless None (the removal is the double-refund guard).
    assert_eq!(close_lease(id), None, "no double refund on a second close");
}

#[test]
fn neutral_refuse_all_denies_and_uncapped_never_exhausts() {
    // A refuse-all cap (`Some(0)`) denies at the door — the plane reads `None` and fails closed.
    assert_eq!(reserve_lease(100, 0, Some(0)), None, "refuse-all denies");
    // An uncapped lease is never exhausted, whatever the settle.
    let unc = reserve_lease(0, 0, None).expect("uncapped opens");
    assert_eq!(settle_lease(unc, u128::from(u64::MAX)), Some(false));
    assert_eq!(settle_lease(unc, u128::from(u64::MAX)), Some(false));
    assert_eq!(close_lease(unc), Some(u128::from(u64::MAX) * 2));
}

#[test]
fn neutral_and_ffi_seams_share_one_lease_registry() {
    // Open a lease through the NEUTRAL seam, then settle it through the FFI `settle` shim: the two seams
    // key off the SAME `LEASES`/`NEXT_ID`, so the FFI settle moves the ledger the neutral reserve opened.
    let id = reserve_lease(0, 0, Some(1_000)).expect("opens");
    assert_eq!(
        settle(id, 600),
        Some(false),
        "FFI settle sees the neutral lease"
    );
    assert_eq!(settled_of(id), Some(600), "neutral tap sees the FFI settle");
    assert_eq!(
        settle(id, 500),
        Some(true),
        "1100 ≥ 1000 → exhausted, one ledger"
    );
    let _ = close_lease(id);
}

#[test]
fn a_caught_panic_maps_to_fault_and_leaves_out_untouched() {
    // A null `HostCtx` trips `recover`'s debug-assert (tests build with `debug_assertions`), so the
    // shim body panics; the mandatory `catch_unwind` catches it and maps to the fail-closed `Fault`,
    // never `Ok`, with the out-param left untouched.
    let mut out = MaybeUninit::<CostLeaseId>::uninit();
    out.write(CostLeaseId(0x1234));
    let status = cost_reserve(
        std::ptr::null_mut(),
        1,
        0,
        0,
        false,
        std::ptr::from_mut(&mut out),
    );
    assert_eq!(
        status,
        StatusClass::Fault,
        "a caught panic is Fault, never Ok"
    );
    // SAFETY: `out` was initialized by the poisoned `write`; a Fault must not have touched it.
    assert_eq!(
        unsafe { out.assume_init() },
        CostLeaseId(0x1234),
        "a faulted reserve leaves out untouched"
    );
}
