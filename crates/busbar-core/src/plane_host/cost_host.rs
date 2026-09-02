// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HOST side of the metering-lease seam (minor-19): the real `cost_reserve` / `cost_settle`
//! shims backed by a host-owned registry of open [`CostHold`](crate::plane::cost::CostHold) leases.
//!
//! A high-rate carrier (a live voice/stream session a plane cannot price after the fact) opens a
//! reserve-then-settle lease with [`cost_reserve`], settles EXACT already-priced increments against
//! it with [`cost_settle`] as it consumes, and reads back exhaustion so it can hard-close the carrier
//! mid-stream. The (sensitive) budget/ceiling state lives HERE behind an opaque [`CostLeaseId`]; only
//! the `u64` handle crosses the seam.
//!
//! ## Money widening (the u64 ↔ u128 boundary)
//!
//! The frozen ABI slot signatures take `u64` nanodollars — a per-lease amount fits `u64` (a ~$18.4B
//! ceiling, far above any single session) and NO `u128` crosses the hot seam. The host widens each
//! amount to its internal [`CostAmount`](crate::plane::cost::CostAmount) (u128 nanodollars) as it
//! builds / settles the hold, so the internal accounting stays lossless.
//!
//! ## Boundary discipline
//!
//! Each shim: recovers its [`HostState`](super::HostState) from the opaque [`HostCtx`] FIRST, runs its
//! body inside a MANDATORY `catch_unwind` (a caught panic maps to the FAIL-CLOSED
//! [`StatusClass::Fault`], never a permissive value), and writes its out-param ONLY on the `Ok` path
//! (init-only-on-Ok, tolerating a null slot via [`busbar_plugin::write_out`]).

use super::{recover, HostState};
use crate::plane::cost::{CostAmount, CostHold};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::{CostLeaseId, CostSettleOut, StatusClass};
use core::mem::MaybeUninit;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// The process-wide registry of OPEN metering leases, keyed by the opaque [`CostLeaseId`] the host
/// minted. A lease outlives a single host call (a live carrier settles many increments against it), so
/// the store is process-global rather than per-dispatch; the `CostHold` behind each id holds the
/// reserve/settled/cap state the plane never sees.
static LEASES: Mutex<Option<HashMap<u64, CostHold>>> = Mutex::new(None);

/// The monotonic lease-id source. Starts at `1` so a minted id is NEVER `0` (the reserved
/// [`CostLeaseId::NONE`] a refusal reads); `fetch_add` hands each reserve the next non-zero id.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Mint the next non-zero lease id, register `hold`, and return the id. `NEXT_ID` starts at `1` and
/// only increments, so the id is always a live (non-`NONE`) handle.
fn register(hold: CostHold) -> CostLeaseId {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let mut guard = LEASES.lock().unwrap_or_else(|p| p.into_inner());
    guard.get_or_insert_with(HashMap::new).insert(id, hold);
    CostLeaseId(id)
}

/// Settle `settle_nanos` against the lease `id` and report exhaustion, or `None` when `id` names no
/// open lease (unknown / already-forgotten). The lease STAYS open after a settle — a live carrier
/// keeps settling increments until it hard-closes; the registry keys off the minted id only.
fn settle(id: u64, settle_nanos: u64) -> Option<bool> {
    let mut guard = LEASES.lock().unwrap_or_else(|p| p.into_inner());
    let hold = guard.as_mut()?.get_mut(&id)?;
    hold.settle_partial(CostAmount(u128::from(settle_nanos)));
    Some(hold.is_exhausted())
}

/// WIRED `cost_reserve` → open a host-owned reserve-then-settle [`CostHold`] over ALREADY-PRICED
/// nanodollars and register it under a freshly minted [`CostLeaseId`].
///
/// The `u64` amounts widen to the internal [`CostAmount`](crate::plane::cost::CostAmount): `reserve_nanos`
/// is the coarse over-estimate, `flat_fee_nanos` the once-per-lease session fee (`0` = none), and the cap
/// is the TRUE budget ceiling exhaustion is judged against — `cap_present == false` leaves the lease
/// UNCAPPED (never exhausts); `cap_present == true` with `cap_nanos == 0` is a REFUSE-ALL cap, denied at
/// the door. On `Ok` the minted [`CostLeaseId`] is written into `out`; a refuse-all cap returns
/// [`StatusClass::Refused`] (`out` untouched ⇒ the plane reads [`CostLeaseId::NONE`] and fails closed);
/// a caught panic returns [`StatusClass::Fault`] (`out` untouched).
pub(super) extern "C-unwind" fn cost_reserve(
    host: HostCtx,
    reserve_nanos: u64,
    flat_fee_nanos: u64,
    cap_nanos: u64,
    cap_present: bool,
    out: *mut MaybeUninit<CostLeaseId>,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`). The registry is process-global, so the state is
        // recovered (validating the live `HostCtx`) and discarded, like `clock_now`.
        let _state: &HostState = unsafe { recover(host) };

        // A refuse-all cap (present, zero) denies the reserve outright: a lease that can never settle a
        // nonzero increment is not worth opening. `out` is left untouched (the plane reads `NONE`).
        if cap_present && cap_nanos == 0 {
            return StatusClass::Refused;
        }
        // `cap_present == false` ⇒ uncapped (never exhausts); otherwise the widened money ceiling.
        let cap: Option<CostAmount> = cap_present.then(|| CostAmount(u128::from(cap_nanos)));
        let hold = CostHold::reserve(
            CostAmount(u128::from(reserve_nanos)),
            CostAmount(u128::from(flat_fee_nanos)),
            cap,
        );
        let lease = register(hold);
        // SAFETY: `out` is a writable, aligned `MaybeUninit<CostLeaseId>` for the call (or null, which
        // `write_out` tolerates); published ONLY on the Ok path (init-only-on-Ok).
        unsafe { busbar_plugin::write_out(out, lease) };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}

/// WIRED `cost_settle` → accrue ONE exact already-priced increment against an open lease and read back
/// whether its budget is now exhausted.
///
/// The host accrues ONLY the scalar `settle_nanos` (widened to [`CostAmount`](crate::plane::cost::CostAmount))
/// toward the cap; the optional itemized `breakdown` bytes are an AUDIT TAP the host never parses on this
/// hot path (`breakdown_len == 0` ⇒ none). On `Ok` a [`CostSettleOut`] carrying the post-settle
/// exhaustion flag is written into `out`; an unknown / already-closed lease returns
/// [`StatusClass::Refused`] (`out` untouched); a caught panic returns [`StatusClass::Fault`] (`out`
/// untouched) — on either the plane fails closed and hard-closes the carrier.
pub(super) extern "C-unwind" fn cost_settle(
    host: HostCtx,
    lease: CostLeaseId,
    settle_nanos: u64,
    _breakdown_ptr: *const u8,
    _breakdown_len: usize,
    out: *mut MaybeUninit<CostSettleOut>,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let _state: &HostState = unsafe { recover(host) };

        // The `breakdown` bytes are an OPAQUE audit tap the host never parses; only the scalar accrues.
        // An unknown / already-closed lease (including the `NONE` sentinel) fails closed.
        match settle(lease.0, settle_nanos) {
            Some(exhausted) => {
                let settle_out = CostSettleOut {
                    size: core::mem::size_of::<CostSettleOut>() as u32,
                    version: busbar_plugin::hot::POD_VERSION,
                    exhausted: u8::from(exhausted),
                    _reserved: 0,
                };
                // SAFETY: `out` is a writable, aligned `MaybeUninit<CostSettleOut>` for the call (or
                // null, tolerated); published ONLY on the Ok path (init-only-on-Ok).
                unsafe { busbar_plugin::write_out(out, settle_out) };
                StatusClass::Ok
            }
            None => StatusClass::Refused, // unknown/closed lease → out-param left untouched.
        }
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}

#[cfg(test)]
#[path = "tests/cost_host_tests.rs"]
mod cost_host_tests;
