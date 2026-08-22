// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HOST side of the [`PlaneHostVtable`]: the construction point that fills every slot with a
//! host-side `extern "C-unwind"` fn wired over a real core primitive. After the Phase-1 capability
//! fan-out (breaker, govern, trust, journal, egress, dispatch) every slot is now wired — ZERO
//! `unimplemented!()` stubs remain. The three PROOF-OF-LIFE impls (`clock_now`, `metrics_emit`,
//! `govern_admit`) live here; the rest forward into their capability modules ([`super::breaker`],
//! [`super::govern`], [`super::trust`], [`super::journal`], [`super::egress`], [`super::dispatch`]).
//!
//! ## Boundary discipline (reused from `plugin-sdk/boundary.rs`)
//!
//! Every wired fn:
//! 1. recovers its [`HostState`](super::HostState) from the opaque [`HostCtx`] FIRST (the recovery
//!    invariant lives on [`super::recover`]);
//! 2. runs its body inside a MANDATORY `catch_unwind` so no panic unwinds across the seam — a caught
//!    panic maps to the FAIL-CLOSED value for that slot (`Decision::Deny`, `StatusClass::Fault`, a `0`
//!    clock), never to a permissive one;
//! 3. translates POD ↔ primitive by pointer, writing any out-param only on the `Ok` path.

use super::{recover, trust, HostState};
use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
use busbar_plugin::hot::{
    AuthQuery, AuthResolved, Decision, EgressDesc, EgressId, EgressOpen, Facts, MeterOutcome,
    MetricSample, StatusClass, Usage,
};
use busbar_plugin::AbiPreamble;
use core::mem::MaybeUninit;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Build the host's [`PlaneHostVtable`]: the FROZEN preamble + sized/versioned header, then every
/// capability slot `Some(<a host-side fn>)`. Three slots are wired over real primitives here
/// (`clock_now`, `metrics_emit`, `govern_admit`); every other slot forwards into its capability
/// module. After the Phase-1 fan-out every slot is wired — no `unimplemented!()` stub remains.
#[must_use]
pub fn build_plane_host_vtable() -> PlaneHostVtable {
    PlaneHostVtable {
        abi: AbiPreamble::CURRENT,
        size: core::mem::size_of::<PlaneHostVtable>() as u32,
        version: busbar_plugin::ABI_MINOR,

        // ── WIRED proof-of-life (real primitives) ──────────────────────────────────────────────
        govern_admit: Some(govern_admit),
        metrics_emit: Some(metrics_emit),
        clock_now: Some(clock_now),

        // ── WIRED capability slots — each forwards into its capability module (breaker / trust /
        //    egress / journal / dispatch), or a wired local fn (meter_charge, auth_resolve) ────────
        meter_charge: Some(meter_charge),
        breaker_admit: Some(super::breaker::breaker_admit),
        breaker_admit_reason: Some(super::breaker::breaker_admit_reason),
        breaker_settle: Some(super::breaker::breaker_settle),
        verify_lookup: Some(trust::verify_lookup),
        verify_store: Some(trust::verify_store),
        egress_open: Some(egress_open),
        egress_poll: Some(egress_poll),
        egress_write: Some(egress_write),
        egress_close: Some(egress_close),
        journal_append: Some(super::journal::journal_append),
        journal_read: Some(super::journal::journal_read),
        nested_dispatch: Some(super::dispatch::nested_dispatch),
        workhandle_open: Some(super::dispatch::workhandle_open),
        workhandle_resume: Some(super::dispatch::workhandle_resume),
        drift_quarantine: Some(trust::drift_quarantine),
        approval_redeem: Some(trust::approval_redeem),
        auth_resolve: Some(auth_resolve),
        trust_evaluate: Some(trust::trust_evaluate),
        entitlement_check: Some(super::dispatch::entitlement_check),
        gate_scan: Some(super::dispatch::gate_scan),
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// WIRED slots — real primitives, full boundary discipline.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// WIRED `clock_now` → `crate::store::now_ms`, the host wall clock. The ABI contract is Unix
/// NANOSECONDS, so the host-side milliseconds clock is scaled up; sourcing it through
/// `crate::store::now_ms` keeps the plane off any ambient clock (the whole point of the slot).
extern "C-unwind" fn clock_now(host: HostCtx) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the host passes a live `HostState` ptr for the dispatch duration (see `recover`).
        let _state: &HostState = unsafe { recover(host) };
        crate::store::now_ms().saturating_mul(1_000_000)
    }))
    .unwrap_or(0) // fail-closed: a panicked clock reads 0, never a wild value.
}

/// WIRED `metrics_emit` → the real `metrics` recorder (`crate::metrics`). Reads the borrowed
/// [`MetricSample`] and emits its value as a gauge under the plane-supplied name. Label passthrough /
/// cardinality policy is the Phase-2 host's job; this proves the sample reaches the process recorder.
extern "C-unwind" fn metrics_emit(host: HostCtx, sample: *const MetricSample) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let _state: &HostState = unsafe { recover(host) };
        if sample.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `sample` is a live, initialized `MetricSample` for the call (ABI).
        let s = unsafe { &*sample };
        let value = f64::from_bits(s.value_bits);
        let name: String = if s.name_ptr.is_null() || s.name_len == 0 {
            "busbar_plane_metric".to_string()
        } else {
            // SAFETY: `(name_ptr, name_len)` is a live borrowed range for the call (ABI discipline).
            let bytes = unsafe { std::slice::from_raw_parts(s.name_ptr, s.name_len) };
            String::from_utf8_lossy(bytes).into_owned()
        };
        // Routes to the process-wide `metrics-exporter-prometheus` recorder installed by
        // `crate::metrics::init` (a no-op sink when the operator did not opt in).
        metrics::gauge!(name).set(value);
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}

/// WIRED `govern_admit` → the REAL admission over `crate::governance` (see [`super::govern::admit`]):
/// the budget gate the [`Facts`] POD encodes, then the `GovState::try_admit` limit engine. On `Admit`
/// the RAII [`AdmitGrant`](crate::governance::AdmitGrant) it yields is REGISTERED in the
/// [`DispatchScope`](super::DispatchScope) arena, so it is released on scope-drop no matter how the
/// dispatch future ends (the §4 leak keystone). Fail-closed (`Deny`) on a null POD or any panic.
extern "C-unwind" fn govern_admit(host: HostCtx, facts: *const Facts) -> Decision {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let state: &HostState = unsafe { recover(host) };
        if facts.is_null() {
            return Decision::Deny;
        }
        // SAFETY: a non-null `facts` is a live, initialized `Facts` for the call (ABI discipline).
        let f = unsafe { &*facts };
        super::govern::admit(state, f)
    }))
    .unwrap_or(Decision::Deny) // fail-closed: a panicked admit denies.
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// WIRED capability slots — local host-side fns and forwarders into the capability modules. No
// `unimplemented!()` stub remains: the Phase-1 fan-out filled every slot.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// WIRED `meter_charge` → the REAL metering over `crate::governance` + `crate::plane::cost` (see
/// [`super::govern::charge`]): compute the money-scalar [`CostBreakdown`](crate::plane::cost::CostBreakdown)
/// this usage settles, then accrue it into the write-behind metering time-series. Fail-closed
/// (`Rejected`) on a null POD, a malformed breakdown, or any panic.
extern "C-unwind" fn meter_charge(host: HostCtx, usage: *const Usage) -> MeterOutcome {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let state: &HostState = unsafe { recover(host) };
        if usage.is_null() {
            return MeterOutcome::Rejected;
        }
        // SAFETY: a non-null `usage` is a live, initialized `Usage` for the call (ABI discipline).
        let u = unsafe { &*usage };
        super::govern::charge(state, u)
    }))
    .unwrap_or(MeterOutcome::Rejected) // fail-closed: a panicked charge rejects.
}
// `breaker_admit` / `breaker_settle` are WIRED over the real breaker in `super::breaker` (the BREAKER
// family fan-out); `verify_lookup` / `verify_store` are WIRED over the real trust store in
// `super::trust` (the TRUST family fan-out); their vtable slots reference those modules directly.
// ── WIRED EGRESS family (fan-egress): the `extern "C-unwind"` seam shims. The recovery, the
//    catch_unwind, the fail-closed mapping and the real guarded transport all live in
//    [`super::egress`]; these four are the ABI boundary that forwards into it. ─────────────────────
extern "C-unwind" fn egress_open(
    host: HostCtx,
    desc: *const EgressDesc,
    out: *mut MaybeUninit<EgressOpen>,
) -> StatusClass {
    super::egress::egress_open(host, desc, out)
}
extern "C-unwind" fn egress_poll(
    host: HostCtx,
    egress: EgressId,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> StatusClass {
    super::egress::egress_poll(host, egress, buf, buf_cap, out_written)
}
extern "C-unwind" fn egress_write(
    host: HostCtx,
    egress: EgressId,
    buf: *const u8,
    len: usize,
) -> StatusClass {
    super::egress::egress_write(host, egress, buf, len)
}
extern "C-unwind" fn egress_close(host: HostCtx, egress: EgressId) -> StatusClass {
    super::egress::egress_close(host, egress)
}
// journal_append / journal_read are WIRED in `super::journal` (the JOURNAL family, over the real
// `crate::audit` hash chain). The builder references them directly; no stub lives here.
// `nested_dispatch` / `workhandle_open` / `workhandle_resume` / `entitlement_check` / `gate_scan`
// are WIRED in `super::dispatch` (the DISPATCH family); their vtable slots reference that module.
// `drift_quarantine` / `approval_redeem` / `trust_evaluate` are WIRED over the real trust store in
// `super::trust` (the TRUST family fan-out); their vtable slots reference that module directly.
/// WIRED `auth_resolve` → the REAL principal resolution over `crate::auth` (see
/// [`super::govern::resolve_auth`]): resolve a credential REF to an OPAQUE host-side reference (NEVER
/// plaintext), writing the [`AuthResolved`] out-param ONLY on `Ok`. Fail-closed (`Refused`) on a null
/// query or a query naming no credential; `Fault` on any panic.
extern "C-unwind" fn auth_resolve(
    host: HostCtx,
    query: *const AuthQuery,
    out: *mut MaybeUninit<AuthResolved>,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let state: &HostState = unsafe { recover(host) };
        if query.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `query` is a live, initialized `AuthQuery` for the call (ABI discipline).
        let q = unsafe { &*query };
        match super::govern::resolve_auth(state, q) {
            Some(resolved) => {
                // SAFETY: `out` is a writable, aligned `MaybeUninit<AuthResolved>` for the call; the
                // write publishes ONLY on the Ok path (init-only-on-Ok), tolerating a null slot.
                unsafe { busbar_plugin::write_out(out, resolved) };
                StatusClass::Ok
            }
            None => StatusClass::Refused, // nothing to resolve → out-param left uninitialized.
        }
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}
