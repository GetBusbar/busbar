// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HOST side of the [`PlaneHostVtable`]: the construction point that fills every slot with a
//! host-side `extern "C-unwind"` fn, plus the three PROOF-OF-LIFE impls wired over real core
//! primitives. The remaining nineteen are `unimplemented!()` stubs — one slot each for the Phase-2
//! capability fan-out to fill against this scaffold.
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
//!
//! The stubs deliberately panic (`unimplemented!`) — they are typed placeholders proving the whole
//! vtable constructs, not runnable host calls.

use super::{recover, trust, HostState};
use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
use busbar_plugin::hot::{
    AuthQuery, AuthResolved, CallerRef, ContentChunk, Decision, EgressDesc, EgressId, EgressOpen,
    Facts, GateDecision, MeterOutcome, MetricSample, OpDesc, OpResult, StatusClass, TargetRef,
    Usage, WorkHandleDesc, WorkHandleId,
};
use busbar_plugin::AbiPreamble;
use core::mem::MaybeUninit;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Build the host's [`PlaneHostVtable`]: the FROZEN preamble + sized/versioned header, then every
/// capability slot `Some(<a host-side fn>)`. Three slots are wired over real primitives; the rest are
/// typed `unimplemented!()` stubs the Phase-2 fan-out replaces. Every slot type-checks, so the fan-out
/// has exactly one hole to fill per capability.
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

        // ── STUBBED (Phase 2 fan-out — one slot each) ──────────────────────────────────────────
        meter_charge: Some(meter_charge),
        breaker_admit: Some(super::breaker::breaker_admit),
        breaker_settle: Some(super::breaker::breaker_settle),
        verify_lookup: Some(trust::verify_lookup),
        verify_store: Some(trust::verify_store),
        egress_open: Some(egress_open),
        egress_poll: Some(egress_poll),
        egress_write: Some(egress_write),
        egress_close: Some(egress_close),
        journal_append: Some(super::journal::journal_append),
        journal_read: Some(super::journal::journal_read),
        nested_dispatch: Some(nested_dispatch),
        workhandle_open: Some(workhandle_open),
        workhandle_resume: Some(workhandle_resume),
        drift_quarantine: Some(trust::drift_quarantine),
        approval_redeem: Some(trust::approval_redeem),
        auth_resolve: Some(auth_resolve),
        trust_evaluate: Some(trust::trust_evaluate),
        entitlement_check: Some(entitlement_check),
        gate_scan: Some(gate_scan),
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
// STUBBED slots — typed placeholders; the Phase-2 fan-out fills one each. Each has the EXACT
// fn-pointer signature of its vtable slot, so the whole surface type-checks.
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
extern "C-unwind" fn egress_open(
    _host: HostCtx,
    _desc: *const EgressDesc,
    _out: *mut MaybeUninit<EgressOpen>,
) -> StatusClass {
    unimplemented!("plane_host::egress_open — Phase 2")
}
extern "C-unwind" fn egress_poll(
    _host: HostCtx,
    _egress: EgressId,
    _buf: *mut u8,
    _buf_cap: usize,
    _out_written: *mut usize,
) -> StatusClass {
    unimplemented!("plane_host::egress_poll — Phase 2")
}
extern "C-unwind" fn egress_write(
    _host: HostCtx,
    _egress: EgressId,
    _buf: *const u8,
    _len: usize,
) -> StatusClass {
    unimplemented!("plane_host::egress_write — Phase 2")
}
extern "C-unwind" fn egress_close(_host: HostCtx, _egress: EgressId) -> StatusClass {
    unimplemented!("plane_host::egress_close — Phase 2")
}
// journal_append / journal_read are WIRED in `super::journal` (the JOURNAL family, over the real
// `crate::audit` hash chain). The builder references them directly; no stub lives here.
extern "C-unwind" fn nested_dispatch(
    _host: HostCtx,
    _desc: *const OpDesc,
    _out: *mut MaybeUninit<OpResult>,
) -> StatusClass {
    unimplemented!("plane_host::nested_dispatch — Phase 2")
}
extern "C-unwind" fn workhandle_open(_host: HostCtx, _desc: *const WorkHandleDesc) -> WorkHandleId {
    unimplemented!("plane_host::workhandle_open — Phase 2")
}
extern "C-unwind" fn workhandle_resume(_host: HostCtx, _handle: WorkHandleId) -> StatusClass {
    unimplemented!("plane_host::workhandle_resume — Phase 2")
}
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
extern "C-unwind" fn entitlement_check(
    _host: HostCtx,
    _caller: *const CallerRef,
    _target: *const TargetRef,
) -> bool {
    unimplemented!("plane_host::entitlement_check — Phase 2")
}
extern "C-unwind" fn gate_scan(_host: HostCtx, _chunk: *const ContentChunk) -> GateDecision {
    unimplemented!("plane_host::gate_scan — Phase 2")
}
