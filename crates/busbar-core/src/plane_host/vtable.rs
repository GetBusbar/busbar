// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HOST side of the [`PlaneHostVtable`]: the construction point that fills every slot with a
//! host-side `extern "C-unwind"` fn, plus the three PROOF-OF-LIFE impls wired over real core
//! primitives. The DISPATCH family (five more — `nested_dispatch`, `workhandle_open`/`_resume`,
//! `entitlement_check`, `gate_scan`) is wired in [`super::dispatch`]. The remaining fourteen are
//! `unimplemented!()` stubs — one slot each for the Phase-2 capability fan-out to fill.
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

use super::{recover, HostState};
use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
use busbar_plugin::hot::{
    AdmissionId, AuthQuery, AuthResolved, CounterpartyRef, Decision, EgressDesc, EgressId,
    EgressOpen, Facts, FramingDesc, JournalQuery, Key, MeterOutcome, MetricSample, Seq, Signal,
    StatusClass, TrustVerdict, Usage, VerifyLease, VerifyVerdict,
};
use busbar_plugin::AbiPreamble;
use core::mem::MaybeUninit;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Build the host's [`PlaneHostVtable`]: the FROZEN preamble + sized/versioned header, then every
/// capability slot `Some(<a host-side fn>)`. Three slots are wired over real primitives here and the
/// DISPATCH family (five) in [`super::dispatch`]; the rest are typed `unimplemented!()` stubs the
/// Phase-2 fan-out replaces. Every slot type-checks, so the fan-out has exactly one hole to fill per
/// capability.
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

        // ── STUBBED (Phase 2 fan-out — one slot each), except the DISPATCH family wired in
        //    `super::dispatch` (nested_dispatch / workhandle_open / workhandle_resume /
        //    entitlement_check / gate_scan) ──────────────────────────────────────────────────────
        meter_charge: Some(meter_charge),
        breaker_admit: Some(breaker_admit),
        breaker_settle: Some(breaker_settle),
        verify_lookup: Some(verify_lookup),
        verify_store: Some(verify_store),
        egress_open: Some(egress_open),
        egress_poll: Some(egress_poll),
        egress_write: Some(egress_write),
        egress_close: Some(egress_close),
        journal_append: Some(journal_append),
        journal_read: Some(journal_read),
        nested_dispatch: Some(super::dispatch::nested_dispatch),
        workhandle_open: Some(super::dispatch::workhandle_open),
        workhandle_resume: Some(super::dispatch::workhandle_resume),
        drift_quarantine: Some(drift_quarantine),
        approval_redeem: Some(approval_redeem),
        auth_resolve: Some(auth_resolve),
        trust_evaluate: Some(trust_evaluate),
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

/// WIRED `govern_admit` → a faithful MINIMAL admit over the real [`Facts`] POD: admit iff the tenant's
/// remaining budget covers the requested units, else deny.
///
/// This is a real decision computed over the actual boundary POD, not a constant. It deliberately does
/// NOT yet drive the full `crate::governance::GovState` admission (pool cells, rate limiters, the
/// `AdmitGrant` release atomics) — that wiring, and registering the resulting admission guard in the
/// [`DispatchScope`](super::DispatchScope), is a Phase-2 fan-out step. Fail-closed on panic.
extern "C-unwind" fn govern_admit(host: HostCtx, facts: *const Facts) -> Decision {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let _state: &HostState = unsafe { recover(host) };
        if facts.is_null() {
            return Decision::Deny;
        }
        // SAFETY: a non-null `facts` is a live, initialized `Facts` for the call (ABI discipline).
        let f = unsafe { &*facts };
        if f.budget_remaining >= f.tokens {
            Decision::Admit
        } else {
            Decision::Deny
        }
    }))
    .unwrap_or(Decision::Deny) // fail-closed: a panicked admit denies.
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// STUBBED slots — typed placeholders; the Phase-2 fan-out fills one each. Each has the EXACT
// fn-pointer signature of its vtable slot, so the whole surface type-checks.
// ─────────────────────────────────────────────────────────────────────────────────────────────

extern "C-unwind" fn meter_charge(_host: HostCtx, _usage: *const Usage) -> MeterOutcome {
    unimplemented!("plane_host::meter_charge — Phase 2")
}
extern "C-unwind" fn breaker_admit(_host: HostCtx, _key: *const Key) -> AdmissionId {
    unimplemented!("plane_host::breaker_admit — Phase 2")
}
extern "C-unwind" fn breaker_settle(
    _host: HostCtx,
    _admission: AdmissionId,
    _signal: *const Signal,
) -> StatusClass {
    unimplemented!("plane_host::breaker_settle — Phase 2")
}
extern "C-unwind" fn verify_lookup(
    _host: HostCtx,
    _key: *const Key,
    _out: *mut MaybeUninit<VerifyVerdict>,
) -> StatusClass {
    unimplemented!("plane_host::verify_lookup — Phase 2")
}
extern "C-unwind" fn verify_store(
    _host: HostCtx,
    _key: *const Key,
    _lease: VerifyLease,
    _ttl_secs: u64,
) -> StatusClass {
    unimplemented!("plane_host::verify_store — Phase 2")
}
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
extern "C-unwind" fn journal_append(
    _host: HostCtx,
    _scope: u32,
    _content_ptr: *const u8,
    _content_len: usize,
    _framing: *const FramingDesc,
) -> Seq {
    unimplemented!("plane_host::journal_append — Phase 2")
}
extern "C-unwind" fn journal_read(
    _host: HostCtx,
    _query: *const JournalQuery,
    _buf: *mut u8,
    _buf_cap: usize,
    _out_written: *mut usize,
) -> StatusClass {
    unimplemented!("plane_host::journal_read — Phase 2")
}
extern "C-unwind" fn drift_quarantine(_host: HostCtx, _key: *const Key) -> StatusClass {
    unimplemented!("plane_host::drift_quarantine — Phase 2")
}
extern "C-unwind" fn approval_redeem(_host: HostCtx, _key: *const Key) -> StatusClass {
    unimplemented!("plane_host::approval_redeem — Phase 2")
}
extern "C-unwind" fn auth_resolve(
    _host: HostCtx,
    _query: *const AuthQuery,
    _out: *mut MaybeUninit<AuthResolved>,
) -> StatusClass {
    unimplemented!("plane_host::auth_resolve — Phase 2")
}
extern "C-unwind" fn trust_evaluate(
    _host: HostCtx,
    _counterparty: *const CounterpartyRef,
) -> TrustVerdict {
    unimplemented!("plane_host::trust_evaluate — Phase 2")
}
