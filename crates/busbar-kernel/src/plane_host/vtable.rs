// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HOST side of the [`PlaneHostVtable`]: the construction point that fills the slots the
//! kernel's own callers still drive with a host-side `extern "C-unwind"` fn over a real core
//! primitive: `clock_now`, `govern_admit`/`govern_admit_reason` (bodies in [`super::govern`]),
//! `meter_charge`, `subkey_sign`, `identity_admit` and the host services. Every other family is
//! absent: no plane is handed a `HostCtx`, the host services a plane calls are the `HostSlots`
//! families (BUSBAR-1.6.0.md Part 3 §4), and Appendix A B.6 (l.3846) deletes the egress, pipe,
//! auth-resolve, metrics, counter, journal, dispatch and breaker slots (u30, u35, u36). The table
//! itself goes with `abi::hot`.
//!
//! ## Boundary discipline (reused from `busbar-contract/src/abi/sdk/boundary.rs`)
//!
//! Every wired fn:
//! 1. recovers its [`HostState`](super::HostState) from the opaque [`HostCtx`] FIRST (the recovery
//!    invariant lives on [`super::recover`]);
//! 2. runs its body inside a MANDATORY `catch_unwind` so no panic unwinds across the seam — a caught
//!    panic maps to the FAIL-CLOSED value for that slot (`Decision::Deny`, `StatusClass::Fault`, a `0`
//!    clock), never to a permissive one;
//! 3. translates POD ↔ primitive by pointer, writing any out-param only on the `Ok` path.

use super::recover;
use busbar_contract::abi::hot::host::{HostCtx, PlaneHostVtable};
use busbar_contract::abi::hot::{Decision, Facts, GovRefusal, MeterOutcome, StatusClass, Usage};
use busbar_contract::abi::AbiPreamble;
use core::mem::MaybeUninit;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Build the host's [`PlaneHostVtable`]: the FROZEN preamble + sized/versioned header, then the
/// slots the kernel's own callers drive (the clock, the govern admit, the meter, the card sign, the
/// inbound identity admission) and the host services; every other slot is `None` (BUSBAR-1.6.0.md
/// Appendix A B.6, l.3846: the egress, pipe, auth-resolve, metrics, counter, journal, dispatch and
/// breaker families are deleted; u36, u35).
#[must_use]
pub fn build_plane_host_vtable() -> PlaneHostVtable {
    PlaneHostVtable {
        abi: AbiPreamble::CURRENT,
        size: core::mem::size_of::<PlaneHostVtable>() as u32,
        version: busbar_contract::abi::ABI_MINOR,

        // ── WIRED proof-of-life (real primitives) ──────────────────────────────────────────────
        govern_admit: Some(govern_admit),
        govern_admit_reason: Some(govern_admit_reason),
        clock_now: Some(clock_now),

        // ── WIRED `meter_charge` (the kernel's own `BudgetHost::meter_charge` drives it) ────────
        meter_charge: Some(meter_charge),
        // ── The CARD-SIGN seam (minor-10): the host derives the deployment's domain-separated card
        //    subkey and signs a plane-framed input, so the card SECRET never crosses to the plane.
        //    Wired only when a plane declares a card-signing domain (the neutral `card-signing`
        //    capability marker, enabled by that plane); absent otherwise. ──
        #[cfg(feature = "card-signing")]
        subkey_sign: Some(card_sign),
        #[cfg(not(feature = "card-signing"))]
        subkey_sign: None,
        // ── WIRED `identity_admit` (minor-17) → the host-side inbound admission in
        //    `super::identity_admit`: the configured auth chain + the one verdict resolution over the
        //    caller's own credential, returning an opaque resolved-identity handle. Always wired (the
        //    host owns the auth chain whatever the plane); no plane feature gates it. ────────────────────
        identity_admit: Some(super::identity_admit::identity_admit),
        // ── The HOST SERVICES (minor 30): the host's entropy and wall clock, served here (the
        //    contract holds neither: a codec is handed them as a `CodecHost`). The usage-tap fault
        //    latch and the translate cap are retired slots and stay `None` (row 155). The
        //    trust family (`verify_lookup`/`verify_store`/`verify_decide`/`drift_quarantine`/
        //    `approval_redeem[_q]`/`trust_evaluate`) and `guard_url` stay at the base's `None`: no
        //    plane calls them, and a plane's trust and destination judging are the `HostSlots`
        //    `trust.*` and `dest.judge` services. ──
        entropy_fill: Some(entropy_fill),
        wall_clock: Some(wall_clock),
        ..PlaneHostVtable::EMPTY
    }
}

/// WIRED `entropy_fill` → the host's CSPRNG ([`crate::proto::CodecHostServices`], the one the kernel
/// hands every codec it drives). Process-wide: `host` may be `HostCtx::NULL`. `Refused` for a NULL
/// `out` with a non-zero length or a CSPRNG that has nothing to give; `Fault` on a caught panic.
extern "C-unwind" fn entropy_fill(_host: HostCtx, out: *mut u8, out_len: usize) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() && out_len > 0 {
            return StatusClass::Refused;
        }
        if out_len == 0 {
            return StatusClass::Ok;
        }
        // SAFETY: a non-null `out` addresses `out_len` writable bytes for the call (the slot's
        // buffer discipline).
        let buf = unsafe { std::slice::from_raw_parts_mut(out, out_len) };
        if busbar_contract::codec::CodecHost::fill_entropy(&crate::proto::CodecHostServices, buf) {
            StatusClass::Ok
        } else {
            StatusClass::Refused
        }
    }))
    .unwrap_or(StatusClass::Fault)
}

/// WIRED `wall_clock` → the host's wall clock in whole Unix seconds (`store::now`, the one a codec
/// the kernel drives is handed). Process-wide: `host` may be `HostCtx::NULL`; `0` on a caught panic.
extern "C-unwind" fn wall_clock(_host: HostCtx) -> u64 {
    catch_unwind(|| {
        busbar_contract::codec::CodecHost::wall_clock_now(&crate::proto::CodecHostServices)
            .unwrap_or(0)
    })
    .unwrap_or(0)
}

/// WIRED `card_sign` → the REAL host-side card signer over `crate::governance` (see
/// [`crate::governance::GovState::card_sign`]): derive the deployment's domain-separated agent-card
/// subkey and sign the plane-framed signing input, writing the 64-byte Ed25519 signature into `out`
/// on the `Ok` path. The subkey secret is derived and used entirely host-side; only the signature
/// bytes cross back. `Refused` on a null in/out pointer or a deployment with no card-signing key;
/// `Fault` on any panic (`out` untouched).
#[cfg(feature = "card-signing")]
extern "C-unwind" fn card_sign(
    host: HostCtx,
    input_ptr: *const u8,
    input_len: usize,
    out: *mut u8,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let Some(state) = (unsafe { recover(host) }) else {
            return StatusClass::Refused;
        };
        if input_ptr.is_null() || out.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: `(input_ptr, input_len)` is a live borrowed range for the call (ABI discipline).
        let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len) };
        match state
            .app
            .governance
            .as_ref()
            .and_then(|g| g.card_sign(input))
        {
            Some(sig) => {
                // SAFETY: `out` is a caller-provided writable range of at least 64 bytes (ABI); `sig`
                // is a live 64-byte array. Written only on the Ok path (init-only-on-Ok).
                unsafe { std::ptr::copy_nonoverlapping(sig.as_ptr(), out, 64) };
                StatusClass::Ok
            }
            None => StatusClass::Refused, // no card-signing key → out-buffer left untouched.
        }
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// WIRED slots — real primitives, full boundary discipline.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// WIRED `clock_now` → `busbar_kernel::store::now_ms`, the host wall clock. The ABI contract is Unix
/// NANOSECONDS, so the host-side milliseconds clock is scaled up; sourcing it through
/// `busbar_kernel::store::now_ms` keeps the plane off any ambient clock (the whole point of the slot).
extern "C-unwind" fn clock_now(host: HostCtx) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the host passes a live `HostState` ptr for the dispatch duration (see `recover`).
        let Some(_state) = (unsafe { recover(host) }) else {
            return 0;
        };
        busbar_kernel::store::now_ms().saturating_mul(1_000_000)
    }))
    .unwrap_or(0) // fail-closed: a panicked clock reads 0, never a wild value.
}

/// WIRED `govern_admit` → the REAL admission over `crate::governance` (see [`super::govern::admit`]):
/// the budget gate the [`Facts`] POD encodes, then the `GovState::try_admit` limit engine. On `Admit`
/// the RAII [`AdmitGrant`](crate::governance::AdmitGrant) it yields is REGISTERED in the
/// [`DispatchScope`](super::DispatchScope) arena, so it is released on scope-drop no matter how the
/// dispatch future ends (the leak keystone). Fail-closed (`Deny`) on a null POD or any panic.
extern "C-unwind" fn govern_admit(host: HostCtx, facts: *const Facts) -> Decision {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let Some(state) = (unsafe { recover(host) }) else {
            return Decision::Deny;
        };
        if facts.is_null() {
            return Decision::Deny;
        }
        // SAFETY: a non-null `facts` is a live, initialized `Facts` for the call (ABI discipline).
        let f = unsafe { &*facts };
        super::govern::admit(state, f)
    }))
    .unwrap_or(Decision::Deny) // fail-closed: a panicked admit denies.
}

/// Copy up to `cap` of `bytes` into the caller's `buf` (tolerating a null/zero-cap slot), returning
/// the number of bytes written. The `egress_poll` variable-length copy: a caller sizes `buf` and
/// learns the written length from [`GovRefusal::reason_len`].
///
/// # Safety
/// `buf`, when non-null, is a writable range of at least `cap` bytes for the call.
unsafe fn write_reason(buf: *mut u8, cap: usize, bytes: &[u8]) -> usize {
    if buf.is_null() || cap == 0 {
        return 0;
    }
    let n = bytes.len().min(cap);
    // SAFETY: `bytes[..n]` is initialized and `buf[..n]` is a writable range (n ≤ cap, caller ABI).
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n) };
    n
}

/// Write the [`GovRefusal`] out-param (tolerating a null slot): the recovery floor + the rendered
/// reason length.
///
/// # Safety
/// `out`, when non-null, is a writable, aligned `MaybeUninit<GovRefusal>` for the call.
unsafe fn write_gov_refusal(
    out: *mut MaybeUninit<GovRefusal>,
    retry_after_secs: u64,
    reason_len: usize,
) {
    let refusal = GovRefusal {
        size: core::mem::size_of::<GovRefusal>() as u32,
        version: busbar_contract::abi::hot::POD_VERSION,
        _reserved: 0,
        retry_after_secs,
        reason_len,
    };
    // SAFETY: `out` is a writable, aligned MaybeUninit slot (or null, which `write_out` tolerates).
    unsafe { busbar_contract::abi::write_out(out, refusal) };
}

/// WIRED `govern_admit_reason` — [`govern_admit`] WITH REFUSAL FIDELITY. Identical admit behaviour
/// (the budget-POD gate, the real `try_admit` chain, the RAII grant registered in the dispatch arena),
/// the difference being that a BLOCKED limit RENDERS its reason into `reason_buf` (the exact
/// `format!("{blocked:?}")` bytes the mcp budget refusal surfaces today — the plane can no longer hold
/// `LimitBlocked`, so the host formats it) and records its length + recovery floor in [`GovRefusal`],
/// instead of discarding it. `out` is initialized up front (never left uninitialized): on an `Admit`
/// it holds `reason_len == 0`; on a `Deny` it holds the reason length; on a caught panic the eagerly
/// written zero. Fail-closed: a null POD or a caught panic denies.
extern "C-unwind" fn govern_admit_reason(
    host: HostCtx,
    facts: *const Facts,
    reason_buf: *mut u8,
    reason_cap: usize,
    out: *mut MaybeUninit<GovRefusal>,
) -> Decision {
    catch_unwind(AssertUnwindSafe(|| {
        // Initialize `out` up front so no path (admit, block, or a caught panic below) leaves it
        // uninitialized; a block overwrites it with the rendered reason length + recovery floor.
        // SAFETY: ABI out-param discipline (writable/aligned or null; see `write_gov_refusal`).
        unsafe { write_gov_refusal(out, 0, 0) };
        // SAFETY: recovery invariant (see `recover`).
        let Some(state) = (unsafe { recover(host) }) else {
            return Decision::Deny;
        };
        if facts.is_null() {
            return Decision::Deny;
        }
        // SAFETY: a non-null `facts` is a live, initialized `Facts` for the call (ABI discipline).
        let f = unsafe { &*facts };
        match super::govern::admit_reason(state, f) {
            Ok(()) => Decision::Admit,
            Err(blocked) => {
                // SAFETY: `reason_buf`/`reason_cap` are a writable range (or null) per the ABI.
                let written =
                    unsafe { write_reason(reason_buf, reason_cap, blocked.reason.as_bytes()) };
                // SAFETY: as above.
                unsafe { write_gov_refusal(out, blocked.retry_after_secs, written) };
                Decision::Deny
            }
        }
    }))
    .unwrap_or(Decision::Deny) // fail-closed: a panicked admit denies (out already zero).
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// WIRED capability slots — local host-side fns and forwarders into the capability modules. No
// `unimplemented!()` stub remains: the Phase-1 fan-out filled every slot.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// WIRED `meter_charge` → the REAL metering over `crate::governance` (see
/// [`super::govern::charge`]): accrue the usage's counts into the write-behind metering time-series.
/// Fail-closed (`Rejected`) on a null POD, an unnamed component, or any panic.
extern "C-unwind" fn meter_charge(host: HostCtx, usage: *const Usage) -> MeterOutcome {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let Some(state) = (unsafe { recover(host) }) else {
            return MeterOutcome::Rejected;
        };
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
// family fan-out); its vtable slots reference that module directly.
// journal_append / journal_read are WIRED in `super::journal` (the JOURNAL family, over the real
// `crate::audit` hash chain). The builder references them directly; no stub lives here.
// `nested_dispatch` / `workhandle_open` / `workhandle_resume` / `entitlement_check` / `gate_scan`
// are WIRED in `super::dispatch` (the DISPATCH family); their vtable slots reference that module.
