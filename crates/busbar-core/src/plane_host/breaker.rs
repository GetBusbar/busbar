// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The BREAKER family of the plane host-vtable — `breaker_admit` + `breaker_settle` — wired over
//! busbar-core's REAL single-flight breaker (`store::planes`, the non-LLM planes' handle on the one
//! cell store).
//!
//! ## Why this pair is the leak-safety-critical one
//!
//! The real breaker admits a dispatch by winning the cell's single-flight half-open probe and hands
//! back a [`store::planes::Admission`](crate::store::PlaneAdmission) — an RAII token whose `Drop`
//! releases that probe. If a plane took a BARE probe handle across the FFI seam and its dispatch
//! future were then dropped (disconnect / cancel / panic / parked-at-await), nothing would run the
//! release and the cell would wedge in `HalfOpen` FOREVER — every caller of that target fast-failing
//! with no recovery. So [`breaker_admit`] never returns the bare token: it REGISTERS the RAII
//! `Admission` in the per-dispatch [`DispatchScope`](super::DispatchScope) arena and returns the
//! arena's opaque [`AdmissionId`]. However the dispatch ends, the arena's `Drop` runs the real
//! `Admission::drop` and the probe is released — no wedge. (Proven in this module's tests.)
//!
//! [`breaker_settle`] looks the admission up in that arena, records the reported [`Signal`] against
//! the breaker (mapped to the real [`CanonicalSignal`](crate::breaker::CanonicalSignal) /
//! [`StatusClass`](crate::breaker::StatusClass) disposition pipeline), and releases the guard.
//!
//! Both fns follow the boundary discipline of the wired slots (`vtable.rs`): recover the
//! [`HostState`] FIRST, run the body inside a MANDATORY `catch_unwind`, and FAIL CLOSED on any error
//! (a refused admit is [`AdmissionId::NONE`]; a faulted settle is the distinct fault class).
//!
//! ## Key → (pool, lane)
//!
//! The breaker cell is `(pool, lane)`-keyed (`store::planes` module header). This slot reads the
//! plane-qualified pool string from the [`Key`]'s borrowed `key_ptr`/`key_len` bytes (e.g.
//! `"tool:fs"` / `"agent:planner"`, already qualified by the caller) and the member LANE from the
//! `Key.scope` field. A lane past the fixed [`MAX_POOL_MEMBERS`] table, a null/empty key, or
//! non-UTF-8 key bytes all fail closed to a refusal rather than risk indexing the lane table.

use super::scope::SettleAdmission;
use super::{recover, HostState};
use crate::breaker::{CanonicalSignal, StatusClass as BreakerClass};
use crate::store::{PlaneAdmission, PlaneBreakers, MAX_POOL_MEMBERS};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::{
    AdmissionId, AdmitRefusal, FaultClass, Key, Signal, StatusClass, Unavailability,
};
use busbar_plugin::read_sized_field;
use core::mem::MaybeUninit;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

/// The arena-held, settle-capable breaker admission. It OWNS the real single-flight probe token
/// (`_admission`), whose `Drop` releases the probe when the [`DispatchScope`](super::DispatchScope)
/// reclaims this guard — the leak-safety guarantee. [`SettleAdmission::settle`] records the reported
/// outcome against the same `(key, lane)` cell before that release, making the release a no-op.
struct BreakerAdmission {
    breakers: Arc<PlaneBreakers>,
    key: String,
    lane: usize,
    /// The RAII probe hold. Read only through its `Drop` (probe release); the leading underscore
    /// keeps it a held-for-drop field without tripping the never-read lint.
    _admission: PlaneAdmission,
}

impl SettleAdmission for BreakerAdmission {
    fn settle(&mut self, signal: &Signal) -> StatusClass {
        // SAFETY: `signal` is a live, initialized `Signal` for this call (settle's ABI discipline);
        // its `provider_signal` borrowed range, when present, is valid for the duration of the call.
        match unsafe { classify(signal) } {
            Outcome::Success => self.breakers.record_success(&self.key, self.lane),
            Outcome::Failure(sig) => {
                self.breakers.record_signal(&self.key, self.lane, &sig);
            }
            // A refusal is not an upstream health signal — record nothing (the ADR-0002
            // `ClientFault` "relay verbatim, penalize nothing" disposition).
            Outcome::RecordNothing => {}
        }
        // The host-call succeeded: the outcome is recorded and the probe consumed. The distinct
        // `Gone`/`Fault`/`Refused` classes are decided by the vtable wrapper, not here.
        StatusClass::Ok
    }
}

/// WIN ONE `(pool, lane)` PROBE THROUGH THE HOST SEAM — the SAFE wrapper the failover sync sites drive
/// per candidate, so the plane never touches the `#[repr(C)]` [`AdmitRefusal`] out-param read or the
/// raw vtable pointer (busbar-core denies `unsafe` outside this audited module; precedent:
/// [`govern_admit_reason_over`](super::govern_admit_reason_over)). Materializes a host over `(app,
/// scope)`, calls the wired [`breaker_admit_reason`] slot for the `(pool, lane)` cell, and — on a live
/// id — leaves the settle-capable [`BreakerAdmission`] REGISTERED in `scope`'s arena (the leak-safety
/// keystone: a dropped dispatch releases the probe). The plane holds only the returned POD
/// [`AdmissionId`]; it NEVER holds a [`PlaneAdmission`].
///
/// On a refusal the returned [`AdmissionId`] is [`NONE`](AdmissionId::NONE), reconstructed into the
/// store's own [`Unavailable`](crate::store::Unavailable) taxonomy so [`crate::failover::walk_with`]'s
/// `admit` closure gets the SAME refusal shape `try_admit_breaker` handed it — the reconstruction is
/// the inverse of [`classify_unavailable`] (coarse: the ABI carries a fine [`Unavailability`] + a
/// second-rounded recovery floor, not the exact internal epoch; the sync sites render `Retry-After`
/// from the store's own `retry_after_secs`, never from this reconstructed value).
// Driven by BOTH the MCP failover sync site (`mcp::reroute`) and the A2A failover sync sites
// (`a2a::route::select_member`'s pooled walk and `a2a::relay::prepare`'s un-pooled admit), so it
// reads dead only when BOTH planes are compiled out.
#[allow(dead_code)]
pub fn breaker_admit_over(
    app: &crate::state::App,
    scope: &super::DispatchScope,
    pool: &[u8],
    lane: u32,
) -> Result<AdmissionId, crate::store::Unavailable> {
    let key = Key {
        size: core::mem::size_of::<Key>() as u32,
        version: busbar_plugin::hot::POD_VERSION,
        _reserved: 0,
        scope: lane,
        _reserved2: 0,
        key_ptr: pool.as_ptr(),
        key_len: pool.len(),
        drift_state: 0,
    };
    let mut out = MaybeUninit::<AdmitRefusal>::uninit();
    let id = super::with_borrowed_host(app, scope, |host, vt| {
        (vt.breaker_admit_reason
            .expect("breaker_admit_reason is a wired slot"))(
            host,
            &key as *const Key,
            std::ptr::from_mut(&mut out),
        )
    });
    if !id.is_none() {
        return Ok(id);
    }
    // SAFETY: the host ALWAYS initializes `out` up front (see `breaker_admit_reason`), so it is a live
    // `AdmitRefusal` on every non-live-id return.
    let refusal = unsafe { out.assume_init() };
    Err(reconstruct_unavailable(
        refusal.reason,
        refusal.retry_after_secs,
    ))
}

/// The inverse of [`classify_unavailable`]: rebuild the store's own [`Unavailable`](crate::store::Unavailable)
/// from the ABI [`Unavailability`] reason + the second-rounded recovery floor a [`breaker_admit_over`]
/// refusal carried back. Coarse by construction — the ABI does not carry the exact internal epoch, so
/// the `BreakerOpen`/`AtCapacity` payloads are reconstituted from the floor. This feeds
/// [`crate::failover::walk_with`]'s `passed_over` reasons (an operator-facing LOG on the sync sites),
/// never a caller-facing `Retry-After` (that is the store's own `retry_after_secs`).
// Reached only through [`breaker_admit_over`], so it shares that fn's dual-plane liveness: dead only
// when BOTH planes are compiled out.
#[allow(dead_code)]
fn reconstruct_unavailable(
    reason: Unavailability,
    retry_after_secs: u64,
) -> crate::store::Unavailable {
    use crate::store::Unavailable;
    match reason {
        Unavailability::Dead => Unavailable::Dead,
        Unavailability::Budget => Unavailable::BudgetExhausted,
        Unavailability::Open | Unavailability::NoneAdmissible => Unavailable::BreakerOpen {
            until: crate::store::now().saturating_add(retry_after_secs),
        },
        Unavailability::AtCapacity => Unavailable::AtCapacity {
            drain_hint_ms: Some(retry_after_secs.saturating_mul(1_000)),
        },
        Unavailability::Shedding => Unavailable::Shedding,
        // A "next-tick" transient covers both an explicit probe-loss and a bare unspecified refusal:
        // neither is a sticky administrative fact, and the sync sites read only the store's own
        // `retry_after_secs` for the caller's wait.
        Unavailability::ProbeInFlight | Unavailability::Unspecified => Unavailable::ProbeInFlight,
    }
}

// The plane-side `Signal` constructors a settle leg builds (`success_signal`/`failure_signal`/
// `refused_signal`) are pure `#[repr(C)]` PODs naming only `busbar_plugin::hot` + the neutral
// `CanonicalSignal`, so they now live in `busbar_substrate::plane_host::breaker`; core re-exports
// them so every in-core caller (the a2a relay/route settle legs) is unchanged. `fault_of` moved with
// them (it was their only reader); this module keeps the INVERSE `classify` the host slot drives.
pub use busbar_substrate::plane_host::breaker::{failure_signal, refused_signal, success_signal};

/// What a reported ABI [`StatusClass`] means to the breaker's disposition pipeline.
enum Outcome {
    /// The guarded operation succeeded — close the half-open probe, dilute the error window.
    Success,
    /// A failure to fold, carried as the breaker's own canonical signal.
    Failure(CanonicalSignal),
    /// Not an upstream health signal (a policy refusal) — record nothing.
    RecordNothing,
}

/// Reproduce the plane's `normalize_raw_error` disposition from a reported [`Signal`], building the
/// FULL [`CanonicalSignal`] the store's `record_signal` folds — so routing a settle through the host
/// is byte-for-byte the same disposition as the plane recording directly.
///
/// The coarse ABI [`StatusClass`] decides the top-level shape: `Ok` is a success, `Refused` records
/// nothing (a policy refusal is not an upstream health signal), and `Gone`/`Unsupported`/`Fault` are
/// failures to fold. On a failure, the FINE breaker class rides in the append-only [`Signal`] tail:
/// when the sender wrote a real [`FaultClass`] (its `size` proves the field and it is not
/// [`FaultClass::Unspecified`]), it maps 1:1 to the breaker's own [`StatusClass`](BreakerClass) and
/// carries the upstream `Retry-After` floor and the borrowed provider error-code — the exact three
/// inputs `record_signal` reads (the RateLimit cooldown floor, the transient/hard-down reason code).
/// A sender that predates the tail (or leaves `Unspecified`) falls back to the coarse mapping the
/// pre-enrichment host used: `Gone → Network`, `Unsupported → ClientError`, `Fault → ServerError`.
///
/// # Safety
/// `signal.provider_signal_ptr`/`provider_signal_len`, when the tail is present and non-null/non-zero,
/// MUST describe a live, initialized byte range for the duration of the call (settle's ABI discipline).
unsafe fn classify(signal: &Signal) -> Outcome {
    match signal.class {
        StatusClass::Ok => return Outcome::Success,
        // A policy refusal is not an upstream health signal — record nothing (ADR-0002).
        StatusClass::Refused => return Outcome::RecordNothing,
        // A failure to fold — fall through to the fine/coarse classification below.
        StatusClass::Gone | StatusClass::Unsupported | StatusClass::Fault => {}
    }

    // Prefer the FINE breaker class when the sender wrote it (append-only sized read); an older
    // sender, a truncated tail, or an explicit `Unspecified` all fall back to the coarse map.
    let fine = read_sized_field!(signal, Signal, fault_class).unwrap_or(FaultClass::Unspecified);
    let class = match fine {
        FaultClass::Unspecified => return Outcome::Failure(coarse_signal(signal.class)),
        FaultClass::RateLimit => BreakerClass::RateLimit,
        FaultClass::Overloaded => BreakerClass::Overloaded,
        FaultClass::UpstreamError => BreakerClass::ServerError,
        FaultClass::Timeout => BreakerClass::Timeout,
        FaultClass::Network => BreakerClass::Network,
        FaultClass::Auth => BreakerClass::Auth,
        FaultClass::Billing => BreakerClass::Billing,
        FaultClass::ClientError => BreakerClass::ClientError,
        FaultClass::ContextLength => BreakerClass::ContextLength,
    };

    // The `Retry-After` floor: present only when the tail was written AND bit 0 of `fault_flags` is
    // set (so a header value of `0` is distinct from "no header").
    let retry_after = match read_sized_field!(signal, Signal, fault_flags) {
        Some(flags) if flags & 0x01 != 0 => read_sized_field!(signal, Signal, retry_after_secs),
        _ => None,
    };

    // The borrowed provider error-code (into the transient/hard-down reason), when present & UTF-8.
    let provider_signal = provider_code(signal);

    Outcome::Failure(CanonicalSignal {
        class,
        provider_signal,
        retry_after,
    })
}

/// The pre-enrichment coarse mapping, used as the forward-compat fallback for a sender that did not
/// write the fine [`FaultClass`] tail. Preserves the exact legacy disposition (no `provider_signal`,
/// no `retry_after`).
fn coarse_signal(class: StatusClass) -> CanonicalSignal {
    let class = match class {
        StatusClass::Gone => BreakerClass::Network,
        StatusClass::Unsupported => BreakerClass::ClientError,
        // `Ok`/`Refused` never reach here (handled before the fallback); `Fault` is the only other.
        StatusClass::Fault | StatusClass::Ok | StatusClass::Refused => BreakerClass::ServerError,
    };
    CanonicalSignal {
        class,
        provider_signal: None,
        retry_after: None,
    }
}

/// The borrowed provider error-CODE from a [`Signal`] tail, as an owned `String` for the canonical
/// signal's reason field. `None` when the tail is absent, the range is null/empty, or non-UTF-8.
///
/// # Safety
/// See [`classify`]: the borrowed range, when present, must be live for the call.
unsafe fn provider_code(signal: &Signal) -> Option<String> {
    let ptr = read_sized_field!(signal, Signal, provider_signal_ptr)?;
    let len = read_sized_field!(signal, Signal, provider_signal_len)?;
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: the caller guarantees `(ptr, len)` is a live, initialized range for the call.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes).ok().map(str::to_string)
}

/// Resolve the `(pool, lane)` cell key from a borrowed [`Key`] POD. `None` (→ refuse) on a null/empty
/// key, non-UTF-8 key bytes, or a lane past the fixed [`MAX_POOL_MEMBERS`] table.
///
/// # Safety
/// `key` must be a live, initialized `Key` for the call (ABI discipline).
unsafe fn resolve_key(key: *const Key) -> Option<(String, usize)> {
    if key.is_null() {
        return None;
    }
    // SAFETY: a non-null `key` is a live, initialized `Key` for the call (ABI discipline).
    let k = unsafe { &*key };
    let lane = k.scope as usize;
    if lane >= MAX_POOL_MEMBERS {
        return None;
    }
    if k.key_ptr.is_null() || k.key_len == 0 {
        return None;
    }
    // SAFETY: `(key_ptr, key_len)` is a live borrowed range for the call (ABI discipline).
    let bytes = unsafe { std::slice::from_raw_parts(k.key_ptr, k.key_len) };
    match std::str::from_utf8(bytes) {
        Ok(pool) if !pool.is_empty() => Some((pool.to_string(), lane)),
        _ => None,
    }
}

/// WIRED `breaker_admit` → [`PlaneBreakers::admit`]. Admits one dispatch against the `(pool, lane)`
/// cell the [`Key`] names; on success REGISTERS the resulting RAII `Admission` in the dispatch arena
/// and returns the arena's [`AdmissionId`], so a dropped dispatch future releases the probe rather
/// than wedging the cell. Fail-closed: a refusal, a bad key, or a caught panic all return
/// [`AdmissionId::NONE`].
pub(super) extern "C-unwind" fn breaker_admit(host: HostCtx, key: *const Key) -> AdmissionId {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let state: &HostState = unsafe { recover(host) };
        // SAFETY: ABI key discipline (see `resolve_key`).
        let Some((pool, lane)) = (unsafe { resolve_key(key) }) else {
            return AdmissionId::NONE;
        };
        let breakers = Arc::clone(&state.app.plane_breakers);
        match breakers.admit(&pool, lane) {
            Ok(admission) => state
                .scope
                .register_settling_admission(Box::new(BreakerAdmission {
                    breakers: Arc::clone(&breakers),
                    key: pool,
                    lane,
                    _admission: admission,
                })),
            // Unavailable (Open / probe-in-flight / dead / budget) → refuse with the NONE sentinel.
            Err(_unavailable) => AdmissionId::NONE,
        }
    }))
    .unwrap_or(AdmissionId::NONE) // fail-closed: a panicked admit refuses.
}

/// Map the store's [`Unavailable`](crate::store::Unavailable) refusal taxonomy onto the neutral ABI
/// [`Unavailability`] reason + a recovery-floor in whole seconds — so a refused admit keeps its
/// SPECIFIC meaning (Open vs probe-lost vs dead vs budget vs capacity) across the host boundary rather
/// than collapsing to a bare [`AdmissionId::NONE`]. The floor is the store's own single definition of
/// "when could this be usable again" (`recovery_hint_ms`), rounded up to seconds; `0` for a refusal
/// that does not self-recover (administratively down / budget spent).
fn classify_unavailable(u: &crate::store::Unavailable, now: u64) -> (Unavailability, u64) {
    let retry = u
        .recovery_hint_ms(now)
        .map(|ms| ms.div_ceil(1_000))
        .unwrap_or(0);
    let reason = match u {
        crate::store::Unavailable::Dead => Unavailability::Dead,
        crate::store::Unavailable::BudgetExhausted => Unavailability::Budget,
        crate::store::Unavailable::BreakerOpen { .. } => Unavailability::Open,
        crate::store::Unavailable::ProbeInFlight => Unavailability::ProbeInFlight,
        crate::store::Unavailable::AtCapacity { .. } => Unavailability::AtCapacity,
        crate::store::Unavailable::Shedding => Unavailability::Shedding,
    };
    (reason, retry)
}

/// Write the fine refusal `reason` + recovery floor into the `out` param (tolerating a null slot).
///
/// # Safety
/// `out`, when non-null, is a writable, aligned `MaybeUninit<AdmitRefusal>` for the call.
unsafe fn write_refusal(
    out: *mut MaybeUninit<AdmitRefusal>,
    reason: Unavailability,
    retry_after_secs: u64,
) {
    let refusal = AdmitRefusal {
        size: core::mem::size_of::<AdmitRefusal>() as u32,
        version: busbar_plugin::hot::POD_VERSION,
        reason,
        _reserved: 0,
        retry_after_secs,
    };
    // SAFETY: `out` is a writable, aligned MaybeUninit slot (or null, which `write_out` tolerates).
    unsafe { busbar_plugin::write_out(out, refusal) };
}

/// WIRED `breaker_admit_reason` — [`breaker_admit`] WITH REFUSAL FIDELITY. Identical admit behaviour
/// (win the `(pool, lane)` probe, register the settle-capable `Admission` in the dispatch arena, return
/// its [`AdmissionId`]); the difference is that a REFUSAL writes the fine [`AdmitRefusal`] reason into
/// `out` (the specific [`Unavailability`] the store yielded, plus its recovery floor) instead of
/// discarding it. `out` is initialized to [`Unavailability::Unspecified`] at the top so it is NEVER
/// left uninitialized — on a live id it holds `Unspecified` (the caller reads it only when the id is
/// [`NONE`](AdmissionId::NONE)); on a refusal it holds the real reason; on a caught panic it holds the
/// eagerly-written `Unspecified`. Fail-closed: a bad key or a caught panic refuses.
pub(super) extern "C-unwind" fn breaker_admit_reason(
    host: HostCtx,
    key: *const Key,
    out: *mut MaybeUninit<AdmitRefusal>,
) -> AdmissionId {
    catch_unwind(AssertUnwindSafe(|| {
        // Initialize `out` up front so no path (admit, refuse, or a caught panic below) leaves it
        // uninitialized; a refusal overwrites it with the specific reason.
        // SAFETY: ABI out-param discipline (writable/aligned or null; see `write_refusal`).
        unsafe { write_refusal(out, Unavailability::Unspecified, 0) };
        // SAFETY: recovery invariant (see `super::recover`).
        let state: &HostState = unsafe { recover(host) };
        // SAFETY: ABI key discipline (see `resolve_key`).
        let Some((pool, lane)) = (unsafe { resolve_key(key) }) else {
            return AdmissionId::NONE; // a bad key is not an availability fact → Unspecified.
        };
        let breakers = Arc::clone(&state.app.plane_breakers);
        match breakers.admit(&pool, lane) {
            Ok(admission) => state
                .scope
                .register_settling_admission(Box::new(BreakerAdmission {
                    breakers: Arc::clone(&breakers),
                    key: pool,
                    lane,
                    _admission: admission,
                })),
            Err(unavailable) => {
                let (reason, retry) = classify_unavailable(&unavailable, crate::store::now());
                // SAFETY: as above.
                unsafe { write_refusal(out, reason, retry) };
                AdmissionId::NONE
            }
        }
    }))
    .unwrap_or(AdmissionId::NONE) // fail-closed: a panicked admit refuses (out already Unspecified).
}

/// WIRED `breaker_settle`. Looks the admission up in the dispatch arena, records the reported
/// [`Signal`] against the breaker (mapped to the canonical disposition), and releases the guard.
/// Returns [`StatusClass::Ok`] when the admission was found and settled, [`StatusClass::Gone`] when
/// `admission` names no live grant (stale / already settled), [`StatusClass::Refused`] on a null
/// signal, and [`StatusClass::Fault`] on a caught panic.
pub(super) extern "C-unwind" fn breaker_settle(
    host: HostCtx,
    admission: AdmissionId,
    signal: *const Signal,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let state: &HostState = unsafe { recover(host) };
        if signal.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `signal` is a live, initialized `Signal` for the call (ABI discipline).
        let sig = unsafe { &*signal };
        state
            .scope
            .settle_admission(admission, sig)
            .unwrap_or(StatusClass::Gone) // no live admission with this id → stale handle.
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}

#[cfg(test)]
#[path = "tests/breaker_tests.rs"]
mod tests;
