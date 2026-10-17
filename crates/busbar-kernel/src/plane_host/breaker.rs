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

use super::recover;
use super::scope::SettleAdmission;
use crate::breaker::{CanonicalSignal, StatusClass as BreakerClass};
use crate::store::{PlaneAdmission, PlaneBreakers, MAX_POOL_MEMBERS};
use busbar_contract::abi::hot::host::HostCtx;
use busbar_contract::abi::hot::{
    AdmissionId, AdmitRefusal, FaultClass, Key, Signal, StatusClass, Unavailability,
};
use busbar_contract::abi::read_sized_field;
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

/// WIN ONE `(pool, lane)` PROBE ON THE KERNEL'S BREAKER — the function a plane's failover sync sites
/// call per candidate. The breaker is a core capability every plane gets: the plane hands over the host
/// it holds and the kernel reaches the shared cell store through it
/// ([`BreakerHost::breaker_store`](super::BreakerHost::breaker_store)); the plane calls no per-plane
/// host method. On a win the settle-capable [`BreakerAdmission`] is REGISTERED in `scope`'s arena (the
/// leak-safety keystone: a dropped dispatch releases the probe) and the plane holds only the returned
/// POD [`AdmissionId`]; it NEVER holds a [`PlaneAdmission`].
///
/// The same admit the wired [`breaker_admit_reason`] slot runs, without the hop through the kernel's
/// own vtable: the same key validation (a null/empty or non-UTF-8 pool, or a lane past the fixed
/// [`MAX_POOL_MEMBERS`] table, refuses), the same win-and-register, and a refusal handed back in the
/// SAME shape that hop produced — the store's own [`Unavailable`](busbar_kernel::store::Unavailable)
/// folded to the fine [`Unavailability`] + a second-rounded recovery floor ([`classify_unavailable`])
/// and rebuilt from them ([`reconstruct_unavailable`]), so [`crate::failover::walk_with`]'s `admit`
/// closure sees exactly the refusal it saw before. A bad key, a caught panic or an arena that hands
/// back no id refuse as the unspecified reason did (a `ProbeInFlight`). The sync sites render
/// `Retry-After` from [`retry_after_secs`], never from this reconstructed value.
pub fn admit<H: super::BreakerHost + ?Sized>(
    host: &H,
    scope: &super::DispatchScope,
    pool: &[u8],
    lane: u32,
) -> Result<AdmissionId, busbar_kernel::store::Unavailable> {
    let won = catch_unwind(AssertUnwindSafe(|| {
        let Some((pool, lane)) = pool_lane(pool, lane) else {
            return Err((Unavailability::Unspecified, 0)); // a bad key is not an availability fact.
        };
        let breakers = host.breaker_store();
        match breakers.admit(&pool, lane) {
            Ok(admission) => Ok(
                scope.register_settling_admission(Box::new(BreakerAdmission {
                    breakers: Arc::clone(breakers),
                    key: pool,
                    lane,
                    _admission: admission,
                })),
            ),
            Err(unavailable) => Err(classify_unavailable(
                &unavailable,
                busbar_kernel::store::now(),
            )),
        }
    }));
    match won {
        Ok(Ok(id)) if !id.is_none() => Ok(id),
        Ok(Err((reason, retry))) => Err(reconstruct_unavailable(reason, retry)),
        // An arena that handed back no id, or a caught panic: the unspecified refusal.
        Ok(Ok(_)) | Err(_) => Err(reconstruct_unavailable(Unavailability::Unspecified, 0)),
    }
}

/// Record a SUCCESS against the `(pool, lane)` cell in place — the fallback a settle leg takes when no
/// arena owns the probe (or a multi-round leg whose probe was already settled). The kernel breaker's
/// own [`PlaneBreakers::record_success`], reached through the host the plane holds.
pub fn record_success<H: super::BreakerHost + ?Sized>(host: &H, pool: &str, lane: usize) {
    host.breaker_store().record_success(pool, lane);
}

/// Record a canonical failure signal against the `(pool, lane)` cell in place — the fallback twin of
/// [`record_success`]. The kernel breaker's own [`PlaneBreakers::record_signal`].
pub fn record_signal<H: super::BreakerHost + ?Sized>(
    host: &H,
    pool: &str,
    lane: usize,
    sig: &CanonicalSignal,
) {
    host.breaker_store().record_signal(pool, lane, sig);
}

/// The seconds until the `(pool, lane)` cell's cooldown expires — the honest `Retry-After` for a
/// refused dispatch, read PER MEMBER so a pool whose members trip independently answers with the
/// soonest. The kernel breaker's own [`PlaneBreakers::retry_after_secs`]; a pure read.
pub fn retry_after_secs<H: super::BreakerHost + ?Sized>(host: &H, pool: &str, lane: usize) -> u64 {
    host.breaker_store().retry_after_secs(pool, lane)
}

/// The inverse of [`classify_unavailable`]: rebuild the store's own [`Unavailable`](busbar_kernel::store::Unavailable)
/// from the fine [`Unavailability`] reason + the second-rounded recovery floor an [`admit`] refusal
/// was folded to. Coarse by construction — the ABI does not carry the exact internal epoch, so
/// the `BreakerOpen`/`AtCapacity` payloads are reconstituted from the floor. This feeds
/// [`crate::failover::walk_with`]'s `passed_over` reasons (an operator-facing LOG on the sync sites),
/// never a caller-facing `Retry-After` (that is the store's own `retry_after_secs`).
fn reconstruct_unavailable(
    reason: Unavailability,
    retry_after_secs: u64,
) -> busbar_kernel::store::Unavailable {
    use busbar_kernel::store::Unavailable;
    match reason {
        Unavailability::Dead => Unavailable::Dead,
        Unavailability::Budget => Unavailable::BudgetExhausted,
        Unavailability::Open | Unavailability::NoneAdmissible => Unavailable::BreakerOpen {
            until: busbar_kernel::store::now().saturating_add(retry_after_secs),
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
// `refused_signal`) are pure `#[repr(C)]` PODs naming only `busbar_contract::abi::hot` + the neutral
// `CanonicalSignal`, so they now live in `busbar_kernel::plane_host::breaker`; core re-exports
// them so every in-core caller (the a2a relay/route settle legs) is unchanged. `fault_of` moved with
// them (it was their only reader); this module keeps the INVERSE `classify` the host slot drives.

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
    // The plugin WROTE this byte, so decode it through the checked carrier: an unnamed class settles
    // as `Fault` (a failure to fold) rather than materializing an invalid discriminant.
    let coarse = signal.class.class();
    match coarse {
        StatusClass::Ok => return Outcome::Success,
        // A policy refusal is not an upstream health signal — record nothing (ADR-0002).
        StatusClass::Refused => return Outcome::RecordNothing,
        // A failure to fold — fall through to the fine/coarse classification below.
        StatusClass::Gone | StatusClass::Unsupported | StatusClass::Fault => {}
    }

    // Prefer the FINE breaker class when the sender wrote it (append-only sized read); an older
    // sender, a truncated tail, or an explicit `Unspecified` all fall back to the coarse map.
    let fine = read_sized_field!(signal, signal.size, Signal, fault_class)
        .map_or(FaultClass::Unspecified, |raw| raw.class());
    let class = match fine {
        FaultClass::Unspecified => return Outcome::Failure(coarse_signal(coarse)),
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
    let retry_after = match read_sized_field!(signal, signal.size, Signal, fault_flags) {
        Some(flags) if flags & 0x01 != 0 => {
            read_sized_field!(signal, signal.size, Signal, retry_after_secs)
        }
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
    let ptr = read_sized_field!(signal, signal.size, Signal, provider_signal_ptr)?;
    let len = read_sized_field!(signal, signal.size, Signal, provider_signal_len)?;
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
    if k.key_ptr.is_null() || k.key_len == 0 {
        return None;
    }
    // SAFETY: `(key_ptr, key_len)` is a live borrowed range for the call (ABI discipline).
    let bytes = unsafe { std::slice::from_raw_parts(k.key_ptr, k.key_len) };
    pool_lane(bytes, k.scope)
}

/// The `(pool, lane)` cell a pool's bytes and a lane name: `None` (→ refuse) on empty or non-UTF-8 pool
/// bytes, or a lane past the fixed [`MAX_POOL_MEMBERS`] table. The one validation [`admit`] and the
/// wired slots share.
fn pool_lane(pool: &[u8], lane: u32) -> Option<(String, usize)> {
    let lane = lane as usize;
    if lane >= MAX_POOL_MEMBERS {
        return None;
    }
    match std::str::from_utf8(pool) {
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
    // The same admit with no refusal slot: `write_refusal` tolerates a null `out`.
    breaker_admit_reason(host, key, core::ptr::null_mut())
}

/// Map the store's [`Unavailable`](busbar_kernel::store::Unavailable) refusal taxonomy onto the neutral ABI
/// [`Unavailability`] reason + a recovery-floor in whole seconds — so a refused admit keeps its
/// SPECIFIC meaning (Open vs probe-lost vs dead vs budget vs capacity) across the host boundary rather
/// than collapsing to a bare [`AdmissionId::NONE`]. The floor is the store's own single definition of
/// "when could this be usable again" (`recovery_hint_ms`), rounded up to seconds; `0` for a refusal
/// that does not self-recover (administratively down / budget spent).
fn classify_unavailable(u: &busbar_kernel::store::Unavailable, now: u64) -> (Unavailability, u64) {
    let retry = u
        .recovery_hint_ms(now)
        .map(|ms| ms.div_ceil(1_000))
        .unwrap_or(0);
    let reason = match u {
        busbar_kernel::store::Unavailable::Dead => Unavailability::Dead,
        busbar_kernel::store::Unavailable::BudgetExhausted => Unavailability::Budget,
        busbar_kernel::store::Unavailable::BreakerOpen { .. } => Unavailability::Open,
        busbar_kernel::store::Unavailable::ProbeInFlight => Unavailability::ProbeInFlight,
        busbar_kernel::store::Unavailable::AtCapacity { .. } => Unavailability::AtCapacity,
        busbar_kernel::store::Unavailable::Shedding => Unavailability::Shedding,
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
        version: busbar_contract::abi::hot::POD_VERSION,
        reason,
        _reserved: 0,
        retry_after_secs,
    };
    // SAFETY: `out` is a writable, aligned MaybeUninit slot (or null, which `write_out` tolerates).
    unsafe { busbar_contract::abi::write_out(out, refusal) };
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
        let Some(state) = (unsafe { recover(host) }) else {
            // A stale handle is not an availability fact either → Unspecified, same as a bad key.
            return AdmissionId::NONE;
        };
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
                let (reason, retry) =
                    classify_unavailable(&unavailable, busbar_kernel::store::now());
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
        let Some(state) = (unsafe { recover(host) }) else {
            return StatusClass::Refused;
        };
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

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
use busbar_contract::abi::hot::{RawFault, RawStatus};

/// The inverse of the host `classify`'s fine [`FaultClass`] → [`BreakerClass`] table: the plane's own
/// canonical class back to the ABI fine class the settle carries. Total — every [`BreakerClass`] maps
/// to exactly one [`FaultClass`], so a settle built here round-trips through the host `classify`.
// Built only by the plane settle paths behind the `dispatch`/`relay` features (via `failure_signal`),
// so it reads dead when both are compiled out; live with either on.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
fn fault_of(class: BreakerClass) -> FaultClass {
    match class {
        BreakerClass::RateLimit => FaultClass::RateLimit,
        BreakerClass::Overloaded => FaultClass::Overloaded,
        BreakerClass::ServerError => FaultClass::UpstreamError,
        BreakerClass::Timeout => FaultClass::Timeout,
        BreakerClass::Network => FaultClass::Network,
        BreakerClass::Auth => FaultClass::Auth,
        BreakerClass::Billing => FaultClass::Billing,
        BreakerClass::ClientError => FaultClass::ClientError,
        BreakerClass::ContextLength => FaultClass::ContextLength,
    }
}

/// Build the ABI [`Signal`] a host settle carries FROM the plane's own [`CanonicalSignal`] — the
/// INVERSE of the host `classify`, so a settle folded through the host scope reproduces the EXACT
/// disposition the plane's own `record_signal` would. A failure rides its fine [`FaultClass`], the
/// `Retry-After` floor (flagged in `fault_flags` bit 0 so a `0`-second header is distinct from "no
/// header"), and the borrowed provider error-code — the exact three inputs the host `classify` reads
/// back. The coarse `class` is the neutral failure carrier [`StatusClass::Fault`]; the FINE
/// `fault_class` is what the host reads.
///
/// The returned `Signal` BORROWS `cs.provider_signal`; it MUST NOT outlive `cs`.
// Built only by the plane settle paths behind the `dispatch`/`relay` features, so it reads dead when
// both are compiled out; live with either on.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
#[must_use]
pub fn failure_signal(cs: &CanonicalSignal) -> Signal {
    let (flags, secs) = match cs.retry_after {
        Some(s) => (0x01u8, s),
        None => (0, 0),
    };
    let (ptr, len) = match cs.provider_signal.as_deref() {
        Some(code) => (code.as_ptr(), code.len()),
        None => (core::ptr::null(), 0),
    };
    Signal {
        fault_class: RawFault::of(fault_of(cs.class)),
        fault_flags: flags,
        retry_after_secs: secs,
        provider_signal_ptr: ptr,
        provider_signal_len: len,
        ..bare_signal(StatusClass::Fault)
    }
}

/// A settle [`Signal`] of coarse `class` carrying nothing else: no fine fault, no `Retry-After`
/// floor, no provider error-code. The one place the POD header and the zeroed fields are written.
fn bare_signal(class: StatusClass) -> Signal {
    Signal {
        size: core::mem::size_of::<Signal>() as u32,
        version: busbar_contract::abi::hot::POD_VERSION,
        class: RawStatus::of(class),
        _reserved: 0,
        latency_nanos: 0,
        bytes: 0,
        fault_class: RawFault::of(FaultClass::Unspecified),
        fault_flags: 0,
        _reserved2: 0,
        _reserved3: 0,
        retry_after_secs: 0,
        provider_signal_ptr: core::ptr::null(),
        provider_signal_len: 0,
    }
}

/// The ABI [`Signal`] a host settle carries for a SUCCESS — the host `classify` maps `Ok` straight to
/// `record_success`, closing the half-open probe exactly as the plane's own success record does.
// Built only by the plane settle paths behind the `dispatch`/`relay` features, so it reads dead when
// both are compiled out; live with either on.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
#[must_use]
pub fn success_signal() -> Signal {
    bare_signal(StatusClass::Ok)
}

/// The ABI [`Signal`] a host settle carries for an outcome that is NOT an upstream health signal —
/// the host `classify` maps `Refused` to `RecordNothing`, so settling this RELEASES the half-open probe
/// without recording, exactly as dropping the raw `PlaneAdmission` did (the "record nothing"
/// disposition: a busbar-side refusal / a not-transmitted leg).
// Built only by the settle leg behind the `dispatch` feature — the `relay` settle path never carries
// the "record nothing" outcome — so it reads dead whenever `dispatch` is compiled out.
#[cfg_attr(not(feature = "dispatch"), allow(dead_code))]
#[must_use]
pub fn refused_signal() -> Signal {
    bare_signal(StatusClass::Refused)
}
