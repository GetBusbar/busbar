// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The BREAKER family of the plane host — [`admit`] and the settle a leg folds through
//! [`BreakerHost::breaker_settle`](super::BreakerHost::breaker_settle) — over busbar's REAL
//! single-flight breaker (`store::planes`, the planes' handle on the one cell store).
//!
//! ## Why this pair is the leak-safety-critical one
//!
//! The real breaker admits a dispatch by winning the cell's single-flight half-open probe and hands
//! back a [`store::planes::Admission`](crate::store::PlaneAdmission) — an RAII token whose `Drop`
//! releases that probe. If a plane held that bare token and its dispatch future were then dropped
//! (disconnect / cancel / panic / parked-at-await), nothing would run the release and the cell would
//! wedge in `HalfOpen` FOREVER — every caller of that target fast-failing with no recovery. So
//! [`admit`] never returns the bare token: it REGISTERS the RAII `Admission` in the per-dispatch
//! [`DispatchScope`](super::DispatchScope) arena and returns the arena's opaque [`AdmissionId`].
//! However the dispatch ends, the arena's `Drop` runs the real `Admission::drop` and the probe is
//! released — no wedge. (Proven in this module's tests.)
//!
//! A settle looks the admission up in that arena, records the reported [`Settle`] against the
//! breaker (the real [`CanonicalSignal`](crate::breaker::CanonicalSignal) disposition pipeline), and
//! releases the guard.
//!
//! ## Key → (pool, lane)
//!
//! The breaker cell is `(pool, lane)`-keyed (`store::planes` module header): the plane-qualified pool
//! string (e.g. `"tool:fs"` / `"agent:planner"`, already qualified by the caller) and the member LANE.
//! A lane past the fixed [`MAX_POOL_MEMBERS`] table, an empty pool, or non-UTF-8 pool bytes all fail
//! closed to a refusal rather than risk indexing the lane table.

use super::scope::{AdmissionId, Settle, SettleAdmission};
use crate::breaker::CanonicalSignal;
use crate::store::{PlaneAdmission, PlaneBreakers, MAX_POOL_MEMBERS};
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
    fn settle(&mut self, signal: &Settle) {
        match signal {
            Settle::Success => self.breakers.record_success(&self.key, self.lane),
            Settle::Failure(sig) => {
                self.breakers.record_signal(&self.key, self.lane, sig);
            }
            // A refusal is not an upstream health signal — record nothing (the ADR-0002
            // `ClientFault` "relay verbatim, penalize nothing" disposition).
            Settle::RecordNothing => {}
        }
    }
}

/// Why a probe was not won: the store's [`Unavailable`](busbar_kernel::store::Unavailable) refusal
/// taxonomy folded to its kind, so [`admit`] hands back a refusal of the store's own shape with the
/// recovery floor rounded to seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unavailability {
    /// No specific reason (a bad key, a caught panic, an arena that handed back no id).
    Unspecified,
    /// The cell's breaker is open.
    Open,
    /// Another caller holds the half-open probe.
    ProbeInFlight,
    /// The member is administratively down.
    Dead,
    /// The member's budget is spent.
    Budget,
    /// The member is at its concurrency cap.
    AtCapacity,
    /// The member is shedding load.
    Shedding,
}

/// WIN ONE `(pool, lane)` PROBE ON THE KERNEL'S BREAKER — the function a plane's failover sync sites
/// call per candidate. The breaker is a core capability every plane gets: the plane hands over the host
/// it holds and the kernel reaches the shared cell store through it
/// ([`BreakerHost::breaker_store`](super::BreakerHost::breaker_store)); the plane calls no per-plane
/// host method. On a win the settle-capable [`BreakerAdmission`] is REGISTERED in `scope`'s arena (the
/// leak-safety keystone: a dropped dispatch releases the probe) and the plane holds only the returned
/// [`AdmissionId`]; it NEVER holds a [`PlaneAdmission`].
///
/// The key validation (an empty or non-UTF-8 pool, or a lane past the fixed [`MAX_POOL_MEMBERS`]
/// table, refuses), the win-and-register, and a refusal handed back as the store's own
/// [`Unavailable`](busbar_kernel::store::Unavailable)
/// folded to its `Unavailability` kind + a second-rounded recovery floor ([`classify_unavailable`])
/// and rebuilt from them ([`reconstruct_unavailable`]), so `failover::walk_with`'s `admit`
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
/// from its [`Unavailability`] kind + the second-rounded recovery floor an [`admit`] refusal
/// was folded to. Coarse by construction — the fold keeps no exact internal epoch, so
/// the `BreakerOpen`/`AtCapacity` payloads are reconstituted from the floor. This feeds
/// `failover::walk_with`'s `passed_over` reasons (an operator-facing LOG on the sync sites),
/// never a caller-facing `Retry-After` (that is the store's own `retry_after_secs`).
fn reconstruct_unavailable(
    reason: Unavailability,
    retry_after_secs: u64,
) -> busbar_kernel::store::Unavailable {
    use busbar_kernel::store::Unavailable;
    match reason {
        Unavailability::Dead => Unavailable::Dead,
        Unavailability::Budget => Unavailable::BudgetExhausted,
        Unavailability::Open => Unavailable::BreakerOpen {
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

/// The `(pool, lane)` cell a pool's bytes and a lane name: `None` (→ refuse) on empty or non-UTF-8 pool
/// bytes, or a lane past the fixed [`MAX_POOL_MEMBERS`] table.
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

/// Map the store's [`Unavailable`](busbar_kernel::store::Unavailable) refusal taxonomy onto its
/// [`Unavailability`] kind + a recovery-floor in whole seconds — so a refused admit keeps its
/// SPECIFIC meaning (Open vs probe-lost vs dead vs budget vs capacity) rather than collapsing to a
/// bare [`AdmissionId::NONE`]. The floor is the store's own single definition of
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

#[cfg(test)]
#[path = "tests/breaker_tests.rs"]
mod tests;

/// The [`Settle`] a leg reports for a FAILURE, carrying the plane's own [`CanonicalSignal`] — so a
/// settle folded through the host scope records the EXACT disposition the plane's own
/// `record_signal` would (the RateLimit cooldown floor, the transient/hard-down reason code).
#[must_use]
pub fn failure_signal(cs: &CanonicalSignal) -> Settle {
    Settle::Failure(cs.clone())
}

/// The [`Settle`] a leg reports for a SUCCESS: `record_success`, closing the half-open probe exactly
/// as the plane's own success record does.
#[must_use]
pub fn success_signal() -> Settle {
    Settle::Success
}

/// The [`Settle`] a leg reports for an outcome that is NOT an upstream health signal: settling it
/// RELEASES the half-open probe without recording, exactly as dropping the raw `PlaneAdmission` did
/// (the "record nothing" disposition: a busbar-side refusal / a not-transmitted leg).
#[must_use]
pub fn refused_signal() -> Settle {
    Settle::RecordNothing
}
