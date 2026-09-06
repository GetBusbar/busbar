// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in RANKING hooks — `cheapest` / `fastest` / `least_busy` / `usage`: busbar-native
//! routing policies, each a small sync sort over the live signals projected into `Candidate`.
//!
//! These are removable built-in order-hooks (the `hooks-ranking` engine feature): each implements
//! the `RoutingPolicy` contract (`busbar-api`) and ranks on a signal the hook wire already
//! projects, so an external hook could do the same. `weighted` is NOT here — it is the engine's
//! non-removable inline SWRR floor, never a plugin (the `weighted` NAME/entry lives alongside for
//! registry completeness, but the floor's zero-cost behavior is the engine's inline path). Each
//! native is the proof-of-completeness for its input signal: if a native can't be written, the
//! contract's in-data is incomplete.
//!
//! All natives are SYNC and never touch async or I/O; the async-trait wrapper is free for them. The
//! default `weighted` native exists only as the explicit `route: native, policy.name: weighted`
//! form — it returns `Abstain`, converging with the zero-cost default SWRR path.
//!
//! The native bodies + `native_policy` registry are live: `resolve_policy` looks a non-weighted name
//! up here at config load, and `forward::decide_policy_order` invokes the resolved policy per request.

use busbar_api::{
    Candidate, PolicyResult, RoutingContext, RoutingDecision, RoutingPolicy, RoutingRequest,
};
use std::time::Duration;

// ── Policy-name constants ─────────────────────────────────────────────────────────────────────────
// Single source of truth for the five native policy wire names. Referenced from:
//   • the `name()` impls below (what feeds `x-busbar-route-policy`),
//   • the `native_policy` registry match arms below,
//   • `config.rs` (deserialization / shorthand desugar),
//   • busbar's `hooks/mod.rs` (the zero-cost-path guard: the `native_policy` lookup that turns a
//     built-in name into one sync, non-failing link instead of a registry hop).
const POLICY_NAME_WEIGHTED: &str = "weighted";
const POLICY_NAME_CHEAPEST: &str = "cheapest";
const POLICY_NAME_FASTEST: &str = "fastest";
const POLICY_NAME_LEAST_BUSY: &str = "least_busy";
const POLICY_NAME_USAGE: &str = "usage";

/// `weighted` — the explicit form of the default. Always `Abstain`, so selection falls through to
/// the unchanged inline SWRR. Lets operators write `route: native, policy.name: weighted` and get
/// byte-identical behavior to the default, proving the seam without changing the hot path.
struct WeightedPolicy;

#[async_trait::async_trait]
impl RoutingPolicy for WeightedPolicy {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Ok(RoutingDecision::Abstain)
    }

    fn name(&self) -> &'static str {
        POLICY_NAME_WEIGHTED
    }
}

/// A ranking key that can be put in a TOTAL order. The float signals a routing policy ranks by
/// (`cost_per_mtok`, `latency_ms`, `rate_headroom`) arrive from operator config and from measured
/// telemetry, and a float has one value that is not orderable at all: `NaN` compares false against
/// everything, including itself. A comparator that reaches for `partial_cmp().unwrap_or(Equal)` on a
/// `NaN` is not merely arbitrary, it is NON-TRANSITIVE (`NaN == 1.0` and `NaN == 0.5` while
/// `1.0 < 0.5` is false), which is precisely the input `sort_by` is documented to be allowed to
/// panic on — a hard 500 on the routing path from one division-by-zero in a telemetry EWMA.
///
/// So a key is `usable` or it is not, and an unusable one is treated exactly like an ABSENT signal:
/// demoted to the end but still reachable, which is already what the ranking does for a member whose
/// signal has not arrived yet. "This number means nothing" and "there is no number" are the same
/// statement to a router.
trait RankKey: PartialOrd + Copy {
    fn usable(&self) -> bool;
}

impl RankKey for f64 {
    fn usable(&self) -> bool {
        self.is_finite()
    }
}

impl RankKey for usize {
    fn usable(&self) -> bool {
        true // an integer signal has no unorderable value
    }
}

/// Rank candidates by a total-order key, ascending (smallest key first). Candidates whose key is
/// `None` — or is present but not orderable, see [`RankKey`] — are demoted to the end (lowest
/// preference) but still ranked among themselves by `idx` for determinism; never dropped, so a
/// member with missing signal data is reachable, not stranded. Returns `Abstain` if EVERY candidate
/// lacks a usable signal (no opinion → default SWRR).
fn rank_ascending_by<K: RankKey>(
    candidates: &[Candidate<'_>],
    key: impl Fn(&Candidate<'_>) -> Option<K>,
) -> RoutingDecision {
    let mut keyed: Vec<(usize, Option<K>)> = candidates
        .iter()
        .map(|c| (c.idx, usable_key(&key, c)))
        .collect();
    if keyed.iter().all(|(_, k)| k.is_none()) {
        return RoutingDecision::Abstain;
    }
    // Sort: Some(k) before None; among Some, ascending by k; ties (and None/None) by idx for a
    // deterministic, stable order. Every surviving `Some` is orderable (the extractor dropped the
    // rest), so `partial_cmp` genuinely cannot yield None; the fallback stays as belt-and-braces.
    keyed.sort_by(|(ia, ka), (ib, kb)| match (ka, kb) {
        (Some(a), Some(b)) => a
            .partial_cmp(b)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(ia.cmp(ib)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => ia.cmp(ib),
    });
    RoutingDecision::Prefer(keyed.into_iter().map(|(idx, _)| idx).collect())
}

/// The key extractor made TOTAL: a signal that is present but not orderable is reported as absent,
/// so the comparator below only ever sees keys it can actually order. See [`RankKey`].
fn usable_key<K: RankKey>(
    key: &impl Fn(&Candidate<'_>) -> Option<K>,
    candidate: &Candidate<'_>,
) -> Option<K> {
    key(candidate).filter(|k| k.usable())
}

/// Rank descending (largest key first) — the same shape as `rank_ascending_by` but preferring the
/// LARGEST signal (e.g. most free concurrency, most budget remaining).
fn rank_descending_by<K: RankKey>(
    candidates: &[Candidate<'_>],
    key: impl Fn(&Candidate<'_>) -> Option<K>,
) -> RoutingDecision {
    let mut keyed: Vec<(usize, Option<K>)> = candidates
        .iter()
        .map(|c| (c.idx, usable_key(&key, c)))
        .collect();
    if keyed.iter().all(|(_, k)| k.is_none()) {
        return RoutingDecision::Abstain;
    }
    keyed.sort_by(|(ia, ka), (ib, kb)| match (ka, kb) {
        (Some(a), Some(b)) => b
            .partial_cmp(a)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(ia.cmp(ib)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => ia.cmp(ib),
    });
    RoutingDecision::Prefer(keyed.into_iter().map(|(idx, _)| idx).collect())
}

/// `cheapest` — prefer the lowest operator-declared `cost_per_mtok`. Members with no declared cost
/// are demoted (but reachable). Proof-of-completeness for the `cost` signal.
struct CheapestPolicy;

#[async_trait::async_trait]
impl RoutingPolicy for CheapestPolicy {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Ok(rank_ascending_by(candidates, |c| c.cost_per_mtok))
    }
    fn name(&self) -> &'static str {
        POLICY_NAME_CHEAPEST
    }
}

/// `fastest` — prefer the lowest measured rolling-EWMA latency. Members with no latency sample yet
/// are demoted (reachable). Proof-of-completeness for the `latency` signal.
struct FastestPolicy;

#[async_trait::async_trait]
impl RoutingPolicy for FastestPolicy {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Ok(rank_ascending_by(candidates, |c| c.latency_ms))
    }
    fn name(&self) -> &'static str {
        POLICY_NAME_FASTEST
    }
}

/// `least_busy` — prefer the lane with the most available concurrency permits (the most headroom).
/// Always has data (available_concurrency is always known), so never Abstains. Proof-of-completeness
/// for the `concurrency` signal.
struct LeastBusyPolicy;

#[async_trait::async_trait]
impl RoutingPolicy for LeastBusyPolicy {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Ok(rank_descending_by(candidates, |c| {
            Some(c.available_concurrency)
        }))
    }
    fn name(&self) -> &'static str {
        POLICY_NAME_LEAST_BUSY
    }
}

/// `usage` — prefer the candidate with the most rate-limit HEADROOM: the largest fraction of the
/// request's governance rate budget (the tighter of the caller key's RPM / TPM limit) still available
/// this window, so traffic steers away from a candidate about to hit a provider 429. Ranks DESCENDING
/// by `Candidate.rate_headroom` (most headroom first); candidates with no headroom signal (`None`) are
/// demoted to last but stay reachable. Abstains when EVERY candidate lacks the signal (no rate limit
/// in play → fall through to the default SWRR). Proof-of-completeness for the `rate_headroom` signal.
struct UsagePolicy;

#[async_trait::async_trait]
impl RoutingPolicy for UsagePolicy {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Ok(rank_descending_by(candidates, |c| c.rate_headroom))
    }
    fn name(&self) -> &'static str {
        POLICY_NAME_USAGE
    }
}

/// Resolve a native policy name to a boxed policy. `None` for an unknown name (rejected at startup
/// validation). `weighted` returns the Abstaining default native.
pub fn native_policy(name: &str) -> Option<std::sync::Arc<dyn RoutingPolicy>> {
    use std::sync::Arc;
    match name {
        POLICY_NAME_WEIGHTED => Some(Arc::new(WeightedPolicy)),
        POLICY_NAME_CHEAPEST => Some(Arc::new(CheapestPolicy)),
        POLICY_NAME_FASTEST => Some(Arc::new(FastestPolicy)),
        POLICY_NAME_LEAST_BUSY => Some(Arc::new(LeastBusyPolicy)),
        POLICY_NAME_USAGE => Some(Arc::new(UsagePolicy)),
        _ => None,
    }
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
