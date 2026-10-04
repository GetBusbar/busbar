// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The RANKING hook: `cheapest` / `fastest` / `least_busy` / `usage`, each a small sync sort over
//! the live signals a `decide` view already carries (`Decoded::candidates`). A hook plugin on the
//! hook kind's memory ABI ([`door`]); the four strategy words are the hook words its Statement
//! claims. `weighted` is NOT a word of this plugin: it is the engine's non-removable inline SWRR
//! floor (the name stays in [`rank`] as the explicit Abstaining form).
//!
//! All rankings are SYNC and never touch async or I/O. A key that is absent, or present but not
//! orderable (`NaN`, infinite), ranks as an absent signal: demoted to the end, still reachable;
//! when EVERY candidate lacks a usable key the answer is `Abstain` (no opinion, default SWRR).
//! Ties break by `idx`, so an order is the same on every call.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod door;

use busbar_contract::abi::sdk::hook::{DecodedCandidate, Verdict};

// ── Policy-name constants ─────────────────────────────────────────────────────────────────────────
// Single source of truth for the strategy names: the `rank` match arms and [`WORDS`] (the hook
// words the Statement claims) both read them.
const POLICY_NAME_WEIGHTED: &str = "weighted";
const POLICY_NAME_CHEAPEST: &str = "cheapest";
const POLICY_NAME_FASTEST: &str = "fastest";
const POLICY_NAME_LEAST_BUSY: &str = "least_busy";
const POLICY_NAME_USAGE: &str = "usage";

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
    candidates: &[DecodedCandidate<'_>],
    key: impl Fn(&DecodedCandidate<'_>) -> Option<K>,
) -> Verdict {
    let mut keyed: Vec<(usize, Option<K>)> = candidates
        .iter()
        .map(|c| (c.idx, usable_key(&key, c)))
        .collect();
    if keyed.iter().all(|(_, k)| k.is_none()) {
        return Verdict::Abstain;
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
    Verdict::Prefer(keyed.into_iter().map(|(idx, _)| idx).collect())
}

/// The key extractor made TOTAL: a signal that is present but not orderable is reported as absent,
/// so the comparator below only ever sees keys it can actually order. See [`RankKey`].
fn usable_key<K: RankKey>(
    key: &impl Fn(&DecodedCandidate<'_>) -> Option<K>,
    candidate: &DecodedCandidate<'_>,
) -> Option<K> {
    key(candidate).filter(|k| k.usable())
}

/// Rank descending (largest key first) — the same shape as `rank_ascending_by` but preferring the
/// LARGEST signal (e.g. most free concurrency, most budget remaining).
fn rank_descending_by<K: RankKey>(
    candidates: &[DecodedCandidate<'_>],
    key: impl Fn(&DecodedCandidate<'_>) -> Option<K>,
) -> Verdict {
    let mut keyed: Vec<(usize, Option<K>)> = candidates
        .iter()
        .map(|c| (c.idx, usable_key(&key, c)))
        .collect();
    if keyed.iter().all(|(_, k)| k.is_none()) {
        return Verdict::Abstain;
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
    Verdict::Prefer(keyed.into_iter().map(|(idx, _)| idx).collect())
}

/// Rank `candidates` by the strategy `name` (`weighted` is the explicit Abstaining form). `None`
/// for a word this plugin does not claim.
///
/// * `cheapest`: lowest operator-declared `cost_per_mtok`; a member with no cost is demoted.
/// * `fastest`: lowest measured rolling-EWMA `latency_ms`; a member with no sample is demoted.
/// * `least_busy`: most `available_concurrency`; the signal is always present, so never Abstains.
/// * `usage`: most `rate_headroom` (the largest fraction of the governance rate budget still
///   available this window); a member with no headroom signal is demoted, and every member lacking
///   it Abstains (no rate limit in play).
#[must_use]
pub fn rank(name: &str, candidates: &[DecodedCandidate<'_>]) -> Option<Verdict> {
    Some(match name {
        POLICY_NAME_WEIGHTED => Verdict::Abstain,
        POLICY_NAME_CHEAPEST => rank_ascending_by(candidates, |c| c.cost_per_mtok),
        POLICY_NAME_FASTEST => rank_ascending_by(candidates, |c| c.latency_ms),
        POLICY_NAME_LEAST_BUSY => rank_descending_by(candidates, |c| Some(c.available_concurrency)),
        POLICY_NAME_USAGE => rank_descending_by(candidates, |c| c.rate_headroom),
        _ => return None,
    })
}

/// The strategy words this plugin claims (its Statement's hook words).
pub const WORDS: [&str; 4] = [
    POLICY_NAME_CHEAPEST,
    POLICY_NAME_FASTEST,
    POLICY_NAME_LEAST_BUSY,
    POLICY_NAME_USAGE,
];

/// The plugin's name: its Statement's, and the linked row's.
pub const NAME: &str = "hooks-ranking";

/// THE LINKED ENTRY: what a build that links the ranking hook registers on the hook axis — its
/// door, the same door a dropped-in build of it exports. Its hook words are [`WORDS`].
pub mod linked {
    pub use crate::door::door;
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
