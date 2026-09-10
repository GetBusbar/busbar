// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Invariant test: ranking must be DETERMINISTIC under ties. When two or more candidates present
//! an identical primary ranking key to a native policy, the source (`crates/hooks-ranking/src/
//! lib.rs`, `rank_ascending_by` / `rank_descending_by`) breaks the tie by `idx` — the candidate's
//! stable slot in the input slice — via `.then(ia.cmp(ib))` in the sort comparator. That is a
//! total, deterministic secondary key: it is NOT influenced by `HashMap` iteration order, thread
//! scheduling, or any other nondeterministic source, because `Candidate` and the ranking function
//! operate over a plain `&[Candidate<'_>]` slice, never a hash-keyed collection.
//!
//! This test builds candidates that tie on every native's primary ranking signal (equal cost,
//! equal latency, equal concurrency headroom, equal rate headroom) and asserts:
//!   1. the output order matches the expected idx-ascending tiebreak rule, and
//!   2. the same input produces the SAME output order across many repeated calls (guards against
//!      any accidental reliance on iteration order that a single run would not reveal).
//!
//! This crate only exports `native_policy`, so exercising it via that public entry point is also
//! the most representative path: it is exactly what `resolve_policy` calls in production.

use busbar_api::{Candidate, RoutingContext, RoutingDecision, RoutingRequest};
use std::time::Duration;

fn cand_tied(idx: usize, rate: Option<f64>) -> Candidate<'static> {
    Candidate {
        idx,
        model: "m",
        provider: "p",
        weight: 1,
        context_max: None,
        tier: None,
        // Identical primary key for cheapest/fastest across every candidate.
        cost_per_mtok: Some(7.0),
        tags: &[],
        latency_ms: Some(50.0),
        // Identical primary key for least_busy across every candidate.
        available_concurrency: 4,
        budget_remaining: None,
        rate_headroom: rate,
        signals: Default::default(),
    }
}

fn req() -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 1,
        pool: "p",
        ingress_protocol: "anthropic",
        message_count: 1,
        has_tools: false,
        total_chars: 10,
        max_tokens: None,
        stream: false,
        argument: None,
        identity: None,
        signals: Default::default(),
    }
}

fn ctx() -> RoutingContext<'static> {
    RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    }
}

/// For every native ranking policy that ranks on a signal (cheapest, fastest, least_busy, usage),
/// a full tie on the primary key must resolve to idx-ascending order, identically on every call.
#[tokio::test]
async fn ranking_is_deterministic_under_full_ties_across_all_signal_natives() {
    // rate_headroom also tied (all Some(0.5)) so `usage` ties too, and stays tied (not Abstain,
    // since the signal is present on every candidate).
    let cands = [
        cand_tied(0, Some(0.5)),
        cand_tied(1, Some(0.5)),
        cand_tied(2, Some(0.5)),
        cand_tied(3, Some(0.5)),
    ];
    let expected = RoutingDecision::Prefer(vec![0, 1, 2, 3]);

    for name in ["cheapest", "fastest", "least_busy", "usage"] {
        let policy = busbar_hooks_ranking::native_policy(name)
            .unwrap_or_else(|| panic!("{name} must be a known native policy"));
        // Repeat many times: a comparator that ever leaked HashMap/iteration-order nondeterminism
        // would be expected to disagree with itself across some subset of these calls.
        for call in 0..50 {
            let decision = policy
                .decide(&req(), &cands, &ctx(), Duration::from_millis(10))
                .await
                .unwrap_or_else(|e| panic!("{name} call {call} returned Err: {e:?}"));
            assert_eq!(
                decision, expected,
                "{name} must break a full tie by ascending idx, deterministically (call {call})"
            );
        }
    }
}

/// A partial tie (some candidates share the primary key, one does not) still resolves the tied
/// subgroup by idx-ascending, with the untied member ranked by its own key as usual. This pins the
/// tiebreak rule precisely (idx, not e.g. insertion-reversed or hash-order) rather than merely
/// "some order that happens to be stable in one process".
#[tokio::test]
async fn partial_tie_group_is_ordered_by_idx_within_the_group() {
    let cands = [
        // idx 5 and idx 2 tie on cost (3.0); idx 9 is strictly cheaper.
        Candidate {
            idx: 5,
            cost_per_mtok: Some(3.0),
            ..cand_tied(5, None)
        },
        Candidate {
            idx: 9,
            cost_per_mtok: Some(1.0),
            ..cand_tied(9, None)
        },
        Candidate {
            idx: 2,
            cost_per_mtok: Some(3.0),
            ..cand_tied(2, None)
        },
    ];
    let policy = busbar_hooks_ranking::native_policy("cheapest").unwrap();
    let expected = RoutingDecision::Prefer(vec![9, 2, 5]); // cheapest first, then tie by idx asc
    for _ in 0..20 {
        let decision = policy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(decision, expected);
    }
}
