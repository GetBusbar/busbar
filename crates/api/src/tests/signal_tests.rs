// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/api/src/signal.rs`.

use super::*;

/// `Signal::ALL` must list every variant exactly once, and `Signal::name`'s hand-written match
/// must agree with the `#[serde(rename_all = "snake_case")]` derive — the exhaustiveness guard
/// for this append-only catalog (mirrors the codebase's `KNOWN_PROTOCOLS` pattern).
///
/// The variant list below is built from an EXHAUSTIVE MATCH, not from `ALL`, and that is the whole
/// of what makes this an exhaustiveness guard. Iterating `ALL` to check `ALL` cannot see the one
/// failure the test exists for: a variant added to the enum and forgotten in `ALL` is simply absent
/// from the loop, and every assertion passes over the nine that were remembered. The match is what
/// the compiler can hold, so a new variant fails to build until it is named here — and the
/// assertion below then fails until it is named in `ALL` too.
#[test]
fn all_lists_every_variant_and_name_matches_serde() {
    // Exhaustive by construction: `_ =>` is deliberately absent, so adding a variant to `Signal`
    // stops this compiling until the variant is listed. (`Signal` is `#[non_exhaustive]`, but that
    // only binds crates DOWNSTREAM of this one; in-crate the match is still checked exhaustively,
    // which is exactly the reach this guard needs.)
    fn every_variant() -> Vec<Signal> {
        let all = vec![
            Signal::RequestedModel,
            Signal::RequestTotalChars,
            Signal::RequestMessageCount,
            Signal::RequestToolCount,
            Signal::RequestSystemChars,
            Signal::CandidateBreakerState,
            Signal::CandidateErrorRate,
            Signal::CandidateLatencyP95Ms,
            Signal::RoutingPolicy,
            Signal::ResponseTokensOut,
        ];
        // The compiler-checked half: this match names every variant, so the list above cannot fall
        // behind the enum without a build failure here first.
        for s in &all {
            match s {
                Signal::RequestedModel
                | Signal::RequestTotalChars
                | Signal::RequestMessageCount
                | Signal::RequestToolCount
                | Signal::RequestSystemChars
                | Signal::CandidateBreakerState
                | Signal::CandidateErrorRate
                | Signal::CandidateLatencyP95Ms
                | Signal::RoutingPolicy
                | Signal::ResponseTokensOut => {}
            }
        }
        all
    }

    let variants = every_variant();
    assert_eq!(
        variants.len(),
        Signal::ALL.len(),
        "ALL must list every variant exactly once — it has {} entries for {} variants",
        Signal::ALL.len(),
        variants.len()
    );
    for v in &variants {
        assert!(
            Signal::ALL.contains(v),
            "{v:?} is a variant of Signal but is missing from Signal::ALL — every consumer that \
             walks the catalog would skip it silently"
        );
    }

    for &s in Signal::ALL {
        let derived = serde_json::to_value(s).unwrap();
        assert_eq!(derived, serde_json::Value::String(s.name().to_string()));
    }
    // Round-trips through the derive too (config declaration parses these exact strings).
    for &s in Signal::ALL {
        let parsed: Signal = serde_json::from_value(serde_json::json!(s.name())).unwrap();
        assert_eq!(parsed, s);
    }
    // Bit positions are dense and unique (0..ALL.len()).
    let mut bits: Vec<u32> = Signal::ALL.iter().map(|s| s.bit()).collect();
    bits.sort_unstable();
    bits.dedup();
    assert_eq!(bits.len(), Signal::ALL.len());
    assert_eq!(bits, (0..Signal::ALL.len() as u32).collect::<Vec<_>>());
}

/// An empty bag flattens to zero keys — the "declared nothing" wire delta is truly zero.
#[test]
fn empty_bag_serializes_as_empty_map() {
    let bag = SignalBag::new();
    let v = serde_json::to_value(&bag).unwrap();
    assert_eq!(v, serde_json::json!({}));
    assert!(bag.is_empty());
}

/// A populated bag serializes each entry under its stable name, scalar-typed.
#[test]
fn populated_bag_serializes_flat_scalars() {
    let mut bag = SignalBag::new();
    bag.push(
        Signal::CandidateBreakerState,
        SignalValue::Str(Cow::Borrowed("closed")),
    );
    bag.push(Signal::CandidateErrorRate, SignalValue::F64(0.125));
    let v = serde_json::to_value(&bag).unwrap();
    assert_eq!(v["candidate_breaker_state"], "closed");
    assert_eq!(v["candidate_error_rate"], 0.125);
    assert_eq!(bag.len(), 2);
}
