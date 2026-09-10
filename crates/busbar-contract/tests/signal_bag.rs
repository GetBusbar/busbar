// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/api/src/signal.rs`.

use busbar_contract::{Signal, SignalBag, SignalValue};
use std::borrow::Cow;

/// `Signal::ALL` must list every variant exactly once, and `Signal::name`'s hand-written match
/// must agree with the `#[serde(rename_all = "snake_case")]` derive — the exhaustiveness guard
/// for this append-only catalog (mirrors the codebase's `KNOWN_PROTOCOLS` pattern).
#[test]
fn all_lists_every_variant_and_name_matches_serde() {
    // THE EXHAUSTIVENESS HALF, and it has to be a `match` rather than a walk of `ALL`. Every other
    // assertion in this test is driven BY `Signal::ALL`, so all of them are self-referential: add a
    // variant plus its `Signal::name` arm (both compiler-forced) and forget `Signal::ALL` (a
    // hand-maintained slice the compiler does NOT check) and the whole test passed -- while
    // `Signal::bit` panics on "Signal::ALL must list every variant" the first time anyone declares
    // that signal, on the live decide/tap path. Degenerately, an EMPTY `ALL` passed everything
    // below too (`0 == 0`, `vec![] == (0..0)`). This match is non-exhaustive the moment a variant
    // is added, so the omission becomes a compile error in the same change that introduces it.
    for &s in Signal::ALL {
        let listed = match s {
            Signal::RequestedModel
            | Signal::RequestTotalChars
            | Signal::RequestMessageCount
            | Signal::RequestToolCount
            | Signal::RequestSystemChars
            | Signal::CandidateBreakerState
            | Signal::CandidateErrorRate
            | Signal::CandidateLatencyP95Ms
            | Signal::RoutingPolicy
            | Signal::ResponseTokensOut => true,
            // `Signal` is `#[non_exhaustive]`, so from outside the crate the match needs this arm;
            // the `ALL.len()` pin directly below is what catches an added variant now.
            #[allow(unreachable_patterns)]
            _ => false,
        };
        assert!(listed);
    }
    assert_eq!(
        Signal::ALL.len(),
        10,
        "the catalog is append-only: a variant was added or removed without updating this pin, \
         and every ALL-driven assertion below cannot see it"
    );

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

/// A populated bag is NOT empty — the other half of `is_empty`'s contract (only the empty case was
/// pinned above).
#[test]
fn populated_bag_is_not_empty() {
    let mut bag = SignalBag::new();
    assert!(bag.is_empty());
    bag.push(Signal::RequestedModel, SignalValue::Bool(true));
    assert!(!bag.is_empty());
}

/// `SignalBag::get` finds a previously-pushed value BY KEY (not by position, not the first/last
/// entry unconditionally) and returns `None` for a signal never pushed.
#[test]
fn get_finds_by_signal_key_and_none_when_absent() {
    let mut bag = SignalBag::new();
    bag.push(
        Signal::RequestedModel,
        SignalValue::Str(Cow::Borrowed("gpt")),
    );
    bag.push(Signal::RequestTotalChars, SignalValue::U64(42));

    assert_eq!(
        bag.get(Signal::RequestTotalChars),
        Some(&SignalValue::U64(42))
    );
    assert_eq!(
        bag.get(Signal::RequestedModel),
        Some(&SignalValue::Str(Cow::Borrowed("gpt")))
    );
    assert_eq!(bag.get(Signal::CandidateErrorRate), None);
}

/// `iter` yields every pushed `(Signal, SignalValue)` pair, in push order.
#[test]
fn iter_yields_every_pushed_entry_in_order() {
    let mut bag = SignalBag::new();
    bag.push(Signal::RequestedModel, SignalValue::I64(1));
    bag.push(Signal::RequestTotalChars, SignalValue::I64(2));
    bag.push(Signal::RequestMessageCount, SignalValue::I64(3));
    let collected: Vec<_> = bag.iter().map(|(s, v)| (*s, v.clone())).collect();
    assert_eq!(
        collected,
        vec![
            (Signal::RequestedModel, SignalValue::I64(1)),
            (Signal::RequestTotalChars, SignalValue::I64(2)),
            (Signal::RequestMessageCount, SignalValue::I64(3)),
        ]
    );
}

/// `spilled` is `false` for the empty bag and for a bag within the inline `SmallVec` capacity (4);
/// pushing past that capacity spills to the heap and `spilled` must flip to `true`. Pins BOTH
/// values so a mutant that hardcodes either constant is caught.
#[test]
fn spilled_reflects_heap_overflow_of_the_inline_capacity() {
    let mut bag = SignalBag::new();
    assert!(!bag.spilled(), "empty bag must not report spilled");
    for _ in 0..4 {
        bag.push(Signal::RequestedModel, SignalValue::Bool(true));
    }
    assert!(!bag.spilled(), "within inline capacity (4) must not spill");
    bag.push(Signal::RequestedModel, SignalValue::Bool(true));
    assert!(
        bag.spilled(),
        "past inline capacity (4) must spill to the heap"
    );
}
