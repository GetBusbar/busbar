// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract/src/signal.rs`.

use super::*;

/// Signal names accepted by configuration agree with their serialized spelling.
#[test]
fn signal_names_match_serde() {
    for &s in Signal::ALL {
        let derived = serde_json::to_value(s).unwrap();
        assert_eq!(derived, serde_json::Value::String(s.name().to_string()));
    }

    for &s in Signal::ALL {
        let parsed: Signal = serde_json::from_value(serde_json::json!(s.name())).unwrap();
        assert_eq!(parsed, s);
    }

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
#[test]
fn populated_bag_is_not_empty() {
    let mut bag = SignalBag::new();
    assert!(bag.is_empty());
    bag.push(Signal::RequestedModel, SignalValue::Bool(true));
    assert!(!bag.is_empty());
}

/// `SignalBag::get` finds a previously-pushed value BY KEY (not by position, not the first/last
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

/// LEGACY the retired engine crate's `src/engine/tests/signal_catalog_tests.rs::default_path_allocates_no_signals_container`.
#[test]
fn a_bag_of_up_to_four_signals_never_spills_onto_the_heap() {
    let mut bag = SignalBag::new();
    assert!(bag.is_empty() && !bag.spilled(), "the default path's bag");
    for (signal, value) in [
        (
            Signal::CandidateBreakerState,
            SignalValue::Str(Cow::Borrowed("closed")),
        ),
        (Signal::CandidateErrorRate, SignalValue::F64(0.0)),
        (Signal::CandidateLatencyP95Ms, SignalValue::U64(1)),
        (Signal::RequestedModel, SignalValue::Bool(true)),
    ] {
        bag.push(signal, value);
        assert!(!bag.spilled(), "{} entries stay inline", bag.len());
    }
    assert_eq!(bag.len(), 4);
}
