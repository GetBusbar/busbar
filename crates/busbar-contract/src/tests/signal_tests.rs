// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract/src/signal.rs`.

use super::*;
use crate::json::JsonContainerTrait as _;

/// Signal names accepted by configuration agree with their serialized spelling.
#[test]
fn signal_names_match_serde() {
    for &s in Signal::ALL {
        let derived = crate::json::to_value(&s).unwrap();
        assert_eq!(derived, crate::json::Value::from(s.name()));
    }

    for &s in Signal::ALL {
        let parsed: Signal = crate::json::from_value(&crate::json::json!(s.name())).unwrap();
        assert_eq!(parsed, s);
    }

    let mut bits: Vec<u32> = Signal::ALL.iter().map(|s| s.bit()).collect();
    bits.sort();
    bits.dedup();
    assert_eq!(bits.len(), Signal::ALL.len());
    assert_eq!(bits, (0..Signal::ALL.len() as u32).collect::<Vec<_>>());
}

/// An empty bag flattens to zero keys — the "declared nothing" wire delta is truly zero.
#[test]
fn empty_bag_serializes_as_empty_map() {
    let bag = SignalBag::new();
    let v = crate::json::to_value(&bag).unwrap();
    assert_eq!(v, crate::json::json!({}));
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
    let v = crate::json::to_value(&bag).unwrap();
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

/// A signal pushed more than once serializes as one key holding all its values in push order.
#[test]
fn a_repeated_signal_serializes_as_one_array_in_push_order() {
    let mut bag = SignalBag::new();
    bag.push(Signal::RequestedModel, SignalValue::Bool(true));
    super::route_cost::append(
        &mut bag,
        [
            super::route_cost::Term {
                class: "a",
                price_per_unit: Some(1.0),
                expected_units: 2.0,
            },
            super::route_cost::Term {
                class: "b",
                price_per_unit: None,
                expected_units: 3.0,
            },
        ],
    );
    let v = crate::json::to_value(&bag).unwrap();
    let arr = v["candidate_route_cost"].as_array().expect("array");
    assert_eq!(arr.len(), 7, "{v}");
    assert_eq!(arr[0], crate::json::json!(true));
    assert_eq!(arr[1], crate::json::json!("a"));
    assert_eq!(arr[4], crate::json::json!("b"));
    assert_eq!(v["requested_model"], crate::json::json!(true));
}

/// A hook's `signals:` as a config document states it, read the way config load reads it.
#[derive(Debug, Deserialize)]
struct Stated {
    #[serde(default, deserialize_with = "configured")]
    signals: Vec<Signal>,
}

/// RED before the two retired signals were dropped at load: `candidate_error_rate` and
/// `response_tokens_out` were accepted in a hook's `signals:` and did nothing (hook 3.0 sends
/// neither to any hook).
///
/// An old config that still names them loads: each is dropped, a warning names the setting
/// and the signal, and the signals that still mean something are kept in their order.
#[test]
fn the_two_retired_signals_load_with_a_warning_and_are_gone() {
    let mut warned = Vec::new();
    let kept = keep_live(
        vec![
            Signal::CandidateBreakerState,
            Signal::CandidateErrorRate,
            Signal::ResponseTokensOut,
            Signal::CandidateLatencyP95Ms,
        ],
        |signal| warned.push(signal),
    );
    assert_eq!(
        kept,
        [Signal::CandidateBreakerState, Signal::CandidateLatencyP95Ms]
    );
    assert_eq!(
        warned,
        [Signal::CandidateErrorRate, Signal::ResponseTokensOut],
        "one warning for each retired signal that was stated"
    );
    for signal in warned {
        let line = retired_warning(signal);
        assert!(line.contains("signals"), "it names the setting: {line}");
        assert!(line.contains(signal.name()), "and the signal: {line}");
        assert!(line.contains("dropped"), "and says what was done: {line}");
    }

    // The same through a config document: it loads, and the two are not in what was loaded.
    let stated: Stated = serde_json::from_str(
        r#"{"signals": ["candidate_error_rate", "candidate_breaker_state", "response_tokens_out"]}"#,
    )
    .expect("an old config that names a retired signal still loads");
    assert_eq!(stated.signals, [Signal::CandidateBreakerState]);
    let only_retired: Stated =
        serde_json::from_str(r#"{"signals": ["response_tokens_out"]}"#).unwrap();
    assert!(only_retired.signals.is_empty());
}

/// The two are the only retired entries, and retiring one moves no other signal's bit: the
/// catalog stays append-only.
#[test]
fn only_the_two_signals_hook_3_0_stopped_sending_are_retired() {
    let retired: Vec<Signal> = Signal::ALL
        .iter()
        .copied()
        .filter(|signal| signal.retired())
        .collect();
    assert_eq!(
        retired,
        [Signal::CandidateErrorRate, Signal::ResponseTokensOut]
    );
    assert_eq!(Signal::CandidateErrorRate.bit(), 6);
    assert_eq!(Signal::ResponseTokensOut.bit(), 9);
}

/// A name that is no signal at all is still refused at load: dropping the retired two does not
/// make `signals:` accept a misspelling.
#[test]
fn a_signal_that_never_existed_is_still_refused_at_load() {
    assert!(serde_json::from_str::<Stated>(r#"{"signals": ["candidate_eror_rate"]}"#).is_err());
    let none: Stated = serde_json::from_str("{}").unwrap();
    assert!(none.signals.is_empty());
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
