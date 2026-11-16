// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::card::CardFields;
use busbar_kernel_ledger::cost::{ClassPrice, LaneClass, RateCard};

fn cards(text: &str) -> PluginRateCards {
    busbar_contract::yaml::from_str(text).unwrap()
}

#[test]
fn exact_common_rates_reject_floats_and_preserve_zero() {
    let rates = cards("hook: { gate: { calls: '0.125', bytes: 0 } }");
    assert_eq!(rates["hook"]["gate"]["calls"].nanos_per_unit(), 125);
    assert_eq!(rates["hook"]["gate"]["bytes"].nanos_per_unit(), 0);
    for bad in ["0.125", "'-1'", "'0.0001'", "18446744073709551615"] {
        assert!(busbar_contract::yaml::from_str::<PluginRateCards>(&format!(
            "hook: {{ gate: {{ calls: {bad} }} }}"
        ))
        .is_err());
    }
}

#[test]
fn stored_common_rates_refuse_an_unknown_kind_or_a_bad_name() {
    assert!(validate(&cards("hook: { gate: { calls: 0 } }")).is_ok());
    assert!(validate(&cards("imaginary: {gate: {calls: 1}}")).is_err());
    assert!(validate(&cards("hook: {'': {calls: 1}}")).is_err());
    assert!(validate(&cards("hook: {\"bad\\u001fname\": {calls: 1}}")).is_err());
}

#[test]
fn common_rates_roundtrip_in_stored_cards_without_changing_legacy_bytes() {
    let old = br#"{"rate_card":null,"per_request_fee":0,"planes":{}}"#;
    assert_eq!(CardFields::from_bytes(old).unwrap().to_bytes(), old);
    let rates = cards("hook: { gate: { input: '0.125', calls: 0 } }");
    let fields = CardFields {
        plugin_rate_cards: rates.clone(),
        ..CardFields::default()
    };
    assert_eq!(CardFields::from_bytes(&fields.to_bytes()).unwrap(), fields);
    assert_eq!(
        CardFields::from_composed(fields.composed().as_ref(), 0, Default::default()),
        fields
    );
    let raw = fields.rates();
    assert!(!raw.present);
    assert!(raw.lanes.is_empty());
    let priced = RateCard::absent(0).with_unit_rates(
        raw.units
            .iter()
            .map(|(lane, class, nanos)| (LaneClass::new(lane, class), *nanos)),
    );
    let lane = measurement_lane("hook", "gate");
    assert_eq!(
        priced.lane_pricing(&lane).class_price("input"),
        ClassPrice::Nanos(125)
    );
    assert_eq!(
        priced.lane_pricing(&lane).class_price("output"),
        ClassPrice::Unpriced
    );
    assert_eq!(
        CardFields::default().differing_fields(&fields),
        ["plugin_rate_cards"]
    );
}

#[test]
fn common_composition_preserves_an_explicit_empty_legacy_card() {
    assert!(compose(None, &cards("hook: {} ")).is_none());
    let fields = CardFields {
        rate_card: Some(Default::default()),
        plugin_rate_cards: cards("hook: { gate: { calls: 1 } }"),
        ..CardFields::default()
    };
    assert_eq!(
        CardFields::from_composed(fields.composed().as_ref(), 0, Default::default()),
        fields
    );
}
