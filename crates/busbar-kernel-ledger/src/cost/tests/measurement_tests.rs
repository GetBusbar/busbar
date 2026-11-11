// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::cost::{
    measurement_lane, split_measurement_lane, Author, CardEntryDraft, ClassPrice, History,
    LaneClass, RateCard, TierRates,
};

#[test]
fn measurement_lane_namespaces_and_kinds_cannot_collide() {
    let a = measurement_lane("hook", "a:b");
    assert_ne!(a, measurement_lane("hook:a", "b"));
    assert_ne!(a, measurement_lane("export", "a:b"));
    assert_eq!(split_measurement_lane(&a), Some(("hook", "a:b")));
    assert_eq!(split_measurement_lane("hook:a:b"), None);
    assert_eq!(split_measurement_lane("\u{1e}measurement:1:é"), None);
}

#[test]
fn measurement_missing_rates_stay_unpriced_with_legacy_pricing_off() {
    let lane = measurement_lane("store", "primary");
    let absent = RateCard::absent(9);
    assert_eq!(
        absent.lane_pricing(&lane).class_price("reads"),
        ClassPrice::Unpriced
    );
    assert_eq!(
        absent.lane_pricing("legacy").class_price("input"),
        ClassPrice::Nanos(0)
    );
    let card = absent.with_unit_rates([
        (LaneClass::new(&lane, "reads"), 125),
        (LaneClass::new(&lane, "bytes"), 0),
    ]);
    assert!(!card.pricing_enabled());
    assert_eq!(
        card.lane_pricing(&lane).class_price("reads"),
        ClassPrice::Nanos(125)
    );
    assert_eq!(
        card.lane_pricing(&lane).class_price("bytes"),
        ClassPrice::Nanos(0)
    );
    assert_eq!(
        card.lane_pricing(&lane).class_price("input"),
        ClassPrice::Unpriced
    );
    assert_eq!(
        card.lane_pricing(&measurement_lane("store", "other"))
            .class_price("reads"),
        ClassPrice::Unpriced
    );
    assert_eq!(
        card.lane_pricing(&measurement_lane("hook", "primary"))
            .class_price("reads"),
        ClassPrice::Unpriced
    );
}

#[test]
fn measurement_composition_does_not_install_legacy_zero_tiers() {
    let lane = measurement_lane("hook", "gate");
    let card = RateCard::from_config(Some([(lane.as_str(), TierRates::default())]), 0)
        .with_unit_rates([(LaneClass::new(&lane, "input"), 123)]);
    assert!(!card.pricing_enabled());
    assert_eq!(
        card.lane_pricing(&lane).class_price("input"),
        ClassPrice::Nanos(123)
    );
    assert_eq!(
        card.lane_pricing(&lane).class_price("output"),
        ClassPrice::Unpriced
    );
    let present = RateCard::from_config(
        Some([
            (lane.as_str(), TierRates::default()),
            ("\u{1f}", TierRates::default()),
        ]),
        0,
    );
    assert!(present.pricing_enabled());
}

#[test]
fn measurement_changes_preserve_stale_history_and_corrections() {
    let lane = measurement_lane("export", "audit");
    let formerly_unpriced = RateCard::absent(0)
        .corrected([(LaneClass::new(&lane, "records"), 125)], None)
        .unwrap();
    assert!(!formerly_unpriced.pricing_enabled());
    assert_eq!(
        formerly_unpriced.lane_pricing(&lane).class_price("records"),
        ClassPrice::Nanos(125)
    );
    let old = RateCard::absent(0).with_unit_rates([(LaneClass::new(&lane, "records"), 125)]);
    let new = old
        .corrected([(LaneClass::new(&lane, "records"), 500)], None)
        .unwrap();
    assert_ne!(old.digest(), new.digest());
    let mut history = History::opening(old, 0);
    history.append(CardEntryDraft {
        effective_from: 10,
        effective_until: None,
        card: new,
        appended_at: 10,
        author: Author::Config { policy_epoch: 1 },
    });
    assert_eq!(
        history
            .current()
            .card_at(9)
            .unwrap()
            .1
            .lane_pricing(&lane)
            .class_price("records"),
        ClassPrice::Nanos(125)
    );
    assert_eq!(
        history
            .current()
            .card_at(10)
            .unwrap()
            .1
            .lane_pricing(&lane)
            .class_price("records"),
        ClassPrice::Nanos(500)
    );
}

#[test]
fn measurement_readback_uses_common_classes_without_legacy_request_fees() {
    use std::collections::BTreeMap;
    let lane = measurement_lane("hook", "gate");
    let card = RateCard::absent(99).with_unit_rates([(LaneClass::new(&lane, "input"), 125)]);
    let classes = BTreeMap::from([("input".to_string(), 8)]);
    let legacy_placeholders = BTreeMap::from([
        ("input".into(), 0),
        ("output".into(), 0),
        ("cache_read".into(), 0),
        ("cache_write".into(), 0),
    ]);
    let row = crate::cost::MeteredRow::new(&lane, legacy_placeholders, 50, &classes);
    assert_eq!(row.spend_micros_at_card(&card).unwrap(), 1);
}
