// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The card as the configuration spells it: stored bytes round-trip, a set replaces whole values,
//! and the composed form a generation prices with reads back to the same card.

use super::*;

fn entry(input: f64) -> RateEntryCfg {
    RateEntryCfg {
        input_utok: input,
        output_utok: input * 2.0,
        ..RateEntryCfg::default()
    }
}

fn card() -> CardFields {
    let mut planes = PlaneRateCards::new();
    planes.insert(
        "mcp".to_string(),
        BTreeMap::from([("tool-a".to_string(), entry(3.0))]),
    );
    CardFields {
        rate_card: Some(BTreeMap::from([("m".to_string(), entry(1.0))])),
        per_request_fee: 2,
        plane_rate_cards: planes,
        plane_fees: BTreeMap::from([(
            "mcp".to_string(),
            busbar_kernel_ledger::cost::PlaneFees {
                per_request: 4,
                per_session: 5,
            },
        )]),
    }
}

#[test]
fn a_card_round_trips_through_its_stored_bytes() {
    let card = card();
    let back = CardFields::from_bytes(&card.to_bytes()).expect("stored card");
    assert_eq!(back, card);
    assert_eq!(back.digest(), card.digest());
    assert_eq!(
        CardFields::default(),
        CardFields::from_bytes(&CardFields::default().to_bytes()).unwrap()
    );
}

#[test]
fn the_fields_two_cards_differ_on_are_named() {
    let card = card();
    let mut next = card.clone();
    next.per_request_fee = 9;
    next.plane_fees.insert(
        "mcp".to_string(),
        busbar_kernel_ledger::cost::PlaneFees {
            per_request: 1,
            per_session: 0,
        },
    );
    assert_eq!(
        next.differing_fields(&card),
        vec!["per_request_fee".to_string(), "planes.mcp.fees".to_string()]
    );
    assert!(card.differing_fields(&card).is_empty());
}
