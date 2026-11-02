// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::bounded::{FactValue, Facts, MAX_LEG_REPLIES};

#[test]
fn a_unit_carries_the_drafts_facts() {
    fn seal() -> busbar_contract::caps::Pass<busbar_contract::caps::Verify> {
        busbar_contract::caps::Pass::mint(&busbar_contract::caps::KernelSeal::acquire_for_kernel())
    }

    let mut facts = Facts::new();
    facts
        .set("verb", FactValue::Str("get_status"))
        .expect("set");
    facts.set("stream", FactValue::Bool(true)).expect("set");

    let unit = busbar_contract::unit::Unit::new(
        &seal(),
        busbar_contract::UnitKey::new(1),
        busbar_contract::unit::Origin::Client,
        None,
        None,
        busbar_contract::wire::Direction::Inbound,
        None,
        busbar_contract::ids::OpClassId::new("op"),
        busbar_contract::bounded::Ir::new(b"{}", &[]),
        facts,
        None,
    );

    assert_eq!(unit.draft_facts().len(), 2);
    assert_eq!(
        unit.draft_facts().get("verb"),
        Some(FactValue::Str("get_status"))
    );
    assert_eq!(
        unit.draft_facts().get("stream"),
        Some(FactValue::Bool(true))
    );
    assert_eq!(unit.draft_facts().get("absent"), None);
}

#[test]
fn a_unit_refuses_the_leg_reply_past_its_ceiling_and_hands_it_back() {
    fn seal() -> busbar_contract::caps::Pass<busbar_contract::caps::Verify> {
        busbar_contract::caps::Pass::mint(&busbar_contract::caps::KernelSeal::acquire_for_kernel())
    }

    let mut unit = busbar_contract::unit::Unit::new(
        &seal(),
        busbar_contract::UnitKey::new(1),
        busbar_contract::unit::Origin::Client,
        None,
        None,
        busbar_contract::wire::Direction::Inbound,
        None,
        busbar_contract::ids::OpClassId::new("op"),
        busbar_contract::bounded::Ir::new(b"{}", &[]),
        Facts::new(),
        None,
    );

    let reply = |leg: u8| busbar_contract::unit::LegResult {
        leg,
        body: None,
        facts: Facts::new(),
    };

    for leg in 0..MAX_LEG_REPLIES {
        unit.push_leg_result(&seal(), reply(u8::try_from(leg).expect("small")))
            .expect("under the ceiling");
    }
    assert_eq!(unit.leg_results().len(), MAX_LEG_REPLIES);

    let handed_back = unit
        .push_leg_result(&seal(), reply(99))
        .expect_err("the unit accepted a reply past its ceiling");
    assert_eq!(
        handed_back.leg, 99,
        "the reply handed back is the one passed in, not a default"
    );
    assert_eq!(
        unit.leg_results().len(),
        MAX_LEG_REPLIES,
        "the replies it already held are untouched"
    );
}
