// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unit's bounded draft facts and leg replies, driven through a unit the kernel sealed.
//!
//! Moved here from `busbar-contract/tests/bounded_limits.rs`: these two tests seal a unit with a
//! minted token, and a token constructor is spelled only inside the kernel (construction
//! `token-sealed`). The rest of that file's bounds need no token and stayed with the contract.

use busbar_contract::bounded::{FactValue, Facts, MAX_LEG_REPLIES};

/// The kernel seals the draft's facts onto the unit, and a later step reads them back unchanged.
///
/// This is what stops a step after decode re-deriving from the same bytes what decode already
/// determined. The map is the draft's, key for key: nothing is dropped and nothing is invented.
#[test]
fn a_unit_carries_the_drafts_facts() {
    // A REAL capability token, not a fixture seal: `Pass<Verify>` is one of the two
    // types this crate implements the sealed `KernelSeal` for (#65).
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

/// A unit refuses the leg reply past its ceiling and hands it back rather than dropping it.
///
/// The hand-back is the point: a refused reply is recoverable — the caller still holds the facts it
/// read off the wire and can decide what to do with them — where a dropped one would be evidence
/// the unit silently lost. The other four ceilings in this file are asserted this way; this one was
/// asserted only as a number.
#[test]
fn a_unit_refuses_the_leg_reply_past_its_ceiling_and_hands_it_back() {
    // A REAL capability token, not a fixture seal: `Pass<Verify>` is one of the two
    // types this crate implements the sealed `KernelSeal` for (#65).
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
