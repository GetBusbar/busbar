// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE KNOB, ONE COUNT, EVERY PLANE.**
//!
//! A fee schedule is only worth having if each of its knobs moves exactly the number it says it
//! moves, and moves it the same way for every plane. This file is that proof, and it is written
//! ONCE and driven over the PLANE DECLARATIONS rather than once per plane — because a cell per
//! plane is a place for the five to be allowed to differ, and they may not. Every plugin of a kind
//! is identical to every other of that kind; billing a plane is billing a plane.
//!
//! # What is driven, and from where
//!
//! [`DECLARED`] is the five shipped planes as the composition root sees them: the registry key each
//! declares, where each says its status is reported, and whether each declares its local work
//! chargeable. Nothing here is written out by hand — every field is read through
//! [`busbar_contract::plane::PlaneMeta`] off the plane's own `meta.rs`, so a sixth plane joins this
//! file by existing and a plane that changes its declaration changes what is asserted about it.
//!
//! # Red before green
//!
//! Every cell below drives `busbar_kernel::teller::charge` over a `TariffCell`. Neither existed
//! before the landing that added them, so this file does not compile against the tree it was
//! written against — which is the strongest red a cell can have and the reason it is worth writing
//! the assertions as *differences* rather than as literals. A knob that did nothing would leave
//! the two sides of every `assert_ne!` below equal, and a knob wired to the wrong count would move
//! a number the cell holds still.

use busbar_contract::plane::PlaneMeta;
use busbar_contract::{FinishClass, StatusClass};
use busbar_kernel::teller::{charge, Charge, DisputePolicy, FeeEvidence, TariffCell};

/// One plane's declarations, as the fee reads them.
struct Declared {
    /// The plane's registry key — what a `tariff.plane:` scope is keyed by.
    key: &'static str,
    /// Where this dialect reports the status of a unit, if it reports one.
    status_at: Option<busbar_contract::StatusAt>,
    /// Whether a unit this plane serves without a destination is still a transaction.
    chargeable_local: bool,
}

/// Read one plane's declarations. The whole of this file's knowledge of a plane.
fn declared<P: PlaneMeta>() -> Declared {
    Declared {
        key: P::KEY,
        status_at: P::STATUS_LEG,
        chargeable_local: P::CHARGEABLE_LOCAL,
    }
}

/// THE FIVE SHIPPED PLANES, and the only place any of them is named.
fn all_planes() -> Vec<Declared> {
    vec![
        declared::<busbar_plane_llm::LlmPlane>(),
        declared::<busbar_plane_mcp::McpPlane>(),
        declared::<busbar_plane_a2a::A2aPlane>(),
        declared::<busbar_plane_voice::VoicePlane>(),
        declared::<busbar_plane_admin::AdminPlane>(),
    ]
}

/// A completed exchange inside an admitted visit, on one plane.
fn completed(plane: &Declared) -> FeeEvidence {
    FeeEvidence {
        admitted: true,
        client_open_or_one_shot: true,
        selected_upstream: true,
        chargeable_local: plane.chargeable_local,
        relayed_first_response_frame: true,
        status_at: plane.status_at,
        status: Some(StatusClass::Success),
        finish: Some(FinishClass::Complete),
    }
}

/// The same visit, whose two endings contradict each other: the client saw an answer start, the
/// plane says it failed.
fn contradicted(plane: &Declared) -> FeeEvidence {
    FeeEvidence {
        finish: Some(FinishClass::Error),
        ..completed(plane)
    }
}

/// A caller refused before the door: nothing was admitted, and nothing about the exchange exists.
fn refused_before_admit(plane: &Declared) -> FeeEvidence {
    FeeEvidence {
        admitted: false,
        selected_upstream: false,
        relayed_first_response_frame: false,
        status: None,
        finish: Some(FinishClass::Error),
        ..completed(plane)
    }
}

/// Every ending shape this file knows how to build, for one plane.
fn every_shape(plane: &Declared) -> Vec<(&'static str, FeeEvidence)> {
    vec![
        ("completed", completed(plane)),
        ("contradicted", contradicted(plane)),
        ("refused before admit", refused_before_admit(plane)),
    ]
}

/// The schedule with one knob turned on and everything else at what a node ships with.
fn with_entry_fee(enabled: bool) -> TariffCell {
    TariffCell {
        entry_fee_enabled: enabled,
        ..TariffCell::default()
    }
}

/// **KNOB 1 — `entry_fee.enabled` MOVES THE ENTRY COUNT AND NOTHING ELSE.**
///
/// Turning the door fee on adds exactly one entry to every ADMITTED visit, on every plane, whatever
/// the visit went on to contain — and changes no transaction count and no units decision anywhere.
/// A knob that moved a second number would be a knob whose name is a lie about what it does.
#[test]
fn the_entry_fee_knob_moves_the_entry_count_on_every_plane_alike() {
    for plane in all_planes() {
        for (shape, evidence) in every_shape(&plane) {
            let off = charge(&evidence, &with_entry_fee(false));
            let on = charge(&evidence, &with_entry_fee(true));
            assert_eq!(
                off.entry, 0,
                "{}/{shape}: a node that does not charge for the door charges for no doors",
                plane.key
            );
            assert_eq!(
                on.entry,
                u32::from(evidence.admitted),
                "{}/{shape}: one entry per admitted visit, none for a caller who never became one",
                plane.key
            );
            assert_eq!(
                (on.transaction, on.units_allowed, on.flags),
                (off.transaction, off.units_allowed, off.flags),
                "{}/{shape}: the door's knob moved something that is not the door",
                plane.key
            );
        }
    }
}

/// **THE ENTRY FEE IS CHARGED AT ADMIT AND NOT AT ARRIVAL.**
///
/// The same knob, the same plane, one fact different. A caller refused at authenticate, verify or
/// approve never became a visit, and a schedule that charged for one would be charging for the act
/// of being turned away.
#[test]
fn a_caller_refused_before_the_door_is_charged_no_entry_on_any_plane() {
    for plane in all_planes() {
        let admitted = charge(&completed(&plane), &with_entry_fee(true)).entry;
        let refused = charge(&refused_before_admit(&plane), &with_entry_fee(true)).entry;
        assert_ne!(
            admitted, refused,
            "{}: if these are equal the door is not what is being charged for",
            plane.key
        );
        assert_eq!((admitted, refused), (1, 0), "{}", plane.key);
    }
}

/// **KNOB 2 — `dispute_policy` MOVES WHAT A CONTRADICTED UNIT OWES, AND ONLY THAT.**
///
/// Three policies, three answers, the same three on every plane: the visit only, the visit and what
/// was delivered, or everything as though the exchange had completed. All three mark the posting,
/// because the mark says the two readings disagreed and that is true under all of them.
#[test]
fn the_dispute_policy_knob_moves_a_contradicted_unit_on_every_plane_alike() {
    let expected = [
        (DisputePolicy::EntryOnly, 0, false),
        (DisputePolicy::EntryPlusUnits, 0, true),
        (DisputePolicy::Full, 1, true),
    ];
    for plane in all_planes() {
        let mut seen = Vec::new();
        for (policy, transaction, units) in expected {
            let charged = charge(
                &contradicted(&plane),
                &TariffCell {
                    dispute_policy: policy,
                    ..TariffCell::default()
                },
            );
            assert_eq!(
                (charged.transaction, charged.units_allowed),
                (transaction, units),
                "{} under {policy:?}",
                plane.key
            );
            assert!(
                charged
                    .flags
                    .contains(busbar_caps::PostingFlags::METER_DISPUTED),
                "{} under {policy:?}: the disagreement is not on the disputes report",
                plane.key
            );
            seen.push((charged.transaction, charged.units_allowed));
        }
        seen.dedup();
        assert_eq!(
            seen.len(),
            3,
            "{}: three policies that answer fewer than three ways is a knob with a dead position",
            plane.key
        );
    }
}

/// **THE DISPUTE KNOB IS INERT WHERE THERE IS NOTHING TO DISPUTE.**
///
/// A unit whose two endings agree is not a pricing question, and a schedule that moved its money
/// would be charging a deployment for a policy it never reached.
#[test]
fn the_dispute_policy_knob_moves_nothing_on_a_unit_that_did_not_contradict() {
    for plane in all_planes() {
        for shape in [completed(&plane), refused_before_admit(&plane)] {
            let answers: Vec<Charge> = [
                DisputePolicy::EntryOnly,
                DisputePolicy::EntryPlusUnits,
                DisputePolicy::Full,
            ]
            .into_iter()
            .map(|dispute_policy| {
                charge(
                    &shape,
                    &TariffCell {
                        dispute_policy,
                        ..TariffCell::default()
                    },
                )
            })
            .collect();
            assert!(
                answers.windows(2).all(|w| w[0] == w[1]),
                "{}: the dispute knob moved a unit whose endings agreed: {answers:?}",
                plane.key
            );
        }
    }
}

/// **KNOB 3 — `CHARGEABLE_LOCAL` IS WHAT MAKES A LOCAL SERVICE A TRANSACTION.**
///
/// Not a tariff knob but the declaration the tariff prices over, driven here for the same reason:
/// it changes exactly one count, the same way, whatever plane declares it. No shipped plane
/// declares it today, so both sides of this are exercised by construction rather than by waiting
/// for one to.
#[test]
fn a_declared_local_service_is_the_only_thing_that_bills_a_visit_with_no_destination() {
    for plane in all_planes() {
        let mut answers = Vec::new();
        for chargeable_local in [false, true] {
            let local_only = FeeEvidence {
                selected_upstream: false,
                chargeable_local,
                ..completed(&plane)
            };
            let charged = charge(&local_only, &TariffCell::default());
            assert_eq!(
                charged.transaction,
                u32::from(chargeable_local),
                "{}: the declaration is the whole of the difference",
                plane.key
            );
            answers.push(charged.transaction);
        }
        assert_ne!(answers[0], answers[1], "{}", plane.key);
    }
}

/// **THE FIVE PLANES ARE CHARGED IDENTICALLY, KNOB FOR KNOB.**
///
/// The summary cell. Every schedule this file can build, over every ending shape, asked of all five
/// planes: the answers must collapse to ONE answer per (schedule, shape). If they ever do not, some
/// plane is being priced for being itself, which is the thing the whole design refuses.
#[test]
fn no_schedule_and_no_shape_tells_the_five_planes_apart() {
    let schedules = [
        TariffCell::default(),
        with_entry_fee(true),
        TariffCell {
            entry_fee_enabled: true,
            dispute_policy: DisputePolicy::Full,
        },
        TariffCell {
            entry_fee_enabled: false,
            dispute_policy: DisputePolicy::EntryOnly,
        },
    ];
    let planes = all_planes();
    for schedule in schedules {
        for index in 0..every_shape(&planes[0]).len() {
            let answers: Vec<Charge> = planes
                .iter()
                .map(|plane| charge(&every_shape(plane)[index].1, &schedule))
                .collect();
            assert!(
                answers.windows(2).all(|w| w[0] == w[1]),
                "shape {index} under {schedule:?} is charged differently by plane: {answers:?}"
            );
        }
    }
    assert_eq!(
        planes.len(),
        5,
        "the shipped planes; a sixth joins by existing"
    );
}
