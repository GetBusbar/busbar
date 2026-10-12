//! THE DURABLE-STRING PIN (1.6.0-TODO KERNEL<>PLUGINS step 31; spec #17/#48; THE DESIGN, the plane
//! verbs and the end-state crate list).
//!
//! The owner renamed the plane `decisions`: this crate is `busbar-plane-decisions`, its feature
//! `plane-decisions`, its config verb `decisions`. What the rename does NOT touch is the plane's
//! `KEY` and its meter class: both stay the durable string `"decision"`, because a stored meter
//! row, a rate-card class and a registry key written under that string must keep meaning this
//! plane. A change to either string, or a crate that is no longer the renamed one, is red here.

use busbar_contract::plane::PlaneMeta;
use busbar_plane_decisions::{meta::CLASS_DECISION, DecisionPlane};

#[test]
fn the_crate_is_the_renamed_one() {
    assert_eq!(env!("CARGO_PKG_NAME"), "busbar-plane-decisions");
}

#[test]
fn the_plane_key_stays_the_durable_string() {
    assert_eq!(<DecisionPlane as PlaneMeta>::KEY, "decision");
}

/// The decision class keeps its durable string and leads the plane's classes; every class the plane
/// declares is in the `decision` family (the card's three: `decision`, `input_tokens`,
/// `output_tokens`, THE DESIGN section 7 owner money rulings).
#[test]
fn the_meter_class_stays_the_durable_string() {
    assert_eq!(CLASS_DECISION.as_str(), "decision");
    let classes = <DecisionPlane as PlaneMeta>::METER_CLASSES;
    assert_eq!(classes.first().map(|c| c.key.as_str()), Some("decision"));
    assert!(classes.iter().all(|c| c.family == "decision"));
}
