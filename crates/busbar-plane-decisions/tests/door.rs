// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S ANSWERS, DRIVEN OVER ITS ABI as the kernel's plane driver drives them.
//!
//! * MODEL RESOLUTION (THE DESIGN section 2, the decisions bullet; DECISIONS D8b): "a request routes
//!   by its model; one configured model and none named is the default (byte-identical); more than
//!   one and none named is 400; an unknown model is 404." The claim is published whenever a model is
//!   configured.
//! * `upstream_model` (the same bullet): "rewrites only the top-level model value, by span splice,
//!   when it is set and differs; otherwise the body passes through."

#![allow(unsafe_code)]

mod door_harness;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::plane::ROUTE_DIRECT;
use door_harness::{open, Bufs, Given};

const SYSTEMONE: (&str, &str) = ("POST", "/v1/systemone");

const TWO: &str = r#"{"models":{"a":{"provider":"typesafe"},"b":{"provider":"typesafe"}}}"#;
const ONE: &str = r#"{"models":{"jev":{"provider":"typesafe"}}}"#;

fn claims(c: &[(&str, &str)]) -> Vec<(String, String)> {
    c.iter()
        .map(|(v, t)| ((*v).to_string(), (*t).to_string()))
        .collect()
}

/// RED (audit plane-decisions#1): several configured models publish the claim; none publishes none.
#[test]
fn every_generation_with_a_model_claims_systemone() {
    assert_eq!(open(TWO).claims, claims(&[SYSTEMONE]), "two models");
    assert_eq!(open(ONE).claims, claims(&[SYSTEMONE]), "one model");
    let none = open(r#"{"models":{}}"#);
    assert!(none.claims.is_empty(), "no model claims nothing");
    // A refresh onto several models keeps the claim, and onto none drops it.
    assert_eq!(none.refresh(TWO, 2), claims(&[SYSTEMONE]));
    assert!(none.refresh("{}", 3).is_empty());
}

/// RED (audit plane-decisions#1): a request routes over the model it names; several configured and
/// none named is 400; a name no model has is 404; one configured and none named is the default.
#[test]
fn a_request_routes_by_its_model() {
    let two = open(TWO);
    let b = two.arrive(1, br#"{"model":"b","state":{}}"#);
    assert_eq!(
        (b.outcome, b.route, b.entry.as_str()),
        (Outcome::Ready, ROUTE_DIRECT, "b"),
        "{b:?}"
    );
    let a = two.arrive(2, br#"{"state":{},"model":"a"}"#);
    assert_eq!(
        (a.outcome, a.entry.as_str()),
        (Outcome::Ready, "a"),
        "{a:?}"
    );

    let unnamed = two.arrive(3, br#"{"state":{}}"#);
    assert_eq!(
        (unnamed.outcome, unnamed.status),
        (Outcome::Refused, 400),
        "{unnamed:?}"
    );
    assert!(
        unnamed.refusal != 0 && !unnamed.text.is_empty(),
        "{unnamed:?}"
    );

    let unknown = two.arrive(4, br#"{"model":"zz","state":{}}"#);
    assert_eq!(
        (unknown.outcome, unknown.status),
        (Outcome::Refused, 404),
        "{unknown:?}"
    );
    assert!(unknown.text.contains("'zz'"), "{unknown:?}");

    let not_a_name = two.arrive(5, br#"{"model":7}"#);
    assert_eq!(
        (not_a_name.outcome, not_a_name.status),
        (Outcome::Refused, 400),
        "{not_a_name:?}"
    );

    let one = open(ONE);
    let default = one.arrive(6, br#"{"state":{}}"#);
    assert_eq!(
        (default.outcome, default.route, default.entry.as_str()),
        (Outcome::Ready, ROUTE_DIRECT, "jev"),
        "{default:?}"
    );
    let named = one.arrive(7, br#"{"model":"jev"}"#);
    assert_eq!(
        (named.outcome, named.entry.as_str()),
        (Outcome::Ready, "jev")
    );
    let elsewhere = one.arrive(8, br#"{"model":"other"}"#);
    assert_eq!(
        (elsewhere.outcome, elsewhere.status),
        (Outcome::Refused, 404),
        "{elsewhere:?}"
    );
}

/// A refused arrival is answered in jev's error shape, the arrival's words and status.
#[test]
fn an_unrouted_arrival_renders_in_the_dialect_shape() {
    let two = open(TWO);
    let unknown = two.arrive(1, br#"{"model":"zz"}"#);
    let (outcome, body) = two.refusal(1, unknown.status, &unknown.text, true);
    assert_eq!(outcome, Outcome::Ready);
    let v: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(v["error"]["message"], unknown.text.as_str(), "{v}");
    assert!(v["error"]["code"].is_string(), "{v}");
}

/// The caller's body as the far end receives it, for a unit routed over `settings` by `body`.
fn sent(settings: &str, body: &[u8]) -> String {
    let door = open(settings);
    let arrived = door.arrive(1, body);
    assert_eq!(arrived.outcome, Outcome::Ready, "{arrived:?}");
    let mut bufs = Bufs::new(1 << 16);
    let attempt = door.piece(1, Given::attempt(1), &mut bufs);
    assert_eq!(attempt.request, "POST /v1/systemone");
    let caller = door.piece(1, Given::caller(body), &mut bufs);
    assert!(caller.far, "the caller's body goes to the far end");
    String::from_utf8(caller.bytes).expect("UTF-8")
}

/// RED (audit plane-decisions#2): a set `upstream_model` that differs replaces the top-level model
/// value alone; every other byte (member order, whitespace) is the caller's.
#[test]
fn upstream_model_is_spliced_into_the_top_level_model() {
    let upstream = r#"{"models":{"jev":{"provider":"typesafe","upstream_model":"jev-1.13.0"}}}"#;
    let body = "{ \"state\" : {\"model\":\"inner\"},\n  \"model\" :  \"jev\" , \"n\":[1, 2] }";
    assert_eq!(
        sent(upstream, body.as_bytes()),
        "{ \"state\" : {\"model\":\"inner\"},\n  \"model\" :  \"jev-1.13.0\" , \"n\":[1, 2] }"
    );
    // The same name, or none set, or a body that names no model: the body passes through.
    let same = r#"{"models":{"jev":{"provider":"typesafe","upstream_model":"jev"}}}"#;
    assert_eq!(sent(same, body.as_bytes()), body);
    assert_eq!(sent(ONE, body.as_bytes()), body);
    let unnamed = "{\"state\":{}}";
    assert_eq!(sent(upstream, unnamed.as_bytes()), unnamed);
}

/// One unit served over [`ONE`]: its ATTEMPT, the caller's body, and the far end's whole answer,
/// `status` with `answer`. Answers the far end's piece.
fn answered(status: u32, answer: &[u8]) -> door_harness::Answered {
    let door = open(ONE);
    assert_eq!(door.arrive(1, br#"{"state":{}}"#).outcome, Outcome::Ready);
    let mut bufs = Bufs::new(1 << 16);
    door.piece(1, Given::attempt(1), &mut bufs);
    door.piece(1, Given::caller(br#"{"state":{}}"#), &mut bufs);
    door.piece(1, Given::whole(status, answer), &mut bufs)
}

/// The class index the tail names `name` at.
fn class(name: &str) -> u32 {
    let tail = busbar_plane_decisions::plane_door::TAIL;
    // SAFETY: the tail's billable classes are a `'static` list of `billable_classes_len` entries,
    // each naming `'static` strings.
    let classes =
        unsafe { std::slice::from_raw_parts(tail.billable_classes, tail.billable_classes_len) };
    let named = |c: &busbar_contract::abi::plane::BillableClass| {
        // SAFETY: as above.
        unsafe { std::slice::from_raw_parts(c.class.ptr, c.class.len) == name.as_bytes() }
    };
    let at = classes
        .iter()
        .position(named)
        .unwrap_or_else(|| panic!("the tail declares no class `{name}`"));
    u32::try_from(at).unwrap()
}

/// `(class, amount)` of every count an answer reported, each REPORTED.
fn counts(a: &door_harness::Answered) -> Vec<(u32, u64)> {
    assert!(
        a.units
            .iter()
            .all(|(_, source, _)| *source == busbar_contract::abi::plane::UNITS_REPORTED),
        "{a:?}"
    );
    a.units.iter().map(|(c, _, n)| (*c, *n)).collect()
}

/// RED (audit plane-decisions#4): THE DESIGN section 7, "bills one `decision` per successful, settled
/// answer from every provider": a success with no count bills one decision, beside its fee.
#[test]
fn a_success_with_no_count_bills_one_decision() {
    let fee = class(busbar_contract::plane::PER_REQUEST);
    let a = answered(200, br#"{"answers":{}}"#);
    assert_eq!(a.outcome, Some(Outcome::Ready), "{a:?}");
    assert_eq!(counts(&a), vec![(class("decision"), 1), (fee, 1)]);
    let reported = answered(200, br#"{"usage":{"units":42}}"#);
    assert_eq!(counts(&reported), vec![(class("decision"), 42), (fee, 1)]);
}

/// RED (audit plane-decisions#4): one success rule: a non-2xx answer bills nothing, whatever count
/// it carries.
#[test]
fn a_non_success_bills_nothing() {
    let a = answered(500, br#"{"usage":{"units":2}}"#);
    assert_eq!(a.outcome, Some(Outcome::Ready), "{a:?}");
    assert!(a.units.is_empty(), "{a:?}");
    assert_eq!(a.bytes, br#"{"usage":{"units":2}}"#, "relayed unchanged");
}

/// RED (audit plane-decisions#4): a success whose count is not a whole count fails the unit loudly
/// (finding 395, kept: "LOCATED, never dropped"), never a silent zero.
#[test]
fn a_success_with_an_unreadable_count_fails_loudly() {
    for answer in [
        &br#"{"usage":{"units":7.5}}"#[..],
        br#"{"usage":{"units":"7"}}"#,
        br#"{"usage":{"units":-3}}"#,
    ] {
        let a = answered(200, answer);
        assert_eq!(
            (a.outcome, a.short),
            (Some(Outcome::Failed), false),
            "{}: {a:?}",
            String::from_utf8_lossy(answer)
        );
        assert!(a.units.is_empty() && a.bytes.is_empty(), "{a:?}");
    }
}

/// RED (audit plane-decisions#5): THE DESIGN section 7, "its card prices `decision`, `input_tokens`
/// and `output_tokens` (family `decision`, all three required, 0 = free)": the tail declares the
/// three in family `decision`, and a success's reported tokens are billed in them.
#[test]
fn the_tokens_a_success_reports_are_billed_in_family_decision() {
    let tail = busbar_plane_decisions::plane_door::TAIL;
    // SAFETY: as in `class`.
    let classes =
        unsafe { std::slice::from_raw_parts(tail.billable_classes, tail.billable_classes_len) };
    let family = |name: &str| {
        let c = &classes[class(name) as usize];
        // SAFETY: as in `class`.
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(c.family.ptr, c.family.len) })
            .into_owned()
    };
    for name in ["decision", "input_tokens", "output_tokens"] {
        assert_eq!(family(name), "decision", "{name}");
    }
    let a = answered(
        200,
        br#"{"usage":{"units":2,"input_tokens":12,"output_tokens":5}}"#,
    );
    let got = counts(&a);
    for want in [
        (class("decision"), 2),
        (class("input_tokens"), 12),
        (class("output_tokens"), 5),
    ] {
        assert!(got.contains(&want), "{want:?} in {got:?}");
    }
}

const MAX_UNITS: u64 = busbar_plane_decisions::plane_door::MAX_UNITS as u64;

/// A live unit over [`ONE`]: arrived, its ATTEMPT crossed.
fn live(door: &door_harness::Door, unit: u64, bufs: &mut Bufs) {
    let arrived = door.arrive(unit, br#"{"state":{}}"#);
    assert_eq!(arrived.outcome, Outcome::Ready, "unit {unit}: {arrived:?}");
    let attempt = door.piece(unit, Given::attempt(1), bufs);
    assert_eq!(attempt.request, "POST /v1/systemone", "unit {unit}");
}

/// Whether `unit`'s body still reaches the far end: its ATTEMPT's state is still held.
fn still_live(door: &door_harness::Door, unit: u64, bufs: &mut Bufs) -> bool {
    door.piece(unit, Given::caller(br#"{"state":{}}"#), bufs)
        .far
}

/// RED (audit plane-decisions#6): a refusal ends its unit and drops its state, so refused traffic
/// never crowds out a live unit.
#[test]
fn a_refused_unit_is_dropped_and_a_live_unit_kept() {
    let door = open(ONE);
    let mut bufs = Bufs::new(1 << 16);
    live(&door, 1, &mut bufs);
    for unit in 2..2 + MAX_UNITS {
        assert_eq!(
            door.arrive(unit, br#"{}"#).outcome,
            Outcome::Ready,
            "unit {unit}"
        );
        door.refusal(unit, 429, "the key's limit is spent", false);
    }
    assert!(still_live(&door, 1, &mut bufs), "the live unit was dropped");
}

/// RED (audit plane-decisions#6): a cancel ends the unit on its ticket and drops its state.
#[test]
fn a_cancelled_unit_is_dropped_and_a_live_unit_kept() {
    let door = open(ONE);
    let mut bufs = Bufs::new(1 << 16);
    live(&door, 1, &mut bufs);
    for unit in 2..2 + MAX_UNITS {
        live(&door, unit, &mut bufs);
        let (outcome, disposition) = door.cancel(door_harness::ticket_of(unit));
        assert_eq!(
            (outcome, disposition),
            (Outcome::Ready, busbar_contract::abi::plane::CANCEL_ABORTED),
            "unit {unit}"
        );
    }
    assert!(still_live(&door, 1, &mut bufs), "the live unit was dropped");
}

/// RED (audit plane-decisions#6): a unit cut after its far end answered was not aborted before it.
#[test]
fn a_unit_cancelled_after_its_far_end_answered_is_cut_partway() {
    let door = open(ONE);
    let mut bufs = Bufs::new(1 << 16);
    live(&door, 1, &mut bufs);
    assert!(still_live(&door, 1, &mut bufs));
    let first = door.piece(1, Given::far(Some(200), false, br#"{"usage":"#), &mut bufs);
    assert_eq!(first.outcome, Some(Outcome::Ready));
    assert_eq!(
        door.cancel(door_harness::ticket_of(1)),
        (
            Outcome::Ready,
            busbar_contract::abi::plane::CANCEL_OK_PARTIAL
        )
    );
}

/// RED (audit plane-decisions#6): past [`MAX_UNITS`] live units a new arrival is refused, about
/// the entry it routed over, and no live unit is dropped to make room.
#[test]
fn past_the_cap_an_arrival_is_refused_and_no_live_unit_dropped() {
    let door = open(ONE);
    let mut bufs = Bufs::new(1 << 16);
    for unit in 1..=MAX_UNITS {
        live(&door, unit, &mut bufs);
    }
    let over = door.arrive(MAX_UNITS + 1, br#"{"state":{}}"#);
    assert_eq!(
        (over.outcome, over.status, over.route, over.entry.as_str()),
        (Outcome::Refused, 503, ROUTE_DIRECT, "jev"),
        "{over:?}"
    );
    assert!(
        still_live(&door, 1, &mut bufs),
        "the first live unit was dropped"
    );
    assert!(still_live(&door, MAX_UNITS, &mut bufs));
}

/// A unit that arrived and never crossed a piece while [`MAX_UNITS`] arrivals followed is
/// reclaimed, so the instance never refuses every arrival for good.
#[test]
fn an_arrival_never_started_is_reclaimed_once_the_cap_is_reached() {
    let door = open(ONE);
    for unit in 1..=MAX_UNITS {
        assert_eq!(door.arrive(unit, br#"{}"#).outcome, Outcome::Ready);
    }
    let next = door.arrive(MAX_UNITS + 1, br#"{}"#);
    assert_eq!(next.outcome, Outcome::Ready, "{next:?}");
}
