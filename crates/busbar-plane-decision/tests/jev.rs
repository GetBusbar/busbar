//! jev-specific evidence the generic conformance/purity/invariance/alloc-gate suites do not cover:
//! round-trip byte-identity on both operations, the billable-success-only metering surface, and the
//! PII witness — the whole reason this plane exists in the shape it does.

mod common;

use busbar_contract::bounded::{FactValue, Facts, Ir};
use busbar_contract::plane::{Plane, Response};
use busbar_contract::unit::FinishClass;
use busbar_plane_decision::{facts, meta::CLASS_DECISION, ops, DecisionPlane};
use common::Scaffold;

/// A successful `systemone` answer, billing 7 units.
const SYSTEMONE_SUCCESS: &[u8] =
    br#"{"request_id":"req_7","usage":{"units":7},"answers":{"decision":"approve"}}"#;

/// A 422 whose body echoes the caller's `state` and the provider's `answers` — the PII witness
/// fixture. Both values are deliberately distinctive strings so a substring search cannot miss a
/// leak.
const SYSTEMONE_422_WITH_STATE: &[u8] = br#"{"error":{"code":"invalid_state","message":"bad transition"},"state":{"session":"CALLER-SECRET-STATE-9f3a"},"answers":{"leaked":"PROVIDER-ANSWER-CONTENT-77bd"}}"#;

/// The two distinctive substrings the fixture above carries, and that must never surface anywhere
/// this plane emits a fact.
const SECRET_STATE_MARKER: &str = "CALLER-SECRET-STATE-9f3a";
const SECRET_ANSWERS_MARKER: &str = "PROVIDER-ANSWER-CONTENT-77bd";

/// The `models` catalogue response, relayed as-is.
const MODELS_LIST: &[u8] =
    br#"{"request_id":"req_9","data":[{"id":"jev-1.13.0","object":"model"}]}"#;

/// Every `FactValue::Str`/`FactValue::Bytes` value a `Facts` map carries, as owned strings — the
/// search surface the PII witness scans.
fn string_values(facts: &Facts<'_>) -> Vec<String> {
    facts
        .iter()
        .filter_map(|(_, v)| match v {
            FactValue::Str(s) => Some(s.to_string()),
            FactValue::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
            _ => None,
        })
        .collect()
}

/// Drive `decode_response` on a body and hand the `Facts` it emitted to a closure — the boundary
/// the PII witness checks. A macro rather than a function: the decoded `Facts` borrows from a
/// `Vec<Frame>` this helper owns, and that borrow cannot outlive a function's return, so the whole
/// decode-and-inspect step has to happen in the caller's own scope.
macro_rules! with_decoded_facts {
    ($plane:expr, $body:expr, $scaffold:expr, |$facts:ident| $body_block:block) => {{
        let ctx = $scaffold.ctx();
        let frames = vec![common::response_frame($body)];
        let mut cursor = busbar_contract::wire::FrameCursor::new(&frames);
        let busbar_contract::plane::Progress::Terminal { r: response, .. } = $plane
            .decode_response(&mut cursor, &common::sealed_destination(), None, &ctx)
            .expect("a whole answer decodes as terminal")
        else {
            panic!("a whole answer decodes as terminal, not a partial frame");
        };
        let $facts = response.facts;
        $body_block
    }};
}

#[test]
fn dialect_round_trip_is_byte_identical_for_both_ops() {
    let plane = DecisionPlane::EMPTY;
    for fixture in [SYSTEMONE_SUCCESS, MODELS_LIST] {
        let scaffold = Scaffold::new("http");
        let ctx = scaffold.ctx();
        let r = Response {
            ir: Ir::new(fixture, &[]),
            finish: FinishClass::Complete,
            facts: Facts::new(),
        };
        let out = plane
            .encode_response(&r, None, &ctx)
            .expect("it round-trips");
        assert_eq!(out.as_slice(), fixture, "round trip changed the bytes");
    }
}

#[test]
fn two_op_passthrough_forwards_both_request_bodies_unchanged() {
    let plane = DecisionPlane::EMPTY;
    let seal = common::TestSeal;
    let dest = common::sealed_destination();
    for (op, body) in [
        (ops::OP_SYSTEMONE, br#"{"state":{"a":1}}"#.as_slice()),
        (ops::OP_MODELS, br#"{}"#.as_slice()),
    ] {
        let scaffold = Scaffold::new("http");
        let ctx = scaffold.ctx();
        let unit = busbar_contract::unit::Unit::new(
            &seal,
            busbar_contract::UnitKey::new(1),
            busbar_contract::unit::Origin::Client,
            None,
            None,
            busbar_contract::wire::Direction::Inbound,
            Some(common::principal()),
            op,
            Ir::new(body, &[]),
            Facts::new(),
            None,
        );
        let egress = plane
            .encode_egress(&unit, &dest, None, &ctx)
            .expect("both ops express a hop to the configured provider");
        assert_eq!(
            egress.body.as_slice(),
            body,
            "op {op:?} was not passed through unchanged"
        );
    }
}

#[test]
fn billable_success_metering_surface_reports_usage_on_success_and_nothing_on_error() {
    let plane = DecisionPlane::EMPTY;
    let seal = common::TestSeal;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let unit = busbar_contract::unit::Unit::new(
        &seal,
        busbar_contract::UnitKey::new(1),
        busbar_contract::unit::Origin::Client,
        None,
        None,
        busbar_contract::wire::Direction::Inbound,
        Some(common::principal()),
        ops::OP_SYSTEMONE,
        Ir::new(b"{}", &[]),
        Facts::new(),
        None,
    );

    // Success: the class is reported, with the exact quantity the response carried.
    with_decoded_facts!(plane, SYSTEMONE_SUCCESS, scaffold, |success_facts| {
        let success_r = Response {
            ir: Ir::new(SYSTEMONE_SUCCESS, &[]),
            finish: FinishClass::Complete,
            facts: success_facts,
        };
        let locators = plane.meter(&unit, &success_r, &ctx);
        assert_eq!(locators.lines.len(), 1);
        let line = &locators.lines.as_slice()[0];
        assert_eq!(line.class, CLASS_DECISION);
        assert_eq!(line.quantity, Some(7));
    });

    // Error: nothing extractable under the billable-decision class at all — not a zero-quantity
    // line, no line.
    let error_scaffold = Scaffold::new("http");
    with_decoded_facts!(
        plane,
        SYSTEMONE_422_WITH_STATE,
        error_scaffold,
        |error_facts| {
            let error_r = Response {
                ir: Ir::new(SYSTEMONE_422_WITH_STATE, &[]),
                finish: FinishClass::Error,
                facts: error_facts,
            };
            let locators = plane.meter(&unit, &error_r, &ctx);
            assert!(
                locators.lines.is_empty(),
                "a 422 must yield nothing extractable under the billable-decision class"
            );
        }
    );
}

#[test]
fn pii_witness_never_surfaces_state_or_answers_in_any_fact() {
    let plane = DecisionPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let seal = common::TestSeal;
    let unit = busbar_contract::unit::Unit::new(
        &seal,
        busbar_contract::UnitKey::new(2),
        busbar_contract::unit::Origin::Client,
        None,
        None,
        busbar_contract::wire::Direction::Inbound,
        Some(common::principal()),
        ops::OP_SYSTEMONE,
        Ir::new(b"{}", &[]),
        Facts::new(),
        None,
    );

    with_decoded_facts!(
        plane,
        SYSTEMONE_422_WITH_STATE,
        scaffold,
        |response_facts| {
            // decode_response's own Facts map: the primary boundary.
            for value in string_values(&response_facts) {
                assert!(
                    !value.contains(SECRET_STATE_MARKER),
                    "decode_response's facts leaked the caller's `state`: {value}"
                );
                assert!(
                    !value.contains(SECRET_ANSWERS_MARKER),
                    "decode_response's facts leaked the provider's `answers`: {value}"
                );
            }

            // content_facts, the record/export-path boundary.
            let r = Response {
                ir: Ir::new(SYSTEMONE_422_WITH_STATE, &[]),
                finish: FinishClass::Error,
                facts: response_facts,
            };
            let ctx = scaffold.ctx();
            let content = plane.content_facts(&unit, &r, &ctx);
            for value in string_values(&content.facts) {
                assert!(!value.contains(SECRET_STATE_MARKER));
                assert!(!value.contains(SECRET_ANSWERS_MARKER));
            }
        }
    );

    // The declared pointer lists themselves never name the two members — the structural guarantee
    // behind every assertion above.
    assert!(!busbar_plane_decision::codec::RESPONSE_PTRS.contains(&"/state"));
    assert!(!busbar_plane_decision::codec::RESPONSE_PTRS.contains(&"/answers"));
    assert!(busbar_plane_decision::codec::REQUEST_PTRS.is_empty());
    assert!(!facts::CONTENT_FACTS
        .iter()
        .any(|k| *k == "state" || *k == "answers"));
    assert!(!facts::SESSION_FACTS
        .iter()
        .any(|k| *k == "state" || *k == "answers"));
}
