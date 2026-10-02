use super::*;

#[test]
fn error_body_is_pinned_bytes() {
    let body = error_body("invalid_request", "the request is too large");
    assert_eq!(
        body,
        br#"{"error":{"code":"invalid_request","message":"the request is too large"}}"#
    );
}

#[test]
fn error_body_escapes_a_quote_in_the_message() {
    let body = error_body("internal", "a \"quoted\" word");
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("still valid JSON");
    assert_eq!(parsed["error"]["message"], "a \"quoted\" word");
}

#[test]
fn refusal_render_is_total_and_never_leaks_the_specific_reason_for_admission_refusals() {
    // Every `RefusalReason` this crate imports is matched explicitly in `refusal_render` — if the
    // enum grows a variant the match becomes a compile error, which is the point. This test instead
    // pins that the ADMISSION-CLASS refusals (budget, breaker, rate, drain, ...) all answer with the
    // SAME neutral words, so a caller cannot distinguish "you're over budget" from "the breaker is
    // open" by reading the response.
    let admission_like = [
        RefusalReason::InFlightCap,
        RefusalReason::OverBudget,
        RefusalReason::BreakerOpen,
        RefusalReason::RateLimited,
        RefusalReason::Drain,
    ];
    let rendered: Vec<_> = admission_like.into_iter().map(refusal_render).collect();
    let first = rendered[0];
    for r in &rendered[1..] {
        assert_eq!(
            *r, first,
            "an admission-class refusal leaked a distinguishable answer"
        );
    }
}

#[test]
fn refusal_render_never_names_a_provider_or_billing_word() {
    // Coarse source-level guard, in the spirit of `busbar-plane-a2a`'s own
    // `the_plane_names_no_money_and_no_decision` test: the rendered WORDS a caller reads back must
    // never carry `state`, `answers`, or a raw number.
    for reason in [
        RefusalReason::BodyTooLarge,
        RefusalReason::ScopeMissing,
        RefusalReason::NoDestination,
        RefusalReason::BreakerOpen,
        RefusalReason::PlanePanic,
    ] {
        let (_, message) = refusal_render(reason);
        assert!(!message.contains("state"));
        assert!(!message.contains("answers"));
    }
}

// ---- the plane driven through its own trait, over the crate's shared test scaffold ----

#[path = "../../tests/common/mod.rs"]
mod common;

use busbar_contract::plane::Progress;
use busbar_contract::wire::FrameCursor;

use crate::DecisionProvider;

/// Decode one provider answer through `decode_response` and meter it — the plane's whole metering
/// surface for one `systemone` exchange, as the kernel would drive it.
fn metered(plane: DecisionPlane, body: &[u8]) -> Vec<UsageLocator> {
    let scaffold = common::Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = common::TestSeal;
    let unit = Unit::new(
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
    let frames = vec![common::response_frame(body)];
    let mut cursor = FrameCursor::new(&frames);
    let Progress::Terminal { r, .. } = plane
        .decode_response(&mut cursor, &common::sealed_destination(), None, &ctx)
        .expect("a whole answer decodes")
    else {
        panic!("a whole answer decodes as terminal");
    };
    for (key, value) in r.facts.iter() {
        if key == f::FACT_USAGE_UNITS {
            assert!(
                matches!(value, FactValue::Int(n) if n >= 0),
                "the usage fact is a whole, non-negative count or absent, never {value:?}"
            );
        }
    }
    plane.meter(&unit, &r, &ctx).lines.as_slice().to_vec()
}

/// Item 395 (LEDGER). A success whose `/usage/units` member is PRESENT but is not a whole count the
/// plane can carry is a reported measurement, not an absent one. Before: no locator at all — the
/// same record as a provider that reported nothing. After: one location-only locator naming where
/// the figure is, so the kernel's decimal reader reads it exactly (#81) or refuses it (#42).
#[test]
fn a_success_whose_usage_member_is_not_a_whole_count_is_located_never_dropped() {
    for body in [
        br#"{"usage":{"units":7.5}}"#.as_slice(),
        br#"{"usage":{"units":-3}}"#.as_slice(),
        br#"{"usage":{"units":"7"}}"#.as_slice(),
        br#"{"usage":{"units":null}}"#.as_slice(),
        br#"{"usage":{"units":18446744073709551615}}"#.as_slice(),
    ] {
        let lines = metered(DecisionPlane::EMPTY, body);
        assert_eq!(
            lines,
            vec![UsageLocator {
                class: CLASS_DECISION,
                location: Some(Location::Arrival(ArrivalLocation::FirstFrameJsonPointer(
                    PTR_USAGE_UNITS
                ))),
                quantity: None,
                lane: None,
            }],
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

/// A whole count is carried exactly as before: the value in hand, no location.
#[test]
fn a_success_with_a_whole_count_carries_it() {
    let lines = metered(DecisionPlane::EMPTY, br#"{"usage":{"units":42}}"#);
    assert_eq!(
        lines,
        vec![UsageLocator {
            class: CLASS_DECISION,
            location: None,
            quantity: Some(42),
            lane: None,
        }]
    );
}

/// A success that reported no usage member at all posts no line: that is the settlement table's
/// "destination reported no usage" row (nothing billed, flagged disputed where a card prices the
/// class), and a locator pointing at a member that is not there would be a fabricated location.
/// An error answer posts nothing whatever its usage member says (billable-success, C-3).
#[test]
fn no_usage_member_and_an_error_answer_both_post_no_line() {
    assert!(metered(DecisionPlane::EMPTY, br#"{"request_id":"r1"}"#).is_empty());
    assert!(metered(
        DecisionPlane::EMPTY,
        br#"{"error":{"code":"x"},"usage":{"units":7.5}}"#
    )
    .is_empty());
}

static ONE: &[DecisionProvider] = &[DecisionProvider {
    id: "typesafe-prod",
    lane: busbar_contract::ids::LaneId::new("prod"),
    host: "api.typesafe.ai",
    transport: "http",
}];

static TWO: &[DecisionProvider] = &[
    DecisionProvider {
        id: "typesafe-prod",
        lane: busbar_contract::ids::LaneId::new("prod"),
        host: "api.typesafe.ai",
        transport: "http",
    },
    DecisionProvider {
        id: "typesafe-backup",
        lane: busbar_contract::ids::LaneId::new("backup"),
        host: "backup.typesafe.ai",
        transport: "http",
    },
];

/// What `verify` and `approve` answer for one `systemone` unit on a plane.
fn verify_and_approve(plane: DecisionPlane) -> (DestinationFacts, Vec<ResourceLocator>) {
    let scaffold = common::Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = common::TestSeal;
    let unit = Unit::new(
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
    (
        plane.verify(&unit, &ctx),
        plane.approve(&unit, &ctx).resources.as_slice().to_vec(),
    )
}

/// Item 399. A request names no provider, so with more than one configured the plane cannot say
/// which one a caller meant. Before: it dialled, and asked scope for, whichever was declared first.
/// After: the same honest answer as a plane with none — the unreachable destination the trust unit
/// refuses, and no provider named for scope.
#[test]
fn more_than_one_provider_resolves_to_no_destination_and_names_no_provider() {
    let (dest, resources) = verify_and_approve(DecisionPlane::new(TWO));
    assert_eq!(dest, verify_and_approve(DecisionPlane::EMPTY).0);
    assert!(resources.is_empty(), "{resources:?}");
}

/// With exactly one provider, it is the one dialled and the one scope is asked for.
#[test]
fn exactly_one_provider_is_the_one_dialled_and_judged() {
    let (dest, resources) = verify_and_approve(DecisionPlane::new(ONE));
    assert_eq!(
        dest,
        DestinationFacts::Upstream {
            transport: "http",
            address: busbar_contract::UpstreamAddress::socket("api.typesafe.ai"),
            lane: busbar_contract::ids::LaneId::new("prod"),
        }
    );
    assert_eq!(
        resources,
        vec![ResourceLocator {
            kind: "decision_provider",
            name: "typesafe-prod",
        }]
    );
}

/// The draft facts `decode_ingress` writes for a `GET /v1/models` on a plane.
fn ingress_provider_fact(plane: DecisionPlane) -> Option<String> {
    let scaffold = common::Scaffold::new("http")
        .with_method("GET")
        .on_path(ops::PATH_MODELS);
    let ctx = scaffold.ctx();
    let frames: Vec<busbar_contract::wire::Frame> = Vec::new();
    let mut cursor = FrameCursor::new(&frames);
    let Ok(Ingress::OneShot(draft)) = plane.decode_ingress(&mut cursor, None, &ctx) else {
        panic!("a models request is complete on arrival");
    };
    match draft.facts.get(f::FACT_PROVIDER) {
        Some(FactValue::Str(id)) => Some(id.to_string()),
        None => None,
        Some(other) => panic!("the provider fact is a name, never {other:?}"),
    }
}

/// Item 397. The provider a unit is dialled against is the session-scoped fact the declaration
/// says it is: declared in `SESSION_FACTS`, and written on every draft with the provider's id.
#[test]
fn the_provider_is_the_declared_and_written_session_fact() {
    assert_eq!(f::SESSION_FACTS, &[f::FACT_PROVIDER]);
    assert_eq!(
        ingress_provider_fact(DecisionPlane::new(ONE)).as_deref(),
        Some("typesafe-prod")
    );
    assert_eq!(ingress_provider_fact(DecisionPlane::new(TWO)), None);
    assert_eq!(ingress_provider_fact(DecisionPlane::EMPTY), None);
}
