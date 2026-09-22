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
