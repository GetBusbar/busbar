use super::*;
use crate::meta::CLASS_DECISION;

#[test]
fn systemone_arrives_as_the_first_op_class_with_a_principal() {
    let a = arrive("POST", ops::PATH_SYSTEMONE).expect("systemone is claimed");
    assert_eq!(a.op, ops::OP_SYSTEMONE);
    assert_eq!(a.op_class, 0);
    assert_eq!(tail::OP_CLASSES[a.op_class as usize], ops::OP_SYSTEMONE);
    assert_eq!(a.principal, PrincipalNeed::Required);
    assert_eq!(tail::DIALECTS[a.dialect as usize], "jev");
}

#[test]
fn models_is_not_claimed() {
    assert_eq!(arrive("GET", ops::PATH_MODELS), None);
    assert!(!tail::CLAIMS.iter().any(|(_, t)| *t == ops::PATH_MODELS));
    assert!(!tail::OP_CLASSES.contains(&ops::OP_MODELS));
}

#[test]
fn an_unknown_request_is_not_claimed() {
    assert_eq!(arrive("GET", ops::PATH_SYSTEMONE), None);
    assert_eq!(arrive("POST", "/v1/elsewhere"), None);
}

#[test]
fn every_claim_arrives() {
    for (verb, target) in tail::CLAIMS {
        assert!(arrive(verb, target).is_some(), "{verb} {target}");
    }
}

#[test]
fn the_tail_names_the_decision_class_at_its_index() {
    let (class, family) = tail::BILLABLE_CLASSES[tail::CLASS_DECISION_INDEX as usize];
    assert_eq!(class, CLASS_DECISION);
    assert_eq!(family, "decision");
    assert!(tail::FEE_UNITS.is_empty());
    assert_eq!(tail::SECTION_DECLARING, crate::config::SECTION);
    assert_eq!(
        tail::NEEDS,
        &[(crate::claims::TRANSPORT, "decision-egress")]
    );
}

#[test]
fn the_caller_body_is_kept_and_an_empty_one_is_refused() {
    assert_eq!(caller_piece(b"{\"state\":{}}", true), CallerAnswer::Keep);
    assert_eq!(caller_piece(b"", false), CallerAnswer::Keep);
    assert_eq!(caller_piece(b"", true), CallerAnswer::Empty);
}

#[test]
fn an_attempt_forwards_the_caller_body_unchanged() {
    let body = br#"{"state":{"session":"s"},"context":{}}"#;
    let r = attempt(body);
    assert_eq!(r.verb, "POST");
    assert_eq!(r.target, "/v1/systemone");
    assert_eq!(r.fields, [("content-type", &b"application/json"[..])]);
    assert_eq!(r.auth, "decision-egress");
    assert!(
        std::ptr::eq(r.body, &body[..]),
        "the body is borrowed, not copied"
    );
}

#[test]
fn far_end_pieces_are_relayed_unchanged_and_the_count_read_over_the_whole_answer() {
    let mut reading = FarEndReading::new();
    let a = br#"{"request_id":"req_1","usage":{"un"#;
    let b = br#"its":42},"answers":{"decision":"approve"}}"#;
    assert_eq!(reading.piece(a), &a[..]);
    assert_eq!(reading.piece(b), &b[..]);
    assert_eq!(
        reading.units(),
        Some(Units {
            class: 0,
            reported: true,
            amount: 42
        })
    );
}

#[test]
fn an_error_answer_reports_no_units() {
    let mut reading = FarEndReading::new();
    reading.piece(br#"{"error":{"code":"invalid_state"},"usage":{"units":3}}"#);
    assert_eq!(reading.units(), None);
}

/// RED: the count is read as `decode_response` reads it. Success is the absence of an `/error`
/// member, whatever the status (a 4xx with no `/error` still reports its count, as predev's decode
/// sets the fact), and a count past `i64::MAX` reports nothing (predev's `i64::try_from` drops it).
#[test]
fn the_count_is_read_as_decode_response_reads_it() {
    let mut reading = FarEndReading::new();
    reading.piece(br#"{"usage":{"units":3}}"#);
    assert_eq!(reading.units().map(|u| u.amount), Some(3));
    for (body, amount) in [
        (
            format!(r#"{{"usage":{{"units":{}}}}}"#, i64::MAX),
            Some(i64::MAX as u64),
        ),
        (
            format!(r#"{{"usage":{{"units":{}}}}}"#, i64::MAX as u64 + 1),
            None,
        ),
        (format!(r#"{{"usage":{{"units":{}}}}}"#, u64::MAX), None),
    ] {
        let mut reading = FarEndReading::new();
        reading.piece(body.as_bytes());
        assert_eq!(reading.units().map(|u| u.amount), amount, "{body}");
    }
}

#[test]
fn a_count_that_is_not_a_whole_number_reports_no_units() {
    for body in [
        &br#"{"usage":{"units":-1}}"#[..],
        br#"{"usage":{"units":1.5}}"#,
        br#"{"usage":{}}"#,
        br#"{}"#,
    ] {
        let mut reading = FarEndReading::new();
        reading.piece(body);
        assert_eq!(reading.units(), None, "{}", String::from_utf8_lossy(body));
    }
}

#[test]
fn the_units_never_read_state_or_answers() {
    let mut reading = FarEndReading::new();
    reading.piece(br#"{"usage":{"units":7},"state":{"units":999},"answers":{"units":888}}"#);
    assert_eq!(reading.units().map(|u| u.amount), Some(7));
}

#[test]
fn a_refusal_carries_the_kernel_text_in_the_dialect_shape() {
    assert_eq!(
        refusal_body(403, "the caller may not perform this operation"),
        br#"{"error":{"code":"unsupported_operation","message":"the caller may not perform this operation"}}"#
    );
    assert_eq!(
        refusal_body(401, "no key"),
        br#"{"error":{"code":"invalid_request","message":"no key"}}"#
    );
    assert_eq!(
        refusal_body(404, "no provider"),
        br#"{"error":{"code":"invalid_params","message":"no provider"}}"#
    );
    assert_eq!(
        refusal_body(500, "x"),
        br#"{"error":{"code":"internal","message":"x"}}"#
    );
    assert_eq!(
        refusal_body(503, "x"),
        br#"{"error":{"code":"unsupported_operation","message":"x"}}"#
    );
}

#[test]
fn only_exactly_one_model_mounts_the_claim() {
    assert!(served_claims(0).is_empty());
    assert_eq!(served_claims(1), tail::CLAIMS);
    assert!(served_claims(2).is_empty());
    assert!(served_claims(7).is_empty());
}
