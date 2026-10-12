//! The jev rig's GATING CHECKS (`xtask/src/conformance_record/jev.rs`, one per Teller step H2
//! gates on the decision plane; cells `jev.rig|<check>` in `qa/teller-steps.json`): each judge is a
//! pure function over what the served leg observed, so every check is pinned here twice -- GREEN
//! over the observation a correct busbar produces, and RED over each way the step can be broken.

use serde_json::json;
use xtask::conformance_record::{
    jev_refusal_code, jev_subject_config, judge_admit, judge_audit, judge_audit_window, judge_exit,
    judge_meter, judge_refused_before_dial, judge_route, ledger_spend, Call, Spend, AUDIT_OP_CLASS,
    ELSEWHERE, H2_CHECKS, JEV_SUCCESS, ONE_REQUEST_GROUP, REPORTED_UNITS, UNAVAILABLE,
};

const AUTHORITY: &[u8] =
    br#"{"error":{"code":"invalid_request","message":"the request did not carry usable authority"}}"#;
const NOT_PERMITTED: &[u8] = br#"{"error":{"code":"unsupported_operation","message":"the caller may not perform this operation"}}"#;
const TERMINAL: &[u8] = br#"{"error":{"code":"unsupported_operation","message":"the request could not be served at this time"}}"#;

fn call(status: u16, body: &[u8], hops: usize) -> Call {
    Call {
        status,
        body: body.to_vec(),
        hops,
    }
}

fn spend(fees: u64, micros: u128) -> Spend {
    Spend { fees, micros }
}

fn served() -> Call {
    call(200, JEV_SUCCESS, 1)
}

fn records(rows: &[(&str, &str)]) -> Vec<u8> {
    json!({"records": rows.iter().enumerate().map(|(i, (op, outcome))| json!({
        "seq": i, "op_class": op, "outcome": outcome, "hash": "00",
    })).collect::<Vec<_>>()})
    .to_string()
    .into_bytes()
}

const STILL: (Spend, Spend) = (
    Spend {
        fees: 3,
        micros: 126,
    },
    Spend {
        fees: 3,
        micros: 126,
    },
);

#[test]
fn the_seven_checks_are_the_gating_steps_cells() {
    assert_eq!(
        H2_CHECKS,
        [
            "h2-authenticate-refusal",
            "h2-verify-refusal",
            "h2-admit-refusal",
            "h2-route-terminal",
            "h2-meter-row",
            "h2-audit-record",
            "h2-exit-terminal",
        ]
    );
    assert_eq!(AUDIT_OP_CLASS, "systemone");
}

/// AUTHENTICATE: a bad credential refused 401 in jev's shape, zero hops, the ledger unmoved.
#[test]
fn authenticate_green_and_its_reds() {
    let ok = call(401, AUTHORITY, 0);
    assert!(judge_refused_before_dial(&ok, 401, "invalid_request", STILL, None).is_ok());
    // RED: the forged key was served.
    assert!(judge_refused_before_dial(&served(), 401, "invalid_request", STILL, None).is_err());
    // RED: refused, but only after the far end was dialled (egress before Verify).
    let late = call(401, AUTHORITY, 1);
    assert!(
        judge_refused_before_dial(&late, 401, "invalid_request", STILL, None)
            .unwrap_err()
            .contains("before the dial")
    );
    // RED: the kernel's unclaimed-route body, not jev's.
    let foreign = call(
        401,
        br#"{"error":{"code":null,"message":"x","type":"t"}}"#,
        0,
    );
    assert!(judge_refused_before_dial(&foreign, 401, "invalid_request", STILL, None).is_err());
    // RED: something was charged for the refused unit.
    let charged = (spend(3, 126), spend(4, 126));
    assert!(judge_refused_before_dial(&ok, 401, "invalid_request", charged, None).is_err());
}

/// VERIFY: a key granted another pool only, refused 403 before Admit, nothing charged or counted.
#[test]
fn verify_green_and_its_reds() {
    let ok = call(403, NOT_PERMITTED, 0);
    let judge = |c: &Call, s, r| judge_refused_before_dial(c, 403, "unsupported_operation", s, r);
    assert!(judge(&ok, STILL, Some((0, 0))).is_ok());
    // RED: the destination the credential may not reach was served.
    assert!(judge(&served(), STILL, Some((0, 1))).is_err());
    // RED: refused at the far end's word, not before the dial.
    assert!(judge(&call(403, NOT_PERMITTED, 1), STILL, Some((0, 0))).is_err());
    // RED: Admit drew the key's bucket before the refusal.
    assert!(judge(&ok, STILL, Some((0, 1)))
        .unwrap_err()
        .contains("counts 0 request(s) before"));
    // RED: a different refusal (the 401 of a credential that never authenticated).
    assert!(judge(&call(401, AUTHORITY, 0), STILL, Some((0, 0))).is_err());
}

/// ADMIT: the one budgeted request served, the next refused 429 before the dial, uncharged.
#[test]
fn admit_green_and_its_reds() {
    let refused = call(429, TERMINAL, 0);
    assert!(judge_admit(&served(), &refused, STILL, (1, 1)).is_ok());
    // RED: the budget never admitted the first request, so the refusal proves nothing.
    assert!(judge_admit(&refused, &refused, STILL, (0, 0)).is_err());
    // RED: over budget and still served.
    assert!(judge_admit(&served(), &served(), STILL, (1, 2)).is_err());
    // RED: refused only after Route dialled.
    assert!(judge_admit(&served(), &call(429, TERMINAL, 1), STILL, (1, 1)).is_err());
    // RED: the refused unit was charged a fee.
    let charged = (spend(3, 126), spend(4, 168));
    assert!(judge_admit(&served(), &refused, charged, (1, 1)).is_err());
    // RED: the refused unit was counted against the key.
    assert!(judge_admit(&served(), &refused, STILL, (1, 2)).is_err());
}

/// ROUTE: the down lane ends in a terminal 5xx, the walk's own, after dialling, uncharged.
#[test]
fn route_green_and_its_reds() {
    assert!(judge_route(&call(503, TERMINAL, 1), UNAVAILABLE, STILL).is_ok());
    assert!(judge_route(&call(502, TERMINAL, 2), UNAVAILABLE, STILL).is_ok());
    // RED: the failure was relayed as the far end's bytes.
    assert!(judge_route(&call(503, UNAVAILABLE, 1), UNAVAILABLE, STILL)
        .unwrap_err()
        .contains("relayed"));
    // RED: no terminal: the unit answered a success or a caller fault.
    assert!(judge_route(&served(), UNAVAILABLE, STILL).is_err());
    assert!(judge_route(&call(404, TERMINAL, 1), UNAVAILABLE, STILL).is_err());
    // RED: the lane was never dialled (a terminal with no route walked).
    assert!(judge_route(&call(503, TERMINAL, 0), UNAVAILABLE, STILL).is_err());
    // RED: the failed unit was charged.
    assert!(judge_route(
        &call(503, TERMINAL, 1),
        UNAVAILABLE,
        (spend(3, 0), spend(4, 0))
    )
    .is_err());
    // RED: a terminal not in jev's shape.
    assert!(judge_route(&call(503, b"upstream down", 1), UNAVAILABLE, STILL).is_err());
}

/// METER: exactly one fee and exactly the reported units, priced, for one request.
#[test]
fn meter_green_and_its_reds() {
    let one = (spend(1, 42), spend(2, 84));
    assert!(judge_meter(&served(), one).is_ok());
    // RED: nothing posted.
    assert!(judge_meter(&served(), (spend(1, 42), spend(1, 42))).is_err());
    // RED: posted twice.
    assert!(judge_meter(&served(), (spend(1, 42), spend(3, 126))).is_err());
    // RED: the fee posted, the reported units unpriced.
    assert!(judge_meter(&served(), (spend(1, 42), spend(2, 42))).is_err());
    // RED: the request was not served as the far end answered it.
    assert!(judge_meter(&call(200, b"{}", 1), one).is_err());
    assert_eq!(REPORTED_UNITS, 42);
}

/// AUDIT: exactly one record under the plane's operation class, Completed.
#[test]
fn audit_green_and_its_reds() {
    let one = records(&[("admin.read", "Completed"), (AUDIT_OP_CLASS, "Completed")]);
    assert!(judge_audit(&served(), &one).is_ok());
    // RED: no record sealed.
    assert!(judge_audit(&served(), &records(&[("admin.read", "Completed")])).is_err());
    // RED: the unit sealed twice.
    let twice = records(&[(AUDIT_OP_CLASS, "Completed"), (AUDIT_OP_CLASS, "Completed")]);
    assert!(judge_audit(&served(), &twice).is_err());
    // RED: the record tells a served unit as refused.
    let wrong = records(&[(AUDIT_OP_CLASS, "Refused(Admit, RateLimited)")]);
    assert!(judge_audit(&served(), &wrong)
        .unwrap_err()
        .contains("not Completed"));
    // RED: an unreadable window.
    assert!(judge_audit_window(b"{}", 1).is_err());
}

/// ENCODE: two units, two terminals: no drop, no double post, no merge.
#[test]
fn exit_green_and_its_reds() {
    let two = records(&[(AUDIT_OP_CLASS, "Completed"), (AUDIT_OP_CLASS, "Completed")]);
    let moved = (spend(2, 84), spend(4, 168));
    let calls = [served(), served()];
    assert!(judge_exit(&calls, moved, &two).is_ok());
    // RED: one unit posted twice.
    assert!(judge_exit(&calls, (spend(2, 84), spend(5, 210)), &two).is_err());
    // RED: two units settled as one.
    let one = records(&[(AUDIT_OP_CLASS, "Completed")]);
    assert!(judge_exit(&calls, moved, &one).is_err());
    // RED: a unit dialled twice for one answer.
    assert!(judge_exit(&[served(), call(200, JEV_SUCCESS, 2)], moved, &two).is_err());
    // RED: an answer encoded twice.
    let doubled = [JEV_SUCCESS, JEV_SUCCESS].concat();
    assert!(judge_exit(&[served(), call(200, &doubled, 1)], moved, &two).is_err());
    // RED: fewer than two units judged.
    assert!(judge_exit(&[served()], moved, &two).is_err());
}

/// The ledger reader: the jev lane (or the caller's bucket at node width), or every row.
#[test]
fn the_ledger_sums_the_rows_asked_for() {
    let totals = json!({"rows": [
        {"bucket": "vk_me", "lane": "", "provider": "", "fee_count": 2, "priced_micros": "84"},
        {"bucket": "vk_other", "lane": "", "provider": "", "fee_count": 5, "priced_micros": "9"},
    ]})
    .to_string();
    assert_eq!(
        ledger_spend(totals.as_bytes(), Some("vk_me")).unwrap(),
        spend(2, 84)
    );
    assert_eq!(ledger_spend(totals.as_bytes(), None).unwrap(), spend(7, 93));
    assert!(ledger_spend(b"{}", None).is_err());
    assert!(ledger_spend(br#"{"rows":[{"fee_count":1,"priced_micros":"-1"}]}"#, None).is_err());
}

#[test]
fn the_refusal_reader_answers_the_code_word() {
    assert_eq!(jev_refusal_code(TERMINAL).unwrap(), "unsupported_operation");
    assert!(jev_refusal_code(br#"{"error":{"code":"","message":"m"}}"#).is_err());
    assert!(jev_refusal_code(UNAVAILABLE).is_ok());
}

/// The subject the gating checks run on declares the admit check's group (one request a day).
#[test]
fn the_subject_declares_the_one_request_group() {
    let text = jev_subject_config(41000, 41001, std::path::Path::new("/tmp/signing.key"));
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).expect("the config is YAML");
    let limit = &doc["groups"][ONE_REQUEST_GROUP]["limits"][0];
    assert_eq!(limit["requests"].as_u64(), Some(1));
    assert_eq!(limit["per"].as_str(), Some("day"));
    assert_ne!(
        ELSEWHERE, "jev-1",
        "the verify key's grant is not the decision provider"
    );
    assert_eq!(
        doc["decisions"]["rate_card"]["jev-1"]["units"]["decision"].as_u64(),
        Some(1)
    );
}
