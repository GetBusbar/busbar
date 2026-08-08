// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CORRELATION, FED HOSTILE INPUT.
//!
//! The pending table answers one question: which request does this reply answer? Every wrong answer
//! it can give is a security bug rather than a bug: a reply matched to the wrong request delivers
//! one caller's tool output to another caller, and a reply matched to a request that no longer
//! exists is how a slow peer's late answer overwrites a fresh one.
//!
//! Time is passed in rather than read, so nothing here sleeps and nothing here is flaky.

use super::super::correlator::{CorrelationError, Correlator};
use super::super::jsonrpc::{Id, Response, RpcError};
use serde_json::json;

fn correlator() -> Correlator {
    Correlator::new(8, 1_000)
}

#[test]
fn a_reply_resolves_the_request_it_answers_and_names_its_method() {
    let mut c = correlator();
    let req = c.issue("tools/list", None, 0).expect("issued");
    let answered = c
        .resolve(Response::ok(req.id.clone(), json!({"tools": []})))
        .expect("resolves");
    assert_eq!(answered.id, req.id);
    assert_eq!(answered.method, "tools/list");
    assert_eq!(answered.outcome.as_ref().ok(), Some(&json!({"tools": []})));
    assert_eq!(c.in_flight(), 0, "a resolved request leaves the table");
}

#[test]
fn an_error_reply_correlates_exactly_like_a_result_reply() {
    // Correlation is about WHICH request, never about whether it succeeded. Letting the outcome
    // affect the lookup would leave failed requests in the table forever.
    let mut c = correlator();
    let req = c.issue("tools/call", None, 0).expect("issued");
    let answered = c
        .resolve(Response::failed(req.id, RpcError::invalid_params("bad")))
        .expect("resolves");
    assert_eq!(answered.method, "tools/call");
    assert!(answered.outcome.is_err());
    assert_eq!(c.in_flight(), 0);
}

#[test]
fn a_reply_to_an_id_we_never_issued_answers_nothing() {
    let mut c = correlator();
    let e = c
        .resolve(Response::ok(Id::Number(424_242), json!({})))
        .expect_err("answers nothing");
    assert_eq!(e, CorrelationError::UnknownId(Id::Number(424_242)));
}

#[test]
fn a_duplicated_reply_resolves_once_and_the_copy_answers_nothing() {
    // A peer that answers twice is either buggy or trying to have the second answer overwrite the
    // first after we acted on it. The table is the arbiter: an id is spent when it is used.
    let mut c = correlator();
    let req = c.issue("tools/list", None, 0).expect("issued");
    assert!(c
        .resolve(Response::ok(req.id.clone(), json!({"n": 1})))
        .is_ok());
    let e = c
        .resolve(Response::ok(req.id.clone(), json!({"n": 2})))
        .expect_err("the copy answers nothing");
    assert_eq!(e, CorrelationError::UnknownId(req.id));
}

#[test]
fn a_string_id_never_answers_a_request_we_issued_as_a_number() {
    // Type confusion at the correlation boundary. Our ids are integers, so a peer replying with the
    // string spelling of one is not answering it, and coercing would let a peer choose to answer a
    // request it was never given.
    let mut c = correlator();
    let req = c.issue("ping", None, 0).expect("issued");
    let digits = match &req.id {
        Id::Number(n) => n.to_string(),
        Id::Text(_) => unreachable!("we issue numeric ids"),
    };
    let e = c
        .resolve(Response::ok(Id::Text(digits.clone()), json!({})))
        .expect_err("does not answer");
    assert_eq!(e, CorrelationError::UnknownId(Id::Text(digits)));
    assert_eq!(c.in_flight(), 1, "the real request is still waiting");
}

#[test]
fn an_id_that_never_arrives_is_reported_once_with_its_method_and_then_forgotten() {
    let mut c = correlator();
    let a = c.issue("tools/list", None, 0).expect("issued");
    let b = c.issue("tools/call", None, 500).expect("issued");

    // At 1_000 only `a` is past its deadline: expiry is per request, not a sweep of the table.
    let expired = c.expire(1_000);
    assert_eq!(expired.len(), 1, "got {expired:?}");
    assert_eq!(expired[0].id, a.id);
    assert_eq!(expired[0].method, "tools/list");
    assert_eq!(c.in_flight(), 1);

    assert!(c.expire(1_000).is_empty(), "an expiry is reported once");

    let expired = c.expire(1_500);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].id, b.id);
    assert_eq!(c.in_flight(), 0);
}

#[test]
fn a_reply_that_arrives_after_its_expiry_answers_nothing_and_cannot_hit_a_later_request() {
    // THE ID-REUSE TRAP, and the reason ids are drawn from a counter that only ever goes up. If an
    // expired id could be handed out again, a peer's late answer to the FIRST request would be
    // delivered as the answer to the SECOND, which is a cross-request delivery on the tool path.
    let mut c = correlator();
    let first = c.issue("tools/call", None, 0).expect("issued");
    assert_eq!(c.expire(2_000).len(), 1);

    let second = c.issue("tools/call", None, 2_000).expect("issued");
    assert_ne!(
        second.id, first.id,
        "an expired id is never handed out again"
    );

    let e = c
        .resolve(Response::ok(first.id.clone(), json!({"stale": true})))
        .expect_err("the late answer answers nothing");
    assert_eq!(e, CorrelationError::UnknownId(first.id));
    assert_eq!(c.in_flight(), 1, "the live request is untouched");
}

#[test]
fn cancelling_a_request_makes_its_eventual_reply_answer_nothing() {
    let mut c = correlator();
    let req = c.issue("tools/call", None, 0).expect("issued");
    assert_eq!(c.cancel(&req.id).as_deref(), Some("tools/call"));
    assert_eq!(c.in_flight(), 0);
    assert!(
        c.cancel(&req.id).is_none(),
        "cancelling twice is idempotent"
    );
    assert!(c.resolve(Response::ok(req.id, json!({}))).is_err());
}

#[test]
fn the_pending_table_is_bounded_so_a_hung_peer_cannot_grow_it_without_end() {
    // Every unanswered request holds a table entry. A peer that accepts requests and never replies
    // is a memory leak with a cap on it, or without one is a memory leak.
    let mut c = Correlator::new(3, 1_000);
    for _ in 0..3 {
        c.issue("tools/call", None, 0).expect("issued");
    }
    let e = c.issue("tools/call", None, 0).expect_err("refused");
    assert_eq!(e, CorrelationError::TooManyInFlight { limit: 3 });
    assert_eq!(c.in_flight(), 3);

    // Expiry frees the slots, so the cap throttles rather than wedges.
    assert_eq!(c.expire(2_000).len(), 3);
    assert!(c.issue("tools/call", None, 2_000).is_ok());
}

#[test]
fn issued_ids_are_numeric_and_strictly_increasing() {
    let mut c = Correlator::new(64, 1_000);
    let mut last = None;
    for _ in 0..16 {
        let req = c.issue("ping", None, 0).expect("issued");
        match (&req.id, &last) {
            (Id::Number(n), Some(prev)) => assert!(n > prev, "{n} followed {prev}"),
            (Id::Number(n), None) => last = Some(*n),
            (Id::Text(_), _) => panic!("we issue numeric ids"),
        }
        if let Id::Number(n) = req.id {
            last = Some(n);
        }
    }
}

#[test]
fn an_issued_request_is_a_well_formed_frame_carrying_the_params_it_was_given() {
    let mut c = correlator();
    let req = c
        .issue("tools/call", Some(json!({"name": "read_file"})), 0)
        .expect("issued");
    assert_eq!(req.method, "tools/call");
    assert_eq!(req.params, Some(json!({"name": "read_file"})));
    let text = String::from_utf8(req.to_frame()).expect("utf8");
    assert!(text.contains(r#""jsonrpc":"2.0""#));
}
