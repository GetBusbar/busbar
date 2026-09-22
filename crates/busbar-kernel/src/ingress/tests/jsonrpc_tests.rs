// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The envelope reader, at the unit. The two socket-level batteries
//! (`mcp/tests/envelope_id_tests.rs`, `a2a/tests/envelope_id_tests.rs`) prove each plane really
//! routes through this; these prove what it decides.

use super::*;

fn read_ok(v: serde_json::Value) -> Envelope {
    read(&v).unwrap_or_else(|e| panic!("expected a valid envelope, got {e:?}"))
}

fn read_err(v: serde_json::Value) -> Invalid {
    read(&v).expect_err("expected a refusal")
}

// ══ THE THREE CASES THAT ARE ROUTINELY CONFLATED ═════════════════════════════════════════════════

#[test]
fn an_absent_id_is_a_notification() {
    assert_eq!(
        read_ok(serde_json::json!({ "jsonrpc": "2.0", "method": "m" })),
        Envelope::Notification {
            method: "m".to_string()
        }
    );
}

#[test]
fn a_null_id_is_not_a_notification_it_is_an_invalid_request() {
    // THE DISTINCTION THIS WHOLE MODULE TURNS ON. `{"id": null}` and `{}` are two different
    // messages: one is a badly formed request, the other is a notification. An implementation that
    // reaches for `unwrap_or(Null)`, or that tests `id.is_null()` to mean "absent", has already
    // merged them and cannot tell these two lines apart.
    let e = read_err(serde_json::json!({ "jsonrpc": "2.0", "id": null, "method": "m" }));
    assert_eq!(e.code, INVALID_REQUEST);
    assert_eq!(e.id, serde_json::Value::Null);
}

#[test]
fn a_string_or_number_id_is_a_request_and_the_value_survives_exactly() {
    for id in [
        serde_json::json!("req-1"),
        serde_json::json!(1),
        serde_json::json!(0),
        serde_json::json!(-7),
        // The empty string is a legal id and is NOT absent. A reader that treats falsy as missing
        // turns this request into a notification and never answers it.
        serde_json::json!(""),
    ] {
        assert_eq!(
            read_ok(serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": "m" })),
            Envelope::Request {
                id: id.clone(),
                method: "m".to_string()
            },
            "id {id} did not survive"
        );
    }
    // A string id and the numeric id that stringifies to it stay DISTINCT values, so a dispatcher
    // keyed on them cannot cross-deliver.
    let s = read_ok(serde_json::json!({ "jsonrpc": "2.0", "id": "1", "method": "m" }));
    let n = read_ok(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "m" }));
    assert_ne!(s, n);
}

#[test]
fn an_id_that_is_neither_string_nor_number_nor_null_is_refused() {
    for id in [
        serde_json::json!(true),
        serde_json::json!([1]),
        serde_json::json!({ "a": 1 }),
    ] {
        let e = read_err(serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": "m" }));
        assert_eq!(e.code, INVALID_REQUEST, "id {id} was accepted");
        assert_eq!(e.id, serde_json::Value::Null);
    }
}

// ══ THE ENVELOPE ITSELF ══════════════════════════════════════════════════════════════════════════

#[test]
fn the_jsonrpc_member_is_required_and_must_be_exactly_2_0() {
    for envelope in [
        serde_json::json!({ "id": 1, "method": "m" }),
        serde_json::json!({ "jsonrpc": "1.0", "id": 1, "method": "m" }),
        serde_json::json!({ "jsonrpc": 2.0, "id": 1, "method": "m" }),
        serde_json::json!({ "jsonrpc": "2.0.0", "id": 1, "method": "m" }),
    ] {
        let e = read_err(envelope.clone());
        assert_eq!(e.code, INVALID_REQUEST, "{envelope} was accepted");
        // section 5's other half: the id WAS legible, so it is echoed rather than nulled.
        assert_eq!(e.id, serde_json::json!(1), "{envelope}");
    }
}

#[test]
fn the_method_member_is_required_and_must_be_a_string() {
    for envelope in [
        serde_json::json!({ "jsonrpc": "2.0", "id": 1 }),
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": 7 }),
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": null }),
    ] {
        assert_eq!(
            read_err(envelope.clone()).code,
            INVALID_REQUEST,
            "{envelope}"
        );
    }
}

#[test]
fn a_batch_array_and_a_scalar_are_both_refused_as_not_a_message_object() {
    for body in [
        serde_json::json!([{ "jsonrpc": "2.0", "id": 1, "method": "m" }]),
        serde_json::json!("a string"),
        serde_json::json!(null),
    ] {
        let e = read_err(body.clone());
        assert_eq!(e.code, INVALID_REQUEST, "{body}");
        assert_eq!(e.id, serde_json::Value::Null, "{body}");
    }
}

#[test]
fn an_envelope_defect_is_judged_before_the_id_so_a_notification_shaped_one_is_still_answered() {
    // The ORDER claim, asserted rather than described. A body with no `id` AND no `jsonrpc` is not
    // silently swallowed as a notification: it is not a JSON-RPC message, so section 5's "error in
    // detecting the id" applies and it is refused with a null id.
    let e = read_err(serde_json::json!({ "method": "m" }));
    assert_eq!(e.code, INVALID_REQUEST);
    assert_eq!(e.id, serde_json::Value::Null);
}

// ══ THE RESPONSE SHAPES ══════════════════════════════════════════════════════════════════════════

#[test]
fn the_error_envelope_always_carries_an_id_member_even_when_it_is_null() {
    // section 5: "This member is REQUIRED." An error response with the member OMITTED is what busbar's MCP
    // ingress used to emit for a request whose id it could not read, and the in-house battery's own
    // `isResponse()` predicate (`'id' in msg`) would not have classified it as a response at all.
    let body = error_body(serde_json::Value::Null, INVALID_REQUEST, "no", None);
    assert!(
        body.as_object().expect("object").contains_key("id"),
        "the `id` member was omitted: {body}"
    );
    assert_eq!(body["id"], serde_json::Value::Null);
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["error"]["code"], INVALID_REQUEST);
    assert!(body["error"].get("data").is_none(), "no data, no member");
}

#[test]
fn a_refusal_is_a_400_and_a_notification_ack_is_a_202_with_no_body() {
    assert_eq!(
        refused(&Invalid {
            code: INVALID_REQUEST,
            message: "no",
            id: serde_json::Value::Null,
        })
        .status(),
        axum::http::StatusCode::BAD_REQUEST
    );
    assert_eq!(parse_error().status(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(accepted().status(), axum::http::StatusCode::ACCEPTED);
}

// ══ THE RESPONSE READER ══════════════════════════════════════════════════════════════════════════
//
// The other direction of travel. These prove what `read_response` DECIDES; the socket-level proof
// that each plane really routes through it is in `mcp/client/tests/transport_tests.rs` and
// `a2a/tests/response_id_tests.rs`, both of which read the bytes off a wire rather than call this.

fn sent(id: serde_json::Value) -> serde_json::Value {
    id
}

fn reply_ok(body: serde_json::Value, sent_id: serde_json::Value) -> Reply {
    read_response(&body, &sent_id)
        .unwrap_or_else(|e| panic!("expected a reply, got {e:?} for {body}"))
}

fn reply_err(body: serde_json::Value, sent_id: serde_json::Value) -> NotAnAnswer {
    read_response(&body, &sent_id).expect_err("expected a refusal")
}

/// THE DEFECT, AT THE UNIT. Every one of these was accepted as the answer to request `1` before the
/// correlation existed: the reader never looked at `id`, so "which request is this?" had no answer
/// and every body that parsed was treated as the answer to the one in flight.
#[test]
fn a_response_that_does_not_name_the_request_that_was_sent_is_not_that_requests_answer() {
    for body in [
        // A DIFFERENT request's answer. The case that serves caller A with upstream B's reply.
        serde_json::json!({ "jsonrpc": "2.0", "id": 2, "result": { "leaked": true } }),
        serde_json::json!({ "jsonrpc": "2.0", "id": "1", "result": {} }),
        // section 5 spends `null` on "I could not tell which request this was".
        serde_json::json!({ "jsonrpc": "2.0", "id": null, "result": {} }),
        // No `id` member at all — REQUIRED on a Response, and the shape a notification has.
        serde_json::json!({ "jsonrpc": "2.0", "result": {} }),
        // Not an id at all.
        serde_json::json!({ "jsonrpc": "2.0", "id": true, "result": {} }),
        serde_json::json!({ "jsonrpc": "2.0", "id": [1], "result": {} }),
        // An ERROR for another request is equally not this request's answer.
        serde_json::json!({ "jsonrpc": "2.0", "id": 2, "error": { "code": -1, "message": "no" } }),
    ] {
        let e = reply_err(body.clone(), sent(serde_json::json!(1)));
        assert_eq!(
            e.kind,
            NotAnAnswerKind::Uncorrelated,
            "{body} was accepted as the answer to `id` 1 (or refused for the wrong reason): {e:?}"
        );
    }
}

/// The control the case above is worthless without: a response that DOES name the request is served,
/// and its payload comes back verbatim.
#[test]
fn a_response_naming_the_request_that_was_sent_is_read_and_its_payload_survives() {
    assert_eq!(
        reply_ok(
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": { "content": [] } }),
            sent(serde_json::json!(1)),
        ),
        Reply::Result(serde_json::json!({ "content": [] }))
    );
    assert_eq!(
        reply_ok(
            serde_json::json!({ "jsonrpc": "2.0", "id": "req-a", "result": null }),
            sent(serde_json::json!("req-a")),
        ),
        // `"result": null` is a LEGAL result. It is the MEMBER's presence that decides, and a reader
        // that tested truthiness would report this as "neither result nor error".
        Reply::Result(serde_json::Value::Null)
    );
}

/// A string id and the number that stringifies to it are DIFFERENT ids, in this direction too — the
/// request reader asserts the same thing, and a correlation that coerced them would let a peer
/// answer request `1` with the answer to request `"1"`.
#[test]
fn correlation_never_coerces_across_types() {
    assert_eq!(
        reply_err(
            serde_json::json!({ "jsonrpc": "2.0", "id": "1", "result": {} }),
            sent(serde_json::json!(1)),
        )
        .kind,
        NotAnAnswerKind::Uncorrelated
    );
    assert_eq!(
        reply_err(
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {} }),
            sent(serde_json::json!("1")),
        )
        .kind,
        NotAnAnswerKind::Uncorrelated
    );
}

/// The ONE deliberate looseness, and its bound. JSON has a single number type, so `1` and `1.0` are
/// the same value and a peer that echoes one for the other has correlated correctly. Refusing a
/// correct answer is as much a correlation failure as accepting a wrong one — but the looseness is
/// numeric only, and `2.0` is still not `1`.
#[test]
fn the_same_number_written_two_ways_correlates_and_a_different_number_still_does_not() {
    assert!(read_response(
        &serde_json::json!({ "jsonrpc": "2.0", "id": 1.0, "result": {} }),
        &serde_json::json!(1),
    )
    .is_ok());
    assert_eq!(
        reply_err(
            serde_json::json!({ "jsonrpc": "2.0", "id": 2.0, "result": {} }),
            sent(serde_json::json!(1)),
        )
        .kind,
        NotAnAnswerKind::Uncorrelated
    );
}

/// A correlated body still has to BE a response. These are the arms that say "the peer is broken"
/// rather than "the peer answered somebody else", and the two are kept apart because an operator
/// acts on them differently.
#[test]
fn a_correlated_body_that_is_not_a_response_is_refused_as_a_shape_and_not_as_a_correlation() {
    for body in [
        serde_json::json!({ "id": 1, "result": {} }),
        serde_json::json!({ "jsonrpc": "1.0", "id": 1, "result": {} }),
        serde_json::json!({ "jsonrpc": 2.0, "id": 1, "result": {} }),
        // Neither member: section 5 requires exactly one.
        serde_json::json!({ "jsonrpc": "2.0", "id": 1 }),
        // BOTH members: section 5 says both MUST NOT be included, and guessing which the sender
        // meant is how a failure is served as a success.
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "ok": true },
            "error": { "code": -1, "message": "actually it failed" }
        }),
        // A batch, and a scalar.
        serde_json::json!([{ "jsonrpc": "2.0", "id": 1, "result": {} }]),
        serde_json::json!("a string"),
    ] {
        assert_eq!(
            reply_err(body.clone(), sent(serde_json::json!(1))).kind,
            NotAnAnswerKind::NotAResponse,
            "{body}"
        );
    }
}

/// `"error": null` beside a `result` is a shape real peers emit, and it means "no error". Reading it
/// as an error would turn every such peer's success into a failed hop — which is why the
/// both-present check above is written against the same non-null filter.
#[test]
fn an_explicitly_null_error_member_is_absent_rather_than_an_error() {
    assert_eq!(
        reply_ok(
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": { "ok": true }, "error": null }),
            sent(serde_json::json!(1)),
        ),
        Reply::Result(serde_json::json!({ "ok": true }))
    );
}

#[test]
fn an_error_member_is_read_with_its_code_and_message() {
    assert_eq!(
        reply_ok(
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "error": { "code": -32601, "message": "no such method" }
            }),
            sent(serde_json::json!(1)),
        ),
        Reply::Error {
            code: Some(serde_json::json!(-32601)),
            message: "no such method".to_string()
        }
    );
}
