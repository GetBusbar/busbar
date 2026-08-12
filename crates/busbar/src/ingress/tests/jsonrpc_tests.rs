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
