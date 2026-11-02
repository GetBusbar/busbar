// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The envelope reader, at the unit. The socket-level batteries of each protocol that reads an

use super::*;

fn read_ok(v: serde_json::Value) -> Envelope {
    read(&v).unwrap_or_else(|e| panic!("expected a valid envelope, got {e:?}"))
}

fn read_err(v: serde_json::Value) -> Invalid {
    read(&v).expect_err("expected a refusal")
}

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
    let e = read_err(serde_json::json!({ "method": "m" }));
    assert_eq!(e.code, INVALID_REQUEST);
    assert_eq!(e.id, serde_json::Value::Null);
}

#[test]
fn the_error_envelope_always_carries_an_id_member_even_when_it_is_null() {
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

#[test]
fn a_response_that_does_not_name_the_request_that_was_sent_is_not_that_requests_answer() {
    for body in [
        serde_json::json!({ "jsonrpc": "2.0", "id": 2, "result": { "leaked": true } }),
        serde_json::json!({ "jsonrpc": "2.0", "id": "1", "result": {} }),
        serde_json::json!({ "jsonrpc": "2.0", "id": null, "result": {} }),
        serde_json::json!({ "jsonrpc": "2.0", "result": {} }),
        serde_json::json!({ "jsonrpc": "2.0", "id": true, "result": {} }),
        serde_json::json!({ "jsonrpc": "2.0", "id": [1], "result": {} }),
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

/// Correlation must not round either request's integer ID through a floating-point value.
#[test]
fn distinct_large_numeric_ids_do_not_correlate_in_either_direction() {
    for (left, right) in [
        ("9007199254740992", "9007199254740993"),
        ("-9007199254740992", "-9007199254740993"),
        ("9223372036854775806", "9223372036854775807"),
        ("18446744073709551614", "18446744073709551615"),
        ("9007199254740993", "9007199254740992.0"),
        ("-9007199254740993", "-9007199254740992.0"),
        ("9223372036854775807", "9223372036854775808.0"),
        ("18446744073709551615", "18446744073709551616.0"),
        ("1", "1.5"),
    ] {
        for (request, response) in [(left, right), (right, left)] {
            let request_id: Value = serde_json::from_str(request).unwrap();
            let response_id: Value = serde_json::from_str(response).unwrap();
            for payload in [
                serde_json::json!({ "result": { "other_request": true } }),
                serde_json::json!({ "error": { "code": -1, "message": "other request" } }),
            ] {
                let mut body = payload;
                body["jsonrpc"] = serde_json::json!("2.0");
                body["id"] = response_id.clone();
                assert_eq!(
                    read_response(&body, &request_id).unwrap_err().kind,
                    NotAnAnswerKind::Uncorrelated,
                    "request {request}, response {response}"
                );
            }
        }
    }
}

/// Large integers remain valid IDs; exact mixed numeric representations still name one request.
#[test]
fn exact_numeric_ids_correlate_without_restricting_the_integer_range() {
    for (left, right) in [
        ("9007199254740993", "9007199254740993"),
        ("9223372036854775807", "9223372036854775807"),
        ("18446744073709551615", "18446744073709551615"),
        ("1", "1.0"),
        ("0", "-0.0"),
        ("-1", "-1.0"),
        ("9007199254740992", "9007199254740992.0"),
        ("-9223372036854775808", "-9223372036854775808.0"),
        ("9223372036854775808", "9223372036854775808.0"),
        ("1.5", "1.50"),
    ] {
        for (request, response) in [(left, right), (right, left)] {
            let request_id: Value = serde_json::from_str(request).unwrap();
            let response_id: Value = serde_json::from_str(response).unwrap();
            let body = serde_json::json!({
                "jsonrpc": "2.0", "id": response_id, "result": { "matched": true }
            });
            assert_eq!(
                read_response(&body, &request_id).unwrap(),
                Reply::Result(serde_json::json!({ "matched": true })),
                "request {request}, response {response}"
            );
        }
    }
}

/// A correlated body still has to BE a response. These are the arms that say "the peer is broken"

#[test]
fn a_correlated_body_that_is_not_a_response_is_refused_as_a_shape_and_not_as_a_correlation() {
    for body in [
        serde_json::json!({ "id": 1, "result": {} }),
        serde_json::json!({ "jsonrpc": "1.0", "id": 1, "result": {} }),
        serde_json::json!({ "jsonrpc": 2.0, "id": 1, "result": {} }),
        serde_json::json!({ "jsonrpc": "2.0", "id": 1 }),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "ok": true },
            "error": { "code": -1, "message": "actually it failed" }
        }),
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

/// A KERNEL REFUSAL WITH NO UNIT, IN THE JSON-RPC WIRE: the bytes v1.5.5 answered when a request was

#[test]
fn a_unitless_kernel_refusal_renders_the_v1_5_5_bytes() {
    use crate::abi::plane::RefusalCode;
    assert_eq!(
        unitless_kernel_body(RefusalCode::Unauthenticated.code()),
        Some(&br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"authentication failed"}}"#[..])
    );
    assert_eq!(
        unitless_kernel_body(RefusalCode::BodyTooLarge.code()),
        Some(
            &br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"request body exceeds the maximum allowed size"}}"#[..]
        )
    );
    for code in RefusalCode::ALL {
        if !matches!(
            code,
            RefusalCode::Unauthenticated | RefusalCode::BodyTooLarge
        ) {
            assert_eq!(unitless_kernel_body(code.code()), None, "{code:?}");
        }
    }

    for (code, message) in [
        (RefusalCode::Unauthenticated, "authentication failed"),
        (
            RefusalCode::BodyTooLarge,
            "request body exceeds the maximum allowed size",
        ),
    ] {
        let body = unitless_kernel_body(code.code()).expect("a body");
        let parsed: serde_json::Value = serde_json::from_slice(body).expect("JSON");
        assert_eq!(
            parsed,
            error_body(serde_json::Value::Null, INVALID_REQUEST, message, None)
        );
    }
}

use serde_json::json;

fn bytes(v: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("JSON")
}

#[test]
fn a_result_is_the_bytes_the_planes_json_sites_write() {
    let result = json!({
        "resultType": "input_required",
        "inputRequests": { "s": { "method": "sampling/createMessage", "params": { "x": [1, 2] } } },
        "requestState": "ours",
    });

    for (id, result) in [
        (json!(7), result),
        (
            json!(4),
            json!({ "resultType": "task", "status": "working", "content": [] }),
        ),
        (
            json!("busbar-ask-3"),
            json!({ "taskId": "far", "kind": "status-update" }),
        ),
        (json!(1), json!({})),
        (json!(0), serde_json::Value::Null),
    ] {
        let want = bytes(&json!({ "jsonrpc": "2.0", "id": id, "result": result }));
        assert_eq!(
            result_bytes(&bytes(&id), &bytes(&result)),
            want,
            "{}",
            String::from_utf8_lossy(&want)
        );
    }
    assert_eq!(
        result_bytes(b"1", b"{}"),
        br#"{"id":1,"jsonrpc":"2.0","result":{}}"#.to_vec()
    );
}

#[test]
fn a_result_carries_the_far_ends_bytes_verbatim() {
    let far = br#"{"z":1,"a":123456789012345678901234567890,"big":1e400}"#;
    assert_eq!(
        result_bytes(b"7", far),
        br#"{"id":7,"jsonrpc":"2.0","result":{"z":1,"a":123456789012345678901234567890,"big":1e400}}"#
            .to_vec()
    );
}

#[test]
fn an_error_is_the_bytes_the_planes_json_sites_write() {
    let info = json!([{
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "domain": "a2a-protocol.org",
        "reason": "TASK_NOT_FOUND",
    }]);
    for (id, code, message, data) in [
        (json!(11), -32603, "grpc-status 13", None),
        (json!(1), -32601, "no such method", None),
        (json!("r-1"), -32001, "no task {x}%", Some(info)),
        (
            serde_json::Value::Null,
            INVALID_REQUEST,
            "authentication failed",
            None,
        ),
        (
            json!(2),
            -32000,
            "a \"quoted\"\\ line\n\t\u{1}\u{7f} é /",
            None,
        ),
    ] {
        let mut error = json!({ "code": code, "message": message });
        if let Some(d) = &data {
            error["data"] = d.clone();
        }
        let want = bytes(&json!({ "jsonrpc": "2.0", "id": id, "error": error }));
        let data = data.as_ref().map(bytes);
        assert_eq!(
            error_bytes(&bytes(&id), code, message, data.as_deref()),
            want,
            "{}",
            String::from_utf8_lossy(&want)
        );

        assert_eq!(
            want,
            bytes(&error_body(
                id,
                code,
                message,
                data.map(|d| { serde_json::from_slice(&d).expect("JSON") })
            ))
        );
    }

    let written = error_bytes(b"null", INVALID_REQUEST, "authentication failed", None);
    let pinned: serde_json::Value = serde_json::from_slice(UNITLESS_UNAUTHENTICATED).expect("JSON");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&written).expect("JSON"),
        pinned
    );
}

#[test]
fn a_request_is_the_bytes_the_planes_json_sites_write() {
    let meta = json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        },
    });
    let init = json!({
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": { "name": "busbar", "version": "1.6.0" },
    });
    for (id, method, params) in [
        (json!(1), "tools/list", Some(meta)),
        (
            json!(0),
            "tools/call",
            Some(json!({ "name": "fs_read", "arguments": { "path": "/a" } })),
        ),
        (json!("busbar-ask-1"), "roots/list", Some(json!({}))),
        (json!(1), "initialize", Some(init)),
        (json!("busbar-ask-2"), "ping", None),
        (
            json!("busbar-rest"),
            "GetExtendedAgentCard",
            Some(json!({})),
        ),
    ] {
        let want = match &params {
            Some(p) => bytes(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": p })),
            None => bytes(&json!({ "jsonrpc": "2.0", "id": id, "method": method })),
        };
        let params = params.as_ref().map(bytes);
        assert_eq!(
            request_bytes(&bytes(&id), method, params.as_deref()),
            want,
            "{}",
            String::from_utf8_lossy(&want)
        );
    }
    assert_eq!(
        request_bytes(b"2", "tools/list", None),
        br#"{"id":2,"jsonrpc":"2.0","method":"tools/list"}"#.to_vec()
    );
}

#[test]
fn a_notification_is_the_bytes_the_planes_json_sites_write() {
    for (method, params) in [
        (
            "notifications/resources/updated",
            Some(json!({ "uri": "file:///readme" })),
        ),
        (
            "notifications/message",
            Some(json!({
                "level": "info",
                "logger": "busbar.mcp.dispatch",
                "data": { "message": "MCP method completed", "httpStatus": 200, "method": "tools/call" },
            })),
        ),
        ("notifications/initialized", None),
    ] {
        let want = match &params {
            Some(p) => bytes(&json!({ "jsonrpc": "2.0", "method": method, "params": p })),
            None => bytes(&json!({ "jsonrpc": "2.0", "method": method })),
        };
        let params = params.as_ref().map(bytes);
        assert_eq!(
            notification_bytes(method, params.as_deref()),
            want,
            "{}",
            String::from_utf8_lossy(&want)
        );
    }
    assert_eq!(
        notification_bytes("notifications/initialized", None),
        br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_vec()
    );
}
