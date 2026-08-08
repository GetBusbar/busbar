// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PARSING SURFACE, FED HOSTILE INPUT.
//!
//! A JSON-RPC peer is not a library we call, it is a party on the other end of a socket that we do
//! not control, and on the client side it is the untrusted external upstream the whole trust
//! lifecycle exists to contain. So these tests are written the way an attacker would write them:
//! every frame here is either a real MCP message or a plausible lie about being one, and the
//! assertion is always that the lie is REFUSED by name rather than absorbed into a default.

use super::super::jsonrpc::{
    Id, Message, Notification, ProtocolError, Request, Response, RpcError, CODE_INTERNAL_ERROR,
    CODE_INVALID_PARAMS, CODE_INVALID_REQUEST, CODE_METHOD_NOT_FOUND, CODE_PARSE_ERROR,
};
use serde_json::json;

fn parse(s: &str) -> Result<Message, ProtocolError> {
    Message::parse(s.as_bytes())
}

// The three shapes, parsed correctly --------------------------------------------------------------

#[test]
fn a_request_carries_its_id_method_and_params() {
    let m = parse(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"x"}}"#)
        .expect("a well-formed request parses");
    match m {
        Message::Request(r) => {
            assert_eq!(r.id, Id::Number(1));
            assert_eq!(r.method, "tools/list");
            assert_eq!(r.params, Some(json!({"cursor": "x"})));
        }
        other => panic!("expected a request, got {other:?}"),
    }
}

#[test]
fn a_string_id_stays_a_string_id() {
    // `1` and `"1"` are DIFFERENT correlation ids. Coercing either way is how a peer gets a reply
    // matched to a request it did not send.
    let m = parse(r#"{"jsonrpc":"2.0","id":"1","method":"ping"}"#).expect("parses");
    match m {
        Message::Request(r) => assert_eq!(r.id, Id::Text("1".into())),
        other => panic!("expected a request, got {other:?}"),
    }
    assert_ne!(Id::Number(1), Id::Text("1".into()));
}

#[test]
fn a_notification_is_a_method_without_an_id() {
    let m =
        parse(r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#).expect("parses");
    match m {
        Message::Notification(n) => {
            assert_eq!(n.method, "notifications/tools/list_changed");
            assert_eq!(n.params, None);
        }
        other => panic!("expected a notification, got {other:?}"),
    }
}

#[test]
fn a_response_carries_either_a_result_or_an_error() {
    let ok = parse(r#"{"jsonrpc":"2.0","id":7,"result":{"tools":[]}}"#).expect("parses");
    match ok {
        Message::Response(r) => {
            assert_eq!(r.id, Id::Number(7));
            assert_eq!(r.outcome.as_ref().ok(), Some(&json!({"tools": []})));
        }
        other => panic!("expected a response, got {other:?}"),
    }

    let err = parse(r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"nope"}}"#)
        .expect("parses");
    match err {
        Message::Response(r) => {
            let e = r.outcome.expect_err("the error arm");
            assert_eq!(e.code, -32601);
            assert_eq!(e.message, "nope");
            assert_eq!(e.data, None);
        }
        other => panic!("expected a response, got {other:?}"),
    }
}

#[test]
fn a_null_result_is_a_result_not_an_absence() {
    // `"result": null` is the legitimate reply to a request that returns nothing. Treating a null
    // result as "no result present" would turn every void reply into a protocol error.
    let m = parse(r#"{"jsonrpc":"2.0","id":1,"result":null}"#).expect("parses");
    match m {
        Message::Response(r) => assert_eq!(r.outcome.as_ref().ok(), Some(&serde_json::Value::Null)),
        other => panic!("expected a response, got {other:?}"),
    }
}

#[test]
fn unknown_members_are_ignored_so_a_newer_peer_still_parses() {
    let m = parse(r#"{"jsonrpc":"2.0","id":1,"method":"ping","_meta":{"trace":"abc"}}"#)
        .expect("an unknown member is not a hostile frame, it is a newer peer");
    assert!(matches!(m, Message::Request(_)));
}

// Hostile input -----------------------------------------------------------------------------------

#[test]
fn a_truncated_frame_is_refused_not_repaired() {
    let e = parse(r#"{"jsonrpc":"2.0","id":1,"method":"tools/"#).expect_err("truncated");
    assert!(matches!(e, ProtocolError::NotJson(_)), "got {e:?}");
}

#[test]
fn the_empty_frame_is_refused() {
    assert!(matches!(parse(""), Err(ProtocolError::NotJson(_))));
}

#[test]
fn the_wrong_jsonrpc_version_is_refused_including_the_absent_one() {
    for frame in [
        r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#,
        r#"{"jsonrpc":2.0,"id":1,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0.0","id":1,"method":"ping"}"#,
        r#"{"jsonrpc":null,"id":1,"method":"ping"}"#,
        r#"{"id":1,"method":"ping"}"#,
    ] {
        let e = parse(frame).expect_err("must be refused");
        assert!(
            matches!(e, ProtocolError::WrongVersion(_)),
            "frame {frame} gave {e:?}"
        );
    }
}

#[test]
fn a_batch_is_refused_rather_than_half_supported() {
    // Batching was removed from MCP in the 2025-06-18 revision. A peer that sends one is speaking a
    // protocol we do not implement, and the fail-closed answer is to say so rather than quietly
    // process element zero and drop the rest.
    let e = parse(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#).expect_err("refused");
    assert!(matches!(e, ProtocolError::BatchUnsupported), "got {e:?}");
}

#[test]
fn a_frame_that_is_not_an_object_is_refused() {
    for frame in [r#""hello""#, "42", "null", "true"] {
        assert!(
            matches!(parse(frame), Err(ProtocolError::NotAnObject)),
            "frame {frame} was not refused"
        );
    }
}

#[test]
fn an_id_that_is_neither_string_nor_integer_is_refused() {
    for frame in [
        r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":true,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":[1],"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#,
    ] {
        let e = parse(frame).expect_err("must be refused");
        assert!(
            matches!(e, ProtocolError::IdNotStringOrInteger),
            "frame {frame} gave {e:?}"
        );
    }
}

#[test]
fn a_notification_that_carries_an_id_is_refused() {
    // The named hostile case. `notifications/*` is the notification namespace, and a frame in it
    // carrying an id is asking to be BOTH: correlated like a request by one reader and fired and
    // forgotten by another. Two readers disagreeing about whether a reply is owed is exactly the
    // desync worth refusing at the door.
    let e = parse(r#"{"jsonrpc":"2.0","id":9,"method":"notifications/cancelled"}"#)
        .expect_err("refused");
    match e {
        ProtocolError::NotificationCarriesId(m) => assert_eq!(m, "notifications/cancelled"),
        other => panic!("got {other:?}"),
    }
}

#[test]
fn a_response_to_nothing_is_still_a_parseable_response_and_the_correlator_judges_it() {
    // Parsing and correlation are different questions and this test pins the boundary: a response
    // whose id was never issued is WELL FORMED, so it parses; whether it answers anything is the
    // correlator's ruling, not the parser's. Refusing it here would put the pending table's
    // knowledge in the parser, where two copies of it would eventually disagree.
    let m = parse(r#"{"jsonrpc":"2.0","id":424242,"result":{}}"#).expect("well formed");
    assert!(matches!(m, Message::Response(_)));
}

#[test]
fn a_response_with_both_a_result_and_an_error_is_refused() {
    let e = parse(r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"m"}}"#)
        .expect_err("refused");
    assert!(
        matches!(e, ProtocolError::ResponseIsBothOutcomes),
        "got {e:?}"
    );
}

#[test]
fn a_frame_with_neither_a_method_nor_an_id_is_refused() {
    let e = parse(r#"{"jsonrpc":"2.0","result":{}}"#).expect_err("refused");
    assert!(matches!(e, ProtocolError::Unroutable), "got {e:?}");
}

#[test]
fn a_response_with_an_id_but_no_outcome_is_refused() {
    let e = parse(r#"{"jsonrpc":"2.0","id":1}"#).expect_err("refused");
    assert!(
        matches!(e, ProtocolError::ResponseHasNoOutcome),
        "got {e:?}"
    );
}

#[test]
fn a_malformed_error_object_is_refused() {
    for frame in [
        r#"{"jsonrpc":"2.0","id":1,"error":"boom"}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"message":"no code"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":1}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":"1","message":"m"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":2}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"m"}}"#,
    ] {
        let e = parse(frame).expect_err("must be refused");
        assert!(
            matches!(e, ProtocolError::MalformedError(_)),
            "frame {frame} gave {e:?}"
        );
    }
}

#[test]
fn a_method_that_is_not_a_non_empty_string_is_refused() {
    for frame in [
        r#"{"jsonrpc":"2.0","id":1,"method":7}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":""}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":null}"#,
    ] {
        let e = parse(frame).expect_err("must be refused");
        assert!(
            matches!(e, ProtocolError::MethodNotAName),
            "frame {frame} gave {e:?}"
        );
    }
}

#[test]
fn scalar_params_are_refused_because_the_spec_says_structured() {
    for frame in [
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":"x"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":7}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":true}"#,
    ] {
        let e = parse(frame).expect_err("must be refused");
        assert!(
            matches!(e, ProtocolError::ParamsNotStructured),
            "frame {frame} gave {e:?}"
        );
    }
    // Absent and null both mean "no params", and an array is structured.
    assert!(parse(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":null}"#).is_ok());
    assert!(parse(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[1,2]}"#).is_ok());
}

#[test]
fn a_deeply_nested_frame_is_rejected_rather_than_overflowing_the_stack() {
    // A recursive-descent parser on attacker-controlled JSON is a stack-overflow primitive, and a
    // stack overflow aborts the PROCESS: no unwind, no per-request isolation, the whole gateway.
    // serde_json's own recursion limit is what stops it, and this test is here so that any future
    // swap to a parser without one fails here rather than in production.
    let hostile = format!("{}{}", "[".repeat(4096), "]".repeat(4096));
    let e = Message::parse(hostile.as_bytes()).expect_err("refused");
    assert!(matches!(e, ProtocolError::NotJson(_)), "got {e:?}");
}

#[test]
fn a_non_utf8_frame_is_refused() {
    let e = Message::parse(&[0x7b, 0xff, 0xfe, 0x7d]).expect_err("refused");
    assert!(matches!(e, ProtocolError::NotJson(_)), "got {e:?}");
}

#[test]
fn a_duplicate_member_does_not_smuggle_a_second_method() {
    // Two `method` members in one object: whichever one a reader takes, both readers must agree.
    // serde_json takes the last, so the assertion is that the frame parses to exactly one method
    // and that it is a defined choice rather than an accident nobody tested.
    let m =
        parse(r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}"#).expect("parses");
    match m {
        Message::Request(r) => assert_eq!(r.method, "tools/call", "last member wins"),
        other => panic!("expected a request, got {other:?}"),
    }
}

// Serialization: what WE put on the wire ----------------------------------------------------------

#[test]
fn a_request_we_emit_round_trips_through_our_own_parser() {
    let req = Request::new(
        Id::Number(3),
        "tools/call",
        Some(json!({"name":"read_file"})),
    );
    let bytes = req.to_frame();
    match Message::parse(&bytes).expect("our own frame parses") {
        Message::Request(back) => assert_eq!(back, req),
        other => panic!("expected a request, got {other:?}"),
    }
}

#[test]
fn every_frame_we_emit_carries_the_version_and_no_newline() {
    // The stdio transport delimits messages by newline, so a newline inside one is a frame-splitting
    // primitive. Serde escapes newlines inside strings, and this pins that the emitted frame is a
    // single line so the framer can never be desynchronised by our own output.
    let frames = [
        Request::new(Id::Text("a\nb".into()), "ping", None).to_frame(),
        Response::ok(Id::Number(1), json!({"multi": "line\nhere"})).to_frame(),
        Response::failed(Id::Number(1), RpcError::method_not_found("x\ny")).to_frame(),
    ];
    for f in frames {
        let text = String::from_utf8(f).expect("utf8");
        assert!(
            text.contains(r#""jsonrpc":"2.0""#),
            "missing version in {text}"
        );
        assert!(
            !text.contains('\n'),
            "emitted frame contains a raw newline: {text}"
        );
        Message::parse(text.as_bytes()).expect("our own frame parses");
    }
}

#[test]
fn a_notification_we_emit_carries_no_id_so_no_peer_can_correlate_it() {
    // A notification that acquires an id is the mirror image of the frame refused above, and it is
    // the one WE could emit. The assertion is structural: the emitted object has no id member at
    // all, so there is nothing for a peer to reply to.
    let n = Notification::new("notifications/initialized", None);
    let text = String::from_utf8(n.to_frame()).expect("utf8");
    assert!(
        !text.contains(r#""id""#),
        "notification carries an id: {text}"
    );
    match Message::parse(text.as_bytes()).expect("our own frame parses") {
        Message::Notification(back) => assert_eq!(back, n),
        other => panic!("expected a notification, got {other:?}"),
    }
}

#[test]
fn every_refusal_maps_to_the_error_code_we_owe_the_peer() {
    // In the direction where busbar is the SERVER, a refused frame still owes the peer a reply, and
    // which code it gets is a decision that belongs beside the refusal rather than at each call
    // site. A parse failure is -32700 and every other refusal is -32600; this is what pins that a
    // new arm cannot be added without picking one.
    assert_eq!(
        ProtocolError::NotJson("truncated".into())
            .to_rpc_error()
            .code,
        CODE_PARSE_ERROR
    );
    for e in [
        ProtocolError::NotAnObject,
        ProtocolError::BatchUnsupported,
        ProtocolError::WrongVersion("null".into()),
        ProtocolError::IdNotStringOrInteger,
        ProtocolError::MethodNotAName,
        ProtocolError::ParamsNotStructured,
        ProtocolError::NotificationCarriesId("notifications/x".into()),
        ProtocolError::ResponseIsBothOutcomes,
        ProtocolError::ResponseHasNoOutcome,
        ProtocolError::MalformedError("code is not an integer"),
        ProtocolError::Unroutable,
    ] {
        let mapped = e.to_rpc_error();
        assert_eq!(mapped.code, CODE_INVALID_REQUEST, "for {e:?}");
        assert!(!mapped.message.is_empty(), "for {e:?}");
    }
}

#[test]
fn the_standard_codes_are_the_standard_numbers() {
    // Transcribed from the JSON-RPC 2.0 specification. Spelled once, and pinned here, because a
    // typo in one of them is invisible until a peer reports the wrong class of failure.
    assert_eq!(CODE_PARSE_ERROR, -32700);
    assert_eq!(CODE_INVALID_REQUEST, -32600);
    assert_eq!(RpcError::method_not_found("x").code, CODE_METHOD_NOT_FOUND);
    assert_eq!(CODE_METHOD_NOT_FOUND, -32601);
    assert_eq!(RpcError::invalid_params("x").code, CODE_INVALID_PARAMS);
    assert_eq!(CODE_INVALID_PARAMS, -32602);
    assert_eq!(RpcError::internal("x").code, CODE_INTERNAL_ERROR);
    assert_eq!(CODE_INTERNAL_ERROR, -32603);
}

#[test]
fn an_id_renders_so_an_operator_can_still_tell_the_two_arms_apart() {
    assert_eq!(Id::Number(1).to_string(), "1");
    assert_eq!(Id::Text("1".into()).to_string(), "\"1\"");
}

#[test]
fn an_error_response_we_emit_never_also_carries_a_result() {
    let text = String::from_utf8(
        Response::failed(Id::Number(1), RpcError::invalid_params("bad")).to_frame(),
    )
    .expect("utf8");
    assert!(text.contains(r#""error""#));
    assert!(
        !text.contains(r#""result""#),
        "an error response must not carry a result member: {text}"
    );
}
