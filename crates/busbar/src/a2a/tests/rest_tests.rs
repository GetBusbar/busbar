// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the plane's HTTP+JSON binding.
//!
//! What is asserted here is the RE-FRAMING and nothing else, because re-framing is the whole of what
//! this module does: everything a request means — admission, catalogue, meter, egress gate, relay —
//! is `ingress::invoke`'s, is unchanged, and is tested where it lives. A test here that exercised
//! the sequence would be a second copy of the ingress tests measuring the same code through a
//! different door.
//!
//! So the questions are: does a REST request compose the envelope the JSON-RPC leg would have
//! received, and does an answer come back in the shape A2A section 11.3 and section 11.6 define?

use super::*;

/// SECTION 11.3, IN ONE ASSERTION: the success body IS the `result` verbatim. Not "contains", not
/// "the task inside it" — the same JSON, member for member. This is what makes the TCK's two readers
/// (`result.get("task", result)` on JSON-RPC, `body.get("task", body)` on REST) see one document.
#[tokio::test]
async fn a_result_becomes_the_body_verbatim() {
    let result = json!({"task": {"id": "t-1", "contextId": "c-1"}, "extra": [1, 2, 3]});
    let answered = (
        axum::http::StatusCode::OK,
        axum::Json(json!({"jsonrpc": "2.0", "id": REST_RPC_ID, "result": result})),
    )
        .into_response();

    let (status, body) = read(reframe(answered).await).await;
    assert_eq!(status, 200);
    assert_eq!(body, result, "the REST body must BE the JSON-RPC result");
}

/// SECTION 11.6: an error becomes AIP-193 — the HTTP status in `error.code`, the canonical name in
/// `error.status`, and the ProtoJSON array moved from `data` to `details` unchanged.
#[tokio::test]
async fn an_error_becomes_aip_193_with_the_status_it_was_refused_with() {
    let answered = super::super::rpcerror::respond(
        &json!(REST_RPC_ID),
        super::super::rpcerror::A2aError::TaskNotFound,
        "no such task",
    );

    let (status, body) = read(reframe(answered).await).await;
    assert_eq!(status, 404, "section 5.4 binds TaskNotFound to 404");
    assert_eq!(
        body["error"]["code"],
        json!(404),
        "AIP-193 puts the HTTP STATUS in error.code, not the JSON-RPC code"
    );
    assert_eq!(body["error"]["status"], "NOT_FOUND");
    assert_eq!(body["error"]["message"], "no such task");
    assert_eq!(
        body["error"]["details"][0]["reason"], "TASK_NOT_FOUND",
        "the ErrorInfo array moves from `data` to `details` unchanged"
    );
    assert_eq!(
        body["error"]["details"][0]["domain"], "a2a-protocol.org",
        "the domain is the specification's, in both bindings"
    );
    // AND THE JSON-RPC MEMBERS ARE GONE. A REST client that saw `jsonrpc` or a negative `code`
    // would be reading an envelope this binding does not have.
    assert!(body.get("jsonrpc").is_none());
    assert!(body.get("id").is_none());
}

/// A REFUSAL WHOSE `code` IS NOT A JSON-RPC CODE STILL RE-FRAMES. Not every refusal on this plane
/// carries the shared table's integer code — a deployment with no governance answers a plain
/// document with a STRING one — and the re-framer must not read that string as a code it can look
/// up. It falls back to the canonical name for the HTTP STATUS, which is the only other fact the
/// answer actually carries; the alternative is a `code` a conformant REST client cannot parse.
#[tokio::test]
async fn a_string_coded_refusal_re_frames_from_its_http_status() {
    let doc = json!({"error": {"code": "unavailable", "message": "no card yet"}});
    let answered = (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(doc.clone()),
    )
        .into_response();

    let (status, body) = read(reframe(answered).await).await;
    assert_eq!(status, 503);
    assert_eq!(
        body["error"]["code"],
        json!(503),
        "a string-coded refusal still re-frames its code to the HTTP status"
    );
    assert_eq!(body["error"]["status"], "UNAVAILABLE");
    assert_eq!(body["error"]["message"], "no card yet");
}

/// AND AN ANSWER THAT IS NEITHER A `result` NOR AN `error` IS NOT TOUCHED AT ALL. A served agent
/// card is the live example: it is a plain document with neither member, and a re-framer that
/// treated "not an envelope" as "empty envelope" would replace it with `null`. The test for "is
/// this an envelope" is the presence of one of those two members and nothing else.
#[tokio::test]
async fn a_document_that_is_not_an_envelope_is_left_alone() {
    let card = json!({"protocolVersion": "1.0", "name": "busbar", "skills": []});
    let answered = (axum::http::StatusCode::OK, axum::Json(card.clone())).into_response();

    let (status, body) = read(reframe(answered).await).await;
    assert_eq!(status, 200);
    assert_eq!(body, card, "a non-envelope document ships byte for byte");
}

/// THE STREAM IS RE-FRAMED EVENT BY EVENT: each `data:` payload becomes its `result`, and the SSE
/// framing survives byte for byte.
#[test]
fn a_streamed_result_event_becomes_the_bare_event() {
    let frame =
        b"data: {\"jsonrpc\":\"2.0\",\"id\":\"a2a-http-json\",\"result\":{\"taskId\":\"t-1\"}}\n\n";
    let out = String::from_utf8(reframe_frames(frame)).expect("utf-8");
    assert_eq!(out, "data: {\"taskId\":\"t-1\"}\n\n");
}

/// A MID-STREAM ERROR FRAME KEEPS ITS ENVELOPE. The status is already spent by the time it is
/// written, so there is no HTTP status for AIP-193's `code` to carry, and re-shaping it would assert
/// one the response does not have.
#[test]
fn a_streamed_error_event_is_left_alone() {
    let frame = b"data: {\"jsonrpc\":\"2.0\",\"id\":\"x\",\"error\":{\"code\":-32001}}\n\n";
    assert_eq!(reframe_frames(frame), frame.to_vec());
}

/// KEEP-ALIVES, COMMENTS AND A BACKEND'S OWN FRAMES ARE PASSED THROUGH. The relay's event reader
/// makes the same decision for the same reason: content busbar does not read is content busbar does
/// not rewrite.
#[test]
fn non_response_frames_are_passed_through() {
    for frame in [
        &b": keep-alive\n\n"[..],
        &b"event: ping\ndata: {\"hello\":1}\n\n"[..],
        &b"data: not json at all\n\n"[..],
    ] {
        assert_eq!(
            reframe_frames(frame),
            frame.to_vec(),
            "{}",
            String::from_utf8_lossy(frame)
        );
    }
}

/// QUERY STRINGS ARE TYPED ON THE WAY INTO THE ENVELOPE. `historyLength=5` means the NUMBER five to
/// every reader of the composed envelope; left as a string, a filter is silently not applied, which
/// is the failure mode that errors nowhere.
#[test]
fn query_values_are_typed_the_way_the_envelope_wants_them() {
    assert_eq!(json_scalar("5"), json!(5));
    assert_eq!(json_scalar("-3"), json!(-3));
    assert_eq!(json_scalar("true"), json!(true));
    assert_eq!(json_scalar("false"), json!(false));
    assert_eq!(json_scalar("ctx-1"), json!("ctx-1"));
    assert_eq!(json_scalar(""), json!(""));
}

/// ABSENT IS NOT EMPTY. A query parameter the caller omitted must not appear in the composed params
/// at all: `historyLength` absent means "no opinion" and is a different request from
/// `historyLength: null`.
#[test]
fn an_omitted_query_parameter_is_absent_from_the_params() {
    let params = Params::new()
        .set("id", "t-1")
        .maybe("historyLength", None)
        .into_value();
    assert_eq!(params, json!({"id": "t-1"}));

    let asked = "7".to_string();
    let params = Params::new()
        .set("id", "t-1")
        .maybe("historyLength", Some(&asked))
        .into_value();
    assert_eq!(params, json!({"id": "t-1", "historyLength": 7}));
}

/// THE PATH WINS OVER THE BODY. A `taskId` member in a posted push-notification config must not
/// re-point the request at a task the caller did not address.
#[test]
fn a_body_member_cannot_re_point_the_addressed_task() {
    let params = Params::new()
        .merge(&json!({"taskId": "somebody-elses", "url": "https://receiver.example/hook"}))
        .set("taskId", "the-one-addressed")
        .into_value();
    assert_eq!(params["taskId"], "the-one-addressed");
    assert_eq!(params["url"], "https://receiver.example/hook");
}

/// AN EMPTY BODY IS NOT A PARSE FAILURE. `POST /tasks/{id}:cancel` carries none, and neither does a
/// `DELETE`; refusing them for a body they are not supposed to have would refuse the specification's
/// own request shape.
#[test]
fn an_absent_body_composes_empty_params() {
    assert_eq!(json_body(&axum::body::Bytes::new()), json!({}));
    assert_eq!(
        json_body(&axum::body::Bytes::from_static(b"nope")),
        json!({})
    );
    assert_eq!(
        json_body(&axum::body::Bytes::from_static(b"{\"message\":1}")),
        json!({"message": 1})
    );
}

/// Read a response back as (status, JSON body).
async fn read(response: Response) -> (u16, Value) {
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body reads back");
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}
