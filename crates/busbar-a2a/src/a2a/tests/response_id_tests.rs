// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JSON-RPC `id` ON THE WAY BACK: what busbar does with a backend agent's answer that does not
//! name the request busbar sent it. The delegating direction's half of what
//! `envelope_id_tests.rs` asserts for the receiving direction.
//!
//! ## The defect these were written red against
//!
//! `relay.rs` read `error` and `result` straight off whatever came back. There was no `jsonrpc`
//! member check and the response `id` was never read at all, on EITHER path — so a backend agent
//! could answer this hop with the reply to a different one and busbar would record it as this
//! task's result and serve it to the caller. Under adversarial timing that is caller A being handed
//! backend-conversation B's answer, with busbar's own task identity stamped onto it by
//! `rewrite_identity`, which is what makes it look correct.
//!
//! And the two paths disagreed about the id they both ignored. The UNARY path answered the caller
//! under `ctx.rpc_id` — busbar's own reading of the caller's envelope. The STREAMING path passed
//! the backend's `id` through verbatim, so on a stream the BACKEND chose the value busbar's caller
//! correlated its own request on. They are equal today only because the relay forwards the caller's
//! body unchanged; nothing enforced it and nothing noticed. The unary path was right, and
//! `a_streamed_event_is_answered_under_busbars_id_not_the_backends` is the assertion that says so.
//!
//! ## Why these read the wire and not a return value
//!
//! The request-side investigation found the in-house battery's `SRV.NOTIF.NO-RESPONSE` check
//! passing against a provably broken binary, because the battery's own `isResponse()` predicate was
//! `'id' in msg`. An instrument can be blind to exactly the defect it is pointed at. So every
//! assertion below is on bytes that crossed a boundary: what busbar sent the backend (`h.sent()`),
//! and what busbar wrote to the caller (the HTTP status and body of a real request through
//! `crate::build_router`).

use super::relay_harness::*;

/// The `id` every envelope in this file sends and every correlated answer must name.
const SENT_ID: i64 = 7;

/// What a backend answers when it answers the WRONG request: a complete, well-formed, entirely
/// plausible Task — carrying a payload the caller must never see, under an `id` the caller never
/// sent.
fn answer_to_another_request(id: serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "id": "SOME-OTHER-TASK",
            "contextId": "SOME-OTHER-CONTEXT",
            "kind": "task",
            "status": { "state": "completed" },
            "artifacts": [{
                "artifactId": "a1",
                "parts": [{ "kind": "text", "text": "ANOTHER-CALLERS-SECRET" }]
            }]
        }
    })
    .to_string()
}

// ══ THE UNARY PATH ═══════════════════════════════════════════════════════════════════════════════

/// THE DEFECT. Every one of these is a well-formed 200 from the backend that is not the answer to
/// this caller's request, and every one of them used to be served as that caller's result.
#[tokio::test]
async fn an_answer_that_does_not_name_the_request_busbar_sent_is_never_served_to_the_caller() {
    for (what, reply) in [
        // A DIFFERENT REQUEST'S ANSWER. The case that serves caller A with conversation B's reply.
        ("a different id", answer_to_another_request(serde_json::json!(8))),
        // Same digits, different TYPE. A correlation that coerced would cross-deliver here.
        (
            "a string id where a number was sent",
            answer_to_another_request(serde_json::json!("7")),
        ),
        // section 5 spends `null` on "the sender could not tell which request this was".
        (
            "a null id",
            answer_to_another_request(serde_json::Value::Null),
        ),
        // REQUIRED on a Response, and absent.
        (
            "no id member",
            serde_json::json!({
                "jsonrpc": "2.0",
                "result": { "id": "SOME-OTHER-TASK", "kind": "task",
                            "artifacts": [{ "artifactId": "a1",
                                            "parts": [{ "kind": "text", "text": "ANOTHER-CALLERS-SECRET" }] }] }
            })
            .to_string(),
        ),
        // Not a JSON-RPC message at all — this plane's relay never checked the version member
        // either, so a bare `{"result": …}` was read as an answer.
        (
            "no jsonrpc member",
            serde_json::json!({
                "id": SENT_ID,
                "result": { "id": "SOME-OTHER-TASK", "kind": "task",
                            "artifacts": [{ "artifactId": "a1",
                                            "parts": [{ "kind": "text", "text": "ANOTHER-CALLERS-SECRET" }] }] }
            })
            .to_string(),
        ),
    ] {
        let h = harness(Outcome::Answers(200, reply), false).await;
        let (status, body) = call(&h).await;
        let rendered = body.to_string();

        assert_eq!(
            h.sent().len(),
            1,
            "the control condition failed: the hop must actually have been made for `{what}`"
        );
        assert!(
            !rendered.contains("ANOTHER-CALLERS-SECRET"),
            "a backend answer with {what} was relayed to the caller: status={status} body={rendered}"
        );
        assert_ne!(
            status, 200,
            "a backend answer with {what} was served as this caller's result: {rendered}"
        );
        assert_eq!(
            status, 502,
            "an uncorrelated answer is a busbar-attributed hop failure: {rendered}"
        );
    }
}

/// THE CONTROL for every case above. The identical exchange whose answer DOES name the request is
/// served, with busbar's own task identity substituted — so the refusals above are the correlation
/// working and not the relay refusing everything.
#[tokio::test]
async fn the_same_exchange_correlated_is_served_under_busbars_identity() {
    let h = harness(
        Outcome::Answers(200, answer_to_another_request(serde_json::json!(SENT_ID))),
        false,
    )
    .await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "the control must be served: {body}");
    assert_eq!(
        body["id"],
        serde_json::json!(SENT_ID),
        "the caller's own id must come back: {body}"
    );
    assert!(
        body.pointer("/result/id").is_some(),
        "the result must be there: {body}"
    );
    assert!(
        !body.to_string().contains("SOME-OTHER-TASK"),
        "the backend's own task id must not reach the caller: {body}"
    );
}

// ══ THE STREAMING PATH, AND THE ASYMMETRY IT USED TO CARRY ═══════════════════════════════════════

fn stream_envelope() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": SENT_ID,
        "method": "message/stream",
        "params": {
            "message": {
                "role": "user",
                "contextId": "ctx-stream",
                "parts": [{ "kind": "text", "text": "STREAM THE PLAN" }]
            }
        }
    })
}

/// One SSE frame carrying a JSON-RPC envelope under an id of the caller's choosing.
fn frame(id: serde_json::Value, text: &str) -> String {
    format!(
        "data: {}\n\n",
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "id": "SOME-OTHER-TASK",
                "contextId": "SOME-OTHER-CONTEXT",
                "kind": "status-update",
                "status": { "state": "working" },
                "artifacts": [{ "artifactId": "a1",
                                "parts": [{ "kind": "text", "text": text }] }]
            }
        })
    )
}

/// A STREAMED EVENT NAMING ANOTHER REQUEST IS NOT WRITTEN TO THE CALLER. Not passed through, and
/// not silently dropped either: the hop is refused, which is a status the ingress can still choose
/// while the first event is the thing being judged.
#[tokio::test]
async fn a_streamed_event_that_does_not_name_the_request_busbar_sent_never_reaches_the_caller() {
    let h = harness(
        Outcome::Streams(vec![frame(serde_json::json!(8), "ANOTHER-CALLERS-SECRET")]),
        false,
    )
    .await;
    let (status, content_type, body) = call_raw(&h, "planner", &stream_envelope()).await;
    assert_eq!(h.sent().len(), 1, "the hop must have been made");
    assert!(
        !body.contains("ANOTHER-CALLERS-SECRET"),
        "an event answering request 8 was written to the caller of request 7: \
         status={status} content-type={content_type} body={body}"
    );
    assert_ne!(
        status, 200,
        "an uncorrelated stream must not be committed to as a served stream: {body}"
    );
}

/// THE ASYMMETRY, NAMED AND CLOSED. The unary path answered under busbar's own `rpc_id`; this path
/// passed the backend's `id` through verbatim, so the backend chose the value the caller correlated
/// on. This asserts the streamed answer now carries the SAME id the unary path returns — read out
/// of the bytes written to the caller's socket, not out of a struct.
#[tokio::test]
async fn a_streamed_event_is_answered_under_busbars_id_not_the_backends() {
    // The backend echoes `7.0` — the same NUMBER the caller sent, written differently. It
    // correlates (JSON has one number type), and what the caller must get back is the id busbar
    // read off the caller's own envelope, byte for byte identical to the unary path's.
    let h = harness(
        Outcome::Streams(vec![frame(serde_json::json!(7.0), "THE PLAN")]),
        false,
    )
    .await;
    let (status, content_type, body) = call_raw(&h, "planner", &stream_envelope()).await;
    assert_eq!(status, 200, "the stream must be served: {body}");
    assert!(
        content_type.starts_with("text/event-stream"),
        "content-type={content_type} body={body}"
    );
    let data = body
        .lines()
        .find_map(|l| l.strip_prefix("data: "))
        .expect("an event was written");
    let event: serde_json::Value = serde_json::from_str(data).expect("the event is JSON");
    assert_eq!(
        event["id"],
        serde_json::json!(SENT_ID),
        "the streamed answer must carry the id busbar read off the CALLER's envelope, which is what \
         the unary path returns; the backend's rendering of it is not the caller's business: {body}"
    );
    assert!(
        !body.contains("SOME-OTHER-TASK"),
        "the backend's own task id must not reach the caller: {body}"
    );
}

/// CONTENT-BLINDNESS SURVIVES THE CORRELATION. A frame that is not a JSON-RPC response — a
/// keep-alive, a comment, a backend's own protocol extension — has no `id` to correlate and must
/// still pass through byte for byte, or the fix would have turned every such frame into a refused
/// hop.
#[tokio::test]
async fn a_frame_that_is_not_a_response_still_passes_through_untouched() {
    let h = harness(
        Outcome::Streams(vec![
            ": keep-alive\n\n".to_string(),
            frame(serde_json::json!(SENT_ID), "THE PLAN"),
        ]),
        false,
    )
    .await;
    let (status, _ct, body) = call_raw(&h, "planner", &stream_envelope()).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(": keep-alive"),
        "a keep-alive must reach the caller as it left: {body}"
    );
    assert!(body.contains("THE PLAN"), "{body}");
}
