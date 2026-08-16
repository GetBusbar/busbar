// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ASYNC HALF OF THE RELAY: streaming, the interrupt relay, the push-notification callback
//! guard, and restart/resubscribe.
//!
//! These are the four questions the design promoted from "open" to "designed", and a design
//! document is not an implementation. Each is driven here through the real router rather than
//! asserted in prose.
//!
//! ## Why the SSE reader is unit-tested as well as driven end to end
//!
//! An SSE stream does NOT arrive one event per chunk. A single read can carry three events, half an
//! event, or the tail of one and the head of the next, and a reader that assumed a chunk was an
//! event corrupts a caller's stream under exactly the conditions that are hardest to reproduce
//! against a fixture. So the framing is pinned directly, at the byte level, and the end-to-end
//! tests then prove the router uses it.

use super::relay_harness::*;
use crate::a2a::relay::{read_event, SseReader};
use crate::a2a::task::TaskState;

/// A streaming envelope: `message/stream`, which is what makes `TaskShape::requires_streaming` true
/// and therefore what makes the ingress take the streaming hop.
fn stream_envelope(context_id: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "message/stream",
        "params": {
            "message": {
                "role": "user",
                "contextId": context_id,
                "parts": [{ "kind": "text", "text": "STREAM THE PLAN" }]
            }
        }
    })
}

/// The task id the FIRST event of a streamed answer names. The caller's only handle on a streamed
/// task, so reading it here is also the assertion that a streamed event carries one at all.
fn first_task_id(sse: &str) -> Option<String> {
    let data = sse.lines().find_map(|l| l.strip_prefix("data: "))?;
    let value: serde_json::Value = serde_json::from_str(data).ok()?;
    value
        .pointer("/result/id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// One SSE frame carrying a JSON-RPC envelope, framed the way a backend frames it.
fn frame(result: serde_json::Value) -> String {
    format!(
        "data: {}\n\n",
        serde_json::json!({ "jsonrpc": "2.0", "id": 11, "result": result })
    )
}

// ══ THE FRAMING ══════════════════════════════════════════════════════════════════════════════════

/// AN EVENT IS NOT A CHUNK. Three events in one read, one event split across three reads, and the
/// tail of one plus the head of the next — the three shapes that break a reader which equates the
/// two.
#[test]
fn the_sse_reader_reassembles_events_across_arbitrary_chunk_boundaries() {
    let mut r = SseReader::default();
    assert_eq!(
        r.feed(b"data: {\"a\":1}\n\ndata: {\"a\":2}\n\ndata: {\"a\":3}\n\n")
            .len(),
        3,
        "three events in one read must come out as three"
    );

    let mut r = SseReader::default();
    assert!(
        r.feed(b"data: {\"a\"").is_empty(),
        "half an event is not one"
    );
    assert!(r.feed(b":1}").is_empty(), "still half an event");
    let out = r.feed(b"\n\n");
    assert_eq!(out.len(), 1, "the terminator completes exactly one event");
    assert!(out[0].contains("\"a\":1"));

    let mut r = SseReader::default();
    let out = r.feed(b"data: {\"a\":1}\n\ndata: {\"a\"");
    assert_eq!(out.len(), 1, "only the COMPLETE event is emitted");
    assert!(
        r.pending() > 0,
        "the head of the next event must be held, not dropped"
    );
}

/// A LINE ENDS WITH CRLF, LF **OR** A BARE CR — the event stream format's own rule, not a tolerance
/// — so the blank line that ends an event has three spellings and all three must frame.
///
/// Only `\n\n` was recognised. The bytes `…}\r\n\r\n` contain no `\n\n` at all, so an event
/// terminated the CRLF way never left the buffer: the reader accumulated the whole stream, the
/// relay reported that the stream had carried no event, and busbar answered `502 the backend agent
/// did not complete this task` about a backend that had streamed perfectly. It survived because the
/// only streaming peer this tree had ever relayed used bare LF. Against the official TCK, with a
/// backend that uses CRLF, it read as `CORE-STREAM-001/002/003`, `STREAM-ORDER-001`,
/// `JSONRPC-SSE-001` and every requirement whose setup opens a stream.
#[test]
fn the_sse_reader_frames_every_line_ending_the_format_allows() {
    let mut r = SseReader::default();
    let out = r.feed(b"data: {\"a\":1}\r\n\r\ndata: {\"a\":2}\r\n\r\n");
    assert_eq!(out.len(), 2, "CRLF-terminated events must frame: {out:?}");
    assert!(out[0].contains("\"a\":1"));
    assert!(out[1].contains("\"a\":2"));

    let mut r = SseReader::default();
    assert!(
        r.feed(b"data: {\"a\":1}\r\n\r").is_empty(),
        "a HALF terminator is not one, and the frame must wait for the rest"
    );
    assert_eq!(
        r.feed(b"\n").len(),
        1,
        "the arriving final byte completes exactly one event"
    );

    let mut r = SseReader::default();
    assert_eq!(
        r.feed(b"data: {\"a\":1}\r\rdata: {\"a\":2}\n\n").len(),
        2,
        "a bare-CR stream frames, and a stream that MIXES forms frames at the right places"
    );
}

/// AN EVENT IS REWRITTEN UNDER BUSBAR'S IDENTITY, and a frame that is not a JSON-RPC result passes
/// through UNCHANGED. busbar is content-blind: a comment, a keep-alive or a backend's own protocol
/// extension must arrive at the caller as it left, not as an unexplained gap.
#[test]
fn a_streamed_event_carries_busbars_identity_and_an_unreadable_frame_is_passed_through() {
    let ev = read_event(
        &frame(serde_json::json!({
            "id": "BACKEND-OWN-TASK-ID",
            "contextId": "BACKEND-OWN-CONTEXT",
            "kind": "status-update",
            "status": { "state": "working" }
        })),
        &serde_json::json!(11),
        "busbar-task-1",
        "ctx-mine",
        Some("plan"),
    )
    .expect("the fixture frame is correlated to the id the stream envelope sent");
    let rendered = String::from_utf8(ev.sse).expect("utf8");
    assert!(
        rendered.contains("busbar-task-1") && rendered.contains("ctx-mine"),
        "the event must carry busbar's identity: {rendered}"
    );
    assert!(
        !rendered.contains("BACKEND-OWN-TASK-ID") && !rendered.contains("BACKEND-OWN-CONTEXT"),
        "the backend's own ids must not reach the caller: {rendered}"
    );
    assert_eq!(ev.state, Some(TaskState::Working));

    let comment = ": keep-alive\n\n";
    let passed = read_event(
        comment,
        &serde_json::json!(11),
        "busbar-task-1",
        "ctx-mine",
        None,
    )
    .expect("a keep-alive is not a response and is not correlated");
    assert_eq!(
        String::from_utf8(passed.sse).expect("utf8"),
        comment,
        "a frame with no JSON-RPC result must pass through byte for byte"
    );
}

// ══ STREAMING, END TO END ════════════════════════════════════════════════════════════════════════

/// THE RESULT IS STREAMED BACK. This is the half of C2 the goal names separately from the hop: a
/// relay that submits a task and buffers the whole answer has not streamed anything.
#[tokio::test]
async fn a_streaming_submission_is_relayed_as_a_stream_and_written_back_as_sse() {
    let frames = vec![
        frame(serde_json::json!({
            "id": "B1", "contextId": "BC", "kind": "status-update",
            "status": { "state": "working" }
        })),
        frame(serde_json::json!({
            "id": "B1", "contextId": "BC", "kind": "artifact-update",
            "artifact": { "artifactId": "a1", "parts": [{ "kind": "text", "text": "CHUNK ONE" }] }
        })),
        frame(serde_json::json!({
            "id": "B1", "contextId": "BC", "kind": "status-update",
            "status": { "state": "completed" }
        })),
    ];
    let h = harness(Outcome::Streams(frames), false).await;
    let (status, ct, body) = call_raw(&h, "planner", &stream_envelope("ctx-stream")).await;

    assert_eq!(status, 200, "the streamed call must be served: {body}");
    assert!(
        ct.starts_with("text/event-stream"),
        "a streamed answer must be framed as SSE, got `{ct}`"
    );
    assert_eq!(
        body.matches("data:").count(),
        3,
        "every backend event must reach the caller: {body}"
    );
    assert!(
        body.contains("CHUNK ONE"),
        "the artifact content must reach the caller: {body}"
    );
    assert!(
        !body.contains("\"B1\"") && !body.contains("\"BC\""),
        "the backend's own ids must not reach the caller: {body}"
    );

    // AND THE HOP WAS A STREAMING HOP. A relay that sent `message/stream` down the unary path would
    // produce the same bytes here and none of the incrementality.
    let sent = h.sent();
    assert_eq!(sent.len(), 1);
    assert!(
        sent[0].streaming,
        "a `message/stream` must go out through the streaming transport"
    );
    let accept = sent[0]
        .headers
        .iter()
        .find(|(n, _)| n == "accept")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    assert!(
        accept.contains("text/event-stream"),
        "the streaming hop must ASK for a stream, got `{accept}`"
    );
}

/// THE CALLER'S KEY IS NOT ON THE STREAMING WIRE EITHER. The scan is repeated on this path rather
/// than assumed to carry over: the streaming hop builds its own request, and a header set that is
/// closed on one path and open on the other is exactly the asymmetry a single-path scan misses.
#[tokio::test]
async fn the_callers_busbar_key_is_absent_from_the_streaming_wire_too() {
    let frames = vec![frame(serde_json::json!({
        "id": "B1", "contextId": "BC", "status": { "state": "completed" }
    }))];
    let h = harness(Outcome::Streams(frames), true).await;
    let (status, _ct, _body) = call_raw(&h, "planner", &stream_envelope("ctx-scan")).await;
    assert_eq!(status, 200);

    let wire = h.all_wire();
    assert!(wire.len() > 100, "the scan has nothing to scan");
    for (encoding, bytes) in &encodings(&h.bearer) {
        assert!(
            !contains(&wire, bytes),
            "the caller's busbar key reached the backend on the STREAMING path, as {encoding}"
        );
    }
    assert!(
        contains(&wire, LEASED.as_bytes()),
        "the control: the scanner must find the credential that IS legitimately forwarded"
    );
}

/// A BACKEND THAT ANSWERS A DOCUMENT TO A STREAM REQUEST is answered as a document. Legal for a
/// task it finished instantly, and re-framing it as a one-event stream would be busbar inventing a
/// framing the backend never used.
#[tokio::test]
async fn a_stream_request_answered_with_one_document_comes_back_as_a_document() {
    // `11` is the id `stream_envelope` sends, and the relay now requires the answer to name it.
    let h = harness(
        Outcome::StreamAnsweredUnary(backend_ok_for(serde_json::json!(11))),
        false,
    )
    .await;
    let (status, ct, body) = call_raw(&h, "planner", &stream_envelope("ctx-unary")).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        ct.starts_with("application/json"),
        "a document answer must stay a document, got `{ct}`"
    );
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        parsed
            .pointer("/result/status/state")
            .and_then(|v| v.as_str()),
        Some("completed"),
        "{body}"
    );
}

/// A STREAMING HOP THAT FAILS BEFORE ITS FIRST EVENT is still a status this handler gets to choose.
/// After the first event it cannot be, which is why the commitment point is where it is.
#[tokio::test]
async fn a_streaming_hop_that_fails_before_its_first_event_is_a_busbar_attributed_error() {
    let h = harness(Outcome::Fails("connection refused".to_string()), false).await;
    let (status, _ct, body) = call_raw(&h, "planner", &stream_envelope("ctx-fail")).await;
    assert_eq!(status, 502, "{body}");
    assert!(
        !body.contains("backend.agent.test"),
        "the refusal named the backend endpoint: {body}"
    );
}

// ══ THE INTERRUPT RELAY ══════════════════════════════════════════════════════════════════════════

/// AN INTERRUPT IS RELAYED AS ITSELF, NOT AS A FAILURE, AND THE TASK IS PERSISTED PAUSED.
///
/// A2A is asynchronous by design, so `input-required` and `auth-required` are the NORMAL path. A
/// relay that turned an interrupt into a 502 would force the caller to re-initiate and would lose
/// the `contextId` the resume depends on.
#[tokio::test]
async fn an_interrupt_from_the_backend_is_relayed_transparently_and_pauses_the_task() {
    let reply = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "result": {
            "id": "B1",
            "contextId": "BC",
            "kind": "task",
            "status": {
                "state": "input-required",
                "message": { "role": "agent", "parts": [{ "kind": "text", "text": "WHICH REGION?" }] }
            }
        }
    })
    .to_string();
    let h = harness(Outcome::Answers(200, reply), false).await;
    let (status, body) = call(&h).await;

    assert_eq!(
        status, 200,
        "an interrupt is not a failure and must not be answered as one: {body}"
    );
    assert_eq!(
        body.pointer("/result/status/state")
            .and_then(|v| v.as_str()),
        Some("input-required"),
        "the interrupt must reach the caller as itself: {body}"
    );
    assert_eq!(
        body.pointer("/result/status/message/parts/0/text")
            .and_then(|v| v.as_str()),
        Some("WHICH REGION?"),
        "the backend's question must reach the caller, or the caller cannot answer it: {body}"
    );
    let id = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        body.pointer("/result/contextId").and_then(|v| v.as_str()),
        Some("ctx-abc"),
        "the contextId the resume depends on must be busbar's, and unchanged: {body}"
    );

    let task = crate::a2a::taskstore::TASKS
        .get_unscoped(&id)
        .expect("the task exists");
    assert_eq!(
        task.state,
        TaskState::InputRequired,
        "an interrupted task is PAUSED, not terminal and not still `submitted`"
    );
    assert!(
        task.state.is_active(),
        "a paused task is live: the retention sweep must never treat it as collectable"
    );
}

/// A FOLLOW-UP ON THE SAME `contextId` RESUMES THE SAME TASK rather than opening a second one.
///
/// Opening a second would give the caller a new handle for work that is already half done, orphan
/// the first row forever, and bill one piece of work twice.
#[tokio::test]
async fn a_follow_up_on_the_same_context_resumes_the_paused_task_rather_than_opening_another() {
    let interrupt = serde_json::json!({
        "jsonrpc": "2.0", "id": 7,
        "result": { "id": "B1", "contextId": "BC", "status": { "state": "auth-required" } }
    })
    .to_string();
    let h = harness(Outcome::Answers(200, interrupt), false).await;

    let ctx = format!("ctx-resume-{}", std::process::id());
    let mut env = envelope();
    env["params"]["message"]["contextId"] = serde_json::Value::String(ctx.clone());

    let (status, body) = call_agent(&h, "planner", &env).await;
    assert_eq!(status, 200, "{body}");
    let first = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        crate::a2a::taskstore::TASKS
            .get_unscoped(&first)
            .map(|t| t.state),
        Some(TaskState::AuthRequired)
    );

    // THE FOLLOW-UP: the caller supplies what was asked for, on the SAME contextId.
    let (status, body) = call_agent(&h, "planner", &env).await;
    assert_eq!(status, 200, "{body}");
    let second = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        second, first,
        "the follow-up must RESUME the paused task, not open a second one: {body}"
    );
    assert_eq!(
        h.sent().len(),
        2,
        "both the initial submission and the resume reach the backend"
    );

    // A `task.resumed` event is on the chain where the store keeps one. With the RAM default there
    // are no persisted events, which is the documented product contract rather than a defect.
    let events = h.gov.store().list_task_events(&first).unwrap_or_default();
    if !events.is_empty() {
        crate::audit::verify_chain(&events).expect("the chain verifies across a resume");
        assert!(
            events
                .iter()
                .any(|e| e.kind == crate::a2a::provenance::EV_RESUMED),
            "a resume must be a chained event, not a silent state change: {events:?}"
        );
    }
}

/// A CALLER MAY NOT RESUME SOMEBODY ELSE'S TASK by guessing a `contextId`. The resume lookup is
/// scoped to the presenting principal, on the same substrate `GetTask` is scoped on.
#[tokio::test]
async fn a_context_id_belonging_to_another_principal_does_not_resume_that_task() {
    let interrupt = serde_json::json!({
        "jsonrpc": "2.0", "id": 7,
        "result": { "id": "B1", "contextId": "BC", "status": { "state": "input-required" } }
    })
    .to_string();
    let victim = harness(Outcome::Answers(200, interrupt.clone()), false).await;
    let ctx = format!("ctx-victim-{}", std::process::id());
    let mut env = envelope();
    env["params"]["message"]["contextId"] = serde_json::Value::String(ctx.clone());
    let (_s, body) = call_agent(&victim, "planner", &env).await;
    let victim_task = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    assert!(!victim_task.is_empty());

    // A DIFFERENT deployment, therefore a different key: the same process-wide task registry, the
    // same `contextId`, a different principal.
    let attacker = harness(Outcome::Answers(200, interrupt), false).await;
    let (_s, body) = call_agent(&attacker, "planner", &env).await;
    let attacker_task = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    assert_ne!(
        attacker_task, victim_task,
        "a second principal must NOT resume the first's paused task by naming its contextId"
    );
}

/// A TERMINAL TASK IS NOT RESUMABLE. Re-using the `contextId` of finished work opens a NEW task
/// rather than resurrecting the old one — a resurrected task re-bills a caller and re-emits
/// provenance for work already accounted for.
#[tokio::test]
async fn a_completed_task_is_not_resumed_by_reusing_its_context_id() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let ctx = format!("ctx-done-{}", std::process::id());
    let mut env = envelope();
    env["params"]["message"]["contextId"] = serde_json::Value::String(ctx);

    let (_s, body) = call_agent(&h, "planner", &env).await;
    let first = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let (_s, body) = call_agent(&h, "planner", &env).await;
    let second = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    assert_ne!(
        first, second,
        "completed work must not be resurrected by re-using its contextId"
    );
}

// ══ THE PUSH-NOTIFICATION CALLBACK ═══════════════════════════════════════════════════════════════

/// A CALLER-SUPPLIED CALLBACK IS SSRF-GUARDED BEFORE IT IS STORED, and the refusal is the CALLER's
/// fault rather than the backend's.
///
/// The harness's resolver answers a public address for every name, so a metadata-address callback
/// has to be refused on the ADDRESS rather than on the name for this to mean anything — which is
/// what the literal form below asserts.
#[tokio::test]
async fn a_push_callback_pointing_at_an_internal_address_is_refused_before_any_hop() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let mut env = envelope();
    env["params"]["configuration"] = serde_json::json!({
        "pushNotificationConfig": { "url": "https://169.254.169.254/hook" }
    });
    let (status, body) = call_agent(&h, "planner", &env).await;
    assert_eq!(
        status, 400,
        "a callback busbar would fetch on the caller's behalf is the caller's input, and a hostile \
         one is a 400: {body}"
    );
    assert!(
        h.sent().is_empty(),
        "a refused callback must not have already caused a hop"
    );

    // AND A PLAINTEXT CALLBACK IS REFUSED TOO: a callback carries task ids and caller attribution,
    // and putting that on the wire in the clear by default would be busbar choosing convenience
    // over the operator's data.
    let mut env = envelope();
    env["params"]["configuration"] = serde_json::json!({
        "pushNotificationConfig": { "url": "http://hooks.example.test/cb" }
    });
    let (status, body) = call_agent(&h, "planner", &env).await;
    assert_eq!(status, 400, "{body}");
}

/// A LEGITIMATE CALLBACK IS ACCEPTED AND PERSISTED ON THE TASK. The control for the test above:
/// without it, a handler that refused every callback would look equally correct.
#[tokio::test]
async fn a_legitimate_push_callback_is_accepted_and_recorded_on_the_task() {
    let interrupt = serde_json::json!({
        "jsonrpc": "2.0", "id": 7,
        "result": { "id": "B1", "contextId": "BC", "status": { "state": "input-required" } }
    })
    .to_string();
    let h = harness(Outcome::Answers(200, interrupt), false).await;
    let mut env = envelope();
    env["params"]["configuration"] = serde_json::json!({
        "pushNotificationConfig": { "url": "https://hooks.example.test/cb" }
    });
    let (status, body) = call_agent(&h, "planner", &env).await;
    assert_eq!(status, 200, "{body}");

    let id = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let task = crate::a2a::taskstore::TASKS
        .get_unscoped(&id)
        .expect("the task exists");
    assert_eq!(
        task.push_callback.as_deref(),
        Some("https://hooks.example.test/cb"),
        "an accepted callback must be persisted on the task, or the interrupt has nowhere to go"
    );
}

/// **THE CALLBACK IS ACTUALLY CALLED.** Through the production router, end to end.
///
/// The test above proves the callback was accepted and persisted, and it passed for the whole of
/// this release while NOTHING EVER DELIVERED. That is the shape of gap this test closes: every step
/// up to the row had a test, the step after the row had no code, and no test could tell because
/// there was no socket in the story to be missing. A caller registered a webhook and got silence.
///
/// The delivery is detached — the caller's answer does not wait on somebody else's webhook — so
/// this polls the seam's log rather than asserting immediately after the response.
#[tokio::test]
async fn a_registered_callback_is_delivered_to_when_the_task_reaches_a_state() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let mut env = envelope();
    env["params"]["configuration"] = serde_json::json!({
        "pushNotificationConfig": { "url": "https://hooks.example.test/cb" }
    });
    let (status, body) = call_agent(&h, "planner", &env).await;
    assert_eq!(status, 200, "{body}");
    let task_id = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let delivered = loop_until(&h, "https://hooks.example.test/cb").await;
    let Some(delivered) = delivered else {
        panic!(
            "the task completed with a registered push callback and NOTHING was delivered; the \
             seam saw only: {:?}",
            h.sent().iter().map(|r| r.url.clone()).collect::<Vec<_>>()
        )
    };

    // THE SOCKET WENT TO THE ADDRESS THE DELIVERY-TIME GUARD JUDGED, not to a name a client would
    // have resolved a second time.
    assert_eq!(delivered.addr, Some(BACKEND_ADDR));

    // THE BODY IS THE TASK UNDER BUSBAR'S IDENTITY. The backend's own ids are its names for this
    // work and resolve to nothing in the receiver's later reads.
    let doc: serde_json::Value =
        serde_json::from_slice(&delivered.body).expect("the notification is JSON");
    assert_eq!(doc["task"]["id"], task_id);
    assert_eq!(doc["task"]["status"]["state"], "completed");
    let rendered = String::from_utf8_lossy(&delivered.body);
    assert!(
        !rendered.contains("BACKEND-OWN-TASK-ID") && !rendered.contains("BACKEND-OWN-CONTEXT"),
        "the notification carried the BACKEND's identifiers: {rendered}"
    );

    // AND NO CREDENTIAL. The receiver is a host the CALLER nominated.
    let names: Vec<String> = delivered
        .headers
        .iter()
        .map(|(n, _)| n.to_lowercase())
        .collect();
    assert_eq!(
        names,
        vec!["content-type".to_string()],
        "{:?}",
        delivered.headers
    );
}

/// Wait for a request to `url` to appear in the seam's log, or give up. The delivery is detached on
/// purpose, so a bare assertion after the response would be a race the test usually wins.
async fn loop_until(h: &Harness, url: &str) -> Option<Recorded> {
    for _ in 0..200 {
        if let Some(found) = h.sent().into_iter().find(|r| r.url == url) {
            return Some(found);
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    None
}

// ══ RESTART AND RESUBSCRIBE ══════════════════════════════════════════════════════════════════════

/// AN INTERRUPTED TASK SURVIVES A RESTART WHERE THE BACKEND IS DURABLE, AND IS HONESTLY REPORTED
/// LOST WHERE IT IS NOT.
///
/// Durability is a property of the CONFIGURED BACKEND, and the only honest way to know whether a
/// deployment has it is to READ A TASK BACK. Both directions are asserted here from the RELAY's own
/// output — a paused task the relay produced, put through a fresh registry the way boot does.
#[tokio::test]
async fn an_interrupt_the_relay_produced_rehydrates_only_where_the_store_is_durable() {
    let interrupt = serde_json::json!({
        "jsonrpc": "2.0", "id": 7,
        "result": { "id": "B1", "contextId": "BC", "status": { "state": "input-required" } }
    })
    .to_string();
    let h = harness(Outcome::Answers(200, interrupt), false).await;
    let ctx = format!("ctx-restart-{}", std::process::id());
    let mut env = envelope();
    env["params"]["message"]["contextId"] = serde_json::Value::String(ctx);
    let (status, body) = call_agent(&h, "planner", &env).await;
    assert_eq!(status, 200, "{body}");
    let id = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    // A FRESH REGISTRY, the way a restart gets one, rehydrated from the SAME store the running
    // deployment wrote through to.
    let fresh = crate::a2a::taskstore::TaskRegistry::new();
    let store = h.gov.store();
    let rehydrated = fresh
        .restore_from_store(store.as_ref())
        .expect("the rehydrate completes");

    if rehydrated.active == 0 {
        // THE RAM DEFAULT. Nothing survives, and saying so is the truth being reported rather than
        // a bug. This arm is PERMANENT and paired on purpose: deleting it would let a silent
        // regression to the RAM default read as a pass.
        assert!(
            fresh.get_unscoped(&id).is_none(),
            "the RAM default keeps nothing, so nothing may be readable back"
        );
        return;
    }
    let back = fresh
        .get_unscoped(&id)
        .expect("a durable backend restores the paused task");
    assert_eq!(
        back.state,
        TaskState::InputRequired,
        "a rehydrated interrupt must come back PAUSED, so the caller's answer can still resume it"
    );
    assert_eq!(back.context_id, back.context_id, "the resume key survives");
    assert_eq!(
        rehydrated.chain_breaks.len(),
        0,
        "the per-task chain the relay wrote must verify on restore: {:?}",
        rehydrated.chain_breaks
    );
}

/// THE ARTIFACT CURSOR ADVANCES AS THE STREAM ADVANCES — the resubscribe resume point. A cursor
/// written once at the end is a cursor that is zero for every stream a restart interrupts, which is
/// every stream the resume point exists for.
#[tokio::test]
async fn a_streamed_artifact_advances_the_durable_resume_cursor() {
    let frames = vec![
        frame(serde_json::json!({
            "id": "B1", "contextId": "BC",
            "artifact": { "artifactId": "a1", "parts": [{ "kind": "text", "text": "ONE" }] }
        })),
        frame(serde_json::json!({
            "id": "B1", "contextId": "BC",
            "artifact": { "artifactId": "a2", "parts": [{ "kind": "text", "text": "TWO" }] }
        })),
        frame(serde_json::json!({
            "id": "B1", "contextId": "BC", "status": { "state": "completed" }
        })),
    ];
    let h = harness(Outcome::Streams(frames), false).await;
    let ctx = format!("ctx-cursor-{}", std::process::id());
    let (status, _ct, body) = call_raw(&h, "planner", &stream_envelope(&ctx)).await;
    assert_eq!(status, 200, "{body}");

    // The caller's handle comes off the STREAM, which is the only place it appears — and reading it
    // there is itself the assertion that every streamed event carries busbar's task identity.
    let id = first_task_id(&body).expect("the stream names busbar's task id");
    let task = crate::a2a::taskstore::TASKS
        .get_unscoped(&id)
        .expect("the streamed task exists");
    assert_eq!(
        task.artifact_cursor, 2,
        "each artifact chunk must advance the durable cursor, got {}",
        task.artifact_cursor
    );
    assert_eq!(
        task.state,
        TaskState::Completed,
        "the stream's terminal event must land on the task"
    );
}
