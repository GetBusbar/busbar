// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One relayed event, read as the served engine reads it: busbar's identity on it, its id
//! correlated, its state and artifact read through either shape, anything else passed through.

use super::*;
use serde_json::json;

/// A far end's frame answering request 11 with `result`.
fn frame_of(result: Value) -> String {
    format!(
        "data: {}\n\n",
        json!({ "jsonrpc": "2.0", "id": 11, "result": result })
    )
}

fn data_of(sse: &[u8]) -> Value {
    let text = std::str::from_utf8(sse).unwrap();
    serde_json::from_str(text.strip_prefix("data: ").unwrap().trim_end()).unwrap()
}

/// An event leaves under busbar's identity, with the matched skill; the far end's own ids are read
/// first and never reach the caller.
#[test]
fn an_event_leaves_under_busbars_identity() {
    let ev = read_event(
        &frame_of(json!({
            "id": "BACKEND-OWN-TASK-ID",
            "contextId": "BACKEND-OWN-CONTEXT",
            "kind": "status-update",
            "status": { "state": "working" }
        })),
        &json!(11),
        "busbar-task-1",
        "ctx-mine",
        Some("plan"),
    )
    .expect("correlated");
    let doc = data_of(&ev.sse);
    assert_eq!(doc["id"], 11);
    assert_eq!(doc["result"]["id"], "busbar-task-1");
    assert_eq!(doc["result"]["contextId"], "ctx-mine");
    assert_eq!(doc["result"]["metadata"]["busbar/skill"], "plan");
    let rendered = String::from_utf8(ev.sse).unwrap();
    assert!(!rendered.contains("BACKEND-OWN"), "{rendered}");
    assert_eq!(ev.state, Some(TaskState::Working));
    assert_eq!(ev.backend_task_id.as_deref(), Some("BACKEND-OWN-TASK-ID"));
    assert!(!ev.artifact);
}

/// The v1.0 wrappers are read through: a status update's state and an artifact update's chunk.
#[test]
fn a_wrapped_event_reports_its_state_and_its_artifact() {
    let status = read_event(
        &frame_of(json!({ "statusUpdate": {
            "taskId": "far-1", "contextId": "c", "status": { "state": "TASK_STATE_INPUT_REQUIRED" }
        } })),
        &json!(11),
        "t",
        "c",
        None,
    )
    .unwrap();
    assert_eq!(status.state, Some(TaskState::InputRequired));
    assert_eq!(status.backend_task_id.as_deref(), Some("far-1"));
    assert_eq!(
        data_of(&status.sse)["result"]["statusUpdate"]["taskId"],
        "t"
    );

    let chunk = read_event(
        &frame_of(json!({ "artifactUpdate": { "taskId": "far-1", "artifact": { "parts": [] } } })),
        &json!(11),
        "t",
        "c",
        None,
    )
    .unwrap();
    assert!(chunk.artifact);
    assert_eq!(chunk.state, None, "an artifact reports no state");
}

/// A keep-alive, a comment and a frame that is not JSON pass byte for byte, read as nothing.
#[test]
fn a_frame_that_is_not_a_response_passes_through_byte_for_byte() {
    for passed in [
        ": keep-alive\n\n",
        "data: not json\n\n",
        "data: {\"x\":1}\n\n",
    ] {
        let ev = read_event(passed, &json!(11), "t", "c", None).unwrap();
        assert_eq!(ev.sse, passed.as_bytes(), "{passed:?}");
        assert_eq!((ev.state, ev.artifact), (None, false));
    }
}

/// A frame answering another request refuses the hop; an `error` frame is relayed under the
/// caller's id as it stands.
#[test]
fn an_uncorrelated_frame_is_refused_and_an_error_frame_relayed() {
    let other = "data: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n\n";
    assert!(read_event(other, &json!(11), "t", "c", None).is_err());

    let error =
        "data: {\"jsonrpc\":\"2.0\",\"id\":11,\"error\":{\"code\":-32603,\"message\":\"x\"}}\n\n";
    let ev = read_event(error, &json!(11), "t", "c", None).unwrap();
    let doc = data_of(&ev.sse);
    assert_eq!(doc["error"]["code"], -32603);
    assert_eq!(doc["id"], 11);
    assert_eq!(ev.state, None);
}

/// An HTTP+JSON far end's frame carries the bare event: it is wrapped as the result of the caller's
/// request so the one reader reads it; a frame with no JSON payload passes as it is.
#[test]
fn a_bare_event_is_wrapped_as_the_result_of_the_request() {
    let wrapped = rewrap(
        "data: {\"kind\":\"status-update\"}\n\n".to_string(),
        &json!("rest"),
    );
    let doc = data_of(wrapped.as_bytes());
    assert_eq!(
        doc,
        json!({ "jsonrpc": "2.0", "id": "rest", "result": { "kind": "status-update" } })
    );
    assert_eq!(rewrap(": ping\n\n".to_string(), &json!(1)), ": ping\n\n");
}

/// The HTTP+JSON line answers each event's bare result; an error frame and a keep-alive pass, and
/// each line keeps its own terminator.
#[test]
fn the_target_line_answers_each_events_bare_result() {
    let events = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"a\":1}}\r\n\r\n: ping\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1}}\n\n";
    assert_eq!(
        String::from_utf8(reframe_events(events)).unwrap(),
        "data: {\"a\":1}\r\n\r\n: ping\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1}}\n\n"
    );
}
