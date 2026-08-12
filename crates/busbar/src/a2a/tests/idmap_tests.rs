// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the inverse of the identity substitution.

use super::*;
use serde_json::json;

/// A busbar id nothing has recorded is forwarded UNCHANGED — as the caller's own bytes, not as a
/// re-serialization. That is the common path and it is the one that must not touch the payload.
#[test]
fn a_request_naming_no_known_task_is_not_rewritten_at_all() {
    assert!(translate_request(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "GetTask",
        "params": { "id": "a-task-nothing-has-seen" }
    }))
    .is_none());
    // No `params` at all, and `params` that is not an object.
    assert!(translate_request(&json!({ "method": "GetTask" })).is_none());
    assert!(translate_request(&json!({ "params": [1, 2, 3] })).is_none());
}

/// THE DEFECT, in one test: busbar hands a caller its own task id, and must be able to resolve it.
#[test]
fn the_id_busbar_issued_is_translated_back_to_the_one_the_backend_knows() {
    remember("a2a-planner-busbar", "backend-019ff");
    let out = translate_request(&json!({
        "jsonrpc": "2.0", "id": 4, "method": "GetTask",
        "params": { "id": "a2a-planner-busbar", "historyLength": 3 }
    }))
    .expect("a known id must be translated");
    let doc: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(doc["params"]["id"], "backend-019ff");
    // EVERYTHING ELSE SURVIVES. The translation is about identity and about nothing else.
    assert_eq!(doc["params"]["historyLength"], 3);
    assert_eq!(doc["method"], "GetTask");
    assert_eq!(doc["id"], 4);
    assert_eq!(doc["jsonrpc"], "2.0");
}

/// The verbs that are ABOUT a task name it `taskId` (and A2A v1.0's JSON-RPC binding also accepts
/// `task_id`). All three spellings translate, or the push-config verbs stay broken.
#[test]
fn every_spelling_of_the_task_member_is_translated() {
    remember("busbar-t", "backend-t");
    for member in ["id", "taskId", "task_id"] {
        let out = translate_request(&json!({
            "method": "GetTaskPushNotificationConfig",
            "params": { member: "busbar-t" }
        }))
        .unwrap_or_else(|| panic!("`{member}` must translate"));
        let doc: serde_json::Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(doc["params"][member], "backend-t");
    }
}

/// A long-running task streams many events and re-records the same pair each time. Re-recording
/// must not re-order the map, or one chatty task evicts every other one.
#[test]
fn re_recording_the_same_pair_does_not_churn_the_map() {
    remember("stable-busbar", "stable-backend");
    for _ in 0..1000 {
        remember("stable-busbar", "stable-backend");
    }
    assert_eq!(
        backend_id_for("stable-busbar").as_deref(),
        Some("stable-backend")
    );
    assert_eq!(
        table()
            .order
            .iter()
            .filter(|k| *k == "stable-busbar")
            .count(),
        1
    );
}

/// Nothing degenerate is recorded: an empty half is not an identity, and a backend that issued the
/// same id busbar did needs no translation and must not occupy a slot.
#[test]
fn a_degenerate_pair_is_not_recorded() {
    remember("", "x");
    remember("y", "");
    remember("same", "same");
    assert!(backend_id_for("").is_none());
    assert!(backend_id_for("y").is_none());
    assert!(backend_id_for("same").is_none());
}

/// THE SECOND TURN'S TASK ID IS NOT AT THE TOP OF `params`, AND IT IS STILL TRANSLATED.
///
/// `SendMessage` names an already-open task at `params.message.taskId`. Only the top-level members
/// were translated, so busbar's own id went to a backend that had never issued it and every
/// multi-turn exchange died on its second message. The official TCK reported that, in the backend's
/// own words on the wire, as:
///
/// ```text
/// {"error":{"code":-32001,"message":"Task a2a-conformance-e3856b026ee67352 not found"}}
/// ```
///
/// against `CORE-HIST-002`, `CORE-MULTI-005` and `PUSH-DELIVER-001/002/003`. It could not be seen
/// until the conformance rig's fronted agent could leave a task open across turns.
#[test]
fn the_task_id_inside_a_message_is_translated() {
    remember("busbar-turn-1", "backend-turn-1");
    let envelope = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "SendMessage",
        "params": {
            "message": {
                "role": "ROLE_USER",
                "messageId": "m-2",
                "taskId": "busbar-turn-1",
                "parts": [{"text": "the second turn"}]
            }
        }
    });
    let out = translate_request(&envelope).expect("a message-nested task id is a translation");
    let out: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    assert_eq!(
        out.pointer("/params/message/taskId")
            .and_then(|v| v.as_str()),
        Some("backend-turn-1"),
        "the backend must be asked about the id IT issued"
    );
    assert_eq!(
        out.pointer("/params/message/messageId")
            .and_then(|v| v.as_str()),
        Some("m-2"),
        "nothing else in the message may be touched"
    );
}

/// A MESSAGE'S OWN `id` IS NOT A TASK ID and must never be rewritten as one — a translation that
/// reached for every member called `id` would corrupt an identity this map knows nothing about.
#[test]
fn a_messages_own_id_member_is_left_alone() {
    remember("busbar-not-a-message-id", "backend-x");
    let envelope = serde_json::json!({
        "params": { "message": { "id": "busbar-not-a-message-id" } }
    });
    assert!(
        translate_request(&envelope).is_none(),
        "a message's `id` is not a task id and nothing may be translated from it"
    );
}
