// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar's task identity on a relayed hop, against the served engine's own cases
//! (`busbar-a2a` `relay::rewrite_identity`, `idmap::translate_request`, `rpcerror::about_task`).

use super::*;
use serde_json::json;

#[test]
fn a_minted_id_is_the_engines_shape_over_the_random_bytes() {
    let id = mint("planner", [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    assert_eq!(id, "a2a-planner-0123456789abcdef");
    assert_eq!(mint("p", [0; MINT_BYTES]), "a2a-p-0000000000000000");
}

#[test]
fn a_bare_task_result_takes_busbars_id_and_context_and_keeps_everything_else() {
    let mut result = json!({
        "kind": "task", "id": "backend-7", "contextId": "backend-ctx",
        "status": { "state": "completed" }, "artifacts": [{ "parts": [] }],
    });
    rewrite_identity(&mut result, "a2a-p-1", "ctx-1", None);
    assert_eq!(
        result,
        json!({
            "kind": "task", "id": "a2a-p-1", "contextId": "ctx-1",
            "status": { "state": "completed" }, "artifacts": [{ "parts": [] }],
        })
    );
}

#[test]
fn a_wrapped_result_is_rewritten_inside_its_wrapper_by_its_own_identity_member() {
    let mut task = json!({ "task": { "id": "b", "contextId": "bc" } });
    rewrite_identity(&mut task, "t", "c", None);
    assert_eq!(task, json!({ "task": { "id": "t", "contextId": "c" } }));

    let mut update = json!({ "statusUpdate": { "taskId": "b", "contextId": "bc",
        "status": { "message": { "taskId": "b", "contextId": "bc", "messageId": "m" } } } });
    rewrite_identity(&mut update, "t", "c", None);
    assert_eq!(
        update,
        json!({ "statusUpdate": { "taskId": "t", "contextId": "c",
            "status": { "message": { "taskId": "t", "contextId": "c", "messageId": "m" } } } })
    );
}

#[test]
fn a_standalone_message_is_given_no_task_and_one_in_a_task_is_given_busbars() {
    let mut alone = json!({ "message": { "messageId": "m", "contextId": "bc" } });
    rewrite_identity(&mut alone, "t", "c", None);
    assert_eq!(
        alone,
        json!({ "message": { "messageId": "m", "contextId": "c" } })
    );
    let mut owned = json!({ "message": { "messageId": "m", "taskId": "b" } });
    rewrite_identity(&mut owned, "t", "c", None);
    assert_eq!(
        owned,
        json!({ "message": { "messageId": "m", "taskId": "t", "contextId": "c" } })
    );
}

#[test]
fn the_matched_skill_is_namespaced_metadata_and_a_non_object_result_becomes_a_task() {
    let mut result = json!({ "id": "b", "metadata": { "theirs": 1 } });
    rewrite_identity(&mut result, "t", "c", Some("summarize"));
    assert_eq!(
        result,
        json!({ "id": "t", "contextId": "c",
            "metadata": { "theirs": 1, "busbar/skill": "summarize" } })
    );
    let mut scalar = json!("done");
    rewrite_identity(&mut scalar, "t", "c", None);
    assert_eq!(
        scalar,
        json!({ "kind": "task", "id": "t", "contextId": "c" })
    );
}

#[test]
fn the_far_ends_id_and_state_are_read_in_both_vocabularies() {
    assert_eq!(
        backend_task_id(&json!({ "task": { "id": "b-1" } })).as_deref(),
        Some("b-1")
    );
    assert_eq!(
        backend_task_id(&json!({ "statusUpdate": { "taskId": "b-2" } })).as_deref(),
        Some("b-2")
    );
    assert_eq!(backend_task_id(&json!({ "id": "" })), None);
    assert_eq!(
        reported_task_state(&json!({ "status": { "state": "input-required" } })),
        TaskState::InputRequired
    );
    assert_eq!(
        reported_task_state(&json!({ "task": { "status": { "state": "TASK_STATE_COMPLETED" } } })),
        TaskState::Completed
    );
    assert_eq!(
        reported_task_state(&json!({ "status": { "state": "pondering" } })),
        TaskState::Working
    );
}

#[test]
fn a_held_id_is_translated_at_the_top_and_in_the_message_and_nothing_else_is() {
    let back = |id: &str| (id == "a2a-p-1").then(|| "b-1".to_string());
    let get =
        json!({ "jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": { "id": "a2a-p-1" } });
    let sent: Value = serde_json::from_slice(&translate_request(&get, &back).unwrap()).unwrap();
    assert_eq!(sent["params"]["id"], "b-1");

    let turn = json!({ "jsonrpc": "2.0", "id": 2, "method": "SendMessage",
        "params": { "message": { "messageId": "a2a-p-1", "taskId": "a2a-p-1" } } });
    let sent: Value = serde_json::from_slice(&translate_request(&turn, &back).unwrap()).unwrap();
    assert_eq!(sent["params"]["message"]["taskId"], "b-1");
    assert_eq!(sent["params"]["message"]["messageId"], "a2a-p-1");

    let foreign =
        json!({ "jsonrpc": "2.0", "id": 3, "method": "GetTask", "params": { "id": "x" } });
    assert_eq!(translate_request(&foreign, &back), None);
}

#[test]
fn the_named_tasks_and_context_are_read_where_the_engine_reads_them() {
    let env = json!({ "params": { "id": "a", "taskId": "b", "task_id": "c",
        "message": { "taskId": "d", "contextId": "ctx" } } });
    assert_eq!(named_tasks(&env), vec!["a", "b", "c"]);
    assert_eq!(translatable(&env), vec!["a", "b", "c", "d"]);
    assert_eq!(context_of(&env), "ctx");
    assert_eq!(context_of(&json!({ "params": {} })), "");
}

#[test]
fn a_refusal_about_a_task_carries_its_resource_info_after_the_error_info() {
    let refusal = Refusal {
        status: 502,
        id: Some(json!(9)),
        code: -32006,
        message: "the backend agent did not complete this task".into(),
    };
    assert_eq!(
        about_task(&refusal, "a2a-p-1"),
        json!({
            "jsonrpc": "2.0", "id": 9,
            "error": {
                "code": -32006,
                "message": "the backend agent did not complete this task",
                "data": [
                    { "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                      "domain": "a2a-protocol.org", "reason": "INVALID_AGENT_RESPONSE" },
                    { "@type": "type.googleapis.com/google.rpc.ResourceInfo",
                      "resourceType": "a2a.busbar/task", "resourceName": "a2a-p-1" },
                ],
            },
        })
    );
}

#[test]
fn the_codes_a_far_end_may_answer_keep_section_5_4s_statuses() {
    assert_eq!(status_of_code(-32001), Some(404));
    assert_eq!(status_of_code(-32002), Some(409));
    assert_eq!(status_of_code(-32005), Some(415));
    assert_eq!(status_of_code(-32602), Some(400));
    assert_eq!(status_of_code(-32603), Some(500));
    assert_eq!(status_of_code(-32050), None);
}
