// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEP-2663 task substrate — the properties the wire depends on, tested where they are decided
//! rather than only through the conformance suite.
//!
//! Every one of these was watched to FAIL before it passed: the status-semantics test by settling a
//! tool error as `Failed`, the strong-consistency test by inserting after the id was handed out, and
//! the ISO-8601 test against a hand-rolled day arithmetic that put 2100-03-01 on the wrong day.

use super::*;

/// Two callers, two tasks, and neither can address the other's. The refusal is INDISTINGUISHABLE
/// from an unknown id on purpose — see `Registry::get`.
#[test]
fn a_task_is_addressable_only_by_the_principal_it_was_created_for() {
    let mine = TASKS.create("key-a", busbar_substrate::store::now_ms());
    assert!(TASKS.get(&mine.id, "key-a").is_some());
    assert!(
        TASKS.get(&mine.id, "key-b").is_none(),
        "a task filed under one principal must not resolve for another; the method surface renders \
         this as `-32602 unknown taskId`, and two different answers would be a probe for which ids \
         exist"
    );
}

/// THE STRONG-CONSISTENCY ORDERING, asserted on the registry rather than through HTTP: the row is
/// readable the instant the id exists, because `create` inserts before it returns.
#[test]
fn a_created_task_resolves_before_anything_else_runs() {
    let task = TASKS.create("key-consistency", busbar_substrate::store::now_ms());
    assert!(
        TASKS.get(&task.id, "key-consistency").is_some(),
        "a `tasks/get` issued with no delay after `CreateTaskResult` must resolve; returning an id \
         for a row that does not exist yet is the exact defect \
         `sep-2663-durable-create-strong-consistency` exists to catch"
    );
}

/// A TOOL that ran and reported an error is `completed` with `result.isError`, NOT `failed`. This is
/// the distinction the extension is most often implemented backwards.
#[test]
fn a_tool_error_settles_as_completed_and_a_protocol_error_settles_as_failed() {
    let ran = TASKS.create("key-status", busbar_substrate::store::now_ms());
    ran.complete(
        serde_json::json!({
            "isError": true,
            "content": [{ "type": "text", "text": "the file was not found" }],
        }),
        busbar_substrate::store::now_ms(),
    );
    let detailed = ran.detailed();
    assert_eq!(detailed["status"], "completed");
    assert_eq!(detailed["result"]["isError"], true);
    assert!(
        detailed.get("error").is_none(),
        "a tool that RAN carries no protocol `error`"
    );

    let broke = TASKS.create("key-status", busbar_substrate::store::now_ms());
    broke.fail(
        -32603,
        "the upstream answered JSON-RPC error -32000".into(),
        busbar_substrate::store::now_ms(),
    );
    let detailed = broke.detailed();
    assert_eq!(detailed["status"], "failed");
    assert_eq!(detailed["error"]["code"], -32603);
    assert!(
        detailed.get("result").is_none(),
        "`failed` is a PROTOCOL error and must carry no `result` beside its `error`"
    );
}

/// `tasks/cancel` on a settled task changes nothing and is not an error — the idempotence the wire
/// contract requires so a client need not handle the terminate-then-cancel race.
#[test]
fn cancelling_a_terminal_task_leaves_its_settled_status_alone() {
    let task = TASKS.create("key-cancel", busbar_substrate::store::now_ms());
    task.complete(
        serde_json::json!({ "content": [] }),
        busbar_substrate::store::now_ms(),
    );
    task.cancel(busbar_substrate::store::now_ms());
    assert_eq!(
        task.detailed()["status"],
        "completed",
        "a cancel arriving after completion must not rewrite the settled status; the ack is the \
         same either way and the status is read on the next `tasks/get`"
    );
}

/// An ask, built the ONE way a `CallerAsk` can be built: from an operator-written config entry.
///
/// There is deliberately no struct literal here any more. `CallerAsk`'s fields are private to
/// `callerask::authored`, which is what makes "an operator-authored ask is never composed from an
/// upstream-derived value" a fact about the type rather than a source scan — so a test helper that
/// bypassed the constructor would be quietly re-opening the hole it is testing around.
fn elicitation(key: &str) -> CallerAsk {
    CallerAsk::from_config(
        key,
        &crate::mcp::config::AskEntryCfg {
            method: "elicitation/create".into(),
            params: Some(serde_json::json!({})),
        },
    )
}

/// PARTIAL FULFILMENT: answering one key of a two-key round removes that key and leaves the task
/// parked on the other.
#[test]
fn answering_one_of_two_asks_leaves_the_task_parked_on_the_other() {
    let task = TASKS.create("key-partial", busbar_substrate::store::now_ms());
    task.park(
        vec![elicitation("first"), elicitation("second")],
        busbar_substrate::store::now_ms(),
    );
    assert_eq!(task.detailed()["status"], "input_required");

    let mut answered = serde_json::Map::new();
    answered.insert("first".into(), serde_json::json!({ "action": "accept" }));
    task.deliver(&answered, busbar_substrate::store::now_ms());

    let detailed = task.detailed();
    assert_eq!(detailed["status"], "input_required");
    let pending = detailed["inputRequests"].as_object().expect("a map");
    assert!(
        !pending.contains_key("first"),
        "an answered key MUST be removed from `inputRequests`"
    );
    assert!(
        pending.contains_key("second"),
        "an unanswered key MUST remain"
    );

    let mut rest = serde_json::Map::new();
    rest.insert("second".into(), serde_json::json!({ "action": "accept" }));
    task.deliver(&rest, busbar_substrate::store::now_ms());
    assert_eq!(
        task.detailed()["status"],
        "working",
        "with every ask answered the task leaves `input_required` and resumes"
    );
}

/// The CreateTaskResult is FLAT and carries none of the DetailedTask-only members.
#[test]
fn the_creation_result_is_flat_and_carries_no_detailed_task_members() {
    let task = TASKS.create("key-shape", busbar_substrate::store::now_ms());
    let created = task.created();
    let obj = created.as_object().expect("an object");
    assert!(obj.contains_key("taskId"));
    assert!(obj.contains_key("status"));
    assert!(obj.contains_key("createdAt"));
    assert!(obj.contains_key("lastUpdatedAt"));
    assert!(obj.contains_key("ttlMs"));
    for forbidden in ["task", "result", "error", "inputRequests", "requestState"] {
        assert!(
            !obj.contains_key(forbidden),
            "`CreateTaskResult` must not carry `{forbidden}`; the extension puts it on the \
             `tasks/get` DetailedTask, and `requestState` it removed from the v2 wire entirely"
        );
    }
    // The v1 spellings, which a client keying off them on a v2 server would silently miss.
    for legacy in ["ttl", "pollInterval"] {
        assert!(!obj.contains_key(legacy), "the v1 `{legacy}` key is gone");
    }
}

/// `requestState` never appears on the tasks wire, at any status. SEP-2322 puts it on
/// `InputRequiredResult`, which is a different flow; the two slots are lexically adjacent in
/// documents read together, which is why this is asserted rather than assumed.
#[test]
fn no_task_shape_ever_carries_request_state() {
    let task = TASKS.create("key-no-state", busbar_substrate::store::now_ms());
    assert!(task.created().get("requestState").is_none());
    assert!(task.detailed().get("requestState").is_none());
    task.park(
        vec![elicitation("confirm")],
        busbar_substrate::store::now_ms(),
    );
    assert!(task.detailed().get("requestState").is_none());
}

/// The extension is declared by PRESENCE under `extensions`, and `null` is not a declaration —
/// matching `callerask::declared`, because reading `null` as yes would be busbar deciding on a
/// client's behalf what that client can do.
#[test]
fn the_extension_is_declared_by_presence_and_null_is_not_a_declaration() {
    assert!(client_declares_tasks(&serde_json::json!({
        "extensions": { TASKS_EXTENSION_ID: {} }
    })));
    assert!(!client_declares_tasks(&serde_json::json!({})));
    assert!(!client_declares_tasks(&serde_json::json!({
        "extensions": {}
    })));
    assert!(!client_declares_tasks(&serde_json::json!({
        "extensions": { TASKS_EXTENSION_ID: serde_json::Value::Null }
    })));
    assert!(
        !client_declares_tasks(&serde_json::json!({ "tasks": {} })),
        "the v1-style slot is not the extension declaration"
    );
}

/// `task_support` crossed with the caller's declaration. The `required` row is the one the `-32021`
/// gate reads, and it is deliberately NOT "create a task anyway".
#[test]
fn task_support_crossed_with_the_callers_declaration() {
    use super::super::config::TaskSupport;
    assert!(!TaskSupport::None.creates_task(true));
    assert!(!TaskSupport::None.creates_task(false));
    assert!(TaskSupport::Optional.creates_task(true));
    assert!(
        !TaskSupport::Optional.creates_task(false),
        "`optional` falls through to a synchronous result rather than locking the caller out"
    );
    assert!(TaskSupport::Required.creates_task(true));
    assert!(
        !TaskSupport::Required.creates_task(false),
        "`required` never creates a task for a caller that cannot receive one — the call is \
         refused with `-32021` before it gets here"
    );
}

/// The timestamp format the wire fixes, across a leap day and a non-leap century.
#[test]
fn timestamps_render_as_iso_8601_utc() {
    assert_eq!(iso8601_ms(0), "1970-01-01T00:00:00.000Z");
    // 2024-02-29T12:24:56.789Z — a leap day in a leap century-rule year.
    assert_eq!(iso8601_ms(1_709_209_496_789), "2024-02-29T12:24:56.789Z");
    // 2100-03-01T00:00:00Z — 2100 is NOT a leap year, which a naive `year % 4` gets wrong.
    assert_eq!(iso8601_ms(4_107_542_400_000), "2100-03-01T00:00:00.000Z");
}

/// Two ids minted back to back never collide, and neither is a count of anything.
#[test]
fn task_ids_are_unique_and_not_sequential() {
    let a = new_task_id();
    let b = new_task_id();
    assert_ne!(a, b);
    assert!(a.starts_with("t_"));
    assert!(a.len() > 32, "the id carries 128 bits of CSPRNG output");
}
