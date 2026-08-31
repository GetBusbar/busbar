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

/// A WORKER SHUTDOWN routes through the SAME cancel transition a caller-issued `tasks/cancel`
/// takes: the runner's outer frame observes the shutdown watch, writes the `cancelled` terminal
/// status, and emits the audit record exactly once — a shutdown-aborted long task is never a
/// caller polling for ever over a row stuck at `working`.
#[tokio::test(flavor = "current_thread")]
async fn a_shutdown_settles_a_working_task_as_cancelled_and_audits_it_once() {
    let task = TASKS.create("key-shutdown", busbar_substrate::store::now_ms());
    let (tx, rx) = tokio::sync::watch::channel(false);
    let audited = std::cell::Cell::new(0u32);
    let settle = settle_or_cancel_on_shutdown(
        &task,
        Some(rx),
        // The long-running task: work that will not finish on its own within any grace.
        std::future::pending::<()>(),
        busbar_substrate::store::now_ms,
        |id| {
            assert_eq!(id, task.id, "the audit record names the task it cancelled");
            audited.set(audited.get() + 1);
        },
    );
    let fire = async {
        // Let the settle arm park on the watch first, then fire the shutdown level — the order
        // the composition root produces (the runner is long since spawned when drain begins).
        tokio::task::yield_now().await;
        let _ = tx.send(true);
    };
    tokio::join!(settle, fire);
    assert_eq!(
        task.detailed()["status"],
        "cancelled",
        "a shutdown-dropped runner must leave the SAME terminal status a `tasks/cancel` writes"
    );
    assert_eq!(audited.get(), 1, "the cancel is audited exactly once");
}

/// A task that COMPLETED before the shutdown arm ran keeps its settled status: the shutdown-time
/// cancel is the same CAS-guarded `McpTask::cancel` the verb calls, so it neither rewrites the
/// terminal state nor emits a spurious audit record.
#[tokio::test(flavor = "current_thread")]
async fn a_completion_that_beat_the_shutdown_keeps_its_status_and_is_not_audited_again() {
    let task = TASKS.create("key-shutdown-complete", busbar_substrate::store::now_ms());
    task.complete(
        serde_json::json!({ "content": [] }),
        busbar_substrate::store::now_ms(),
    );
    let (tx, rx) = tokio::sync::watch::channel(false);
    let _ = tx.send(true); // shutdown already fired when the arm runs
    settle_or_cancel_on_shutdown(
        &task,
        Some(rx),
        std::future::pending::<()>(),
        busbar_substrate::store::now_ms,
        |_| panic!("a task that completed must not get a shutdown-cancel audit record"),
    )
    .await;
    assert_eq!(
        task.detailed()["status"],
        "completed",
        "the shutdown arm must never rewrite a terminal status"
    );
}

/// A caller-issued cancel RACING the shutdown-issued one stays a single terminal transition with a
/// single audit record: whichever ran first won the CAS under the task lock, and the loser's
/// `cancel` returns `false` so its audit closure never fires.
#[tokio::test(flavor = "current_thread")]
async fn a_caller_cancel_racing_the_shutdown_yields_one_transition_and_one_audit() {
    let task = TASKS.create("key-shutdown-race", busbar_substrate::store::now_ms());
    // The caller's `tasks/cancel` lands first (the verb path audits it on its own).
    assert!(TASKS
        .cancel(
            &task.id,
            "key-shutdown-race",
            busbar_substrate::store::now_ms()
        )
        .is_some());
    let (tx, rx) = tokio::sync::watch::channel(false);
    let _ = tx.send(true);
    settle_or_cancel_on_shutdown(
        &task,
        Some(rx),
        std::future::pending::<()>(),
        busbar_substrate::store::now_ms,
        |_| panic!("the shutdown arm lost the CAS and must not emit a second audit record"),
    )
    .await;
    assert_eq!(task.detailed()["status"], "cancelled");
}

/// The runner's own work finishing FIRST is the whole of normal life: the inner future wrote its
/// terminal status and the shutdown arm never ran. `None` (no watch registered — a non-worker
/// thread) is the same statement made structurally: the arm can never fire at all.
#[tokio::test(flavor = "current_thread")]
async fn the_inner_work_finishing_first_leaves_the_shutdown_arm_unrun() {
    let task = TASKS.create("key-shutdown-none", busbar_substrate::store::now_ms());
    settle_or_cancel_on_shutdown(
        &task,
        None,
        async {
            task.complete(
                serde_json::json!({ "content": [] }),
                busbar_substrate::store::now_ms(),
            );
        },
        busbar_substrate::store::now_ms,
        |_| panic!("no shutdown fired, so no cancel may be audited"),
    )
    .await;
    assert_eq!(task.detailed()["status"], "completed");
}

/// `McpTask::cancel` reports whether THIS call made the transition — the guard the shutdown arm's
/// single-audit property rests on.
#[test]
fn cancel_reports_the_transition_it_made_and_only_that_one() {
    let task = TASKS.create("key-cancel-cas", busbar_substrate::store::now_ms());
    assert!(
        task.cancel(busbar_substrate::store::now_ms()),
        "the first cancel of a working task performs the transition"
    );
    assert!(
        !task.cancel(busbar_substrate::store::now_ms()),
        "a second cancel finds the task terminal and reports no transition"
    );
}

/// THE ABANDONMENT CEILING (the missing age bound on ACTIVE tasks): an active task whose last
/// update is older than `ACTIVE_TASK_ABANDON_MS` is CANCELLED by the create-time sweep — through
/// the normal `cancel` transition, never a drop — and then rides the ordinary terminal TTL out of
/// the working set; a younger active task is untouched. Over a LOCAL `Registry` (not the process
/// global) because the clock here is driven a day into the future, which would abandon every
/// concurrently running test's live task.
#[test]
fn an_abandoned_active_task_is_cancelled_by_the_sweep_and_then_ages_out() {
    let reg = Registry {
        tasks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };
    let t0 = 1_000_000_u64;
    let old = reg.create("key-abandon", t0);
    // Exactly AT the ceiling is not abandoned (the bound is strict, matching `is_expired`).
    let young = reg.create("key-abandon", t0 + ACTIVE_TASK_ABANDON_MS);
    let sweep_now = t0 + ACTIVE_TASK_ABANDON_MS + 1;
    let _trigger = reg.create("key-abandon", sweep_now);
    assert_eq!(
        old.detailed()["status"],
        "cancelled",
        "an active task a day beyond its last update is cancelled by the sweep, not dropped"
    );
    assert!(
        reg.get(&old.id, "key-abandon").is_some(),
        "the cancelled task is still pollable — abandonment is a transition into the normal \
         terminal retention window, not an eviction"
    );
    assert_eq!(
        young.detailed()["status"],
        "working",
        "an active task at (not past) the ceiling is untouched"
    );
    // The cancel stamped `updated_ms = sweep_now`, so the ordinary terminal TTL now applies.
    let _later = reg.create("key-abandon", sweep_now + TASK_TTL_MS + 1);
    assert!(
        reg.get(&old.id, "key-abandon").is_none(),
        "after the terminal TTL the abandoned-then-cancelled task is evicted like any other \
         terminal task"
    );
    assert!(
        reg.get(&young.id, "key-abandon").is_some(),
        "the younger active task survives every sweep"
    );
}
