// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the inverse of the identity substitution.
//!
//! ## Every test names its own principal, and that is the isolation
//!
//! `taskstore::TASKS` and this module's own table are process-globals, and these tests run in
//! parallel with the rest of the crate. The tenancy boundary IS the principal, so a test that
//! invents its own is isolated by the mechanism under test rather than by a lock — the same
//! argument `local_tests` makes, and the same one that lets the two-principal tests below use that
//! mechanism as their assertion.
//!
//! ## The two-principal shape, stated once
//!
//! A2A section 3.3.2: a server "MUST NOT reveal the existence of resources the client is not
//! authorized to access". A test with ONE principal cannot tell perfect scoping from none — it sees
//! a translation happen and cannot say whose. So every scoping test here asserts BOTH halves: the
//! owner's request IS translated, and the non-owner's is NOT, and the non-owner's outcome is
//! compared against the outcome for an id that has never existed rather than merely asserted to be
//! "an error". Untranslated is the only observable that matters here, because it is what makes the
//! relayed request name an id the backend has never heard of — which is exactly what a nonexistent
//! id does.

use super::*;
use crate::a2a::task::{Direction, Task};
use busbar_core::plane::taskstore::TASKS;
use serde_json::json;

/// Open a real task row owned by `principal`, so the scoped lookup has an ownership fact to read.
fn own(principal: &str, task_id: &str) {
    let task = Task::submitted(task_id, "ctx-idmap", principal, Direction::Inbound, 1_000)
        .expect("a task with these fields is constructible");
    busbar_core::plane::taskstore::with_global_task_host(|host| {
        TASKS
            .submit(host, &task.to_row(), task_id)
            .expect("the row records");
    });
}

/// A busbar id nothing has recorded is forwarded UNCHANGED — as the caller's own bytes, not as a
/// re-serialization. That is the common path and it is the one that must not touch the payload.
#[test]
fn a_request_naming_no_known_task_is_not_rewritten_at_all() {
    crate::testkit::install_test_seams();
    assert!(translate_request(
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "GetTask",
            "params": { "id": "a-task-nothing-has-seen" }
        }),
        "key-unknown"
    )
    .is_none());
    // No `params` at all, and `params` that is not an object.
    assert!(translate_request(&json!({ "method": "GetTask" }), "key-unknown").is_none());
    assert!(translate_request(&json!({ "params": [1, 2, 3] }), "key-unknown").is_none());
}

/// THE DEFECT, in one test: busbar hands a caller its own task id, and must be able to resolve it.
#[test]
fn the_id_busbar_issued_is_translated_back_to_the_one_the_backend_knows() {
    crate::testkit::install_test_seams();
    let me = "key-idmap-planner";
    own(me, "a2a-planner-busbar");
    remember("a2a-planner-busbar", "backend-019ff");
    let out = translate_request(
        &json!({
            "jsonrpc": "2.0", "id": 4, "method": "GetTask",
            "params": { "id": "a2a-planner-busbar", "historyLength": 3 }
        }),
        me,
    )
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
    crate::testkit::install_test_seams();
    let me = "key-idmap-spellings";
    own(me, "busbar-t");
    remember("busbar-t", "backend-t");
    for member in ["id", "taskId", "task_id"] {
        let out = translate_request(
            &json!({
                "method": "GetTaskPushNotificationConfig",
                "params": { member: "busbar-t" }
            }),
            me,
        )
        .unwrap_or_else(|| panic!("`{member}` must translate"));
        let doc: serde_json::Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(doc["params"][member], "backend-t");
    }
}

/// A long-running task streams many events and re-records the same pair each time. Re-recording
/// must not re-order the map, or one chatty task evicts every other one.
#[test]
fn re_recording_the_same_pair_does_not_churn_the_map() {
    crate::testkit::install_test_seams();
    let me = "key-idmap-stable";
    own(me, "stable-busbar");
    remember("stable-busbar", "stable-backend");
    for _ in 0..1000 {
        remember("stable-busbar", "stable-backend");
    }
    assert_eq!(
        backend_id_for(me, "stable-busbar").as_deref(),
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
    crate::testkit::install_test_seams();
    let me = "key-idmap-degenerate";
    own(me, "y");
    own(me, "same");
    remember("", "x");
    remember("y", "");
    remember("same", "same");
    assert!(backend_id_for(me, "").is_none());
    assert!(backend_id_for(me, "y").is_none());
    assert!(backend_id_for(me, "same").is_none());
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
    crate::testkit::install_test_seams();
    let me = "key-idmap-turn";
    own(me, "busbar-turn-1");
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
    let out = translate_request(&envelope, me).expect("a message-nested task id is a translation");
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
    crate::testkit::install_test_seams();
    let me = "key-idmap-message-id";
    own(me, "busbar-not-a-message-id");
    remember("busbar-not-a-message-id", "backend-x");
    let envelope = serde_json::json!({
        "params": { "message": { "id": "busbar-not-a-message-id" } }
    });
    assert!(
        translate_request(&envelope, me).is_none(),
        "a message's `id` is not a task id and nothing may be translated from it"
    );
}

// ══ THE TENANCY BOUNDARY ═════════════════════════════════════════════════════════════════════════

/// `GetTask`: THE REPORTED DEFECT, both halves.
///
/// Two principals differing only in identity. The owner's `GetTask` resolves to the backend's id;
/// the non-owner's must be left EXACTLY as an id that has never existed is left, so the request that
/// goes out names a task the backend cannot know about and the two answers are one answer.
#[test]
fn get_task_is_translated_for_its_owner_and_for_nobody_else() {
    crate::testkit::install_test_seams();
    let owner = "key-get-owner";
    let intruder = "key-get-intruder";
    own(owner, "a2a-conformance-get-owned");
    remember("a2a-conformance-get-owned", "backend-get-owned");

    let addressed = |id: &str| json!({ "jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": { "id": id } });

    // THE OWNER CAN.
    let mine = translate_request(&addressed("a2a-conformance-get-owned"), owner)
        .expect("the owner's own id must resolve, or GetTask is broken for everybody");
    let mine: serde_json::Value = serde_json::from_slice(&mine).expect("json");
    assert_eq!(mine["params"]["id"], "backend-get-owned");

    // THE NON-OWNER CANNOT, and cannot tell that there was anything to be refused.
    let foreign = translate_request(&addressed("a2a-conformance-get-owned"), intruder);
    let absent = translate_request(&addressed("a2a-conformance-never-existed"), intruder);
    assert_eq!(
        foreign, absent,
        "another principal's task id must be handled identically to an id that never existed — a \
         distinguishable answer is the existence oracle A2A section 3.3.2 forbids"
    );
    assert!(
        foreign.is_none(),
        "a foreign id must not be translated: translating it is what let the backend answer about \
         another principal's task"
    );
}

/// `CancelTask` — the same boundary on the WRITE verb, which is the worse half of the same defect:
/// an untranslated cancel names an id the backend does not hold, a translated one destroys another
/// principal's running work.
#[test]
fn cancel_task_is_translated_for_its_owner_and_for_nobody_else() {
    crate::testkit::install_test_seams();
    let owner = "key-cancel-owner";
    let intruder = "key-cancel-intruder";
    own(owner, "a2a-conformance-cancel-owned");
    remember("a2a-conformance-cancel-owned", "backend-cancel-owned");

    let addressed = |id: &str| json!({ "jsonrpc": "2.0", "id": 1, "method": "CancelTask", "params": { "id": id } });

    let mine = translate_request(&addressed("a2a-conformance-cancel-owned"), owner)
        .expect("the owner must be able to cancel its own task");
    let mine: serde_json::Value = serde_json::from_slice(&mine).expect("json");
    assert_eq!(mine["params"]["id"], "backend-cancel-owned");

    assert_eq!(
        translate_request(&addressed("a2a-conformance-cancel-owned"), intruder),
        translate_request(&addressed("a2a-conformance-never-existed"), intruder),
        "cancelling another principal's task must be indistinguishable from cancelling a task that \
         does not exist"
    );
}

/// EVERY SPELLING OF THE ADDRESSING MEMBER, for the non-owner. The boundary must not depend on
/// which of the three names a caller reached for — one unscoped spelling is the whole defect back.
#[test]
fn no_spelling_of_the_task_member_crosses_the_boundary() {
    crate::testkit::install_test_seams();
    let owner = "key-spell-owner";
    let intruder = "key-spell-intruder";
    own(owner, "a2a-spell-owned");
    remember("a2a-spell-owned", "backend-spell-owned");

    for member in ["id", "taskId", "task_id"] {
        let envelope = json!({ "method": "GetTaskPushNotificationConfig", "params": { member: "a2a-spell-owned" } });
        assert!(
            translate_request(&envelope, owner).is_some(),
            "`{member}` must still translate for the owner"
        );
        assert!(
            translate_request(&envelope, intruder).is_none(),
            "`{member}` must not translate for a principal that does not own the task"
        );
    }
}

/// THE WRITE THROUGH THE SECOND TURN. `params.message.taskId` is how a caller continues a
/// conversation, so an unscoped translation there did not leak another principal's task — it
/// APPENDED to it. The owner continues its own conversation; nobody else can join it.
#[test]
fn the_second_turns_task_id_cannot_be_pointed_at_another_principals_conversation() {
    crate::testkit::install_test_seams();
    let owner = "key-turn-owner";
    let intruder = "key-turn-intruder";
    own(owner, "a2a-turn-owned");
    remember("a2a-turn-owned", "backend-turn-owned");

    let envelope = |id: &str| {
        json!({
            "jsonrpc": "2.0", "id": 9, "method": "SendMessage",
            "params": { "message": { "role": "ROLE_USER", "messageId": "m-9", "taskId": id } }
        })
    };

    let mine = translate_request(&envelope("a2a-turn-owned"), owner)
        .expect("the owner's second turn must reach its own open task");
    let mine: serde_json::Value = serde_json::from_slice(&mine).expect("json");
    assert_eq!(
        mine.pointer("/params/message/taskId").unwrap(),
        "backend-turn-owned"
    );

    assert_eq!(
        translate_request(&envelope("a2a-turn-owned"), intruder),
        translate_request(&envelope("a2a-turn-never-existed"), intruder),
        "a second turn addressed at another principal's task must be indistinguishable from one \
         addressed at a task that does not exist"
    );
}

/// AN UNAUTHENTICATED IDENTITY OWNS NOTHING. An empty principal reaching this seam must translate
/// nothing at all, rather than matching whatever a row happened to carry — the same floor
/// `taskstore::get_scoped` puts under itself, asserted through this caller because this caller is
/// the one that composes a request out of the answer.
#[test]
fn an_empty_principal_can_address_nothing() {
    crate::testkit::install_test_seams();
    let owner = "key-empty-owner";
    own(owner, "a2a-empty-owned");
    remember("a2a-empty-owned", "backend-empty-owned");
    assert!(backend_id_for("", "a2a-empty-owned").is_none());
    assert!(translate_request(
        &json!({ "method": "GetTask", "params": { "id": "a2a-empty-owned" } }),
        ""
    )
    .is_none());
}
