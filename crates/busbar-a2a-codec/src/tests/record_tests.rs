// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Round-trip tests for the A2A plane rows (`TaskRow` / `TaskEventRow`) through the store-seam\n//! `PlaneRecord` encoding — field-name stability across the plugin ABI and terminal-state\n//! disposition. Relocated out of `record.rs` per the tests-in-their-own-file convention.

use super::*;

/// The task rows round-trip through serde unchanged. They cross a plugin ABI, so a field whose
/// serialized name drifts is a field a backend silently stops persisting. (Moved here from
/// `busbar-api` in the 1.7.0 plane extraction — the plane owns its own row schema now.)
#[test]
fn task_rows_round_trip_through_the_store_seam_encoding() {
    let task = TaskRow {
        task_id: "t-1".into(),
        context_id: "ctx-1".into(),
        principal: "key-1".into(),
        direction: "outbound".into(),
        state: "auth-required".into(),
        agent_id: "planner".into(),
        artifact_cursor: 7,
        push_callback: "https://caller.example/cb".into(),
        created_at: 10,
        updated_at: 20,
    };
    let env = task.to_plane_record().unwrap();
    assert_eq!(env.kind, KIND_TASK);
    assert_eq!(env.id, "t-1");
    assert_eq!(env.disposition, PlaneDisposition::Active); // auth-required is not terminal
    assert_eq!(TaskRow::from_body(&env.body).unwrap(), task);
    let json = String::from_utf8(env.body).unwrap();
    for field in [
        "task_id",
        "context_id",
        "principal",
        "direction",
        "state",
        "agent_id",
        "artifact_cursor",
        "push_callback",
        "created_at",
        "updated_at",
    ] {
        assert!(
            json.contains(field),
            "`{field}` must be on the wire: {json}"
        );
    }
}

#[test]
fn a_terminal_task_state_marks_the_envelope_terminal() {
    let mut task = TaskRow {
        task_id: "t-2".into(),
        context_id: "ctx".into(),
        principal: "key".into(),
        direction: "inbound".into(),
        state: "completed".into(),
        agent_id: String::new(),
        artifact_cursor: 0,
        push_callback: String::new(),
        created_at: 1,
        updated_at: 2,
    };
    assert_eq!(
        task.to_plane_record().unwrap().disposition,
        PlaneDisposition::Terminal
    );
    task.state = "working".into();
    assert_eq!(
        task.to_plane_record().unwrap().disposition,
        PlaneDisposition::Active
    );
}

#[test]
fn task_event_rows_round_trip_through_the_task_event_envelope() {
    let event = TaskEventRow {
        task_id: "t-1".into(),
        seq: 1,
        ts: 10,
        kind: "task.submitted".into(),
        context_id: "ctx-1".into(),
        principal: "key-1".into(),
        agent_id: String::new(),
        state: "submitted".into(),
        request_id: "req-1".into(),
        prev_hash: String::new(),
        hash: "deadbeef".into(),
        digest_version: DIGEST_VERSION_LEN_PREFIXED,
    };
    let env = event.to_plane_record().unwrap();
    assert_eq!(env.kind, KIND_TASK_EVENT);
    assert_eq!(env.parent.as_deref(), Some("t-1"));
    assert_eq!(env.seq, 1);
    assert_eq!(TaskEventRow::from_body(&env.body).unwrap(), event);
}
