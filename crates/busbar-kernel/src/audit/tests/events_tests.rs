// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 17: engine events become rows of the one feed.

use super::*;

#[test]
fn boot_writes_node_boot() {
    let row = event_row(
        &node_boot(&["open_relay", "ephemeral_store"]),
        Some("node_00000000000000a1"),
        0,
    );
    assert_eq!(row.action, "node.boot");
    assert_eq!(row.principal, "node:node_00000000000000a1");
    assert_eq!(row.severity, "warning");
    assert_eq!(
        row.data.as_str(),
        r#"{"posture":["open_relay","ephemeral_store"]}"#
    );
    let clean = event_row(&node_boot(&[]), Some("node_00000000000000a1"), 0);
    assert_eq!(clean.severity, "info");
    assert_eq!(clean.data.as_str(), r#"{"posture":[]}"#);
}

#[test]
fn event_rows_carry_instance_and_severity() {
    let event = EngineEvent {
        action: "store.disconnected",
        kind: Some("store".into()),
        instance: Some("main".into()),
        severity: "error",
        outcome: Some("degraded"),
        ..Default::default()
    };
    let row = event_row(&event, Some("node_1"), 0);
    assert_eq!(row.kind.as_deref(), Some("store"));
    assert_eq!(row.instance.as_deref(), Some("main"));
    assert_eq!(row.severity, "error");
    assert_eq!(row.outcome, "degraded");
    assert_eq!(row.resource, "store:main");
    assert_eq!(row.principal, "node:node_1");
    assert_eq!(node_principal(None), "node:unpublished");
}

#[test]
fn diagnostic_raised_coalesced() {
    let mut c = Coalescer::default();
    assert_eq!(c.admit("diagnostic.raised", "1002", 100), Some(0));
    assert_eq!(c.admit("diagnostic.raised", "1002", 100), None);
    assert_eq!(c.admit("diagnostic.raised", "1002", 100), None);
    assert_eq!(
        c.admit("diagnostic.raised", "1003", 100),
        Some(0),
        "per instance"
    );
    assert_eq!(
        c.admit("diagnostic.raised", "1002", 101),
        Some(2),
        "folded ones are counted"
    );
    assert_eq!(c.admit("diagnostic.raised", "1002", 102), Some(0));
    let row = event_row(
        &diagnostic_raised(1002, "durable-second-writer-detach", 5),
        Some("n"),
        2,
    );
    assert_eq!(row.action, "diagnostic.raised");
    assert_eq!(row.instance.as_deref(), Some("1002"));
    assert_eq!(
        row.data.as_str(),
        r#"{"code":1002,"coalesced":2,"count":5,"name":"durable-second-writer-detach"}"#
    );
}

#[test]
fn coalesced_is_added_only_when_events_were_folded() {
    assert_eq!(data_with_coalesced("", 0), "{}");
    assert_eq!(data_with_coalesced("{}", 3), r#"{"coalesced":3}"#);
    assert_eq!(
        data_with_coalesced(r#"{"a":1}"#, 3),
        r#"{"a":1,"coalesced":3}"#
    );
}

#[test]
fn engine_event_actions_are_in_the_closed_catalogue() {
    for event in [node_boot(&[]), node_drain(), diagnostic_raised(1, "x", 1)] {
        assert!(
            super::super::auditlog::AUDIT_ACTIONS.contains(&event.action),
            "{}",
            event.action
        );
    }
}
