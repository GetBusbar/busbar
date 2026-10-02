// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The notification codec's tests — the same contract the cells are held to, for a message that has
//! no answer: write it, read it back, and assert it is what it was.

use super::*;

// ── THE NOTIFICATION VOCABULARY ──────────────────────────────────────────────────────────────────

/// THE MESSAGE THAT MAKES A SUBSCRIPTION WORTH HAVING, and its sibling that says a tool list moved.
/// One reader and one writer for both directions of travel: busbar emits these when it is the server
/// and receives them when it is the client, and a second implementation per direction is how two
/// readings of one message come to disagree.
#[test]
fn the_notifications_round_trip_and_carry_no_id() {
    for n in [
        McpNotification::ToolsListChanged,
        McpNotification::ResourceUpdated {
            uri: "file:///log.txt".to_string(),
        },
    ] {
        let out: serde_json::Value = serde_json::from_slice(&n.write()).expect("writes JSON");
        assert_eq!(out["jsonrpc"], "2.0");
        assert_eq!(out["method"], n.method());
        assert!(
            out.get("id").is_none(),
            "a notification has no id: an id would make it a request, and a request obliges an \
             answer nobody is waiting for"
        );
        let back = McpNotification::read(
            out["method"].as_str().expect("a method name"),
            out.get("params"),
        );
        assert_eq!(back.as_ref(), Some(&n), "and it reads back as what it was");
    }
}

#[test]
fn the_tools_list_changed_notification_carries_no_params_at_all() {
    let out: serde_json::Value =
        serde_json::from_slice(&McpNotification::ToolsListChanged.write()).expect("writes JSON");
    assert_eq!(out["method"], "notifications/tools/list_changed");
    assert!(
        out.get("params").is_none(),
        "this message has no parameters, so emitting an empty object would be inventing a member"
    );
}

/// AN UPDATE THAT NAMES NO RESOURCE IS NOT AN UPDATE. Acting on it would mean guessing which of a
/// caller's subscriptions it was about.
#[test]
fn a_resource_update_that_names_no_resource_is_not_read() {
    assert_eq!(
        McpNotification::read("notifications/resources/updated", None),
        None
    );
    assert_eq!(
        McpNotification::read(
            "notifications/resources/updated",
            Some(&serde_json::json!({ "uri": "" }))
        ),
        None
    );
}

/// A NOTIFICATION THIS PROTOCOL DOES NOT CARRY IS DROPPED, NOT REFUSED. JSON-RPC 2.0 forbids
/// replying to a notification, so there is nothing to send back and inventing an error envelope
/// would break that rule to report a message that harmed nothing.
#[test]
fn an_unknown_notification_is_simply_not_one_of_these() {
    assert_eq!(McpNotification::read("notifications/nope", None), None);
}
