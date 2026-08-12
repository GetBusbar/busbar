// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/operation.rs`.

use super::*;

/// Every variant, listed once. Adding an operation without adding it here leaves the new variant
/// unnamed by any test — so this array is written out rather than derived, and the pairing below is
/// what pins the operator-visible strings.
const ALL: [(Operation, &str); 13] = [
    (Operation::Chat, "chat"),
    (Operation::Embeddings, "embeddings"),
    (Operation::Moderation, "moderation"),
    (Operation::Image, "image"),
    (Operation::Transcription, "transcription"),
    (Operation::Speech, "speech"),
    (Operation::Rerank, "rerank"),
    (Operation::Invoke, "invoke"),
    (Operation::Catalogue, "catalogue"),
    (Operation::Fetch, "fetch"),
    (Operation::Task, "task"),
    (Operation::Subscribe, "subscribe"),
    (Operation::Control, "control"),
];

#[test]
fn names_are_stable_and_distinct() {
    let names: Vec<_> = ALL.iter().map(|(o, _)| o.name()).collect();
    // all distinct
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "operation names must be unique");
    assert_eq!(Operation::Chat.name(), "chat");
}

/// THE NAMES ARE AN OPERATOR-VISIBLE CONTRACT — the metrics label and the `paths:` config key — so
/// each one is pinned to its literal here. A rename that reaches this file is a breaking change to
/// somebody's dashboard and somebody's config, and it should have to be written down twice.
#[test]
fn every_name_is_pinned_to_its_literal() {
    for (op, expected) in ALL {
        assert_eq!(op.name(), expected, "{op:?} must keep its published name");
    }
}

/// `ToolCall` became `Invoke` in 1.6.0 because the operation now carries A2A `message/send` as well
/// as MCP `tools/call`; the old MCP-flavoured label must not survive anywhere on this axis, or a
/// dashboard would keep reading a name that claims the engine knows which protocol it is serving.
#[test]
fn no_operation_is_still_called_tool_call() {
    assert!(
        ALL.iter().all(|(_, n)| *n != "tool_call"),
        "`tool_call` was renamed to `invoke`; no operation may publish the old label"
    );
}
