// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/operation.rs`.

use crate::operation::*;

/// Every verb, listed once, with the SHAPE it collapsed onto and the operator-visible name it
/// publishes. Written out rather than derived: a verb added without a line here is a verb no test
/// names, and the pairing below is what pins both halves of `Verb { op, name }`.
///
/// These are the core's own six. A plane's named verbs are that plane's constants and its suite
/// pins them (the llm plane's seven endpoint words, and the thirteen-label metric surface they make
/// with these six, are pinned in `busbar_plane_llm::verbs`).
const ALL: [(OpVerb, OpShape, &str); 6] = [
    // The protocol surface: one verb per shape today, carrying the shape's own word.
    (OpVerb::INVOKE, OpShape::Invoke, "invoke"),
    (OpVerb::CATALOGUE, OpShape::Catalogue, "catalogue"),
    (OpVerb::FETCH, OpShape::Fetch, "fetch"),
    (OpVerb::TASK, OpShape::Task, "task"),
    (OpVerb::SUBSCRIBE, OpShape::Subscribe, "subscribe"),
    (OpVerb::CONTROL, OpShape::Control, "control"),
];

#[test]
fn names_are_stable_and_distinct() {
    let names: Vec<_> = ALL.iter().map(|(o, _, _)| o.name()).collect();
    // all distinct
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "operation names must be unique");
    assert_eq!(OpVerb::INVOKE.name(), "invoke");
}

/// THE NAMES ARE AN OPERATOR-VISIBLE CONTRACT — the metrics label and the `paths:` config key — so
/// each one is pinned to its literal here. A rename that reaches this file is a breaking change to
/// somebody's dashboard and somebody's config, and it should have to be written down twice.
#[test]
fn every_name_is_pinned_to_its_literal() {
    for (op, _, expected) in ALL {
        assert_eq!(op.name(), expected, "{op:?} must keep its published name");
    }
}

/// EVERY VERB'S SHAPE, PINNED. If one of them ever needs a different shape, that is a design
/// decision and it should have to be written down here first.
#[test]
fn every_verb_is_pinned_to_its_shape() {
    for (op, expected, name) in ALL {
        assert_eq!(op.shape(), expected, "`{name}` must keep its shape");
    }
}

/// `Operation::ALL` IS THE CORE-OWNED VOCABULARY — the six shape verbs, exactly the table's rows,
/// in the same order. A plane's named verbs are deliberately NOT in it: they are that plane's own
/// constants.
#[test]
fn all_holds_every_core_owned_verb_and_nothing_else() {
    let listed: Vec<OpVerb> = ALL
        .iter()
        .filter(|(_, _, n)| OpShape::ALL.iter().any(|s| s.as_str() == *n))
        .map(|(o, _, _)| *o)
        .collect();
    assert_eq!(
        OpVerb::ALL,
        listed.as_slice(),
        "`Operation::ALL` and this file's shape-verb rows must be the same list in the same order"
    );
}

/// `ToolCall` became `Invoke` in 1.6.0 because the operation now carries A2A `message/send` as well
/// as MCP `tools/call`; the old MCP-flavoured label must not survive anywhere on this axis, or a
/// dashboard would keep reading a name that claims the engine knows which protocol it is serving.
#[test]
fn no_operation_is_still_called_tool_call() {
    assert!(
        ALL.iter().all(|(_, _, n)| *n != "tool_call"),
        "`tool_call` was renamed to `invoke`; no operation may publish the old label"
    );
}

/// THE SHAPE SET IS ENUMERABLE, and every shape has a distinct word. The same role
/// `Transport::ALL` plays for its axis: a shape absent from `OpShape::ALL` is a shape nothing
/// enumerates.
#[test]
fn every_shape_is_enumerated_once_with_a_distinct_word() {
    let mut words: Vec<&str> = OpShape::ALL.iter().map(|s| s.as_str()).collect();
    let n = words.len();
    assert_eq!(n, 6, "the shape set is six");
    words.sort_unstable();
    words.dedup();
    assert_eq!(words.len(), n, "every shape's word must be distinct");
    for shape in OpShape::ALL {
        assert!(
            ALL.iter().any(|(_, s, _)| s == shape),
            "{shape:?} is enumerated but no verb carries it"
        );
    }
}

/// THE STREAMING FLOOR IS A PROPERTY OF THE SHAPE, and exactly one shape has increments to deliver.
/// A catalogue page, a fetched document, a task record, a subscription acknowledgement and a
/// handshake are each ONE answer; a cell that claimed otherwise would leave the engine holding a
/// response open for a body that is never coming.
#[test]
fn only_the_invoke_shape_may_stream() {
    assert!(OpShape::Invoke.may_stream());
    for shape in OpShape::ALL {
        if *shape == OpShape::Invoke {
            continue;
        }
        assert!(
            !shape.may_stream(),
            "{shape:?} answers once; it must not be able to claim a stream"
        );
    }
}
