// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/operation.rs`.

use crate::operation::*;

/// Every verb, listed once, with the SHAPE it collapsed onto and the operator-visible name it
/// publishes. Written out rather than derived: a verb added without a line here is a verb no test
/// names, and the pairing below is what pins both halves of `Verb { op, name }`.
///
/// **THE THIRTEEN NAMES ARE THE 1.5-ERA METRIC LABEL SET, UNCHANGED.** Collapsing thirteen flat
/// variants onto six shapes must not re-base a single metric series, and this table is where that
/// is asserted rather than assumed.
const ALL: [(OpVerb, OpShape, &str); 13] = [
    // The LLM family: seven words, ONE shape. Name a model, hand it arguments, get content back.
    (OpVerb::CHAT, OpShape::Invoke, "chat"),
    (OpVerb::EMBEDDINGS, OpShape::Invoke, "embeddings"),
    (OpVerb::MODERATION, OpShape::Invoke, "moderation"),
    (OpVerb::IMAGE, OpShape::Invoke, "image"),
    (OpVerb::TRANSCRIPTION, OpShape::Invoke, "transcription"),
    (OpVerb::SPEECH, OpShape::Invoke, "speech"),
    (OpVerb::RERANK, OpShape::Invoke, "rerank"),
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
    assert_eq!(OpVerb::CHAT.name(), "chat");
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

/// EVERY VERB'S SHAPE, PINNED. The seven LLM words collapsing onto one shape is the finding this
/// change is built on; if one of them ever needs a shape of its own, that is a design decision and
/// it should have to be written down here first.
#[test]
fn every_verb_is_pinned_to_its_shape() {
    for (op, expected, name) in ALL {
        assert_eq!(op.shape(), expected, "`{name}` must keep its shape");
    }
}

/// `Operation::ALL` IS THE CORE-OWNED HALF OF THE VOCABULARY — the six shape verbs, exactly the
/// table's protocol-surface rows, in the same order. The LLM rows are deliberately NOT in it any
/// more: a plane's dialects declare them (spec Part 1, Law 5), and the kernel holds no protocol
/// set; `crates/busbar/tests/operation_names_cross_plane.rs` pins the linked roster's half.
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

/// THE KERNEL'S HALF OF THE METRIC LABEL SURFACE, AS A SET. `Operation::name` is a
/// Prometheus/tracing label; the set of values it can take is the set of series an operator's
/// dashboard can select. The kernel owns the six shape verbs; a plane's dialects declare the rest
/// (spec Part 1, Law 5), and `crates/busbar/tests/operation_names_cross_plane.rs` pins the whole
/// thirteen over the linked roster. This is the kernel's six, spelled once, sorted, so any change to
/// it is a visible diff in this file rather than a silently re-based series.
#[test]
fn the_kernel_owned_label_surface_is_exactly_these_six() {
    let mut labels: Vec<&str> = OpVerb::ALL.iter().map(|o| o.name()).collect();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(
        labels,
        [
            "catalogue",
            "control",
            "fetch",
            "invoke",
            "subscribe",
            "task"
        ],
        "the kernel's operation metric label surface changed; a dashboard depends on this set"
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

/// NO VERB NAMES A PROTOCOL. The whole point of the split is that a core type carries no protocol's
/// identity, so the metric label surface may not contain one either — `mcp_tools_call` in this list
/// would fail the deletion test on line one.
#[test]
fn no_verb_name_carries_a_protocol_identity() {
    // The identities are READ OFF THE LENT TABLE'S PLANES, not listed here: every provider dialect
    // a plane of the neutral test table declares, so a dialect a plane adds is checked the day it
    // lands. The plane keys of the real roster are checked against the same verbs in
    // `crates/busbar/tests/operation_names_cross_plane.rs`, where that roster is linked.
    let identities: Vec<&str> = crate::test_support::neutral_test_doors().provider_dialects();
    assert!(
        !identities.is_empty(),
        "the neutral plane declares provider dialects; an empty list would pass vacuously"
    );
    for (_, _, name) in ALL {
        for forbidden in &identities {
            assert!(
                !name.contains(forbidden),
                "`{name}` names the `{forbidden}` protocol; verbs are shapes plus neutral words"
            );
        }
    }
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

/// THE SEVEN LLM VERBS SHARE A SHAPE, so the shape alone cannot tell them apart — which is exactly
/// why the word rides beside it. If this ever fails, either a verb changed shape or two verbs
/// collided on a name, and both are breaking changes.
#[test]
fn the_named_invoke_family_is_one_shape_with_seven_distinct_words() {
    let family: Vec<&str> = ALL
        .iter()
        .filter(|(op, _, _)| *op != OpVerb::INVOKE && op.shape() == OpShape::Invoke)
        .map(|(_, _, n)| *n)
        .collect();
    assert_eq!(family.len(), 7, "seven named verbs, all `Invoke`-shaped");
    assert!(
        !family.contains(&"invoke"),
        "the named verbs keep their published endpoint names; none is the shape's own word"
    );
}
