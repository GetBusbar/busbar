// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/operation.rs`.

use super::*;

/// Every verb, listed once, with the SHAPE it collapsed onto and the operator-visible name it
/// publishes. Written out rather than derived: a verb added without a line here is a verb no test
/// names, and the pairing below is what pins both halves of `Verb { op, name }`.
///
/// **THE THIRTEEN NAMES ARE THE 1.5-ERA METRIC LABEL SET, UNCHANGED.** Collapsing thirteen flat
/// variants onto six shapes must not re-base a single metric series, and this table is where that
/// is asserted rather than assumed.
const ALL: [(Operation, OpShape, &str); 13] = [
    // The LLM family: seven words, ONE shape. Name a model, hand it arguments, get content back.
    (Operation::CHAT, OpShape::Invoke, "chat"),
    (Operation::EMBEDDINGS, OpShape::Invoke, "embeddings"),
    (Operation::MODERATION, OpShape::Invoke, "moderation"),
    (Operation::IMAGE, OpShape::Invoke, "image"),
    (Operation::TRANSCRIPTION, OpShape::Invoke, "transcription"),
    (Operation::SPEECH, OpShape::Invoke, "speech"),
    (Operation::RERANK, OpShape::Invoke, "rerank"),
    // The protocol surface: one verb per shape today, carrying the shape's own word.
    (Operation::INVOKE, OpShape::Invoke, "invoke"),
    (Operation::CATALOGUE, OpShape::Catalogue, "catalogue"),
    (Operation::FETCH, OpShape::Fetch, "fetch"),
    (Operation::TASK, OpShape::Task, "task"),
    (Operation::SUBSCRIBE, OpShape::Subscribe, "subscribe"),
    (Operation::CONTROL, OpShape::Control, "control"),
];

#[test]
fn names_are_stable_and_distinct() {
    let names: Vec<_> = ALL.iter().map(|(o, _, _)| o.name()).collect();
    // all distinct
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "operation names must be unique");
    assert_eq!(Operation::CHAT.name(), "chat");
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
/// more: they reach the vocabulary through `proto::registry::declared_verbs()` (the declarations),
/// which `the_metric_label_surface_is_exactly_these_thirteen` below pins as the other half.
#[test]
fn all_holds_every_core_owned_verb_and_nothing_else() {
    let listed: Vec<Operation> = ALL
        .iter()
        .filter(|(_, _, n)| OpShape::ALL.iter().any(|s| s.as_str() == *n))
        .map(|(o, _, _)| *o)
        .collect();
    assert_eq!(
        Operation::ALL,
        listed.as_slice(),
        "`Operation::ALL` and this file's shape-verb rows must be the same list in the same order"
    );
}

/// THE METRIC LABEL SURFACE, AS A SET. `Operation::name` is a Prometheus/tracing label; the set of
/// values it can take is the set of series an operator's dashboard can select. This is that set,
/// spelled once, sorted, so any change to it is a visible diff in this file rather than a silently
/// re-based series.
///
/// DERIVED FROM BOTH HALVES since the LLM rows left `Operation::ALL`: the core's six shape verbs
/// plus whatever the registered protocol declarations serve. With the built-in protocols present
/// this is the SAME thirteen labels the 1.5 era published — asserting that here is what proves the
/// derivation re-based nothing — and in a build whose protocols are deleted the declared half
/// genuinely shrinks, which is the vocabulary-level teeth the deletion test lacked while the seven
/// words were a core table.
#[test]
fn the_metric_label_surface_is_exactly_these_thirteen() {
    let mut labels: Vec<&str> = Operation::ALL
        .iter()
        .chain(crate::proto::registry::declared_verbs())
        .map(|o| o.name())
        .collect();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(
        labels,
        [
            "catalogue",
            "chat",
            "control",
            "embeddings",
            "fetch",
            "image",
            "invoke",
            "moderation",
            "rerank",
            "speech",
            "subscribe",
            "task",
            "transcription",
        ],
        "the operation metric label surface changed; a dashboard depends on this set"
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
    for (_, _, name) in ALL {
        for forbidden in ["mcp", "a2a", "openai", "anthropic", "gemini", "bedrock"] {
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
fn the_llm_family_is_one_shape_with_seven_distinct_words() {
    let llm: Vec<&str> = ALL
        .iter()
        .filter(|(op, _, _)| *op != Operation::INVOKE && op.shape() == OpShape::Invoke)
        .map(|(_, _, n)| *n)
        .collect();
    assert_eq!(llm.len(), 7, "seven LLM verbs, all `Invoke`-shaped");
    assert!(
        !llm.contains(&"invoke"),
        "the LLM verbs keep their published endpoint names; none is the shape's own word"
    );
}
