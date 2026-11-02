// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::operation::*;

const ALL: [(OpVerb, OpShape, &str); 13] = [
    (OpVerb::CHAT, OpShape::Invoke, "chat"),
    (OpVerb::EMBEDDINGS, OpShape::Invoke, "embeddings"),
    (OpVerb::MODERATION, OpShape::Invoke, "moderation"),
    (OpVerb::IMAGE, OpShape::Invoke, "image"),
    (OpVerb::TRANSCRIPTION, OpShape::Invoke, "transcription"),
    (OpVerb::SPEECH, OpShape::Invoke, "speech"),
    (OpVerb::RERANK, OpShape::Invoke, "rerank"),
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

    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "operation names must be unique");
    assert_eq!(OpVerb::CHAT.name(), "chat");
}

#[test]
fn every_name_is_pinned_to_its_literal() {
    for (op, _, expected) in ALL {
        assert_eq!(op.name(), expected, "{op:?} must keep its published name");
    }
}

#[test]
fn every_verb_is_pinned_to_its_shape() {
    for (op, expected, name) in ALL {
        assert_eq!(op.shape(), expected, "`{name}` must keep its shape");
    }
}

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

#[test]
fn the_metric_label_surface_is_exactly_these_thirteen() {
    let mut labels: Vec<&str> = OpVerb::ALL
        .iter()
        .chain(crate::test_support::protocols::declared_verbs())
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

#[test]
fn no_operation_is_still_called_tool_call() {
    assert!(
        ALL.iter().all(|(_, _, n)| *n != "tool_call"),
        "`tool_call` was renamed to `invoke`; no operation may publish the old label"
    );
}

#[test]
fn no_verb_name_carries_a_protocol_identity() {
    let identities: Vec<&str> = crate::ingress::protocols::registry()
        .decls()
        .iter()
        .map(|d| d.name)
        .collect();
    assert_eq!(
        identities.len(),
        7,
        "core's test binary registers seven protocols; an empty list would pass vacuously"
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
