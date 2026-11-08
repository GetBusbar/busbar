// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::operation::{OpShape, OpVerb};

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
fn the_metric_label_surface_is_exactly_these_thirteen() {
    let (_, facts) =
        busbar_plugin_loader::dispatch::kinds::plane::stated_facts(busbar_plane_llm::door)
            .expect("the actual LLM door declares its operations");
    let mut labels: Vec<&str> = OpVerb::ALL
        .iter()
        .map(|op| op.name())
        .chain(facts.served.op_classes.iter().copied())
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
fn no_verb_name_carries_a_protocol_identity() {
    let (_, facts) =
        busbar_plugin_loader::dispatch::kinds::plane::stated_facts(busbar_plane_llm::door)
            .expect("the actual LLM door declares its dialects");
    let identities = facts.served.dialects;
    assert_eq!(
        identities.len(),
        6,
        "the actual linked LLM product declares six dialects; an empty list would pass vacuously"
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
