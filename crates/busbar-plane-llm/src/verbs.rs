// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THIS PLANE'S SEVEN ENDPOINT WORDS. All one shape (`Invoke`): name a model, hand it arguments,
//! get content or an error back. They keep their published names to the letter, because those
//! names are the metrics label and the `paths:` config key and a rename is a broken dashboard.
//!
//! They are this plane's vocabulary, so they are this plane's constants (Q128 contract p11
//! finding 1): the contract owns only the six shape verbs and the `const` constructor these are
//! built with, and the words leave with the plane.

use busbar_contract::operation::OpVerb;

/// A chat completion.
pub const CHAT: OpVerb = OpVerb::named_invoke("chat");
/// An embeddings request.
pub const EMBEDDINGS: OpVerb = OpVerb::named_invoke("embeddings");
/// A moderation request.
pub const MODERATION: OpVerb = OpVerb::named_invoke("moderation");
/// An image generation.
pub const IMAGE: OpVerb = OpVerb::named_invoke("image");
/// An audio transcription.
pub const TRANSCRIPTION: OpVerb = OpVerb::named_invoke("transcription");
/// A speech synthesis.
pub const SPEECH: OpVerb = OpVerb::named_invoke("speech");
/// A rerank.
pub const RERANK: OpVerb = OpVerb::named_invoke("rerank");

#[cfg(test)]
mod tests {
    use busbar_contract::operation::{OpShape, OpVerb};

    /// Every word is `Invoke`-shaped and carries its published name to the letter, and none is one
    /// of the core's own six shape verbs.
    #[test]
    fn the_seven_words_are_invoke_shaped_with_their_published_names() {
        let cases = [
            (super::CHAT, "chat"),
            (super::EMBEDDINGS, "embeddings"),
            (super::MODERATION, "moderation"),
            (super::IMAGE, "image"),
            (super::TRANSCRIPTION, "transcription"),
            (super::SPEECH, "speech"),
            (super::RERANK, "rerank"),
        ];
        for (op, name) in cases {
            assert_eq!(op.shape(), OpShape::Invoke, "{name} must be Invoke-shaped");
            assert_eq!(op.name(), name);
            assert!(
                !OpVerb::ALL.contains(&op),
                "{name} is not a core shape verb"
            );
        }
    }

    /// NO WORD NAMES A DIALECT OR THE PLANE: the words are endpoint names, so a dashboard label never
    /// claims which wire spoke.
    #[test]
    fn no_word_names_a_dialect_or_the_plane() {
        let words = [
            super::CHAT,
            super::EMBEDDINGS,
            super::MODERATION,
            super::IMAGE,
            super::TRANSCRIPTION,
            super::SPEECH,
            super::RERANK,
        ];
        for verb in words {
            let name = verb.name();
            for dialect in crate::dialect::DIALECTS {
                assert!(
                    !name.contains(dialect.name),
                    "`{name}` names the `{}` dialect",
                    dialect.name
                );
            }
            assert!(!name.contains("llm"), "`{name}` names the plane");
        }
    }

    /// THE METRIC LABEL SURFACE, AS A SET: the core's six shape verbs plus this plane's seven words
    /// are the thirteen labels the 1.5 era published, unchanged. `OpVerb::name` is a Prometheus and
    /// tracing label, so this set is the set of series a dashboard can select; a change to it is a
    /// visible diff here rather than a silently re-based series.
    #[test]
    fn the_metric_label_surface_is_exactly_these_thirteen() {
        let plane = [
            super::CHAT,
            super::EMBEDDINGS,
            super::MODERATION,
            super::IMAGE,
            super::TRANSCRIPTION,
            super::SPEECH,
            super::RERANK,
        ];
        let mut labels: Vec<&str> = OpVerb::ALL
            .iter()
            .chain(plane.iter())
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
}
