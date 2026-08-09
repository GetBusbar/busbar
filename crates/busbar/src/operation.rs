// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `Operation` axis — busbar's semantic operation vocabulary.
//!
//! A coarse TAG only: a metrics label and the `paths:` config key. It carries NO capability booleans
//! — whether a given (protocol, operation, model) streams or reports usage is an OperationHandler fact and lives on
//! the `OperationHandler`, not here. Variant names are 1:1 with the forthcoming
//! `enum Ir`, so the egress-`write` dispatch is a trivial same-name match.
//!
//! Semantic, endpoint-count-agnostic: `translation` is `Transcription` with a `target_language`;
//! image edit/variation are `Image` with an `op` discriminant — NOT separate operations.
//!
//! Foundation type; `dead_code` allowed until the Router/IR wiring lands.

/// The seven semantic operations busbar 1.2 speaks. Closed set — adding one is a compile error at
/// every exhaustive match (the removability/symmetry gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Operation {
    Chat,
    Embeddings,
    Moderation,
    Image,
    Transcription,
    Speech,
    Rerank,
}

impl Operation {
    /// Stable identifier — the metrics label and the `paths:` config key.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Operation::Chat => "chat",
            Operation::Embeddings => "embeddings",
            Operation::Moderation => "moderation",
            Operation::Image => "image",
            Operation::Transcription => "transcription",
            Operation::Speech => "speech",
            Operation::Rerank => "rerank",
        }
    }
}

#[cfg(test)]
#[path = "tests/operation_tests.rs"]
mod tests;
