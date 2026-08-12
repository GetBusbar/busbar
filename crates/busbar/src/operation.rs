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

/// The semantic operations busbar speaks. Closed set — adding one is a compile error at
/// every exhaustive match (the removability/symmetry gate).
///
/// `ToolCall` is the EIGHTH, and it is the first that did not come from the LLM surface. It is the
/// MCP `tools/call`: a caller names a tool and hands it arguments, and gets content or an error
/// back. It is listed here rather than modelled as a plane of its own because the gate above is
/// exactly the mechanism this needs — every site that must decide something about it now refuses to
/// compile until it does, which is the opposite of how the MCP plane was built the first time
/// (beside the pipeline, where no compiler could ask it anything).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Operation {
    Chat,
    Embeddings,
    Moderation,
    Image,
    Transcription,
    Speech,
    Rerank,
    ToolCall,
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
            Operation::ToolCall => "tool_call",
        }
    }
}

#[cfg(test)]
#[path = "tests/operation_tests.rs"]
mod tests;
