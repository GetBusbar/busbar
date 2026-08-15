// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Embeddings IR. Cross-protocol across OpenAI, Cohere, Gemini,
//! Bedrock (NO Anthropic — it ships no embeddings API). Split request/response per;
//! token-metered → `Billing::Tokens`.
//!
//! Losslessness crux: a single response can carry MULTIPLE typed
//! vectors AT ONCE (Cohere/Titan return float AND int8/binary), so vectors are keyed BY ENCODING in
//! [`EmbeddingItem::vectors`] — a flat `Vec<f32>` would silently drop the others.

use crate::billing::{Billing, TokenUsage};
use crate::lossless::SourceScopedExtra;
use std::collections::BTreeMap;

/// Output vector encoding. Also the KEY into [`EmbeddingItem::vectors`], so multi-encoding responses
/// are lossless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum EncFmt {
    Float,
    Base64,
    Int8,
    Uint8,
    Binary,
    Ubinary,
}

/// One vector's data in a given encoding.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum VectorData {
    Float(Vec<f32>),
    Int(Vec<i32>),
    Base64(String),
}

/// The input to embed. Text / token-arrays / images cover OpenAI/Cohere/Gemini/Bedrock; anything
/// exotic (Cohere v2 `inputs` mixed content) rides `extra` for lossless round-trip.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum EmbInput {
    Text(Vec<String>),
    /// Cohere/Gemini/Bedrock accept token-array input; no 1.5.0 ingress reader constructs this
    /// variant yet, but the superset IR must be able to express it once one does.
    #[allow(dead_code)]
    Tokens(Vec<Vec<u32>>),
    /// Cohere/Gemini/Bedrock accept image input for embedding; no 1.5.0 ingress reader constructs
    /// this variant yet, but the superset IR must be able to express it once one does.
    #[allow(dead_code)]
    Images(Vec<String>), // data-URI / base64 refs
}

impl Default for EmbInput {
    fn default() -> Self {
        EmbInput::Text(Vec::new())
    }
}

/// Embeddings request IR — the superset over all four providers.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct EmbeddingsReq {
    pub(crate) model: String,
    pub(crate) input: EmbInput,
    pub(crate) input_type: Option<String>, // Cohere/Bedrock semantic role (search_document/query/…)
    pub(crate) task_type: Option<String>,  // Gemini task type — kept DISTINCT from input_type
    pub(crate) title: Option<String>,      // Gemini RETRIEVAL_DOCUMENT
    pub(crate) dimensions: Option<u32>,    // OpenAI/Cohere/Gemini/Titan (one canonical field)
    pub(crate) encoding_formats: Vec<EncFmt>, // Vec: Cohere/Titan may request several at once
    pub(crate) truncate: Option<String>, // NONE/START/END (Cohere/Bedrock); Gemini autoTruncate maps here
    pub(crate) max_tokens: Option<u32>,  // Cohere
    pub(crate) normalize: Option<bool>,  // Titan v2
    pub(crate) user: Option<String>,     // OpenAI
    pub(crate) priority: Option<i32>,    // Cohere
    pub(crate) extra: SourceScopedExtra,
}

/// One embedding, positionally aligned to the request input at `index`.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct EmbeddingItem {
    pub(crate) index: usize,
    /// Keyed by encoding — the losslessness crux (multi-encoding responses keep every vector).
    pub(crate) vectors: BTreeMap<EncFmt, VectorData>,
    pub(crate) shape: Option<Vec<u32>>, // Gemini
}

/// Embeddings response IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct EmbeddingsResp {
    pub(crate) id: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) object_kind: Option<String>, // "list" / "embeddings_floats"
    pub(crate) embeddings: Vec<EmbeddingItem>,
    pub(crate) input_echo: Option<Vec<String>>, // Cohere/Bedrock `texts`
    pub(crate) usage: Option<TokenUsage>,
    pub(crate) extra: SourceScopedExtra,
}

impl EmbeddingsResp {
    /// Billing projection: embeddings are token-metered (input tokens; Bedrock returns none → `None`).
    pub(crate) fn billing(&self) -> Option<Billing> {
        self.usage.clone().map(Billing::Tokens)
    }
}

#[cfg(test)]
#[path = "tests/embeddings_tests.rs"]
mod tests;
