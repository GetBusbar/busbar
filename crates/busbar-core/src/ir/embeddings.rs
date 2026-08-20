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
pub enum EncFmt {
    Float,
    Base64,
    Int8,
    Uint8,
    Binary,
    Ubinary,
}

/// One vector's data in a given encoding.
#[derive(Debug, Clone, PartialEq)]
pub enum VectorData {
    Float(Vec<f32>),
    Int(Vec<i32>),
    Base64(String),
}

/// The input to embed. Text / token-arrays / images cover OpenAI/Cohere/Gemini/Bedrock; anything
/// exotic (Cohere v2 `inputs` mixed content) rides `extra` for lossless round-trip.
#[derive(Debug, Clone, PartialEq)]
pub enum EmbInput {
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
pub struct EmbeddingsReq {
    pub model: String,
    pub input: EmbInput,
    pub input_type: Option<String>, // Cohere/Bedrock semantic role (search_document/query/…)
    pub task_type: Option<String>,  // Gemini task type — kept DISTINCT from input_type
    pub title: Option<String>,      // Gemini RETRIEVAL_DOCUMENT
    pub dimensions: Option<u32>,    // OpenAI/Cohere/Gemini/Titan (one canonical field)
    pub encoding_formats: Vec<EncFmt>, // Vec: Cohere/Titan may request several at once
    pub truncate: Option<String>, // NONE/START/END (Cohere/Bedrock); Gemini autoTruncate maps here
    pub max_tokens: Option<u32>,  // Cohere
    pub normalize: Option<bool>,  // Titan v2
    pub user: Option<String>,     // OpenAI
    pub priority: Option<i32>,    // Cohere
    pub extra: SourceScopedExtra,
}

/// THE EMBEDDINGS FAMILY'S WALK — this IR's answer to [`crate::ir::facts::IrFacts`], the
/// family-blind seam the shared pipeline (hook/gate/tap) reads a request through. It lives HERE, in
/// the module that owns the IR, for the reason [`crate::ir::invoke`]'s header states: one IR, one
/// walk, one file — never folded into `facts.rs`, which carries the CHAT family's walk and would
/// become a cross-family superset if a second family joined it.
///
/// Every CALLER-AUTHORED text field is projected to [`crate::ir::facts::ContentItem::Text`] so a
/// `prompt: ro` screening gate sees it (the whole point of this change — an embeddings request was
/// gate-blind before): each `input` string, and the Gemini retrieval `title` when present. Inputs
/// that are present but UNSCREENABLE — a pre-tokenized token array, or an image reference — project
/// [`crate::ir::facts::ContentItem::Opaque`] (present-but-unscreenable), never silently nothing.
/// `input_type`/`task_type`/`truncate`/`dimensions` are enum/numeric ROLES, not caller free-text,
/// and stay out.
impl crate::ir::facts::IrFacts for EmbeddingsReq {
    fn verb(&self) -> crate::operation::Operation {
        crate::operation::Operation::EMBEDDINGS
    }

    fn wants_stream(&self) -> bool {
        false
    }

    fn end_user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    fn shape(&self) -> crate::ir::facts::Shape {
        let items = crate::ir::facts::IrFacts::content(self);
        let (text_chars, system_chars) = crate::ir::facts::Shape::counts_over(&items);
        crate::ir::facts::Shape {
            turn_count: 1,
            has_tools: false,
            tool_count: 0,
            text_chars,
            system_chars,
            max_tokens: None,
        }
    }

    fn content(&self) -> Vec<crate::ir::facts::ContentItem<'_>> {
        use crate::ir::facts::{ContentItem, Slot, OPAQUE_CONTENT_MARKER};
        use std::borrow::Cow;
        let mut out = Vec::new();
        match &self.input {
            EmbInput::Text(strings) => {
                for s in strings {
                    out.push(ContentItem::Text {
                        author: "user",
                        slot: Slot::Turn(0),
                        text: Cow::Borrowed(s.as_str()),
                    });
                }
            }
            // Pre-tokenized input is content busbar cannot render back to screenable text — one
            // opaque marker per array, present-but-unscreenable rather than silently empty.
            EmbInput::Tokens(arrays) => {
                for _ in arrays {
                    out.push(ContentItem::Opaque {
                        author: "user",
                        slot: Slot::Turn(0),
                        label: "tokens",
                        marker: OPAQUE_CONTENT_MARKER,
                    });
                }
            }
            // Image references embed as binary/opaque input (MINOR-7): present-but-unscreenable.
            EmbInput::Images(images) => {
                for _ in images {
                    out.push(ContentItem::Opaque {
                        author: "user",
                        slot: Slot::Turn(0),
                        label: "image",
                        marker: OPAQUE_CONTENT_MARKER,
                    });
                }
            }
        }
        // FATAL-3: the Gemini RETRIEVAL_DOCUMENT title is caller free-text, read+written on the
        // Gemini retrieval path, so a gate must see it.
        if let Some(title) = &self.title {
            out.push(ContentItem::Text {
                author: "user",
                slot: Slot::Turn(0),
                text: Cow::Borrowed(title.as_str()),
            });
        }
        out
    }
}

/// One embedding, positionally aligned to the request input at `index`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EmbeddingItem {
    pub index: usize,
    /// Keyed by encoding — the losslessness crux (multi-encoding responses keep every vector).
    pub vectors: BTreeMap<EncFmt, VectorData>,
    pub shape: Option<Vec<u32>>, // Gemini
}

/// Embeddings response IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EmbeddingsResp {
    pub id: Option<String>,
    pub model: Option<String>,
    pub object_kind: Option<String>, // "list" / "embeddings_floats"
    pub embeddings: Vec<EmbeddingItem>,
    pub input_echo: Option<Vec<String>>, // Cohere/Bedrock `texts`
    pub usage: Option<TokenUsage>,
    pub extra: SourceScopedExtra,
}

impl EmbeddingsResp {
    /// Billing projection: embeddings are token-metered (input tokens; Bedrock returns none → `None`).
    pub fn billing(&self) -> Option<Billing> {
        self.usage.clone().map(Billing::Tokens)
    }
}

#[cfg(test)]
#[path = "tests/embeddings_tests.rs"]
mod tests;
