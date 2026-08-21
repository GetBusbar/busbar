// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Rerank IR (the seventh operation). Cross-protocol across Cohere (`/v2/rerank`) and Bedrock
//! (rerank models via `InvokeModel`) — the two protocols that ship a rerank surface. The wire
//! shapes are near-identical (query + documents in, index + relevance_score out), so the IR is a
//! thin normalization; OpenAI/Anthropic/Gemini/Responses have no surface and 404 via the standard
//! no-handler rule. Search-unit metered → `Billing::Flat` (Cohere bills per search unit, carried
//! for the response echo; the pricing engine lands in 1.3).

use busbar_core::billing::Billing;
use busbar_core::lossless::SourceScopedExtra;

/// Rerank request IR — the superset over both providers.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RerankReq {
    pub model: String,
    pub query: String,
    pub documents: Vec<String>,
    pub top_n: Option<u32>,
    pub max_tokens_per_doc: Option<u32>, // Cohere
    pub extra: SourceScopedExtra,
}

/// THE RERANK FAMILY'S WALK — this IR's answer to [`busbar_core::ir::facts::IrFacts`]. Both the `query`
/// and every `document` are caller free-text sent upstream verbatim, so both project to
/// [`busbar_core::ir::facts::ContentItem::Text`] for a screening gate. `top_n`/`max_tokens_per_doc` are
/// numeric knobs, not content.
impl busbar_core::ir::facts::IrFacts for RerankReq {
    fn verb(&self) -> busbar_core::operation::Operation {
        busbar_core::operation::Operation::RERANK
    }

    fn wants_stream(&self) -> bool {
        false
    }

    fn end_user(&self) -> Option<&str> {
        None
    }

    fn shape(&self) -> busbar_core::ir::facts::Shape {
        let items = busbar_core::ir::facts::IrFacts::content(self);
        let (text_chars, system_chars) = busbar_core::ir::facts::Shape::counts_over(&items);
        busbar_core::ir::facts::Shape {
            turn_count: 1,
            has_tools: false,
            tool_count: 0,
            text_chars,
            system_chars,
            max_tokens: None,
        }
    }

    fn content(&self) -> Vec<busbar_core::ir::facts::ContentItem<'_>> {
        use busbar_core::ir::facts::{ContentItem, Slot};
        use std::borrow::Cow;
        let mut out = Vec::with_capacity(1 + self.documents.len());
        out.push(ContentItem::Text {
            author: "user",
            slot: Slot::Turn(0),
            text: Cow::Borrowed(self.query.as_str()),
        });
        for doc in &self.documents {
            out.push(ContentItem::Text {
                author: "user",
                slot: Slot::Turn(0),
                text: Cow::Borrowed(doc.as_str()),
            });
        }
        out
    }
}

/// One ranked hit: the index into the REQUEST's `documents` and its relevance.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RerankResult {
    pub index: usize,
    pub relevance_score: f64,
}

/// Rerank response IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RerankResp {
    pub id: Option<String>,
    pub results: Vec<RerankResult>,
    pub search_units: Option<u64>, // Cohere meta.billed_units.search_units
    pub extra: SourceScopedExtra,
}

impl RerankResp {
    /// Billing projection: no token meter on either wire; flat until the 1.3 pricing engine
    /// prices search units.
    pub fn billing(&self) -> Option<Billing> {
        Some(Billing::Flat)
    }
}

#[cfg(test)]
#[path = "tests/rerank_tests.rs"]
mod tests;
