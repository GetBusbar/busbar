// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Polymorphic billable-item data model.
//!
//! The billable UNIT is (operation, model)-dependent: chat/embeddings bill tokens, `whisper-1` bills
//! audio DURATION, `tts-1` bills CHARACTERS, dall-e bills per IMAGE. A single fixed struct cannot
//! represent that, so [`Billing`] is a closed enum every `OperationHandler` emits from a response (or
//! computes from request params when the provider returns no usage object). The 1.2 middle RECORDS
//! every variant (observability from day one) and PRICES [`Billing::Tokens`] exactly as today; the
//! 1.3 governance overhaul prices the remaining units. Closed enum → pricing is an exhaustive match,
//! so adding a unit is a compile error at every price site.
//!
//! Foundation types for the 1.2 operations rebuild; wired into the IR as
//! `IrResp::usage() -> Option<Billing>` (see `ir/variant.rs`). The shipped 1.5.0 pricing path
//! constructs and prices `Billing::Tokens`; `Billing::Characters` (tts-1) is modelled by the IR but
//! not yet priced.

/// Token usage — the SUPERSET of chat's cache-aware accounting AND the new ops' modality breakdown.
///
/// Subsumes the former `ir::IrUsage`: `input` is UNCACHED input (readers normalize to this), the
/// cache fields stay ADDITIVE across protocols, and the optional per-modality fields carry
/// `gpt-4o-transcribe`-style audio/text/image detail — without losing the chat cache convention. So
/// one `Tokens` variant is lossless for chat (cache) and audio/image (modality) alike.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TokenUsage {
    /// Uncached input tokens (normalized; providers whose wire total includes the cache subtract it).
    pub(crate) input: u64,
    pub(crate) output: u64,
    /// Additive cache accounting (Anthropic/Bedrock native; OpenAI-family normalized to additive).
    pub(crate) cache_read: Option<u64>,
    pub(crate) cache_creation: Option<u64>,
    /// Per-modality input breakdown (gpt-4o-transcribe etc). When present, these partition `input`.
    pub(crate) input_text: Option<u64>,
    pub(crate) input_audio: Option<u64>,
    pub(crate) input_image: Option<u64>,
}

/// The billable item produced for one response. Priced by the 1.3 engine via an exhaustive match.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Billing {
    /// Token-metered (chat, embeddings, `gpt-image-1`, `gpt-4o-transcribe`/`-tts`, Gemini).
    Tokens(TokenUsage),
    /// Audio duration in seconds (`whisper-1` transcription: `usage.type == "duration"`).
    Duration { seconds: f64 },
    /// Character count (`tts-1`/`-hd` speech — no usage in the binary body; counted from `input`).
    /// Modelled by the IR (constructed by the tts-1 speech-billing path) but not yet priced; the
    /// shipped 1.5.0 pricing path only prices `Billing::Tokens`.
    #[cfg_attr(not(test), allow(dead_code))]
    Characters { count: u64 },
    /// Per-image, tiered by size/quality (dall-e, Imagen, Titan, SDXL — no usage object in the body).
    Images {
        count: u32,
        size: Option<String>,
        quality: Option<String>,
    },
    /// Flat / no meter (moderations).
    Flat,
}

#[cfg(test)]
#[path = "tests/billing_tests.rs"]
mod tests;
