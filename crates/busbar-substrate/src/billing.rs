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
//!
//! NEUTRAL, RELOCATED DOWN from `busbar-core` (Batch C-0): pure data naming zero core type, so a
//! plane crate (`busbar-mcp`) names `Billing`/`TokenUsage` without reaching into `busbar-core`. Core
//! re-exports both from `busbar_core::billing` so every in-core and plugin caller compiles unchanged.

/// Token usage — the SUPERSET of chat's cache-aware accounting AND the new ops' modality breakdown.
///
/// Subsumes the former `ir::IrUsage`: `input` is UNCACHED input (readers normalize to this), the
/// cache fields stay ADDITIVE across protocols, and the optional per-modality fields carry
/// `gpt-4o-transcribe`-style audio/text/image detail — without losing the chat cache convention. So
/// one `Tokens` variant is lossless for chat (cache) and audio/image (modality) alike.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenUsage {
    /// Uncached input tokens (normalized; providers whose wire total includes the cache subtract it).
    pub input: u64,
    pub output: u64,
    /// Additive cache accounting (Anthropic/Bedrock native; OpenAI-family normalized to additive).
    pub cache_read: Option<u64>,
    pub cache_creation: Option<u64>,
    /// Per-modality input breakdown (gpt-4o-transcribe etc). When present, these partition `input`.
    pub input_text: Option<u64>,
    pub input_audio: Option<u64>,
    pub input_image: Option<u64>,
}

/// The billable item produced for one response. Priced by the 1.3 engine via an exhaustive match.
#[derive(Debug, Clone, PartialEq)]
pub enum Billing {
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

// ── The neutral usage_units billing spine (1.6.0 M1) ────────────────────────────────────────────
//
// `Usage` is the ONE neutral carrier a plane hands core: the reserved-four `Copy` summary PLUS an
// opaque keyed-unit map of the OPEN (non-reserved) billable counts. It is ADDITIVE — it sits beside
// the existing usage/ledger types, replacing none, so the hot enforcement path and its `Copy`
// structs are untouched. Core prices it by OPAQUE map lookup (`extras.get(k)`), never by comparing a
// key to a literal, exactly as it treats `CostComponent.label` and `Magnitude.unit` — so no reserved
// key literal lives in a neutral crate: the reserved four ride [`Usage::tokens`] as STRUCT FIELDS,
// and `usage_units` carries only the opens.
//
// The neutral ATTRIBUTION facets (who paid, which pool, which plane, which operation) are a designed
// later-milestone addition — they arrive when a plane is threaded onto the pricer, and their closed
// facets need a purity-gate-compatible home. M1 lands only the priced-usage half of the carrier.

/// The service-tier modifier a plane may carry. CLOSED enum (§7.2 of `billing-unified.md`). A tier
/// is a MODIFIER, not a counted unit, so it never rides `usage_units`; config resolves each variant
/// to an integer basis-point multiplier the pricer applies (`Standard` = ×1.0000 = 10_000 bp).
/// Extend additively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ServiceTier {
    #[default]
    Standard,
    Priority,
    Batch,
    Flex,
}

/// The one neutral usage representation every plane hands core (§2 of `billing-unified.md`).
///
/// `tokens` is the reserved-four `Copy` enforcement/pricing summary (priced by the unchanged
/// `RateNanos::cost_nanos`); `usage_units` carries ONLY the OPEN (non-reserved) keyed counts — the
/// plane projection NEVER emits a reserved name into it (§9.3), so core can iterate it opaquely
/// without ever naming a reserved key. Both are handed together (§2.3): the reserved four never
/// touch a non-`Copy` map, and the opens never touch the hot `Copy` path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Usage {
    /// The reserved-four pricing/enforcement summary, `Copy`.
    pub tokens: busbar_api::TierTokens,
    /// OPAQUE open-key billable counts. Keys are plane/operator DATA, never interpreted by core.
    pub usage_units: std::collections::BTreeMap<String, u64>,
}
