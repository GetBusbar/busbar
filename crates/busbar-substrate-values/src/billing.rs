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

// ── The neutral usage_units billing spine (1.6.0 M1b) ───────────────────────────────────────────
//
// `Usage` is the ONE neutral carrier a plane hands core: a SINGLE opaque name-keyed unit map. The
// reserved four (input/output/cache_read/cache_write) are now ORDINARY KEYS in that one map beside
// every open (operator/plane) unit — `TierTokens` is dissolved (M1b). This crate stays PURE: it
// names no reserved key literal at all; it is just a `BTreeMap<String, u64>` here. Core prices it by
// looking each key up against the rate card (the reserved four via the tier rates, opens via the
// per-model extras table), exactly as it treats `CostComponent.label` and `Magnitude.unit`.
//
// The neutral ATTRIBUTION facets (who paid, which pool, which plane, which operation) are a designed
// later-milestone addition — they arrive when a plane is threaded onto the pricer, and their closed
// facets need a purity-gate-compatible home. M1b lands only the priced-usage half of the carrier.

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
/// (1.6.0 M1b) `usage_units` is the SOLE representation: the reserved four
/// (`input`/`output`/`cache_read`/`cache_write`) are ordinary keys beside every open (non-reserved)
/// keyed count. Core iterates it opaquely and prices each key against the rate card. This crate
/// names no reserved literal — the map is pure DATA here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Usage {
    /// OPAQUE billable counts, reserved four AND opens. Keys are plane/operator DATA.
    pub usage_units: std::collections::BTreeMap<String, u64>,
}

/// THE NEUTRAL RAW-RATE VIEW (1.6.0 config-seam S2a): one entry's four reserved-tier rates as RAW
/// micro-float-per-token values (1e-6 abstract cost unit per token), in the CANONICAL reserved-four
/// order the engine already fixes ([`busbar_api::RESERVED_UNITS`] = input, output, cache_read,
/// cache_write). The field names are the neutral reserved-unit spellings (`busbar_api::UNIT_INPUT`
/// …), NOT any plane's config grammar (`rate_card:`'s `input_utok:` etc.).
///
/// It is the read-back seam core's pricing oracle projects to integer nanos through
/// (`busbar_core::cost::RateNanos::from_raw`) WITHOUT naming the plane's own config type: today
/// (S2a) core fills it from its in-core `RateEntryCfg`; once the `rate_card:` grammar relocates to
/// the owning plane (S2b, `busbar-llm`), the plane fills the SAME view from its parsed section and
/// core is unchanged. FLOATS live ONLY at this config boundary; the projection to integer nanos and
/// all hot-path math stay integer, exactly as before.
///
/// THE REUSABLE PATTERN: each evictable numeric config section (S3 `limits`, S4 `models`-caps) gets
/// its own neutral raw-value view of this shape — a small POD of the section's raw scalars in a
/// canonical order — that core reads through and the owning plane fills. The section's GRAMMAR (field
/// spellings, `deny_unknown_fields`, validation strings) stays with the plane; only these neutral
/// numbers cross into core.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct RawTierRates {
    /// Raw micro-units per token for the `input` reserved tier (`busbar_api::UNIT_INPUT`).
    pub input: f64,
    /// Raw micro-units per token for the `output` reserved tier (`busbar_api::UNIT_OUTPUT`).
    pub output: f64,
    /// Raw micro-units per token for the `cache_read` reserved tier (`busbar_api::UNIT_CACHE_READ`).
    pub cache_read: f64,
    /// Raw micro-units per token for the `cache_write` reserved tier (`busbar_api::UNIT_CACHE_WRITE`).
    pub cache_write: f64,
}

impl RawTierRates {
    /// The ROUTING cost scalar (abstract units per MILLION tokens) the `cheapest` policy and the hook
    /// `Candidate.cost_per_mtok` signal read: the blended `(input + output) / 2` (1 micro-unit/token
    /// == 1 unit/mtok, so no further scaling). Byte-identical to the pre-seam
    /// `busbar_core::config::rate_entry_per_mtok`, which now delegates here.
    pub fn blended_per_mtok(&self) -> f64 {
        (self.input + self.output) / 2.0
    }
}
