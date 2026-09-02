// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAYER 4 — USAGE / RATE-LIMIT (EXTRACTION only). Design §2.5.
//!
//! `response.done.usage` (audio vs text are SEPARATE token classes, audio dominates) and
//! `rate_limits.updated` are EXTRACTED, never client-translated. This is the metering/audit tap that
//! the plane folds into a `CostBreakdown` (whose labeled components core never interprets) feeding
//! `cost_settle` + `journal_append_scoped`. The same move the LLM reader makes with `IrUsage`.

/// THE NEUTRAL USAGE CARRIER — token classes the plane extracts from a duplex turn. Folded into a
/// `CostBreakdown` whose top-level components sum to `total` (the one invariant core enforces), with
/// audio/text as labeled opaque components core never interprets.
///
/// SKELETON: a plain token-class tally; the `CostBreakdown` fold is future work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IrDuplexUsage {
    /// Audio input tokens consumed this turn.
    pub audio_in: u64,
    /// Audio output tokens produced this turn.
    pub audio_out: u64,
    /// Text input tokens consumed this turn.
    pub text_in: u64,
    /// Text output tokens produced this turn.
    pub text_out: u64,
    /// Cached tokens billed at the cache rate this turn.
    pub cached: u64,
}
