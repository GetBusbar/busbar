// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAYER 4 — USAGE / RATE-LIMIT (EXTRACTION only). Design `plane4-duplex-session.md` §2.5.
//!
//! `response.done.usage` (audio vs text are SEPARATE token classes, audio dominates) and
//! `rate_limits.updated` are EXTRACTED, never client-translated. This is the metering/audit tap that
//! the plane folds into a `CostBreakdown` (whose labeled components core never interprets) feeding
//! `cost_settle` + `journal_append_scoped`. The same move the LLM reader makes with `IrUsage`.

/// THE NEUTRAL USAGE CARRIER — token classes the plane extracts from a duplex turn. Folded into a
/// `CostBreakdown` whose top-level components sum to `total` (the one invariant core enforces), with
/// audio/text as labeled opaque components core never interprets.
///
/// A plain token-class tally, folded (5→4 reserved keys, see [`Self::to_billing_usage`]) onto the
/// neutral [`busbar_substrate::billing::Usage`] the host prices via the D2 lease's `price_usage`
/// (`runtime::metering::MeteringPort::price_usage`) and settled through `cost_settle`.
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

impl IrDuplexUsage {
    /// FOLD this turn's five token classes onto the neutral [`busbar_substrate::billing::Usage`] the
    /// host prices — the 5→4 reserved-key map the plane hands
    /// [`MeteringHost::price_usage`](busbar_substrate::plane_host::MeteringHost::price_usage). Audio and
    /// text collapse onto the SAME reserved lane by direction (a session prices audio vs text as separate
    /// rate-card MODEL lanes, never separate unit keys), so NO new unit/label/constant is introduced —
    /// only the four EXISTING reserved keys ([`busbar_api::UNIT_INPUT`]/`UNIT_OUTPUT`/`UNIT_CACHE_READ`):
    ///
    /// - `audio_in + text_in` → `input`
    /// - `audio_out + text_out` → `output`
    /// - `cached` → `cache_read`
    ///
    /// Only non-zero classes are keyed (the pricer reads absent keys as zero, so this is purely tidy —
    /// no zero component ever prices). Saturating sums: a runaway turn pins the count, never wraps small.
    #[must_use]
    pub fn to_billing_usage(&self) -> busbar_substrate::billing::Usage {
        let mut usage_units = std::collections::BTreeMap::new();
        let input = self.audio_in.saturating_add(self.text_in);
        let output = self.audio_out.saturating_add(self.text_out);
        if input != 0 {
            usage_units.insert(busbar_api::UNIT_INPUT.to_string(), input);
        }
        if output != 0 {
            usage_units.insert(busbar_api::UNIT_OUTPUT.to_string(), output);
        }
        if self.cached != 0 {
            usage_units.insert(busbar_api::UNIT_CACHE_READ.to_string(), self.cached);
        }
        busbar_substrate::billing::Usage { usage_units }
    }
}
