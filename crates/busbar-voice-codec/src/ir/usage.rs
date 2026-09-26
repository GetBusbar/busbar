// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAYER 4 — USAGE / RATE-LIMIT (EXTRACTION only). Design `plane4-duplex-session.md`.
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
/// neutral [`busbar_contract::billing::Usage`] the host prices via the D2 lease's `price_usage`
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
    /// FOLD this turn's five token classes onto the neutral [`busbar_contract::billing::Usage`] the
    /// host prices — the 5→4 reserved-key map the plane hands
    /// `MeteringHost::price_usage` (the host's pricer). Audio and
    /// text collapse onto the SAME reserved lane by direction (a session prices audio vs text as separate
    /// rate-card MODEL lanes, never separate unit keys), so NO new unit/label/constant is introduced —
    /// only the four EXISTING reserved keys ([`busbar_contract::records::UNIT_INPUT`]/`UNIT_OUTPUT`/`UNIT_CACHE_READ`):
    ///
    /// - `(audio_in + text_in) - cached` → `input`
    /// - `audio_out + text_out` → `output`
    /// - `cached` → `cache_read`
    ///
    /// `cached` is NETTED OUT of the input lane because in BOTH dialects the cached figure is a SUBSET
    /// of the input figure, not a class beside it — OpenAI Realtime reports `cached_tokens` INSIDE
    /// `input_token_details` alongside `audio_tokens`/`text_tokens`, and Gemini's
    /// `cachedContentTokenCount` is part of `promptTokenCount` (which is what `promptTokensDetails`
    /// breaks out by modality). Billing the full input figure AND the cache figure would charge the
    /// cached tokens on two lanes at once. This is the same normalization the LLM plane's reader makes
    /// (`prompt_tokens` minus `cached_tokens` is what lands on the input lane), so a cached turn prices
    /// identically whichever plane carried it.
    ///
    /// The IR carrier itself stays wire-faithful (extraction-only, raw provider figures, so the
    /// re-frame writers round-trip); the netting happens HERE, at the billing fold, and nowhere else.
    ///
    /// Only non-zero classes are keyed (the pricer reads absent keys as zero, so this is purely tidy —
    /// no zero component ever prices). Saturating sums: a runaway turn pins the count, never wraps small.
    /// The subtraction saturates too: a provider that over-reports `cached` floors the input lane at
    /// zero rather than wrapping to a colossal charge.
    #[must_use]
    pub fn to_billing_usage(&self) -> busbar_contract::billing::Usage {
        let mut usage_units = std::collections::BTreeMap::new();
        let input = self
            .audio_in
            .saturating_add(self.text_in)
            .saturating_sub(self.cached);
        let output = self.audio_out.saturating_add(self.text_out);
        if input != 0 {
            usage_units.insert(busbar_contract::records::UNIT_INPUT.to_string(), input);
        }
        if output != 0 {
            usage_units.insert(busbar_contract::records::UNIT_OUTPUT.to_string(), output);
        }
        if self.cached != 0 {
            usage_units.insert(
                busbar_contract::records::UNIT_CACHE_READ.to_string(),
                self.cached,
            );
        }
        busbar_contract::billing::Usage { usage_units }
    }
}

/// THE ONE SEAM every BILLED count read in this crate goes through.
///
/// # Why this exists here, beside the carrier it fills
///
/// [`serde_json::Value::as_u64`] returns `None` for ANY float-backed `Number` — including `27.0`,
/// which is exactly an integer. The house idiom in the duplex dialects was
/// `.and_then(Value::as_u64).unwrap_or_default()`, so a provider that spells a count as a float
/// turned a real count of 27 into a recorded count of ZERO. That is not a money bug, it is a
/// LEDGER bug, which is worse: money is a view over `ledger × ratecard` and cannot be wrong on its
/// own, so a zeroed count is faithfully reported as nothing at every layer below and is invisible
/// everywhere except here, at the read.
///
/// The LLM codec crate carries the identical seam (`busbar_llm_codec::usage_count::read_count_u64`)
/// and this is deliberately a SEPARATE copy, not an import: the two crates are per-plane codecs and
/// a codec→codec edge is a lateral plugin edge (BUSBAR-1.6.0 Law 2), which no convenience justifies.
/// The honest single home for both is a neutral crate, and consolidating them there is OWED — it is
/// tracked with the decimal-count work (decision #81), which replaces the `u64` return type here
/// with an exact fixed-point decimal read from the JSON number's TEXT. Until that lands this
/// function is the one place in this crate a count is read, so that swap is a one-function change
/// rather than a hunt through five call sites.
///
/// # What is rejected, and why
///
/// A fractional value, a negative value, a non-finite value, and anything at or above 2^53 (past
/// which an `f64` no longer represents consecutive integers, so the integrality test stops carrying
/// information) all read as `None`. Rounding would invent a quantity the provider never reported.
///
/// CAVEAT, STATED PLAINLY: every caller in this crate currently ends in `unwrap_or_default()`, so a
/// refused value still lands as ZERO. Decision #81 rules that a refused count is a REFUSAL, never a
/// zero; implementing that refusal is the decimal-count work's, not this seam's.
#[must_use]
pub fn read_count_u64(v: &serde_json::Value) -> Option<u64> {
    if let Some(u) = v.as_u64() {
        return Some(u);
    }
    let f = v.as_f64()?;
    // 2^53 — the largest magnitude at which an f64 still represents every integer distinctly, and
    // therefore the largest at which `fract() == 0.0` still proves anything. `contains` also
    // rejects NaN and both infinities, since neither compares inside any range.
    const EXACT_INTEGER_LIMIT: f64 = 9_007_199_254_740_992.0;
    if (0.0..EXACT_INTEGER_LIMIT).contains(&f) && f.fract() == 0.0 {
        Some(f as u64)
    } else {
        None
    }
}
