// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BILLABLE-ITEM SHAPES a plane fills and the kernel prices (DECISIONS #83: contract = shapes).
//!
//! The billable UNIT is (operation, model)-dependent: some operations meter tokens, some meter audio
//! DURATION, some meter CHARACTERS, some meter per-item COUNT (e.g. generated images). A single fixed
//! struct cannot represent that, so [`Billing`] is a closed enum every operation codec emits from a
//! response (or computes from request params when the upstream returns no usage object). Closed enum
//! → pricing is an exhaustive match, so adding a unit is a compile error at every price site.
//!
//! [`Usage`] is the ONE neutral carrier a plane hands the kernel, [`TokenUsage`] the token total a
//! reader projects, and [`RawTierRates`] the neutral exact tier-rate view a plane fills from its own
//! rate card grammar. Every side of the seam must agree on these fields, which is what makes them shapes.
//!
//! RELOCATED, module-path-only and byte-identical, from `busbar-substrate-values::billing`, which
//! re-exports every item here under its historical path so every caller compiles unchanged. The
//! rate-card representation (`UnitRate`, its parse refusals) is semantics and stays there.

use crate::Count;

/// Token usage — the SUPERSET of chat's cache-aware accounting AND other operations' modality
/// breakdown.
///
/// Subsumes the former `ir::IrUsage`: `input` is UNCACHED input (readers normalize to this), the
/// cache fields stay ADDITIVE across protocols, and the optional per-modality fields carry
/// audio/text/image usage detail (as some transcription-style operations report) — without losing
/// the chat cache convention. So one `Tokens` variant is lossless for chat (cache) and other
/// modality-reporting operations alike.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenUsage {
    /// Uncached input tokens (normalized; an upstream whose wire total includes the cache subtracts it).
    pub input: u64,
    pub output: u64,
    /// Additive cache accounting (some upstreams report it natively as additive; others are
    /// normalized to additive by the reader).
    pub cache_read: Option<u64>,
    pub cache_creation: Option<u64>,
    /// Per-modality input breakdown (as some transcription-style operations report). When present,
    /// these partition `input`.
    pub input_text: Option<u64>,
    pub input_audio: Option<u64>,
    pub input_image: Option<u64>,
    /// Every OPEN class the reader counted beside the token split (a turn's billed searches), keyed
    /// by the class the plane declares and ledgered verbatim beside the reserved four (#71). A zero
    /// count is not carried.
    pub open_units: std::collections::BTreeMap<String, u64>,
    /// RESIDUALS: counts the provider reported that no billing class records (MONEY LAW, owner
    /// 2026-10-02), keyed by the provider's own count name (a policy-unit count, or
    /// `<identity>.stated_total_gap` for a stated total above its itemized sum). NEVER BILLED: no billed-usage builder reads this map, and no
    /// meter class is made from it. The reader WARNs where it fills it; no durable row is written
    /// for it. Sparse: a zero count is left off.
    pub residual_units: std::collections::BTreeMap<String, u64>,
}

/// The billable item produced for one response. Priced by the 1.3 engine via an exhaustive match.
#[derive(Debug, Clone, PartialEq)]
pub enum Billing {
    /// Token-metered (the common case: chat, embeddings, and most other token-based operations).
    Tokens(TokenUsage),
    /// Audio duration in seconds (an operation whose upstream usage reports elapsed audio time
    /// rather than a token count).
    ///
    /// AN EXACT DECIMAL, NOT A DOUBLE (#81, #77(8)). Seconds are a MEASUREMENT at a fixed scale in
    /// exactly the way tokens are, and `12.1` is no more representable in binary floating point than
    /// `27.1` is — a double holds it as `12.0999999999999996447…`. That is invisible until the
    /// quantity is multiplied or summed, and then it is not: sampled over 400,000 realistic
    /// `duration x rate` pairs, better than one in eight products already differs from the exact
    /// answer, and ten thousand calls of `0.1s` sum to `1000.0000000001588` rather than `1000`. A
    /// duration is not priced yet, so nothing has been mis-billed; carrying it exactly NOW is what
    /// makes sure nothing ever is, and doing it while the quantity is unpriced is the cheapest
    /// moment this change will ever have.
    ///
    /// [`COUNT_SCALE`](crate::COUNT_SCALE) is 6, so the resolution is one MICROSECOND —
    /// finer than any provider reports elapsed audio time.
    Duration { seconds: Count },
    /// Character count (an operation whose upstream carries no usage object in the body; the
    /// count is derived from the request input instead).
    /// Modelled by the IR (constructed by the character-metered billing path) but not yet priced;
    /// the shipped 1.5.0 pricing path only prices `Billing::Tokens`.
    #[cfg_attr(not(test), allow(dead_code))]
    Characters { count: u64 },
    /// Per-item count, tiered by size/quality (an image-generation-style operation with no usage
    /// object in the body).
    Images {
        count: u32,
        size: Option<String>,
        quality: Option<String>,
    },
    /// Flat / no meter (an operation with no usage-based cost, e.g. content moderation).
    Flat,
    /// A COUNTED non-token unit the provider billed (item 134): a rerank's search units. The
    /// `class` is the plane's DATA — the meter-class string it declares and an operator prices under
    /// `rate_card.<model>.units` (#77(1)/(4)); this crate names no class. Ledgered verbatim as that
    /// open class (#71); a present card silent about it refuses (#42), an absent card reads 0.
    Counted { class: String, count: u64 },
}

/// RENDER AN EXACT DURATION BACK ONTO THE WIRE, AND THE ONLY PLACE A BILLABLE QUANTITY BECOMES A
/// DOUBLE.
///
/// The usage object busbar echoes to the caller is JSON, and a JSON number in a
/// [`serde_json::Value`] can only be built from an integer or an `f64` — there is no constructor
/// that takes a decimal string unless `serde_json`'s `arbitrary_precision` feature is turned on for
/// the whole workspace, which would change `Number`'s representation for every unrelated read in the
/// tree. So the conversion happens HERE, once, at the boundary where the number stops being a
/// quantity and becomes a rendering of one — exactly the shape of the #44 card-build exemption, and
/// for the same reason: a boundary is where a decimal is allowed, a runtime path is not.
///
/// IT IS BYTE-IDENTICAL, AND THAT IS MEASURED RATHER THAN HOPED. `micros / 1e6` and parsing the
/// original decimal text produce THE SAME DOUBLE, bit for bit, for every quantity the scale can
/// hold: checked over 200,009 values spanning zero to a thousand hours, zero differed. So a response
/// busbar echoes carries the same bytes it carried before the quantity became exact.
#[must_use]
pub fn duration_seconds_to_wire(seconds: Count) -> f64 {
    // Both operands are exactly representable and the division is correctly rounded, so the result
    // is the nearest double to the exact decimal — which is precisely what parsing the text gives.
    seconds.micros() as f64 / 1_000_000.0_f64
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

/// The service-tier modifier a plane may carry. CLOSED enum (the service-tier section of
/// `BUSBAR-1.6.0.md` THE DESIGN). A tier is a MODIFIER, not a counted unit, so it never rides `usage_units`;
/// config resolves each variant to an integer basis-point multiplier the pricer applies (`Standard`
/// = ×1.0000 = 10_000 bp). Extend additively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ServiceTier {
    #[default]
    Standard,
    Priority,
    Batch,
    Flex,
}

/// The one neutral usage representation every plane hands core (the neutral-usage section of
/// `BUSBAR-1.6.0.md` THE DESIGN).
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

/// THE NEUTRAL TIER-RATE VIEW (1.6.0 config-seam S2a): one entry's four reserved-tier rates as EXACT
/// integer NANO-units per token (1e-9 abstract cost unit per token), in the CANONICAL reserved-four
/// order the engine already fixes ([`crate::records::RESERVED_UNITS`] = input, output, cache_read,
/// cache_write). The field names are the neutral reserved-unit spellings (`crate::records::UNIT_INPUT`
/// …), NOT any plane's config grammar (`rate_card:`'s `input_utok:` etc.).
///
/// NO FLOAT CROSSES THIS SEAM (#81, #77(8)). The configured decimal is converted ONCE, at the config
/// intake (`RateEntryCfg::raw_tier_rates`, through the ledger's `representable_nano_rate`), and
/// every hop after it — the rate-apply seam, the root's relay, the card — carries these integers
/// unchanged. `None` is a configured rate the card CANNOT hold (item 22: a positive rate that is not
/// a whole number of nano-units, or past a `u64`; never rounded, OWNER rule 21), which boot
/// validation refuses and the card records UNPRICED so a hit refuses (#42); it is never read as zero.
///
/// THE REUSABLE PATTERN: each evictable numeric config section (S3 `limits`, S4 `models`-caps) gets
/// its own neutral view of this shape — a small POD of the section's values in a canonical order —
/// that core reads through and the owning plane fills. The section's GRAMMAR (field spellings,
/// `deny_unknown_fields`, validation strings) stays with the plane; only these neutral numbers cross
/// into core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawTierRates {
    /// Nano-units per token for the `input` reserved tier (`crate::records::UNIT_INPUT`).
    pub input: Option<u64>,
    /// Nano-units per token for the `output` reserved tier (`crate::records::UNIT_OUTPUT`).
    pub output: Option<u64>,
    /// Nano-units per token for the `cache_read` reserved tier (`crate::records::UNIT_CACHE_READ`).
    pub cache_read: Option<u64>,
    /// Nano-units per token for the `cache_write` reserved tier (`crate::records::UNIT_CACHE_WRITE`).
    pub cache_write: Option<u64>,
}

impl Default for RawTierRates {
    /// Every tier configured at zero — an omitted tier prices at 0 (1.5.5's `#[serde(default)]`).
    fn default() -> Self {
        RawTierRates {
            input: Some(0),
            output: Some(0),
            cache_read: Some(0),
            cache_write: Some(0),
        }
    }
}

/// READ A JSON NUMBER AS AN EXACT, NON-NEGATIVE INTEGER COUNT, or `None` when it is not one: the
/// one seam a plane reads a billed count through (plane-llm `codec/usage_count.rs` and
/// plane-streaming `codec/ir/usage.rs` each carried it).
///
/// [`serde_json::Value::as_u64`] answers `None` for ANY float-backed number, `27.0` included, so a
/// provider that spells a count as a float would read as zero work: a ledger that says nothing
/// happened, faithfully wrong in every money view over it. The integer representation is tried
/// first; the float one only when it provably denotes an exact integer.
///
/// A fractional value (never rounded: rounding invents a quantity), a negative one, a non-finite
/// one, and anything at or above 2^53 (past which every `f64` has `fract() == 0.0`, so the
/// integrality test proves nothing) all read as `None`.
#[must_use]
pub fn read_count_u64(v: &serde_json::Value) -> Option<u64> {
    if let Some(u) = v.as_u64() {
        return Some(u);
    }
    let f = v.as_f64()?;
    // 2^53. `contains` also rejects NaN and both infinities, which compare inside no range.
    const EXACT_INTEGER_LIMIT: f64 = 9_007_199_254_740_992.0;
    if (0.0..EXACT_INTEGER_LIMIT).contains(&f) && f.fract() == 0.0 {
        Some(f as u64)
    } else {
        None
    }
}

#[cfg(test)]
#[path = "tests/billing_duration_tests.rs"]
mod billing_duration_tests;

#[cfg(test)]
#[path = "tests/billing_count_tests.rs"]
mod billing_count_tests;
