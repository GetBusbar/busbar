// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Polymorphic billable-item data model.
//!
//! The billable UNIT is (operation, model)-dependent: some operations meter tokens, some meter audio
//! DURATION, some meter CHARACTERS, some meter per-item COUNT (e.g. generated images). A single fixed
//! struct cannot represent that, so [`Billing`] is a closed enum every `OperationHandler` emits from a
//! response (or computes from request params when the upstream returns no usage object). The 1.2
//! middle RECORDS every variant (observability from day one) and PRICES [`Billing::Tokens`] exactly as
//! today; the 1.3 governance overhaul prices the remaining units. Closed enum → pricing is an
//! exhaustive match, so adding a unit is a compile error at every price site.
//!
//! Foundation types for the 1.2 operations rebuild; wired into the IR as
//! `IrResp::usage() -> Option<Billing>` (see `ir/variant.rs`). The shipped 1.5.0 pricing path
//! constructs and prices `Billing::Tokens`; `Billing::Characters` (a character-metered operation) is
//! modelled by the IR but not yet priced.
//!
//! NEUTRAL, RELOCATED DOWN from `busbar-core` (Batch C-0): pure data naming zero core type, so a
//! plane crate (`busbar-mcp`) names `Billing`/`TokenUsage` without reaching into `busbar-core`. Core
//! re-exports both from `busbar_kernel::billing` so every in-core and plugin caller compiles unchanged.

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
    /// [`COUNT_SCALE`](busbar_contract::COUNT_SCALE) is 6, so the resolution is one MICROSECOND —
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
}

/// The exact decimal every measured quantity is carried in (DECISION #81).
///
/// Re-exported HERE, beside the carrier that holds one, so a codec crate reads and writes a billable
/// quantity through the crate it already depends on for [`Billing`] — no new dependency edge, and
/// one obvious place to look for the type a billable number has.
pub use busbar_contract::Count;

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
/// (`busbar_kernel::cost::RateNanos::from_raw`) WITHOUT naming the plane's own config type: today
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
    /// `busbar_kernel::config::rate_entry_per_mtok`, which now delegates here.
    pub fn blended_per_mtok(&self) -> f64 {
        (self.input + self.output) / 2.0
    }
}

/// **ONE OPEN METER CLASS'S CONFIGURED RATE, held the way the rate card holds it: an integer number
/// of NANO-units per unit** (item 123, #71, #77(4)).
///
/// The four reserved token classes are configured as `*_utok` micro-units per token and cross into
/// the card through [`RawTierRates`] and one float conversion (#44's card-build exemption). An OPEN
/// class — a rerank's `search_units`, an a2a `hops`, a streaming `audio-seconds` — is a class string
/// the plane declares, and its rate is configured in the SAME unit (micro-units per unit) but is
/// never a float at all: the configured text is read EXACTLY, by integer arithmetic over its digits
/// ([`busbar_contract::Count`]), straight into the card's own representation. A rate finer than one
/// nano-unit, negative, or past a `u64` of nano-units is REFUSED at parse — a card that cannot hold a
/// configured rate must not claim to (item 22), and a refusal at the config boundary is the boot
/// refusal #77(5) asks for.
///
/// **THE WIRE FORM.** An integer (`search_units: 2000` — 2000 micro-units per unit) or a decimal
/// STRING (`search_units: "0.5"`). A bare YAML/JSON float (`0.5` unquoted) is refused: it has already
/// transited a binary double by the time it reaches this type, and a double cannot hold `0.1`. It
/// serializes back to the same two forms, so a config round-trips byte-for-byte exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnitRate(u64);

/// Nano-units per configured micro-unit: the one scale step between the config's unit and the card's.
const NANOS_PER_MICRO_UNIT: u64 = 1_000;

impl UnitRate {
    /// A rate already in the card's representation.
    pub const fn from_nanos(nanos_per_unit: u64) -> UnitRate {
        UnitRate(nanos_per_unit)
    }

    /// The rate in the card's representation: integer nano-units per unit.
    pub const fn nanos_per_unit(self) -> u64 {
        self.0
    }

    /// A whole number of micro-units per unit, exactly; `None` past the representable range.
    pub fn from_whole_micros(micros_per_unit: u64) -> Option<UnitRate> {
        micros_per_unit
            .checked_mul(NANOS_PER_MICRO_UNIT)
            .map(UnitRate)
    }

    /// Decimal text in micro-units per unit, read EXACTLY (no float), or the reason it cannot be.
    pub fn parse_micros(text: &str) -> Result<UnitRate, String> {
        let count = busbar_contract::count::read_count(text)
            .map_err(|e| format!("`{text}` is not an exact non-negative decimal rate ({e:?})"))?;
        // `Count` holds the value at scale 6; the card's unit is scale 3 of the configured one.
        let per_nano = i128::from(1_000_000 / NANOS_PER_MICRO_UNIT);
        if count.micros() % per_nano != 0 {
            return Err(format!(
                "`{text}` micro-units per unit is finer than one nano-unit, the finest rate the card \
                 holds; round it to three decimal places"
            ));
        }
        u64::try_from(count.micros() / per_nano)
            .map(UnitRate)
            .map_err(|_| {
                format!("`{text}` micro-units per unit is past the largest rate the card holds")
            })
    }
}

impl serde::Serialize for UnitRate {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let (whole, frac) = (self.0 / NANOS_PER_MICRO_UNIT, self.0 % NANOS_PER_MICRO_UNIT);
        if frac == 0 {
            s.serialize_u64(whole)
        } else {
            let digits = format!("{frac:03}");
            s.serialize_str(&format!("{whole}.{}", digits.trim_end_matches('0')))
        }
    }
}

impl<'de> serde::Deserialize<'de> for UnitRate {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<UnitRate, D::Error> {
        struct Exact;
        impl serde::de::Visitor<'_> for Exact {
            type Value = UnitRate;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(
                    "a non-negative integer number of micro-units per unit, or an exact decimal \
                     STRING such as \"0.5\" (a bare float is refused: it is not exact)",
                )
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<UnitRate, E> {
                UnitRate::from_whole_micros(v).ok_or_else(|| {
                    E::custom(format!(
                        "{v} micro-units per unit is past the largest rate the card holds"
                    ))
                })
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<UnitRate, E> {
                let v = u64::try_from(v)
                    .map_err(|_| E::custom(format!("a rate cannot be negative (got {v})")))?;
                self.visit_u64(v)
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<UnitRate, E> {
                UnitRate::parse_micros(v).map_err(E::custom)
            }
        }
        d.deserialize_any(Exact)
    }
}

#[cfg(test)]
#[path = "tests/billing_duration_tests.rs"]
mod billing_duration_tests;
