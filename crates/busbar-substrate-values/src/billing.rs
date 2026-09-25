// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Polymorphic billable-item data model.
//!
//! The billable SHAPES — [`Billing`], [`TokenUsage`], [`Usage`], [`ServiceTier`], [`RawTierRates`]
//! and [`duration_seconds_to_wire`] — moved to `busbar_contract::billing` (DECISIONS #83: contract =
//! shapes; SD-1 of the #83a split) and are re-exported here under their historical paths, so every
//! caller compiles unchanged. What stays is the rate-card representation, [`UnitRate`], which is
//! pricing semantics rather than a shape.

pub use busbar_contract::billing::{
    duration_seconds_to_wire, Billing, RawTierRates, ServiceTier, TokenUsage, Usage,
};

/// The exact decimal every measured quantity is carried in (DECISION #81).
///
/// Re-exported HERE, beside the carrier that holds one, so a codec crate reads and writes a billable
/// quantity through the crate it already depends on for [`Billing`] — no new dependency edge, and
/// one obvious place to look for the type a billable number has.
pub use busbar_contract::Count;

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
