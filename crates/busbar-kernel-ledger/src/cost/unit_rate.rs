// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AN OPEN METER CLASS'S CONFIGURED RATE, in the card's own representation (#83a O1: the rate-card
//! representation is ledger semantics, so it lives with the card). Relocated verbatim from the
//! shared value crate's `billing` module: the type, its exact-decimal parse and its two-form wire
//! encoding are unchanged, and it reads no float anywhere.

/// **ONE OPEN METER CLASS'S CONFIGURED RATE, held the way the rate card holds it: an integer number
/// of NANO-units per unit** (item 123, #71, #77(4)).
///
/// The four reserved classes cross into the card through
/// [`RawTierRates`](busbar_contract::billing::RawTierRates) and one float conversion (#44's
/// card-build exemption). An OPEN class — any class string a plane declares with its meter, such as
/// `calls` — has its rate configured in the SAME unit (micro-units per unit) but never as a float: the
/// configured text is read EXACTLY, by integer arithmetic over its digits
/// ([`busbar_contract::Count`]), straight into the card's own representation. A rate finer than one
/// nano-unit, negative, or past a `u64` of nano-units is REFUSED at parse — a card that cannot hold
/// a configured rate must not claim to (item 22), and a refusal at the config boundary is the boot
/// refusal #77(5) asks for.
///
/// **THE WIRE FORM.** An integer (`calls: 2000` — 2000 micro-units per unit) or a decimal STRING
/// (`calls: "0.5"`). A bare YAML/JSON float (`0.5` unquoted) is refused: it has already
/// transited a binary double by the time it reaches this type, and a double cannot hold `0.1`. It
/// serializes back to the same two forms, so a config round-trips byte-for-byte exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnitRate(u64);

/// Nano-units per configured micro-unit: the one scale step between the config's unit and the card's
/// — the crate's own [`NANOS_PER_MICRO`](super::NANOS_PER_MICRO), at this type's width.
const NANOS_PER_MICRO_UNIT: u64 = super::NANOS_PER_MICRO as u64;

impl UnitRate {
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
