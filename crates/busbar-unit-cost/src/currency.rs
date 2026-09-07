// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The currency a price is quoted in, and the ONE place a currency's rounding scale is decided.
//!
//! A currency here is three upper-case letters and nothing else: no symbol, no name, no exchange
//! rate and no table of conversions. That absence is the design. A card prices every currency it
//! names NATIVELY — one configured integer per (lane, class, currency) — so a price in yen is a
//! configured yen rate, never a dollar rate through a cross-rate. There is no pivot currency in this
//! crate because there is no conversion in this crate to need one.
//!
//! What a currency DOES decide is where the money is cut: how many decimal places its minor unit
//! has. That single number is [`CurrencyCode::minor_exponent`], and every projection in the crate
//! reaches it through [`CurrencyCode::nanos_per_minor`] rather than carrying a divisor of its own.
//! Two copies of a rounding scale is the same defect the crate already paid for once with the rate
//! conversion (see [`crate::nano_rate`]), and the answer is the same: one site.

use std::fmt;

/// ISO 4217 alpha-3, upper-case, validated once when it is built.
///
/// Three bytes, `Copy`, and no allocation anywhere: a currency travels on the hot path beside the
/// lane and the class, and a heap-allocated `String` there would be a per-line allocation for what
/// is always exactly three characters.
///
/// Ordered by the code's bytes, which is what lets a card key its per-currency prices in a
/// `BTreeMap` and iterate them in a stable, deployment-independent order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CurrencyCode([u8; 3]);

impl CurrencyCode {
    /// The currency the 1.5.5 release's abstract cost unit becomes.
    ///
    /// 1.5.5 has no currency at all — its figures are abstract cost units that the legacy usage
    /// endpoint labels `"USD"` on the way out. Reading that deployment as a card naming exactly one
    /// currency, USD, is what makes the migration arithmetically empty: USD's minor exponent is 2,
    /// so [`nanos_per_minor`](Self::nanos_per_minor) is ten million — which is
    /// [`crate::NANOS_PER_CENT`] — and every projected figure is bit-identical to the one the older
    /// release produced.
    pub const USD: CurrencyCode = CurrencyCode(*b"USD");

    /// Build a currency from text, or refuse it.
    ///
    /// Exactly three ASCII letters, upper-case. Lower case is REFUSED rather than folded: a card
    /// keyed by `usd` and a read asking for `USD` must not be two names for one bucket, because the
    /// only thing standing between a reader and a wrong currency is that the two spellings compared
    /// unequal. Folding here would make `usd` and `USD` the same key at this seam and different keys
    /// at any seam that stores the operator's text, which is worse than refusing.
    pub fn new(code: &str) -> Option<Self> {
        let bytes = code.as_bytes();
        let [a, b, c] = <[u8; 3]>::try_from(bytes).ok()?;
        if [a, b, c].iter().all(|byte| byte.is_ascii_uppercase()) {
            Some(CurrencyCode([a, b, c]))
        } else {
            None
        }
    }

    /// The three letters, borrowed.
    pub fn as_str(&self) -> &str {
        // The constructor admits only ASCII upper-case bytes, so the slice is valid UTF-8 by
        // construction; the fallback keeps the method total without an unsafe conversion.
        std::str::from_utf8(&self.0).unwrap_or("???")
    }

    /// The currency's minor-unit exponent: how many decimal places its smallest denomination has.
    ///
    /// THE ONE PLACE A CURRENCY'S ROUNDING SCALE IS DECIDED. USD is 2 (cents), JPY is 0 (there is no
    /// sub-yen denomination), the Gulf dinars are 3 (fils), and CLF is 4.
    ///
    /// A currency this table does not name reads as 2, and that default is deliberate rather than
    /// lazy: two places is what the overwhelming majority of ISO 4217 currencies use, and a wrong
    /// guess here truncates a fraction of one minor unit rather than mis-scaling a figure by a
    /// factor of a hundred. The exponent is NOT read from config, because a rounding scale an
    /// operator can type is a rounding scale an operator can type wrong.
    pub fn minor_exponent(self) -> u8 {
        match &self.0 {
            // No minor unit at all: the major unit is the smallest denomination there is.
            b"BIF" | b"CLP" | b"DJF" | b"GNF" | b"ISK" | b"JPY" | b"KMF" | b"KRW" | b"PYG"
            | b"RWF" | b"UGX" | b"UYI" | b"VND" | b"VUV" | b"XAF" | b"XOF" | b"XPF" => 0,
            // Three places: the Gulf and North African dinars, and the ouguiya's khoums.
            b"BHD" | b"IQD" | b"JOD" | b"KWD" | b"LYD" | b"OMR" | b"TND" => 3,
            // Four places: the accounting units.
            b"CLF" | b"UYW" => 4,
            _ => 2,
        }
    }

    /// Nano-units of the major unit in one minor unit: ten to the power of nine less the exponent.
    ///
    /// Every projection in the crate divides by THIS and never by a literal, so adding a currency
    /// cannot leave a divisor behind somewhere. USD gives ten million, which is
    /// [`crate::NANOS_PER_CENT`] exactly; JPY gives a billion, so a yen figure truncates at the
    /// whole yen; BHD gives a million, so a dinar figure truncates at the fils.
    pub fn nanos_per_minor(self) -> u128 {
        10u128.pow(9 - u32::from(self.minor_exponent()))
    }
}

impl fmt::Display for CurrencyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for CurrencyCode {
    /// The code itself, so a failing assertion names the currency rather than three byte values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
