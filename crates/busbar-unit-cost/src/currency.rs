// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The currency a rate is quoted in, and the ONE place a currency's rounding scale is decided.
//!
//! A card prices every cell NATIVELY, once per currency it names. There is no pivot currency here,
//! no exchange table and no conversion: a rate in yen is a configured integer, not a dollar rate
//! multiplied by something. That is why this module carries a scale and nothing else — the moment a
//! cross-rate existed, two currencies would round through each other and the answer would depend on
//! which one was asked for first.

/// An ISO 4217 alphabetic code: three upper-case ASCII letters, validated once when it is built.
///
/// `Copy` and three bytes wide on purpose. A currency is asked for on the hot path — once per priced
/// line, inside the cell lookup — and a currency that owned a `String` would allocate on every one of
/// those, or force the caller to keep one alive across the whole read. Three bytes travel in a
/// register.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CurrencyCode([u8; 3]);

impl CurrencyCode {
    /// The United States dollar — the one currency a 1.5.5 deployment's figures are in.
    ///
    /// 1.5.5 prices in "abstract cost units" with no currency at all and the usage endpoint labels
    /// them `USD` through a synthetic serializer. The migration reads such a card as a card naming
    /// exactly this currency, whose minor exponent is 2, so [`Self::nanos_per_minor`] is ten
    /// million — the same [`crate::NANOS_PER_CENT`] every 1.5.5 figure was projected through, and
    /// every figure comes out bit-identical.
    pub const USD: CurrencyCode = CurrencyCode(*b"USD");

    /// Read a code from text. `None` unless it is exactly three ASCII letters; the code is folded
    /// to upper case, so `usd` and `USD` are the same currency and cannot both be named by one card.
    ///
    /// Validation happens HERE and nowhere else, which is what lets every later step treat the three
    /// bytes as a name rather than as text to be checked again.
    pub fn new(code: &str) -> Option<Self> {
        let bytes = code.as_bytes();
        if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_alphabetic) {
            return None;
        }
        Some(CurrencyCode([
            bytes[0].to_ascii_uppercase(),
            bytes[1].to_ascii_uppercase(),
            bytes[2].to_ascii_uppercase(),
        ]))
    }

    /// The code as text. Always three upper-case ASCII letters, because nothing else can be built.
    pub fn as_str(&self) -> &str {
        // The bytes were checked ASCII-alphabetic at construction and nothing mutates them, so this
        // cannot fail. It is written as a checked conversion rather than an unchecked one because
        // the crate forbids unsafe code outright, and the fallback is a name no card can hold rather
        // than a panic on a money path.
        std::str::from_utf8(&self.0).unwrap_or("???")
    }

    /// The currency's minor-unit exponent: how many decimal places its smallest unit sits at.
    ///
    /// USD 2 (cents), JPY 0 (whole yen), BHD/KWD/TND and their siblings 3 (fils), CLF 4. THE ONE
    /// PLACE A CURRENCY'S ROUNDING SCALE IS DECIDED — [`Self::nanos_per_minor`] is derived from it
    /// and the projection divides by that, so a currency cannot be truncated at two different scales
    /// by two different readers.
    ///
    /// Anything this table does not name is 2. That is the ISO 4217 default and it is the safe
    /// reading: a currency nobody listed rounds like a dollar rather than like a yen, which
    /// truncates less, and truncating less can never bill more than the operator configured.
    pub fn minor_exponent(self) -> u8 {
        match &self.0 {
            // Zero-decimal currencies: the minor unit IS the major unit.
            b"BIF" | b"CLP" | b"DJF" | b"GNF" | b"ISK" | b"JPY" | b"KMF" | b"KRW" | b"PYG"
            | b"RWF" | b"UGX" | b"UYI" | b"VND" | b"VUV" | b"XAF" | b"XOF" | b"XPF" => 0,
            // Three-decimal currencies.
            b"BHD" | b"IQD" | b"JOD" | b"KWD" | b"LYD" | b"OMR" | b"TND" => 3,
            // Four-decimal currencies.
            b"CLF" | b"UYW" => 4,
            _ => 2,
        }
    }

    /// Nano-units of the MAJOR unit in one MINOR unit: ten to the ninth less the minor exponent.
    ///
    /// USD gives ten million, which is [`crate::NANOS_PER_CENT`] exactly. JPY gives a billion — a
    /// yen is its own minor unit. BHD gives a million.
    ///
    /// This is the divisor the single truncation at the end of a read uses, and it is the only
    /// divisor it uses. A rate, an accumulation and a tier are all in nano-units of the major unit
    /// whatever the currency; the currency enters exactly once, at the projection.
    pub fn nanos_per_minor(self) -> u128 {
        match self.minor_exponent() {
            0 => 1_000_000_000,
            1 => 100_000_000,
            2 => 10_000_000,
            3 => 1_000_000,
            // Four is the deepest ISO 4217 goes; the arm is written as the general power anyway so
            // that adding a code to the table above cannot leave this one behind.
            e => 10u128.pow(9 - u32::from(e.min(9))),
        }
    }
}

impl std::fmt::Debug for CurrencyCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The three letters, not a byte array: a currency in a diagnostic should read as a currency.
        f.write_str(self.as_str())
    }
}

impl std::fmt::Display for CurrencyCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
