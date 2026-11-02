// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The exact decimal quantity every usage count is measured in (DECISION #81).

use core::fmt;

use crate::json_grammar::{resolve_pointer, Resolved};

/// The ONE scale every count is held at: six decimal places, i.e. micro-units.

pub const COUNT_SCALE: u32 = 6;

/// `10^COUNT_SCALE`: how many mantissa steps make one whole unit.
const SCALE_FACTOR: i128 = 1_000_000;

/// The largest quantity a [`Count`] can hold: `170141183460469231731687303715884.105727`.
pub const MAX: Count = Count(i128::MAX);

/// The smallest quantity a [`Count`] can hold: `-170141183460469231731687303715884.105728`.
pub const MIN: Count = Count(i128::MIN);

/// The largest quantity whose mantissa still fits a SIGNED 64-BIT store column — about `9.2e12`

pub const MAX_ACROSS_A_64_BIT_COLUMN: Count = Count(i64::MAX as i128);

/// The smallest quantity whose mantissa still fits a signed 64-bit store column.
pub const MIN_ACROSS_A_64_BIT_COLUMN: Count = Count(i64::MIN as i128);

/// The scale a record's SILENCE means: whole units, no fraction (#81a).

pub const SCALE_WHOLE_UNITS: u32 = 0;

/// The scale every row written from here on declares: micro-units, i.e. [`COUNT_SCALE`].
pub const SCALE_MICRO_UNITS: u32 = COUNT_SCALE;

/// The scale a record's absent discriminator means — the function `#[serde(default = "…")]` names.

#[must_use]
pub const fn stored_scale_default() -> u32 {
    SCALE_WHOLE_UNITS
}

/// An exact decimal quantity: an `i128` count of micro-units.
///
/// Two counts are equal when they are the same quantity, and ordered the way the quantities are
/// ordered, because there is exactly one mantissa per quantity. Construct one from decimal text
/// with [`Count::parse`], from a whole number with [`Count::from_integer`], or from a mantissa
/// already at the scale with [`Count::from_micros`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Count(i128);

impl Count {
    /// Nothing measured.
    pub const ZERO: Count = Count(0);

    /// One whole unit.
    pub const ONE: Count = Count(SCALE_FACTOR);

    /// The smallest quantity the scale distinguishes: `0.000001`.
    pub const EPSILON: Count = Count(1);

    /// A count from a mantissa that is ALREADY at [`COUNT_SCALE`].

    #[must_use]
    pub const fn from_micros(micros: i128) -> Count {
        Count(micros)
    }

    /// The mantissa at [`COUNT_SCALE`] — the exact integer this count IS.
    #[must_use]
    pub const fn micros(self) -> i128 {
        self.0
    }

    /// A count of `n` whole units.

    pub const fn from_integer(n: i128) -> Result<Count, CountError> {
        match n.checked_mul(SCALE_FACTOR) {
            Some(m) => Ok(Count(m)),
            None => Err(CountError::OutOfRange),
        }
    }

    /// Whether this is exactly nothing.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Whether this quantity is below zero.
    #[must_use]
    pub const fn is_negative(self) -> bool {
        self.0 < 0
    }

    /// Whether this quantity's mantissa fits a signed 64-bit store column.

    #[must_use]
    pub const fn fits_a_64_bit_column(self) -> bool {
        self.0 >= MIN_ACROSS_A_64_BIT_COLUMN.0 && self.0 <= MAX_ACROSS_A_64_BIT_COLUMN.0
    }

    /// Read a count back out of a store, branching on the row's own scale discriminator (#81a).

    pub const fn from_stored(value: i128, scale: u32) -> Result<Count, CountError> {
        if scale == SCALE_WHOLE_UNITS {
            return Count::from_integer(value);
        }
        if scale == SCALE_MICRO_UNITS {
            return Ok(Count(value));
        }
        Err(CountError::UnknownScale)
    }

    /// `self + rhs`, exactly.

    pub const fn checked_add(self, rhs: Count) -> Result<Count, CountError> {
        match self.0.checked_add(rhs.0) {
            Some(m) => Ok(Count(m)),
            None => Err(CountError::Overflow),
        }
    }

    /// `self - rhs`, exactly.

    pub const fn checked_sub(self, rhs: Count) -> Result<Count, CountError> {
        match self.0.checked_sub(rhs.0) {
            Some(m) => Ok(Count(m)),
            None => Err(CountError::Overflow),
        }
    }

    /// `self * rate`, where the rate is itself an exact decimal at the same scale.

    pub const fn checked_mul(self, rate: Count) -> Result<Count, CountError> {
        match self.0.checked_mul(rate.0) {
            None => Err(CountError::Overflow),
            Some(wide) => {
                if wide % SCALE_FACTOR != 0 {
                    Err(CountError::Inexact)
                } else {
                    Ok(Count(wide / SCALE_FACTOR))
                }
            }
        }
    }

    /// The exact mantissa of `self * rate` at DOUBLE the scale (12 places).

    pub const fn checked_mul_wide(self, rate: Count) -> Result<i128, CountError> {
        match self.0.checked_mul(rate.0) {
            Some(wide) => Ok(wide),
            None => Err(CountError::Overflow),
        }
    }

    /// The total of a sequence, exactly.

    pub fn total<I: IntoIterator<Item = Count>>(counts: I) -> Result<Count, CountError> {
        let mut acc = Count::ZERO;
        for c in counts {
            acc = acc.checked_add(c)?;
        }
        Ok(acc)
    }

    /// The canonical decimal spelling of this quantity.

    #[must_use]
    pub fn to_decimal_string(self) -> String {
        let magnitude = self.0.unsigned_abs();
        let whole = magnitude / (SCALE_FACTOR as u128);
        let fraction = magnitude % (SCALE_FACTOR as u128);
        let sign = if self.0 < 0 { "-" } else { "" };
        if fraction == 0 {
            return format!("{sign}{whole}");
        }
        let mut places = format!("{fraction:0width$}", width = COUNT_SCALE as usize);
        while places.ends_with('0') {
            places.pop();
        }
        format!("{sign}{whole}.{places}")
    }

    /// Read decimal TEXT as an exact count.

    pub fn parse(text: &str) -> Result<Count, CountError> {
        Count::parse_bytes(text.as_bytes())
    }

    /// Read decimal text as an exact count, from bytes.

    pub fn parse_bytes(text: &[u8]) -> Result<Count, CountError> {
        let lexed = lex(text)?;
        if lexed.all_zero {
            return Ok(Count::ZERO);
        }

        let shift = (COUNT_SCALE as i64)
            .checked_add(lexed.exponent)
            .and_then(|v| v.checked_sub(lexed.fraction_len))
            .ok_or(CountError::OutOfRange)?;
        mantissa(lexed.digits, shift, lexed.negative)
    }

    /// Read a JSON number located by pointer, straight out of a body's bytes.

    pub fn read_at(body: &[u8], pointer: &str) -> Result<Option<Count>, CountError> {
        match resolve_pointer(body, pointer) {
            Resolved::Found(span) => {
                let raw = span.of(body);
                let trimmed = trim_ascii_whitespace(raw);
                read_count_bytes(trimmed).map(Some)
            }
            Resolved::Missing => Ok(None),
            Resolved::NeedMore => Err(CountError::Truncated),
            Resolved::Malformed => Err(CountError::Malformed),
        }
    }
}

/// THE SEAM: read one reported usage count from its decimal text.

pub fn read_count(text: &str) -> Result<Count, CountError> {
    read_count_bytes(text.as_bytes())
}

/// THE SEAM, over bytes — see [`read_count`].

pub fn read_count_bytes(text: &[u8]) -> Result<Count, CountError> {
    let count = Count::parse_bytes(text)?;
    if count.is_negative() {
        return Err(CountError::Negative);
    }
    Ok(count)
}

/// Why a quantity was refused.
///
/// Every variant is a refusal to invent. None of them has a "near enough" sibling, on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CountError {
    /// There was no text to read.
    Empty,
    /// The text is not a JSON number.
    Malformed,
    /// The bytes ran out before the value did; a later chunk may complete it.
    Truncated,
    /// The quantity is exact but finer than [`COUNT_SCALE`] — `0.0000001` has a seventh place and
    /// the scale has six. Rounding it away would be inventing the measurement.
    TooFine,
    /// The magnitude is past what the scale can hold.
    OutOfRange,
    /// An addition or a multiplication would leave the range.
    Overflow,
    /// A product needs more than [`COUNT_SCALE`] places to be stated exactly.
    Inexact,
    /// A measurement below zero, at the reading seam.
    Negative,
    /// The quantity has a fraction and the destination holds only whole units.
    NotWhole,
    /// A stored row declares a scale this build has no reading for.
    UnknownScale,
}

impl fmt::Display for CountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CountError::Empty => "no digits to read a count from",
            CountError::Malformed => "not a decimal number",
            CountError::Truncated => "the bytes ran out before the number did",
            CountError::TooFine => "finer than the fixed scale can hold exactly",
            CountError::OutOfRange => "past what the fixed scale can hold",
            CountError::Overflow => "the arithmetic leaves the range",
            CountError::Inexact => "the product needs more places than the fixed scale has",
            CountError::Negative => "a measurement below zero is not a count",
            CountError::NotWhole => "a fraction cannot be written where only whole units fit",
            CountError::UnknownScale => "the stored row declares a scale this build cannot read",
        })
    }
}

impl std::error::Error for CountError {}

impl fmt::Display for Count {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_decimal_string())
    }
}

impl fmt::Debug for Count {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Count({})", self.to_decimal_string())
    }
}

impl std::str::FromStr for Count {
    type Err = CountError;

    fn from_str(s: &str) -> Result<Count, CountError> {
        Count::parse(s)
    }
}

/// What the grammar found: the significant digits as written, how many of them sat after the point,

struct Lexed<'a> {
    negative: bool,
    digits: DigitRun<'a>,
    fraction_len: i64,
    exponent: i64,
    all_zero: bool,
}

/// The digits of a number as two runs of the original bytes — the integer part and the fraction —
/// read left to right without being copied into a buffer.
#[derive(Clone, Copy)]
struct DigitRun<'a> {
    whole: &'a [u8],
    fraction: &'a [u8],
}

impl DigitRun<'_> {
    /// How many digits there are in total.
    fn len(&self) -> usize {
        self.whole.len() + self.fraction.len()
    }

    /// The digit at `i`, counting from the left across both runs.
    fn at(&self, i: usize) -> u8 {
        if i < self.whole.len() {
            self.whole[i]
        } else {
            self.fraction[i - self.whole.len()]
        }
    }
}

/// An exponent magnitude no mantissa can survive being shifted by, used when the exponent literal

const ABSURD_EXPONENT: i64 = 1 << 40;

/// The byte at `i`, by value, or `None` past the end.

fn byte_at(text: &[u8], i: usize) -> Option<u8> {
    text.get(i).copied()
}

/// Read the JSON number grammar strictly, or refuse.
fn lex(text: &[u8]) -> Result<Lexed<'_>, CountError> {
    if text.is_empty() {
        return Err(CountError::Empty);
    }
    let mut i = 0usize;

    let negative = text[i] == b'-';
    if negative {
        i += 1;
    }

    let whole_start = i;
    match byte_at(text, i) {
        Some(b'0') => {
            i += 1;
            if byte_at(text, i).is_some_and(|d| d.is_ascii_digit()) {
                return Err(CountError::Malformed);
            }
        }
        Some(d) if d.is_ascii_digit() => {
            while byte_at(text, i).is_some_and(|d| d.is_ascii_digit()) {
                i += 1;
            }
        }
        _ => return Err(CountError::Malformed),
    }
    let whole = &text[whole_start..i];

    let mut fraction: &[u8] = &[];
    if byte_at(text, i) == Some(b'.') {
        i += 1;
        let start = i;
        while byte_at(text, i).is_some_and(|d| d.is_ascii_digit()) {
            i += 1;
        }
        if i == start {
            return Err(CountError::Malformed);
        }
        fraction = &text[start..i];
    }

    let mut exponent = 0i64;
    if matches!(byte_at(text, i), Some(b'e' | b'E')) {
        i += 1;
        let exponent_negative = match byte_at(text, i) {
            Some(b'-') => {
                i += 1;
                true
            }
            Some(b'+') => {
                i += 1;
                false
            }
            _ => false,
        };
        let start = i;
        let mut absurd = false;
        while let Some(d) = byte_at(text, i) {
            if !d.is_ascii_digit() {
                break;
            }

            exponent = match exponent
                .checked_mul(10)
                .and_then(|v| v.checked_add(i64::from(d - b'0')))
            {
                Some(v) if v <= ABSURD_EXPONENT => v,
                _ => {
                    absurd = true;
                    ABSURD_EXPONENT
                }
            };
            i += 1;
        }
        if i == start {
            return Err(CountError::Malformed);
        }
        if absurd {
            exponent = ABSURD_EXPONENT;
        }
        if exponent_negative {
            exponent = -exponent;
        }
    }

    if i != text.len() {
        return Err(CountError::Malformed);
    }

    let digits = DigitRun { whole, fraction };
    let all_zero = (0..digits.len()).all(|k| digits.at(k) == b'0');
    Ok(Lexed {
        negative,
        digits,
        fraction_len: fraction.len() as i64,
        exponent,
        all_zero,
    })
}

/// Turn a digit run and a decimal shift into the mantissa at [`COUNT_SCALE`].

fn mantissa(digits: DigitRun<'_>, shift: i64, negative: bool) -> Result<Count, CountError> {
    let mut lo = 0usize;
    while lo < digits.len() && digits.at(lo) == b'0' {
        lo += 1;
    }
    let mut hi = digits.len();
    let mut shift = shift;

    while shift < 0 {
        if hi == lo || digits.at(hi - 1) != b'0' {
            return Err(CountError::TooFine);
        }
        hi -= 1;
        shift += 1;
    }

    let mut value: i128 = 0;
    for k in lo..hi {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_sub(i128::from(digits.at(k) - b'0')))
            .ok_or(CountError::OutOfRange)?;
    }
    while shift > 0 {
        value = value.checked_mul(10).ok_or(CountError::OutOfRange)?;
        shift -= 1;
    }

    if negative {
        return Ok(Count(value));
    }

    Ok(Count(value.checked_neg().ok_or(CountError::OutOfRange)?))
}

/// The bytes with ASCII whitespace trimmed from both ends.

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let mut start = 0usize;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[start..end]
}

#[cfg(test)]
#[path = "tests/count_tests.rs"]
mod tests;
