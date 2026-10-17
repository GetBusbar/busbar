// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The exact decimal quantity every usage count is measured in (DECISION #81).
//!
//! A usage count is a MEASUREMENT, and a measurement is whatever was observed. `27` is 27, `27.0`
//! is 27, `27.5` is 27.5 and `0.001` is 0.001. Nothing here rounds up, rounds down, rounds to even,
//! or quietly drops a digit: a quantity that cannot be held EXACTLY is refused, because a refusal
//! is a fact and an invented digit is a wrong book.
//!
//! # The representation
//!
//! One `i128` mantissa at ONE fixed scale of [`COUNT_SCALE`] = 6 — micro-units — for every count
//! and every reading of every count. `27.5` is held as `27_500_000` and read back as `27.5`. The
//! scale is fixed rather than per-value so that two counts are the same kind of number by
//! construction: addition is an integer add with no alignment step, ordering is integer ordering,
//! and equality is integer equality, so no two representations of one quantity can compare unequal.
//!
//! # Two ranges, and the smaller one is the one that binds
//!
//! IN MEMORY the range is `i128::MIN / 1e6 ..= i128::MAX / 1e6`, whose positive end is
//! `170141183460469231731687303715884.105727` — about `1.7e32` units. [`MAX`] and [`MIN`] name both
//! ends, and they are asserted rather than asserted-about in the tests beside this module.
//!
//! ACROSS THE STORE ABI the range is far smaller and it is the one that actually binds. A persisted
//! count column is a SIGNED 64-BIT integer, so a mantissa at this scale runs out at
//! `i64::MAX` micro-units — [`MAX_ACROSS_A_64_BIT_COLUMN`], about `9.2e12` whole units. Quoting
//! `1.7e32` as the usable range would be quoting the wrong number: it is what the type holds, not
//! what survives a round trip through a store. [`Count::fits_a_64_bit_column`] is the check, and it
//! is a check rather than a clamp because a clamped quantity is an invented one.
//!
//! # What is written down, and how an old row is read (#81a)
//!
//! A count is persisted as its MANTISSA beside a per-record SCALE discriminator, and it is never
//! rescaled in place. [`SCALE_WHOLE_UNITS`] is what a record's silence means — a row written before
//! the scale existed holds whole units, because that is what those rows are — and
//! [`SCALE_MICRO_UNITS`] is what every row written from here on says about itself.
//! [`Count::from_stored`] is the branch, and [`stored_scale_default`] is the function a record's
//! `#[serde(default = …)]` names.
//!
//! The alternative — multiplying every stored value by `10^6` once — is FORBIDDEN, and not as a
//! matter of taste: the existing fold is crash-safe only because re-folding an already-folded row
//! adds zero, and `× 10^6` run twice is `× 10^12`. A discriminator is idempotent by construction
//! because it rewrites nothing.
//!
//! # No binary floating point, anywhere
//!
//! There is no `f32` or `f64` in this module, in its arithmetic, in a convenience constructor or in
//! a test helper, and a gate proves it (`cargo xtask gate no-float-money`). The reason is not taste.
//! Binary floating point holds only fractions whose denominator is a power of two, so it cannot
//! hold `27.1` at all — it holds `27.100000000000001421…` and calls it `27.1`. A count that transits
//! a double has already lost the exactness no later conversion can give back, so the double is
//! excluded from the whole path rather than corrected at the end of it.
//!
//! That is also why the parser here reads TEXT. [`Count::parse`] is handed the digits as they were
//! written and turns them into a mantissa by integer arithmetic over the digit bytes; it never
//! builds an intermediate binary float, so `27.1` is `27_100_000` and not something near it.
//!
//! # Exact, or a refusal
//!
//! Every fallible operation returns [`CountError`] rather than a nearby answer:
//!
//! * text that is not a JSON number is [`CountError::Malformed`];
//! * a quantity finer than the scale (`0.0000001`) is [`CountError::TooFine`];
//! * a magnitude past the range (`1e400`) is [`CountError::OutOfRange`];
//! * a sum or a product that would leave the range is [`CountError::Overflow`];
//! * a product that would need more than [`COUNT_SCALE`] places is [`CountError::Inexact`];
//! * a negative measurement, at the reading seam only, is [`CountError::Negative`];
//! * a fraction bound for a whole-unit destination is [`CountError::NotWhole`];
//! * a stored row declaring a scale this build has no reading for is [`CountError::UnknownScale`].
//!
//! Addition and multiplication are CHECKED. Nothing here wraps, and nothing here saturates: a
//! saturated total is a wrong total that looks like a right one, which is the failure the checked
//! form exists to make impossible to miss.
//!
//! # Order independence
//!
//! A total is the same total whatever order the rows arrived in. Integer addition over a fixed
//! scale is associative and commutative with no rounding step to be sensitive to ordering, so a
//! shuffled sum of a million rows is byte-for-byte one number — proven, not assumed, in
//! `tests/count_tests.rs`.

use core::fmt;

use crate::json_grammar::{resolve_pointer, Resolved};

/// The ONE scale every count is held at: six decimal places, i.e. micro-units.
///
/// Fixed for every count and every reading of a count. It is a PRECISION, not a currency and not a
/// unit — a count carries no symbol and no denomination (#66).
pub const COUNT_SCALE: u32 = 6;

/// `10^COUNT_SCALE`: how many mantissa steps make one whole unit.
const SCALE_FACTOR: i128 = 1_000_000;

/// The largest quantity a [`Count`] can hold: `170141183460469231731687303715884.105727`.
pub const MAX: Count = Count(i128::MAX);

/// The smallest quantity a [`Count`] can hold: `-170141183460469231731687303715884.105728`.
pub const MIN: Count = Count(i128::MIN);

/// The largest quantity whose mantissa still fits a SIGNED 64-BIT store column — about `9.2e12`
/// whole units.
///
/// The bound that actually binds. [`MAX`] is what the type holds; this is what survives being
/// written down, because a persisted count column is 64 bits wide and holds the mantissa. A
/// quantity past it has nowhere to go, and [`Count::fits_a_64_bit_column`] says so before anything
/// tries to put it there.
pub const MAX_ACROSS_A_64_BIT_COLUMN: Count = Count(i64::MAX as i128);

/// The smallest quantity whose mantissa still fits a signed 64-bit store column.
pub const MIN_ACROSS_A_64_BIT_COLUMN: Count = Count(i64::MIN as i128);

/// The scale a record's SILENCE means: whole units, no fraction (#81a).
///
/// Every row persisted before a scale discriminator existed simply lacks the field, and an absent
/// field means exactly this, because that is what those rows are. Nothing is rewritten and no
/// stored value is multiplied — the row identifies itself and the branch at the read does the rest.
pub const SCALE_WHOLE_UNITS: u32 = 0;

/// The scale every row written from here on declares: micro-units, i.e. [`COUNT_SCALE`].
pub const SCALE_MICRO_UNITS: u32 = COUNT_SCALE;

/// The scale a record's absent discriminator means — the function `#[serde(default = "…")]` names.
///
/// A free function because serde's `default` attribute needs one to call rather than the constant
/// directly. This is the same shape the audit entry's framing tag and the task row's digest version
/// already use, and it is deliberately the same shape: a fourth spelling of one idea is a fourth
/// place it can drift.
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
    ///
    /// The inverse of [`Count::micros`], and the one constructor that cannot fail: every `i128` is
    /// a quantity at this scale. Use it to read a count back out of a store that holds the mantissa
    /// — never to convert a whole number, which is [`Count::from_integer`] and is checked.
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
    ///
    /// # Errors
    /// [`CountError::OutOfRange`] when `n` whole units do not fit the scale.
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

    /// Whether this quantity is a whole number of units.
    #[must_use]
    pub const fn is_whole(self) -> bool {
        self.0 % SCALE_FACTOR == 0
    }

    /// Whether this quantity's mantissa fits a signed 64-bit store column.
    ///
    /// See [`MAX_ACROSS_A_64_BIT_COLUMN`]. A quantity that does not fit cannot be written down, and
    /// the only honest answers to that are a refusal or a wider column — never a clamp.
    #[must_use]
    pub const fn fits_a_64_bit_column(self) -> bool {
        self.0 >= MIN_ACROSS_A_64_BIT_COLUMN.0 && self.0 <= MAX_ACROSS_A_64_BIT_COLUMN.0
    }

    /// Read a count back out of a store, branching on the row's own scale discriminator (#81a).
    ///
    /// [`SCALE_WHOLE_UNITS`] — which is what an ABSENT discriminator means — says the stored value
    /// is a whole-unit count and is lifted to the scale here, once, at the read. [`SCALE_MICRO_UNITS`]
    /// says it is already a mantissa and is taken as it stands. THE STORE IS NEVER REWRITTEN: an old
    /// row keeps its old bytes and its own reading, which is what makes this safe to re-run after a
    /// crash — re-reading a row is idempotent where multiplying one is not.
    ///
    /// # Errors
    /// [`CountError::UnknownScale`] when the row declares a scale this build has no reading for — a
    /// row from a future it cannot interpret is refused, not guessed at.
    /// [`CountError::OutOfRange`] when a whole-unit value does not fit the scale.
    pub const fn from_stored(value: i128, scale: u32) -> Result<Count, CountError> {
        if scale == SCALE_WHOLE_UNITS {
            return Count::from_integer(value);
        }
        if scale == SCALE_MICRO_UNITS {
            return Ok(Count(value));
        }
        Err(CountError::UnknownScale)
    }

    /// The value to persist, which is the mantissa — see [`Count::micros`].
    ///
    /// A record that writes this MUST also write [`SCALE_MICRO_UNITS`] in its scale field. The two
    /// are one fact and a row carrying only half of it is a row nobody can read.
    #[must_use]
    pub const fn stored_value(self) -> i128 {
        self.0
    }

    /// The whole-unit count, for a destination that has no place to put a fraction.
    ///
    /// # Errors
    /// [`CountError::NotWhole`] when the quantity has a fraction. Truncating it would be inventing
    /// a smaller measurement than the one that was taken, which is the one thing a count may never
    /// do (#81/#42) — so the fraction that cannot be carried is a refusal, and the refusal names
    /// itself rather than arriving as a quietly smaller number.
    pub const fn whole_units(self) -> Result<i128, CountError> {
        if self.0 % SCALE_FACTOR != 0 {
            return Err(CountError::NotWhole);
        }
        Ok(self.0 / SCALE_FACTOR)
    }

    /// `self + rhs`, exactly.
    ///
    /// # Errors
    /// [`CountError::Overflow`] when the total leaves the range. It does not saturate: a total that
    /// stopped at the ceiling is a wrong total wearing a right total's clothes.
    pub const fn checked_add(self, rhs: Count) -> Result<Count, CountError> {
        match self.0.checked_add(rhs.0) {
            Some(m) => Ok(Count(m)),
            None => Err(CountError::Overflow),
        }
    }

    /// `self - rhs`, exactly.
    ///
    /// # Errors
    /// [`CountError::Overflow`] when the difference leaves the range.
    pub const fn checked_sub(self, rhs: Count) -> Result<Count, CountError> {
        match self.0.checked_sub(rhs.0) {
            Some(m) => Ok(Count(m)),
            None => Err(CountError::Overflow),
        }
    }

    /// `self * n` for a whole multiplier, exactly.
    ///
    /// # Errors
    /// [`CountError::Overflow`] when the product leaves the range.
    pub const fn checked_mul_integer(self, n: i128) -> Result<Count, CountError> {
        match self.0.checked_mul(n) {
            Some(m) => Ok(Count(m)),
            None => Err(CountError::Overflow),
        }
    }

    /// `self * rate`, where the rate is itself an exact decimal at the same scale.
    ///
    /// The product of two scale-6 numbers is a scale-12 number, so it comes back at scale 6 ONLY
    /// when the last six places of that wider product are zero. They usually are — a count of
    /// `27.5` against a rate of `1.87` is exactly `51.425` — and when they are not, the honest
    /// answer is a refusal, not a rounded one. A caller that must keep the extra places (to sum
    /// products before deciding anything about rounding) takes them from [`Count::checked_mul_wide`]
    /// instead.
    ///
    /// # Errors
    /// [`CountError::Overflow`] when the wider product leaves the range;
    /// [`CountError::Inexact`] when it needs more than [`COUNT_SCALE`] places.
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
    ///
    /// No rounding and no refusal: every product of two mantissas that fits an `i128` is returned
    /// whole. This is the form a running total of `Σ count × rate` accumulates in, so that whatever
    /// rounding a later division owes (#44) is applied ONCE to the total rather than per row.
    ///
    /// # Errors
    /// [`CountError::Overflow`] when the product does not fit an `i128`.
    pub const fn checked_mul_wide(self, rate: Count) -> Result<i128, CountError> {
        match self.0.checked_mul(rate.0) {
            Some(wide) => Ok(wide),
            None => Err(CountError::Overflow),
        }
    }

    /// The total of a sequence, exactly.
    ///
    /// The answer does not depend on the order the sequence arrives in, because integer addition at
    /// a fixed scale has no rounding step to be order-sensitive about.
    ///
    /// # Errors
    /// [`CountError::Overflow`] when the running total leaves the range.
    pub fn total<I: IntoIterator<Item = Count>>(counts: I) -> Result<Count, CountError> {
        let mut acc = Count::ZERO;
        for c in counts {
            acc = acc.checked_add(c)?;
        }
        Ok(acc)
    }

    /// The canonical decimal spelling of this quantity.
    ///
    /// One quantity has ONE spelling: no exponent, no trailing zeros in the fraction, no fraction
    /// at all when the quantity is whole, and a leading `-` exactly when it is below zero. `27.5`
    /// renders `27.5` and `27.1` renders `27.1`; both `27` and `27.0` render `27`, because the
    /// ruling says they are the same quantity and this is a rendering of the quantity, not a replay
    /// of the keystrokes. Feeding the result back to [`Count::parse`] yields the same count, for
    /// every count.
    #[must_use]
    pub fn to_decimal_string(self) -> String {
        // `unsigned_abs` rather than a negation, so the most negative mantissa has a spelling too.
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
    ///
    /// The text is a JSON number (RFC 8259) and is read strictly: an optional `-`, an integer part
    /// with no redundant leading zero, an optional fraction of at least one digit, an optional
    /// `e`/`E` exponent with at least one digit, and nothing else on either side. `NaN`,
    /// `Infinity`, a bare `-`, `007`, `1.`, `.5` and trailing punctuation are all
    /// [`CountError::Malformed`] — the one serialization busbar reads does not spell numbers that
    /// way, and guessing at what was meant is how a book acquires a digit nobody sent.
    ///
    /// An exponent is honoured exactly: `2.75e1` is `27.5`, and a mantissa of all zeros is `0` at
    /// any exponent at all. What an exponent cannot do is smuggle in a place the scale does not
    /// have — `1e-7` is [`CountError::TooFine`], not `0`.
    ///
    /// Negative text parses: the mantissa is signed, and a reversal is a real quantity. The seam
    /// that reads a MEASUREMENT is [`read_count`], and that one refuses it.
    ///
    /// # Errors
    /// [`CountError::Empty`], [`CountError::Malformed`], [`CountError::TooFine`] or
    /// [`CountError::OutOfRange`], as described above.
    pub fn parse(text: &str) -> Result<Count, CountError> {
        Count::parse_bytes(text.as_bytes())
    }

    /// Read decimal text as an exact count, from bytes.
    ///
    /// The byte form is the one that matters: it is what a JSON body hands back, so a count is read
    /// from the wire without a copy and without a `Value` in between. See [`Count::parse`] for the
    /// grammar and the refusals.
    ///
    /// # Errors
    /// As [`Count::parse`].
    pub fn parse_bytes(text: &[u8]) -> Result<Count, CountError> {
        let lexed = lex(text)?;
        if lexed.all_zero {
            // A zero mantissa is exactly zero however it was scaled, so the exponent never has to
            // be reasoned about — which is what keeps `0e999999999` an answer instead of a range
            // complaint.
            return Ok(Count::ZERO);
        }
        // Where the decimal point ends up once the value is expressed at COUNT_SCALE. Positive
        // means zeros to append; negative means places to give back, and giving back a place that
        // holds anything but a zero is the refusal.
        let shift = (COUNT_SCALE as i64)
            .checked_add(lexed.exponent)
            .and_then(|v| v.checked_sub(lexed.fraction_len))
            .ok_or(CountError::OutOfRange)?;
        mantissa(lexed.digits, shift, lexed.negative)
    }

    /// Read a JSON number located by pointer, straight out of a body's bytes.
    ///
    /// The pointer is resolved by the closed span grammar ([`crate::spans`]), which answers with a
    /// range of the caller's own bytes. Those bytes are the digits as the sender wrote them, and
    /// they go to [`read_count`] as text — so the count never exists as anything but text and an
    /// integer, which is the whole point of #81's parsing clause.
    ///
    /// `Ok(None)` means the body is well-formed as far as it was read and does not carry that
    /// pointer — an absent count, which is a different fact from a count of zero.
    ///
    /// # Errors
    /// [`CountError::Truncated`] when the bytes ran out mid-value (a later chunk may still carry
    /// it), [`CountError::Malformed`] when the body is not readable as structure, and otherwise
    /// whatever [`read_count`] says about the digits it found.
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
///
/// [`Count::parse`] plus the one rule a MEASUREMENT has that a quantity does not — it is not below
/// zero. A provider reporting `-3` tokens has not reported a count; it has reported something the
/// book has no reading for, and [`CountError::Negative`] says so instead of a book saying `-3`.
///
/// Every other refusal is inherited unchanged, and none of them is a rounded guess.
///
/// # Errors
/// [`CountError::Negative`], or anything [`Count::parse`] returns.
pub fn read_count(text: &str) -> Result<Count, CountError> {
    read_count_bytes(text.as_bytes())
}

/// THE SEAM, over bytes — see [`read_count`].
///
/// # Errors
/// As [`read_count`].
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

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The lexer: JSON number text to digits, a fraction width and an exponent. No division, no float.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// What the grammar found: the significant digits as written, how many of them sat after the point,
/// the exponent, the sign, and whether the whole mantissa was zeros.
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
/// itself is longer than an `i64` will hold. It only has to be big enough that the digit loop
/// leaves the range, and small enough that adding the scale to it cannot overflow.
const ABSURD_EXPONENT: i64 = 1 << 40;

/// The byte at `i`, by value, or `None` past the end.
///
/// By value rather than by reference so every match arm below is a plain byte literal: a pattern
/// that reads the same as the grammar it is transcribing is a pattern that can be checked against
/// the grammar by eye.
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

    // The integer part: `0` alone, or a digit 1-9 and then any digits. `007` is not a number.
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

    // The fraction: a point and then at least one digit. `1.` is not a number.
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

    // The exponent: `e` or `E`, an optional sign, then at least one digit.
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
            // An exponent literal too long for an `i64` is clamped to a magnitude nothing survives,
            // rather than refused here: a mantissa of all zeros is still exactly zero at it.
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
///
/// A positive shift appends zeros; a negative shift gives digits back, and every digit given back
/// must be a zero or the quantity is finer than the scale. Both directions are integer work over
/// the digit bytes, so nothing is ever held in a form that could round.
fn mantissa(digits: DigitRun<'_>, shift: i64, negative: bool) -> Result<Count, CountError> {
    // Leading zeros carry nothing; skipping them is what makes `0.001` and `1e-3` the same walk.
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

    // ACCUMULATE NEGATIVELY, ALWAYS, WHATEVER THE SIGN.
    //
    // Two's complement is not symmetric: the negative side reaches one step further than the
    // positive side. Building the magnitude positive-first and negating at the end therefore cannot
    // reach the most negative quantity AT ALL — it overflows one step before it, so [`MIN`] would be
    // a quantity the type can hold, can render, and cannot read back. A quantity that does not
    // round-trip is a wrong ledger, and a wrong ledger is the one thing this module exists to make
    // impossible, so the accumulation runs on the side that reaches everything and the POSITIVE case
    // is the one that takes a checked negation at the end.
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
    // And this is where a positive magnitude one step past the top is refused, which is exactly
    // right: `+170141183460469231731687303715884.105728` is out of range even though its negative
    // twin is not.
    Ok(Count(value.checked_neg().ok_or(CountError::OutOfRange)?))
}

/// The bytes with ASCII whitespace trimmed from both ends.
///
/// The span grammar answers with the value's own bytes, but a span read back out of a journal is
/// whatever someone wrote down, so the trim is what keeps a stray space from reading as malformed
/// digits.
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
