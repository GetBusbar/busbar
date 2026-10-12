// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WELL-KNOWN TYPES the gRPC line's messages name (`google.protobuf.Struct`, `Value`,
//! `ListValue`, `NullValue`, `Timestamp`), with their protobuf JSON mapping.
//!
//! Ported from `pbjson-types` 0.9.0 (MIT OR Apache-2.0), whose mapping the engine's messages were
//! written and read in, so the bytes are its bytes. The one thing not taken is `chrono`: the
//! timestamp's RFC 3339 form is written and read here exactly as `chrono` 0.4 wrote
//! (`DateTime<Utc>::to_rfc3339`) and read (`DateTime::parse_from_rfc3339`) it for `pbjson-types`,
//! because the calendar crate's clock half reaches the OS, and a plane's closure reaches nothing
//! (the dependency wall; ARCHITECT ruling Q1 (C), 2026-10-04).

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{self, Serializer};
use serde::{Deserialize, Serialize};

/// `google.protobuf.Struct`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Struct {
    /// The members.
    #[prost(map = "string, message", tag = "1")]
    pub fields: HashMap<String, Value>,
}

/// `google.protobuf.Value`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Value {
    /// Which value it is.
    #[prost(oneof = "value::Kind", tags = "1, 2, 3, 4, 5, 6")]
    pub kind: Option<value::Kind>,
}

/// `google.protobuf.Value`'s kinds.
pub mod value {
    /// The kind of a [`super::Value`].
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        /// `null`.
        #[prost(enumeration = "super::NullValue", tag = "1")]
        NullValue(i32),
        /// A number.
        #[prost(double, tag = "2")]
        NumberValue(f64),
        /// A string.
        #[prost(string, tag = "3")]
        StringValue(String),
        /// A boolean.
        #[prost(bool, tag = "4")]
        BoolValue(bool),
        /// An object.
        #[prost(message, tag = "5")]
        StructValue(super::Struct),
        /// An array.
        #[prost(message, tag = "6")]
        ListValue(super::ListValue),
    }
}

/// `google.protobuf.ListValue`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ListValue {
    /// The elements.
    #[prost(message, repeated, tag = "1")]
    pub values: Vec<Value>,
}

/// `google.protobuf.NullValue`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum NullValue {
    /// `null`.
    NullValue = 0,
}

/// `google.protobuf.Timestamp`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, prost::Message)]
pub struct Timestamp {
    /// Seconds since the Unix epoch.
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    /// Nanoseconds of the second.
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}

// ── Struct, Value, ListValue: the JSON value they are ─────────────────────────────────────────

impl Serialize for Struct {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        self.fields.serialize(ser)
    }
}

impl<'de> Deserialize<'de> for Struct {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StructVisitor;
        impl<'de> Visitor<'de> for StructVisitor {
            type Value = Struct;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("google.protobuf.Struct")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Struct, A::Error> {
                let mut fields = HashMap::new();
                while let Some((key, value)) = map.next_entry()? {
                    fields.insert(key, value);
                }
                Ok(Struct { fields })
            }
        }
        deserializer.deserialize_map(StructVisitor)
    }
}

impl Serialize for ListValue {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        self.values.serialize(ser)
    }
}

impl<'de> Deserialize<'de> for ListValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ListValueVisitor;
        impl<'de> Visitor<'de> for ListValueVisitor {
            type Value = ListValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("google.protobuf.ListValue")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<ListValue, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element()? {
                    values.push(value);
                }
                Ok(ListValue { values })
            }
        }
        deserializer.deserialize_seq(ListValueVisitor)
    }
}

impl Serialize for NullValue {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ().serialize(ser)
    }
}

impl<'de> Deserialize<'de> for NullValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NullValueVisitor;
        impl Visitor<'_> for NullValueVisitor {
            type Value = NullValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("google.protobuf.NullValue")
            }
            fn visit_unit<E: de::Error>(self) -> Result<NullValue, E> {
                Ok(NullValue::NullValue)
            }
        }
        deserializer.deserialize_unit(NullValueVisitor)
    }
}

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        self.kind.serialize(ser)
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Value {
            kind: <_>::deserialize(deserializer)?,
        })
    }
}

impl Serialize for value::Kind {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use value::Kind;
        match self {
            Kind::NullValue(_) => ().serialize(ser),
            Kind::StringValue(v) => v.serialize(ser),
            Kind::BoolValue(v) => v.serialize(ser),
            Kind::StructValue(v) => v.serialize(ser),
            Kind::ListValue(v) => v.serialize(ser),
            Kind::NumberValue(v) => {
                if v.is_nan() {
                    Err(ser::Error::custom(
                        "Cannot serialize NaN as google.protobuf.Value.number_value",
                    ))
                } else if v.is_infinite() {
                    Err(ser::Error::custom(
                        "Cannot serialize infinity as google.protobuf.Value.number_value",
                    ))
                } else {
                    v.serialize(ser)
                }
            }
        }
    }
}

impl<'de> Deserialize<'de> for value::Kind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(KindVisitor)
    }
}

struct KindVisitor;

/// The largest integer a double holds exactly is `2^53`; past it a JSON integer is refused.
const EXACT: i64 = 1 << f64::MANTISSA_DIGITS;

const OUT_OF_RANGE_INTEGRAL: &str = "out of range integral type conversion attempted";

impl<'de> Visitor<'de> for KindVisitor {
    type Value = value::Kind;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("google.protobuf.Value")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<value::Kind, E> {
        Ok(value::Kind::BoolValue(v))
    }
    fn visit_i8<E: de::Error>(self, v: i8) -> Result<value::Kind, E> {
        Ok(value::Kind::NumberValue(v.into()))
    }
    fn visit_i16<E: de::Error>(self, v: i16) -> Result<value::Kind, E> {
        Ok(value::Kind::NumberValue(v.into()))
    }
    fn visit_i32<E: de::Error>(self, v: i32) -> Result<value::Kind, E> {
        Ok(value::Kind::NumberValue(v.into()))
    }
    #[allow(clippy::cast_precision_loss)]
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<value::Kind, E> {
        if v > -EXACT && v < EXACT {
            return Ok(value::Kind::NumberValue(v as f64));
        }
        Err(de::Error::custom(OUT_OF_RANGE_INTEGRAL))
    }
    fn visit_i128<E: de::Error>(self, v: i128) -> Result<value::Kind, E> {
        self.visit_i64(v.try_into().map_err(de::Error::custom)?)
    }
    fn visit_u8<E: de::Error>(self, v: u8) -> Result<value::Kind, E> {
        Ok(value::Kind::NumberValue(v.into()))
    }
    fn visit_u16<E: de::Error>(self, v: u16) -> Result<value::Kind, E> {
        Ok(value::Kind::NumberValue(v.into()))
    }
    fn visit_u32<E: de::Error>(self, v: u32) -> Result<value::Kind, E> {
        Ok(value::Kind::NumberValue(v.into()))
    }
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<value::Kind, E> {
        if v < EXACT as u64 {
            return Ok(value::Kind::NumberValue(v as f64));
        }
        Err(de::Error::custom(OUT_OF_RANGE_INTEGRAL))
    }
    fn visit_u128<E: de::Error>(self, v: u128) -> Result<value::Kind, E> {
        self.visit_u64(v.try_into().map_err(de::Error::custom)?)
    }
    fn visit_f32<E: de::Error>(self, v: f32) -> Result<value::Kind, E> {
        Ok(value::Kind::NumberValue(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<value::Kind, E> {
        Ok(value::Kind::NumberValue(v))
    }
    fn visit_char<E: de::Error>(self, v: char) -> Result<value::Kind, E> {
        Ok(value::Kind::StringValue(v.into()))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<value::Kind, E> {
        Ok(value::Kind::StringValue(v.into()))
    }
    fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<value::Kind, E> {
        Ok(value::Kind::StringValue(v.into()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<value::Kind, E> {
        Ok(value::Kind::StringValue(v))
    }
    fn visit_none<E: de::Error>(self) -> Result<value::Kind, E> {
        Ok(value::Kind::NullValue(0))
    }
    fn visit_some<D: Deserializer<'de>>(self, de: D) -> Result<value::Kind, D::Error> {
        Deserialize::deserialize(de)
    }
    fn visit_unit<E: de::Error>(self) -> Result<value::Kind, E> {
        Ok(value::Kind::NullValue(0))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<value::Kind, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element()? {
            values.push(value);
        }
        Ok(value::Kind::ListValue(ListValue { values }))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<value::Kind, A::Error> {
        let mut fields = HashMap::new();
        while let Some((key, value)) = map.next_entry()? {
            fields.insert(key, value);
        }
        Ok(value::Kind::StructValue(Struct { fields }))
    }
}

// ── Timestamp: its RFC 3339 string ────────────────────────────────────────────────────────────

const SECS_PER_DAY: i64 = 86_400;
const NANOS_PER_SEC: u32 = 1_000_000_000;
/// The calendar's first and last representable years (`chrono`'s `NaiveDate::MIN`/`MAX`).
const MIN_YEAR: i64 = -262_144;
const MAX_YEAR: i64 = 262_143;

/// Days from 1970-01-01 to the civil date (proleptic Gregorian).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date of a day count from 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(year) => 29,
        _ => 28,
    }
}

/// The date, when the calendar holds it (`NaiveDate::from_ymd_opt`).
fn date(year: i64, month: u32, day: u32) -> Option<i64> {
    ((MIN_YEAR..=MAX_YEAR).contains(&year)
        && (1..=12).contains(&month)
        && (1..=days_in_month(year, month)).contains(&day))
    .then(|| days_from_civil(year, month, day))
}

/// The UTC date and time of `(seconds, nanos)`, when the calendar holds it (`chrono`'s
/// `DateTime::from_timestamp`): a leap second is a `nanos` of a second or more on the 59th second.
fn civil(seconds: i64, nanos: i32) -> Option<(i64, u32, u32, u32, u32)> {
    let nanos = u32::try_from(nanos).ok()?;
    let days = seconds.div_euclid(SECS_PER_DAY);
    let of_day = u32::try_from(seconds.rem_euclid(SECS_PER_DAY)).ok()?;
    let (year, month, day) = civil_from_days(days);
    if !(MIN_YEAR..=MAX_YEAR).contains(&year)
        || nanos >= 2 * NANOS_PER_SEC
        || (nanos >= NANOS_PER_SEC && of_day % 60 != 59)
    {
        return None;
    }
    Some((year, month, day, of_day, nanos))
}

/// Whether the calendar represents `(seconds, nanos)` (the SDK model's rule, `chrono`'s range).
#[must_use]
pub fn representable(seconds: i64, nanos: i32) -> bool {
    civil(seconds, nanos).is_some()
}

impl Timestamp {
    /// Its RFC 3339 form, as `chrono`'s `to_rfc3339` wrote a UTC time: four-digit years (signed
    /// past `0..=9999`), the fraction in 0, 3, 6 or 9 digits, and `+00:00`.
    fn rfc3339(self) -> Result<String, &'static str> {
        if self.nanos < 0 {
            return Err(OUT_OF_RANGE_INTEGRAL);
        }
        let (year, month, day, of_day, nanos) =
            civil(self.seconds, self.nanos).ok_or("invalid or out-of-range datetime")?;
        let mut out = String::with_capacity(32);
        if (0..=9999).contains(&year) {
            let _ = write!(out, "{year:04}");
        } else {
            let _ = write!(out, "{year:+05}");
        }
        let (mut sec, mut nano) = (of_day % 60, nanos);
        if nano >= NANOS_PER_SEC {
            sec += 1;
            nano -= NANOS_PER_SEC;
        }
        let _ = write!(
            out,
            "-{month:02}-{day:02}T{:02}:{:02}:{sec:02}",
            of_day / 3600,
            of_day / 60 % 60
        );
        if nano == 0 {
        } else if nano % 1_000_000 == 0 {
            let _ = write!(out, ".{:03}", nano / 1_000_000);
        } else if nano % 1_000 == 0 {
            let _ = write!(out, ".{:06}", nano / 1_000);
        } else {
            let _ = write!(out, ".{nano:09}");
        }
        out.push_str("+00:00");
        Ok(out)
    }
}

/// Why an RFC 3339 string does not read (`chrono`'s `ParseError`, in its words).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// A value past its field's range.
    OutOfRange,
    /// A character the grammar does not allow.
    Invalid,
    /// The string ends early.
    TooShort,
    /// Something follows the offset.
    TooLong,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ParseError::OutOfRange => "input is out of range",
            ParseError::Invalid => "input contains invalid characters",
            ParseError::TooShort => "premature end of input",
            ParseError::TooLong => "trailing input",
        })
    }
}

fn digit(bytes: &[u8], i: usize) -> Result<u32, ParseError> {
    match bytes[i] {
        b @ b'0'..=b'9' => Ok(u32::from(b - b'0')),
        _ => Err(ParseError::Invalid),
    }
}

/// The fraction after a `.`: one to nine digits read, more skipped (`chrono`'s `nanosecond`).
fn fraction(s: &str) -> Result<(&str, u32), ParseError> {
    const SCALE: [u32; 10] = [
        0,
        100_000_000,
        10_000_000,
        1_000_000,
        100_000,
        10_000,
        1_000,
        100,
        10,
        1,
    ];
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Err(ParseError::TooShort);
    }
    let mut n = 0u32;
    let mut taken = 0;
    for &c in bytes.iter().take(9) {
        if !c.is_ascii_digit() {
            break;
        }
        n = n * 10 + u32::from(c - b'0');
        taken += 1;
    }
    if taken == 0 {
        return Err(ParseError::Invalid);
    }
    let rest = s[taken..].trim_start_matches(|c: char| c.is_ascii_digit());
    Ok((rest, n * SCALE[taken]))
}

/// The offset (`Z`, or `±HH:MM`; `chrono`'s `timezone_offset` with zulu and the minus sign
/// allowed and minutes required), in seconds east, and what follows it.
fn offset(mut s: &str) -> Result<(&str, i32), ParseError> {
    if let Some(b'Z' | b'z') = s.as_bytes().first() {
        return Ok((&s[1..], 0));
    }
    let negative = match s.chars().next() {
        Some('+') => {
            s = &s[1..];
            false
        }
        Some('-') => {
            s = &s[1..];
            true
        }
        Some('\u{2212}') => {
            s = &s['\u{2212}'.len_utf8()..];
            true
        }
        Some(_) => return Err(ParseError::Invalid),
        None => return Err(ParseError::TooShort),
    };
    let two = |s: &str| -> Result<(u8, u8), ParseError> {
        let b = s.as_bytes();
        if b.len() < 2 {
            Err(ParseError::TooShort)
        } else {
            Ok((b[0], b[1]))
        }
    };
    let hours = match two(s)? {
        (h1 @ b'0'..=b'9', h2 @ b'0'..=b'9') => i32::from((h1 - b'0') * 10 + (h2 - b'0')),
        _ => return Err(ParseError::Invalid),
    };
    s = &s[2..];
    s = match s.as_bytes().first() {
        Some(b':') => &s[1..],
        Some(_) => return Err(ParseError::Invalid),
        None => return Err(ParseError::TooShort),
    };
    let minutes = match two(s) {
        Ok((m1 @ b'0'..=b'5', m2 @ b'0'..=b'9')) => i32::from((m1 - b'0') * 10 + (m2 - b'0')),
        Ok((b'6'..=b'9', b'0'..=b'9')) => return Err(ParseError::OutOfRange),
        Ok(_) => return Err(ParseError::Invalid),
        Err(_) => return Err(ParseError::TooShort),
    };
    s = &s[2..];
    let seconds = hours * 3600 + minutes * 60;
    Ok((s, if negative { -seconds } else { seconds }))
}

impl std::str::FromStr for Timestamp {
    type Err = ParseError;

    /// Read an RFC 3339 string as `chrono`'s `DateTime::parse_from_rfc3339` read it, then as UTC.
    fn from_str(s: &str) -> Result<Self, ParseError> {
        let bytes = s.as_bytes();
        if bytes.len() < 19 {
            return Err(ParseError::TooShort);
        }
        let year = digit(bytes, 0)? * 1000
            + digit(bytes, 1)? * 100
            + digit(bytes, 2)? * 10
            + digit(bytes, 3)?;
        if bytes[4] != b'-' {
            return Err(ParseError::Invalid);
        }
        let month = digit(bytes, 5)? * 10 + digit(bytes, 6)?;
        if bytes[7] != b'-' {
            return Err(ParseError::Invalid);
        }
        let day = digit(bytes, 8)? * 10 + digit(bytes, 9)?;
        let days = date(i64::from(year), month, day).ok_or(ParseError::OutOfRange)?;
        if !matches!(bytes[10], b't' | b'T' | b' ') {
            return Err(ParseError::Invalid);
        }
        let hour = digit(bytes, 11)? * 10 + digit(bytes, 12)?;
        if bytes[13] != b':' {
            return Err(ParseError::Invalid);
        }
        let min = digit(bytes, 14)? * 10 + digit(bytes, 15)?;
        if bytes[16] != b':' {
            return Err(ParseError::Invalid);
        }
        let sec = digit(bytes, 17)? * 10 + digit(bytes, 18)?;
        let (sec, extra) = if sec == 60 {
            (59, NANOS_PER_SEC)
        } else {
            (sec, 0)
        };
        let (rest, nano) = if bytes.get(19) == Some(&b'.') {
            let (rest, n) = fraction(&s[20..])?;
            (rest, extra + n)
        } else {
            (&s[19..], extra)
        };
        if hour >= 24
            || min >= 60
            || sec >= 60
            || nano >= 2 * NANOS_PER_SEC
            || (nano >= NANOS_PER_SEC && sec != 59)
        {
            return Err(ParseError::OutOfRange);
        }
        let (rest, east) = offset(rest)?;
        if !rest.is_empty() {
            return Err(ParseError::TooLong);
        }
        if east <= -86_400 || east >= 86_400 {
            return Err(ParseError::OutOfRange);
        }
        let local = days * SECS_PER_DAY + i64::from(hour * 3600 + min * 60 + sec);
        Ok(Timestamp {
            seconds: local - i64::from(east),
            nanos: i32::try_from(nano).map_err(|_| ParseError::OutOfRange)?,
        })
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.rfc3339().map_err(ser::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TimestampVisitor;
        impl Visitor<'_> for TimestampVisitor {
            type Value = Timestamp;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a date string")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Timestamp, E> {
                s.parse().map_err(de::Error::custom)
            }
        }
        deserializer.deserialize_str(TimestampVisitor)
    }
}

#[cfg(test)]
#[path = "tests/wkt_tests.rs"]
mod tests;
