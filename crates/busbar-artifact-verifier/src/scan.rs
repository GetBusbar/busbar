// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stamp scan, moved from the abi (IF §7.4, §11.1), and the error-code identity grammar (round 34, §50).
//!
//! `stamp` finds exactly one stamp in an image's bytes and validates every field before anything uses it (r10
//! §2.3.1 step 3 with round 28's format 2: 272 bytes, flags `STAMP_FLAGS_KNOWN` only). The bytes are untrusted
//! and later printed, so a failure names the byte offset inside the stamp and the rule, never the bytes.

use busbar_plugin_abi::stamp::{Stamp, STAMP_FLAGS_KNOWN, STAMP_LOCAL_BUILD, STAMP_MAGIC};
use busbar_plugin_abi::versions::EngineVersion;

use crate::refusal::{Refusal, RefusalCode};

/// The stamp's size (IF §7.4).
pub const STAMP_SIZE: usize = 272;
/// The stamp format this busbar reads: busbar-plugin-abi's `stamp::STAMP_FORMAT`, the one a stamp is
/// written with (no second copy kept here).
pub const STAMP_FORMAT: u32 = busbar_plugin_abi::stamp::STAMP_FORMAT;

/// Why `stamp` found no usable stamp (r10 step 3). W1-L1: the IF names this type and never defines it; it is the
/// three stamp refusals with what each prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StampScanErr {
    /// No stamp magic in the image.
    Missing,
    /// More than one stamp magic (universal binaries are not supported).
    Ambiguous { count: u32 },
    /// The one stamp breaks a field rule: `byte` is the offset inside the stamp, `rule` the rule.
    Malformed { byte: u32, rule: &'static str },
}

impl StampScanErr {
    /// The refusal code this scan error is.
    pub fn code(self) -> RefusalCode {
        match self {
            StampScanErr::Missing => RefusalCode::StampMissing,
            StampScanErr::Ambiguous { .. } => RefusalCode::StampAmbiguous,
            StampScanErr::Malformed { byte, rule } => RefusalCode::StampMalformed { byte, rule },
        }
    }

    /// The refusal (no name: the stamp's own name is not trusted until it passes).
    pub fn refusal(self) -> Refusal {
        match self {
            StampScanErr::Missing => Refusal::new(self.code(), "stamp", "", "one stamp"),
            StampScanErr::Ambiguous { count } => {
                Refusal::new(self.code(), "stamp", count.to_string(), "1")
            }
            StampScanErr::Malformed { byte, rule } => {
                Refusal::new(self.code(), "stamp", format!("byte {byte}"), rule)
            }
        }
    }
}

// `scan` (find exactly one stamp in image bytes and validate every field, r10 step 3); its only callers are
// admit and pack (IF §7.4).
pub fn stamp(image: &[u8]) -> Result<Stamp, StampScanErr> {
    let mut first = None;
    let mut count: u32 = 0;
    let mut from = 0;
    while let Some(i) = image[from..].iter().position(|&b| b == STAMP_MAGIC[0]) {
        let at = from + i;
        if image[at..].starts_with(&STAMP_MAGIC) {
            count = count.saturating_add(1);
            first.get_or_insert(at);
        }
        from = at + 1;
    }
    let at = match (first, count) {
        (None, _) => return Err(StampScanErr::Missing),
        (Some(at), 1) => at,
        (Some(_), count) => return Err(StampScanErr::Ambiguous { count }),
    };
    let Some(bytes) = image.get(at..at + STAMP_SIZE) else {
        return Err(malformed(20, "the stamp runs past the end of the image"));
    };
    let mut one = [0u8; STAMP_SIZE];
    one.copy_from_slice(bytes);
    check(&one)
}

/// Step 3 on one stamp's bytes: every field rule, in offset order. A compiled-in image's stamp is checked here too
/// (`admit_linked`), since nothing else has read it.
pub fn check(bytes: &[u8; STAMP_SIZE]) -> Result<Stamp, StampScanErr> {
    let stamp = decode(bytes);
    if stamp.magic != STAMP_MAGIC {
        return Err(malformed(0, "magic"));
    }
    if stamp.format != STAMP_FORMAT {
        return Err(malformed(16, "format is not 3"));
    }
    if stamp.size as usize != STAMP_SIZE {
        return Err(malformed(20, "size is not 272"));
    }
    if stamp.flags & !STAMP_FLAGS_KNOWN != 0 {
        return Err(malformed(36, "an unknown flag is set"));
    }
    if stamp.engine_min._reserved != 0 {
        return Err(malformed(78, "a reserved byte is not zero"));
    }
    if stamp.engine_max._reserved != 0 {
        return Err(malformed(86, "a reserved byte is not zero"));
    }
    let name = padded(&stamp.name, 88, "name is not NUL-padded")?;
    if name.is_empty() || !crate::sign::valid_name(name) {
        return Err(malformed(
            88,
            "name is not 1 to 64 bytes of [a-z0-9-] with no leading or trailing '-'",
        ));
    }
    let version = padded(&stamp.version, 152, "version is not NUL-padded")?;
    if !valid_version(version) {
        return Err(malformed(
            152,
            "version is not a SemVer x.y.z of [0-9A-Za-z.+-]",
        ));
    }
    let target = padded(&stamp.target, 184, "target is not NUL-padded")?;
    if !target
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
    {
        return Err(malformed(184, "target is not [a-z0-9_-]"));
    }
    let local = stamp.flags & STAMP_LOCAL_BUILD != 0;
    if local != stamp.build_id.iter().all(|&b| b == 0) {
        return Err(malformed(
            216,
            "LOCAL_BUILD is set exactly when build_id is zero",
        ));
    }
    let crypto = padded(&stamp.crypto, 248, "crypto is not NUL-padded")?;
    if crypto.is_empty()
        || !crypto
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(malformed(248, "crypto is not 1 to 8 bytes of [a-z0-9-]"));
    }
    if let Some(i) = stamp._reserved2.iter().position(|&b| b != 0) {
        return Err(malformed(64 + i as u32, "a reserved byte is not zero"));
    }
    if let Some(i) = stamp._reserved.iter().position(|&b| b != 0) {
        return Err(malformed(256 + i as u32, "a reserved byte is not zero"));
    }
    Ok(stamp)
}

/// The text of a NUL-padded stamp field, once `check` has passed it (ASCII, before the first NUL).
pub fn text(field: &[u8]) -> &str {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    core::str::from_utf8(&field[..end]).unwrap_or("")
}

/// The typed view of 272 little-endian stamp bytes (IF §7.4 offsets).
fn decode(b: &[u8; STAMP_SIZE]) -> Stamp {
    fn array<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(&b[at..at + N]);
        out
    }
    let u16_at = |at: usize| u16::from_le_bytes(array(b, at));
    let u32_at = |at: usize| u32::from_le_bytes(array(b, at));
    let u64_at = |at: usize| u64::from_le_bytes(array(b, at));
    let engine = |at: usize| EngineVersion {
        major: u16_at(at),
        minor: u16_at(at + 2),
        patch: u16_at(at + 4),
        _reserved: u16_at(at + 6),
    };
    Stamp {
        magic: array(b, 0),
        format: u32_at(16),
        size: u32_at(20),
        kind: u32_at(24),
        kind_abi: u32_at(28),
        core_abi: u32_at(32),
        flags: u32_at(36),
        layout: u64_at(40),
        core_layout: u64_at(48),
        kind_minor: u32_at(56),
        core_minor: u32_at(60),
        _reserved2: array(b, 64),
        engine_min: engine(72),
        engine_max: engine(80),
        name: array(b, 88),
        version: array(b, 152),
        target: array(b, 184),
        build_id: array(b, 216),
        crypto: array(b, 248),
        _reserved: array(b, 256),
    }
}

fn malformed(byte: u32, rule: &'static str) -> StampScanErr {
    StampScanErr::Malformed { byte, rule }
}

/// The ASCII text before the first NUL of a field at stamp offset `at`, every byte after it zero.
fn padded<'a>(field: &'a [u8], at: u32, rule: &'static str) -> Result<&'a str, StampScanErr> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    if let Some(i) = field[end..].iter().position(|&b| b != 0) {
        return Err(malformed(at + (end + i) as u32, rule));
    }
    match core::str::from_utf8(&field[..end]) {
        Ok(text) if text.is_ascii() => Ok(text),
        _ => Err(malformed(at, rule)),
    }
}

/// r10 `valid_semver` plus the step-3 charset `[0-9A-Za-z.+-]` (at most the field's 32 bytes).
fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
        && crate::sign::valid_semver(version)
}

/// Round 34 (PLUGIN-ERROR-CODES §2.2; `scan.rs`, L1). The identity grammar for an image that declares D_ERRORS:
/// the stamp `name` bytes before the first NUL match `^[a-z][a-z0-9-]{0,63}$` and do not end in `-` (so ≤ 64
/// bytes). On a compiled-in image no name rule has run before this (`admit_linked` has no manifest, and the
/// stamp may come from a `CARGO_PKG_NAME` holding `_`), so `Registry::add` calls it on both load paths. The fault
/// names the position or length only, never a byte: `BadChar { byte }` → "bad character at byte N", `Length
/// { len }` → "length L > 64" (also `Empty`, `TrailingDash`). Admission is unchanged: no new `RefusalCode`; an
/// image without D_ERRORS is never checked (a digit-led or `_` name stays valid; it simply has no codes).
pub fn error_identity(name: &[u8; 64]) -> Result<&str, IdentityFault> {
    let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let text = &name[..len];
    if text.is_empty() {
        return Err(IdentityFault::Empty);
    }
    if len > 64 {
        return Err(IdentityFault::Length { len: len as u32 });
    }
    for (i, &b) in text.iter().enumerate() {
        let ok = if i == 0 {
            b.is_ascii_lowercase()
        } else {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
        };
        if !ok {
            return Err(IdentityFault::BadChar { byte: i as u32 });
        }
    }
    if text.last() == Some(&b'-') {
        return Err(IdentityFault::TrailingDash);
    }
    core::str::from_utf8(text).map_err(|_| IdentityFault::BadChar { byte: 0 })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityFault {
    Empty,
    BadChar { byte: u32 },
    Length { len: u32 },
    TrailingDash,
}

impl core::fmt::Display for IdentityFault {
    /// The position or length only, never the byte (PLUGIN-ERROR-CODES §2.2).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IdentityFault::Empty => f.write_str("empty"),
            IdentityFault::BadChar { byte } => write!(f, "bad character at byte {byte}"),
            IdentityFault::Length { len } => write!(f, "length {len} > 64"),
            IdentityFault::TrailingDash => f.write_str("ends in '-'"),
        }
    }
}
