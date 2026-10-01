// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE gRPC LAYER'S BYTES (gRPC over HTTP/2, `PROTOCOL-HTTP2.md`): the length-prefixed message, the
//! `grpc-timeout` value, `grpc-status` and its classes, the percent-encoded `grpc-message`, and the
//! head block this door's host speaks in.
//!
//! THE HEAD BLOCK. What the host hands this door on `emit` (and what `encode` renders) is a head
//! block, then messages:
//!
//! ```text
//! name: value\r\n        one line per field (the dial side's `path` names the method)
//! content-length: N\r\n  optional: the N bytes after the block are the whole message stream
//! \r\n
//! <messages, each in its length-prefixed form>
//! ```
//!
//! A message on this wire, both ways, is its LENGTH-PREFIXED FORM: one flag byte (`0` = not
//! compressed; this door negotiates no compression), a four-byte big-endian length, the payload.
//! A frame this door answers is one whole message in that form, so it is never empty — an empty
//! payload is still five bytes — and the empty piece stays what the kind says it is: the stream's
//! end.

use std::time::Duration;

use bytes::{Bytes, BytesMut};

/// The prefix of a length-prefixed message.
pub const PREFIX: usize = 5;

/// The one content type every gRPC answer and request carries (its `+proto`/`+json` forms extend
/// it).
pub const CONTENT_TYPE: &str = "application/grpc";

/// Whether `v` is a gRPC content type: `application/grpc`, or it followed by `+` or `;`.
#[must_use]
pub fn is_grpc_content_type(v: &[u8]) -> bool {
    let base = CONTENT_TYPE.as_bytes();
    v.len() >= base.len()
        && v[..base.len()].eq_ignore_ascii_case(base)
        && matches!(v.get(base.len()), None | Some(b'+' | b';'))
}

/// `payload` in its length-prefixed form.
#[must_use]
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREFIX + payload.len());
    out.push(0);
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(payload);
    out
}

/// Why a message stream is not one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bad {
    /// A message is compressed, and no compression was agreed.
    Compressed,
    /// A message is larger than the ceiling.
    TooLarge(usize),
    /// The stream ended inside a message.
    Truncated,
}

impl std::fmt::Display for Bad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compressed => {
                f.write_str("a message is compressed and no compression was agreed")
            }
            Self::TooLarge(n) => write!(f, "a message of {n} bytes is over the ceiling"),
            Self::Truncated => f.write_str("the stream ended inside a message"),
        }
    }
}

/// Cuts a byte stream into whole length-prefixed messages.
#[derive(Debug)]
pub struct Messages {
    buf: BytesMut,
    max: usize,
}

impl Messages {
    /// A cutter whose messages are at most `max` payload bytes.
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            buf: BytesMut::new(),
            max,
        }
    }

    /// Take `bytes`, and answer every message they complete (each in its length-prefixed form).
    ///
    /// # Errors
    ///
    /// A message is compressed or over the ceiling.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Bytes>, Bad> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while self.buf.len() >= PREFIX {
            if self.buf[0] != 0 {
                return Err(Bad::Compressed);
            }
            let n =
                u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
            if n > self.max {
                return Err(Bad::TooLarge(n));
            }
            if self.buf.len() < PREFIX + n {
                break;
            }
            out.push(self.buf.split_to(PREFIX + n).freeze());
        }
        Ok(out)
    }

    /// The stream ended.
    ///
    /// # Errors
    ///
    /// It ended inside a message.
    pub fn end(&self) -> Result<(), Bad> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Bad::Truncated)
        }
    }
}

// ── grpc-timeout ─────────────────────────────────────────────────────────────────────────────────

/// `d` as a `grpc-timeout` value: at most eight digits, in the finest unit that holds it.
#[must_use]
pub fn timeout_value(d: Duration) -> String {
    const MAX: u128 = 99_999_999;
    let ns = d.as_nanos();
    let units: [(u128, char); 6] = [
        (1, 'n'),
        (1_000, 'u'),
        (1_000_000, 'm'),
        (1_000_000_000, 'S'),
        (60_000_000_000, 'M'),
        (3_600_000_000_000, 'H'),
    ];
    for (per, unit) in units {
        // Rounded UP, so the far end never waits less than the caller's clock allows.
        let v = ns.div_ceil(per);
        if v <= MAX {
            return format!("{v}{unit}");
        }
    }
    format!("{MAX}H")
}

/// A `grpc-timeout` value, read.
#[must_use]
pub fn parse_timeout(v: &[u8]) -> Option<Duration> {
    let (digits, unit) = v.split_at(v.len().checked_sub(1)?);
    if digits.is_empty() || digits.len() > 8 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n: u64 = std::str::from_utf8(digits).ok()?.parse().ok()?;
    Some(match unit {
        b"n" => Duration::from_nanos(n),
        b"u" => Duration::from_micros(n),
        b"m" => Duration::from_millis(n),
        b"S" => Duration::from_secs(n),
        b"M" => Duration::from_secs(n.saturating_mul(60)),
        b"H" => Duration::from_secs(n.saturating_mul(3600)),
        _ => return None,
    })
}

// ── the gRPC fields ──────────────────────────────────────────────────────────────────────────────

/// The field the call's status travels in (the trailers, or a trailers-only head).
pub const GRPC_STATUS: &str = "grpc-status";
/// The field the status's text travels in, percent-encoded.
pub const GRPC_MESSAGE: &str = "grpc-message";
/// The field a call's deadline travels in.
pub const GRPC_TIMEOUT: &str = "grpc-timeout";

// ── grpc-status ──────────────────────────────────────────────────────────────────────────────────

/// `OK`.
pub const OK: u16 = 0;
/// `CANCELLED`.
pub const CANCELLED: u16 = 1;
/// `UNKNOWN`.
pub const UNKNOWN: u16 = 2;
/// `DEADLINE_EXCEEDED`.
pub const DEADLINE_EXCEEDED: u16 = 4;
/// `PERMISSION_DENIED`.
pub const PERMISSION_DENIED: u16 = 7;
/// `UNIMPLEMENTED`.
pub const UNIMPLEMENTED: u16 = 12;
/// `INTERNAL`.
pub const INTERNAL: u16 = 13;
/// `UNAVAILABLE`.
pub const UNAVAILABLE: u16 = 14;
/// `UNAUTHENTICATED`.
pub const UNAUTHENTICATED: u16 = 16;

/// The `grpc-status` an answer that is not gRPC stands for, by its HTTP status
/// (`http-grpc-status-mapping.md`).
#[must_use]
pub fn status_of_http(code: u16) -> u16 {
    match code {
        400 => INTERNAL,
        401 => UNAUTHENTICATED,
        403 => PERMISSION_DENIED,
        404 => UNIMPLEMENTED,
        429 | 502 | 503 | 504 => UNAVAILABLE,
        _ => UNKNOWN,
    }
}

/// A `grpc-status` value, read: the canonical codes are `0..=16`; anything else is `UNKNOWN`.
#[must_use]
pub fn parse_status(v: &[u8]) -> u16 {
    std::str::from_utf8(v)
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .filter(|c| *c <= 16)
        .unwrap_or(UNKNOWN)
}

/// `grpc-message`, percent-decoded (a malformed escape stays as it was sent).
#[must_use]
pub fn decode_message(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len());
    let mut i = 0;
    while i < v.len() {
        if v[i] == b'%' && i + 2 < v.len() {
            let hex = std::str::from_utf8(&v[i + 1..i + 3]).ok();
            if let Some(b) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(v[i]);
        i += 1;
    }
    out
}

/// `text` as a `grpc-message` value: every byte outside printable ASCII, and `%`, percent-encoded.
#[must_use]
pub fn encode_message(text: &[u8]) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text {
        if (0x20..=0x7e).contains(&b) && b != b'%' {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ── the head block ───────────────────────────────────────────────────────────────────────────────

/// A head block, read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Head {
    /// Every field line but `content-length`, in order.
    pub fields: Vec<(String, Vec<u8>)>,
    /// The message stream's length, when the block states it.
    pub content_length: Option<usize>,
}

impl Head {
    /// The value of the first field named `name` (any case).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }
}

/// Read a head block off the front of `buf`: `Ok(None)` while it is incomplete, else the head and
/// how many bytes of `buf` it took.
///
/// # Errors
///
/// A line is not `name: value`, or `content-length` is not a number.
pub fn read_head(buf: &[u8], max: usize) -> Result<Option<(Head, usize)>, String> {
    // An empty block is the blank line alone; otherwise the block ends at the first blank line.
    let (lines, took) = if buf.starts_with(b"\r\n") {
        (&buf[..0], 2)
    } else if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        (&buf[..p], p + 4)
    } else {
        if buf.len() > max {
            return Err("the head block is over the ceiling".into());
        }
        return Ok(None);
    };
    let mut head = Head::default();
    for line in lines.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let colon = line
            .iter()
            .position(|b| *b == b':')
            .ok_or("a head line is not a field")?;
        let name = std::str::from_utf8(&line[..colon])
            .map_err(|_| "a field name is not text")?
            .trim()
            .to_ascii_lowercase();
        let value = line[colon + 1..].trim_ascii().to_vec();
        if name.is_empty() {
            return Err("a field has no name".into());
        }
        if name == "content-length" {
            let n = std::str::from_utf8(&value)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or("content-length is not a number")?;
            head.content_length = Some(n);
        } else {
            head.fields.push((name, value));
        }
    }
    Ok(Some((head, took)))
}

/// Render a head block: `fields`, then `content-length` when given, then the blank line.
///
/// # Errors
///
/// A name or value carries a CR, an LF or a NUL (it would end a line the caller does not own).
pub fn render_head(
    fields: &[(&str, &[u8])],
    content_length: Option<usize>,
) -> Result<Vec<u8>, &'static str> {
    let clean = |v: &[u8]| !v.iter().any(|b| matches!(b, b'\r' | b'\n' | 0));
    let mut out = Vec::new();
    for (name, value) in fields {
        if name.is_empty() || name.contains(':') || !clean(name.as_bytes()) || !clean(value) {
            return Err("a field cannot be written as one head line");
        }
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    if let Some(n) = content_length {
        out.extend_from_slice(format!("content-length: {n}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

#[cfg(test)]
#[path = "tests/msg_tests.rs"]
mod tests;
