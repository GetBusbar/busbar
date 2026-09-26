// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
//! THE LLM PLANE'S OWN JSON SEAM (#83a O6): the one place this plane names its JSON library.
//!
//! Every body parse and serialize on this plane's translate path goes through here, so the
//! implementation (sonic-rs, SIMD on the large string-heavy LLM bodies) lives in ONE place and the
//! in-memory document type is `serde_json::Value`. It is dialect machinery, not a contract shape: the
//! contract takes no sonic-rs (#83(d) call 1), and the host keeps its own copy of this seam for its
//! own bodies.
//!
//! TWO COPIES OF ONE SECURITY FLOOR. The nesting-depth guard below is a security floor, not a
//! tunable, and the host's copy guards the same way. `MAX_JSON_DEPTH` is 128 on both sides; the drift
//! test beside this module fails if the two copies disagree on the floor or on the depth scan's
//! verdict over a shared fixture set.

/// Maximum JSON nesting depth accepted at any parse boundary. Matches `serde_json`'s long-standing
/// default of 128 — generous for real plugin payloads (a deeply nested structured body is still only
/// a handful of levels) while bounding the recursion below. This is a SECURITY floor, not an
/// operational tunable: `sonic-rs` parses nesting ITERATIVELY into a `serde_json::Value` (no depth
/// limit on that path, unlike `serde_json::from_slice` which rejects past 128), but the resulting
/// `Value` is then recursively re-serialized (`to_vec` on the injected body) and recursively dropped —
/// and a ~10k-deep body (well under the 32 MiB body cap) overflows the worker stack and ABORTS the
/// process (uncatchable; kills every in-flight request). The pre-scan below rejects such input before
/// any `Value` is built, so it can neither be re-serialized nor dropped.
pub(crate) const MAX_JSON_DEPTH: usize = 128;

/// Single-pass, string-aware scan for the maximum `{`/`[` nesting depth in `bytes`. Brackets inside
/// JSON string literals (and `\`-escaped quotes) do not count. Returns `true` as soon as `max` is
/// exceeded (short-circuit). O(n), no allocation — far cheaper than the parse it guards.
pub(crate) fn exceeds_max_depth(bytes: &[u8], max: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// Parse body bytes into a document. SIMD-accelerated. Rejects pathologically-nested input (see
/// `MAX_JSON_DEPTH`) BEFORE building a `Value`, returning a parse `Err` so callers take their existing
/// malformed-body (400) path. Callers log via `parse_err_log(len)`, never the raw `Display`, so the
/// substitute error's message is never surfaced.
#[inline]
pub fn parse<'de, T: serde::Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, sonic_rs::Error> {
    if exceeds_max_depth(bytes, MAX_JSON_DEPTH) {
        // Manufacture a real `sonic_rs::Error` of the right type without touching the deep input.
        return sonic_rs::from_slice::<T>(b"");
    }
    sonic_rs::from_slice(bytes)
}

/// Parse a body `&str` into a document (e.g. an SSE `data:` payload). SIMD-accelerated. Same depth
/// guard as [`parse`].
#[inline]
pub fn parse_str<'de, T: serde::Deserialize<'de>>(s: &'de str) -> Result<T, sonic_rs::Error> {
    if exceeds_max_depth(s.as_bytes(), MAX_JSON_DEPTH) {
        return sonic_rs::from_slice::<T>(b"");
    }
    sonic_rs::from_slice(s.as_bytes())
}

/// Serialize a document to body bytes. SIMD-accelerated; the request/response hot-path serializer.
#[inline]
pub fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, sonic_rs::Error> {
    sonic_rs::to_vec(value)
}

/// Serialize a document to a `String` (error envelopes, SSE-event data). sonic-rs always emits valid
/// UTF-8, so `from_utf8_lossy` never substitutes a replacement char (that path never fires here) — it
/// scans the bytes and returns the borrowed `&str`, then `into_owned()` allocates the `String`. This is
/// a cold path (error envelopes and SSE data, not the per-chunk hot loop), so the extra copy is fine.
#[inline]
pub fn to_string<T: serde::Serialize>(value: &T) -> Result<String, sonic_rs::Error> {
    sonic_rs::to_vec(value).map(|v| String::from_utf8_lossy(&v).into_owned())
}

/// Sanitized one-line description of a parse error for OPERATOR LOGS — never the raw library `Display`,
/// which (with sonic-rs) embeds a fragment of the offending input bytes. A malformed body can contain
/// secrets/PII, so logs must not echo it; "<n> bytes" is enough to correlate without leaking content.
#[inline]
pub fn parse_err_log(bytes_len: usize) -> String {
    format!("invalid JSON ({bytes_len} bytes)")
}

#[cfg(test)]
#[path = "tests/json_seam_tests.rs"]
mod seam_tests;
