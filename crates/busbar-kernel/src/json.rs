// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
//! The single seam where the JSON library is named.
//!
//! Every hot request/response body parse and serialize on the translate path goes through here, so
//! the implementation (today: sonic-rs, SIMD on the large string-heavy bodies plugin traffic carries)
//! lives in ONE place instead of being scattered as `sonic_rs::`/`serde_json::` across the request
//! path. Swapping the parser/serializer — or, later, eliminating the `serde_json::Value` intermediate
//! in favour of parsing straight into the IR — becomes a change to this module, not a hunt across
//! `ingress/` and `proxy/`. ALL body JSON — hot translate path AND the cold error-body /
//! error-envelope / SSE-event paths — goes through here; only config (YAML) and tests use a JSON
//! library directly. The in-memory document type is `serde_json::Value` (sonic-rs parses/serializes
//! it directly); replacing it with a native value, or swapping the engine, is a change to THIS module.

// The nesting-depth floor (128) and its scan are the contract's, shared with every plane that
// parses JSON: a SECURITY floor, not a tunable. `sonic-rs` parses nesting ITERATIVELY into a
// `serde_json::Value` (no depth limit on that path, unlike `serde_json::from_slice`), but the `Value`
// is then recursively re-serialized and recursively dropped, and a ~10k-deep body (well under the
// 32 MiB body cap) overflows the worker stack and ABORTS the process. The pre-scan rejects such input
// before any `Value` is built.
use busbar_contract::spans::{exceeds_max_depth, MAX_JSON_DEPTH};

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
#[path = "tests/depth_guard_tests.rs"]
mod depth_guard_tests;
