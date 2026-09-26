// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Reading an OAuth token endpoint's `expires_in`: the default a response that omits it gets, and
//! the tolerant parse the self-minting egress credentials (JWT bearer, client credentials) read it
//! with. Pure token-response semantics — the minting itself, which dials the token endpoint, stays
//! with the kernel's engine.

/// Default token TTL when a token endpoint omits `expires_in` (RFC 6749 section 5.1 makes it
/// RECOMMENDED, not required): a conservative 1 h so the token still refreshes on schedule.
pub fn default_expires_in() -> u64 {
    3600
}

/// Deserialize an OAuth `expires_in` TOLERANTLY. RFC 6749 specifies a number of seconds, but real IdPs
/// vary — some emit it as a JSON STRING (`"3600"`), and some omit it (handled by
/// `#[serde(default = "default_expires_in")]` on the field). A strict `u64` field breaks token minting
/// for those providers, silently downing the lane. Accept an integer, a JSON float/decimal
/// (`3600.0` / `"3600.5"`, truncated toward zero — a fractional second on a token TTL is noise), or a
/// numeric string. A negative or non-finite value is rejected.
pub fn deserialize_expires_in<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum NumOrStr {
        // Order matters for `untagged`: an integer matches `Num` first; `Float` only catches a
        // non-integer JSON number; `Str` catches a quoted value.
        Num(u64),
        Float(f64),
        Str(String),
    }
    fn float_to_secs<E: serde::de::Error>(f: f64) -> Result<u64, E> {
        if f.is_finite() && f >= 0.0 {
            Ok(f as u64)
        } else {
            Err(E::custom(format!(
                "expires_in must be a non-negative number, got {f}"
            )))
        }
    }
    match NumOrStr::deserialize(d)? {
        NumOrStr::Num(n) => Ok(n),
        NumOrStr::Float(f) => float_to_secs(f),
        NumOrStr::Str(s) => {
            let t = s.trim();
            if let Ok(n) = t.parse::<u64>() {
                Ok(n)
            } else if let Ok(f) = t.parse::<f64>() {
                float_to_secs(f)
            } else {
                Err(serde::de::Error::custom(format!(
                    "expires_in {s:?} is not a number"
                )))
            }
        }
    }
}
