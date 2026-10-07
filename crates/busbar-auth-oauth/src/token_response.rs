// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Reading an OAuth token endpoint's `expires_in`: the default a response that omits it gets, and
//! the tolerant parse the self-minting styles (JWT bearer, client credentials) read it with. MOVED
//! VERBATIM from the identity unit's `egress_auth/token_response.rs` in the kernel (KERNEL<>PLUGINS step
//! 22); the minting that reads it moved with it, into [`crate::mint`].
//!
//! Beside it, the two secret-hygiene (#53) helpers the minters decode with: [`deserialize_redacted`]
//! lands a secret field of a decoded document straight in `Redacted`, and [`json_err`] describes a
//! decode failure without the decoder's text, which can quote the secret it was decoding.

use busbar_contract::redacted::Redacted;

/// Deserialize a secret string STRAIGHT into [`Redacted`], for a `#[serde(deserialize_with)]` field.
///
/// `Redacted` deliberately implements neither `Serialize` nor `Deserialize` (its serde fence), so a
/// secret-bearing field of a decoded document names this helper instead: the plaintext exists as a
/// bare `String` only for the instant between the decoder and the wrapper. Narrowly the READ
/// direction: nothing here can write a secret back out.
pub fn deserialize_redacted<'de, D>(d: D) -> Result<Redacted<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <String as serde::Deserialize>::deserialize(d).map(Redacted::new)
}

/// The `map_err` for a `serde_json` decode whose INPUT may carry a secret: a service-account key or
/// a token response. `serde_json::Error`'s own `Display` is withheld: a data error quotes the
/// offending value (`invalid type: string "<the value>"`), which here can be the secret itself, and
/// these messages reach `--validate` output, read-scope admin callers and logs. What survives is
/// `what` failed, the CLASS of failure and WHERE (secret-hygiene #53, Check 3: redact at the format
/// site). The one decoder text kept verbatim is a MISSING FIELD: serde spells it from the type's own
/// schema (``missing field `private_key` ``), never from the input.
pub fn json_err(what: &'static str) -> impl FnOnce(serde_json::Error) -> String {
    move |e: serde_json::Error| {
        if e.is_data() && e.to_string().starts_with("missing field `") {
            return format!("{what}: {e}");
        }
        let class = match e.classify() {
            serde_json::error::Category::Io => "the input could not be read",
            serde_json::error::Category::Syntax => "it is not well-formed JSON",
            serde_json::error::Category::Data => "a field is missing or has the wrong type",
            serde_json::error::Category::Eof => "it ends before the JSON does",
        };
        let (line, column) = (e.line(), e.column());
        format!("{what}: {class} (line {line}, column {column}; the decoder's text is withheld)")
    }
}

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
