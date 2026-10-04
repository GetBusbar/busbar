// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO ONE-SHOT PASSES THE PLANE BROKERS TO ITS PROVIDER, what it says and what it reads: the
//! ephemeral client-secret mint a browser session is handed, and the SDP offer it relays.
//!
//! Pure. Nothing here sends a request, reads a clock or holds a key: the caller carries the bytes
//! these functions shape to the provider, and hands the provider's answer back to be read. The real
//! provider key authenticates only the busbar-to-provider hop and never enters anything built or
//! returned here.

use crate::codec::ir::config::SessionConfig;

/// The provider's client-secret mint path, under its base URL.
pub const CLIENT_SECRETS_PATH: &str = "/v1/realtime/client_secrets";

/// The provider's SDP call path, under its base URL.
pub const CALLS_PATH: &str = "/v1/realtime/calls";

/// The media type of an SDP offer and of the answer relayed back.
pub const SDP_CONTENT_TYPE: &str = "application/sdp";

/// The header a mint request names its caller in, so the provider can attribute the browser session.
pub const SAFETY_IDENTIFIER_HEADER: &str = "OpenAI-Safety-Identifier";

/// The lifetime of a minted secret when none is requested, in seconds.
pub const DEFAULT_TTL_SECS: u64 = 600;
/// The shortest lifetime a mint asks for, in seconds.
pub const MIN_TTL_SECS: u64 = 10;
/// The longest lifetime a mint asks for, in seconds.
pub const MAX_TTL_SECS: u64 = 7200;

/// The prefix every ephemeral secret the provider mints carries.
const EK_PREFIX: &str = "ek_";

/// The lifetime a mint asks for: the requested one, else [`DEFAULT_TTL_SECS`], held inside
/// [`MIN_TTL_SECS`]..=[`MAX_TTL_SECS`].
#[must_use]
pub fn clamped_ttl_secs(requested: Option<u64>) -> u64 {
    requested
        .unwrap_or(DEFAULT_TTL_SECS)
        .clamp(MIN_TTL_SECS, MAX_TTL_SECS)
}

/// The mint request's body: the secret's lifetime, anchored at its creation, and the locked session
/// params the browser's session is bound to.
///
/// # Errors
/// The serializer's text when the body does not serialize.
pub fn mint_request_body(ttl_secs: u64, config: &SessionConfig) -> Result<Vec<u8>, String> {
    let body = serde_json::json!({
        "expires_after": { "anchor": "created_at", "seconds": ttl_secs },
        "session": config,
    });
    serde_json::to_vec(&body).map_err(|e| format!("mint request body did not serialize: {e}"))
}

/// A minted ephemeral secret and when it expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Minted {
    /// The `ek_` secret the browser presents.
    pub value: String,
    /// When it expires, in Unix seconds; `0` when the provider did not say.
    pub expires_at_unix: u64,
}

#[derive(serde::Deserialize)]
struct ClientSecretResponse {
    value: String,
    #[serde(default)]
    expires_at: u64,
}

/// Read a successful mint answer's body.
///
/// # Errors
/// A body that does not parse, or a value that is not an `ek_` ephemeral secret, each with the text
/// the caller reports.
pub fn read_minted(body: &[u8]) -> Result<Minted, String> {
    let parsed: ClientSecretResponse = serde_json::from_slice(body)
        .map_err(|e| format!("client-secret response did not parse: {e}"))?;
    if !parsed.value.starts_with(EK_PREFIX) {
        return Err("client-secret response value is not an ek_ ephemeral secret".into());
    }
    Ok(Minted {
        value: parsed.value,
        expires_at_unix: parsed.expires_at,
    })
}

/// The browser's answer to a mint: the secret and its expiry, and nothing else.
#[must_use]
pub fn minted_answer(minted: &Minted) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "value": minted.value,
        "expires_at_unix": minted.expires_at_unix,
    }))
    .unwrap_or_default()
}

/// The provider's call id in an SDP answer's `Location`: the last path segment starting `rtc_`, less
/// any query or fragment.
#[must_use]
pub fn rtc_call_id_of(location: &str) -> Option<String> {
    location
        .rsplit('/')
        .find(|seg| seg.starts_with("rtc_"))
        .map(|seg| seg.split(['?', '#']).next().unwrap_or(seg).to_string())
}

#[cfg(test)]
#[path = "tests/broker_tests.rs"]
mod tests;
