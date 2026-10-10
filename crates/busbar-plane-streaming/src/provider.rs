// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DIALECT'S PROVIDER ADDRESS RULES — the names of the two dialects this plane speaks, the keyless
//! provider endpoint each dials, and where each dialect's credential is presented on that dial.

/// THE DIALECT NAME this plane speaks first — OpenAI's bidirectional Realtime voice API. Named once
/// here; it is the dialect registry key and the FIRST of the plane's wire formats.
pub const OPENAI_REALTIME: &str = "openai_realtime";

/// THE SECOND DIALECT this plane speaks — Google's Gemini Live `BidiGenerateContent` API. Its codec is
/// `GeminiLiveCodec`; adding it to the wire formats is what EARNS the plane its superset IR
/// (a plane earns a superset at its SECOND wire format and not before).
pub const GEMINI_LIVE: &str = "gemini_live";

/// THE PROVIDER SIDE OF A DIAL — the origin, converted to its socket scheme, plus the fixed path the
/// dialect's realtime endpoint answers on. Carries no credential: the dialect's
/// [`credential_placement`] says where the host presents one, and the host adds it to the upgrade
/// request only, so this plane never holds or formats the secret.
#[must_use]
pub fn provider_ws_url(base_url: &str, dialect: &str) -> String {
    let ws = base_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    let ws = ws.trim_end_matches('/');
    if dialect == GEMINI_LIVE {
        format!("{ws}/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent")
    } else {
        format!("{ws}/v1/realtime")
    }
}

/// Where a dialect's provider dial presents its credential — declared here as data, applied by the
/// host to the upgrade request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialPlacement {
    /// A query parameter with this name on the request target.
    Query(&'static str),
    /// A request header `name: {prefix}{secret}`.
    Header {
        /// The header name (lowercase).
        name: &'static str,
        /// Written before the secret.
        prefix: &'static str,
    },
}

/// THE DIALECT'S NATIVE CREDENTIAL SCHEME on its realtime socket: Gemini Live takes the documented
/// `?key=` query parameter (the bytes on the wire are the ones this plane has always sent); OpenAI
/// Realtime takes `Authorization: Bearer`.
#[must_use]
pub fn credential_placement(dialect: &str) -> CredentialPlacement {
    if dialect == GEMINI_LIVE {
        CredentialPlacement::Query("key")
    } else {
        CredentialPlacement::Header {
            name: "authorization",
            prefix: "Bearer ",
        }
    }
}

#[cfg(test)]
#[path = "tests/provider_tests.rs"]
mod tests;
