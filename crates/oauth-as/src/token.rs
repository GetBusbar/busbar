// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Token wire and storage shapes: the RFC 6749 section 5.1 success response, plus the records the
//! server persists through [`crate::store::Storage`]. Access and refresh tokens here are OPAQUE
//! random strings; structured (JWT) access tokens are a possible later addition and would slot in
//! at issuance without changing these shapes.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
use crate::scope::ScopeSet;

/// `token_type` values this server issues. Only `Bearer` (RFC 6750); the registered value is
/// case-insensitive on the wire but conventionally spelled `Bearer`, which the rename pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    /// RFC 6750 bearer token.
    #[serde(rename = "Bearer")]
    Bearer,
}

/// The RFC 6749 section 5.1 successful token response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The opaque access token.
    pub access_token: String,
    /// Always `Bearer` from this server.
    pub token_type: TokenType,
    /// Lifetime in seconds (RECOMMENDED by the RFC; this server always includes it).
    pub expires_in: u64,
    /// The rotating refresh token, when the grant and server config produce one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Space-delimited granted scope. This server always includes it when non-empty, which also
    /// satisfies the section 3.3 requirement to report a scope differing from the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// A persisted access token: what introspection needs to answer for an opaque token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedToken {
    /// The opaque access token string (the storage key).
    pub access_token: String,
    /// The client the token was issued to.
    pub client_id: ClientId,
    /// The resource owner the token acts for; `None` for client-only grants.
    pub subject: Option<String>,
    /// The granted scope.
    pub scope: ScopeSet,
    /// Issuance instant.
    pub issued_at: SystemTime,
    /// Expiry instant; the token is dead at and after this instant.
    pub expires_at: SystemTime,
}

/// A persisted refresh token. Single use: redemption goes through
/// [`crate::store::Storage::take_refresh_token`], and rotation issues a replacement carrying the
/// SAME `expires_at`, so a chain has an absolute lifetime rather than a sliding one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshTokenRecord {
    /// The opaque refresh token string (the storage key).
    pub refresh_token: String,
    /// The client the token was issued to; presentation by any other client consumes it.
    pub client_id: ClientId,
    /// The resource owner the chain acts for.
    pub subject: Option<String>,
    /// The scope originally granted; refreshes may narrow, never widen.
    pub scope: ScopeSet,
    /// Absolute chain expiry; `None` means the chain does not expire by time.
    pub expires_at: Option<SystemTime>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_response_shape_is_rfc6749_5_1() {
        let full = TokenResponse {
            access_token: "at".into(),
            token_type: TokenType::Bearer,
            expires_in: 3600,
            refresh_token: Some("rt".into()),
            scope: Some("read write".into()),
        };
        assert_eq!(
            serde_json::to_value(&full).unwrap(),
            serde_json::json!({
                "access_token": "at",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "rt",
                "scope": "read write",
            })
        );
        let minimal = TokenResponse {
            access_token: "at".into(),
            token_type: TokenType::Bearer,
            expires_in: 60,
            refresh_token: None,
            scope: None,
        };
        assert_eq!(
            serde_json::to_value(&minimal).unwrap(),
            serde_json::json!({ "access_token": "at", "token_type": "Bearer", "expires_in": 60 }),
            "absent optionals must be omitted, not null"
        );
    }
}
