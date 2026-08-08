// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The OAuth error response object, mirrored from RFC 6749 section 5.2 (token endpoint), section
//! 4.1.2.1 (authorization endpoint), and the RFC 8628 section 3.5 device-grant extension codes.
//! One enum, one struct, owned here: never a third party's generated types.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Registered `error` codes this server can emit.
///
/// The wire spelling is the exact registered token (`snake_case`), which the `serde` rename below
/// pins; `tests/conformance_schema.rs` locks the full emitted set against a schema transcribed
/// from the RFCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    // RFC 6749 section 5.2 (token endpoint).
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    // RFC 6749 section 4.1.2.1 (authorization endpoint; `access_denied` is also an RFC 8628
    // section 3.5 device-grant terminal code).
    AccessDenied,
    UnsupportedResponseType,
    ServerError,
    TemporarilyUnavailable,
    // RFC 8628 section 3.5 (device access token request).
    AuthorizationPending,
    SlowDown,
    ExpiredToken,
}

impl ErrorCode {
    /// The registered wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::InvalidClient => "invalid_client",
            ErrorCode::InvalidGrant => "invalid_grant",
            ErrorCode::UnauthorizedClient => "unauthorized_client",
            ErrorCode::UnsupportedGrantType => "unsupported_grant_type",
            ErrorCode::InvalidScope => "invalid_scope",
            ErrorCode::AccessDenied => "access_denied",
            ErrorCode::UnsupportedResponseType => "unsupported_response_type",
            ErrorCode::ServerError => "server_error",
            ErrorCode::TemporarilyUnavailable => "temporarily_unavailable",
            ErrorCode::AuthorizationPending => "authorization_pending",
            ErrorCode::SlowDown => "slow_down",
            ErrorCode::ExpiredToken => "expired_token",
        }
    }

    /// The HTTP status a token-endpoint response carrying this code takes, per RFC 6749
    /// section 5.2: 400 unless the code is `invalid_client` (401, and the host should attach a
    /// `WWW-Authenticate` header when the client attempted header-based authentication), plus the
    /// conventional 500/503 for the two server-side codes.
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::InvalidClient => 401,
            ErrorCode::ServerError => 500,
            ErrorCode::TemporarilyUnavailable => 503,
            _ => 400,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The RFC 6749 section 5.2 error response body: `error` required, `error_description` and
/// `error_uri` optional and omitted (never `null`) when absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// The registered error code.
    pub error: ErrorCode,
    /// Human-readable ASCII detail for the developer (not the end user), per section 5.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// A URI identifying a human-readable page with more information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

impl ErrorResponse {
    /// A bare error with no description.
    pub fn new(error: ErrorCode) -> Self {
        ErrorResponse {
            error,
            error_description: None,
            error_uri: None,
        }
    }

    /// Attach a developer-facing description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.error_description = Some(description.into());
        self
    }

    /// The HTTP status for this response; see [`ErrorCode::http_status`].
    pub fn http_status(&self) -> u16 {
        self.error.http_status()
    }
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.error_description {
            Some(d) => write!(f, "{}: {}", self.error, d),
            None => f.write_str(self.error.as_str()),
        }
    }
}

impl std::error::Error for ErrorResponse {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_spellings_are_the_registered_tokens() {
        for (code, wire) in [
            (ErrorCode::InvalidRequest, "invalid_request"),
            (ErrorCode::InvalidClient, "invalid_client"),
            (ErrorCode::InvalidGrant, "invalid_grant"),
            (ErrorCode::UnauthorizedClient, "unauthorized_client"),
            (ErrorCode::UnsupportedGrantType, "unsupported_grant_type"),
            (ErrorCode::InvalidScope, "invalid_scope"),
            (ErrorCode::AccessDenied, "access_denied"),
            (
                ErrorCode::UnsupportedResponseType,
                "unsupported_response_type",
            ),
            (ErrorCode::ServerError, "server_error"),
            (ErrorCode::TemporarilyUnavailable, "temporarily_unavailable"),
            (ErrorCode::AuthorizationPending, "authorization_pending"),
            (ErrorCode::SlowDown, "slow_down"),
            (ErrorCode::ExpiredToken, "expired_token"),
        ] {
            assert_eq!(serde_json::to_value(code).unwrap(), serde_json::json!(wire));
            assert_eq!(code.as_str(), wire);
        }
    }

    #[test]
    fn absent_optional_fields_are_omitted_not_null() {
        let body =
            serde_json::to_value(ErrorResponse::new(ErrorCode::AuthorizationPending)).unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "error": "authorization_pending" })
        );
    }

    #[test]
    fn http_status_mapping_follows_rfc6749_5_2() {
        assert_eq!(
            ErrorResponse::new(ErrorCode::InvalidClient).http_status(),
            401
        );
        assert_eq!(
            ErrorResponse::new(ErrorCode::InvalidGrant).http_status(),
            400
        );
        assert_eq!(ErrorResponse::new(ErrorCode::SlowDown).http_status(), 400);
        assert_eq!(
            ErrorResponse::new(ErrorCode::ServerError).http_status(),
            500
        );
        assert_eq!(
            ErrorResponse::new(ErrorCode::TemporarilyUnavailable).http_status(),
            503
        );
    }
}
