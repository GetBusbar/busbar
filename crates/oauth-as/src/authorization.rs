// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Authorization-endpoint request/response types, mirrored from RFC 6749 section 4.1 with the
//! OAuth 2.1 constraints: `code` is the only response type (the implicit grant is removed), PKCE
//! is required, and only the `S256` challenge method is offered (`plain` is not implemented).
//!
//! The endpoint MACHINE lives in [`crate::server::AuthorizationServer::authorize`] (validation,
//! code issuance) and in the token endpoint's `authorization_code` arm (redemption with PKCE
//! verification). The host still owns everything interactive: login, consent UI, and the actual
//! HTTP redirect; it hands this crate the parsed parameters and the authenticated subject.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
use crate::error::ErrorResponse;
use crate::scope::ScopeSet;

/// `response_type` values this server will ever accept. OAuth 2.1 removes `token` (implicit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    /// The authorization-code response type.
    #[serde(rename = "code")]
    Code,
}

/// PKCE challenge methods this server offers (RFC 7636). OAuth 2.1 requires `S256`; `plain` is
/// deliberately not implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    /// `code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))`, no padding.
    S256,
}

/// The parsed authorization request (RFC 6749 section 4.1.1 plus RFC 7636 parameters). The host
/// parses the query string into this; validation happens in the (future) endpoint machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// Must be `code`.
    pub response_type: ResponseType,
    /// The requesting client.
    pub client_id: ClientId,
    /// Requested redirect target; must exact-match a registered URI when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    /// Requested scope; `None` means the client's registered default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeSet>,
    /// Opaque client state, echoed back verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// The PKCE challenge (required in OAuth 2.1 for the authorization-code grant).
    pub code_challenge: String,
    /// The PKCE method; only `S256`.
    pub code_challenge_method: CodeChallengeMethod,
}

/// The RAW query parameters of an authorization request, exactly as the host parsed them from
/// the query string and BEFORE any validation. Every field is optional here because the wire
/// makes no promises; [`crate::server::AuthorizationServer::authorize`] turns this into either
/// a validated grant or the RFC-mandated rejection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorizeParams {
    /// `response_type` as presented; must be `code` (RFC 6749 section 4.1.1; OAuth 2.1 removes
    /// every other value).
    pub response_type: Option<String>,
    /// `client_id` as presented.
    pub client_id: Option<String>,
    /// `redirect_uri` as presented; must exact-match a registered URI when present.
    pub redirect_uri: Option<String>,
    /// `scope` as presented (space-delimited).
    pub scope: Option<String>,
    /// `state` as presented; echoed back verbatim on every redirect.
    pub state: Option<String>,
    /// `code_challenge` as presented (RFC 7636 section 4.3; REQUIRED in OAuth 2.1).
    pub code_challenge: Option<String>,
    /// `code_challenge_method` as presented; only `S256` is accepted (RFC 7636 defaults an
    /// absent method to `plain`, which this server does not implement).
    pub code_challenge_method: Option<String>,
}

/// How an authorization request is rejected. RFC 6749 section 4.1.2.1 splits the world in two:
/// when the client identity or redirection target cannot be trusted the server MUST NOT
/// redirect, and everything else is delivered to the (validated) redirect URI as an error
/// redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeRejection {
    /// `client_id` or `redirect_uri` is missing, unknown, or mismatched: the user agent MUST NOT
    /// be redirected (RFC 6749 section 4.1.2.1). The host renders this however its UI wants.
    Unredirectable(ErrorResponse),
    /// The client and redirect target validated, so the error goes back via the redirect URI
    /// with `state` echoed (RFC 6749 section 4.1.2.1).
    Redirect {
        /// The VALIDATED redirect target the error parameters go to.
        redirect_uri: String,
        /// The request's `state`, echoed verbatim when present.
        state: Option<String>,
        /// The error to serialize into the redirect's query.
        error: ErrorResponse,
    },
}

/// A granted authorization: where to send the user agent and the parameters to append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationGrant {
    /// The validated redirect target.
    pub redirect_uri: String,
    /// The `code` and echoed `state` (RFC 6749 section 4.1.2).
    pub response: AuthorizationResponse,
}

/// A persisted, not-yet-redeemed authorization code: everything the token endpoint needs to
/// enforce RFC 6749 section 4.1.3 and RFC 7636 section 4.6 at redemption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationCodeRecord {
    /// The single-use code (the storage key).
    pub code: String,
    /// The client the code was issued to; redemption by any other client is `invalid_grant`.
    pub client_id: ClientId,
    /// The `redirect_uri` EXPLICITLY presented in the authorization request, if any. When
    /// `Some`, the token request must present the identical value (RFC 6749 section 4.1.3).
    pub redirect_uri: Option<String>,
    /// The granted scope.
    pub scope: ScopeSet,
    /// The PKCE `S256` challenge to verify the redemption's `code_verifier` against.
    pub code_challenge: String,
    /// The authenticated resource owner who approved the request.
    pub subject: String,
    /// The request's `state`, kept for auditability (never re-emitted at redemption).
    pub state: Option<String>,
    /// Expiry instant; RFC 6749 section 4.1.2 recommends a maximum lifetime of 10 minutes.
    pub expires_at: SystemTime,
}

/// The success redirect parameters (RFC 6749 section 4.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    /// The single-use authorization code.
    pub code: String,
    /// The request's `state`, echoed verbatim; REQUIRED iff the request carried one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_spellings() {
        assert_eq!(
            serde_json::to_value(ResponseType::Code).unwrap(),
            serde_json::json!("code")
        );
        assert_eq!(
            serde_json::to_value(CodeChallengeMethod::S256).unwrap(),
            serde_json::json!("S256")
        );
    }

    #[test]
    fn implicit_grant_is_not_representable() {
        assert!(serde_json::from_value::<ResponseType>(serde_json::json!("token")).is_err());
        assert!(serde_json::from_value::<CodeChallengeMethod>(serde_json::json!("plain")).is_err());
    }
}
