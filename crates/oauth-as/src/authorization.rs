// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Authorization-endpoint request/response types, mirrored from RFC 6749 section 4.1 with the
//! OAuth 2.1 constraints: `code` is the only response type (the implicit grant is removed), PKCE
//! is required, and only the `S256` challenge method is offered (`plain` is not implemented).
//!
//! The interactive endpoint MACHINE (consent, redirects, code issuance and redemption) is a later
//! pass; these types pin the wire shape now so the host-facing surface cannot drift when the
//! machine lands.

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
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
