// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `oauth-token-exchange` egress auth — OAuth 2.0 Token Exchange (RFC 8693), audience-bound by an
//! RFC 8707 `resource` (ARCHITECT round 5 Q-L3B-EXCHANGE (B); BUSBAR-1.6.0.md B.3 item 12: an
//! outbound style whose one per-request call runs the exchange inside the auth plugin, the
//! provider's target as the audience).
//!
//! The credential is BUSBAR'S OWN subject token, never a caller's; the settings name the
//! authorization server's `token_url`, the `subject_token_type` (default: an access token) and the
//! `resource` (the upstream's audience). What the exchange asks FOR is not a setting: the scope is
//! the per-call down-scope the request states (`abi::auth::EXT_SCOPE` in the call's extensions
//! blob), so each distinct scope is its own exchange and its own cached token — two scopes never
//! share a token.
//!
//! The request is the previous release's byte for byte (its `ExchangeRequest::form_fields`): the
//! form fields in RFC order, `grant_type`, `subject_token`, `subject_token_type`,
//! `requested_token_type` (always an access token), `resource`, `scope` (present, empty when the
//! call states none), POSTed to `token_url` over the plugin's own need.

use std::sync::Arc;

use busbar_contract::redacted::Redacted;

use super::TokenRequest;

/// RFC 8693 section 2.1 `grant_type`.
pub(crate) const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 8693 section 3: an access token — the default `subject_token_type`, and always the
/// `requested_token_type` (an access token back, not another exchangeable subject token).
pub(crate) const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// One binding's exchange material, immutable after construction: every per-call exchange shares
/// it and adds its own scope.
#[derive(Debug)]
pub(crate) struct Exchange {
    /// Busbar's own subject token, held redacted (never printed; zeroised on drop) and exposed only
    /// into the token-endpoint POST body.
    subject_token: Redacted<String>,
    subject_token_type: String,
    token_url: String,
    resource: String,
}

/// Build a binding's exchange material.
pub(crate) fn build(
    subject_token: &str,
    token_url: &str,
    subject_token_type: &str,
    resource: &str,
) -> Exchange {
    Exchange {
        subject_token: Redacted::new(subject_token.to_string()),
        subject_token_type: subject_token_type.to_string(),
        token_url: token_url.to_string(),
        resource: resource.to_string(),
    }
}

/// ONE SCOPE's exchange: the binding's material and the scope this cell's token is asked for.
#[derive(Debug)]
pub(crate) struct Scoped {
    exchange: Arc<Exchange>,
    scope: String,
}

impl Scoped {
    /// The exchange of `exchange` for `scope`.
    pub(crate) fn new(exchange: Arc<Exchange>, scope: &str) -> Self {
        Self {
            exchange,
            scope: scope.to_string(),
        }
    }

    /// The token request (RFC 8693 section 2.1): the form, encoded through `serde_urlencoded`,
    /// POSTed to `token_url` over the need that names it.
    pub(crate) fn request(&self) -> Result<TokenRequest, String> {
        let x = &self.exchange;
        let form = serde_urlencoded::to_string([
            ("grant_type", GRANT_TYPE),
            ("subject_token", x.subject_token.expose_secret().as_str()),
            ("subject_token_type", x.subject_token_type.as_str()),
            ("requested_token_type", ACCESS_TOKEN_TYPE),
            ("resource", x.resource.as_str()),
            ("scope", self.scope.as_str()),
        ])
        .map_err(|e| format!("the RFC 8693 exchange form could not be encoded: {e}"))?;
        Ok(TokenRequest::form(
            super::need::TOKEN_URL,
            x.token_url.clone(),
            form,
        ))
    }
}

#[cfg(test)]
#[path = "../tests/token_exchange_tests.rs"]
mod tests;
