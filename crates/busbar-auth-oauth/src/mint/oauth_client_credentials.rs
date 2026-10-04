// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `oauth-client-credentials` egress auth — OAuth 2.0 client-credentials grant (RFC 6749 §4.4).
//!
//! The simplest OAuth machine-to-machine flow: POST `client_id` + `client_secret` (+ `scope`) to a
//! token endpoint and receive a short-lived bearer. No signing (unlike `jwt-bearer`). GENERIC —
//! **Azure OpenAI via Microsoft Entra ID / AAD** is the first consumer (token_url =
//! `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, scope =
//! `https://cognitiveservices.azure.com/.default`), but any client-credentials backend works by
//! config.
//!
//! MOVED VERBATIM from the kernel's `egress_auth/oauth_client_credentials.rs` (KERNEL<>PLUGINS
//! step 22). This module owns only the token request; the exchange runs over the plugin's own need,
//! and the token cache, the per-request read and the refresh ahead of expiry on `tick` live in
//! [`super`], shared with `jwt-bearer`.
//!
//! The `token_url` https / cloud-metadata vetting (`validate_token_url`) did NOT move: the kernel
//! judges an auth plugin's need target at seal and at `--validate` and renders those 1.5.5 texts
//! itself (ARCHITECT ruling 2026-09-28, Q2 (a)).

use super::TokenRequest;

/// The exchange material for one binding. Immutable after construction.
#[derive(Debug)]
pub(crate) struct ClientCreds {
    client_id: String,
    /// The confidential-client secret, held [`busbar_contract::redacted::Redacted`] so it never leaks via `Debug`
    /// (this struct derives it) and zeroizes on drop. Exposed only into the token-endpoint POST body.
    client_secret: busbar_contract::redacted::Redacted<String>,
    token_url: String,
    scope: String,
}

/// Build an `oauth-client-credentials` binding. `credential` is `client_id:client_secret` (the first
/// `:` splits them, so a secret may itself contain `:`). `token_url` and `scope` come from the
/// provider config. Fails loud on a malformed credential; the token itself mints on `tick`.
pub(crate) fn build(credential: &str, token_url: &str, scope: &str) -> Result<ClientCreds, String> {
    let (client_id, client_secret) = split_credential(credential)?;
    Ok(ClientCreds {
        client_id: client_id.to_string(),
        client_secret: busbar_contract::redacted::Redacted::new(client_secret.to_string()),
        token_url: token_url.to_string(),
        scope: scope.to_string(),
    })
}

/// Split + check a `client_id:client_secret` credential (the first `:` splits, so a secret may contain
/// `:`). Shared by [`build`] and [`validate_credential`] so the boot/apply path and the config
/// `--validate` dry-run enforce identical checks with identical messages.
fn split_credential(credential: &str) -> Result<(&str, &str), String> {
    let (client_id, client_secret) = credential
        .split_once(':')
        .ok_or("oauth-client-credentials key must be `client_id:client_secret`")?;
    if client_id.is_empty() || client_secret.is_empty() {
        return Err(
            "oauth-client-credentials key has an empty client_id or client_secret".to_string(),
        );
    }
    Ok((client_id, client_secret))
}

/// Validate an `oauth-client-credentials` credential WITHOUT constructing the provider — the config
/// `--validate` dry-run entry point (mirrors `jwt_bearer::validate_credential`, so a malformed
/// credential is caught at validate time for BOTH OAuth mechanisms, not only jwt-bearer).
pub(crate) fn validate_credential(credential: &str) -> Result<(), String> {
    split_credential(credential).map(|_| ())
}

impl ClientCreds {
    /// The token request (RFC 6749 §4.4): the form encodes through `serde_urlencoded` (the exact call
    /// reqwest's `.form()` was), POSTed to `token_url`.
    pub(crate) fn request(&self) -> Result<TokenRequest, String> {
        let form = serde_urlencoded::to_string([
            ("grant_type", "client_credentials"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.expose_secret().as_str()),
            ("scope", self.scope.as_str()),
        ])
        .map_err(|e| format!("token request form could not be encoded: {e}"))?;
        Ok(TokenRequest::form(self.token_url.clone(), form))
    }
}

#[cfg(test)]
#[path = "../tests/oauth_client_credentials_tests.rs"]
mod tests;
