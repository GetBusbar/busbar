// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `open_outbound`'s body: `jwt-bearer` and `oauth-client-credentials` bind from their settings
//! ([`open_binding`]). Neither touches the network at open — the first mint runs in the background
//! on `tick`. Neither serves a caller-credential passthrough mode: an OAuth token is always minted
//! from the OPERATOR's own configured credential (a service-account key, a client id/secret), never
//! from a per-request caller credential, so this mechanism declares no
//! [`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`] (ARCHITECT ruling 2026-09-29).
//!
//! THE SETTINGS SCHEMA (ARCHITECT ruling 2026-09-28):
//!
//! | style | settings |
//! |---|---|
//! | `jwt-bearer` | `{scope?, subject?, max_response_bytes?}` |
//! | `oauth-client-credentials` | `{token_url, scope, max_response_bytes?}` |
//!
//! THE REFUSALS (ARCHITECT ruling 2026-09-28): a binding that cannot open answers FAILED with one
//! line per finding, each `credential: <text>` or `settings: <text>`. The kernel composes the 1.5.5
//! sentence — `provider '<p>' <style> credential (from <src>) is invalid: <text>`, or
//! `provider '<p>' <text>` — so every `<text>` below is 1.5.5's own words.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::mint::{self, Minted, Minter};

/// RFC 7523.
pub const JWT_BEARER: &str = "jwt-bearer";
/// RFC 6749 §4.4.
pub const OAUTH_CLIENT_CREDENTIALS: &str = "oauth-client-credentials";

/// One finding that refuses a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The credential is invalid: the kernel wraps it in `<style> credential (from <src>) is
    /// invalid:`.
    Credential(String),
    /// The settings are: the kernel prefixes `provider '<p>' `.
    Settings(String),
}

impl Refusal {
    /// The line `open_outbound` answers.
    pub fn line(&self) -> String {
        match self {
            Refusal::Credential(t) => format!("credential: {t}"),
            Refusal::Settings(t) => format!("settings: {t}"),
        }
    }
}

/// The settings object (`{}` when absent).
fn object(settings: Option<&[u8]>) -> Result<Map<String, Value>, Refusal> {
    let Some(bytes) = settings.filter(|b| !b.is_empty()) else {
        return Ok(Map::new());
    };
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err(Refusal::Settings(
            "outbound auth settings must be a JSON object".to_string(),
        )),
        Err(e) => Err(Refusal::Settings(format!(
            "outbound auth settings are not JSON: {e}"
        ))),
    }
}

fn field<T: for<'de> Deserialize<'de>>(
    m: &Map<String, Value>,
    key: &str,
) -> Result<Option<T>, Refusal> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => serde_json::from_value(v.clone()).map(Some).map_err(|e| {
            Refusal::Settings(format!("outbound auth setting `{key}` is invalid: {e}"))
        }),
    }
}

/// A non-blank string setting.
fn text(m: &Map<String, Value>, key: &str) -> Result<Option<String>, Refusal> {
    Ok(field::<String>(m, key)?.filter(|s| !s.trim().is_empty()))
}

fn max_response_bytes(m: &Map<String, Value>) -> Result<usize, Refusal> {
    Ok(field::<usize>(m, "max_response_bytes")?.unwrap_or(mint::DEFAULT_MAX_RESPONSE_BYTES))
}

/// What opening a style needs from the instance: the token cache, keyed by (style, credential,
/// settings), so a re-open shares the cell a previous generation minted into.
pub trait TokenCache {
    /// The cell for `key`; `minter` makes it when absent (and is dropped when a cell is held).
    fn cell(&self, key: [u8; 32], minter: Minter, max: usize) -> Arc<Minted>;
}

/// The token cache key: SHA-256 over (style, credential, settings), NUL-separated.
pub fn cache_key(style: &str, credential: &[u8], settings: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(style.as_bytes());
    h.update([0]);
    h.update(credential);
    h.update([0]);
    h.update(settings);
    h.finalize().into()
}

/// Bind `style` to `credential` under `settings` — `open_outbound`'s body. Never touches the
/// network: a minted style's first mint runs on `tick`.
///
/// # Errors
///
/// Every finding that refuses the binding, in 1.5.5's check order.
pub fn open_binding(
    style: &str,
    credential: Option<&[u8]>,
    settings: Option<&[u8]>,
    cache: &dyn TokenCache,
) -> Result<Arc<Minted>, Vec<Refusal>> {
    let m = object(settings).map_err(|r| vec![r])?;
    let credential_text = match credential.map(std::str::from_utf8) {
        None => None,
        Some(Ok(s)) => Some(s),
        Some(Err(_)) => {
            return Err(vec![Refusal::Credential(
                "the credential is not UTF-8".to_string(),
            )])
        }
    };
    match style {
        OAUTH_CLIENT_CREDENTIALS => {
            open_client_credentials(&m, credential_text, credential, settings, cache)
        }
        JWT_BEARER => open_jwt_bearer(&m, credential_text, credential, settings, cache),
        other => Err(vec![Refusal::Settings(format!(
            "outbound auth style `{other}` is not served by this plugin"
        ))]),
    }
}

/// `oauth-client-credentials`: 1.5.5's `config_validate` checks, in its order (the keyless
/// contradiction, `token_url`, `scope`, the credential shape), then the binding.
fn open_client_credentials(
    m: &Map<String, Value>,
    credential: Option<&str>,
    raw: Option<&[u8]>,
    settings: Option<&[u8]>,
    cache: &dyn TokenCache,
) -> Result<Arc<Minted>, Vec<Refusal>> {
    let mut refusals = Vec::new();
    // A keyless declaration contradicts the grant: this flow MINTS its token FROM the credential
    // (`client_id:client_secret`), so `none` leaves it nothing to exchange.
    if credential.is_none() {
        refusals.push(Refusal::Settings(
            "uses auth: oauth-client-credentials but declares `api_key: none`; that grant mints \
             its token FROM the credential (`client_id:client_secret`), so there is nothing to \
             declare keyless"
                .to_string(),
        ));
    }
    let token_url = text(m, "token_url").map_err(|r| vec![r])?;
    if token_url.is_none() {
        refusals.push(Refusal::Settings(
            "uses auth: oauth-client-credentials but has no `token_url` (the OAuth token endpoint \
             the client credentials are POSTed to)"
                .to_string(),
        ));
    }
    let scope = text(m, "scope").map_err(|r| vec![r])?;
    if scope.is_none() {
        refusals.push(Refusal::Settings(
            "uses auth: oauth-client-credentials but has no `scope`".to_string(),
        ));
    }
    let cred = credential.unwrap_or("");
    if !cred.trim().is_empty() {
        if let Err(e) = mint::oauth_client_credentials::validate_credential(cred) {
            refusals.push(Refusal::Credential(e));
        }
    }
    let max = max_response_bytes(m).map_err(|r| vec![r])?;
    if !refusals.is_empty() {
        return Err(refusals);
    }
    let (Some(token_url), Some(scope)) = (token_url, scope) else {
        return Err(refusals);
    };
    let built = mint::oauth_client_credentials::build(cred, &token_url, &scope)
        .map_err(|e| vec![Refusal::Credential(e)])?;
    let key = cache_key(
        OAUTH_CLIENT_CREDENTIALS,
        raw.unwrap_or_default(),
        settings.unwrap_or_default(),
    );
    Ok(cache.cell(key, Minter::ClientCredentials(built), max))
}

/// `jwt-bearer`: the keyless contradiction, then the service-account credential.
fn open_jwt_bearer(
    m: &Map<String, Value>,
    credential: Option<&str>,
    raw: Option<&[u8]>,
    settings: Option<&[u8]>,
    cache: &dyn TokenCache,
) -> Result<Arc<Minted>, Vec<Refusal>> {
    // Same contradiction as the oauth arm: this grant SIGNS its assertion with the credential (the
    // service-account JSON or key file), so `none` disarms it entirely.
    let Some(cred) = credential else {
        return Err(vec![Refusal::Settings(
            "uses auth: jwt-bearer but declares `api_key: none`; that grant signs its assertion \
             WITH the credential (the service-account JSON or key file), so there is nothing to \
             declare keyless"
                .to_string(),
        )]);
    };
    let scope = text(m, "scope").map_err(|r| vec![r])?;
    let subject = text(m, "subject").map_err(|r| vec![r])?;
    let max = max_response_bytes(m).map_err(|r| vec![r])?;
    let signer = mint::jwt_bearer::build(cred, scope.as_deref(), subject.as_deref())
        .map_err(|e| vec![Refusal::Credential(e)])?;
    let key = cache_key(
        JWT_BEARER,
        raw.unwrap_or_default(),
        settings.unwrap_or_default(),
    );
    Ok(cache.cell(key, Minter::JwtBearer(Box::new(signer)), max))
}

#[cfg(test)]
#[path = "tests/style_tests.rs"]
mod tests;
