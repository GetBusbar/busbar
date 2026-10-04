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
//! | `oauth-token-exchange` | `{token_url, resource, subject_token_type?, max_response_bytes?}` |
//!
//! `oauth-token-exchange` (RFC 8693, ARCHITECT round 5 Q-L3B-EXCHANGE (B)) binds busbar's own
//! subject token (the credential) and mints nothing at open: each request's scope (the call's
//! extensions blob) is its own exchange, on demand, cached per scope ([`ExchangeBinding`]).
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
/// RFC 8693.
pub const OAUTH_TOKEN_EXCHANGE: &str = "oauth-token-exchange";

/// ONE BOUND STYLE, as a handle holds it: a minted style's token cell, or a token-exchange
/// binding whose cells are per scope.
#[derive(Clone)]
pub enum Binding {
    /// `jwt-bearer` / `oauth-client-credentials`: one cell, refreshed ahead of expiry.
    Minted(Arc<Minted>),
    /// `oauth-token-exchange`: one cell per requested scope, minted on demand.
    Exchange(Arc<ExchangeBinding>),
}

/// AN `oauth-token-exchange` BINDING: the exchange material every scope shares, the key its scopes'
/// cells are cached under, and the response cap.
pub struct ExchangeBinding {
    exchange: Arc<mint::token_exchange::Exchange>,
    key: [u8; 32],
    max_response_bytes: usize,
}

impl ExchangeBinding {
    /// The cache key of this binding's cell for `scope`: SHA-256 over the binding's own key and the
    /// scope, so two scopes never share a token and two bindings never share a scope's.
    pub fn scope_key(&self, scope: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.key);
        h.update([0]);
        h.update(scope.as_bytes());
        h.finalize().into()
    }

    /// The cell for `scope` in `cache` (made, unminted, when absent).
    pub fn cell(&self, scope: &str, cache: &dyn TokenCache) -> ([u8; 32], Arc<Minted>) {
        let key = self.scope_key(scope);
        let minter = Minter::TokenExchange(mint::token_exchange::Scoped::new(
            Arc::clone(&self.exchange),
            scope,
        ));
        (key, cache.cell(key, minter, self.max_response_bytes))
    }
}

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

/// Bind `style` to `credential` under `settings`, whichever this plugin serves — `open_outbound`'s
/// body. Never touches the network.
///
/// # Errors
///
/// Every finding that refuses the binding.
pub fn open(
    style: &str,
    credential: Option<&[u8]>,
    settings: Option<&[u8]>,
    cache: &dyn TokenCache,
) -> Result<Binding, Vec<Refusal>> {
    if style == OAUTH_TOKEN_EXCHANGE {
        return open_token_exchange(credential, settings).map(|b| Binding::Exchange(Arc::new(b)));
    }
    open_binding(style, credential, settings, cache).map(Binding::Minted)
}

/// `oauth-token-exchange`: the keyless contradiction (the credential IS the subject token), then
/// `token_url` and `resource` (the previous release required both: an exchange with no RFC 8707
/// resource indicator mints a token spendable at any backend the authorization server serves), then
/// the binding. `subject_token_type` defaults to an access token.
fn open_token_exchange(
    credential: Option<&[u8]>,
    settings: Option<&[u8]>,
) -> Result<ExchangeBinding, Vec<Refusal>> {
    let m = object(settings).map_err(|r| vec![r])?;
    let subject = match credential.map(std::str::from_utf8) {
        None => None,
        Some(Ok(s)) => Some(s),
        Some(Err(_)) => {
            return Err(vec![Refusal::Credential(
                "the credential is not UTF-8".to_string(),
            )])
        }
    };
    let mut refusals = Vec::new();
    if subject.is_none_or(|s| s.trim().is_empty()) {
        refusals.push(Refusal::Settings(
            "uses auth: oauth-token-exchange but declares no credential; that grant exchanges \
             busbar's own subject token (the credential) for the upstream's, so there is nothing to \
             exchange"
                .to_string(),
        ));
    }
    let token_url = text(&m, "token_url").map_err(|r| vec![r])?;
    if token_url.is_none() {
        refusals.push(Refusal::Settings(
            "uses auth: oauth-token-exchange but has no `token_url` (the authorization server's \
             token endpoint busbar's subject token is exchanged at)"
                .to_string(),
        ));
    }
    let resource = text(&m, "resource").map_err(|r| vec![r])?;
    if resource.is_none() {
        refusals.push(Refusal::Settings(
            "uses auth: oauth-token-exchange but has no `resource` — the RFC 8707 resource \
             indicator the exchanged token is audience-bound to. A token minted for one upstream \
             must not be spendable at another."
                .to_string(),
        ));
    }
    let subject_token_type = text(&m, "subject_token_type")
        .map_err(|r| vec![r])?
        .unwrap_or_else(|| mint::token_exchange::ACCESS_TOKEN_TYPE.to_string());
    let max = max_response_bytes(&m).map_err(|r| vec![r])?;
    let (Some(subject), Some(token_url), Some(resource), true) =
        (subject, token_url, resource, refusals.is_empty())
    else {
        return Err(refusals);
    };
    let key = cache_key(
        OAUTH_TOKEN_EXCHANGE,
        credential.unwrap_or_default(),
        settings.unwrap_or_default(),
    );
    Ok(ExchangeBinding {
        exchange: Arc::new(mint::token_exchange::build(
            subject,
            &token_url,
            &subject_token_type,
            &resource,
        )),
        key,
        max_response_bytes: max,
    })
}

/// Bind `style` to `credential` under `settings` — `open_outbound`'s body for a minted style.
/// Never touches the network: a minted style's first mint runs on `tick`.
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
