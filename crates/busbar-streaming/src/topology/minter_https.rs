// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONCRETE HTTPS EPHEMERAL-SECRET MINTER for the browser WebRTC sideband.
//!
//! Implements the [`TokenMinter`] port over the substrate egress engine: a one-shot
//! `POST /v1/realtime/client_secrets` carrying the REAL provider key, from which the browser-facing
//! `ek_` client secret is returned. The real key stays server-side — it authenticates only the
//! busbar↔provider hop and never appears in the returned [`EphemeralToken`].
//!
//! The mint stamps two guards the raw token carries no policy for on its own: the requested secret
//! lifetime is clamped to the provider's accepted window, and an `OpenAI-Safety-Identifier` header
//! binds the minted secret to the calling identity so it is attributable and rate-limitable to that
//! caller rather than a shared blob. The returned value is asserted to carry the `ek_` prefix before
//! it is handed back.

use crate::ir::config::SessionConfig;
use crate::topology::webrtc::{EphemeralToken, MintError, TokenMinter};
use async_trait::async_trait;
use busbar_substrate::egress::engine::{send_bounded, EngineClient};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use std::time::Duration;

/// The default requested secret lifetime when the caller pins none.
const DEFAULT_TTL_SECS: u64 = 600;
/// The provider's minimum accepted secret lifetime.
const MIN_TTL_SECS: u64 = 10;
/// The provider's maximum accepted secret lifetime.
const MAX_TTL_SECS: u64 = 7200;
/// The prefix every ephemeral client secret the provider mints carries.
const EK_PREFIX: &str = "ek_";
/// The header binding a minted secret to the caller identity.
const SAFETY_IDENTIFIER_HEADER: &str = "OpenAI-Safety-Identifier";
/// The bound on the whole mint exchange up to the response head plus its small body read.
const MINT_DEADLINE: Duration = Duration::from_secs(30);
/// The client-secrets endpoint path on the provider.
const CLIENT_SECRETS_PATH: &str = "/v1/realtime/client_secrets";

/// MINTS the browser's ephemeral client secret over a real HTTPS call to the provider's
/// client-secrets endpoint, holding the real key server-side.
///
/// The `base_url` + owned [`EngineClient`] are constructor inputs so the composition root binds the
/// production provider origin while a test points them at a loopback server; the same request path
/// runs against both. `safety_identifier` is the caller-identity binding stamped on every mint;
/// `requested_ttl_secs` is the desired secret lifetime before clamping (`None` ⇒ the default).
pub struct HttpsTokenMinter {
    client: EngineClient,
    base_url: String,
    api_key: String,
    safety_identifier: String,
    requested_ttl_secs: Option<u64>,
}

impl HttpsTokenMinter {
    /// Build a minter over an already-assembled egress client. `base_url` is the provider origin
    /// (scheme + authority, e.g. `https://api.openai.com`); `api_key` is the REAL provider key held
    /// server-side; `safety_identifier` is the caller-identity binding; `requested_ttl_secs` is the
    /// desired secret lifetime (`None` ⇒ [`DEFAULT_TTL_SECS`]), clamped to the accepted window on mint.
    pub fn new(
        client: EngineClient,
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        safety_identifier: impl Into<String>,
        requested_ttl_secs: Option<u64>,
    ) -> Self {
        HttpsTokenMinter {
            client,
            base_url: base_url.into(),
            api_key: api_key.into(),
            safety_identifier: safety_identifier.into(),
            requested_ttl_secs,
        }
    }

    /// The requested lifetime clamped to the provider's accepted `[MIN, MAX]` window.
    fn clamped_ttl_secs(&self) -> u64 {
        self.requested_ttl_secs
            .unwrap_or(DEFAULT_TTL_SECS)
            .clamp(MIN_TTL_SECS, MAX_TTL_SECS)
    }
}

/// The provider's client-secret response: the `ek_` value and its absolute expiry in unix seconds.
#[derive(serde::Deserialize)]
struct ClientSecretResponse {
    value: String,
    #[serde(default)]
    expires_at: u64,
}

#[async_trait]
impl TokenMinter for HttpsTokenMinter {
    async fn mint(&self, config: &SessionConfig) -> Result<EphemeralToken, MintError> {
        let ttl_secs = self.clamped_ttl_secs();
        let body = serde_json::json!({
            "expires_after": { "anchor": "created_at", "seconds": ttl_secs },
            "session": config,
        });
        let body_bytes = serde_json::to_vec(&body).map_err(|e| {
            MintError::Provider(format!("mint request body did not serialize: {e}"))
        })?;

        let uri = format!(
            "{}{}",
            self.base_url.trim_end_matches('/'),
            CLIENT_SECRETS_PATH
        );
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(&uri)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(
                http::header::AUTHORIZATION,
                format!("Bearer {}", self.api_key),
            )
            .header(SAFETY_IDENTIFIER_HEADER, &self.safety_identifier)
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|e| MintError::Provider(format!("mint request did not build: {e}")))?;

        let deadline = tokio::time::Instant::now() + MINT_DEADLINE;
        let resp = send_bounded(&self.client, req, deadline)
            .await
            .map_err(|e| MintError::Provider(e.into_cause()))?;

        let status = resp.status();
        let raw = tokio::time::timeout_at(deadline, resp.into_body().collect())
            .await
            .map_err(|_| {
                MintError::Provider(
                    "client-secret response was not read before the deadline".into(),
                )
            })?
            .map_err(|e| MintError::Provider(format!("client-secret response body failed: {e}")))?
            .to_bytes();

        if !status.is_success() {
            return Err(MintError::Provider(format!(
                "client-secret endpoint returned {status}"
            )));
        }

        let parsed: ClientSecretResponse = serde_json::from_slice(&raw).map_err(|e| {
            MintError::Provider(format!("client-secret response did not parse: {e}"))
        })?;

        // The browser-facing invariant: only an `ek_` secret ever leaves this boundary. A response
        // whose value lacks the prefix is refused rather than handed on as if it were a client secret.
        if !parsed.value.starts_with(EK_PREFIX) {
            return Err(MintError::Provider(
                "client-secret response value is not an ek_ ephemeral secret".into(),
            ));
        }

        Ok(EphemeralToken {
            value: parsed.value,
            expires_at_unix: parsed.expires_at,
        })
    }
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/minter_https_tests.rs"]
mod minter_https_tests;
