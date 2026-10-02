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
use busbar_kernel::egress::engine::{send_bounded, EngineClient};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use std::time::Duration;

use busbar_plane_streaming::broker::{
    clamped_ttl_secs, mint_request_body, read_minted, CLIENT_SECRETS_PATH, SAFETY_IDENTIFIER_HEADER,
};

/// The bound on the whole mint exchange up to the response head plus its small body read.
const MINT_DEADLINE: Duration = Duration::from_secs(30);

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
    /// desired secret lifetime (`None` ⇒ [`busbar_plane_streaming::broker::DEFAULT_TTL_SECS`]),
    /// clamped to the accepted window on mint.
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
        clamped_ttl_secs(self.requested_ttl_secs)
    }
}

#[async_trait]
impl TokenMinter for HttpsTokenMinter {
    async fn mint(&self, config: &SessionConfig) -> Result<EphemeralToken, MintError> {
        let ttl_secs = self.clamped_ttl_secs();
        let body_bytes = mint_request_body(ttl_secs, config).map_err(MintError::Provider)?;

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

        let minted = read_minted(&raw).map_err(MintError::Provider)?;

        Ok(EphemeralToken {
            value: minted.value,
            expires_at_unix: minted.expires_at_unix,
        })
    }
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/minter_https_tests.rs"]
mod minter_https_tests;
