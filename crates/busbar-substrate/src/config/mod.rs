// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral LLM-RUNTIME config VALUE enums a plane crate (`busbar-llm`) names via the ABI
//! instead of reaching back into `busbar_core::config::`.
//!
//! ABI-purity CONFIG-ENUMS: `PolicyOnError` (the resolved on_error/on_empty terminal) and
//! `ProviderAuth` (the per-provider auth-style selector) are LLM-runtime concepts that sat in the
//! core config grammar. They are fieldless serde enums — no reach into any core type — so they move
//! DOWN here WITH their `#[derive(Serialize/Deserialize)]` + `#[serde(...)]` attrs VERBATIM (the
//! serialized/deserialized wire form is byte-identical). Core re-exports each from its historical
//! `busbar_core::config::` path so the frozen config-grammar call sites and every deserialization
//! are unchanged.

use serde::{Deserialize, Serialize};

/// A resolved on_error/on_empty TERMINAL. `Weighted` (default) is the non-negotiable safety
/// stance: a broken/slow policy is indistinguishable from no policy and NEVER blocks or fails a
/// request. `Reject` is fail-closed (503). `First` uses the configured member order (a
/// deterministic degraded pick). The `on_error` CONFIG field is a free string (a fallback chain of
/// hook names bottoming out on one of these three reserved terminals); `on_empty` parses this enum
/// directly.
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOnError {
    #[default]
    Weighted,
    Reject,
    First,
}

/// Per-provider auth-style override. Closed set: the request is signed with the protocol's native
/// auth (`bearer`) unless `api-key` selects an `api-key: <key>` header (Azure OpenAI). The wire
/// strings are unchanged from the pre-enum `Option<String>` field (`bearer` / `api-key`), so an
/// unknown spelling is now a deserialize error instead of a hand-checked validation error.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAuth {
    #[serde(rename = "bearer")]
    Bearer,
    #[serde(rename = "api-key")]
    ApiKey,
    /// OAuth 2.0 JWT-bearer grant (RFC 7523): the provider's credential is a signing key (delivered as
    /// a Google service-account JSON in `api_key_env`), which busbar uses to mint + auto-refresh a
    /// short-lived bearer token per lane. Generic — Vertex AI is the first provider to select it. The
    /// token minting/refresh lives in `crate::egress_auth::jwt_bearer`; this is only the selector.
    #[serde(rename = "jwt-bearer")]
    JwtBearer,
    /// OAuth 2.0 client-credentials grant (RFC 6749 §4.4): `api_key_env` carries
    /// `client_id:client_secret`, and the provider's `token_url` + `scope` complete the exchange for
    /// an auto-refreshed bearer. Generic — Azure OpenAI via Microsoft Entra ID is the first consumer.
    /// The token minting/refresh lives in `crate::egress_auth::oauth_client_credentials`.
    #[serde(rename = "oauth-client-credentials")]
    OAuthClientCredentials,
}
