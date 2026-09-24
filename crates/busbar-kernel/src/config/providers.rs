// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plane's config-section SHAPES, housed in the neutral substrate for now (slated to move to the
//! owning plane crate) and carried as opaque serde data the substrate never interprets: the catalog
//! definition (`ProviderDef`, from providers.yaml), the operator deployment (`ProviderDeploy`, from
//! config.yaml), the resolved section the runtime reads (`ProviderCfg`) and the active-health block.
//! The catalog/deployment MERGE that produces a `ProviderCfg` stays in busbar-core's `resolve`,
//! which re-exports every item here at its historical `config::` path.
//!
//! `ModelCfg` (the per-entry config) is NOT defined here any more — it moved to `busbar-contract`
//! (DECISIONS #40/#38) because a plugin crate (`busbar-plane-decision`) reuses it verbatim for its
//! own `decisions.models.<name>` and a plugin's whole dependency closure must be `busbar-contract`
//! alone. It is re-exported below at its historical path.

use std::collections::HashMap;

use serde::Deserialize;

use busbar_api::SecretRef;

use super::ProviderAuth;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)] // a typo'd provider key must fail boot, not be silently ignored.
pub struct ProviderCfg {
    #[serde(default = "default_protocol")]
    pub protocol: String,
    pub base_url: String,
    /// The provider credential as a SECRET REFERENCE - `{ env: VAR }`, `{ file: … }`, or a
    /// secret module. Resolved once at startup; the resolved value never appears in config or logs.
    pub api_key: SecretRef,
    /// Active health-probe settings for this provider's lanes (mode + interval + timeout).
    #[serde(default)]
    pub health: Option<HealthCfg>,
    // error_map is REQUIRED on every provider — NO default (fail loud if missing)
    pub error_map: HashMap<String, String>,
    /// Optional upstream request-path override (see ProviderDef::path).
    #[serde(default)]
    pub path: Option<String>,
    /// Optional path-BASE override (see ProviderDef::path_base) — replaces a URL-model protocol's
    /// hardcoded base segment so the per-request `/{model}:verb` suffix is appended to it (Vertex AI).
    #[serde(default)]
    pub path_base: Option<String>,
    /// OAuth token endpoint for `auth: oauth-client-credentials` (see ProviderDef::token_url).
    #[serde(default)]
    pub token_url: Option<String>,
    /// OAuth scope for `auth: oauth-client-credentials` (see ProviderDef::scope).
    #[serde(default)]
    pub scope: Option<String>,
    /// JWT-bearer assertion `sub` (subject) claim for `auth: jwt-bearer` (see ProviderDef::subject).
    #[serde(default)]
    pub subject: Option<String>,
    /// Optional auth-style override (see ProviderDef::auth).
    #[serde(default)]
    pub auth: Option<ProviderAuth>,
    /// Per-provider SURGICAL escape hatch: the cloud-metadata hosts/IPs to UNBLOCK for THIS
    /// provider's `base_url` (and path-override composition) only. Each entry carves a single
    /// exception out of the metadata denylist (hardcoded ∪ `security.blocked_metadata_hosts`) — e.g.
    /// `allow_metadata_hosts: ["169.254.169.254"]` lets only this provider reach IMDS while every
    /// OTHER metadata endpoint (and every other provider) stays blocked. An entry is matched with the
    /// SAME canonicalization as the block check, so an IP entry also unblocks its obfuscated spellings
    /// (decimal-int, IPv4-mapped IPv6, trailing-dot). For an everywhere-unblock use
    /// `security.allow_metadata_hosts`; for a full disable use `security.allow_all_metadata`.
    /// Loopback / RFC-1918 / CGNAT / public targets are allowed regardless — a client never chooses a
    /// provider URL (model NAME → operator pool → operator URL), so private upstreams pose no
    /// client-driven SSRF and local models (Ollama / vLLM) "just work" with no entry. Default empty
    /// (all metadata blocked).
    #[serde(default)]
    pub allow_metadata_hosts: Vec<String>,
}

/// Default provider protocol when not specified. Wire-contract: providers.yaml catalog entries
/// and un-overridden deployments use this protocol for the dispatch registry lookup. This is the
/// FROZEN config-grammar default for an omitted `protocol:` — independent of which dialects are
/// compiled in (a build with every LLM dialect deleted still parses providers.yaml against it), so it
/// cannot be read off the (possibly-empty) protocol registry and is named as a frozen-wire literal.
// plane-purity: frozen-wire the omitted-`protocol:` default in the frozen providers.yaml config grammar (frozen since 1.5.3)
pub const DEFAULT_PROTOCOL: &str = "anthropic";

/// The serde default for an omitted `protocol:` — see [`DEFAULT_PROTOCOL`].
pub fn default_protocol() -> String {
    DEFAULT_PROTOCOL.to_string()
}

/// Active health-probe mode for a provider's lanes.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum HealthMode {
    /// No active probing. Health is inferred purely from organic traffic (the breaker trips on
    /// real failures and recovers via the half-open probe). This is the default.
    #[default]
    None,
    /// Periodically re-probe ONLY lanes that are currently tripped (Open/HalfOpen), so a recovered
    /// upstream is picked back up promptly instead of waiting for organic traffic to probe it.
    Dead,
    /// Periodically probe EVERY lane, so a silently-dead upstream is tripped out before real
    /// traffic hits it. Sends a tiny billable request per interval — opt-in.
    Active,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HealthCfg {
    /// Probing strategy (see `HealthMode`). Defaults to `none` — a `health:` block with only an
    /// interval does nothing until a mode is chosen.
    #[serde(default)]
    pub mode: HealthMode,
    /// Seconds between probes for this provider's lanes (default 30, floored at 1).
    #[serde(default)]
    pub interval_secs: Option<u64>,
    /// Per-probe request timeout in seconds (default 5, floored at 1).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

// `ModelCfg` (and its `neg1` default fn) moved to `busbar-contract` (DECISIONS #40/#38): it is the
// per-entry shape BOTH `pools.models.<name>` (this crate) and `decisions.models.<name>`
// (`busbar-plane-decision`, a plugin crate whose entire dependency closure must be `busbar-contract`
// alone) deserialize into, so a plugin naming it must not also be naming the kernel. Moved VERBATIM
// — same field names, order, types and serde attributes, so no config key and no wire byte changed
// — and re-exported here at its historical `config::providers::ModelCfg` path (and, transitively,
// `config::ModelCfg` via this module's own re-export in `config/mod.rs`) so every existing
// kernel-side caller keeps compiling unchanged. See `busbar_contract::config`'s own module doc.
pub use busbar_contract::config::{neg1, ModelCfg};

/// Provider definition - vetted knowledge shipped in providers.yaml (no keys).
#[derive(Debug, Deserialize, Clone)]
pub struct ProviderDef {
    pub protocol: String,
    pub base_url: String,
    #[serde(default)]
    pub error_map: HashMap<String, String>,
    #[serde(default)]
    pub health: Option<HealthCfg>,
    /// Optional override of the upstream request path appended to `base_url`. Defaults to the
    /// protocol's standard path. Use it for OpenAI-compatible providers that embed the API version
    /// in `base_url` and serve `/chat/completions` (no `/v1`), e.g. `base_url: .../api/paas/v4` +
    /// `path: /chat/completions`.
    #[serde(default)]
    pub path: Option<String>,
    /// Optional path-BASE override for URL-model protocols (Gemini): replaces the protocol's
    /// hardcoded base segment (`/v1beta/models`) so the per-request `/{model}:verb` suffix is appended
    /// to a different layout. Unlike `path` (a static full path that ignores the model), `path_base`
    /// keeps the model in the URL — e.g. Vertex AI: `path_base:
    /// /v1/projects/{project}/locations/{location}/publishers/google/models`.
    #[serde(default)]
    pub path_base: Option<String>,
    /// OAuth token endpoint for `auth: oauth-client-credentials` — the URL busbar POSTs the client
    /// credentials to for a bearer. Required for that auth style; ignored otherwise. E.g. Azure Entra:
    /// `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`.
    #[serde(default)]
    pub token_url: Option<String>,
    /// OAuth scope for `auth: oauth-client-credentials`. Required for that auth style; ignored
    /// otherwise. E.g. Azure OpenAI: `https://cognitiveservices.azure.com/.default`.
    #[serde(default)]
    pub scope: Option<String>,
    /// JWT-bearer assertion `sub` (subject) claim for `auth: jwt-bearer` (RFC 7523 §3). Optional and
    /// UNSET by default — omitted entirely, not merely empty. Google's own client libraries
    /// (`google-auth-python` et al.) only emit `sub` when a subject/impersonation is explicitly
    /// configured, because for a Google service account the mere PRESENCE of `sub` switches the grant
    /// into domain-wide-delegation/impersonation semantics regardless of its value — so this must stay
    /// opt-in, never defaulted to `iss`, or every plain (non-delegated) service account (e.g. the
    /// shipped Vertex AI setup) starts failing `unauthorized_client`/`invalid_grant`. Set this only when
    /// impersonating a specific principal (Google domain-wide delegation) or when a non-Google IdP's
    /// jwt-bearer profile requires `sub`. Ignored for every other auth style.
    #[serde(default)]
    pub subject: Option<String>,
    /// Optional auth-style override. Defaults to the protocol's native auth (bearer for
    /// openai/anthropic/responses, `x-goog-api-key` for gemini, SigV4 for bedrock). Set to
    /// `api-key` for backends that authenticate with an `api-key: <key>` header instead of a
    /// bearer token — e.g. Azure OpenAI (which also carries `?api-version=` and the deployment in
    /// its `path`). Recognized values: `bearer` (default) | `api-key`.
    #[serde(default)]
    pub auth: Option<ProviderAuth>,
    /// Catalog default for the per-provider metadata allow-override (see
    /// `ProviderCfg::allow_metadata_hosts`). A deployment's `allow_metadata_hosts` (`Some`) replaces
    /// this; `None` falls back to the catalog list. Default empty (all metadata blocked).
    #[serde(default)]
    pub allow_metadata_hosts: Vec<String>,
}

/// Provider deployment - operator config in config.yaml (names provider + supplies key).
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProviderDeploy {
    /// The provider credential as a SECRET REFERENCE. Replaces the removed `api_key_env:`
    /// (`api_key_env: VAR` becomes `api_key: { env: VAR }`).
    pub api_key: SecretRef,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub error_map: Option<HashMap<String, String>>,
    /// Optional upstream request-path override (see ProviderDef::path).
    #[serde(default)]
    pub path: Option<String>,
    /// Optional path-BASE override (see ProviderDef::path_base) — replaces a URL-model protocol's
    /// hardcoded base segment so the per-request `/{model}:verb` suffix is appended to it (Vertex AI).
    #[serde(default)]
    pub path_base: Option<String>,
    /// OAuth token endpoint for `auth: oauth-client-credentials` (see ProviderDef::token_url).
    #[serde(default)]
    pub token_url: Option<String>,
    /// OAuth scope for `auth: oauth-client-credentials` (see ProviderDef::scope).
    #[serde(default)]
    pub scope: Option<String>,
    /// JWT-bearer assertion `sub` claim for `auth: jwt-bearer` (see ProviderDef::subject). Opt-in;
    /// unset (the default) means no `sub` claim, unchanged from before this field existed.
    #[serde(default)]
    pub subject: Option<String>,
    /// Optional auth-style override (see ProviderDef::auth).
    #[serde(default)]
    pub auth: Option<ProviderAuth>,
    /// Per-provider metadata allow-override (see `ProviderCfg::allow_metadata_hosts`). `Some` REPLACES
    /// the catalog default; `None` falls back to the catalog's `allow_metadata_hosts`.
    #[serde(default)]
    pub allow_metadata_hosts: Option<Vec<String>>,
    /// Optional active health-probe settings (see ProviderDef::health). Overrides the catalog's
    /// `health` when set; this is the block the shipped `config.yaml` documents under a provider.
    #[serde(default)]
    pub health: Option<HealthCfg>,
}
