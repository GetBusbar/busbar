// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `providers:` config SHAPES — an upstream catalog's vocabulary: the catalog definition
//! (`ProviderDef`, from providers.yaml), the operator deployment (`ProviderDeploy`, from
//! config.yaml), the frozen whole-entry parse shape (`ProviderCfg`), the active-health block and the
//! per-provider auth-style selector (`ProviderAuth`); and the RESOLVED provider the runtime reads
//! ([`ResolvedProvider`]), which is not config grammar. The kernel parses the section into these and
//! merges each catalog entry with its deployment (`resolve`); the lane-capability keys they carry
//! are [`crate::ir::lane_caps`]'s.
//!
//! THE SPLIT (row 155 B1; BUSBAR-1.6.0.md #49, THE DESIGN §4 "its `api_key`, `auth`, `token_url`,
//! `scope` and `subject` bind the auth object (§6); its dialect fields go to the planes that use the
//! provider"). A resolved provider carries the keys the KERNEL owns typed ([`CORE_PROVIDER_KEYS`]:
//! the destination, the credential and its auth binding, the health probe and the metadata
//! carve-outs) and every other key of the entry as an OPAQUE [`ProviderTable`] the kernel carries,
//! merges by one neutral rule ([`merge_tables`]) and hands to the plane. The kernel names none of
//! the table's keys.
//!
//! Moved VERBATIM back from `busbar-substrate-values` when that crate was deleted (#83a SD-8): same
//! type names, field names, order, types and serde attributes, so every parse, every refusal text and
//! the config-schema snapshot are byte-identical.
//!
//! `ModelCfg` (the per-entry config) lives in `busbar-contract` (DECISIONS #40/#38) because a
//! plugin crate (`busbar-plane-decisions`) reuses it verbatim for its own `decisions.models.<name>`;
//! it is re-exported below at its historical path.
//!
//! This file is config grammar: the config-schema gate tracks it, so every `Deserialize` shape below
//! is frozen additive-only.

pub use busbar_contract::config::{neg1, ModelCfg};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use busbar_contract::secret_ref::SecretRef;

use crate::ir::lane_caps::{MaxOutputKeyCfg, ModelCapabilities};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)] // a typo'd provider key must fail boot, not be silently ignored.
pub struct ProviderCfg {
    /// The dialect the provider speaks, as the catalog (or a deployment override) names it, carried
    /// as an opaque word. The kernel supplies no dialect of its own (BUSBAR-1.6.0.md #49: the kernel
    /// contains zero transport-protocol literals), so an omitted key here is EMPTY. A resolved
    /// provider always carries one, because the catalog's `ProviderDef::protocol` is required; the
    /// default for a key omitted elsewhere is the speaking plane's own.
    #[serde(default)]
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
    /// The tenant the upstream bills this provider's traffic to (OpenAI family: `organization`
    /// and `project`), set on every upstream request from this config and never from the caller.
    /// Absent: none is sent.
    #[serde(default)]
    pub organization: Option<String>,
    /// See `organization`.
    #[serde(default)]
    pub project: Option<String>,
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
    /// The key this provider's upstream expects a CROSS-PROTOCOL output-token cap under, for the
    /// dialect with two spellings (OpenAI Chat Completions: `max_tokens` | `max_completion_tokens`).
    /// Omitted = `max_tokens`, what 1.5.5 wrote and what every OpenAI-compatible host accepts; set
    /// `max_completion_tokens` for OpenAI's own API (its o-series / gpt-5 models reject `max_tokens`).
    pub max_output_key: Option<MaxOutputKeyCfg>,
    /// The upstream accepts Anthropic ADAPTIVE thinking (`thinking:{type:"adaptive"}` +
    /// `output_config.effort`). Omitted = false: a reasoning ask is written as
    /// `thinking.budget_tokens`, the form every other Claude model accepts.
    pub anthropic_adaptive_thinking: Option<bool>,
    /// The upstream accepts NATIVE structured outputs (`output_config.format`). Omitted = false: a
    /// structured-output directive takes the dialect's pre-capability form (a forced tool).
    pub native_structured_output: Option<bool>,
    /// Per-MODEL overrides of the three capabilities above, for a provider that serves models of
    /// several generations: the FIRST rule whose `models` glob list matches the lane's wire model
    /// sets every capability it names. Evaluated after the provider-level values.
    #[serde(default)]
    pub model_capabilities: Vec<ModelCapabilities>,
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

/// Active health-probe mode for a provider's lanes.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default)]
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

#[derive(Debug, Deserialize, Serialize, Clone)]
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

/// Provider definition - vetted knowledge shipped in providers.yaml (no keys).
#[derive(Debug, Deserialize, Serialize, Clone)]
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
    /// The tenant the upstream bills this provider's traffic to (OpenAI family: `organization`
    /// and `project`), set on every upstream request from this config and never from the caller.
    /// Absent: none is sent.
    #[serde(default)]
    pub organization: Option<String>,
    /// See `organization`.
    #[serde(default)]
    pub project: Option<String>,
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
    /// The key this provider's upstream expects a CROSS-PROTOCOL output-token cap under, for the
    /// dialect with two spellings (OpenAI Chat Completions: `max_tokens` | `max_completion_tokens`).
    /// Omitted = `max_tokens`, what 1.5.5 wrote and what every OpenAI-compatible host accepts; set
    /// `max_completion_tokens` for OpenAI's own API (its o-series / gpt-5 models reject `max_tokens`).
    pub max_output_key: Option<MaxOutputKeyCfg>,
    /// The upstream accepts Anthropic ADAPTIVE thinking (`thinking:{type:"adaptive"}` +
    /// `output_config.effort`). Omitted = false: a reasoning ask is written as
    /// `thinking.budget_tokens`, the form every other Claude model accepts.
    pub anthropic_adaptive_thinking: Option<bool>,
    /// The upstream accepts NATIVE structured outputs (`output_config.format`). Omitted = false: a
    /// structured-output directive takes the dialect's pre-capability form (a forced tool).
    pub native_structured_output: Option<bool>,
    /// Per-MODEL overrides of the three capabilities above, for a provider that serves models of
    /// several generations: the FIRST rule whose `models` glob list matches the lane's wire model
    /// sets every capability it names. Evaluated after the provider-level values.
    #[serde(default)]
    pub model_capabilities: Vec<ModelCapabilities>,
    /// Catalog default for the per-provider metadata allow-override (see
    /// `ProviderCfg::allow_metadata_hosts`). A deployment's `allow_metadata_hosts` (`Some`) replaces
    /// this; `None` falls back to the catalog list. Default empty (all metadata blocked).
    #[serde(default)]
    pub allow_metadata_hosts: Vec<String>,
}

/// Provider deployment - operator config in config.yaml (names provider + supplies key).
#[derive(Debug, Deserialize, Serialize, Clone)]
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
    /// The tenant the upstream bills this provider's traffic to (OpenAI family: `organization`
    /// and `project`), set on every upstream request from this config and never from the caller.
    /// Absent: none is sent.
    #[serde(default)]
    pub organization: Option<String>,
    /// See `organization`.
    #[serde(default)]
    pub project: Option<String>,
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
    /// The key this provider's upstream expects a CROSS-PROTOCOL output-token cap under, for the
    /// dialect with two spellings (OpenAI Chat Completions: `max_tokens` | `max_completion_tokens`).
    /// Omitted = `max_tokens`, what 1.5.5 wrote and what every OpenAI-compatible host accepts; set
    /// `max_completion_tokens` for OpenAI's own API (its o-series / gpt-5 models reject `max_tokens`).
    pub max_output_key: Option<MaxOutputKeyCfg>,
    /// The upstream accepts Anthropic ADAPTIVE thinking (`thinking:{type:"adaptive"}` +
    /// `output_config.effort`). Omitted = false: a reasoning ask is written as
    /// `thinking.budget_tokens`, the form every other Claude model accepts.
    pub anthropic_adaptive_thinking: Option<bool>,
    /// The upstream accepts NATIVE structured outputs (`output_config.format`). Omitted = false: a
    /// structured-output directive takes the dialect's pre-capability form (a forced tool).
    pub native_structured_output: Option<bool>,
    /// Per-MODEL overrides of the three capabilities above, for a provider that serves models of
    /// several generations: the FIRST rule whose `models` glob list matches the lane's wire model
    /// sets every capability it names. Evaluated after the provider-level values. `Some` REPLACES the
    /// catalog list; each provider-level value above overrides the catalog's when set.
    pub model_capabilities: Option<Vec<ModelCapabilities>>,
    /// Per-provider metadata allow-override (see `ProviderCfg::allow_metadata_hosts`). `Some` REPLACES
    /// the catalog default; `None` falls back to the catalog's `allow_metadata_hosts`.
    #[serde(default)]
    pub allow_metadata_hosts: Option<Vec<String>>,
    /// Optional active health-probe settings (see ProviderDef::health). Overrides the catalog's
    /// `health` when set; this is the block the shipped `config.yaml` documents under a provider.
    #[serde(default)]
    pub health: Option<HealthCfg>,
}

/// Per-provider auth-style override. Closed set: the request is signed with the protocol's native
/// auth (`bearer`) unless `api-key` selects an `api-key: <key>` header (Azure OpenAI). The wire
/// strings are unchanged from the pre-enum `Option<String>` field (`bearer` / `api-key`), so an
/// unknown spelling is now a deserialize error instead of a hand-checked validation error.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAuth {
    #[serde(rename = "bearer")]
    Bearer,
    #[serde(rename = "api-key")]
    ApiKey,
    /// OAuth 2.0 JWT-bearer grant (RFC 7523): the provider's credential is a signing key (delivered as
    /// a Google service-account JSON in `api_key_env`), which busbar uses to mint + auto-refresh a
    /// short-lived bearer token per lane. Generic — Vertex AI is the first provider to select it. The
    /// token minting/refresh lives in the auth plugin serving the `jwt-bearer` style; this is only
    /// the selector.
    #[serde(rename = "jwt-bearer")]
    JwtBearer,
    /// OAuth 2.0 client-credentials grant (RFC 6749 §4.4): `api_key_env` carries
    /// `client_id:client_secret`, and the provider's `token_url` + `scope` complete the exchange for
    /// an auto-refreshed bearer. Generic — Azure OpenAI via Microsoft Entra ID is the first consumer.
    /// The token minting/refresh lives in the auth plugin serving the `oauth-client-credentials`
    /// style.
    #[serde(rename = "oauth-client-credentials")]
    OAuthClientCredentials,
}

// ── the resolved provider ─────────────────────────────────────────────────────────────────────────

/// THE PLANE-SHAPED KEYS OF ONE PROVIDER ENTRY, as written (catalog-merged), carried unread: every
/// key of the entry that is not one of [`CORE_PROVIDER_KEYS`]. The kernel holds it as data, merges it
/// by [`merge_tables`] and hands it to the plane that speaks the provider, which parses it (THE
/// DESIGN §4: "A plane receives, at open, the dialect fields of the providers it references and
/// resolves model -> dialect itself").
pub type ProviderTable = serde_json::Map<String, Value>;

/// THE KEYS OF A PROVIDER ENTRY THE KERNEL OWNS (row 155 B1 split, ARCHITECT ruling): the
/// destination it dials and guards (`base_url`, and the `path` / `path_base` composed onto it,
/// re-judged against the metadata denylist at boot as 1.5.5's `config_validate` did at :406/:430),
/// the credential and its outbound-auth binding (`api_key`, `auth`, `token_url`, `scope`,
/// `subject`; THE DESIGN §6), the health probe (`health`) and the metadata carve-outs
/// (`allow_metadata_hosts`). Everything else is the plane's ([`ProviderTable`]).
pub const CORE_PROVIDER_KEYS: &[&str] = &[
    "api_key",
    "base_url",
    "path",
    "path_base",
    "token_url",
    "scope",
    "subject",
    "auth",
    "allow_metadata_hosts",
    "health",
];

/// ONE RESOLVED PROVIDER: its catalog definition merged with its deployment. The kernel-owned keys
/// typed, the rest an opaque [`ProviderTable`]. Not config grammar (it is never parsed), so it is not
/// in the config-schema fingerprint; the grammar is [`ProviderDef`] / [`ProviderDeploy`].
#[derive(Debug, Clone)]
pub struct ResolvedProvider {
    /// The upstream base URL (the destination core dials and guards).
    pub base_url: String,
    /// The provider credential as a SECRET REFERENCE, resolved core-side and never handed to a plane.
    pub api_key: SecretRef,
    /// Active health-probe settings for this provider's lanes.
    pub health: Option<HealthCfg>,
    /// The request-path override composed onto `base_url` (a destination fact).
    pub path: Option<String>,
    /// The path-BASE override composed onto `base_url` (a destination fact).
    pub path_base: Option<String>,
    /// The token endpoint of the client-credentials auth style (see [`ProviderDef::token_url`]).
    pub token_url: Option<String>,
    /// The scope of the client-credentials auth style (see [`ProviderDef::scope`]).
    pub scope: Option<String>,
    /// JWT-bearer assertion `sub` claim for `auth: jwt-bearer`.
    pub subject: Option<String>,
    /// The auth-style override.
    pub auth: Option<ProviderAuth>,
    /// The per-provider metadata allow-override (see `ProviderCfg::allow_metadata_hosts`).
    pub allow_metadata_hosts: Vec<String>,
    /// Every other key of the entry, unread.
    pub table: ProviderTable,
}

/// The [`ProviderTable`] of one parsed entry: the entry as written, less [`CORE_PROVIDER_KEYS`] and
/// less every key it left unset (an absent key and an unset optional one are the same thing to the
/// plane that reads the table).
pub fn plane_table<T: Serialize>(entry: &T) -> ProviderTable {
    let Ok(Value::Object(mut table)) = serde_json::to_value(entry) else {
        return ProviderTable::new();
    };
    for key in CORE_PROVIDER_KEYS {
        table.remove(*key);
    }
    drop_unset(&mut table);
    table
}

/// Remove every `null` member, at every depth: an unset optional key is an absent one.
fn drop_unset(table: &mut ProviderTable) {
    table.retain(|_, v| !v.is_null());
    for value in table.values_mut() {
        match value {
            Value::Object(inner) => drop_unset(inner),
            Value::Array(items) => {
                for item in items {
                    if let Value::Object(inner) = item {
                        drop_unset(inner);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Whether `value` is a STRING MAP: an object every member of which is a string.
fn is_str_map(value: &ProviderTable) -> bool {
    value.values().all(Value::is_string)
}

/// THE NEUTRAL MERGE of a catalog entry's table with its deployment's (ARCHITECT ruling, row 155
/// B1b): a key the deployment sets wins; where both sides hold a STRING MAP the two merge member by
/// member, the deployment's member winning; every other value is REPLACED whole. This is the
/// previous release's merge, stated without naming a key: its one map-valued key (the upstream
/// error map) unioned with the deployment's entries winning, and every other key was a deployment
/// override of the catalog default (a list of rules is replaced, not appended).
#[must_use]
pub fn merge_tables(mut catalog: ProviderTable, deployment: ProviderTable) -> ProviderTable {
    for (key, value) in deployment {
        if let (Some(Value::Object(have)), Value::Object(over)) = (catalog.get_mut(&key), &value) {
            if is_str_map(have) && is_str_map(over) {
                for (member, v) in over {
                    have.insert(member.clone(), v.clone());
                }
                continue;
            }
        }
        catalog.insert(key, value);
    }
    catalog
}

/// The key of the table a plane's dialect word is read under, while the kernel still reads it
/// (TRANSITIONAL, below): the contract's neutral model-entry key, not a kernel spelling.
fn dialect_key() -> &'static str {
    busbar_contract::section::MODEL_PROTOCOL_KEYS[0]
}

/// The key of the table the upstream error map is read under, while the kernel still reads it
/// (TRANSITIONAL, below).
const ERROR_MAP_KEY: &str = "error_map";

impl ResolvedProvider {
    /// The resolved provider of one catalog definition and its deployment: each kernel-owned key the
    /// deployment sets wins over the catalog default (1.5.5's merge), and the two tables merge by
    /// [`merge_tables`].
    #[must_use]
    pub fn merge(def: &ProviderDef, deploy: &ProviderDeploy) -> Self {
        Self {
            base_url: deploy
                .base_url
                .clone()
                .unwrap_or_else(|| def.base_url.clone()),
            api_key: deploy.api_key.clone(),
            // Deployment health config wins over the catalog default (mirrors path/auth), so the
            // `health:` block documented in config.yaml actually takes effect.
            health: deploy.health.clone().or_else(|| def.health.clone()),
            path: deploy.path.clone().or_else(|| def.path.clone()),
            path_base: deploy.path_base.clone().or_else(|| def.path_base.clone()),
            token_url: deploy.token_url.clone().or_else(|| def.token_url.clone()),
            scope: deploy.scope.clone().or_else(|| def.scope.clone()),
            subject: deploy.subject.clone().or_else(|| def.subject.clone()),
            auth: deploy.auth.or(def.auth),
            // A deployment list (`Some`) replaces the catalog default.
            allow_metadata_hosts: deploy
                .allow_metadata_hosts
                .clone()
                .unwrap_or_else(|| def.allow_metadata_hosts.clone()),
            table: merge_tables(plane_table(def), plane_table(deploy)),
        }
    }

    /// TRANSITIONAL (row 155 B1b; drains at B1c, where the plane states its provider keys through
    /// its Statement and answers the checks that read this word at their points): the dialect word
    /// the table carries, or empty. Read only by the provider checks that still run kernel-side.
    #[must_use]
    pub fn dialect(&self) -> &str {
        self.table
            .get(dialect_key())
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    /// TRANSITIONAL (row 155 B1b; drains at B1c, as [`Self::dialect`]): the upstream error map the
    /// table carries, `(code, class)` in the table's order; empty when it carries none.
    pub fn error_map(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.table
            .get(ERROR_MAP_KEY)
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|m| m.iter())
            .filter_map(|(code, class)| Some((code.as_str(), class.as_str()?)))
    }
}

/// A whole-entry parse ([`ProviderCfg`]) as a resolved provider: the kernel-owned keys moved, the
/// rest the table.
impl From<ProviderCfg> for ResolvedProvider {
    fn from(p: ProviderCfg) -> Self {
        let table = plane_table(&p);
        Self {
            base_url: p.base_url,
            api_key: p.api_key,
            health: p.health,
            path: p.path,
            path_base: p.path_base,
            token_url: p.token_url,
            scope: p.scope,
            subject: p.subject,
            auth: p.auth,
            allow_metadata_hosts: p.allow_metadata_hosts,
            table,
        }
    }
}
