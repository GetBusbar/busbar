// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub use busbar_contract::config::{neg1, ModelCfg};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use busbar_contract::secret_ref::SecretRef;

use super::provider_grammar::{Form, ValueSeed};

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
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
    /// The provider's options: every key of the entry that is not one of
    /// the keys above, under its far end's own wire name (`OpenAI-Organization`, `api-version`,
    /// ...), carried unread into the plane's table. The plane that speaks the provider's dialect
    /// judges each one against that dialect's list ([`judge_options`]); the kernel names none.
    /// Read by [`deployments`] beside the typed keys, so a typed key's refusal keeps its path and
    /// position.
    #[serde(skip)]
    pub options: ProviderTable,
}

#[derive(Deserialize)]
#[serde(remote = "ProviderCfg", deny_unknown_fields)]
struct ProviderCfgCore {
    #[serde(default)]
    protocol: String,
    base_url: String,
    api_key: SecretRef,
    #[serde(default)]
    health: Option<HealthCfg>,

    error_map: HashMap<String, String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    path_base: Option<String>,
    #[serde(default)]
    token_url: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    auth: Option<ProviderAuth>,
    #[serde(default)]
    allow_metadata_hosts: Vec<String>,
    #[serde(skip)]
    options: ProviderTable,
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

/// Provider definition - vetted knowledge shipped in providers.yaml (no keys). Read by [`catalog`]:
/// its typed keys ([`CATALOG_KEYS`]) here, every other key into [`Self::options`].
#[derive(Serialize, Clone)]
#[serde(deny_unknown_fields)]
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
    /// Optional auth-style override: a style a loaded auth plugin declares ([`ProviderAuth`]).
    /// Omitted, the protocol's native auth.
    #[serde(default)]
    pub auth: Option<ProviderAuth>,
    /// Catalog default for the per-provider metadata allow-override (see
    /// `ProviderCfg::allow_metadata_hosts`). A deployment's `allow_metadata_hosts` (`Some`) replaces
    /// this; `None` falls back to the catalog list. Default empty (all metadata blocked).
    #[serde(default)]
    pub allow_metadata_hosts: Vec<String>,
    /// The entry's OPTIONS: every key that is not one of the keys above, under its far end's own
    /// wire name, judged at resolve by the plane that speaks its dialect;
    /// the catalog follows the `config.yaml` rule (see [`ProviderDeploy::options`]).
    #[serde(skip)]
    pub options: ProviderTable,
}

#[derive(Deserialize)]
#[serde(remote = "ProviderDef", deny_unknown_fields)]
struct ProviderDefCore {
    protocol: String,
    base_url: String,
    #[serde(default)]
    error_map: HashMap<String, String>,
    #[serde(default)]
    health: Option<HealthCfg>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    path_base: Option<String>,
    #[serde(default)]
    token_url: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    auth: Option<ProviderAuth>,
    #[serde(default)]
    allow_metadata_hosts: Vec<String>,
    #[serde(skip)]
    options: ProviderTable,
}

/// Provider deployment - operator config in config.yaml (names provider + supplies key).
#[derive(Serialize, Clone)]
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
    /// The provider's options: every key of the entry that is not one of
    /// the keys above, under its far end's own wire name (`OpenAI-Organization`, `api-version`,
    /// ...), carried unread into the plane's table. The plane that speaks the provider's dialect
    /// judges each one against that dialect's list ([`judge_options`]); the kernel names none.
    /// Read by [`deployments`] beside the typed keys, so a typed key's refusal keeps its path and
    /// position.
    #[serde(skip)]
    pub options: ProviderTable,
}

#[derive(Deserialize)]
#[serde(remote = "ProviderDeploy", deny_unknown_fields)]
struct ProviderDeployCore {
    api_key: SecretRef,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    error_map: Option<HashMap<String, String>>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    path_base: Option<String>,
    #[serde(default)]
    token_url: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    auth: Option<ProviderAuth>,
    #[serde(default)]
    allow_metadata_hosts: Option<Vec<String>>,
    #[serde(default)]
    health: Option<HealthCfg>,
    #[serde(skip)]
    options: ProviderTable,
}

/// Per-provider auth-style override: an OPAQUE style word (BUSBAR-1.6.0.md #50: "the auth style
/// resolves ... as opaque strings"; arch-audit u29 F1). The words a provider may name are the
/// outbound styles the loaded auth plugins DECLARE ([`crate::preflight::declared_styles`]: linked
/// and dropped in), read at parse; the kernel names none. A word no loaded plugin declares is a
/// deserialize error in serde's own unknown-variant words over the declared styles in the host's one
/// listing order (ranked first: the previous release's four, in its order, as their plugins rank
/// them), so a configuration the previous release refused for an unknown word is refused with its
/// text as the prefix. What a style needs (a `token_url`, an endpoint its credential names) is the
/// flag its plugin declares beside it, never its name.
#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct ProviderAuth(String);

impl ProviderAuth {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn named(word: impl Into<String>) -> Self {
        Self(word.into())
    }
}

impl<'de> Deserialize<'de> for ProviderAuth {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let word = String::deserialize(d)?;
        let declared = crate::preflight::declared_styles();
        provider_auth_from_declared_word(word, &declared).map_err(serde::de::Error::custom)
    }
}

fn provider_auth_from_declared_word(
    word: String,
    declared: &[busbar_contract::auth_calls::DeclaredStyle],
) -> Result<ProviderAuth, String> {
    if declared.iter().any(|s| s.name == word) {
        return Ok(ProviderAuth(word));
    }
    Err(unknown_style(&word, declared))
}

fn unknown_style(word: &str, declared: &[busbar_contract::auth_calls::DeclaredStyle]) -> String {
    let quoted: Vec<String> = declared.iter().map(|s| format!("`{}`", s.name)).collect();
    match quoted.as_slice() {
        [] => format!("unknown variant `{word}`, there are no variants"),
        [one] => format!("unknown variant `{word}`, expected {one}"),
        [a, b] => format!("unknown variant `{word}`, expected {a} or {b}"),
        all => format!(
            "unknown variant `{word}`, expected one of {}",
            all.join(", ")
        ),
    }
}

pub type ProviderTable = serde_json::Map<String, Value>;

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
#[derive(Clone)]
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

fn with_options<T: Serialize>(entry: &T, options: &ProviderTable) -> ProviderTable {
    let mut table = plane_table(entry);
    for (name, value) in options {
        table.insert(name.clone(), value.clone());
    }
    table
}

pub const DEPLOY_KEYS: &[&str] = &[
    "api_key",
    "protocol",
    "base_url",
    "error_map",
    "path",
    "path_base",
    "token_url",
    "scope",
    "subject",
    "auth",
    "allow_metadata_hosts",
    "health",
];

pub fn deployments<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<HashMap<String, ProviderDeploy>, D::Error> {
    let entries: HashMap<String, ProviderDeploy> = unique_entries(de)?;
    Ok(entries)
}

pub const CATALOG_KEYS: &[&str] = &[
    "protocol",
    "base_url",
    "error_map",
    "health",
    "path",
    "path_base",
    "token_url",
    "scope",
    "subject",
    "auth",
    "allow_metadata_hosts",
];

pub(super) fn catalog_grammar_keys() -> &'static [&'static str] {
    super::migrate_catalog::struct_keys(ProviderDefCore::deserialize)
}

#[cfg(test)]
pub(super) fn deploy_grammar_keys() -> &'static [&'static str] {
    super::migrate_catalog::struct_keys(ProviderDeployCore::deserialize)
}

pub fn catalog<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<HashMap<String, ProviderDef>, D::Error> {
    let entries: HashMap<String, ProviderDef> = unique_entries(de)?;
    Ok(entries)
}

fn unique_entries<'de, D, T>(de: D) -> Result<HashMap<String, T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Entries<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Entries<T> {
        type Value = HashMap<String, T>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a map")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut entries = HashMap::new();
            while let Some(name) = map.next_key::<String>()? {
                if entries.contains_key(&name) {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate entry with key {name:?}"
                    )));
                }
                entries.insert(name, map.next_value()?);
            }
            Ok(entries)
        }
    }
    de.deserialize_map(Entries(std::marker::PhantomData))
}

pub fn catalog_from_str(text: &str) -> Result<HashMap<String, ProviderDef>, serde_yaml::Error> {
    catalog(serde_yaml::Deserializer::from_str(text))
}

macro_rules! provider_entry {
    ($ty:ident, $core:ident, $keys:ident, $form:ident) => {
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
                struct EntryVisitor;
                impl<'de> serde::de::Visitor<'de> for EntryVisitor {
                    type Value = $ty;
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.write_str(concat!("struct ", stringify!($ty)))
                    }
                    fn visit_map<A: serde::de::MapAccess<'de>>(
                        self,
                        map: A,
                    ) -> Result<$ty, A::Error> {
                        let mut options = ProviderTable::new();
                        let mut entry = $core::deserialize(
                            serde::de::value::MapAccessDeserializer::new(OptionsAside {
                                inner: map,
                                keys: $keys,
                                form: Form::$form,
                                options: &mut options,
                            }),
                        )?;
                        if let Some(descriptor) = crate::plane_driver::door::provider_keys(
                            crate::plane_driver::registry::plane_decls(),
                        ) {
                            Form::$form.omit_unset(&mut options, descriptor);
                        }
                        entry.options = options;
                        Ok(entry)
                    }
                }
                de.deserialize_map(EntryVisitor)
            }
        }
    };
}

provider_entry!(ProviderCfg, ProviderCfgCore, ENTRY_KEYS, Entry);
provider_entry!(ProviderDef, ProviderDefCore, CATALOG_KEYS, Catalog);
provider_entry!(ProviderDeploy, ProviderDeployCore, DEPLOY_KEYS, Deployment);

const ENTRY_KEYS: &[&str] = &[
    "protocol",
    "base_url",
    "api_key",
    "health",
    "error_map",
    "path",
    "path_base",
    "token_url",
    "scope",
    "subject",
    "auth",
    "allow_metadata_hosts",
];

struct OptionsAside<'a, A> {
    inner: A,
    keys: &'static [&'static str],
    form: Form,
    options: &'a mut ProviderTable,
}

impl<'de, A: serde::de::MapAccess<'de>> serde::de::MapAccess<'de> for OptionsAside<'_, A> {
    type Error = A::Error;

    fn next_key_seed<K: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, A::Error> {
        use serde::de::{Error, IntoDeserializer};
        loop {
            let Some(key) = self.inner.next_key::<String>()? else {
                return Ok(None);
            };
            if self.keys.contains(&key.as_str()) {
                return seed
                    .deserialize(IntoDeserializer::<A::Error>::into_deserializer(key))
                    .map(Some);
            }
            let descriptor = crate::plane_driver::door::provider_keys(
                crate::plane_driver::registry::plane_decls(),
            );
            let field =
                descriptor.and_then(|d| self.form.table(d).keys.iter().find(|k| k.name == key));
            let value = match field {
                Some(field) => self.inner.next_value_seed(ValueSeed::field(field))?,
                None => self.inner.next_value::<Value>()?,
            };
            if self.options.insert(key.clone(), value).is_some() {
                return Err(<A::Error as Error>::custom(format!(
                    "duplicate field `{key}`"
                )));
            }
        }
    }

    fn next_value_seed<V: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, A::Error> {
        self.inner.next_value_seed(seed)
    }
}

pub fn judge_options(name: &str, provider: &ResolvedProvider) -> Result<(), String> {
    judge_table(name, &provider.table, false)
}

pub fn judge_catalog_entry(name: &str, def: &ProviderDef) -> Result<(), String> {
    judge_table(name, &with_options(def, &def.options), false)
}

pub(super) fn judge_unused_catalog_entry(name: &str, def: &ProviderDef) -> Result<(), String> {
    judge_table(name, &with_options(def, &def.options), true)
}

fn judge_table(name: &str, table: &ProviderTable, defer_unowned: bool) -> Result<(), String> {
    let core = |k: &String| CORE_PROVIDER_KEYS.contains(&k.as_str());
    let typed = |k: &String| DEPLOY_KEYS.contains(&k.as_str()) || core(k);
    let Some(first) = table.keys().find(|k| !typed(k)) else {
        return Ok(());
    };
    match crate::plane_driver::door::judge_provider(name, table) {
        Some(judged) => judged,
        None if defer_unowned => Ok(()),
        None => Err(format!(
            "providers.{name}: unknown field `{first}`: no loaded plane speaks this provider's \
             dialect, so it takes no option"
        )),
    }
}

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

fn is_str_map(value: &ProviderTable) -> bool {
    value.values().all(Value::is_string)
}

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

fn dialect_key() -> &'static str {
    busbar_contract::section::MODEL_PROTOCOL_KEYS[0]
}

const ERROR_MAP_KEY: &str = "error_map";

impl ResolvedProvider {
    #[must_use]
    pub fn merge(def: &ProviderDef, deploy: &ProviderDeploy) -> Self {
        Self {
            base_url: deploy
                .base_url
                .clone()
                .unwrap_or_else(|| def.base_url.clone()),
            api_key: deploy.api_key.clone(),

            health: deploy.health.clone().or_else(|| def.health.clone()),
            path: deploy.path.clone().or_else(|| def.path.clone()),
            path_base: deploy.path_base.clone().or_else(|| def.path_base.clone()),
            token_url: deploy.token_url.clone().or_else(|| def.token_url.clone()),
            scope: deploy.scope.clone().or_else(|| def.scope.clone()),
            subject: deploy.subject.clone().or_else(|| def.subject.clone()),
            auth: deploy.auth.clone().or_else(|| def.auth.clone()),

            allow_metadata_hosts: deploy
                .allow_metadata_hosts
                .clone()
                .unwrap_or_else(|| def.allow_metadata_hosts.clone()),
            table: merge_tables(
                with_options(def, &def.options),
                with_options(deploy, &deploy.options),
            ),
        }
    }

    #[must_use]
    pub fn dialect(&self) -> &str {
        self.table
            .get(dialect_key())
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    pub fn error_map(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.table
            .get(ERROR_MAP_KEY)
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|m| m.iter())
            .filter_map(|(code, class)| Some((code.as_str(), class.as_str()?)))
    }
}

impl From<ProviderCfg> for ResolvedProvider {
    fn from(p: ProviderCfg) -> Self {
        let table = with_options(&p, &p.options);
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

struct PrintedUrl<'a>(&'a str);

impl std::fmt::Debug for PrintedUrl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(
            &busbar_kernel_egress::trust::net::redact_userinfo(self.0),
            f,
        )
    }
}

fn printed_url(url: Option<&String>) -> Option<PrintedUrl<'_>> {
    url.map(|u| PrintedUrl(u))
}

impl std::fmt::Debug for ProviderCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            protocol,
            base_url,
            api_key,
            health,
            error_map,
            path,
            path_base,
            token_url,
            scope,
            subject,
            auth,
            allow_metadata_hosts,
            options,
        } = self;
        f.debug_struct("ProviderCfg")
            .field("protocol", protocol)
            .field("base_url", &PrintedUrl(base_url))
            .field("api_key", api_key)
            .field("health", health)
            .field("error_map", error_map)
            .field("path", path)
            .field("path_base", path_base)
            .field("token_url", &printed_url(token_url.as_ref()))
            .field("scope", scope)
            .field("subject", subject)
            .field("auth", auth)
            .field("allow_metadata_hosts", allow_metadata_hosts)
            .field("options", &options.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl std::fmt::Debug for ProviderDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            protocol,
            base_url,
            error_map,
            health,
            path,
            path_base,
            token_url,
            scope,
            subject,
            auth,
            allow_metadata_hosts,
            options,
        } = self;
        f.debug_struct("ProviderDef")
            .field("protocol", protocol)
            .field("base_url", &PrintedUrl(base_url))
            .field("error_map", error_map)
            .field("health", health)
            .field("path", path)
            .field("path_base", path_base)
            .field("token_url", &printed_url(token_url.as_ref()))
            .field("scope", scope)
            .field("subject", subject)
            .field("auth", auth)
            .field("allow_metadata_hosts", allow_metadata_hosts)
            .field("options", &options.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl std::fmt::Debug for ProviderDeploy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            api_key,
            protocol,
            base_url,
            error_map,
            path,
            path_base,
            token_url,
            scope,
            subject,
            auth,
            allow_metadata_hosts,
            health,
            options,
        } = self;
        f.debug_struct("ProviderDeploy")
            .field("api_key", api_key)
            .field("protocol", protocol)
            .field("base_url", &printed_url(base_url.as_ref()))
            .field("error_map", error_map)
            .field("path", path)
            .field("path_base", path_base)
            .field("token_url", &printed_url(token_url.as_ref()))
            .field("scope", scope)
            .field("subject", subject)
            .field("auth", auth)
            .field("allow_metadata_hosts", allow_metadata_hosts)
            .field("health", health)
            .field("options", &options.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl std::fmt::Debug for ResolvedProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            base_url,
            api_key,
            health,
            path,
            path_base,
            token_url,
            scope,
            subject,
            auth,
            allow_metadata_hosts,
            table,
        } = self;
        f.debug_struct("ResolvedProvider")
            .field("base_url", &PrintedUrl(base_url))
            .field("api_key", api_key)
            .field("health", health)
            .field("path", path)
            .field("path_base", path_base)
            .field("token_url", &printed_url(token_url.as_ref()))
            .field("scope", scope)
            .field("subject", subject)
            .field("auth", auth)
            .field("allow_metadata_hosts", allow_metadata_hosts)
            .field("table", &table.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod declared_auth_style_tests {
    use super::provider_auth_from_declared_word;

    #[test]
    fn test_provider_auth_style_is_a_declared_word() {
        let declared: Vec<_> = [
            "bearer",
            "api-key",
            "jwt-bearer",
            "oauth-client-credentials",
            "x-double-mint",
        ]
        .into_iter()
        .map(|name| busbar_contract::auth_calls::DeclaredStyle {
            name: name.to_string(),
            flags: 0,
        })
        .collect();
        for word in [
            "bearer",
            "api-key",
            "jwt-bearer",
            "oauth-client-credentials",
            "x-double-mint",
        ] {
            let style = provider_auth_from_declared_word(
                serde_yaml::from_str::<String>(word).expect("style is a YAML string"),
                &declared,
            )
            .unwrap_or_else(|e| panic!("declared style '{word}' must parse: {e}"));
            assert_eq!(style.as_str(), word);
        }
        let refused = provider_auth_from_declared_word(
            serde_yaml::from_str::<String>("oauth2").expect("style is a YAML string"),
            &declared,
        )
        .expect_err("'oauth2' is declared by no plugin and must fail to deserialize")
        .to_string();
        assert!(
            refused.starts_with(
                "unknown variant `oauth2`, expected one of `bearer`, `api-key`, `jwt-bearer`, \
             `oauth-client-credentials`, `x-double-mint`"
            ),
            "an undeclared style is refused in serde's words over the declared list: {refused}"
        );
    }
}
