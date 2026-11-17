// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MIN-3 config keys: the top-level `upstreams:` section with each entry's `auth` and `upstream_credentials`,
//! per-instance `insecure_transport`, and the auth `provisioning:` block (IF §12.1, §12.18, §12.29;
//! TRANSPORT-SECURITY-POLICY §4). Every key is additive (PRD-4: a 1.5.5 config parses unchanged). W1-K7 parses the
//! upstreams section and `insecure_transport` into [`RootCfg::min3`](super::RootCfg::min3) at load
//! ([`parse_min3`], called by `config::resolve`, which also calls W1-K6's [`check_upstream_credentials`] hook);
//! There is no per-instance `limits` key and no `routes` section: an instance
//! runs at its kind's defaults, and the plugin's settled LIMITS answer is applied in memory at its open.

use std::collections::BTreeMap;

use busbar_contract::config::UpstreamCreds;
use busbar_contract::json::{
    self, JsonContainerTrait as _, JsonValueTrait as _, Map as JsonMap, Value as JsonValue,
};
use busbar_contract::secret_ref::SecretRef;
use busbar_contract::yaml::{Value as YamlValue, ValueExt};
use serde::Deserialize;

use super::DeployCfg;

/// Every MIN-3 key of one config load, carried on [`RootCfg::min3`](super::RootCfg::min3). Empty (the default)
/// for a config that writes none of them.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Min3Config {
    /// The checked core-owned `auth.verdict_cache` policy (IF §12.28).
    pub verdict_cache: crate::auth::verdicts::VerdictPolicy,
    /// `identity-providers.<name>.provisioning`, by configured auth instance name (IF §12.29).
    pub provisioning: BTreeMap<Box<str>, ProvisioningCfg>,
    /// `<kind>.<name>.insecure_transport`, by (kind section, configured instance name) (TRANSPORT-SECURITY-POLICY
    /// §4); absent = verified TLS only. Read into `InstanceLimits.accept` by `appbuild::instance_limits`.
    pub insecure_transport: InsecureTransportMap,
}

/// Per-instance `insecure_transport`, by (kind section, configured instance name).
pub type InsecureTransportMap = BTreeMap<(Box<str>, Box<str>), InsecureTransport>;

/// The MIN-3 keys of one `upstreams.<name>` entry (the rest of the entry is W1-K1's `UpstreamDef`).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct UpstreamCfg {
    /// Opaque configured rate identity; omitted/null means no selected resource.
    pub resource: Option<Box<str>>,
    /// `upstreams.<name>.auth`: the operator form or one core-vocabulary form (IF §12.18 upstream bindings).
    pub auth: Option<UpstreamAuthCfg>,
    /// `upstreams.<name>.upstream_credentials`; None = derived from the binding (IF §12.18 round 22).
    pub upstream_credentials: Option<UpstreamCreds>,
}

/// `upstreams.<name>.auth` as written, with its optional `cache_max_s`.
#[derive(Clone, PartialEq, Eq)]
pub struct UpstreamAuthCfg {
    pub form: UpstreamAuthForm,
    pub cache_max_s: Option<u32>,
}

/// The forms of `upstreams.<name>.auth` (IF §12.18): an auth instance name, or exactly one core-vocabulary form.
// No `Debug`: the form carries URLs (credential typecheck `printable-url`).
#[derive(Clone, PartialEq, Eq)]
pub enum UpstreamAuthForm {
    /// `auth: <auth instance name>`.
    Instance(Box<str>),
    /// `auth: {bearer: <secret ref>}`.
    Bearer(SecretRef),
    /// `auth: {api_key: {header, secret}}`.
    ApiKey { header: Box<str>, secret: SecretRef },
    /// `auth: {token_exchange: {token_url, resource, subject_token, subject_token_type?}}` (RFC 8693).
    TokenExchange {
        token_url: Box<str>,
        resource: Box<str>,
        subject_token: SecretRef,
        subject_token_type: Option<Box<str>>,
    },
    /// `auth: {connection: {issuer, resource, client_id, redirect_uri, authorization_endpoint, token_endpoint,
    /// scopes?}}`.
    Connection {
        issuer: Box<str>,
        resource: Box<str>,
        client_id: Box<str>,
        redirect_uri: Box<str>,
        authorization_endpoint: Box<str>,
        token_endpoint: Box<str>,
        scopes: Option<Vec<Box<str>>>,
    },
}

/// `identity-providers.<name>.provisioning` (IF §12.29).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningCfg {
    pub clients: Vec<Box<str>>,
    /// Absent = no CA-5 hold.
    pub link: Option<ProvisioningLink>,
    pub guard: ProvisioningGuard,
}

/// `provisioning.link`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningLink {
    pub index: Box<str>,
    pub auth: Vec<Box<str>>,
    pub refresh_ms: u32,
}

/// `provisioning.guard`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningGuard {
    pub max: u32,
    pub window_s: u64,
}

/// Parses every MIN-3 key of `deploy`; Err = every refusal text of every key (core text naming the key's path
/// in the file; an `insecure_transport` refusal is BUSBAR-3163). Every key is additive: a 1.5.5-shaped document
/// carries none of them and parses to the empty config.
///
/// `insecure_transport` sits beside `module` in an instance block of any kind (`store`,
/// `secrets.<name>`, `identity-providers.<name>`, `hooks.<name>`, `export.<name>`;
/// TRANSPORT-SECURITY-POLICY §4). The typed section structs keep it as written, so the grammar admits it
/// and the authoring view writes it back; it is never part of an instance's `settings`, the only bag a
/// plugin is bound from, so it is stripped before binding by construction. It is keyed here by (the
/// section word, the configured instance name); the store is (`store`, `store`).
pub fn parse_min3(deploy: &DeployCfg) -> Result<Min3Config, Vec<String>> {
    let mut refused = Vec::new();
    let insecure_transport = kept(parse_insecure_transport(deploy), &mut refused);
    let provisioning = kept(parse_provisioning(deploy), &mut refused);
    let verdict_cache = kept(
        deploy
            .auth
            .as_ref()
            .map_or_else(Default::default, |auth| auth.verdict_cache)
            .resolve()
            .map_err(|why| vec![why.to_owned()]),
        &mut refused,
    );
    if !refused.is_empty() {
        return Err(refused);
    }
    Ok(Min3Config {
        verdict_cache,
        provisioning,
        insecure_transport,
    })
}

/// The parsed value, or its default with its refusals appended to `refused`.
fn kept<T: Default>(parsed: Result<T, Vec<String>>, refused: &mut Vec<String>) -> T {
    parsed.unwrap_or_else(|mut why| {
        refused.append(&mut why);
        T::default()
    })
}

/// One instance block that may carry `insecure_transport` beside `module`.
struct Block<'a> {
    /// The section word (`store`, `secrets`, `identity-providers`, `hooks`, `export`).
    section: &'static str,
    /// The configured instance name (`store` for the one store).
    name: &'a str,
    /// The block's path in the file, as a refusal names it (`store`, `secrets.vault`).
    path: String,
    insecure_transport: Option<&'a YamlValue>,
}

/// Every instance block of `deploy` that carries the two core keys, in section order then name order.
fn blocks(deploy: &DeployCfg) -> Vec<Block<'_>> {
    // The store's section word and its one instance name (`appbuild::STORE_INSTANCE`).
    const STORE_INSTANCE: &str = "store";
    let mut out = Vec::new();
    if let Some(store) = &deploy.store {
        out.push(Block {
            section: STORE_INSTANCE,
            name: STORE_INSTANCE,
            path: STORE_INSTANCE.to_owned(),
            insecure_transport: store.insecure_transport.as_ref(),
        });
    }
    for (name, secret) in &deploy.secrets {
        out.push(Block {
            section: "secrets",
            name: name.as_str(),
            path: format!("secrets.{name}"),
            insecure_transport: secret.insecure_transport.as_ref(),
        });
    }
    for (name, def) in &deploy.identity_providers {
        out.push(Block {
            section: "identity-providers",
            name: name.as_str(),
            path: format!("identity-providers.{name}"),
            insecure_transport: def.insecure_transport.as_ref(),
        });
    }
    for (name, def) in &deploy.hooks {
        out.push(Block {
            section: "hooks",
            name: name.as_str(),
            path: format!("hooks.{name}"),
            insecure_transport: def.insecure_transport.as_ref(),
        });
    }
    for (name, def) in &deploy.export {
        out.push(Block {
            section: "export",
            name: name.as_str(),
            path: format!("export.{name}"),
            insecure_transport: def.insecure_transport.as_ref(),
        });
    }
    out
}

/// Parses `upstreams.<name>.auth` and `upstreams.<name>.upstream_credentials` (consumers W1-K1, W1-K6): an
/// upstream with neither key has no entry. An entry that is not a map is left to
/// [`crate::upstreams::ConfiguredUpstreams::from_config`], which refuses it with the rest of the entry grammar.
pub fn parse_upstream_entry(at: &str, entry: &JsonValue) -> Result<UpstreamCfg, Vec<String>> {
    let mut refused = Vec::new();
    let Some(map) = entry.as_object() else {
        return Err(vec![format!("{at}: a registration must be an object")]);
    };
    let resource = match map.get(&"resource").filter(|value| !value.is_null()) {
        None => None,
        Some(value) => match value
            .as_str()
            .filter(|text| super::groups::valid_selected_identifier(text))
        {
            Some(text) => Some(text.into()),
            None => {
                refused.push(format!("{at}.resource must be a nonempty string of at most 128 UTF-8 bytes without controls"));
                None
            }
        },
    };
    let auth = match map.get(&"auth").filter(|v| !v.is_null()) {
        None => None,
        Some(value) => match upstream_auth(at, value) {
            Ok(auth) => Some(auth),
            Err(why) => {
                refused.push(why);
                None
            }
        },
    };
    let upstream_credentials = match map.get(&"upstream_credentials").filter(|v| !v.is_null()) {
        None => None,
        Some(value) => match json::from_value::<UpstreamCreds>(value) {
            Ok(creds) => Some(creds),
            Err(e) => {
                refused.push(format!(
                        "`{at}.upstream_credentials` is not one of `own`, `passthrough` or `connection`: {e}"
                    ));
                None
            }
        },
    };
    if refused.is_empty() {
        Ok(UpstreamCfg {
            resource,
            auth,
            upstream_credentials,
        })
    } else {
        Err(refused)
    }
}

/// The core-vocabulary forms of `upstreams.<name>.auth` (IF §12.18), as a refusal lists them.
const AUTH_FORMS: &str = "`bearer`, `api_key`, `token_exchange` or `connection`";

/// `upstreams.<name>.auth` (`at` = `upstreams.<name>`): an auth instance name, or a map with exactly one
/// core-vocabulary form and an optional `cache_max_s`. No refusal repeats a value (URLs and references stay out).
fn upstream_auth(at: &str, value: &JsonValue) -> Result<UpstreamAuthCfg, String> {
    if let Some(instance) = value.as_str() {
        if instance.is_empty() || instance.trim() != instance {
            return Err(format!(
                "`{at}.auth` names no auth instance: write the instance's exact name, or a map with exactly one \
                 of {AUTH_FORMS}"
            ));
        }
        return Ok(UpstreamAuthCfg {
            form: UpstreamAuthForm::Instance(instance.into()),
            cache_max_s: None,
        });
    }
    let Some(map) = value.as_object() else {
        return Err(format!(
            "`{at}.auth` must be an auth instance name or a map with exactly one of {AUTH_FORMS} (and an \
             optional `cache_max_s`)"
        ));
    };
    let mut cache_max_s = None;
    let mut forms: Vec<(&str, &JsonValue)> = Vec::new();
    for (key, form) in map {
        match key {
            "cache_max_s" => match form.as_u64().and_then(|s| u32::try_from(s).ok()) {
                Some(seconds) if seconds > 0 => cache_max_s = Some(seconds),
                _ => {
                    return Err(format!(
                        "`{at}.auth.cache_max_s` must be a whole number of seconds, 1 to {}",
                        u32::MAX
                    ))
                }
            },
            "bearer" | "api_key" | "token_exchange" | "connection" => {
                forms.push((key, form));
            }
            other => {
                return Err(format!(
                    "`{at}.auth.{other}` is not an upstream auth form; the forms are {AUTH_FORMS}"
                ))
            }
        }
    }
    let &[(word, form)] = forms.as_slice() else {
        return Err(format!(
            "`{at}.auth` states {} forms; state exactly one of {AUTH_FORMS}",
            forms.len()
        ));
    };
    let form = match word {
        "bearer" => UpstreamAuthForm::Bearer(auth_secret(at, "bearer", Some(form))?),
        "api_key" => {
            let m = form_map(at, word, form, &["header", "secret"])?;
            UpstreamAuthForm::ApiKey {
                header: auth_text(at, "api_key.header", m.get(&"header"))?,
                secret: auth_secret(at, "api_key.secret", m.get(&"secret"))?,
            }
        }
        "token_exchange" => {
            let m = form_map(
                at,
                word,
                form,
                &[
                    "token_url",
                    "resource",
                    "subject_token",
                    "subject_token_type",
                ],
            )?;
            UpstreamAuthForm::TokenExchange {
                token_url: auth_text(at, "token_exchange.token_url", m.get(&"token_url"))?,
                resource: auth_text(at, "token_exchange.resource", m.get(&"resource"))?,
                subject_token: auth_secret(
                    at,
                    "token_exchange.subject_token",
                    m.get(&"subject_token"),
                )?,
                subject_token_type: match m.get(&"subject_token_type") {
                    None => None,
                    Some(value) if value.is_null() => None,
                    some => Some(auth_text(at, "token_exchange.subject_token_type", some)?),
                },
            }
        }
        _ => {
            let m = form_map(
                at,
                word,
                form,
                &[
                    "issuer",
                    "resource",
                    "client_id",
                    "redirect_uri",
                    "authorization_endpoint",
                    "token_endpoint",
                    "scopes",
                ],
            )?;
            let scopes = match m.get(&"scopes") {
                None => None,
                Some(value) if value.is_null() => None,
                Some(value) if value.is_array() => Some(
                    value
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|item| {
                            item.as_str()
                                .filter(|scope| !scope.is_empty())
                                .map(Box::<str>::from)
                        })
                        .collect::<Option<Vec<Box<str>>>>()
                        .ok_or_else(|| {
                            format!("`{at}.auth.connection.scopes` must be a list of scope names")
                        })?,
                ),
                Some(_) => {
                    return Err(format!(
                        "`{at}.auth.connection.scopes` must be a list of scope names"
                    ))
                }
            };
            UpstreamAuthForm::Connection {
                issuer: auth_text(at, "connection.issuer", m.get(&"issuer"))?,
                resource: auth_text(at, "connection.resource", m.get(&"resource"))?,
                client_id: auth_text(at, "connection.client_id", m.get(&"client_id"))?,
                redirect_uri: auth_text(at, "connection.redirect_uri", m.get(&"redirect_uri"))?,
                authorization_endpoint: auth_text(
                    at,
                    "connection.authorization_endpoint",
                    m.get(&"authorization_endpoint"),
                )?,
                token_endpoint: auth_text(
                    at,
                    "connection.token_endpoint",
                    m.get(&"token_endpoint"),
                )?,
                scopes,
            }
        }
    };
    Ok(UpstreamAuthCfg { form, cache_max_s })
}

/// The map of one auth form, with no key outside `keys`.
fn form_map<'a>(
    at: &str,
    word: &str,
    form: &'a JsonValue,
    keys: &[&str],
) -> Result<&'a JsonMap, String> {
    let listed = keys
        .iter()
        .map(|key| format!("`{key}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let Some(map) = form.as_object() else {
        return Err(format!("`{at}.auth.{word}` must be a map of {listed}"));
    };
    if let Some(key) = map
        .iter()
        .map(|(key, _)| key)
        .find(|key| !keys.contains(key))
    {
        return Err(format!(
            "`{at}.auth.{word}.{key}` is not a key of `{word}`; the keys are {listed}"
        ));
    }
    Ok(map)
}

/// A required non-empty string of an auth form (`key` = its path under `auth`).
fn auth_text(at: &str, key: &str, value: Option<&JsonValue>) -> Result<Box<str>, String> {
    match value.and_then(JsonValue::as_str) {
        Some(text) if !text.trim().is_empty() => Ok(text.into()),
        _ => Err(format!("`{at}.auth.{key}` must be a non-empty string")),
    }
}

/// A required secret reference of an auth form (`key` = its path under `auth`); `none` names no credential, so
/// it is refused here (an upstream with no credential has no `auth`).
fn auth_secret(at: &str, key: &str, value: Option<&JsonValue>) -> Result<SecretRef, String> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Err(format!("`{at}.auth.{key}` must be a secret reference"));
    };
    match json::from_value::<SecretRef>(value) {
        Ok(SecretRef::None) => Err(format!(
            "`{at}.auth.{key}` is `none`, which names no credential; drop `{at}.auth` for an upstream that takes none"
        )),
        Ok(reference) => Ok(reference),
        Err(e) => Err(format!("`{at}.auth.{key}` must be a secret reference: {e}")),
    }
}

/// Parses every instance's `insecure_transport` (TRANSPORT-SECURITY-POLICY §4; see [`parse_min3`]): every
/// refusal is BUSBAR-3163 naming `<path>.insecure_transport[.<key>]`.
fn parse_insecure_transport(deploy: &DeployCfg) -> Result<InsecureTransportMap, Vec<String>> {
    let mut out = InsecureTransportMap::new();
    let mut refused = Vec::new();
    for block in blocks(deploy) {
        let Some(value) = block.insecure_transport else {
            continue;
        };
        match insecure_transport_of(&block.path, value) {
            Ok(accepted) => {
                out.insert((block.section.into(), block.name.into()), accepted);
            }
            Err(why) => refused.push(why),
        }
    }
    if refused.is_empty() {
        Ok(out)
    } else {
        Err(refused)
    }
}

/// One `insecure_transport` object as written (`path` = the instance's path in the file): the keys and the
/// `accept` words are judged here so each refusal names its key, then [`InsecureTransportDoc::resolve`] judges
/// the list and the reason.
fn insecure_transport_of(path: &str, value: &YamlValue) -> Result<InsecureTransport, String> {
    let refuse =
        |key: &str, why: &str| format!("BUSBAR-3163: {path}.insecure_transport{key} {why}");
    let Some(pairs) = value.as_mapping() else {
        return Err(refuse(
            "",
            "must be a map: { accept: plaintext | unverified_tls | [plaintext, unverified_tls], reason: \"...\" }",
        ));
    };
    for (key, _) in pairs {
        match key.as_str() {
            Some("accept" | "reason") => {}
            Some(other) => {
                return Err(refuse(
                    &format!(".{other}"),
                    "is not a key of insecure_transport: the keys are accept and reason",
                ))
            }
            None => {
                return Err(refuse(
                    "",
                    "has a key that is not a word: the keys are accept and reason",
                ))
            }
        }
    }
    let word = |v: &YamlValue| matches!(v.as_str(), Some("plaintext" | "unverified_tls"));
    match value.get("accept") {
        None => {
            return Err(refuse(
                ".accept",
                "is missing: name plaintext, unverified_tls or both",
            ))
        }
        Some(accept) if word(accept) => {}
        Some(accept)
            if accept
                .as_sequence()
                .is_some_and(|items| items.iter().all(word)) => {}
        Some(_) => {
            return Err(refuse(
                ".accept",
                "is not plaintext, unverified_tls or a list of them",
            ))
        }
    }
    if value
        .get("reason")
        .is_some_and(|reason| !reason.is_null() && reason.as_str().is_none())
    {
        return Err(refuse(".reason", "must be one line of text"));
    }
    let doc = busbar_contract::yaml::from_value::<InsecureTransportDoc>(value.clone())
        .map_err(|e| refuse("", &format!("does not parse: {e}")))?;
    doc.resolve(path)
}

/// Parses every auth instance's core-owned provisioning policy. Image capabilities and
/// inbound link references are checked after the boot walk by `directory::check_provisioning`.
pub fn parse_provisioning(
    deploy: &DeployCfg,
) -> Result<BTreeMap<Box<str>, ProvisioningCfg>, Vec<String>> {
    let mut out = BTreeMap::new();
    let mut refused = Vec::new();
    for (name, def) in &deploy.identity_providers {
        let Some(value) = &def.provisioning else {
            continue;
        };
        let cfg = match busbar_contract::yaml::from_value::<ProvisioningCfg>(value.clone()) {
            Ok(cfg) => cfg,
            Err(error) => {
                refused.push(format!("identity-providers.{name}.provisioning: {error}"));
                continue;
            }
        };
        match crate::directory::check_provisioning_shape(name, &cfg) {
            Ok(()) => {
                out.insert(name.as_str().into(), cfg);
            }
            Err(mut reasons) => refused.append(&mut reasons),
        }
    }
    if refused.is_empty() {
        Ok(out)
    } else {
        Err(refused)
    }
}

/// The `upstream_credentials` refusals (IF §12.18 round 22, (i)-(iii)), run at config load once the bindings are
/// resolved (consumer W1-K6); Err = the refusal texts. W0-ABI stub: refuses nothing.
pub fn check_upstream_credentials(min3: &Min3Config) -> Result<(), Vec<String>> {
    let _ = min3;
    Ok(())
}

/// The longest a reason may be (TRANSPORT-SECURITY-POLICY §4).
pub(crate) const MAX_REASON_CHARS: usize = 256;

/// One `accept` word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum AcceptWord {
    Plaintext,
    UnverifiedTls,
}

/// `accept: <word>` or `accept: [<word>, ...]`.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum AcceptDoc {
    One(AcceptWord),
    Many(Vec<AcceptWord>),
}

/// `<kind>.<name>.insecure_transport` as written (TRANSPORT-SECURITY-POLICY §4): the grammar of the object,
/// before validation. An unknown key is refused.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InsecureTransportDoc {
    accept: AcceptDoc,
    #[serde(default)]
    reason: Option<String>,
}

/// A validated `insecure_transport`: the acceptance and the human's reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsecureTransport {
    pub accept: busbar_plugin_abi::host_side::caller::Accept,
    pub reason: Box<str>,
}

impl InsecureTransportDoc {
    /// Validates the object: `accept` is `plaintext`, `unverified_tls` or a non-empty list of distinct words;
    /// `reason` is present, 1..=256 printable characters, no newline and not the `<why ...>` placeholder core
    /// prints in BUSBAR-3160/3161. Every refusal is BUSBAR-3163 naming `<path>.insecure_transport.<key>`.
    pub fn resolve(self, path: &str) -> Result<InsecureTransport, String> {
        use busbar_plugin_abi::host_side::caller::Accept;
        let words = match self.accept {
            AcceptDoc::One(w) => vec![w],
            AcceptDoc::Many(v) => v,
        };
        if words.is_empty() {
            return Err(format!(
                "BUSBAR-3163: {path}.insecure_transport.accept is an empty list: name plaintext, unverified_tls or both"
            ));
        }
        let mut bits = 0u8;
        for w in &words {
            let bit = match w {
                AcceptWord::Plaintext => Accept::PLAINTEXT,
                AcceptWord::UnverifiedTls => Accept::UNVERIFIED_TLS,
            };
            if bits & bit != 0 {
                return Err(format!(
                    "BUSBAR-3163: {path}.insecure_transport.accept repeats a value: each of plaintext and unverified_tls is named once"
                ));
            }
            bits |= bit;
        }
        let reason = self.reason.unwrap_or_default();
        let bad = if reason.trim().is_empty() {
            Some("is missing or empty: say why this instance may not use verified TLS")
        } else if reason.chars().count() > MAX_REASON_CHARS {
            Some("is longer than 256 characters")
        } else if reason.chars().any(char::is_control) {
            Some("holds a newline or a control character: one printable line")
        } else if reason.trim_start().starts_with("<why") {
            Some("is the <why ...> placeholder: write the real reason")
        } else {
            None
        };
        if let Some(why) = bad {
            return Err(format!(
                "BUSBAR-3163: {path}.insecure_transport.reason {why}"
            ));
        }
        Ok(InsecureTransport {
            accept: Accept(bits),
            reason: reason.into(),
        })
    }
}

impl InsecureTransport {
    /// The `accept` words as the audit row, the admin API and the warning print them.
    #[must_use]
    pub fn accept_words(&self) -> Vec<&'static str> {
        use busbar_plugin_abi::host_side::caller::Accept;
        let mut words = Vec::new();
        if self.accept.0 & Accept::PLAINTEXT != 0 {
            words.push("plaintext");
        }
        if self.accept.0 & Accept::UNVERIFIED_TLS != 0 {
            words.push("unverified_tls");
        }
        words
    }

    /// The BUSBAR-3162 warning line, logged at every boot and every kept reload (policy §4 "Visibility").
    /// `endpoints` is the instance's declared endpoints as `dest (class, note)`; empty = none declared yet.
    #[must_use]
    pub fn warning_line(&self, path: &str, module: &str, endpoints: &[String]) -> String {
        let accept = self.accept_words();
        let accept = if accept.len() == 1 {
            accept[0].to_owned()
        } else {
            format!("[{}]", accept.join(", "))
        };
        let dests = if endpoints.is_empty() {
            "no declared endpoint uses this yet".to_owned()
        } else {
            endpoints.join(", ")
        };
        format!(
            "BUSBAR-3162: {path} (module {module}) runs with insecure_transport: accept {accept} for {dests}. Anything sent to it, credentials included, can be read and altered by anyone who can intercept the network path. Reason: \"{}\". Remove {path}.insecure_transport once the server offers verifiable TLS.",
            self.reason
        )
    }
}

#[cfg(test)]
#[path = "tests/min3_tests.rs"]
mod tests;
