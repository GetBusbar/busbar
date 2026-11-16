// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MIN-3 config keys: `upstreams.<name>.auth` and `.upstream_credentials`, `routes.<id>.auth_instances`,
//! per-instance `limits` and the auth `provisioning:` block (IF §12.1, §12.11, §12.18, §12.22, §12.29). W0-ABI stub:
//! the types and their parse hooks, which return `Default` so no existing config changes meaning; W1-K7 parses
//! each key into [`RootCfg::min3`](super::RootCfg::min3) and calls each consumer's hook at load.

use std::collections::BTreeMap;

use busbar_contract::config::UpstreamCreds;
use busbar_contract::secret_ref::SecretRef;

use super::DeployCfg;

/// Every MIN-3 key of one config load, carried on [`RootCfg::min3`](super::RootCfg::min3). Empty (the default)
/// until W1-K7 parses the keys.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Min3Config {
    /// `upstreams.<name>`, by configured upstream name (IF §12.1, §12.18).
    pub upstreams: BTreeMap<Box<str>, UpstreamCfg>,
    /// `routes.<id>`, by route id (IF §12.11 "Route credential header").
    pub routes: BTreeMap<Box<str>, RouteCfg>,
    /// `<kind>.<name>.limits`, by (kind section, configured instance name) (IF §12.22).
    pub limits: InstanceLimitsMap,
    /// `auth.<name>.provisioning`, by configured auth instance name (IF §12.29).
    pub provisioning: BTreeMap<Box<str>, ProvisioningCfg>,
}

/// Per-instance `limits`, by (kind section, configured instance name).
pub type InstanceLimitsMap = BTreeMap<(Box<str>, Box<str>), InstanceLimitsCfg>;

/// The MIN-3 keys of one `upstreams.<name>` entry (the rest of the entry is W1-K1's `UpstreamDef`).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct UpstreamCfg {
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

/// The MIN-3 keys of one `routes.<id>` entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteCfg {
    /// `routes.<id>.auth_instances`: the route's effective chain, configured auth instance names in order; None =
    /// rule (2) or (3) of IF §12.11 "Route credential header".
    pub auth_instances: Option<Vec<Box<str>>>,
}

/// `<kind>.<name>.limits`, beside `module` (IF §12.22). 0 = unset (the kind default) in every field. The
/// `plaintext` row is deleted (owner ruling; transport security is `insecure_transport`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InstanceLimitsCfg {
    pub timeout_ms: u32,
    pub connect_timeout_ms: u32,
    pub max_inflight: u32,
    /// Transport instances only.
    pub stream_stall_ms: u32,
}

/// `auth.<name>.provisioning` (IF §12.29).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisioningCfg {
    pub clients: Vec<Box<str>>,
    /// Absent = no CA-5 hold.
    pub link: Option<ProvisioningLink>,
    pub guard: ProvisioningGuard,
}

/// `provisioning.link`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisioningLink {
    pub index: Box<str>,
    pub auth: Vec<Box<str>>,
    pub refresh_ms: u32,
}

/// `provisioning.guard`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvisioningGuard {
    pub max: u32,
    pub window_s: u64,
}

/// Parses every MIN-3 key of `deploy`; Err = the refusal texts (core text naming the key). W0-ABI stub: the empty
/// config, no refusal.
pub fn parse_min3(deploy: &DeployCfg) -> Result<Min3Config, Vec<String>> {
    let _ = deploy;
    Ok(Min3Config::default())
}

/// Parses `upstreams.<name>.auth` and `upstreams.<name>.upstream_credentials` (consumers W1-K1, W1-K6). W0-ABI
/// stub: none.
pub fn parse_upstreams(deploy: &DeployCfg) -> Result<BTreeMap<Box<str>, UpstreamCfg>, Vec<String>> {
    let _ = deploy;
    Ok(BTreeMap::new())
}

/// Parses `routes.<id>.auth_instances` (consumer W1-K8B). W0-ABI stub: none.
pub fn parse_routes(deploy: &DeployCfg) -> Result<BTreeMap<Box<str>, RouteCfg>, Vec<String>> {
    let _ = deploy;
    Ok(BTreeMap::new())
}

/// Parses and strips every instance's `limits` (consumers W1-K8D, W1-C1A). W0-ABI stub: none.
pub fn parse_limits(deploy: &DeployCfg) -> Result<InstanceLimitsMap, Vec<String>> {
    let _ = deploy;
    Ok(BTreeMap::new())
}

/// Parses every auth instance's `provisioning:` block (consumer W1-K6P). W0-ABI stub: none.
pub fn parse_provisioning(
    deploy: &DeployCfg,
) -> Result<BTreeMap<Box<str>, ProvisioningCfg>, Vec<String>> {
    let _ = deploy;
    Ok(BTreeMap::new())
}

/// The `upstream_credentials` refusals (IF §12.18 round 22, (i)-(iii)), run at config load once the bindings are
/// resolved (consumer W1-K6); Err = the refusal texts. W0-ABI stub: refuses nothing.
pub fn check_upstream_credentials(min3: &Min3Config) -> Result<(), Vec<String>> {
    let _ = min3;
    Ok(())
}

/// The longest any `limits` duration may be (IF §12.22).
pub(crate) const MAX_LIMIT_MS: u64 = 600_000;
/// The most concurrent port calls `limits.max_inflight` may name (IF §12.22).
pub const MAX_INFLIGHT: u64 = 65_535;
/// The longest a reason may be (TRANSPORT-SECURITY-POLICY §4).
pub(crate) const MAX_REASON_CHARS: usize = 256;

/// `<kind>.<name>.limits` as written: the grammar of the object, before validation. A key outside these four
/// (`plaintext` included: the row is deleted) is refused as unknown.
#[derive(Clone, Copy, Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsDoc {
    #[serde(default)]
    pub timeout_ms: u64,
    #[serde(default)]
    pub connect_timeout_ms: u64,
    #[serde(default)]
    pub max_inflight: u64,
    #[serde(default)]
    pub stream_stall_ms: u64,
}

impl LimitsDoc {
    /// Validates the object (numbers at most 600,000 ms and 65,535 in flight; `stream_stall_ms` 0 or
    /// 1,000..=600,000) and returns the parsed limits. `path` is the instance's config path (`store.main`); the
    /// refusal names `<path>.limits.<key>`.
    pub fn resolve(self, path: &str) -> Result<InstanceLimitsCfg, String> {
        let ms = |key: &str, v: u64| -> Result<u32, String> {
            if v > MAX_LIMIT_MS {
                return Err(format!(
                    "{path}.limits.{key} is {v}: at most {MAX_LIMIT_MS} milliseconds"
                ));
            }
            Ok(v as u32)
        };
        let stall = self.stream_stall_ms;
        if stall != 0 && !(1_000..=MAX_LIMIT_MS).contains(&stall) {
            return Err(format!(
                "{path}.limits.stream_stall_ms is {stall}: 0 (the default) or 1000..={MAX_LIMIT_MS} milliseconds"
            ));
        }
        if self.max_inflight > MAX_INFLIGHT {
            return Err(format!(
                "{path}.limits.max_inflight is {}: at most {MAX_INFLIGHT} calls in flight",
                self.max_inflight
            ));
        }
        Ok(InstanceLimitsCfg {
            timeout_ms: ms("timeout_ms", self.timeout_ms)?,
            connect_timeout_ms: ms("connect_timeout_ms", self.connect_timeout_ms)?,
            max_inflight: self.max_inflight as u32,
            stream_stall_ms: stall as u32,
        })
    }
}

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
