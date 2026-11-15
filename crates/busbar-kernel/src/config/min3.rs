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
