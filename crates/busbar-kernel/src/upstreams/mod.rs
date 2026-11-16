// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Configured upstreams: where each is, how its peer is authenticated, its outbound binding (IF §12.1).
//!
//! The types below are frozen (IF r35). [`UpstreamDef::from_config`] types one `upstreams.<name>` entry over the
//! `auth` and `upstream_credentials` keys the config grammar parsed ([`crate::config::min3::UpstreamCfg`]), and
//! [`ConfiguredUpstreams`] is the table every consumer reads through [`Upstreams`]. There is no egress judge here:
//! the connector's destination guard is it (§12.1).

mod declared;
#[cfg(test)]
mod declared_tests;
mod entry;
mod table;
#[cfg(test)]
mod tests;

pub use declared::{core_field_paths, core_secret_paths, declared, Declared};
pub use entry::{implicit_instance, DEFAULT_IDLE_S, MAX_NAME};
pub use table::ConfiguredUpstreams;

/// A configured upstream (operator vocabulary: `upstreams.<name>`; `Target::upstream` names it). Holds what a
/// plane used to keep in its own config: where it is, how its peer is authenticated, which client identity core
/// presents, and (stdio) the command core runs. Filled at boot from core config; a 1.5.x plane-a2a `agents:` entry (url, `cert_spki`/`mtls` pins, client
/// identity) or plane-mcp member (url, stdio command) arrives here as a CORE_CFG(UPSTREAM) fragment from that
/// plane's own `migrate` (§12.10), never from a core table that knows the plane.
pub struct UpstreamDef {
    pub name: Box<str>,
    /// Private-address authority for this registration only; metadata and TLS policy still apply.
    pub allow_private: bool,
    pub url: Option<Box<str>>,
    /// CARRIER_STDIO: argv and env (env values may be secret references, resolved through custody at spawn).
    pub command: Option<StdioCommand>,
    pub tls: UpstreamTls,
    /// Round 21: the outbound binding OUTBOUND_DEFAULT uses for this upstream (§12.18 upstream bindings).
    /// None = no credential (round 22: and the upstream is never caller-mode).
    pub auth: Option<UpstreamAuth>,
}
/// Round 21 (K1 parses, K6 resolves at config load, before 2c opens auth instances). `instance` = the auth
/// instance's configured name: the operator's `upstreams.<name>.auth: <instance>`, or the implicit
/// `auth.upstream-<name>-outbound` K6 builds from a core-vocabulary form (§12.18). `cache_max_s` caps the
/// CredKey cache entry for this upstream below the plugin's F_CACHE_S (a2a's `lease_ttl_ms`, rounded up to whole
/// seconds); None = the plugin's F_CACHE_S alone. `connect_callback` = the path of the `connection` form's
/// `redirect_uri`, on which K10 serves the caller-connection callback (§12.12); None for every other form.
/// Round 22, derived by K6 from the binding's style flags (`Registry::style_flags`, D_STYLE_FLAGS), never from
/// the plane: `caller` = the style declared STYLE_CALLER (every exchange presents the verified caller's own grant,
/// O_CALLER_GRANT; none held = R_CONNECT_REQUIRED); `scoped` = the style declared STYLE_SCOPE (core passes the
/// plane's UP_SCOPE as O_SCOPE and keys `CredKey.scope` by it; otherwise UP_SCOPE is dropped and the key's scope
/// is zero). Round 24: `per_request` = the style declared STYLE_PER_REQUEST (its credential is bound to one
/// request, e.g. a sigv4 signature or a header read per call; §12.2 rule 5), likewise derived, never inferred
/// from an answer's F_CACHE_S.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamAuth {
    pub instance: Box<str>,
    pub cache_max_s: Option<u32>,
    pub connect_callback: Option<Box<str>>,
    pub caller: bool,
    pub scoped: bool,
    pub per_request: bool,
}
/// Round 6: `cwd` = the child's working directory (absolute, no NUL; None = inherit busbar's, exactly what 1.5.5
/// does for a member with no `cwd:`; plane-mcp's `migrate` copies a member's `cwd:` into this field verbatim); `pin` = how the operator authenticated this program
/// (today's plane-mcp `pin`, moved to core with the command). `ProgramPin::LocalProgram` requires `cwd` to be
/// Some and `key == argv[0]`, both absolute (today's tools_config.rs:1068-1095 rules, enforced by core at config
/// load); `ProgramPin::Unpinned` = no approval claim.
pub struct StdioCommand {
    pub argv: Vec<Box<str>>,
    pub env: Vec<(Box<str>, busbar_contract::secret_ref::SecretRef)>,
    pub cwd: Option<Box<str>>,
    pub pin: ProgramPin,
    pub idle_s: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProgramPin {
    Unpinned,
    LocalProgram { key: Box<str> },
}
/// pin_spki = SHA-256 of acceptable SubjectPublicKeyInfo DER (any match passes; empty = no pin): checked by the
/// connector after the handshake and before any request byte, mismatch = the exchange fails P_ERROR (R_NOT_TRUSTED)
/// and is audited `upstream_pin_mismatch`. client_identity = a secret holding a PEM cert chain + key, presented as
/// the TLS client certificate. trust = an operator CA added to the roots for this upstream only.
pub struct UpstreamTls {
    pub pin_spki: Vec<[u8; 32]>,
    pub client_identity: Option<busbar_contract::secret_ref::SecretRef>,
    pub trust: Option<std::sync::Arc<crate::plugin_config::TrustAnchor>>,
}
pub trait Upstreams: Send + Sync + 'static {
    fn get(&self, name: &str) -> Option<std::sync::Arc<UpstreamDef>>;
}
