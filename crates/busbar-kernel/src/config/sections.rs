// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::{Deserialize, Serialize};

use busbar_kernel_ledger::cost::UnitRate;

use super::limits::default_usage_flush_interval_ms;

pub use busbar_contract::conn::inbound::TlsCfg;

pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";

pub const DEFAULT_ADMIN_LISTEN_ADDR: &str = "127.0.0.1:8081";

/// Operator-owned security controls (config.yaml `security:` block).
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct SecurityCfg {
    /// Additional hosts/IPs APPENDED to the hardcoded cloud-metadata denylist. A provider `base_url`
    /// resolving to any of these is rejected at boot (unless carved out by an allow-override),
    /// exactly like the built-in metadata endpoints. This is the answer to "an unknown cloud's
    /// metadata IP/hostname is not in the built-in list" — add it here. Entries may be IP literals
    /// (matched against the resolved host, including the obfuscation-decoded forms) or DNS hostnames
    /// (matched case-insensitively, trailing dot stripped). Default empty.
    #[serde(default)]
    pub blocked_metadata_hosts: Vec<String>,
    /// Global SURGICAL allow-override: hosts/IPs to UNBLOCK from the cloud-metadata denylist for ALL
    /// providers. Carves a single exception out of the denylist everywhere (the everywhere-scoped
    /// twin of per-provider `allow_metadata_hosts`). An IP entry also unblocks its obfuscated
    /// spellings, mirroring how a block entry blocks all spellings. Default empty.
    #[serde(default)]
    pub allow_metadata_hosts: Vec<String>,
    /// Nuclear override: when true the cloud-metadata SSRF guard is FULLY DISABLED for every provider
    /// (every metadata/IMDS endpoint becomes reachable). Logs a startup WARNING. Default false.
    #[serde(default)]
    pub allow_all_metadata: bool,
}

/// The top-level `store:` block: the durable store as `{ module, settings }` - the same
/// module/settings shape as every other plugin instance. `settings` is the store module's OWN
/// config, passed through verbatim (the built-in sqlite plugin reads `db_path` /
/// `busy_timeout_ms`; postgres/valkey read `url`). Required: exactly one store resolves
/// from config — a config with no `store:` block is refused
/// with [`store_required`], and no linked row stands in as a default.
///
/// Read as the map form or the positional `[module, settings]` ([`positional`]); `insecure_transport`
/// is only ever a key beside `module` (TRANSPORT-SECURITY-POLICY §4), never a third position.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
#[serde(remote = "Self")]
pub struct StoreCfg {
    /// The store module, by plugin ALIAS or CANONICAL NAME: a linked row's name opens in process; any
    /// other name is a STORE PLUGIN resolved from the `plugins.*` registry - the shipped first-party
    /// stores (canonically `busbar-store-<x>-plugin`) or a third-party store by its manifest name -
    /// and REQUIRES `plugins.enabled: true`; anything else is a boot error naming the flag. Omitted,
    /// it is empty, which `--validate` refuses as 1.5.5 refused an empty one.
    #[serde(default)]
    pub module: String,

    /// The module's own opaque settings, passed through verbatim as its config JSON.
    #[serde(default)]
    pub settings: busbar_contract::plugin_settings::Settings,
    /// `insecure_transport` beside `module` (TRANSPORT-SECURITY-POLICY §4), as written: parsed
    /// and stripped by [`super::min3::parse_min3`].
    #[serde(default, deserialize_with = "busbar_contract::yaml::untyped_option")]
    pub insecure_transport: Option<busbar_contract::yaml::Value>,
}
impl StoreCfg {
    /// Borrow the exact authoring representation under concrete kernel authority.
    pub fn authoring<'a>(
        &'a self,
        seal: &'a busbar_contract::caps::KernelSeal,
    ) -> impl Serialize + 'a {
        #[derive(Serialize)]
        struct View<'a, F0: Serialize> {
            module: &'a String,
            settings: F0,
            #[serde(skip_serializing_if = "Option::is_none")]
            insecure_transport: Option<&'a busbar_contract::yaml::Value>,
        }
        View {
            module: &self.module,
            settings: self.settings.authoring(seal),
            insecure_transport: self.insecure_transport.as_ref(),
        }
    }
}

/// The refusal of a config with no `store:` block (BUSBAR-3120). 1.6.0 has no absent-store default
/// (AGREED QM2, owner 2026-11-15T20:54Z): every config names its store. A 1.5.5 config with no block
/// ran on the store built into 1.5.5, and the one-time upgrade writes that block into it, so only a
/// config already stamped for 1.6.0 reaches this refusal.
pub fn store_required() -> String {
    "store is required; add a `store:` block with the configured Store module and settings. 1.6.0 \
     has no default store: a 1.5.5 config.yaml with no `store:` block is upgraded once with the \
     block 1.5.5 implied, and a config.yaml stamped `config_version: 1` must name its store itself"
        .into()
}

/// The positional reading [`StoreCfg`] and [`SecretModuleCfg`] share: `[module]` or
/// `[module, settings]`, `module` defaulting to empty only where `module_default`. A third item is
/// refused: it would otherwise land in `insecure_transport`, which is a key beside `module`
/// (TRANSPORT-SECURITY-POLICY §4), never a position.
fn positional<'de, A: serde::de::SeqAccess<'de>>(
    mut seq: A,
    module_default: bool,
    expecting: &dyn serde::de::Expected,
) -> Result<(String, busbar_contract::plugin_settings::Settings), A::Error> {
    let module = match seq.next_element::<String>()? {
        Some(module) => module,
        None if module_default => String::new(),
        None => return Err(serde::de::Error::invalid_length(0, expecting)),
    };
    let settings = seq.next_element()?.unwrap_or_default();
    if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
        return Err(serde::de::Error::invalid_length(3, expecting));
    }
    Ok((module, settings))
}

impl<'de> Deserialize<'de> for StoreCfg {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Block;
        impl<'de> serde::de::Visitor<'de> for Block {
            type Value = StoreCfg;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a store block `{ module, settings }` or `[module, settings]`")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<StoreCfg, A::Error> {
                StoreCfg::deserialize(serde::de::value::MapAccessDeserializer::new(map))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, seq: A) -> Result<StoreCfg, A::Error> {
                let (module, settings) = positional(seq, true, &self)?;
                Ok(StoreCfg {
                    module,
                    settings,
                    insecure_transport: None,
                })
            }
        }
        deserializer.deserialize_any(Block)
    }
}

/// A secret instance without `module`: the 1.5.5 module-keyed shape, which the 1.6.0 upgrade
/// (migrate-on-boot) converts by naming the module after the instance key (IF §8.2).
pub(crate) const MODULE_KEYED_SECRET: &str = "missing field `module`: a 1.5.5 module-keyed secret \
     instance is converted by the 1.6.0 upgrade, which names `module` after the instance key; boot \
     the unstamped 1.5.5 config once so migrate-on-boot rewrites it, or add `module:` \
     (docs/migration-1.6)";

impl<'de> Deserialize<'de> for SecretModuleCfg {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Block;
        impl<'de> serde::de::Visitor<'de> for Block {
            type Value = SecretModuleCfg;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a secret instance `{ module, settings }` or `[module, settings]`")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<SecretModuleCfg, A::Error> {
                use serde::de::Error as _;
                SecretModuleCfg::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map_err(|error| {
                        // 01149013b8: `module` is required; a 1.5.5 module-keyed instance reaches
                        // 1.6.0 through the upgrade, which names the module after the instance key.
                        if error.to_string().starts_with("missing field `module`") {
                            A::Error::custom(MODULE_KEYED_SECRET)
                        } else {
                            error
                        }
                    })
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                seq: A,
            ) -> Result<SecretModuleCfg, A::Error> {
                let (module, settings) = positional(seq, false, &self)?;
                Ok(SecretModuleCfg {
                    module,
                    settings,
                    insecure_transport: None,
                })
            }
        }
        deserializer.deserialize_any(Block)
    }
}

/// One named secret instance (IF §8.2): its image identity and opaque opening settings.
/// References select the configured map key; shorthands select its unique instance.
/// Read as the map form or the positional `[module, settings]` ([`positional`]), as [`StoreCfg`].
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
#[serde(remote = "Self")]
pub struct SecretModuleCfg {
    /// Admitted image identity or declared former name. Required in canonical 1.6 configuration.
    pub module: String,
    /// The module's own opaque module-level settings, delivered to the plugin's `open()` as its config
    /// JSON. Any `SecretRef`-typed value (e.g. `token: { env: VAULT_TOKEN }`) is resolved via the
    /// built-in env/file modules before it crosses the ABI.
    #[serde(default)]
    pub settings: busbar_contract::plugin_settings::Settings,
    /// `insecure_transport` beside the settings (TRANSPORT-SECURITY-POLICY §4), as written: parsed
    /// and stripped by [`super::min3::parse_min3`].
    #[serde(default, deserialize_with = "busbar_contract::yaml::untyped_option")]
    pub insecure_transport: Option<busbar_contract::yaml::Value>,
}
impl SecretModuleCfg {
    /// Borrow the exact authoring representation under concrete kernel authority.
    pub fn authoring<'a>(
        &'a self,
        seal: &'a busbar_contract::caps::KernelSeal,
    ) -> impl Serialize + 'a {
        #[derive(Serialize)]
        struct View<'a, F0: Serialize> {
            module: &'a str,
            settings: F0,
            #[serde(skip_serializing_if = "Option::is_none")]
            insecure_transport: Option<&'a busbar_contract::yaml::Value>,
        }
        View {
            module: &self.module,
            settings: self.settings.authoring(seal),
            insecure_transport: self.insecure_transport.as_ref(),
        }
    }
}

/// The `advanced:` block: the durability tuning (`usage_flush_interval_ms`) and nothing else an
/// operator chooses. Every other key here is an old one: REMOVED (no longer a setting, ignored)
/// or MOVED (read, then carried to its own section when the document is read,
/// [`super::DeployCfg::carry_moved`]). Neither kind is ever written back.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AdvancedCfg {
    /// MOVED to top-level `shutdown`.
    #[serde(default, skip_serializing)]
    pub shutdown: Option<super::shutdown::ShutdownCfg>,
    /// REMOVED (was the budget-table sweep cadence): accepted from an old configuration, ignored,
    /// never written back; [`AdvancedCfg::removed`] names it so `config::resolve` logs one line.
    #[serde(default, skip_serializing)]
    pub rate_sweep_interval: Option<serde::de::IgnoredAny>,
    /// Write-behind flush cadence (ms) for the in-memory usage/budget counters. On an UNGRACEFUL
    /// crash (kill -9 / power loss) at most this many ms of accrued spend/requests can be lost; a
    /// graceful shutdown flushes fully. Default 100.
    #[serde(default = "default_usage_flush_interval_ms")]
    pub usage_flush_interval_ms: u64,
    /// Release a metered response only after its audit line is committed
    /// (`advanced.wait_for_commit`). Off by default: the line goes to the request's core outbox
    /// and is committed with every core's lines by the flusher every `usage_flush_interval_ms`, so
    /// an ungraceful crash can lose the lines of the last unflushed interval. On: the response's
    /// last byte waits for the group commit that holds its line. Money is recorded the same way in
    /// both modes. Administrative changes wait either way. Read from the generation a request was
    /// admitted under. A configuration without the key behaves as `false`.
    #[serde(default)]
    pub wait_for_commit: bool,
    /// REMOVED (was the data-plane worker count; the engine runs [`data_workers`]): accepted from
    /// an old configuration, ignored, never written back; named by [`AdvancedCfg::removed`].
    #[serde(default, skip_serializing)]
    pub worker_threads: Option<serde::de::IgnoredAny>,
    /// MOVED to `outbound.http1_only`.
    #[serde(default, skip_serializing)]
    pub upstream_http1_only: Option<bool>,
    /// MOVED to `outbound.h2_prior_knowledge`.
    #[serde(default, skip_serializing)]
    pub upstream_h2_prior_knowledge: Option<bool>,
    /// MOVED to `telemetry.response_headers`.
    #[serde(default, skip_serializing)]
    pub response_headers: Option<ResponseHeadersCfg>,
    /// MOVED to `outbound.block_private_addresses`.
    #[serde(default, skip_serializing)]
    pub block_private_addresses: Option<bool>,
    /// MOVED to `client_address.trusted_proxies`.
    #[serde(default, skip_serializing)]
    pub trusted_proxies: Option<Vec<String>>,
    /// MOVED to `client_address.header`.
    #[serde(default, skip_serializing)]
    pub forwarded_header: Option<String>,
    /// MOVED to `outbound.tls`.
    #[serde(default, skip_serializing)]
    pub tls: Option<super::tls::OutboundTlsCfg>,
    /// MOVED to `outbound.proxy_resolution`.
    #[serde(default, skip_serializing)]
    pub proxy_resolution: Option<super::tls::ProxyResolution>,
    /// REMOVED (was the global destination allowlist): accepted from an old configuration, ignored,
    /// never written back; [`AdvancedCfg::removed`] names it so `config::resolve` logs one line.
    #[serde(default, skip_serializing)]
    pub allow_destinations: Option<serde::de::IgnoredAny>,
}

fn is_local_resolution(r: &super::tls::ProxyResolution) -> bool {
    *r == super::tls::ProxyResolution::Local
}

pub const DEFAULT_BLOCK_PRIVATE_ADDRESSES: bool = true;

pub(crate) fn default_block_private_addresses() -> bool {
    DEFAULT_BLOCK_PRIVATE_ADDRESSES
}

/// The top-level `outbound:` section: how the engine dials out. Every key is read once at boot
/// (restart to apply).
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OutboundCfg {
    /// The destination guard refuses ordinary private-address dials (default `true`). A GLOBAL
    /// switch, kept until per-registration private reach replaces it: a core-selected
    /// registration may carry its own `allow_private`; configured providers retain reach only to
    /// their own base/token origins; operator-infrastructure Needs retain their declared-target
    /// policy. Metadata, own-listener protection and TLS policy remain enforced either way.
    #[serde(default = "default_block_private_addresses")]
    pub block_private_addresses: bool,
    /// The outbound TLS trust store: base roots, global trust anchors and per-destination entries,
    /// selected by the guard-judged dial host.
    #[serde(
        default,
        skip_serializing_if = "super::tls::OutboundTlsCfg::is_default"
    )]
    pub tls: super::tls::OutboundTlsCfg,
    /// `local` (default: the guard judges a proxied target by address and the CONNECT names the
    /// judged address) or `proxy` (CONNECT by name; a name that does not resolve here is the
    /// proxy's to check).
    #[serde(default, skip_serializing_if = "is_local_resolution")]
    pub proxy_resolution: super::tls::ProxyResolution,
    /// Speak only HTTP/1.1 to upstreams (default `false`: TLS negotiates h2 or http/1.1 by ALPN,
    /// cleartext is http/1.1). Dealt to the HTTP transport under the settings path its schema
    /// names (`advanced.upstream_http1_only`). Wins when `h2_prior_knowledge` is also true.
    #[serde(default)]
    pub http1_only: bool,
    /// Speak HTTP/2 without negotiation, including to cleartext upstreams (default `false`). Dealt
    /// to the HTTP transport under `advanced.upstream_h2_prior_knowledge`.
    #[serde(default)]
    pub h2_prior_knowledge: bool,
}

impl Default for OutboundCfg {
    fn default() -> Self {
        Self {
            block_private_addresses: DEFAULT_BLOCK_PRIVATE_ADDRESSES,
            tls: super::tls::OutboundTlsCfg::default(),
            proxy_resolution: super::tls::ProxyResolution::Local,
            http1_only: false,
            h2_prior_knowledge: false,
        }
    }
}

/// The top-level `client_address:` section: who may state a client's address for it. Read once
/// at boot (restart to apply).
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientAddressCfg {
    /// The ingresses and load balancers that may state a client's address (an IP or a CIDR each).
    /// Their `header` is honoured; nobody else's is. Default empty: the socket peer is the client.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxies: Vec<String>,
    /// The one forwarding header read from a trusted proxy: `x-forwarded-for` (default) or
    /// `forwarded`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

/// The `advanced` keys that moved to their own section: the old key (under `advanced`) and its new
/// home. The one place a move is worded ([`moved_advanced_line`]).
pub const MOVED_ADVANCED: [(&str, &str); 9] = [
    ("shutdown.deregister_delay", "shutdown.deregister_delay"),
    ("trusted_proxies", "client_address.trusted_proxies"),
    ("forwarded_header", "client_address.header"),
    ("tls", "outbound.tls"),
    ("proxy_resolution", "outbound.proxy_resolution"),
    (
        "block_private_addresses",
        "outbound.block_private_addresses",
    ),
    ("upstream_http1_only", "outbound.http1_only"),
    ("upstream_h2_prior_knowledge", "outbound.h2_prior_knowledge"),
    (
        "response_headers.server_timing",
        "telemetry.response_headers.server_timing",
    ),
];

/// The line said when an old configuration carries `advanced.<old>`: carried over, or ignored
/// because the new home is written too (it wins).
#[must_use]
pub fn moved_advanced_line(old: &str, carried: bool) -> String {
    let new = MOVED_ADVANCED
        .iter()
        .find(|(from, _)| *from == old)
        .map_or(old, |(_, to)| to);
    if carried {
        format!("advanced.{old} moved to {new}; the value was carried over")
    } else {
        format!("advanced.{old} moved to {new}; {new} is also written and wins, the old value is ignored")
    }
}

/// THE DESTINATION GUARD'S INPUTS, as one deployment states them (`RootCfg::destinations`): the
/// connector builds its one guard from these. `Default` blocks nothing: state the owner default
/// (`block_private_addresses: true`) where it is meant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Destinations {
    /// `advanced.block_private_addresses`.
    pub block_private_addresses: bool,
    /// `security.blocked_metadata_hosts`: extra refusals inside the one guard.
    pub blocked: Vec<String>,
    /// The engine's own listen addresses as configured (`listen`, `admin_listen`): the front door
    /// no plugin connection may reach, in any class (IF 12.1).
    pub listens: Vec<String>,
}

impl super::RootCfg {
    /// The guard's inputs. The 1.5.5 cloud-metadata carve-outs (`security.allow_metadata_hosts`,
    /// `security.allow_all_metadata`, a provider's `allow_metadata_hosts`) are retired and refused
    /// at validation (BUSBAR-3136): cloud metadata is refused for every outbound connection, so none
    /// reaches the guard.
    #[must_use]
    pub fn destinations(&self) -> Destinations {
        Destinations {
            blocked: self.blocked_metadata_hosts.clone(),
            listens: self.own_listens().map(str::to_owned).to_vec(),
            ..self.guard.clone()
        }
    }

    /// The addresses the engine's own listeners take, as configured: the data door (`listen`)
    /// and the admin surface (`admin_listen`). The one source of both own-port lists.
    #[must_use]
    pub fn own_listens(&self) -> [&str; 2] {
        [self.listen.as_str(), self.admin_listen.as_str()]
    }
}

impl Default for AdvancedCfg {
    fn default() -> Self {
        Self {
            shutdown: None,
            rate_sweep_interval: None,
            usage_flush_interval_ms: default_usage_flush_interval_ms(),
            wait_for_commit: false,
            worker_threads: None,
            upstream_http1_only: None,
            upstream_h2_prior_knowledge: None,
            response_headers: None,
            block_private_addresses: None,
            tls: None,
            proxy_resolution: None,
            trusted_proxies: None,
            forwarded_header: None,
            allow_destinations: None,
        }
    }
}

/// The most worker threads the engine will start: the most the Tokio multi-thread scheduler can
/// run. It keeps its count of searching workers in the low 16 bits of one atomic word
/// (`UNPARK_SHIFT = 16` in `runtime/scheduler/multi_thread/idle.rs`), so 65,535 is its limit.
/// The engine's own earlier ceiling of 128 protected an audit write-through reserve that no longer
/// exists, so nothing the engine owns bounds the count any lower.
pub const MAX_WORKER_THREADS: usize = u16::MAX as usize;

/// THE DATA-PLANE WORKER COUNT, the one place it is decided: one worker per CPU core this process
/// may use. `std::thread::available_parallelism` reads the process's CPU affinity and, on Linux,
/// the cgroup v1/v2 CPU quota, so a container gets its CPU limit and a pinned process its cpuset.
/// Where the operating system cannot say, one worker. Never more than the runtime can run
/// ([`MAX_WORKER_THREADS`]). No setting chooses it: an operator who wants fewer workers sets the
/// CPU limit or affinity the platform already provides.
#[must_use]
pub fn data_workers() -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(MAX_WORKER_THREADS)
}

/// The `advanced` keys that are no longer settings, each with what the engine does instead: the
/// one place that is worded. An old configuration carrying one still loads (the configuration
/// file, a settings patch, a document edit), and `config::resolve` says this line once per key.
pub const REMOVED_ADVANCED: [(&str, &str); 3] = [
    (
        "allow_destinations",
        "a private address is reached only by a registration that sets its own allow_private, \
         or by a provider's own origin",
    ),
    (
        "rate_sweep_interval",
        "the budget tables are swept on the usage writer's tick (advanced.usage_flush_interval_ms), \
         releasing every entry that holds nothing unwritten and whose window has passed",
    ),
    (
        "worker_threads",
        "the engine runs one data worker per CPU core it may use (its CPU affinity and container \
         CPU limit); to run fewer, lower the CPU limit",
    ),
];

/// The line said for a removed `advanced` key an old configuration carries.
#[must_use]
pub fn removed_advanced_line(key: &str) -> Option<String> {
    REMOVED_ADVANCED
        .iter()
        .find(|(removed, _)| *removed == key)
        .map(|(removed, instead)| {
            format!("advanced.{removed} is no longer a setting and is ignored: {instead}")
        })
}

impl AdvancedCfg {
    /// The removed keys this block still carries (an old configuration), in [`REMOVED_ADVANCED`]
    /// order.
    pub fn removed(&self) -> impl Iterator<Item = &'static str> + '_ {
        let Self {
            allow_destinations,
            rate_sweep_interval,
            worker_threads,
            ..
        } = self;
        [
            ("allow_destinations", allow_destinations.is_some()),
            ("rate_sweep_interval", rate_sweep_interval.is_some()),
            ("worker_threads", worker_threads.is_some()),
        ]
        .into_iter()
        .filter_map(|(key, carried)| carried.then_some(key))
    }
}

/// The `advanced.response_headers:` block: opt-in toggles for every busbar-INJECTED
/// response header, unified in ONE place instead of each header having its own bespoke gate. Every field defaults `false`
/// (invisible out of the box) — see each field's doc comment for the header it controls and why it
/// defaults off.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeadersCfg {
    /// Emit the `Server-Timing: busbar;dur=<ms>` response header (default `false`). MIGRATED from
    /// the 1.5.x `observability.emit_server_timing`; the old key is now
    /// an `unknown field` boot error (`deny_unknown_fields` on `ObservabilityCfg`); the boot's one-time
    /// upgrade of a 1.5.x config.yaml moves it. The header is a useful latency probe, but it is also an
    /// in-band busbar fingerprint on an otherwise anti-fingerprinting gateway — and the one
    /// fingerprint observable by an UNAUTHENTICATED client on every response — so it defaults OFF to
    /// preserve backend-facing indistinguishability. Operators who want the latency probe (and accept
    /// the product tell) opt IN by setting `true`.
    #[serde(default = "default_response_headers_server_timing")]
    pub server_timing: bool,
}

impl Default for ResponseHeadersCfg {
    fn default() -> Self {
        Self {
            server_timing: default_response_headers_server_timing(),
        }
    }
}

pub const DEFAULT_RESPONSE_HEADERS_SERVER_TIMING: bool = false;
pub fn default_response_headers_server_timing() -> bool {
    DEFAULT_RESPONSE_HEADERS_SERVER_TIMING
}

/// Runtime config-management policy. Mutations persist exclusively through the base-config
/// `store:` instance; the Store's own durability determines whether they survive restart.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct ConfigMgmtCfg {
    /// `false` (default) permits admin config mutations persisted through the configured Store.
    /// `true` selects immutable/GitOps management: edit config.yaml and reload instead.
    #[serde(default)]
    pub locked: bool,
}

/// How many request headers `records.labels` may name (ADMIN-API-1.6 §3.5).
pub const RECORDS_LABELS_MAX: usize = 8;

/// Request headers that carry a credential: never a label, since a label is sealed into the audit
/// chain and published with it.
const RECORDS_LABELS_REFUSED: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "x-admin-token",
];

/// `records.user` (ADMIN-API-1.6 §3.5): what a unit's record keeps of the end user the plane
/// projected. `off` (the default) keeps nothing.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RecordsUser {
    /// Nothing is kept.
    #[default]
    Off,
    /// `"u_" + hex(HMAC-SHA256(K_user, value)[..16])`, `K_user` derived from the deployment keyset.
    Pseudonymous,
    /// The value itself, cut to 128 bytes on a character boundary.
    Plain,
}

impl RecordsUser {
    /// The configured spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RecordsUser::Off => "off",
            RecordsUser::Pseudonymous => "pseudonymous",
            RecordsUser::Plain => "plain",
        }
    }
}

/// The top-level `records:` block (ADMIN-API-1.6 §3.5): what `/records` keeps of each unit beyond
/// the engine's own facts. Never an aggregation dimension. Both parts are off by default, and off
/// costs a unit nothing. Read at boot.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(try_from = "RecordsDoc")]
pub struct RecordsCfg {
    /// `records.user`.
    pub user: RecordsUser,
    /// `records.labels`: request header names whose values each record keeps verbatim (at most
    /// [`RECORDS_LABELS_MAX`], each a header name at most once, none carrying a credential).
    pub labels: Vec<String>,
}

/// `records:` as written, before [`RecordsCfg`]'s checks.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordsDoc {
    #[serde(default)]
    user: RecordsUser,
    #[serde(default)]
    labels: Vec<String>,
}

impl TryFrom<RecordsDoc> for RecordsCfg {
    type Error = String;

    fn try_from(doc: RecordsDoc) -> Result<Self, String> {
        if doc.labels.len() > RECORDS_LABELS_MAX {
            return Err(format!(
                "records.labels names {} headers; at most {RECORDS_LABELS_MAX} are kept",
                doc.labels.len()
            ));
        }
        for (at, name) in doc.labels.iter().enumerate() {
            let token = !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
            if !token {
                return Err(format!("records.labels: `{name}` is not a header name"));
            }
            if doc.labels[..at]
                .iter()
                .any(|n| n.eq_ignore_ascii_case(name))
            {
                return Err(format!("records.labels names `{name}` twice"));
            }
            if RECORDS_LABELS_REFUSED
                .iter()
                .any(|refused| refused.eq_ignore_ascii_case(name))
            {
                return Err(format!(
                    "records.labels: `{name}` carries a credential and is never sealed into a record"
                ));
            }
        }
        Ok(RecordsCfg {
            user: doc.user,
            labels: doc.labels,
        })
    }
}

/// One top-level `rate_card:` entry: the four per-token rates in MICRO-units (1e-6 abstract cost
/// unit) per token, one per pricing tier. An omitted (or `null`) `cache_write_utok` means "no
/// separate write tariff": cache writes price at `input_utok` ([`RateEntryCfg::cache_write_rate`]),
/// the floor every provider bills a write at, so an unpriced write never silently bills 0. An
/// explicit `0` is a configured free class; it reaches this type only through the admin API or a
/// version-2 overlay, because a root `rate_card:` YAML `0` is the 1.5.5 spelling of "no separate
/// tariff" and is removed before parse ([`zero_cache_write_models`]). Any other tier omitted in YAML
/// prices at 0 for that tier (e.g. a model with no cache-read pricing simply omits that rate).
/// Values must be finite and >= 0 (validated at boot). Floats exist ONLY here at the config
/// boundary: [`RateEntryCfg::raw_tier_rates`] converts them ONCE, exactly, to integer nano-units per
/// token, and nothing past it carries a float.
///
/// `units:` prices the OPEN meter classes a plane declares on this lane — a rerank's
/// `search_units`, an a2a `hops` — keyed by the class string, each rate in micro-units per unit like
/// the four above but parsed EXACTLY, with no float, straight into the card's integer nano-unit
/// representation ([`UnitRate`]). Absent ⇒ no open class is priced
/// here, and a hit on one refuses (#42). A reserved class named under `units:` is refused at boot
/// (it would be priced twice). Omitted from the serialized form when empty, so an existing card
/// round-trips byte-identically.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct RateEntryCfg {
    #[serde(default)]
    pub input_utok: f64,
    #[serde(default)]
    pub output_utok: f64,
    #[serde(default)]
    pub cache_read_utok: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write_utok: Option<f64>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub units: std::collections::BTreeMap<String, UnitRate>,
}

impl RateEntryCfg {
    /// The cache-write rate this entry prices at: the configured `cache_write_utok`, else
    /// `input_utok` (an omitted write rate means "no separate write tariff", never 0).
    pub fn cache_write_rate(&self) -> f64 {
        self.cache_write_utok.unwrap_or(self.input_utok)
    }

    pub fn raw_tier_rates(&self) -> busbar_contract::billing::RawTierRates {
        let nanos = busbar_kernel_ledger::cost::representable_nano_rate;
        busbar_contract::billing::RawTierRates {
            input: nanos(self.input_utok),
            output: nanos(self.output_utok),
            cache_read: nanos(self.cache_read_utok),
            cache_write: nanos(self.cache_write_rate()),
        }
    }
}

/// The models of a root `rate_card:` mapping whose `cache_write_utok` is the number 0 (`0` or
/// `0.0`). In a root `rate_card:` that spelling is 1.5.5's "no separate write tariff" (1.5.5 billed
/// Chat cache writes inside the input and wrote `0` into every card), never a free write class. The
/// one predicate both the startup/migration unfold and the reload refusal use, so they cover the
/// same keys: root entries only (plane `rate_card:` blocks are not 1.5.5 shapes), and only a
/// number (a non-number is refused downstream as written).
pub fn zero_cache_write_models(root: &busbar_contract::yaml::Pairs) -> Vec<String> {
    use busbar_contract::yaml::{MappingExt as _, Value, ValueExt as _};
    let Some(card) = root.get_key("rate_card").and_then(Value::as_mapping) else {
        return Vec::new();
    };
    card.iter()
        .filter(|(_, entry)| {
            entry
                .get("cache_write_utok")
                .and_then(Value::as_f64)
                .is_some_and(|rate| rate == 0.0)
        })
        .filter_map(|(model, _)| model.as_str())
        .filter(|model| !model.contains(busbar_kernel_ledger::cost::PLANE_LANE_SEP))
        .map(str::to_owned)
        .collect()
}

pub fn rate_entry_per_mtok(r: &RateEntryCfg) -> f64 {
    (r.input_utok + r.output_utok) / 2.0
}

/// One entry in the top-level `export:` NAMED-DEFINITION map (1.5.3). The map KEY is the
/// exporter INSTANCE name; `module:` says which built-in exporter backs it and `settings:` is the
/// opaque per-module bag — the SAME shape as `hooks:` / `identity-providers:` / `store:`.
///
/// The whole point of the rename from the retired TYPE-KEYED `export:` block is that the SAME module
/// may back MULTIPLE named instances: two `request-log-webhook`s shipping to two different URLs is a
/// real deployment (app logs + SIEM) that the type-keyed shape could not express at all.
///
/// The four modules map onto the export-ABI streams: `prometheus` → Metrics (PULL
/// `/metrics`), `request-log-webhook` / `request-log-file` → Logs (PUSH per request), `otlp` →
/// Traces. `otlp` ABSORBS the DELETED `observability:` block's only remaining field (`otlp_url`), so
/// `export:` is now the single telemetry-egress surface.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExportDefCfg {
    /// The built-in exporter module backing this instance: `prometheus` | `request-log-webhook` |
    /// `request-log-file` | `otlp` (see [`EXPORT_MODULES`]). An unknown module is a boot error.
    pub module: String,
    /// `streams:` — WHAT this sink subscribes to, as tokens of the frozen
    /// `busbar_contract::export_stream::ExportStream` vocabulary. Each stream carries DOCUMENTED
    /// DEFAULT FIELDS. Absent ⇒ the streams the instance's `module:` itself carries (which is what
    /// every pre-projection config means), never "nothing".
    ///
    /// Deserialized as RAW STRINGS, not as the typed enum, so every diagnostic is ours: serde's
    /// "unknown variant" could not say that `audit` was REMOVED and why, nor that a stream exists in
    /// the vocabulary but has no producer in this release. Parsed + validated by busbar-core's
    /// `export::projection::resolve_projection`.
    #[serde(default)]
    pub streams: Option<Vec<String>>,
    /// `fields:` — an optional EXHAUSTIVE OVERRIDE of what this sink receives. If present it fully
    /// REPLACES the subscribed streams' default field sets; it is never additive.
    ///
    /// THE ASYMMETRY WITH `hooks:` IS DELIBERATE AND IS A SECURITY PROPERTY. `hooks:` lists COMBINE
    /// ADDITIVELY (see busbar-core's `config::overlay`) because hooks compose BEHAVIOUR. Projections
    /// bound DISCLOSURE, and if `fields:` were additive then a future release that adds a field to a
    /// stream's defaults would SILENTLY WIDEN what every already-configured sink receives. Override
    /// means the operator's list is exhaustive, so a field added next year can never leak into a
    /// sink someone configured today.
    ///
    /// It bounds DISCLOSURE but must not break STRUCTURE: omitting a PINNED field (the join key, the
    /// chain link) is a LOUD config error, never a silent no-op.
    #[serde(default)]
    pub fields: Option<Vec<String>>,
    /// `durable:` — should core SPOOL this sink's records before the request completes (core owns
    /// the completeness guarantee; the exporter drains, delayed and retried, and never blocks a
    /// request)? The key is part of the frozen surface; the spool that backs it is a later unit, so
    /// `true` is a LOUD "not yet implemented" error rather than a promise nothing keeps.
    #[serde(default)]
    pub durable: bool,

    /// The module's own settings bag. OPAQUE at this layer exactly like `hooks.<name>.settings` —
    /// typed per module by busbar-core's `resolve_export`, so a typo inside it still fails boot loudly.
    #[serde(default)]
    pub settings: busbar_contract::plugin_settings::Settings,
    /// `insecure_transport` beside `module` (TRANSPORT-SECURITY-POLICY §4), as written: parsed
    /// and stripped by [`super::min3::parse_min3`].
    #[serde(default, deserialize_with = "busbar_contract::yaml::untyped_option")]
    pub insecure_transport: Option<busbar_contract::yaml::Value>,
}
impl ExportDefCfg {
    /// Borrow the exact authoring representation under concrete kernel authority.
    pub fn authoring<'a>(
        &'a self,
        seal: &'a busbar_contract::caps::KernelSeal,
    ) -> impl Serialize + 'a {
        #[derive(Serialize)]
        struct View<'a, F0: Serialize> {
            module: &'a String,
            streams: &'a Option<Vec<String>>,
            fields: &'a Option<Vec<String>>,
            durable: &'a bool,
            settings: F0,
            #[serde(skip_serializing_if = "Option::is_none")]
            insecure_transport: Option<&'a busbar_contract::yaml::Value>,
        }
        View {
            module: &self.module,
            streams: &self.streams,
            fields: &self.fields,
            durable: &self.durable,
            settings: self.settings.authoring(seal),
            insecure_transport: self.insecure_transport.as_ref(),
        }
    }
}

pub type ExportDefs = indexmap::IndexMap<String, ExportDefCfg>;

/// The `audit.seal_every` default: one page stamp per millisecond (SEALING-FIX §3.4).
pub const DEFAULT_AUDIT_SEAL_EVERY_MS: u64 = 1;

/// The `audit:` block (SEALING-FIX r20 §3.4). BOOT-TIME. A 1.5.5 config does not set it.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditCfg {
    /// How often the audit notary signs the newest audit line's fingerprint, in whole
    /// milliseconds from 1 to 1000, written with no unit (`seal_every: 1`); default 1. One stamp
    /// vouches for every line before it; a crash leaves at most about this long of lines
    /// unstamped (each still durable and linked). Anything else (`0`, `1001`, `-1`, `"1ms"`,
    /// `1.5`) refuses the config.
    #[serde(default = "default_seal_every", deserialize_with = "seal_every_ms")]
    pub seal_every: u64,
}

impl Default for AuditCfg {
    fn default() -> Self {
        AuditCfg {
            seal_every: DEFAULT_AUDIT_SEAL_EVERY_MS,
        }
    }
}

fn default_seal_every() -> u64 {
    DEFAULT_AUDIT_SEAL_EVERY_MS
}

/// `audit.seal_every`: a plain integer from 1 to 1000. Every other form is refused, explained.
fn seal_every_ms<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    struct Ms;
    fn refused<E: serde::de::Error>(got: std::fmt::Arguments<'_>) -> E {
        E::custom(format_args!(
            "audit.seal_every must be a whole number of milliseconds from 1 to 1000 (got {got})"
        ))
    }
    impl serde::de::Visitor<'_> for Ms {
        type Value = u64;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a whole number of milliseconds from 1 to 1000")
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<u64, E> {
            if (1..=1000).contains(&v) {
                Ok(v)
            } else {
                Err(refused(format_args!("{v}")))
            }
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<u64, E> {
            match u64::try_from(v) {
                Ok(v) => self.visit_u64(v),
                Err(_) => Err(refused(format_args!("{v}"))),
            }
        }
        fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<u64, E> {
            Err(refused(format_args!("{v}")))
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<u64, E> {
            Err(refused(format_args!("{v:?}")))
        }
        fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<u64, E> {
            Err(refused(format_args!("{v}")))
        }
    }
    deserializer.deserialize_any(Ms)
}

#[cfg(test)]
mod secret_instance_shape_tests {
    use super::SecretModuleCfg;
    #[test]
    fn a_secret_instance_requires_its_image_separately_from_its_name() {
        let configured: SecretModuleCfg =
            busbar_contract::yaml::from_str("module: source-image\nsettings: {}\n").unwrap();
        assert_eq!(configured.module, "source-image");
        assert!(busbar_contract::yaml::from_str::<SecretModuleCfg>("settings: {}\n").is_err());
        assert!(busbar_contract::yaml::from_str::<SecretModuleCfg>(
            "module: source-image\nunknown: true\n"
        )
        .is_err());
    }
}
