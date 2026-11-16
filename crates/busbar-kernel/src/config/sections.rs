// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::{Deserialize, Serialize};

use busbar_kernel_ledger::cost::UnitRate;

use super::limits::{DEFAULT_RATE_SWEEP_INTERVAL, DEFAULT_USAGE_FLUSH_INTERVAL_MS};

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
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
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
    /// `limits` beside `module` (IF §12.22), as written: parsed and stripped by [`super::min3::parse_min3`].
    #[serde(default, deserialize_with = "busbar_contract::yaml::untyped_option")]
    pub limits: Option<busbar_contract::yaml::Value>,
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
            limits: Option<&'a busbar_contract::yaml::Value>,
            #[serde(skip_serializing_if = "Option::is_none")]
            insecure_transport: Option<&'a busbar_contract::yaml::Value>,
        }
        View {
            module: &self.module,
            settings: self.settings.authoring(seal),
            limits: self.limits.as_ref(),
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

/// A top-level `secrets:` entry — MODULE-LEVEL initialization config for a `kind: secret` plugin,
/// keyed by the module NAME (alias or canonical). This is the delivery path for the config a secret
/// plugin needs in its `open()` (a Vault plugin's address / namespace / auth token / TLS CA), exactly
/// as `store.settings` carries a store plugin's `open()` config. WITHOUT this block a `kind: secret`
/// plugin's `open()` receives `{}`, forcing operators to repeat every piece of module config in EVERY
/// individual `SecretRef.settings` (multiplying exposure of the Vault address/token). The built-in
/// `env` / `file` modules take no module config and MUST NOT appear here (validated).
///
/// The `settings` are resolved against the BUILT-IN `env` / `file` secret resolvers ONLY (so
/// `{ token: { env: VAULT_TOKEN } }` works) — NEVER against another secret plugin, which would be a
/// bootstrap cycle (a secret module cannot resolve its OWN config through itself).
///
/// # FREEZE BLOCKER: `secrets:` IS A DELIBERATE EXEMPTION FROM THE NAMED-INSTANCE PATTERN
///
/// Every OTHER plugin-instance kind in 1.5.3 is a top-level NAMED-DEFINITION map — `hooks:`,
/// `identity-providers:`, `export:`, `store:` are all `name → {module, settings, …}` and are
/// referenced by bare name. **`secrets:` is deliberately NOT, and must stay that way.**
///
/// The reason is that `secrets:` does not configure an INSTANCE. It configures a MODULE's `open()` —
/// the one-time initialization of the secret backend itself. There is nothing to reference by name:
/// a `SecretRef` already names its module (`{ module: vault, settings: {…} }`), and the entry here
/// supplies the module-wide half of that module's configuration. Wrapping it in a named map would
/// invent an instance identity that no reference site can use, and would then require every
/// `SecretRef` in the config to be rewritten to point at an instance name instead of a module — a
/// large break that buys nothing.
///
/// This is recorded HERE, on the struct, precisely so nobody later "fixes" the inconsistency: the
/// module-keyed shape is the correct shape for module-level `open()` config, and it is frozen.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct SecretModuleCfg {
    /// The module's own opaque module-level settings, delivered to the plugin's `open()` as its config
    /// JSON. Any `SecretRef`-typed value (e.g. `token: { env: VAULT_TOKEN }`) is resolved via the
    /// built-in env/file modules before it crosses the ABI.
    #[serde(default)]
    pub settings: busbar_contract::plugin_settings::Settings,
    /// `limits` beside the settings (IF §12.22), as written: parsed and stripped by [`super::min3::parse_min3`].
    #[serde(default, deserialize_with = "busbar_contract::yaml::untyped_option")]
    pub limits: Option<busbar_contract::yaml::Value>,
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
            settings: F0,
            #[serde(skip_serializing_if = "Option::is_none")]
            limits: Option<&'a busbar_contract::yaml::Value>,
            #[serde(skip_serializing_if = "Option::is_none")]
            insecure_transport: Option<&'a busbar_contract::yaml::Value>,
        }
        View {
            settings: self.settings.authoring(seal),
            limits: self.limits.as_ref(),
            insecure_transport: self.insecure_transport.as_ref(),
        }
    }
}

/// The `advanced:` block - INTERNAL tuning knobs (formerly under `governance:`). Every field
/// defaults to its historical value; the whole block is normally omitted.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AdvancedCfg {
    /// Amortization interval for the rate-limiter stale-entry sweep: every Nth `check_rate` pays
    /// the full retain (default 256).
    #[serde(default = "default_rate_sweep_interval")]
    pub rate_sweep_interval: u32,
    /// Write-behind flush cadence (ms) for the in-memory usage/budget counters. On an UNGRACEFUL
    /// crash (kill -9 / power loss) at most this many ms of accrued spend/requests can be lost; a
    /// graceful shutdown flushes fully. Default 100.
    #[serde(default = "default_usage_flush_interval_ms")]
    pub usage_flush_interval_ms: u64,
    /// Tokio worker-thread count (`advanced.worker_threads`, migrated from `BUSBAR_WORKER_THREADS`).
    /// A BOOT-TIME knob read once before the runtime is built — not runtime-mutable via the overlay.
    /// Absent (`None`) ⇒ one worker per available core (`available_parallelism`, capped at
    /// `MAX_WORKER_THREADS`). The `BUSBAR_WORKER_THREADS` env var was deprecated in 1.5.3 and removed
    /// in 1.6.0.
    #[serde(default)]
    pub worker_threads: Option<usize>,
    /// Pin the shared upstream client to HTTP/1.1 (`advanced.upstream_http1_only`, migrated from
    /// `BUSBAR_UPSTREAM_HTTP1_ONLY`). BOOT-TIME (client-build) knob; default `false` (ALPN default:
    /// h2 where the backend accepts it, h1 otherwise). The `BUSBAR_UPSTREAM_HTTP1_ONLY` env var was
    /// deprecated in 1.5.3 and removed in 1.6.0.
    #[serde(default)]
    pub upstream_http1_only: bool,
    /// Force HTTP/2 prior-knowledge to cleartext upstreams (`advanced.upstream_h2_prior_knowledge`,
    /// migrated from `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE`). BOOT-TIME (client-build) knob; default
    /// `false` — prior-knowledge h2c measurably HURT throughput in perf testing. The
    /// `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` env var was deprecated in 1.5.3 and removed in 1.6.0.
    #[serde(default)]
    pub upstream_h2_prior_knowledge: bool,
    /// The `advanced.response_headers:` block — opt-in toggles for every busbar-INJECTED response
    /// header. Every busbar-injected header is a fingerprint an unauthenticated client
    /// can observe on every response, so each one is OFF by default and an operator opts IN
    /// per-header. See `docs/observability.md#response-headers` for the full catalogue. BOOT-TIME
    /// (restart-to-apply), same freezing mechanism as the rest of this struct's non-`Patch`able
    /// fields: `server_timing` is baked into router middleware state at process start
    /// (`main.rs::apply_common_layers`) and `route_policy` seeds a process-wide `OnceLock` read by
    /// `proxy::wire::maybe_attach_route_policy` — neither is rebuilt by a config apply.
    #[serde(default)]
    pub response_headers: ResponseHeadersCfg,
    /// The destination guard refuses ordinary private-address dials by default. A core-selected
    /// registration may carry its own `allow_private`; configured providers retain reach only to
    /// their own base/token origins. Operator-infrastructure Needs retain their declared-target
    /// policy. Metadata, own-listener protection and TLS policy remain enforced. BOOT-TIME.
    #[serde(default = "default_block_private_addresses")]
    pub block_private_addresses: bool,
    /// The ingresses and load balancers that may state a client's address for it (an IP or a
    /// CIDR each, read by the destination guard's CIDR reader). Their `forwarded_header` is
    /// honoured; nobody else's is. Default empty: the socket peer is the client. BOOT-TIME.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// The one forwarding header read from a trusted proxy: `x-forwarded-for` (default) or
    /// `forwarded`. BOOT-TIME.
    #[serde(default)]
    pub forwarded_header: Option<String>,
    /// The outbound TLS trust store (`advanced.tls`): base roots, global trust anchors and
    /// per-destination entries, selected by the guard-judged dial host. BOOT-TIME.
    #[serde(
        default,
        skip_serializing_if = "super::tls::OutboundTlsCfg::is_default"
    )]
    pub tls: super::tls::OutboundTlsCfg,
    /// `advanced.proxy_resolution`: `local` (default: the guard judges a proxied target by
    /// address and the CONNECT names the judged address) or `proxy` (CONNECT by name; a name that
    /// does not resolve here is the proxy's to check). BOOT-TIME.
    #[serde(default, skip_serializing_if = "is_local_resolution")]
    pub proxy_resolution: super::tls::ProxyResolution,
    /// `advanced.shutdown`: the shutdown drain (SHUTDOWN-HANG F4). BOOT-TIME.
    #[serde(default, skip_serializing_if = "AdvancedShutdownCfg::is_default")]
    pub shutdown: AdvancedShutdownCfg,
    /// `advanced.governance`: governed-admission custody (SHUTDOWN-HANG F4a). BOOT-TIME.
    #[serde(default, skip_serializing_if = "AdvancedGovernanceCfg::is_default")]
    pub governance: AdvancedGovernanceCfg,
}

/// `advanced.shutdown:`. A 1.5.5 config does not set it.
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdvancedShutdownCfg {
    /// The drain budget from the first shutdown signal to exit, a duration (`<n><s|m|h|d>`):
    /// default `20s`, at least `1s`. A value that does not parse, or is below `1s`, refuses boot
    /// (BUSBAR-3117); it is never clamped. A quarter of it is the reserve the drain keeps for
    /// settling, sealing, the journal flush and retirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_timeout: Option<String>,
}

impl AdvancedShutdownCfg {
    pub(crate) fn is_default(&self) -> bool {
        self.drain_timeout.is_none()
    }
}

/// `advanced.governance:`. A 1.5.5 config does not set it.
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdvancedGovernanceCfg {
    /// The most finished governed requests whose spend may await settlement in the store before
    /// new governed admission is refused with `503 durability_unavailable` (`Retry-After: 1`):
    /// an integer, at least 1; default 1,000 per second of `advanced.shutdown.drain_timeout`
    /// (20,000 at the default 20 s). Running requests never count. Below 1 refuses boot
    /// (BUSBAR-3117); it is never clamped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pending_checkpoints: Option<u64>,
}

impl AdvancedGovernanceCfg {
    pub(crate) fn is_default(&self) -> bool {
        self.max_pending_checkpoints.is_none()
    }
}

fn is_local_resolution(r: &super::tls::ProxyResolution) -> bool {
    *r == super::tls::ProxyResolution::Local
}

pub const DEFAULT_BLOCK_PRIVATE_ADDRESSES: bool = true;

pub(crate) fn default_block_private_addresses() -> bool {
    DEFAULT_BLOCK_PRIVATE_ADDRESSES
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
            ..self.guard.clone()
        }
    }
}

impl Default for AdvancedCfg {
    fn default() -> Self {
        Self {
            rate_sweep_interval: default_rate_sweep_interval(),
            usage_flush_interval_ms: default_usage_flush_interval_ms(),
            worker_threads: None,
            upstream_http1_only: false,
            upstream_h2_prior_knowledge: false,
            response_headers: ResponseHeadersCfg::default(),
            block_private_addresses: DEFAULT_BLOCK_PRIVATE_ADDRESSES,
            tls: super::tls::OutboundTlsCfg::default(),
            proxy_resolution: super::tls::ProxyResolution::Local,
            trusted_proxies: Vec::new(),
            forwarded_header: None,
            shutdown: AdvancedShutdownCfg::default(),
            governance: AdvancedGovernanceCfg::default(),
        }
    }
}

pub fn default_rate_sweep_interval() -> u32 {
    DEFAULT_RATE_SWEEP_INTERVAL
}
pub fn default_usage_flush_interval_ms() -> u64 {
    DEFAULT_USAGE_FLUSH_INTERVAL_MS
}

/// The `advanced.response_headers:` block: opt-in toggles for every busbar-INJECTED
/// response header, unified in ONE place instead of each header having its own bespoke gate (or, as
/// `x-busbar-route-policy`/`-target` had before this, NO gate at all). Every field defaults `false`
/// (invisible out of the box) — see each field's doc comment for the header it controls and why it
/// defaults off.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
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
    /// Emit the `x-busbar-route-policy` / `x-busbar-route-target` TRANSPARENCY headers on a response
    /// whose lane was chosen by a non-default routing policy (default `false`). Previously emitted
    /// UNCONDITIONALLY whenever a non-default policy fired (no config gate at all) — the same
    /// fingerprinting concern as `server_timing` above: the header names apply, so it defaults OFF and
    /// an operator opts IN by setting `true`.
    #[serde(default = "default_response_headers_route_policy")]
    pub route_policy: bool,
}

impl Default for ResponseHeadersCfg {
    fn default() -> Self {
        Self {
            server_timing: default_response_headers_server_timing(),
            route_policy: default_response_headers_route_policy(),
        }
    }
}

pub const DEFAULT_RESPONSE_HEADERS_SERVER_TIMING: bool = false;
pub fn default_response_headers_server_timing() -> bool {
    DEFAULT_RESPONSE_HEADERS_SERVER_TIMING
}

pub const DEFAULT_RESPONSE_HEADERS_ROUTE_POLICY: bool = false;
pub fn default_response_headers_route_policy() -> bool {
    DEFAULT_RESPONSE_HEADERS_ROUTE_POLICY
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
    /// `limits` beside `module` (IF §12.22), as written: parsed and stripped by [`super::min3::parse_min3`].
    #[serde(default, deserialize_with = "busbar_contract::yaml::untyped_option")]
    pub limits: Option<busbar_contract::yaml::Value>,
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
            limits: Option<&'a busbar_contract::yaml::Value>,
            #[serde(skip_serializing_if = "Option::is_none")]
            insecure_transport: Option<&'a busbar_contract::yaml::Value>,
        }
        View {
            module: &self.module,
            streams: &self.streams,
            fields: &self.fields,
            durable: &self.durable,
            settings: self.settings.authoring(seal),
            limits: self.limits.as_ref(),
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
