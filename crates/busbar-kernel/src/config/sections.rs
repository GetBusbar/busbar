// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The remaining small top-level config SECTION shapes: `tls:`, `security:`, `store:`,
//! `secrets:`, `advanced:` (with its `response_headers:`), `config:` (management policy and the
//! overlay backend), the `rate_card:` entry and the `export:` definition entry, plus the two
//! listen-address defaults. Plain serde data with their `Default`s. The `export:` LOWERING into
//! typed per-module settings stays in busbar-core (those settings carry a core-owned projection);
//! busbar-core re-exports every item here at its historical `config::` path.

use serde::{Deserialize, Serialize};

use busbar_api::SecretRef;

use super::limits::{DEFAULT_RATE_SWEEP_INTERVAL, DEFAULT_USAGE_FLUSH_INTERVAL_MS};

/// Native inbound TLS configuration for the client↔Busbar hop. Absent (`Config.tls == None`) ⇒
/// Busbar serves plain HTTP exactly as before. Present ⇒ Busbar terminates TLS itself; if
/// `client_ca` is also set, it additionally requires and verifies a client certificate (mTLS).
/// All three values are SECRET REFERENCES (`{ file: … }` / `{ env: … }` / a secret module)
/// resolving to PEM bytes; they are resolved once at startup and any resolve/parse error is fatal
/// (`die`). Key bytes are never logged.
// deny_unknown_fields: a typo under `tls:` - e.g. `client_c:` for `client_ca:` - would
// otherwise be SILENTLY IGNORED, leaving mTLS DISABLED while the operator believes it is on
// (a security downgrade with no diagnostic). Reject any unknown key here so the typo fails boot.
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct TlsCfg {
    /// PEM certificate chain, leaf first (e.g. fullchain.pem), as a secret reference.
    pub cert: SecretRef,
    /// PEM private key matching the leaf cert (PKCS#8, PKCS#1, or SEC1), as a secret reference.
    pub key: SecretRef,
    /// PEM CA bundle to verify client certs against. `Some` ⇒ mTLS required: a client must present
    /// a cert chaining to this CA to complete the handshake at all. `None` ⇒ server-only TLS.
    #[serde(default)]
    pub client_ca: Option<SecretRef>,
}

/// Default listen address for the inbound HTTP server.
pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";

/// Default admin-plane listen address. The admin API (`/api/v1/admin/…`) ALWAYS runs on its own
/// listener, never sharing the data port — the management plane is privileged and stays isolated by
/// default. The default binds LOOPBACK so a zero-config deployment boots (an exposed default would
/// trip the mTLS boot-guard); to manage Busbar off-host, set an exposed `admin_listen` with
/// `admin_tls.client_ca_file` (mTLS) or an explicit `admin_require_mtls: false` waiver.
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

/// The compiled-in store name (`store.module: memory`) - the only store that is not a plugin.
pub const GOVERNANCE_STORE_MEMORY: &str = "memory";

/// The top-level `store:` block: the durable store as `{ module, settings }` - the same
/// module/settings shape as every other plugin instance. `settings` is the store module's OWN
/// config, passed through verbatim (the built-in sqlite plugin reads `db_path` /
/// `busy_timeout_ms`; postgres/valkey read `url`). Absent block = the compiled-in ephemeral RAM
/// store (keys/usage reset on restart).
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StoreCfg {
    /// The store module, by plugin ALIAS or CANONICAL NAME. `memory` (default) is the compiled-in
    /// ephemeral RAM store. Anything else names a STORE PLUGIN resolved from the `plugins.*`
    /// registry - the shipped first-party stores (`sqlite` / `postgres` / `valkey`, canonically
    /// `busbar-store-<x>-plugin`) or a third-party store by its manifest name. A non-`memory` store
    /// REQUIRES `plugins.enabled: true`; anything else is a boot error naming the flag.
    #[serde(default = "default_governance_store")]
    pub module: String,
    /// The module's own opaque settings, passed through verbatim as its config JSON.
    #[serde(default)]
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first.
    pub settings: serde_json::Map<String, serde_json::Value>,
}

impl Default for StoreCfg {
    fn default() -> Self {
        Self {
            module: default_governance_store(),
            settings: serde_json::Map::new(),
        }
    }
}

pub fn default_governance_store() -> String {
    GOVERNANCE_STORE_MEMORY.to_string()
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
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct SecretModuleCfg {
    /// The module's own opaque module-level settings, delivered to the plugin's `open()` as its config
    /// JSON. Any `SecretRef`-typed value (e.g. `token: { env: VAULT_TOKEN }`) is resolved via the
    /// built-in env/file modules before it crosses the ABI.
    #[serde(default)]
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first.
    pub settings: serde_json::Map<String, serde_json::Value>,
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
    /// an `unknown field` boot error (`deny_unknown_fields` on `ObservabilityCfg`) — run
    /// `busbar --migrate-config` to move it. The header is a useful latency probe, but it is also an
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

/// `Server-Timing: busbar` header is SUPPRESSED by default (indistinguishability); operators opt IN.
pub const DEFAULT_RESPONSE_HEADERS_SERVER_TIMING: bool = false;
pub fn default_response_headers_server_timing() -> bool {
    DEFAULT_RESPONSE_HEADERS_SERVER_TIMING
}

/// `x-busbar-route-policy` / `x-busbar-route-target` are SUPPRESSED by default (same fingerprinting
/// concern as `server_timing`); operators opt IN.
pub const DEFAULT_RESPONSE_HEADERS_ROUTE_POLICY: bool = false;
pub fn default_response_headers_route_policy() -> bool {
    DEFAULT_RESPONSE_HEADERS_ROUTE_POLICY
}

/// The top-level `config:` block — config-MANAGEMENT policy (1.5.3). This is DISTINCT from the
/// data-plane `store:` section (where request/usage data lives): `config:` governs whether the admin
/// API may mutate config and WHERE those mutations persist. Absent ⇒ durable-by-default: `locked:
/// false` and an overlay file `busbar-overlay.json` next to the resolved config.yaml, so out of the
/// box admin mutations survive a restart (the 1.5.3 fix for silent RAM-only mutation).
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct ConfigMgmtCfg {
    /// `false` (default) ⇒ MUTABLE: the admin API may change config, and every change persists to the
    /// `overlay` backend. `true` ⇒ IMMUTABLE (GitOps posture): admin-API config mutations are refused
    /// at runtime; `overlay` is irrelevant and ignored. Edit config.yaml + POST /config/reload to
    /// change a locked deployment.
    #[serde(default)]
    pub locked: bool,
    /// WHERE a mutable config's changes persist — a PLUGGABLE backend. Absent ⇒ the default file
    /// backend (`busbar-overlay.json` next to the resolved config.yaml). `overlay: false` disables it
    /// explicitly (only valid together with `locked: true`, else boot refuses — see the boot
    /// invariant). `overlay: { file: <path> }` selects the file backend at a chosen path.
    #[serde(default)]
    pub overlay: Option<OverlayCfg>,
}

/// The `config.overlay` value — either an explicit DISABLE (`overlay: false`) or a named BACKEND
/// (`overlay: { file: <path> }`). Untagged so both YAML forms parse. The map form names the backend
/// by KEY (`file:` today), mirroring the top-level `store: { module, settings }` shape so a second
/// backend (e.g. `db:`) is ADDITIVE, not a breaking reshape.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum OverlayCfg {
    /// `overlay: false` ⇒ no writable overlay backend. Only `false` is meaningful; `true` is rejected
    /// at boot (it names no backend). Reachable-to-boot only with `locked: true`.
    Disabled(bool),
    /// `overlay: { file: <path> }` ⇒ the builtin file backend.
    Backend(OverlayBackend),
}

/// A named overlay backend. Exactly one backend key may be set. Today only `file:` exists; a future
/// durable-store backend slots in as an additive sibling field (`db:`), validated at boot to be
/// mutually exclusive with `file:`.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct OverlayBackend {
    /// File-backend path. Relative paths resolve against the config.yaml directory. Absent ⇒ treated
    /// as "no backend named" (equivalent to disabled).
    #[serde(default)]
    pub file: Option<String>,
}

/// One top-level `rate_card:` entry: the four per-token rates in MICRO-units (1e-6 abstract cost
/// unit) per token, one per pricing tier. A tier omitted in YAML prices at 0 for that tier (e.g. a
/// model with no cache pricing simply omits the cache rates). Values must be finite and >= 0
/// (validated at boot). Floats exist ONLY here at the config boundary: they are converted once at
/// resolve time to integer nano-units per token, and the hot path does pure integer math.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct RateEntryCfg {
    #[serde(default)]
    pub input_utok: f64,
    #[serde(default)]
    pub output_utok: f64,
    #[serde(default)]
    pub cache_read_utok: f64,
    #[serde(default)]
    pub cache_write_utok: f64,
}

impl RateEntryCfg {
    /// This entry's NEUTRAL raw-rate view — the four raw micro-float rates in canonical reserved order
    /// ([`crate::billing::RawTierRates`]). The seam the pricing oracle + routing scalar read rates
    /// through WITHOUT naming this config type's `_utok` grammar: the map values ARE the raw
    /// micro-floats, so this is a pure field lift, byte-identical.
    pub fn raw_tier_rates(&self) -> crate::billing::RawTierRates {
        crate::billing::RawTierRates {
            input: self.input_utok,
            output: self.output_utok,
            cache_read: self.cache_read_utok,
            cache_write: self.cache_write_utok,
        }
    }
}

/// The routing-scalar projection of a rate entry (abstract units per million tokens), fed to the
/// `cheapest` policy and the hook `Candidate.cost_per_mtok` signal: the blended
/// (input + output) / 2 (1 micro-unit/token == 1 unit/mtok, so no further scaling).
///
/// Delegates to the NEUTRAL raw-rate view ([`crate::billing::RawTierRates::blended_per_mtok`])
/// so the routing scalar is computed through the same seam the pricing oracle projects through;
/// byte-identical to the pre-seam `(r.input_utok + r.output_utok) / 2.0`.
pub fn rate_entry_per_mtok(r: &RateEntryCfg) -> f64 {
    r.raw_tier_rates().blended_per_mtok()
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
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)] // a typo'd key must fail boot, not silently disable telemetry.
pub struct ExportDefCfg {
    /// The built-in exporter module backing this instance: `prometheus` | `request-log-webhook` |
    /// `request-log-file` | `otlp` (see [`EXPORT_MODULES`]). An unknown module is a boot error.
    pub module: String,
    /// `streams:` — WHAT this sink subscribes to, as tokens of the frozen
    /// `busbar_plugin_loader::ExportStream` vocabulary. Each stream carries DOCUMENTED
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
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first.
    pub settings: serde_json::Map<String, serde_json::Value>,
}

/// The top-level `export:` NAMED-DEFINITION map: instance name → [`ExportDefCfg`]. Insertion-ordered
/// so the resolved sink order (and therefore delivery order) is deterministic.
pub type ExportDefs = indexmap::IndexMap<String, ExportDefCfg>;

/// `export.<name>.module: prometheus` — the PULL metrics exporter (Metrics stream).
pub const EXPORT_MODULE_PROMETHEUS: &str = "prometheus";
/// `export.<name>.module: request-log-webhook` — the PUSH per-request webhook (Logs stream).
pub const EXPORT_MODULE_REQUEST_LOG_WEBHOOK: &str = "request-log-webhook";
/// `export.<name>.module: request-log-file` — the PUSH per-request JSONL append (Logs stream).
pub const EXPORT_MODULE_REQUEST_LOG_FILE: &str = "request-log-file";
/// `export.<name>.module: otlp` — the OTLP/HTTP trace exporter (Traces stream). Absorbs the DELETED
/// `observability.otlp_url`.
pub const EXPORT_MODULE_OTLP: &str = "otlp";

/// Every built-in `export:` module, for the boot-time unknown-module diagnostic.
pub const EXPORT_MODULES: &[&str] = &[
    EXPORT_MODULE_PROMETHEUS,
    EXPORT_MODULE_REQUEST_LOG_WEBHOOK,
    EXPORT_MODULE_REQUEST_LOG_FILE,
    EXPORT_MODULE_OTLP,
];
