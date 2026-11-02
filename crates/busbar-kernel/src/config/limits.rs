// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::{Deserialize, Serialize};

use super::hooks::default_policy_timeout_ms;
use super::sections::AdvancedCfg;

pub const DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS: u64 = 300;

pub const DEFAULT_REQUEST_BODY_MAX_BYTES: usize = 32 * 1024 * 1024;

pub const REQUEST_BODY_MAX_BYTES_FLOOR: usize = 64 * 1024;

pub const REQUEST_BODY_MAX_BYTES_CEIL: usize = 1024 * 1024 * 1024;

pub const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = DEFAULT_MAX_INBOUND_CONCURRENT;

const _: () = assert!(
    DEFAULT_POOL_MAX_IDLE_PER_HOST >= DEFAULT_MAX_INBOUND_CONCURRENT,
    "the default idle cap must cover the admissible working set"
);

pub const DEFAULT_POOL_IDLE_TIMEOUT_SECS: u64 = 300;

pub const DEFAULT_MAX_INBOUND_CONCURRENT: usize = 8192;

pub const DEFAULT_HARD_DOWN_COOLDOWN_SECS: u64 = 1800;

pub const DEFAULT_MAX_HONORED_RETRY_AFTER_SECS: u64 = 86_400;

pub const DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES: usize =
    busbar_kernel_egress::upstream::UPSTREAM_ERROR_BODY_MAX_BYTES_DEFAULT;

pub const DEFAULT_PLUGIN_FETCH_MAX_BYTES: usize = 256 * 1024 * 1024;

pub const DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

pub const DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS: u64 = 30;

pub const DEFAULT_MAX_TOKENS: u32 = 4096;

pub const DEFAULT_DEFAULT_MAX_TOKENS: u32 = DEFAULT_MAX_TOKENS;

pub const DEFAULT_KEY_GAUGE_LIMIT: usize = 2000;

pub const DEFAULT_RATE_SWEEP_INTERVAL: u32 = 256;

pub const DEFAULT_USAGE_FLUSH_INTERVAL_MS: u64 = 100;

pub const DEFAULT_PROBE_INTERVAL_SECS: u64 = 30;

pub const DEFAULT_PROBE_TIMEOUT_SECS: u64 = 5;

pub fn default_upstream_request_timeout_secs() -> u64 {
    DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS
}
pub fn default_request_body_max_bytes() -> usize {
    DEFAULT_REQUEST_BODY_MAX_BYTES
}
pub fn default_pool_max_idle_per_host() -> usize {
    DEFAULT_POOL_MAX_IDLE_PER_HOST
}
pub fn default_pool_idle_timeout_secs() -> u64 {
    DEFAULT_POOL_IDLE_TIMEOUT_SECS
}
pub fn default_max_inbound_concurrent() -> usize {
    DEFAULT_MAX_INBOUND_CONCURRENT
}

pub fn default_max_keys_per_principal() -> usize {
    0
}

pub fn default_max_auto_provisioned_groups() -> usize {
    0
}
pub fn default_hook_content_max_bytes() -> usize {
    crate::hooks::DEFAULT_HOOK_CONTENT_MAX_BYTES
}
pub fn default_hard_down_cooldown_secs() -> u64 {
    DEFAULT_HARD_DOWN_COOLDOWN_SECS
}
pub fn default_max_honored_retry_after_secs() -> u64 {
    DEFAULT_MAX_HONORED_RETRY_AFTER_SECS
}
pub fn default_upstream_error_body_max_bytes() -> usize {
    DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES
}
pub fn default_tls_handshake_timeout_secs() -> u64 {
    DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS
}
pub fn default_request_body_read_timeout_secs() -> u64 {
    DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS
}
pub fn default_default_max_tokens() -> u32 {
    DEFAULT_DEFAULT_MAX_TOKENS
}
pub fn default_key_gauge_limit() -> usize {
    DEFAULT_KEY_GAUGE_LIMIT
}
pub fn default_rate_sweep_interval() -> u32 {
    DEFAULT_RATE_SWEEP_INTERVAL
}
pub fn default_usage_flush_interval_ms() -> u64 {
    DEFAULT_USAGE_FLUSH_INTERVAL_MS
}
pub fn default_probe_interval_secs() -> u64 {
    DEFAULT_PROBE_INTERVAL_SECS
}
pub fn default_probe_timeout_secs() -> u64 {
    DEFAULT_PROBE_TIMEOUT_SECS
}

/// The `limits:` block — global operational caps. Each field defaults to its historical behavior,
/// so an absent field (or an absent block) changes nothing. Optional opt-in caps default to unset.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LimitsCfg {
    #[serde(default = "default_upstream_request_timeout_secs")]
    pub upstream_request_timeout_secs: u64,
    /// Max accepted inbound body (bytes). COUPLED: also drives the egress translate-body cap
    /// (`limits::translate_body_max_bytes`) — one knob feeds both so an accepted request is
    /// always buffer-translatable on egress.
    #[serde(default = "default_request_body_max_bytes")]
    pub request_body_max_bytes: usize,
    /// Advanced opt-in byte limit per datagram LINE pairing. Counts combined retained requested
    /// capacity across both directions, including queued output ownership and metadata. Omitted
    /// or null = unlimited by this mechanism; a configured value must be positive. Exhaustion
    /// closes only the affected connection. This is not a process RSS limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datagram_line_memory_bytes: Option<usize>,
    #[serde(default = "default_pool_max_idle_per_host")]
    pub pool_max_idle_per_host: usize,
    /// Idle keep-alive lifetime (seconds) for pooled upstream connections — see
    /// `DEFAULT_POOL_IDLE_TIMEOUT_SECS` for the 300s (vs reqwest's implicit 90s) rationale.
    #[serde(default = "default_pool_idle_timeout_secs")]
    pub pool_idle_timeout_secs: u64,
    /// Inbound concurrency cap. `0` (default) = unlimited: NO layer is added (a true no-op). When
    /// `>0`, a `tower` global concurrency limit wraps the router as the outermost layer.
    #[serde(default = "default_max_inbound_concurrent")]
    pub max_inbound_concurrent: usize,
    /// Cap on how many keys may be BOUND TO ONE GROUP — the anti-sprawl mitigation for self-service
    /// minting. Because a `user:<sub>` leaf group IS the principal, this is
    /// effectively "max keys per principal": a self-issued mint into a group already holding this
    /// many keys is a `409`. `0` (default) = UNLIMITED (today's behavior — an absent knob changes
    /// nothing). Enforced at `POST /keys` only; keys already present are never retroactively revoked.
    #[serde(default = "default_max_keys_per_principal")]
    pub max_keys_per_principal: usize,
    /// Cap on how many groups `POST /keys` may AUTO-PROVISION (`parent:` self-service). The
    /// key-count cap bounds keys per group but says nothing about the number of GROUPS, so a
    /// `mint`-scope credential could grow the limit tree without bound — every new `user:<sub>`
    /// leaf is a new bucket in the enforcement chain, the version log and the persisted overlay
    /// Counted over the WHOLE runtime (overlay) group set, since that is what
    /// auto-provisioning grows. `0` (default) = UNLIMITED (an absent knob changes nothing).
    /// Explicitly configured groups are unaffected: the ceiling gates auto-provisioning only.
    #[serde(default = "default_max_auto_provisioned_groups")]
    pub max_auto_provisioned_groups: usize,
    /// Ceiling, in bytes, on the request CONTENT a hook holding a `prompt: ro|rw` grant is shown in
    /// one projection (default 65536). Over-cap content is OMITTED WHOLE — never truncated
    /// mid-value, because a guardrail that screens half a payload and passes it is worse than one
    /// that refuses — and the hook is sent an EMPTY content projection, which the wire distinguishes
    /// from an ungranted one; the always-present size bucket still reports the real total, so the
    /// omission is visible in the payload rather than silent. `busbar_hook_content_truncated_total`
    /// counts it. This bounds a widening: a content-granted hook now also sees tool-call arguments
    /// and tool-result content, which on an agent request is bounded by neither a context window nor
    /// a token count. `0` = unlimited.
    #[serde(default = "default_hook_content_max_bytes")]
    pub hook_content_max_bytes: usize,
    #[serde(default = "default_hard_down_cooldown_secs")]
    pub hard_down_cooldown_secs: u64,
    #[serde(default = "default_upstream_error_body_max_bytes")]
    pub upstream_error_body_max_bytes: usize,
    #[serde(default = "default_tls_handshake_timeout_secs")]
    pub tls_handshake_timeout_secs: u64,
    /// Max time (seconds) allowed BETWEEN inbound request-body frames before the connection is
    /// dropped - the slow-loris body defense the header-read timeout does not cover. See
    /// `DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS`.
    #[serde(default = "default_request_body_read_timeout_secs")]
    pub request_body_read_timeout_secs: u64,
    #[serde(default = "default_max_honored_retry_after_secs")]
    pub max_honored_retry_after_secs: u64,
    #[serde(default = "default_default_max_tokens")]
    pub default_max_tokens: u32,
    /// Effort-word → thinking-token-budget table for the cross-protocol reasoning carry: what
    /// OpenAI's `reasoning_effort` words mean in tokens when projected onto Anthropic
    /// `thinking.budget_tokens` / Gemini `thinkingBudget` (and, inverted, the bucket thresholds
    /// when a numeric budget is projected onto an effort word). "Medium" is a cost decision, so
    /// operators can override it; defaults 1024/4096/8192/16384.
    #[serde(default)]
    pub reasoning_effort_budgets: ReasoningEffortBudgets,
}

/// The `minimal/low/medium/high` → token-budget table (see `LimitsCfg::reasoning_effort_budgets`).
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReasoningEffortBudgets {
    #[serde(default = "default_reasoning_minimal")]
    pub minimal: u32,
    #[serde(default = "default_reasoning_low")]
    pub low: u32,
    #[serde(default = "default_reasoning_medium")]
    pub medium: u32,
    #[serde(default = "default_reasoning_high")]
    pub high: u32,
}

impl Default for ReasoningEffortBudgets {
    fn default() -> Self {
        Self {
            minimal: default_reasoning_minimal(),
            low: default_reasoning_low(),
            medium: default_reasoning_medium(),
            high: default_reasoning_high(),
        }
    }
}

pub fn default_reasoning_minimal() -> u32 {
    1024
}
pub fn default_reasoning_low() -> u32 {
    4096
}
pub fn default_reasoning_medium() -> u32 {
    8192
}
pub fn default_reasoning_high() -> u32 {
    16384
}

impl Default for LimitsCfg {
    fn default() -> Self {
        Self {
            upstream_request_timeout_secs: default_upstream_request_timeout_secs(),
            request_body_max_bytes: default_request_body_max_bytes(),
            datagram_line_memory_bytes: None,
            pool_max_idle_per_host: default_pool_max_idle_per_host(),
            pool_idle_timeout_secs: default_pool_idle_timeout_secs(),
            max_inbound_concurrent: default_max_inbound_concurrent(),
            max_keys_per_principal: default_max_keys_per_principal(),
            max_auto_provisioned_groups: default_max_auto_provisioned_groups(),
            hook_content_max_bytes: default_hook_content_max_bytes(),
            hard_down_cooldown_secs: default_hard_down_cooldown_secs(),
            upstream_error_body_max_bytes: default_upstream_error_body_max_bytes(),
            tls_handshake_timeout_secs: default_tls_handshake_timeout_secs(),
            request_body_read_timeout_secs: default_request_body_read_timeout_secs(),
            max_honored_retry_after_secs: default_max_honored_retry_after_secs(),
            default_max_tokens: default_default_max_tokens(),
            reasoning_effort_budgets: ReasoningEffortBudgets::default(),
        }
    }
}

/// The `health:` block — process-wide active-probe fallbacks (per-lane `health.interval_secs` /
/// `timeout_secs` still override these).
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HealthDefaultsCfg {
    #[serde(default = "default_probe_interval_secs")]
    pub default_probe_interval_secs: u64,
    #[serde(default = "default_probe_timeout_secs")]
    pub default_probe_timeout_secs: u64,
}

impl Default for HealthDefaultsCfg {
    fn default() -> Self {
        Self {
            default_probe_interval_secs: default_probe_interval_secs(),
            default_probe_timeout_secs: default_probe_timeout_secs(),
        }
    }
}

/// The `routing:` block — the global default policy timeout (per-policy `policy.timeout_ms` still
/// overrides).
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RoutingCfg {
    #[serde(default = "default_policy_timeout_ms")]
    pub default_policy_timeout_ms: u64,
}

impl Default for RoutingCfg {
    fn default() -> Self {
        Self {
            default_policy_timeout_ms: default_policy_timeout_ms(),
        }
    }
}

/// The limit that comes from the resolved `export:` block rather than from `limits:` itself: the
/// per-scrape gauge cap. The `export:` block is
/// lowered in busbar-core (its typed settings carry a core-owned projection), so the resolver hands
/// just these two numbers across; `Default` is the historical pair an export-less config resolves
/// to. busbar-core implements `From<&ExportCfg>` for this so its callers pass the resolved block
/// straight through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportLimits {
    /// Max per-key gauge series emitted per `/metrics` scrape: the `prometheus` instance's setting,
    /// or the historical default with no instance configured.
    pub key_gauge_limit: usize,
}

impl Default for ExportLimits {
    fn default() -> Self {
        Self {
            key_gauge_limit: default_key_gauge_limit(),
        }
    }
}

/// Fully-resolved operational limits, projected onto `RootCfg` by `resolve`. Grouped here so the
/// startup wiring (`limits::install` + the explicit main.rs/store threading) reads a flat
/// struct rather than re-walking optional config sections.
#[derive(Debug, Clone)]
pub struct LimitsResolved {
    pub upstream_request_timeout_secs: u64,
    pub request_body_max_bytes: usize,
    /// Per-pairing datagram LINE retained-capacity limit. None leaves the mechanism disabled;
    /// new pairings capture the resolved setting and keep it for their lifetime.
    pub datagram_line_memory_bytes: Option<usize>,
    pub pool_max_idle_per_host: usize,
    pub pool_idle_timeout_secs: u64,
    pub max_inbound_concurrent: usize,
    /// Max keys bound to one group (0 = unlimited) — the self-service mint anti-sprawl cap.
    pub max_keys_per_principal: usize,
    /// Max groups a mint may AUTO-PROVISION (0 = unlimited) — the sibling anti-sprawl cap on the
    /// SHAPE of the limit tree, not just its contents.
    pub max_auto_provisioned_groups: usize,
    /// Ceiling on the request CONTENT a `prompt: ro|rw` hook is shown in one projection (0 =
    /// unlimited). Over-cap content is omitted WHOLE, never truncated mid-value.
    pub hook_content_max_bytes: usize,
    pub hard_down_cooldown_secs: u64,
    pub upstream_error_body_max_bytes: usize,
    pub tls_handshake_timeout_secs: u64,
    pub request_body_read_timeout_secs: u64,
    pub max_honored_retry_after_secs: u64,
    pub default_max_tokens: u32,
    pub reasoning_effort_budgets: ReasoningEffortBudgets,
    pub key_gauge_limit: usize,
    pub rate_sweep_interval: u32,
    pub usage_flush_interval_ms: u64,
    /// Pin the shared upstream client to HTTP/1.1 (`advanced.upstream_http1_only`). BOOT-TIME knob
    /// read once at client build. Carried here (like `rate_sweep_interval`) so the client-build wiring
    /// reads a flat struct. (The `BUSBAR_UPSTREAM_HTTP1_ONLY` env var was removed in 1.6.0.)
    pub upstream_http1_only: bool,
    /// Force HTTP/2 prior-knowledge to cleartext upstreams (`advanced.upstream_h2_prior_knowledge`).
    /// BOOT-TIME knob; default off. (The `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` env var was removed in
    /// 1.6.0.)
    pub upstream_h2_prior_knowledge: bool,
    pub default_probe_interval_secs: u64,
    pub default_probe_timeout_secs: u64,
    pub default_policy_timeout_ms: u64,
}

impl Default for LimitsResolved {
    fn default() -> Self {
        Self::from_sections(
            &LimitsCfg::default(),
            &AdvancedCfg::default(),
            ExportLimits::default(),
            &HealthDefaultsCfg::default(),
            &RoutingCfg::default(),
        )
    }
}

impl LimitsResolved {
    pub fn from_sections(
        limits: &LimitsCfg,
        advanced: &AdvancedCfg,
        export: impl Into<ExportLimits>,
        health: &HealthDefaultsCfg,
        routing: &RoutingCfg,
    ) -> Self {
        let ExportLimits { key_gauge_limit } = export.into();
        Self {
            upstream_request_timeout_secs: limits.upstream_request_timeout_secs,
            request_body_max_bytes: limits.request_body_max_bytes,
            datagram_line_memory_bytes: limits.datagram_line_memory_bytes,
            pool_max_idle_per_host: limits.pool_max_idle_per_host,
            pool_idle_timeout_secs: limits.pool_idle_timeout_secs,
            max_inbound_concurrent: limits.max_inbound_concurrent,
            max_keys_per_principal: limits.max_keys_per_principal,
            max_auto_provisioned_groups: limits.max_auto_provisioned_groups,
            hook_content_max_bytes: limits.hook_content_max_bytes,
            hard_down_cooldown_secs: limits.hard_down_cooldown_secs,
            upstream_error_body_max_bytes: limits.upstream_error_body_max_bytes,
            tls_handshake_timeout_secs: limits.tls_handshake_timeout_secs,
            request_body_read_timeout_secs: limits.request_body_read_timeout_secs,
            max_honored_retry_after_secs: limits.max_honored_retry_after_secs,
            default_max_tokens: limits.default_max_tokens,
            reasoning_effort_budgets: limits.reasoning_effort_budgets,
            key_gauge_limit,
            rate_sweep_interval: advanced.rate_sweep_interval,
            usage_flush_interval_ms: advanced.usage_flush_interval_ms,
            upstream_http1_only: advanced.upstream_http1_only,
            upstream_h2_prior_knowledge: advanced.upstream_h2_prior_knowledge,
            default_probe_interval_secs: health.default_probe_interval_secs,
            default_probe_timeout_secs: health.default_probe_timeout_secs,
            default_policy_timeout_ms: routing.default_policy_timeout_ms,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_request_body_max_bytes(request_body_max_bytes: usize) -> Self {
        Self {
            request_body_max_bytes,
            ..Self::default()
        }
    }
}

static INSTALLED: std::sync::RwLock<Option<LimitsResolved>> = std::sync::RwLock::new(None);

pub fn installed() -> Option<LimitsResolved> {
    if let Some(candidate) = BUILDING.with(|b| b.borrow().clone()) {
        return Some(candidate);
    }
    INSTALLED.read().unwrap_or_else(|e| e.into_inner()).clone()
}

std::thread_local! {
    /// The limits of the configuration being built ON THIS THREAD, if one is ([`BuildScope`]).
    static BUILDING: std::cell::RefCell<Option<LimitsResolved>> =
        const { std::cell::RefCell::new(None) };
}

#[must_use = "the candidate's limits are visible to the build only while the scope is held"]
pub struct BuildScope {
    outer: Option<LimitsResolved>,
    _not_send: std::marker::PhantomData<*const ()>,
}

impl BuildScope {
    pub fn enter(resolved: &LimitsResolved) -> Self {
        let outer = BUILDING.with(|b| b.borrow_mut().replace(resolved.clone()));
        Self {
            outer,
            _not_send: std::marker::PhantomData,
        }
    }
}

impl Drop for BuildScope {
    fn drop(&mut self) {
        let outer = self.outer.take();
        BUILDING.with(|b| *b.borrow_mut() = outer);
    }
}

pub fn publish(resolved: &LimitsResolved) {
    *INSTALLED.write().unwrap_or_else(|e| e.into_inner()) = Some(resolved.clone());
    mirror_derived_caps(Some(resolved));
}

#[cfg(test)]
pub use crate::test_support::fixture_limits::LIMITS_TEST_LOCK;

#[cfg(test)]
pub fn install(resolved: &LimitsResolved) {
    *INSTALLED.write().unwrap_or_else(|e| e.into_inner()) = Some(resolved.clone());
    mirror_derived_caps(Some(resolved));
}

/// Put `slot` in the live slot (the uninstalled `None` included) and hand back what was there,
/// mirroring the derived caps as every other mutation does. Production writes the slot only through
/// [`publish`]; this is the test fixtures' one write (the kernel testkit's `InstallGuard`, and the
/// guard's own restore-on-drop tests), which must be able to put the slot back exactly as it found it.
#[doc(hidden)]
pub fn swap_installed(slot: Option<LimitsResolved>) -> Option<LimitsResolved> {
    let mut installed = INSTALLED.write().unwrap_or_else(|e| e.into_inner());
    mirror_derived_caps(slot.as_ref());
    std::mem::replace(&mut *installed, slot)
}

#[cfg(test)]
pub use crate::test_support::fixture_limits::InstallGuard;

fn mirror_derived_caps(slot: Option<&LimitsResolved>) {
    let translate_cap = slot
        .map(|l| l.request_body_max_bytes)
        .unwrap_or(DEFAULT_REQUEST_BODY_MAX_BYTES);
    busbar_kernel_egress::upstream::set_max_translate_body_bytes(translate_cap);

    let hook_content = slot
        .map(|l| l.hook_content_max_bytes)
        .unwrap_or(crate::hooks::DEFAULT_HOOK_CONTENT_MAX_BYTES);
    crate::hooks::set_hook_content_max_bytes(hook_content);
}
