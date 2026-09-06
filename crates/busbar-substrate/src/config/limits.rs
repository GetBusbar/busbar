// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The operational-limit config SHAPES ("NEVER CODED CAPS"): the historical default constants,
//! the `limits:` / `health:` / `routing:` blocks and the flat resolved `LimitsResolved` every
//! startup wire reads. Every field defaults — via a `default = "fn"` whose body is the historical
//! hardcoded const — to today's behavior, so an absent key (the common case) is byte-for-byte
//! unchanged. busbar-core re-exports every item here at its historical `config::` path.
//!
//! The process-wide INSTALL of the resolved values lives at the bottom of this page too — the slot,
//! the rollback guard, and the test-only unconditional installer and serializing lock. The deep
//! call-stack ACCESSORS that read it are still busbar-core's; only the state is neutral, which is
//! what lets a plane crate's tests install a non-default posture without reaching into the engine.

use serde::{Deserialize, Serialize};

use super::hooks::default_policy_timeout_ms;
use super::sections::AdvancedCfg;

/// Default upstream per-request timeout (seconds). Single source of truth for both serde's
/// `default = "..."` and the resolved-default fallback. Mirrors the historical `main.rs` const.
pub const DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS: u64 = 300;
/// Default maximum accepted request body size (bytes). Couples to the egress translate-body cap
/// (`limits::translate_body_max_bytes`): a body the gateway accepts inbound must also be
/// buffer-translatable on egress, so ONE knob (`limits.request_body_max_bytes`) drives both.
pub const DEFAULT_REQUEST_BODY_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Hard floor on `request_body_max_bytes` — a too-small cap would reject legitimate multi-turn /
/// multimodal requests with no recourse. 64 KiB comfortably holds a minimal request.
pub const REQUEST_BODY_MAX_BYTES_FLOOR: usize = 64 * 1024;
/// Hard ceiling on `request_body_max_bytes` — the body is buffered per request, so an absurd value
/// is a memory-exhaustion foot-gun. 1 GiB is far above any legitimate completion payload.
pub const REQUEST_BODY_MAX_BYTES_CEIL: usize = 1024 * 1024 * 1024;
/// Default max idle keep-alive connections the upstream client pools per host. Mirrors `main.rs`.
///
/// EQUAL TO `DEFAULT_MAX_INBOUND_CONCURRENT` BY DESIGN, and the coupling is the point: the
/// upstream working set is bounded by inbound admission (each in-flight request holds at most one
/// upstream connection), so an idle cap BELOW the admissible working set cannot bound anything
/// useful — it can only convert every lull into a mass-close and every following burst into a
/// redial storm. Measured on the rig (the "post-at-cap dial-churn regime"): with the former 1024
/// cap, an at-cap window built a ~7,100-connection working set, the window's end slammed it to
/// 1,024 in under a second, and the next burst locked into ~9,400 upstream dials/s — 188,535
/// connects in one 20s window against 26,263 in a clean one — with 54% of CPU burned in the
/// kernel's ephemeral-port scan (`__inet_hash_connect` over a TIME_WAIT-saturated port space) and
/// goodput collapsed from ~53k to ~7.5-39k rps. With the cap at the admission bound the working
/// set survives lulls, the next window reuses warm sockets, and the regime cannot arm. The
/// history below still holds for the LOWER bound (the former 64 forced hot-path churn); this
/// raises the ceiling to the one resource bound that is real. Idle-socket cost stays bounded:
/// an idle keep-alive is far cheaper than the live request the admission cap already permits,
/// `pool_idle_timeout`/`tcp_keepalive` bound its lifetime, and the OS reclaims under pressure.
/// Operators with many distinct upstream hosts can lower it, exactly as before.
pub const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = DEFAULT_MAX_INBOUND_CONCURRENT;
// THE COUPLING IS THE CONTRACT, enforced at compile time: the idle cap's default must never sit
// below the admission bound, or the dial-churn regime above re-arms. A future edit that decouples
// the two constants fails to BUILD, not to bench.
const _: () = assert!(
    DEFAULT_POOL_MAX_IDLE_PER_HOST >= DEFAULT_MAX_INBOUND_CONCURRENT,
    "the default idle cap must cover the admissible working set"
);
/// Default idle keep-alive lifetime (seconds) for pooled upstream connections.
///
/// EXPLICIT 300s, replacing reqwest's implicit 90s default: under a bursty LLM workload the warm
/// working set (`pool_max_idle_per_host` sockets, each carrying an amortized TCP+TLS handshake and
/// — on h2 — an established multiplexed session) should SURVIVE inter-burst gaps of a few minutes
/// instead of being reaped at 90s and re-paid as cold handshakes on the hot path when the next
/// burst lands. Safe to hold that long because `tcp_keepalive(60s)` actively validates every idle
/// socket — a middlebox silently dropping a long-idle connection is detected by the keepalive
/// probe, not discovered as a spurious request failure — so the longer lifetime adds warm-socket
/// retention without adding stale-socket risk. Bounded: the OS reclaims idle sockets under
/// pressure, and `pool_max_idle_per_host` caps the count.
pub const DEFAULT_POOL_IDLE_TIMEOUT_SECS: u64 = 300;
/// Default inbound concurrency limit. `0` = unlimited (NO layer added).
///
/// Non-zero by default because this is the ONLY global bound on buffered request memory: every
/// request buffers its body (up to `request_body_max_bytes`, default 32 MiB) BEFORE any handler
/// logic can reject it, so peak memory is `(concurrent requests) x (body cap)` — with no admission
/// bound, a hostile connection burst is an OOM, not a slowdown. The limit layer is applied
/// OUTERMOST (see `apply_inbound_concurrency_limit`), so a queued request has NOT yet buffered its
/// body — the bound genuinely caps peak at `limit x body cap`. 8192 is ~4x the highest useful
/// in-flight count measured on a 4-core box (sustained throughput peaks near 1-2k concurrent) —
/// far above any legitimate working set, low enough that the worst case stays bounded. Operators
/// who want the old unlimited posture set `limits.max_inbound_concurrent: 0` explicitly.
pub const DEFAULT_MAX_INBOUND_CONCURRENT: usize = 8192;
/// Default hard-down sticky cooldown (seconds). Mirrors `store.rs`.
pub const DEFAULT_HARD_DOWN_COOLDOWN_SECS: u64 = 1800;
/// Default ceiling on a honored upstream `Retry-After` (seconds). Mirrors `store.rs` (24h).
pub const DEFAULT_MAX_HONORED_RETRY_AFTER_SECS: u64 = 86_400;
/// Default cap on a buffered upstream ERROR / verbatim-relay body (bytes). The literal lives ONCE, in
/// the neutral `proxy` module (which owns the process-global this seeds), so the serde default here
/// and the accessor a plane reads can never drift apart.
pub const DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES: usize =
    crate::proxy::UPSTREAM_ERROR_BODY_MAX_BYTES_DEFAULT;
/// Default cap on a single `plugins.fetch:` download (bytes). Mirrors the same defense the
/// token-endpoint reads already apply (`egress_auth::read_capped_token_response`,
/// `proxy::wire::read_capped`): a mistyped or compromised `plugins.fetch` URL serving a multi-GB
/// body must NOT be buffered whole into memory via an unbounded `resp.bytes()` read — that OOMs
/// busbar on boot (`fatal_on_miss`) or on `POST /plugins/reload`. 256 MiB comfortably holds any
/// legitimate signed plugin tarball while bounding the worst case; the download is aborted with a
/// clear "exceeded the cap" error the instant more bytes arrive, never buffered past it.
pub const DEFAULT_PLUGIN_FETCH_MAX_BYTES: usize = 256 * 1024 * 1024;
/// Default depth, in FRAMES, of the OUTBOUND queue on one full-duplex leg: how many frames a plane
/// may have handed a socket that has not yet drained them.
///
/// The mirror of the inbound queue depth the duplex acceptor and dialer already bound, pointed the
/// other way, and it is a cap for the same reason. An UNBOUNDED outbound queue charges this node's
/// memory for the difference between the rate a plane produces frames at and the rate the far end
/// accepts them: a relay leg whose upstream has stalled (a wedged provider, a peer that stopped
/// reading, a socket held open by a middlebox) goes on accepting frames forever, and the amount of
/// memory one session can cost is then decided by the producer alone with nothing on the other side
/// of the equation. Bounded, the producer's own `send` waits for capacity instead, which is what
/// pushes the stall back to whoever is causing it — the same discipline the inbound side applies to
/// a flooding peer. 64 frames is deep enough that ordinary jitter between a plane's writes and a
/// socket's drain never reaches it, and shallow enough that a wedged leg is bounded by a queue and
/// not by the heap.
///
/// Lives HERE, with every other operational cap, rather than beside the transport that reads it: it
/// is the same kind of number as the rest of this page, and a neutral transport reads it without
/// naming the engine. No `limits:` key drives it — like [`DEFAULT_MAX_TOKENS`], the constant IS the
/// posture.
pub const DEFAULT_DUPLEX_OUTBOUND_QUEUE_FRAMES: usize = 64;
/// Default TLS handshake wall-clock bound (seconds). Mirrors `tls.rs`.
pub const DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
/// Default inbound request-BODY read bound (seconds): the max time allowed BETWEEN inbound body
/// frames before the connection is dropped. Bounds a slow-loris that dribbles the request body one
/// byte at a time (the header-read timeout only covers the header phase). Mirrors `tls.rs`. 30s is
/// far longer than any real client needs to send its next body chunk, so it cannot false-positive on
/// a healthy upload.
pub const DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS: u64 = 30;
/// Conservative fallback for the `max_tokens` injected at a translation boundary when the source
/// protocol omitted it (legal for OpenAI) but the target REQUIRES it (Anthropic, Bedrock — see
/// `ProtocolWriter::requires_max_tokens`). Used only when the lane has no configured
/// `default_max_tokens`. 4096 is a safe output ceiling across current chat models — large enough
/// not to truncate typical completions, small enough not to be refused.
///
/// Lives HERE, beside the `limits:` block whose `default_max_tokens` key overrides it, rather than
/// in a protocol module: the value is an operational cap, the same kind as every other constant on
/// this page, and a plane crate reads it without naming the engine. busbar-core re-exports it at
/// its historical `proto::DEFAULT_MAX_TOKENS` path.
pub const DEFAULT_MAX_TOKENS: u32 = 4096;
/// Default global fallback for the translation-injected `max_tokens`. The SAME number as
/// [`DEFAULT_MAX_TOKENS`], and now literally it — the two can no longer drift.
pub const DEFAULT_DEFAULT_MAX_TOKENS: u32 = DEFAULT_MAX_TOKENS;
/// Default max concurrent webhook deliveries. Mirrors `observability.rs`.
pub const DEFAULT_MAX_INFLIGHT_WEBHOOK_DELIVERIES: usize = 64;
/// Default per-webhook delivery timeout (seconds). Mirrors `observability.rs`.
pub const DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS: u64 = 2;
/// Default max per-key gauge series emitted per scrape. Mirrors `metrics.rs`.
pub const DEFAULT_KEY_GAUGE_LIMIT: usize = 2000;
/// Default rate-sweep amortization interval. Mirrors `governance.rs`.
pub const DEFAULT_RATE_SWEEP_INTERVAL: u32 = 256;
/// Default write-behind flush cadence (ms) for the in-memory governance usage/budget counters.
/// Mirrors `governance.rs`.
pub const DEFAULT_USAGE_FLUSH_INTERVAL_MS: u64 = 100;
/// Default active-probe interval (seconds) — the process-wide fallback for the per-lane override.
pub const DEFAULT_PROBE_INTERVAL_SECS: u64 = 30;
/// Default active-probe timeout (seconds) — the process-wide fallback for the per-lane override.
pub const DEFAULT_PROBE_TIMEOUT_SECS: u64 = 5;

// The serde `default = "..."` functions. Each one returns the matching constant above, so the
// omitted-key path and the omitted-block path (`Default`) share one source of truth. They are `pub`
// because busbar-core's config tests pin every one of them against its constant.
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
/// `0` = unlimited keys per group (today's behavior — an absent knob changes nothing).
pub fn default_max_keys_per_principal() -> usize {
    0
}
/// `0` = unlimited auto-provisioned groups (today's behavior — an absent knob changes nothing).
pub fn default_max_auto_provisioned_groups() -> usize {
    0
}
pub fn default_hook_content_max_bytes() -> usize {
    crate::proxy::DEFAULT_HOOK_CONTENT_MAX_BYTES
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
pub fn default_max_inflight_webhook_deliveries() -> usize {
    DEFAULT_MAX_INFLIGHT_WEBHOOK_DELIVERIES
}
pub fn default_webhook_delivery_timeout_secs() -> u64 {
    DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS
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

/// The `limits:` block — global operational caps. Each field defaults to its historical hardcoded
/// value, so an absent field (or an absent block) is today's behavior.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)] // a typo'd limits key must fail boot, not be silently ignored.
pub struct LimitsCfg {
    #[serde(default = "default_upstream_request_timeout_secs")]
    pub upstream_request_timeout_secs: u64,
    /// Max accepted inbound body (bytes). COUPLED: also drives the egress translate-body cap
    /// (`limits::translate_body_max_bytes`) — one knob feeds both so an accepted request is
    /// always buffer-translatable on egress.
    #[serde(default = "default_request_body_max_bytes")]
    pub request_body_max_bytes: usize,
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
        // Route every field through the serde-default fn so the omitted-block path (this `Default`)
        // and the omitted-field path share one source of truth and cannot drift.
        Self {
            upstream_request_timeout_secs: default_upstream_request_timeout_secs(),
            request_body_max_bytes: default_request_body_max_bytes(),
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
#[serde(deny_unknown_fields)] // a typo'd health key must fail boot, not be silently ignored.
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
#[serde(deny_unknown_fields)] // a typo'd routing key must fail boot, not be silently ignored.
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

/// The two limits that come from the resolved `export:` block rather than from `limits:` itself:
/// the shared webhook-delivery admission bound and the per-scrape gauge cap. The `export:` block is
/// lowered in busbar-core (its typed settings carry a core-owned projection), so the resolver hands
/// just these two numbers across; `Default` is the historical pair an export-less config resolves
/// to. busbar-core implements `From<&ExportCfg>` for this so its callers pass the resolved block
/// straight through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportLimits {
    /// The SHARED webhook-delivery admission bound: the MAX across every configured
    /// `request-log-webhook` instance, or the historical default with none configured.
    pub max_inflight_webhook_deliveries: usize,
    /// Max per-key gauge series emitted per `/metrics` scrape: the `prometheus` instance's setting,
    /// or the historical default with no instance configured.
    pub key_gauge_limit: usize,
}

impl Default for ExportLimits {
    fn default() -> Self {
        Self {
            max_inflight_webhook_deliveries: default_max_inflight_webhook_deliveries(),
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
    /// The SHARED webhook-delivery admission bound (max across every configured
    /// `request-log-webhook` export instance — see [`ExportLimits`]). The per-delivery
    /// TIMEOUT is deliberately NOT here: it is per instance on the webhook settings.
    pub max_inflight_webhook_deliveries: usize,
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
    /// Project the operational-limit sections onto the flat resolved struct. `export` takes anything
    /// that converts to [`ExportLimits`] — busbar-core passes its resolved `&ExportCfg`, which it
    /// converts through its own `From` impl; an export-less caller passes `ExportLimits::default()`.
    pub fn from_sections(
        limits: &LimitsCfg,
        advanced: &AdvancedCfg,
        export: impl Into<ExportLimits>,
        health: &HealthDefaultsCfg,
        routing: &RoutingCfg,
    ) -> Self {
        // 1.5.3: the webhook + gauge limits moved from the retired `observability.*`/`metrics.*` keys
        // onto the built-in EXPORTER settings. They arrive here already reduced to the two numbers
        // (historical defaults when the exporter is absent) so the deep `limits` readers (metrics
        // gauge cap, webhook admission bound) are unchanged while the CONFIG SURFACE they read from
        // is the new one.
        let ExportLimits {
            max_inflight_webhook_deliveries,
            key_gauge_limit,
        } = export.into();
        Self {
            upstream_request_timeout_secs: limits.upstream_request_timeout_secs,
            request_body_max_bytes: limits.request_body_max_bytes,
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
            max_inflight_webhook_deliveries,
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

    /// TEST-SUPPORT constructor: the default resolved limits with ONLY `request_body_max_bytes`
    /// overridden — the shape the relocated ingress body-cap tests need (they name no other
    /// field). Kept on the test-support surface so a plane's tests build the posture through one
    /// seam instead of a struct literal.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_request_body_max_bytes(request_body_max_bytes: usize) -> Self {
        Self {
            request_body_max_bytes,
            ..Self::default()
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────────────────────────
// THE PROCESS-WIDE INSTALL of the resolved limits.
//
// The slot lives HERE, with the shape it holds, rather than in busbar-core: the deep-call-stack
// accessors that read it are core's, but the SLOT is neutral state over a neutral struct, and a
// plane crate's tests install a non-default posture (a small body cap, a short handshake bound) to
// make themselves fast. With the slot in the engine, that install was an engine reach from a plane
// test tree. busbar-core re-exports every item below at its historical `limits::` path, so its own
// accessors, its composition root and its tests are unchanged by identity.
// ───────────────────────────────────────────────────────────────────────────────────────────────

/// The installed limits. `None` until an install runs; `None` means "use the historical default",
/// which is what each of busbar-core's per-accessor fallbacks returns. An `RwLock` (not a
/// `OnceLock`) because the config plane RE-installs on every apply/reload — limit changes take
/// effect live. Reads take an uncontended read lock (writes happen only on config changes), and the
/// values these guard are not per-byte hot (per-request/per-connection reads at most).
static INSTALLED: std::sync::RwLock<Option<LimitsResolved>> = std::sync::RwLock::new(None);

/// The currently-installed limits, or `None` when nothing has been installed (boot, or a test
/// process that never installed). Every accessor resolves that `None` to its own historical
/// default constant.
pub fn installed() -> Option<LimitsResolved> {
    INSTALLED.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// TEST-ONLY. Serializes every test in a binary that MUTATES the process-global slot above
/// (busbar-core's own `InstallGuard` tests and its TLS body-bound tests, and a plane crate's
/// ingress body-cap tests, which install a non-default `LimitsResolved` to make themselves fast).
/// Cargo runs those tests concurrently in ONE process, and an install is a whole-struct swap behind
/// a shared lock, so without this a sibling test's install lands mid-assertion in another and both
/// are flaky in a way that depends on machine core count. Lives beside the static rather than in
/// any one test module because the hazard is the static, not the file — and now beside it across
/// crates, so a plane's installs and the engine's serialize against EACH OTHER rather than only
/// among themselves.
///
/// A `tokio::sync::Mutex`, not a `std` one, for two reasons: the TLS holders await socket I/O for
/// their entire critical section (holding a `std` guard across an await is clippy's
/// `await_holding_lock`, `-D warnings` here), and it does not poison, so one failing test does not
/// cascade into every other test that wants the lock. Synchronous tests take it with
/// `blocking_lock()`, which is legal precisely because a plain `#[test]` fn has no runtime.
#[cfg(any(test, feature = "test-support"))]
pub static LIMITS_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Install (or RE-install) the resolved limits process-wide, unconditionally and with no rollback.
///
/// TEST-ONLY. Production installs through [`InstallGuard`], never through this: a config that is
/// subsequently REJECTED must not leave its limits behind, and an unconditional install is exactly
/// what made that possible. The remaining consumer is the one test whose SUBJECT is racing the live
/// cap by re-installing it in a hot loop with no rollback between iterations — `InstallGuard` cannot
/// serve that (a guard restores on drop, but the test wants the value to keep flipping mid-run).
#[cfg(any(test, feature = "test-support"))]
pub fn install(resolved: &LimitsResolved) {
    *INSTALLED.write().unwrap_or_else(|e| e.into_inner()) = Some(resolved.clone());
    mirror_derived_caps(Some(resolved));
}

/// TEST-ONLY. Write the slot DIRECTLY, including back to the uninstalled `None` — the raw poke
/// [`install`] cannot express and [`InstallGuard`] must not be used for.
///
/// The consumer is the guard's OWN test file: its restore-on-drop fixture has to put the slot back
/// exactly as it found it (uninstalled included) on the failure path, and it deliberately does not
/// use `InstallGuard` for that, because a broken `InstallGuard::drop` would then silently repair the
/// very state the assertions inspect. Mirrors the derived caps exactly as every other mutation does,
/// so a raw poke cannot leave the `proxy` globals disagreeing with the accessors.
#[cfg(any(test, feature = "test-support"))]
pub fn set_installed(slot: Option<LimitsResolved>) {
    mirror_derived_caps(slot.as_ref());
    *INSTALLED.write().unwrap_or_else(|e| e.into_inner()) = slot;
}

/// INSTALL FOR THE DURATION OF A BUILD, AND ROLL BACK UNLESS THE BUILD SUCCEEDS.
///
/// busbar-core's `build_app_from_config` installs the candidate limits FIRST — it has to, because
/// the build reads them through the deep-call-stack accessors (the store open, the health-probe
/// fallbacks, the routing policy timeout) — but every step AFTER the install is fallible: semantic
/// validation, the plugin pre-flight, secret-ref resolution, the store open. Before this guard, a
/// rejected apply left the REJECTED config's limits installed process-wide while the old `App` kept
/// serving, and no error path put them back. That broke the surface's central promise that an
/// invalid apply changes nothing, and it did so in the worst direction: the values `validate_limits`
/// exists to reject — e.g. a `request_body_max_bytes` below its floor — are precisely the ones that
/// got installed anyway, because the range check runs after the install. A 400-ed
/// `POST /config/apply` could shrink the live SigV4 auth-middleware buffer and the cross-protocol
/// translate buffer under a still-running gateway, 401-ing larger Bedrock requests.
///
/// So: snapshot, install, and restore on drop unless [`InstallGuard::commit`] is called. Rollback on
/// the DROP rather than on each `return Err` is what makes it total — a build step added later
/// cannot forget to unwind, and neither can a `?`.
#[must_use = "an uncommitted InstallGuard rolls the limits back when dropped"]
pub struct InstallGuard {
    /// What was installed before — `None` when nothing was (boot, or a test process).
    prior: Option<LimitsResolved>,
    committed: bool,
}

impl InstallGuard {
    /// Snapshot the currently-installed limits and install `resolved` in their place.
    pub fn install(resolved: &LimitsResolved) -> Self {
        let mut slot = INSTALLED.write().unwrap_or_else(|e| e.into_inner());
        let prior = slot.clone();
        *slot = Some(resolved.clone());
        mirror_derived_caps(Some(resolved));
        Self {
            prior,
            committed: false,
        }
    }

    /// The build succeeded: KEEP the installed limits.
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for InstallGuard {
    fn drop(&mut self) {
        if !self.committed {
            *INSTALLED.write().unwrap_or_else(|e| e.into_inner()) = self.prior.clone();
            mirror_derived_caps(self.prior.as_ref());
        }
    }
}

/// Mirror the upstream-error-body cap AND the egress translate-body cap into the `proxy` process
/// globals, so a reader that has no `App` in hand (the proxy paths, and the plane crates that read
/// the translate cap) sees the SAME value busbar-core's own accessors return. Called after EVERY
/// mutation of `INSTALLED` (install, reload, and the [`InstallGuard`] rollback) with that same
/// slot's value, resolving the `None`/uninstalled case to the historical default exactly as each
/// accessor does — the mirrors can never diverge from the accessors.
fn mirror_derived_caps(slot: Option<&LimitsResolved>) {
    let cap = slot
        .map(|l| l.upstream_error_body_max_bytes)
        .unwrap_or(DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES);
    crate::proxy::set_max_upstream_buffered_bytes(cap);
    // The egress translate-body cap is `request_body_max_bytes` (one knob feeds both ingress and this
    // egress cap); mirror it with the SAME uninstalled-fallback the accessor uses.
    let translate_cap = slot
        .map(|l| l.request_body_max_bytes)
        .unwrap_or(DEFAULT_REQUEST_BODY_MAX_BYTES);
    crate::proxy::set_max_translate_body_bytes(translate_cap);
}
