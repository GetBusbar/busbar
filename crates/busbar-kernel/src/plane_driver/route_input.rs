// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S OWN ROUTE-TABLE INPUTS: every resolved lane and pool, flattened from the resolved
//! `RootCfg` into neutral rows (owned strings, numbers, the neutral upstream-credential mode, the
//! resolved credential in `busbar_contract::redacted::Secret`) that
//! [`ConfigTables::of`](super::route_tables::ConfigTables::of) builds the driver's route tables from.
//! A resolved secret is carried in `Secret`, never as a bare `String`: these rows are formatted on
//! the build path, so the wrapper is what keeps the credential out of a trace line.
//!
//! The kernel's plane hosting used to hand the same rows on to a registry plane's own runtime build
//! (`plane_host::build_input`'s `PlaneBuildInput`); no plane builds a runtime that way any more —
//! a door plane reads its sections behind its door — so that hand-off is deleted with the kernel's
//! plane hosting (status row 82) and these rows are the route tables' alone.

use std::collections::HashMap;

/// The per-provider outbound AUTH STYLE, a neutral mirror of `Option<busbar_kernel::config::ProviderAuth>`
/// (`None` ⇒ [`AuthStyleInput::Default`], the protocol's native auth). The plane maps it to the style
/// its lane's credential is bound under, on the auth plugin that serves that style
/// (`busbar_kernel::bound_credential`). The style is an opaque word some loaded auth plugin declares
/// (BUSBAR-1.6.0.md #50), carried with the flags it declares, so a plane branches on what the style
/// states (its endpoint bits) and the kernel names no style.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum AuthStyleInput {
    /// No `auth:` override — the protocol's native auth (its declared egress scheme).
    #[default]
    Default,
    /// `auth: <style>`, and the `abi::auth::StyleDecl::flags` its plugin declares.
    Named {
        /// The style word.
        style: String,
        /// Its declared flags.
        flags: u32,
    },
}

/// Active health-probe mode — a neutral mirror of `busbar_kernel::config::HealthMode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum HealthModeInput {
    /// No active probing (`none`).
    #[default]
    None,
    /// Re-probe only tripped lanes (`dead`).
    Dead,
    /// Probe every lane (`active`).
    Active,
}

/// A provider `health:` block — a neutral mirror of `busbar_kernel::config::HealthCfg`.
#[derive(Clone, Debug, Default)]
pub struct HealthInput {
    /// The probing strategy.
    pub mode: HealthModeInput,
    /// Seconds between probes (`None` ⇒ the plane's default).
    pub interval_secs: Option<u64>,
    /// Per-probe request timeout in seconds (`None` ⇒ the plane's default).
    pub timeout_secs: Option<u64>,
}

/// ONE resolved lane (one per model), flattened to neutral scalars — including its provider's
/// egress + auth inputs, WITHOUT the row naming an `EgressTarget` / `CredentialProvider`.
#[derive(Clone)]
pub struct LaneInput {
    /// The model name (config key) — the lane's stable identity and `by_model` key.
    pub model: String,
    /// The provider name this lane routes through.
    pub provider: String,
    /// The lane's protocol NAME (the registry's interned dialect key), carried as an owned `String`;
    /// the plane re-interns it against the protocol registry.
    pub protocol: String,
    /// The provider's upstream base URL, already trailing-slash-trimmed, its userinfo stripped.
    pub base_url: String,
    /// The `Authorization: Basic` the operator's base URL spelled as `user:pass@` (row 74, F25),
    /// opaque: the plane hands it back to the kernel's hop on each request it sends to this lane,
    /// and the hop presents it as 1.5.5 did. `None` when the base URL spelled no userinfo.
    /// TRANSITIONAL: deleted with the legacy lane plane (row 155 C).
    pub url_userinfo: Option<crate::egress::engine::UrlUserinfo>,
    /// Optional upstream request-path override.
    pub path: Option<String>,
    /// Optional path-BASE override (URL-model protocols).
    pub path_base: Option<String>,
    /// The provider's configured tenant (`organization`, `project`), set on every upstream request
    /// under the header its dialect declares; `None` sends nothing.
    pub organization: Option<String>,
    /// See `organization`.
    pub project: Option<String>,
    /// Optional upstream model-name override (the wire model), else the config key.
    pub upstream_model: Option<String>,
    /// The PRE-RESOLVED provider credential — the resolved secret, carried because the plane cannot
    /// re-resolve a secret ref (it has no `SecretResolver`). Held in the SAME `busbar_contract::redacted::Secret`
    /// wrapper the `Lane` it feeds holds it in, for the whole of its life here rather than only after
    /// it lands: a bare `String` on a carrier that a build trace, a panic message or an error `{:?}`
    /// can reach is the plaintext in a log, and the wrapper is what makes that structurally impossible
    /// (it prints `[REDACTED]`, does not serialize, and zeroizes on drop). Read through
    /// the sealed `expose` at the one place the credential is actually built.
    pub api_key: busbar_contract::redacted::Secret<String>,
    /// The provider's auth-style override (neutral).
    pub auth_style: AuthStyleInput,
    /// OAuth scope (`auth: oauth-client-credentials` / an override for `jwt-bearer`).
    pub scope: Option<String>,
    /// OAuth token endpoint (`auth: oauth-client-credentials`), its userinfo stripped: a plane never
    /// receives a URL carrying `user:pass@` (row 74, F25).
    pub token_url: Option<String>,
    /// The `Authorization: Basic` the operator's `token_url` spelled as `user:pass@`, opaque: the
    /// plane hands it back to the kernel's bind, and the host presents it on the mint as 1.5.5 did.
    /// `None` when the endpoint spelled no userinfo.
    /// TRANSITIONAL: deleted with the legacy lane plane (row 155 C).
    pub token_userinfo: Option<crate::egress::engine::UrlUserinfo>,
    /// JWT-bearer `sub` claim (`auth: jwt-bearer`).
    pub subject: Option<String>,
    /// The provider's response error-map (upstream code → canonical), cloned verbatim.
    pub error_map: HashMap<String, String>,
    /// The provider's `health:` block, if any (neutral mirror).
    pub health: Option<HealthInput>,
    /// The provider's per-provider metadata-SSRF allow list (unioned with the global one by the plane).
    pub allow_metadata_hosts: Vec<String>,
    /// The resolved single-valued context window for this model, if any.
    pub context_max: Option<usize>,
    /// The resolved per-lane default max output tokens, if any. Named neutrally (prefixed) to match the
    /// established neutral carrier vocabulary (`EgressPrep::lane_default_max_tokens`) rather than the
    /// bare LLM-request-param spelling — this neutral carrier owns only the primitive, not the noun.
    pub lane_default_max_tokens: Option<u32>,
    /// Model-level per-attempt time-to-headers cap (ms).
    pub attempt_timeout_ms: Option<u64>,
    /// Operator-declared reasoning-carry capability (model level).
    pub reasoning: bool,
    /// Operator-declared prompt-cache capability (model level).
    pub prompt_caching: bool,
    /// The lane's declared request-shape capabilities, resolved from the provider entry and its
    /// model patterns against the lane's wire model (all defaults when nothing is declared).
    pub lane_caps: busbar_contract::ir::egress_prep::LaneCaps,
    /// The realized concurrency cap (`Semaphore::MAX_PERMITS` for an omitted / unbounded cap).
    pub max_concurrent: usize,
    /// Whether this lane has a finite request budget (`max_requests >= 0`).
    pub limited: bool,
    /// The request budget when `limited`, else `-1`.
    pub budget: i64,
}

/// HAND-ROLLED, never derived. This carrier holds a resolved provider credential, and a type that
/// does is one the construction gate names as a secret carrier and holds to writing this impl —
/// belt and braces over the `Secret` field, so neither the wrapper nor the derive is the single
/// thing standing between the credential and a log line. What a reader of a build trace needs is
/// which lane this is and where it points; nothing else printed here is a secret.
impl std::fmt::Debug for LaneInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaneInput")
            .field("model", &self.model)
            .field("provider", &self.provider)
            .field("protocol", &self.protocol)
            .field("base_url", &self.base_url)
            .field("upstream_model", &self.upstream_model)
            .field("api_key", &self.api_key)
            .field("auth_style", &self.auth_style)
            .finish_non_exhaustive()
    }
}

/// ONE pool member, flattened to neutral scalars — a `WeightedLane` plus its `MemberMeta`.
#[derive(Clone, Debug)]
pub struct PoolMemberInput {
    /// The member's model name (for the `by_model` → lane-index resolution the plane redoes).
    pub model: String,
    /// The resolved lane index (into the build's lane rows, `lanes[i]` is lane `i`).
    pub lane_idx: usize,
    /// The member weight (config `PoolMember.weight`, default 1).
    pub weight: u32,
    /// Pool-member reasoning override (`None` ⇒ inherit the model flag).
    pub reasoning: Option<bool>,
    /// Pool-member attempt-timeout override (`None` ⇒ inherit the model value).
    pub attempt_timeout_ms: Option<u64>,
    /// Operator-declared member tier (routing metadata).
    pub tier: Option<String>,
    /// The member's rate-card-derived cost per Mtok, resolved core-side (the plane has no rate card).
    pub cost_per_mtok: Option<f64>,
    /// Operator-declared member tags (routing metadata).
    pub tags: Vec<String>,
}

/// A pool's `failover:` block — a neutral mirror of `busbar_kernel::config::FailoverCfg`.
#[derive(Clone, Debug)]
pub struct FailoverInput {
    /// Failover wall-clock budget in seconds.
    pub timeout_secs: u64,
    /// Member model names excluded from this pool's candidate set.
    pub exclusions: Option<Vec<String>>,
    /// Maximum failover hops per request.
    pub max_hops: usize,
}

/// A pool's `affinity:` block — a neutral mirror of `busbar_kernel::config::AffinityCfg` (only the
/// single supported `session` mode exists, so the mode need not be carried — its presence is the fact).
#[derive(Clone, Debug)]
pub struct AffinityInput {
    /// The request header carrying the session id (`None` ⇒ the plane's `x-session-id` default).
    pub header_name: Option<String>,
}

/// A pool's `on_exhausted:` policy — a neutral mirror of `busbar_kernel::config::OnExhausted`.
#[derive(Clone, Debug, Default)]
pub enum OnExhaustedInput {
    /// `503` + Retry-After (the default).
    #[default]
    Status503,
    /// Route to the named fallback pool.
    FallbackPool(String),
    /// Send to the least-bad (soonest-cooldown) Open member.
    LeastBad,
    /// Wait up to `max_ms` for a permit, else fall through to 503.
    Queue {
        /// The queue wait ceiling in milliseconds.
        max_ms: u64,
    },
}

/// A pool's breaker trip mode — a neutral mirror of `busbar_kernel::store::TripMode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TripModeInput {
    /// Trip on the error RATE over the window (the ADR-0002 default).
    #[default]
    ErrorRate,
    /// Trip on N consecutive failures.
    Consecutive,
}

/// A pool's resolved breaker TRIP parameters — a neutral mirror of `busbar_kernel::store::TripConfig`.
#[derive(Clone, Debug)]
pub struct TripInput {
    /// The trip mode.
    pub mode: TripModeInput,
    /// The outcome window in seconds.
    pub window_s: u64,
    /// The error-rate trip threshold (`ErrorRate` mode).
    pub threshold: f64,
    /// The minimum request count before the rate can trip.
    pub min_requests: usize,
    /// The consecutive-failure count that trips (`Consecutive` mode).
    pub consecutive_n: u32,
}

/// A pool's RESOLVED breaker config — a neutral mirror of the runtime `busbar_kernel::store::BreakerCfg`
/// (the config `pools.<pool>.breaker:` block already lowered core-side via `BreakerCfg::from`, then
/// flattened here, so the row names no core type). `None` on `PoolInput` ⇒ the pool uses the ADR-0002 defaults.
#[derive(Clone, Debug)]
pub struct BreakerInput {
    /// Base cooldown after a trip (seconds).
    pub base_cooldown_secs: u64,
    /// Cooldown ceiling for the exponential backoff (seconds).
    pub max_cooldown_secs: u64,
    /// Whether an upstream `Retry-After` is honored as the cooldown floor.
    pub honor_retry_after: bool,
    /// Whether a sub-trip-threshold transient still benches the cell for a cooldown.
    pub bench_below_trip_threshold: bool,
    /// The resolved trip parameters (the config `trip:` block, or the ADR-0002 defaults).
    pub trip: TripInput,
}

/// ONE pool, flattened to neutral scalars. Its routing POLICY / gates / rewrites are NOT here — those
/// stay resolved-and-read core-side behind `App::resolve_pool_*` (they carry the core-owned
/// `ResolvedPolicy`, which must not cross the downcast); this carries only the pool's neutral config.
#[derive(Clone, Debug)]
pub struct PoolInput {
    /// The pool name.
    pub name: String,
    /// The pool's members (weighted lanes + their metadata), in config order.
    pub members: Vec<PoolMemberInput>,
    /// The pool's `failover:` override, if any.
    pub failover: Option<FailoverInput>,
    /// The pool's `affinity:` block, if any.
    pub affinity: Option<AffinityInput>,
    /// The pool's `on_exhausted:` policy.
    pub on_exhausted: OnExhaustedInput,
    /// The pool's own `upstream_credentials:` override (`None` ⇒ inherit the all-pools default).
    pub upstream_credentials: Option<busbar_contract::config::UpstreamCreds>,
    /// The pool's resolved `breaker:` override (`None` ⇒ ADR-0002 defaults).
    pub breaker: Option<BreakerInput>,
}

/// TRANSITIONAL (row 155 B1b; deleted with the legacy lane carrier, which goes with the legacy llm
/// crate): the plane keys of a resolved provider's table that [`LaneInput`] still carries typed,
/// read off the table. The door path never reads this; its plane parses the table itself. A key
/// that does not read is unset, as an absent one is: the entry was judged when it was parsed.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct LegacyLaneKeys {
    /// The provider's configured tenant (`LaneInput::organization`).
    pub organization: Option<String>,
    /// See `organization`.
    pub project: Option<String>,
    /// The provider-level lane capabilities, read off the same table.
    #[serde(flatten)]
    provider_caps: crate::ir::lane_caps::ProviderLaneCaps,
    model_capabilities: Vec<crate::ir::lane_caps::ModelCapabilities>,
}

impl LegacyLaneKeys {
    /// The keys `provider`'s table carries.
    #[must_use]
    pub fn of(provider: &crate::config::ResolvedProvider) -> Self {
        serde_json::from_value(serde_json::Value::Object(provider.table.clone()))
            .unwrap_or_default()
    }

    /// The lane capabilities these keys resolve to for `wire_model` (`LaneInput::lane_caps`).
    #[must_use]
    pub fn lane_caps(&self, wire_model: &str) -> busbar_contract::ir::egress_prep::LaneCaps {
        crate::ir::lane_caps::resolve_lane_caps(
            self.provider_caps,
            &self.model_capabilities,
            wire_model,
        )
    }
}

#[cfg(test)]
#[path = "tests/route_input_tests.rs"]
mod tests;
