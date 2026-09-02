// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL LLM-RUNTIME BUILD CARRIER (1.6.0 money-path Phase 3-4 C) — the single-compiled DTO
//! `busbar-core`'s `appbuild` populates from the already-resolved `RootCfg` and hands to the LLM
//! plane's `build_runtime` seam (`PlaneDecl::build_runtime`, through `&dyn Any`), so the plane rebuilds
//! its `Lane`/`WeightedLane`/`PoolRuntime`/`NativeRuntime` tables WITHOUT core naming a single plane
//! type and WITHOUT a core type crossing the type-erased downcast.
//!
//! ## Why every field is a NEUTRAL SCALAR
//!
//! The `build_runtime` fn-pointer is stored on the plane's `&'static PlaneDecl`, which — in
//! `busbar-core`'s own `cfg(test)` binary — is registered through the neutral substrate test seam
//! against a SECOND, independently-compiled copy of `busbar-core` (the plane crate's normal-dep core,
//! distinct from the `cfg(test)` core under test). A `busbar_core::` type erased to `&dyn Any` in one
//! and downcast in the other carries a DIFFERENT `TypeId`, so the downcast silently returns `None` —
//! the dual-compile hazard. This carrier therefore holds NO `busbar_core::` type: only owned `String`s,
//! numbers, `bool`s, `Vec`/`HashMap` of those, and the neutral `busbar_api::UpstreamCreds`. It lives in
//! `busbar-substrate` (compiled ONCE for the whole workspace) so its own `TypeId` is stable across the
//! dual compile, and so a zero-plane binary that `git-rm`'d `busbar-llm` (the `plane-delete-test --all`
//! posture) still compiles `appbuild` — which populates this — without naming the plane crate.
//!
//! ## What it does NOT carry
//!
//! Pre-RESOLVED plaintext secrets and the rate-card-derived costs ARE carried (fidelity: the plane
//! cannot re-resolve a secret ref — it has no `SecretResolver` — nor re-price without the rate card).
//! Pool-hook ROUTING POLICIES are NOT: their resolved value is the core-owned
//! `busbar_core::hooks::ResolvedPolicy` (an `Arc<dyn RoutingPolicy>` over a dlopen plugin), which
//! cannot be named here and must not cross the downcast — so, exactly as the container-plane gate
//! rebuild does (`ContainerGateSink`), pool policies stay resolved-and-read core-side behind the
//! `App::resolve_pool_*` down-facade and never enter this carrier.

use std::collections::HashMap;

/// The per-provider outbound AUTH STYLE, a neutral mirror of `Option<busbar_core::config::ProviderAuth>`
/// (`None` ⇒ [`AuthStyleInput::Default`], the protocol's native auth). The plane maps this back to the
/// core enum to drive `egress_auth::{resolve,jwt_bearer,oauth_client_credentials}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AuthStyleInput {
    /// No `auth:` override — the protocol's native auth (`egress_auth::resolve(protocol, None)`).
    #[default]
    Default,
    /// `auth: bearer`.
    Bearer,
    /// `auth: api-key`.
    ApiKey,
    /// `auth: jwt-bearer` (RFC 7523).
    JwtBearer,
    /// `auth: oauth-client-credentials` (RFC 6749 §4.4).
    OAuthClientCredentials,
}

/// Active health-probe mode — a neutral mirror of `busbar_core::config::HealthMode`.
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

/// A provider `health:` block — a neutral mirror of `busbar_core::config::HealthCfg`.
#[derive(Clone, Debug, Default)]
pub struct HealthInput {
    /// The probing strategy.
    pub mode: HealthModeInput,
    /// Seconds between probes (`None` ⇒ the plane's default).
    pub interval_secs: Option<u64>,
    /// Per-probe request timeout in seconds (`None` ⇒ the plane's default).
    pub timeout_secs: Option<u64>,
}

/// ONE resolved lane (one per model), flattened to neutral scalars. Everything the plane's
/// `build_runtime` needs to reconstruct a `Lane` — including its provider's egress + auth inputs, so
/// the plane owns the `build_egress_targets` / `egress_auth` calls (the allowed plane→core edge)
/// WITHOUT the carrier naming an `EgressTarget` / `CredentialProvider`.
#[derive(Clone, Debug)]
pub struct LaneInput {
    /// The model name (config key) — the lane's stable identity and `by_model` key.
    pub model: String,
    /// The provider name this lane routes through.
    pub provider: String,
    /// The lane's protocol NAME (the registry's interned dialect key), carried as an owned `String`;
    /// the plane re-interns it against the protocol registry.
    pub protocol: String,
    /// The provider's upstream base URL, already trailing-slash-trimmed.
    pub base_url: String,
    /// Optional upstream request-path override.
    pub path: Option<String>,
    /// Optional path-BASE override (URL-model protocols).
    pub path_base: Option<String>,
    /// Optional upstream model-name override (the wire model), else the config key.
    pub upstream_model: Option<String>,
    /// The PRE-RESOLVED provider credential PLAINTEXT — the resolved secret, carried because the plane
    /// cannot re-resolve a secret ref. Held here in the clear only for the duration of the build; the
    /// plane wraps it in `busbar_api::Redacted` the instant it lands in the `Lane`.
    pub api_key_plaintext: String,
    /// The provider's auth-style override (neutral).
    pub auth_style: AuthStyleInput,
    /// OAuth scope (`auth: oauth-client-credentials` / an override for `jwt-bearer`).
    pub scope: Option<String>,
    /// OAuth token endpoint (`auth: oauth-client-credentials`).
    pub token_url: Option<String>,
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
    /// The resolved default max output tokens, if any.
    pub default_max_tokens: Option<u32>,
    /// Model-level per-attempt time-to-headers cap (ms).
    pub attempt_timeout_ms: Option<u64>,
    /// Operator-declared reasoning-carry capability (model level).
    pub reasoning: bool,
    /// Operator-declared prompt-cache capability (model level).
    pub prompt_caching: bool,
    /// The realized concurrency cap (`Semaphore::MAX_PERMITS` for an omitted / unbounded cap).
    pub max_concurrent: usize,
    /// Whether this lane has a finite request budget (`max_requests >= 0`).
    pub limited: bool,
    /// The request budget when `limited`, else `-1`.
    pub budget: i64,
}

/// ONE pool member, flattened to neutral scalars — a `WeightedLane` plus its `MemberMeta`.
#[derive(Clone, Debug)]
pub struct PoolMemberInput {
    /// The member's model name (for the `by_model` → lane-index resolution the plane redoes).
    pub model: String,
    /// The resolved lane index (into [`PlaneBuildInput::lanes`]).
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

/// A pool's `failover:` block — a neutral mirror of `busbar_core::config::FailoverCfg`.
#[derive(Clone, Debug)]
pub struct FailoverInput {
    /// Failover wall-clock budget in seconds.
    pub timeout_secs: u64,
    /// Member model names excluded from this pool's candidate set.
    pub exclusions: Option<Vec<String>>,
    /// Maximum failover hops per request.
    pub max_hops: usize,
}

/// A pool's `affinity:` block — a neutral mirror of `busbar_core::config::AffinityCfg` (only the
/// single supported `session` mode exists, so the mode need not be carried — its presence is the fact).
#[derive(Clone, Debug)]
pub struct AffinityInput {
    /// The request header carrying the session id (`None` ⇒ the plane's `x-session-id` default).
    pub header_name: Option<String>,
}

/// A pool's `on_exhausted:` policy — a neutral mirror of `busbar_core::config::OnExhausted`.
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

/// A pool's breaker trip mode — a neutral mirror of `busbar_core::store::TripMode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TripModeInput {
    /// Trip on the error RATE over the window (the ADR-0002 default).
    #[default]
    ErrorRate,
    /// Trip on N consecutive failures.
    Consecutive,
}

/// A pool's resolved breaker TRIP parameters — a neutral mirror of `busbar_core::store::TripConfig`.
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

/// A pool's RESOLVED breaker config — a neutral mirror of the runtime `busbar_core::store::BreakerCfg`
/// (the config `pools.<pool>.breaker:` block already lowered core-side via `BreakerCfg::from`, then
/// flattened here so the plane's `build_runtime` reconstructs the runtime cfg WITHOUT the carrier
/// naming a core type). `None` on `PoolInput` ⇒ the pool uses the ADR-0002 defaults.
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
    pub upstream_credentials: Option<busbar_api::UpstreamCreds>,
    /// The pool's resolved `breaker:` override (`None` ⇒ ADR-0002 defaults).
    pub breaker: Option<BreakerInput>,
}

/// The client-affecting subset of the resolved limits — the inputs the plane's upstream HTTP client
/// build reads, and the tuple the warm-pool-reuse compare is keyed on (the plane reuses the prior
/// generation's warm client iff these are unchanged).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientSettingsInput {
    /// The overall streaming request timeout (`limits.upstream_request_timeout_secs`) the warm-pool
    /// -reuse compare is keyed on: a config apply that CHANGES it must REBUILD the sharded upstream
    /// client so the new deadline takes effect, not silently reuse the prior client and pin the old
    /// timeout until restart. Carried here (part of the reuse tuple) as the byte-identical successor to
    /// the pre-relocation `UpstreamClientSettings.upstream_request_timeout_secs` the compare keyed on.
    pub upstream_request_timeout_secs: u64,
    /// Per-host idle connection budget (divided across shards by the plane).
    pub pool_max_idle_per_host: usize,
    /// Idle connection keep-alive ceiling in seconds.
    pub pool_idle_timeout_secs: u64,
    /// Pin the client to HTTP/1.1 (`advanced.upstream_http1_only`).
    pub http1_only: bool,
    /// Assume HTTP/2 prior-knowledge for cleartext upstreams (`advanced.upstream_h2_prior_knowledge`).
    pub h2_prior_knowledge: bool,
}

/// THE NEUTRAL LLM-RUNTIME BUILD CARRIER — see the module docs. Populated field-by-field by
/// `busbar-core`'s `appbuild` from the resolved `RootCfg`, passed as `&dyn Any` to the LLM plane's
/// `PlaneDecl::build_runtime`, and downcast (single-compiled-safe) in `busbar-llm`.
#[derive(Clone, Debug)]
pub struct PlaneBuildInput {
    /// Every lane, in the deterministic sorted-by-model order core assigns indices in (so
    /// `lanes[i]` IS lane index `i`).
    pub lanes: Vec<LaneInput>,
    /// Every pool.
    pub pools: Vec<PoolInput>,
    /// The ALL-POOLS upstream-credential default (`pools.upstream_credentials:`).
    pub upstream_credentials: busbar_api::UpstreamCreds,
    /// The global metadata-SSRF allow list (`security.allow_metadata_hosts`).
    pub allow_metadata_hosts: Vec<String>,
    /// The nuclear metadata-guard disable (`security.allow_all_metadata`).
    pub allow_all_metadata: bool,
    /// The operator's extra metadata denylist (`security.blocked_metadata_hosts`).
    pub blocked_metadata_hosts: Vec<String>,
    /// The client-affecting resolved limits (warm-pool reuse key + client build inputs).
    pub client_settings: ClientSettingsInput,
    /// The GLOBAL-DEFAULT failover config — the fallback for pools that set no `failover:` of their
    /// own. Production `appbuild` always fills this with the fixed `DEFAULT_FAILOVER_*` constants (there
    /// is no operator knob for a custom global), so carrying it changes nothing there; it exists so the
    /// test fixture can drive the whole-App failover deadline the way it always could. `None` ⇒ the
    /// plane's own fixed default.
    pub default_failover: Option<FailoverInput>,
}
