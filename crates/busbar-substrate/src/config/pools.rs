// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-pool config SHAPES: the pool itself (`PoolCfg`, with its hand-written `hooks:` list
//! split), its members, the ranking strategy, the breaker/failover/affinity blocks and the
//! structured `on_exhausted:` value plus its runtime form. Plain serde data with pure accessors.
//! The `pools:` SECTION reader (which lifts the reserved section keys) stays in busbar-core, which
//! re-exports every item here at its historical `config::` path.

use serde::Deserialize;

use super::hooks::ON_ERROR_WEIGHTED;
use crate::failover::{DEFAULT_FAILOVER_CAP, DEFAULT_FAILOVER_DEADLINE_SECS};

#[derive(Debug, Clone, Default)]
pub struct PoolCfg {
    pub members: Vec<PoolMember>,
    /// Per-pool OVERRIDE of the all-pools `pools.upstream_credentials:` default (a
    /// SCALAR, so the entity value REPLACES the inherited one — it does not union). `None` = inherit
    /// the `pools:`-level default. Moved here (out of the retired `auth.upstream_credentials:`) in
    /// 1.5.3: whose credential reaches the upstream is a routing property of the pool, not of the
    /// inbound auth chain.
    pub upstream_credentials: Option<busbar_api::UpstreamCreds>,
    /// Per-pool breaker settings (resolved into `store::BreakerCfg` at startup; drives trip
    /// thresholds and cooldown backoff for this pool's lanes).
    pub breaker: Option<BreakerCfg>,
    pub failover: Option<FailoverCfg>,
    pub on_exhausted: Option<OnExhaustedCfg>,
    pub affinity: Option<AffinityCfg>,
    /// The pool's native ranking STRATEGY (a strategy name in `hooks: [...]`). `weighted`
    /// (default / absent) is today's SWRR
    /// with ZERO added cost — no `RoutingPolicy` object, byte-identical hot path. `cheapest`/`fastest`/
    /// `least_busy`/`usage` resolve a native ordering policy that runs once before the failover loop.
    /// This is the pool's ranking FLOOR.
    pub policy: PoolPolicy,
    /// The pool's GATES (the non-strategy names in `hooks: [...]`). Each names an entry in the
    /// top-level `hooks:` registry; validated to be `kind: gate` at startup.
    /// Empty = no per-pool gate (pure native ordering). Config order is preserved — it is the
    /// phase-2 chain order (order last-wins; reject/restrict commute).
    pub gates: Vec<String>,
    /// Whether the pool EXPLICITLY named its base ordering strategy (a strategy name in
    /// `hooks: [...]`), vs leaving it defaulted. `false` (defaulted) is the pool that INHERITS the
    /// `default:` hook when one is registered (else the compiled-in `weighted` backstop); `true` means
    /// the operator picked a base, so the `default:` hook does NOT override it. `policy` alone can't
    /// carry this — it defaults to `Weighted` indistinguishably from an explicit `weighted`.
    pub base_named: bool,
    /// NEUTRAL ROUTING KNOB (1.6.0): pool-level member weights, `{ member-name: weight }`. When
    /// present, the pool load-balances by these weights; when absent, the pool fails over in member
    /// order (first = primary). This is the uniform-grammar way to weight members without per-member
    /// rich objects; on the LLM plane a per-member `weight:` still wins for byte-identity, and this
    /// map refines any member the operator did not weight inline. Empty ⇒ ordered failover.
    pub weights: std::collections::BTreeMap<String, u32>,
    /// NEUTRAL ROUTING KNOB (1.6.0): the pool's routing tier label (`large`/`small`/…), a plane-neutral
    /// hint read by ranking policies. Applies to every member lacking its own inline `tier:`. `None` ⇒
    /// no pool tier.
    pub tier: Option<String>,
    /// NEUTRAL ROUTING KNOB (1.6.0): pool-level per-attempt response-headers cap (ms), applied to every
    /// member lacking an inline `attempt_timeout_ms:`. `None` ⇒ the model-level default stands.
    pub attempt_timeout_ms: Option<u64>,
    /// NEUTRAL ROUTING KNOB: the operations that may be performed TWICE after a dispatch has gone out
    /// (reads/searches/queries). Plane-neutral field; the values name the plugin's verbs. EMPTY BY
    /// DEFAULT = fail-safe (reroute-before-first-byte only). Read on the tool/agent planes; inert on
    /// the model plane.
    pub repeatable: Vec<String>,
}

/// Whether `name` is one of the native ordering strategies (usable BARE in a pool `hooks:` list).
/// The strategy set is fixed + known at parse time; any OTHER bare name is a hook-NAME reference
/// (1.5.3: no inline instances — a hook is defined in the top-level `hooks:` map and referenced by
/// bare name here).
pub fn is_strategy_name(name: &str) -> bool {
    matches!(
        name,
        ON_ERROR_WEIGHTED
            | STRATEGY_CHEAPEST
            | STRATEGY_FASTEST
            | STRATEGY_LEAST_BUSY
            | STRATEGY_USAGE
    )
}

/// The strategy a bare `hooks:` keyword selects (`weighted` for anything that is not one of the
/// four native policies — see [`is_strategy_name`]).
pub fn parse_strategy(name: &str) -> PoolPolicy {
    match name {
        STRATEGY_CHEAPEST => PoolPolicy::Cheapest,
        STRATEGY_FASTEST => PoolPolicy::Fastest,
        STRATEGY_LEAST_BUSY => PoolPolicy::LeastBusy,
        STRATEGY_USAGE => PoolPolicy::Usage,
        _ => PoolPolicy::Weighted,
    }
}

/// Manual `Deserialize` for [`PoolCfg`]: the `hooks: [...]` list is THE pool form — one ORDERED list
/// mixing an optional built-in ordering strategy (bare `cheapest`/… ) and hook NAMES (bare names
/// referencing the top-level `hooks:` DEFINITION map, 1.5.3 — no inline instances). The strategy sets
/// the base ordering; every other bare name is a hook reference stored in `gates` (validated to exist
/// and be a `kind: gate` at startup).
impl<'de> Deserialize<'de> for PoolCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deny unknown keys so a typo'd pool key fails boot.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawPoolCfg {
            #[serde(default)]
            members: Vec<PoolMember>,
            #[serde(default)]
            breaker: Option<BreakerCfg>,
            #[serde(default)]
            failover: Option<FailoverCfg>,
            #[serde(default)]
            on_exhausted: Option<OnExhaustedCfg>,
            #[serde(default)]
            affinity: Option<AffinityCfg>,
            /// The pool's hooks - an ordering strategy (bare built-in name) and/or hook NAMES
            /// (bare names referencing the top-level `hooks:` map) - in ONE ordered list.
            #[serde(default)]
            hooks: Option<Vec<String>>,
            /// Per-pool override of the all-pools `pools.upstream_credentials:` default.
            #[serde(default)]
            upstream_credentials: Option<busbar_api::UpstreamCreds>,
            /// NEUTRAL 1.6.0 routing knobs. See [`PoolCfg`].
            #[serde(default)]
            weights: std::collections::BTreeMap<String, u32>,
            #[serde(default)]
            tier: Option<String>,
            #[serde(default)]
            attempt_timeout_ms: Option<u64>,
            #[serde(default)]
            repeatable: Vec<String>,
        }

        let raw = RawPoolCfg::deserialize(deserializer)?;

        // Split the `hooks:` list into (base policy, referenced hook names). A strategy name sets
        // the base ordering (at most one); every other name is a hook reference.
        let (policy, gates, base_named) = if let Some(entries) = raw.hooks {
            let mut policy: Option<PoolPolicy> = None;
            let mut gates: Vec<String> = Vec::new();
            for name in entries {
                if name.trim().is_empty() {
                    return Err(serde::de::Error::custom(
                        "a pool `hooks:` entry must be a non-empty strategy keyword or hook name",
                    ));
                }
                if is_strategy_name(&name) {
                    if policy.is_some() {
                        return Err(serde::de::Error::custom(
                            "a pool `hooks:` list names more than one ordering strategy; a pool \
                             has one base ordering",
                        ));
                    }
                    policy = Some(parse_strategy(&name));
                } else {
                    gates.push(name);
                }
            }
            let base_named = policy.is_some();
            (policy.unwrap_or_default(), gates, base_named)
        } else {
            (PoolPolicy::default(), Vec::new(), false)
        };

        Ok(PoolCfg {
            members: raw.members,
            upstream_credentials: raw.upstream_credentials,
            breaker: raw.breaker,
            failover: raw.failover,
            on_exhausted: raw.on_exhausted,
            affinity: raw.affinity,
            policy,
            gates,
            base_named,
            weights: raw.weights,
            tier: raw.tier,
            attempt_timeout_ms: raw.attempt_timeout_ms,
            repeatable: raw.repeatable,
        })
    }
}

/// A pool's native ranking STRATEGY — the base ordering strategy named in a pool's `hooks:` list
/// (the retired `policy:` key). `weighted` (default / absent) is today's smooth-weighted-round-robin:
/// ZERO added cost, no policy object constructed, the byte-identical hot path. The others resolve a
/// Busbar-native ordering policy that runs once before the failover loop. This is the pool's ranking
/// FLOOR; a gate named in the pool's `hooks:` list can override it per-request.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PoolPolicy {
    /// Smooth-weighted-round-robin (SWRR). Default and also the absent case. Zero added cost.
    #[default]
    Weighted,
    Cheapest,
    Fastest,
    LeastBusy,
    Usage,
}

impl PoolPolicy {
    /// The ranking-registry name for this strategy (`plugins::hooks::ranking::native_policy`).
    /// `weighted` returns `None` — it IS the zero-cost inline-SWRR default and constructs no policy
    /// object. Engine-level `STRATEGY_*` consts (not the ranking plugin's constants) so this
    /// compiles when the `hooks-ranking` plugin is removed; the plugin matches the same names.
    pub fn native_name(&self) -> Option<&'static str> {
        match self {
            PoolPolicy::Weighted => None,
            PoolPolicy::Cheapest => Some(STRATEGY_CHEAPEST),
            PoolPolicy::Fastest => Some(STRATEGY_FASTEST),
            PoolPolicy::LeastBusy => Some(STRATEGY_LEAST_BUSY),
            PoolPolicy::Usage => Some(STRATEGY_USAGE),
        }
    }
}

/// The native ranking-strategy names — shared by the pool `hooks:` classifier/parser,
/// `PoolPolicy::native_name`, `RESERVED_HOOK_NAMES`, and the config validator's built-in-strategy
/// check, so the vocabulary cannot drift. `weighted` is NOT listed here: it is the zero-cost
/// inline-SWRR floor and its name is owned by `ON_ERROR_WEIGHTED` in the hooks shapes.
pub const STRATEGY_CHEAPEST: &str = "cheapest";
pub const STRATEGY_FASTEST: &str = "fastest";
pub const STRATEGY_LEAST_BUSY: &str = "least_busy";
pub const STRATEGY_USAGE: &str = "usage";

#[derive(Debug, Clone)]
pub struct PoolMember {
    /// The member's REFERENCED NAME — a `models:` key on the model plane, a `tools:` key on the tool
    /// plane, an `agents:` key on the agent plane. Named `model` for the byte-identity path that
    /// reads it; the [`PoolMember::name`] accessor is the plane-neutral reader. 1.6.0: a member may
    /// be written as a BARE NAME (uniform grammar across every plane) or, on the model plane, as the
    /// legacy rich object `{ model, weight, context_max, tier, attempt_timeout_ms, reasoning, tags }`.
    pub model: String,
    pub weight: u32,
    pub context_max: Option<usize>,
    /// Operator-declared routing tier (e.g. `"large"`/`"small"`/`"primary"`/`"overflow"`). Projected
    /// into the routing `Candidate` (via `MemberMeta`) and read by hook plugin policies.
    pub tier: Option<String>,
    /// Per-ATTEMPT time-to-response-headers cap (ms) for THIS member in THIS pool — overrides the
    /// model-level `attempt_timeout_ms`, so one model can be patient in an image pool (10000) and
    /// ruthless in a realtime pool (50). See `ModelCfg::attempt_timeout_ms` for semantics.
    pub attempt_timeout_ms: Option<u64>,
    /// Per-pool override of the model-level `reasoning` capability flag (member wins), so the same
    /// lane can allow thinking in a research pool and refuse it in a latency-critical one. See
    /// `ModelCfg::reasoning` for semantics.
    pub reasoning: Option<bool>,
    /// Free-form operator tags (e.g. `["opus"]`) a policy can match on. Projected into the routing
    /// `Candidate` and read by hook plugin policies.
    ///
    /// NOTE: the 1.4.x `cost_per_mtok:` member field is REMOVED: `rate_card` is the ONLY cost
    /// source, and routing (`cheapest`) derives its scalar from the member's model's rate entry.
    pub tags: Vec<String>,
}

impl PoolMember {
    /// The plane-neutral reader of the member's referenced name (the bare name that resolves into a
    /// plugin noun — `models:`/`tools:`/`agents:`). The struct field is spelled `model` for the
    /// model-plane hot path; this is the name every plane-neutral caller (kind inference, the
    /// validator) uses.
    pub fn name(&self) -> &str {
        &self.model
    }
}

/// Manual `Deserialize` for [`PoolMember`]: the 1.6.0 uniform grammar admits a member written as a
/// BARE NAME (`- gpt4o-openai`) on EVERY plane, while the model plane also still accepts the legacy
/// rich object (`{ model: gpt4o, weight: 3, tier: large, ... }`). A bare name lowers to the same
/// struct with every knob defaulted — identical to writing `{ model: <name> }`.
impl<'de> Deserialize<'de> for PoolMember {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)] // a typo'd pool-member key must fail boot, not be silently ignored.
        struct RichMember {
            model: String,
            #[serde(default = "default_weight")]
            weight: u32,
            #[serde(default)]
            context_max: Option<usize>,
            #[serde(default)]
            tier: Option<String>,
            #[serde(default)]
            attempt_timeout_ms: Option<u64>,
            #[serde(default)]
            reasoning: Option<bool>,
            #[serde(default)]
            tags: Vec<String>,
        }

        // A hand-written visitor (NOT `#[serde(untagged)]`): untagged would swallow the rich
        // object's `deny_unknown_fields` diagnostic into a generic "did not match any variant",
        // hiding the exact typo'd key. The visitor dispatches on the YAML node shape and forwards a
        // MAP straight to `RichMember`, so a bad key still fails boot with its own name.
        struct MemberVisitor;
        impl<'de> serde::de::Visitor<'de> for MemberVisitor {
            type Value = PoolMember;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a bare member name, or a member object `{ model, weight, ... }`")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<PoolMember, E> {
                Ok(PoolMember {
                    model: v.to_string(),
                    weight: default_weight(),
                    context_max: None,
                    tier: None,
                    attempt_timeout_ms: None,
                    reasoning: None,
                    tags: Vec::new(),
                })
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<PoolMember, A::Error> {
                let r = RichMember::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(PoolMember {
                    model: r.model,
                    weight: r.weight,
                    context_max: r.context_max,
                    tier: r.tier,
                    attempt_timeout_ms: r.attempt_timeout_ms,
                    reasoning: r.reasoning,
                    tags: r.tags,
                })
            }
        }

        deserializer.deserialize_any(MemberVisitor)
    }
}

/// The serde default for a pool member's `weight:` — `1`, the plain unweighted member. Also the
/// sentinel `resolve` reads to tell "left at the default" from an explicit per-member weight.
pub fn default_weight() -> u32 {
    1
}

/// Trip mode for breaker configuration.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BreakerTripMode {
    #[default]
    ErrorRate,
    Consecutive,
}

/// Trip configuration parameters (ADR-0002 defaults).
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct BreakerTripConfig {
    #[serde(default = "default_trip_mode")]
    pub mode: BreakerTripMode,
    /// Sliding-window length in seconds (one canonical name; the pre-1.0 `window_s` alias is
    /// GONE - an unknown key fails boot).
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    #[serde(default = "default_min_requests")]
    pub min_requests: usize,
    /// Consecutive-failure threshold for `BreakerTripMode::Consecutive` (one canonical name;
    /// the pre-1.0 `n` alias is GONE).
    #[serde(default = "default_consecutive_n")]
    pub consecutive_n: u32,
}

pub fn default_trip_mode() -> BreakerTripMode {
    BreakerTripMode::ErrorRate
}

/// Default sliding-window length in seconds for the breaker trip evaluation (ADR-0002).
pub const DEFAULT_BREAKER_WINDOW_SECS: u64 = 30;
/// Default error-rate threshold for tripping the breaker (fraction in (0.0, 1.0]).
pub const DEFAULT_BREAKER_THRESHOLD: f64 = 0.5;
/// Default minimum request count before the error-rate breaker can trip.
pub const DEFAULT_BREAKER_MIN_REQUESTS: usize = 5;
/// Default consecutive-failure streak length for `BreakerTripMode::Consecutive`.
pub const DEFAULT_BREAKER_CONSECUTIVE_N: u32 = 3;

pub fn default_window_secs() -> u64 {
    DEFAULT_BREAKER_WINDOW_SECS
}

pub fn default_threshold() -> f64 {
    DEFAULT_BREAKER_THRESHOLD
}

pub fn default_min_requests() -> usize {
    DEFAULT_BREAKER_MIN_REQUESTS
}

pub fn default_consecutive_n() -> u32 {
    DEFAULT_BREAKER_CONSECUTIVE_N
}

/// Breaker configuration per pool with full trip settings (ADR-0002).
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BreakerCfg {
    #[serde(default = "default_cooldown")]
    pub base_cooldown_secs: u64,
    #[serde(default = "default_max_cooldown")]
    pub max_cooldown_secs: u64,
    #[serde(default)]
    pub trip: Option<BreakerTripConfig>,
}

impl Default for BreakerCfg {
    fn default() -> Self {
        // Delegate to the serde-default fns so the `breaker:`-omitted path (this `Default`) and the
        // per-field-omitted path (`#[serde(default = ...)]`) share a single source of truth for the
        // cooldown literals and cannot drift. See `breaker_cfg_default_matches_serde_default_fns`.
        Self {
            base_cooldown_secs: default_cooldown(),
            max_cooldown_secs: default_max_cooldown(),
            trip: Some(BreakerTripConfig::default()),
        }
    }
}

/// Default base cooldown (seconds) for the escalating breaker back-off (ADR-0002). Single source
/// of truth for both `BreakerCfg::default()` and the `#[serde(default)]` path.
pub const DEFAULT_BREAKER_BASE_COOLDOWN_SECS: u64 = 15;
/// Default maximum cooldown (seconds) for the escalating breaker back-off (ADR-0002).
pub const DEFAULT_BREAKER_MAX_COOLDOWN_SECS: u64 = 120;

pub fn default_cooldown() -> u64 {
    // Single source of truth for the base cooldown: both `BreakerCfg::default()` (used when a pool
    // omits the `breaker:` block) and `#[serde(default = "default_cooldown")]` (used when the block
    // is present but omits `base_cooldown_secs`) route through here, so the value is a consistent
    // 15s on every path.
    DEFAULT_BREAKER_BASE_COOLDOWN_SECS
}

pub fn default_max_cooldown() -> u64 {
    DEFAULT_BREAKER_MAX_COOLDOWN_SECS
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FailoverCfg {
    /// Failover wall-clock budget in seconds (one canonical name; the pre-1.0 `deadline_secs`
    /// alias is GONE).
    #[serde(default = "default_failover_timeout")]
    pub timeout_secs: u64,
    /// Member model names excluded from this pool's candidate set — never selected (primary or
    /// failover). A per-pool blocklist for temporarily benching a member without editing `members`.
    #[serde(default)]
    pub exclusions: Option<Vec<String>>,
    /// Maximum failover hops per request (one canonical name; the pre-1.0 `cap` alias is GONE).
    #[serde(default = "default_max_hops")]
    pub max_hops: usize,
}

pub fn default_failover_timeout() -> u64 {
    DEFAULT_FAILOVER_DEADLINE_SECS
}

pub fn default_max_hops() -> usize {
    DEFAULT_FAILOVER_CAP
}

/// A pool's STRUCTURED `on_exhausted:` (a keyword stays bare, a reference is structured):
///
/// ```yaml
/// on_exhausted: reject                       # 503 + Retry-After (the default)
/// on_exhausted: least_bad                    # degraded: soonest-recovering member
/// on_exhausted: { fallback_pool: cold }      # route to another pool
/// on_exhausted: { queue: { max_ms: 250 } }   # bounded wait for a freed permit, then reject
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnExhaustedCfg {
    Reject,
    LeastBad,
    FallbackPool(String),
    /// Bounded wait for a concurrency permit to free on an at-capacity member, then fall through to
    /// reject. `max_ms` is the wait ceiling in milliseconds (validated `> 0` and `<= resolved
    /// failover.timeout_secs * 1000` at `--validate`).
    Queue {
        max_ms: u64,
    },
}

impl OnExhaustedCfg {
    /// The executable behavior this config value selects.
    pub fn to_runtime(&self) -> OnExhausted {
        match self {
            OnExhaustedCfg::Reject => OnExhausted::Status503,
            OnExhaustedCfg::LeastBad => OnExhausted::LeastBad,
            OnExhaustedCfg::FallbackPool(name) => OnExhausted::FallbackPool(name.clone()),
            OnExhaustedCfg::Queue { max_ms } => OnExhausted::Queue { max_ms: *max_ms },
        }
    }
}

impl<'de> Deserialize<'de> for OnExhaustedCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct FallbackBody {
            fallback_pool: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct QueueInner {
            max_ms: u64,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct QueueBody {
            queue: QueueInner,
        }

        let value = serde_yaml::Value::deserialize(deserializer)?;
        match value {
            serde_yaml::Value::String(word) => match word.as_str() {
                "reject" => Ok(OnExhaustedCfg::Reject),
                "least_bad" => Ok(OnExhaustedCfg::LeastBad),
                other => Err(serde::de::Error::custom(format!(
                    "unknown on_exhausted keyword '{other}': the bare keywords are `reject` | \
                     `least_bad`; a fallback pool is referenced structured: \
                     `on_exhausted: {{ fallback_pool: <pool> }}`, a bounded wait as \
                     `on_exhausted: {{ queue: {{ max_ms: <ms> }} }}`"
                ))),
            },
            v @ serde_yaml::Value::Mapping(_) => {
                // A structured `on_exhausted` mapping is DISAMBIGUATED by its key set rather than
                // force-fit into `FallbackBody` — peek the top-level keys so `fallback_pool` and
                // `queue` route to distinct variants, both keys present is an explicit error, and an
                // unrecognized mapping still gets the actionable "one of …" message.
                let has_fallback = v.get("fallback_pool").is_some();
                let has_queue = v.get("queue").is_some();
                match (has_fallback, has_queue) {
                    (true, true) => Err(serde::de::Error::custom(
                        "on_exhausted takes exactly one of `fallback_pool` | `queue`, not both",
                    )),
                    (true, false) => {
                        let body: FallbackBody =
                            serde_yaml::from_value(v).map_err(serde::de::Error::custom)?;
                        if body.fallback_pool.trim().is_empty() {
                            return Err(serde::de::Error::custom(
                                "on_exhausted: { fallback_pool: … } must name a non-empty pool",
                            ));
                        }
                        Ok(OnExhaustedCfg::FallbackPool(body.fallback_pool))
                    }
                    (false, true) => {
                        let body: QueueBody =
                            serde_yaml::from_value(v).map_err(serde::de::Error::custom)?;
                        Ok(OnExhaustedCfg::Queue {
                            max_ms: body.queue.max_ms,
                        })
                    }
                    (false, false) => Err(serde::de::Error::custom(
                        "on_exhausted is `reject`, `least_bad`, `{ fallback_pool: <pool> }`, or \
                         `{ queue: { max_ms: <ms> } }`",
                    )),
                }
            }
            _ => Err(serde::de::Error::custom(
                "on_exhausted is `reject`, `least_bad`, `{ fallback_pool: <pool> }`, or \
                 `{ queue: { max_ms: <ms> } }`",
            )),
        }
    }
}

/// Pool exhaustion mode - the executable behavior when all members are tripped/excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnExhausted {
    /// Status503: return 503 Service Unavailable with Retry-After header
    /// set to the soonest member's cooldown expiry.
    Status503,
    /// FallbackPool(name): route to a configured fallback pool by name.
    /// Guard against loops via depth cap (max 1) or visited pool tracking.
    FallbackPool(String),
    /// LeastBad: send to the member with soonest cooldown expiry even though Open.
    /// Log loudly that this is a degraded path.
    LeastBad,
    /// Queue{max_ms}: wait up to `max_ms` (bounded also by the failover budget) for a concurrency
    /// permit to free on an at-capacity member, dispatch on the freed lane, else fall through to a
    /// 503 + Retry-After. Handled by the engine's on_exhausted dispatch, never inside the member
    /// pick.
    Queue { max_ms: u64 },
}

/// Affinity mode. `session` is the default and only supported mode. Modelled as a (currently
/// single-variant) enum so an unrecognized spelling (e.g. `sticky`) is a deserialize error rather
/// than a silently-accepted value that degrades to default behaviour. The wire string (`session`)
/// is unchanged from the pre-enum `String` field.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AffinityMode {
    #[default]
    Session,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AffinityCfg {
    /// Affinity mode. `session` (the default and only supported mode) pins a session to a lane
    /// using the header named by `header_name`.
    #[serde(default)]
    pub mode: AffinityMode,
    /// Request header carrying the session id (defaults to `x-session-id` when unset).
    #[serde(default)]
    pub header_name: Option<String>,
}
