// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM DATA-PLANE ROUTING TABLES, relocated from busbar-core::state (1.6.0 money-path Phase 3-4 C).
//! Lane/WeightedLane/MemberMeta/PoolRuntime/QueuedDepth/QueueDepthGuard/NativeRuntime/EngineTables now
//! live in the plane crate; core names none of them and reads only the neutral EngineTablesView.

use std::collections::HashMap;
use std::sync::Arc;

use busbar_core::proxy::EgressClient as Client;
use busbar_core::state::UpstreamClients;

// ---------- lane (one per model) ----------
#[derive(Clone)]
pub(crate) struct Lane {
    pub(crate) model: String,
    pub(crate) provider: String,
    pub(crate) base_url: String,
    /// The SigV4 signed-`host` header value, derived ONCE at boot from `base_url` (scheme + userinfo
    /// stripped, authority only — see `proxy::host_from_base`). Precomputed so the request path borrows
    /// it into `SigningContext` instead of re-running the parse + `String` allocation on every
    /// forwarded request (it is a pure function of the immutable `base_url`). Only the Bedrock SigV4
    /// writer reads it; other protocols ignore `SigningContext::host`.
    pub(crate) signing_host: String,
    /// The resolved provider credential (api key / SigV4 secret material / OAuth credential string),
    /// held [`busbar_api::Redacted`] so it never leaks via `Debug`/logs and zeroizes on drop. Reach
    /// the plaintext only at the egress seam via `expose_secret()`.
    pub(crate) api_key: busbar_api::Redacted<String>,
    /// This lane's protocol, as the registry's interned `&'static str` NAME. Post-G6-A4b the concrete
    /// `Protocol` (reader + writer) lives in the `busbar-llm` plugin and core names none of it; a lane
    /// reaches its dialect's neutral computed-codec facade via `proto::decl_for(self.protocol).dialect()`
    /// and its constant facts via `decl_for(self.protocol).<field>`. Copy-cheap, so `Lane: Clone` stays.
    pub(crate) protocol: &'static str,
    /// Outbound credential — how this lane presents Busbar's identity to the upstream. Resolved once
    /// at boot from (protocol, auth). See `busbar_core::egress_auth`; the request path calls `headers_for`.
    pub(crate) credential: Arc<dyn busbar_core::egress_auth::CredentialProvider>,
    pub(crate) max: usize,
    // error_map cloned into each lane at startup for Stage 1b normalization
    pub(crate) error_map: Arc<std::collections::HashMap<String, String>>,
    /// Optional maximum context window size for this lane's model.
    pub(crate) context_max: Option<usize>,
    /// Optional upstream request-path override. When set, used verbatim instead of the protocol's
    /// default path (for providers that embed the API version in base_url and serve /chat/completions).
    pub(crate) path: Option<String>,
    /// Optional path-BASE override for URL-model protocols (Gemini): replaces the hardcoded base
    /// segment while keeping the per-request `/{model}:verb` suffix (Vertex AI). See `EgressCtx`.
    pub(crate) path_base: Option<String>,
    /// Optional active health-probe settings (from the provider's `health:` block). `None` or
    /// `mode: none` means no background probing for this lane.
    pub(crate) health: Option<busbar_core::config::HealthCfg>,
    /// Model-level per-ATTEMPT time-to-response-headers cap (ms) — the hang detector. A pool
    /// member's `attempt_timeout_ms` overrides it per workload; see `ModelCfg::attempt_timeout_ms`.
    pub(crate) attempt_timeout_ms: Option<u64>,
    /// Operator-declared: this model accepts reasoning/thinking request params (the cross-protocol
    /// reasoning-carry gate). A pool member's `reasoning` overrides it. See `ModelCfg::reasoning`.
    pub(crate) reasoning: bool,
    /// Operator-declared: this model accepts prompt-cache markers on model-gated dialects
    /// (Bedrock `cachePoint`). Gates the cross-protocol cache-breakpoint carry; see
    /// `ModelCfg::prompt_caching`.
    pub(crate) prompt_caching: bool,
    /// Optional default max output tokens, injected at the cross-protocol translation seam when the
    /// source request omitted `max_tokens` (legal for OpenAI) but this lane's protocol REQUIRES it
    /// (Anthropic Messages — see `ProtocolWriter::requires_max_tokens`). Falls back to
    /// `busbar_core::proto::DEFAULT_MAX_TOKENS` when unset.
    pub(crate) default_max_tokens: Option<u32>,
    /// Optional upstream model name override. When set, this value is sent to the provider as the
    /// model identifier in the body and URL path, instead of `self.model` (the config key).
    /// Useful when the provider expects a different model string (e.g. Bedrock model IDs).
    pub(crate) upstream_model: Option<String>,
    /// Boot-precomputed `(operation, stream) → (wire URL, SigV4 canonical URI)` — every egress
    /// target this lane can be dispatched to is a pure function of lane-constant config, so the
    /// forward path does one table read instead of rendering the path, URI-encoding it, and
    /// WHATWG-parsing the URL per request. Built by `proxy::build_egress_targets` (which
    /// documents the vocabulary and the never-`Url::join` encoding rule). A lookup miss is exactly
    /// the old per-request `upstream_path` `None` arm: the lane's protocol has no handler.
    pub(crate) egress_targets:
        HashMap<(busbar_core::operation::Operation, bool), crate::engine::EgressTarget>,
    /// Boot-prebuilt egress auth headers for `Own`-mode dispatch, or `None` when this lane's
    /// credential is not lane-constant (OAuth mints, SigV4 signs — those stay per-request). Built
    /// by `egress_auth::prebuild_auth` from the SAME `headers_for` call the request path makes, so
    /// a clone of this map is byte-identical to the per-request build; the request path takes the
    /// clone (one buffer copy) iff the resolved credential mode is `Own` — Passthrough carries the
    /// CALLER's credential and always builds live.
    pub(crate) prebuilt_auth: Option<http::header::HeaderMap>,
}

impl Lane {
    /// The model name to send on the wire. Returns `upstream_model` when set,
    /// otherwise falls back to the config key (`self.model`).
    pub(crate) fn wire_model(&self) -> &str {
        self.upstream_model.as_deref().unwrap_or(&self.model)
    }
    /// The precomputed egress target for one `(operation, stream)` — the forward path's URL/canonical
    /// read. `None` == the old `upstream_path` `None` arm (no handler for this lane's protocol).
    pub(crate) fn egress_target(
        &self,
        op: busbar_core::operation::Operation,
        stream: bool,
    ) -> Option<&crate::engine::EgressTarget> {
        self.egress_targets.get(&(op, stream))
    }
}

/// A pool lane with its associated weight.
#[derive(Clone)]
pub(crate) struct WeightedLane {
    pub(crate) idx: usize,  // index into lanes array
    pub(crate) weight: u32, // member weight from config
    /// Pool-member override of the lane's `reasoning` capability flag (member wins). `None` =
    /// inherit the model-level flag. See `ModelCfg::reasoning`.
    pub(crate) reasoning: Option<bool>,
    /// Pool-member override of the lane's `attempt_timeout_ms` (one model, different budgets per
    /// workload/pool). `None` = inherit the model-level value.
    pub(crate) attempt_timeout_ms: Option<u64>,
}

/// Operator-declared per-member routing metadata (config), projected into the routing `Candidate`
/// at the seam. Lives on `PoolRuntime` keyed by lane idx (NOT on the shared `Lane`, since the same
/// lane can be a member of several pools with different tier/cost/tags). Building this ONLY for pools
/// that declare a non-default `route:` is NOT required — it is cheap to populate for every pool, but it is
/// READ only inside the policy arm of the seam, so the zero-cost default path never touches it.
#[derive(Clone, Default)]
pub(crate) struct MemberMeta {
    pub(crate) tier: Option<String>,
    pub(crate) cost_per_mtok: Option<f64>,
    pub(crate) tags: Vec<String>,
}

/// Per-pool runtime config resolved from config.yaml. Keyed by pool name so the re-entrant
/// `forward_with_pool` (which knows its pool name) can look up the right failover/breaker/affinity
/// settings — pools are first-class, but lanes are shared, so this config lives per pool.
#[derive(Clone, Default)]
pub(crate) struct PoolRuntime {
    /// Operator-declared member metadata (tier / cost / tags) keyed by lane idx, for the routing
    /// `Candidate` projection. Read ONLY inside the policy arm of the seam; the default SWRR path
    /// never touches it. Empty for a pool with no members declaring metadata.
    pub(crate) members: std::collections::HashMap<usize, MemberMeta>,
    /// Per-pool failover settings (deadline, cap, and member exclusions).
    pub(crate) failover: Option<busbar_core::config::FailoverCfg>,
    /// Per-pool OVERRIDE of the all-pools `pools.upstream_credentials:` default (1.5.3).
    /// `None` = inherit `App::upstream_credentials`. Read per request by
    /// [`App::pool_upstream_creds`].
    pub(crate) upstream_credentials: Option<busbar_core::auth::UpstreamCreds>,
    /// Per-pool session-affinity settings (which request header pins a session to a lane).
    pub(crate) affinity: Option<busbar_core::config::AffinityCfg>,
    /// Per-pool breaker settings (trip mode/thresholds + cooldown backoff), resolved into the
    /// runtime `store::BreakerCfg` the FSM evaluates. `None` falls back to ADR-0002 defaults.
    pub(crate) breaker: Option<busbar_core::store::BreakerCfg>,
    // NOTE (1.6.0 money-path Phase 3-4 C — the RATIFIED pool-hook facade): the per-pool routing
    // `policy` / decision `gates` / `rewrite_hooks` USED to live here, resolved at config load from
    // `hooks::resolve_pool_*`. They carry the core-owned `ResolvedPolicy`/`Arc<dyn RoutingPolicy>`
    // (an Arc over a dlopen plugin), which cannot be resolved inside the plane's `build_runtime` (no
    // `hook_env`, no usable current-`&App`). So they STAY resolved-and-read CORE-SIDE, keyed by pool,
    // reached from the engine through the `busbar_core::state::App::pool_{policy,gates,rewrites}`
    // down-facades (mirroring `App::resolve_container_gates`) — byte-identical objects, read via the
    // facade instead of stored here.
}
/// Live per-pool depth of requests currently PARKED in an `on_exhausted: queue` wait — the real
/// source behind the `busbar_pool_queued{pool}` gauge, which reads this at scrape time.
/// A parked request calls [`park`](QueuedDepth::park) on entry and holds
/// the returned RAII guard for the whole wait; the guard decrements on EVERY exit (dispatch, deadline
/// shed, or a dropped future on client disconnect), so the depth can never leak. Arc-shared across
/// config swaps (`App::clone` clones the Arc) so an in-flight parked request on an old `App` snapshot
/// and a `/metrics` scrape on a new one agree on the count. The map lock is taken only at park
/// enter/exit and at scrape time — the already-slow queue path, never hot dispatch.
#[derive(Default)]
pub(crate) struct QueuedDepth {
    counts: std::sync::Mutex<HashMap<String, Arc<std::sync::atomic::AtomicU64>>>,
}

impl QueuedDepth {
    /// Register a request parking in `pool`'s queue wait; returns a guard that decrements on drop. The
    /// per-pool counter is created on first use.
    pub(crate) fn park(&self, pool: &str) -> QueueDepthGuard {
        let counter = {
            let mut m = self.counts.lock().unwrap_or_else(|e| e.into_inner());
            m.entry(pool.to_string())
                .or_insert_with(|| Arc::new(std::sync::atomic::AtomicU64::new(0)))
                .clone()
        };
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        QueueDepthGuard { counter }
    }

    /// Current parked depth for `pool` (0 if nothing has ever queued there).
    pub(crate) fn depth(&self, pool: &str) -> u64 {
        let m = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        m.get(pool)
            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// RAII decrement for a parked queue request — see [`QueuedDepth::park`].
pub(crate) struct QueueDepthGuard {
    counter: Arc<std::sync::atomic::AtomicU64>,
}

impl Drop for QueueDepthGuard {
    fn drop(&mut self) {
        self.counter
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}
/// THE LLM DATA-PLANE RUNTIME — the pool/lane/failover/egress tables that were 12 flat `App` fields,
/// now ONE bundle built once per config apply ([`busbar_core::appbuild`]) and carried on the snapshot in the
/// opaque plane slot ([`App::plane_slots`]) under `runtime_slot_key(<llm plane key>)`, reached through
/// the [`App::llm_runtime`] downcast (R3/R4 sub-phase B). Grouping them was sub-phase A's payoff (core
/// carries no LLM-shaped FLAT state); sub-phase B then moved the bundle off its typed field into the
/// SAME type-erased slot every other plane's runtime already rides, so `App` names one `&'static str`
/// key ([`App::llm_runtime_key`]) instead of this type. `cost` deliberately stays OUTSIDE this (it is
/// NEUTRAL — MCP/A2A meter through it too). Still `Clone` (Phase 3 relocates the type to `busbar-llm`;
/// today the apply-path `build_runtime` seam clones the freshly-lowered bundle into the shared slot).
/// Neutral: names no dialect, adds no LLM type to core (the freeze witness stays 0).
#[derive(Clone)]
pub(crate) struct NativeRuntime {
    pub(crate) lanes: Vec<Lane>,
    pub(crate) by_model: HashMap<String, usize>,
    pub(crate) pools: HashMap<String, Vec<WeightedLane>>,
    pub(crate) pool_runtime: HashMap<String, PoolRuntime>,
    pub(crate) fallback_pools: HashMap<String, Vec<WeightedLane>>,
    pub(crate) on_exhausted_cfgs: std::collections::HashMap<String, busbar_core::config::OnExhausted>,
    pub(crate) failover_cfg: Option<busbar_core::config::FailoverCfg>,
    pub(crate) queued_depth: Arc<QueuedDepth>,
    pub(crate) probe_schedule: Arc<crate::engine::health::ProbeSchedule>,
    pub(crate) upstream_credentials: busbar_core::auth::UpstreamCreds,
    pub(crate) any_pool_upstream_creds_override: bool,
    pub(crate) client: UpstreamClients,
    /// The client-affecting resolved limits this generation's `client` was built on — the key the
    /// warm-pool-reuse compare in [`build_runtime`](crate::engine::build_runtime) reads: the next
    /// generation reuses this generation's warm `client` (its kept-alive upstream sockets) iff these
    /// are unchanged. Moved IN-PLANE from core's `App::client_settings` with the client build itself.
    pub(crate) client_settings: busbar_substrate::plane_host::LlmClientSettings,
}

impl NativeRuntime {
    /// The ALL-POOLS upstream-credential default (the pool-less egress path's `Own`/`Passthrough`).
    /// Moved verbatim from `App::upstream_creds`.
    pub(crate) fn upstream_creds(&self) -> busbar_core::auth::UpstreamCreds {
        self.upstream_credentials
    }

    /// The upstream-credential mode in force for `pool` — the pool's own `upstream_credentials:` when
    /// it sets one, else the all-pools default. SCALAR override. Moved verbatim from
    /// `App::pool_upstream_creds` (same fast path, same SipHash-probe skip when no override exists).
    pub(crate) fn pool_upstream_creds(&self, pool: &str) -> busbar_core::auth::UpstreamCreds {
        if !self.any_pool_upstream_creds_override {
            return self.upstream_credentials;
        }
        self.pool_runtime
            .get(pool)
            .and_then(|rt| rt.upstream_credentials)
            .unwrap_or(self.upstream_credentials)
    }
}

/// NEUTRAL READ-SIDE PROJECTION of this runtime's routing tables for the core-resident scrape/
/// discovery readers (1.6.0 money-path Phase 3-4 B). `NativeRuntime` is still a core type this commit
/// (the pivot relocates it to `busbar-llm`); implementing the substrate trait now lets `/metrics`, the
/// `/v1/models` listing, and the telemetry label bank read these tables through neutral projections —
/// naming no `Lane`/`WeightedLane` — so they need not move when the tables do. Every projection is a
/// cold/scrape-path read that may allocate; the hot engine path never touches this seam (it reads the
/// concrete fields directly).
impl busbar_substrate::plane_host::EngineTablesView for NativeRuntime {
    fn pools(&self) -> Vec<(&str, Vec<usize>)> {
        self.pools
            .iter()
            .map(|(name, members)| (name.as_str(), members.iter().map(|wl| wl.idx).collect()))
            .collect()
    }
    fn model_indices(&self) -> Vec<(&str, usize)> {
        self.by_model
            .iter()
            .map(|(m, &idx)| (m.as_str(), idx))
            .collect()
    }
    fn model_index(&self, model: &str) -> Option<usize> {
        self.by_model.get(model).copied()
    }
    fn lane_view(&self, idx: usize) -> Option<busbar_substrate::plane_host::LaneView<'_>> {
        self.lanes
            .get(idx)
            .map(|lane| busbar_substrate::plane_host::LaneView {
                model: &lane.model,
                provider: &lane.provider,
                base_url: &lane.base_url,
            })
    }
    fn lane_count(&self) -> usize {
        self.lanes.len()
    }
    fn pool_members(&self, pool: &str) -> Vec<(usize, u32)> {
        self.pools
            .get(pool)
            .map(|members| members.iter().map(|wl| (wl.idx, wl.weight)).collect())
            .unwrap_or_default()
    }
    fn queued_depth(&self, pool: &str) -> u64 {
        self.queued_depth.depth(pool)
    }
    fn on_exhausted_fallback(&self, pool: &str) -> Option<String> {
        match self.on_exhausted_cfgs.get(pool) {
            Some(busbar_core::config::OnExhausted::FallbackPool(fallback)) => Some(fallback.clone()),
            _ => None,
        }
    }
    fn upstream_creds(&self) -> busbar_api::UpstreamCreds {
        self.upstream_credentials
    }
}

/// EXTENSION TRAIT giving `&App` the money-path table accessors that USED to be inherent `App` methods
/// in core (`App::engine_tables` / `App::llm_runtime`), relocated here WITH the tables they read (1.6.0
/// money-path Phase 3-4 C — THE PIVOT). Core no longer names [`NativeRuntime`], so these can no longer
/// be inherent on `App`; the relocated engine reaches them through this trait (in scope wherever an
/// engine submodule does `use super::*`). Byte-identical to the deleted inherent methods: ONE
/// `plane_slots` lookup by the interned fallback-plane runtime-slot key + ONE downcast, then plain field
/// reads through the returned borrow. An ABSENT slot — the featureless zero-plane boot — yields the
/// process-lifetime EMPTY default (zero lanes/pools), the byte-identical successor to the deleted
/// always-present-but-empty flat field, never a panic.
pub(crate) trait AppEngineExt {
    /// Borrow this snapshot's LLM data-plane routing tables through the [`EngineTables`] seam.
    fn engine_tables(&self) -> EngineTables<'_>;
    /// This snapshot's LLM data-plane runtime, read through the opaque plane slot; EMPTY on absence.
    fn llm_runtime(&self) -> &NativeRuntime;
    /// MUTABLE access to this snapshot's LLM data-plane runtime for IN-PLACE TEST mutation — the
    /// successor to the deleted inherent `App::llm_runtime_mut`. Reaches the runtime through the
    /// neutral `plane_slot_mut` seam + `Arc::get_mut` + downcast; panics (as the inherent method did)
    /// when the slot is absent or not uniquely owned, both test-setup invariants.
    #[cfg(any(test, feature = "test-support"))]
    fn llm_runtime_mut(&mut self) -> &mut NativeRuntime;
}

impl AppEngineExt for busbar_core::state::App {
    fn engine_tables(&self) -> EngineTables<'_> {
        EngineTables {
            rt: self.llm_runtime(),
        }
    }
    fn llm_runtime(&self) -> &NativeRuntime {
        // `runtime_slot_key(<this plane's key>)` is exactly the interned key core stored in
        // `App::llm_runtime_key` at build (`runtime_slot_key(fallback_key())`, which resolves to THIS
        // plane's `"llm"` key in every production and core-`cfg(test)` build), so this reads the same
        // slot the deleted inherent `App::llm_runtime` did.
        match self
            .plane_slot(self.llm_runtime_key())
            .and_then(|slot| slot.downcast_ref::<NativeRuntime>())
        {
            Some(rt) => rt,
            None => empty_native_runtime(),
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    fn llm_runtime_mut(&mut self) -> &mut NativeRuntime {
        let key = self.llm_runtime_key();
        std::sync::Arc::get_mut(
            self.plane_slot_mut(key)
                .expect("fallback-plane runtime slot present for in-place test mutation"),
        )
        .expect("fallback-plane runtime slot uniquely owned for in-place test mutation")
        .downcast_mut::<NativeRuntime>()
        .expect("fallback-plane runtime slot is a NativeRuntime")
    }
}

// `compose_native_runtime_slot` (the core-local runtime-slot constructor `appbuild` used while
// `NativeRuntime` still lived in core) is GONE (money-path Phase 3-4 C — THE PIVOT): the type is now
// plane-owned and the slot is composed through the plane's own `build_runtime` fn-pointer
// (`crate::engine::build_runtime::build_runtime`, wired into `PLANE_DECL.build_runtime`).

/// THE PROCESS-LIFETIME EMPTY LLM RUNTIME the money-path read ([`App::llm_runtime`]) falls back to when
/// no LLM plane contributed a slot — the featureless zero-plane binary, whose `appbuild` inserted none.
/// Zero lanes, zero pools, a single default egress shard that is never dialled (nothing routes without a
/// lane). Built once, lazily, and ONLY if such a build actually reads `engine_tables()` (a boot
/// health/metrics/telemetry probe); a normal LLM-planed boot always finds its slot and never touches
/// this. Replicates the emptiness the always-present-but-empty flat `llm_runtime` field used to carry,
/// so the field→slot move stays byte-identical for the zero-plane case — an empty read, never a panic.
fn empty_native_runtime() -> &'static NativeRuntime {
    static EMPTY: std::sync::OnceLock<NativeRuntime> = std::sync::OnceLock::new();
    EMPTY.get_or_init(|| NativeRuntime {
        lanes: Vec::new(),
        by_model: HashMap::new(),
        pools: HashMap::new(),
        pool_runtime: HashMap::new(),
        fallback_pools: HashMap::new(),
        on_exhausted_cfgs: std::collections::HashMap::new(),
        failover_cfg: None,
        queued_depth: Arc::new(QueuedDepth::default()),
        probe_schedule: Arc::new(crate::engine::health::ProbeSchedule::new(0)),
        upstream_credentials: busbar_core::auth::UpstreamCreds::default(),
        any_pool_upstream_creds_override: false,
        client: UpstreamClients::build(1, || {
            busbar_core::proxy::build_egress_client(&busbar_core::proxy::EgressClientSpec::llm_lane(
                4, 300, false, false,
            ))
        }),
        // The empty runtime's client is the never-dialled default shard; its settings key exists only
        // so the warm-reuse compare has a value to read (it never matches a real generation's).
        client_settings: busbar_substrate::plane_host::LlmClientSettings {
            upstream_request_timeout_secs: 0,
            pool_max_idle_per_host: 4,
            pool_idle_timeout_secs: 300,
            http1_only: false,
            h2_prior_knowledge: false,
        },
    })
}

/// THE LLM DATA-PLANE ROUTING TABLES, behind ONE accessor surface (R3/R4 sub-phase A, LOCKED §7
/// "wire the seam in place"). A zero-cost newtype over `&NativeRuntime`, so every read through it is
/// byte-identical to reading the bundle directly. It exists so the engine and the model-plane readers
/// reach the pool/lane/failover tables through ONE named seam — the seam whose SOURCE sub-phase B
/// flipped from the flat `App::llm_runtime` field to the LLM plane's opaque `plane_slot` (downcast ONCE
/// per [`App::engine_tables`] call), WITHOUT touching a single reader.
#[derive(Clone, Copy)]
pub(crate) struct EngineTables<'a> {
    rt: &'a NativeRuntime,
}

impl<'a> EngineTables<'a> {
    /// The pool table — each pool name to its weighted lane members.
    pub(crate) fn pools(&self) -> &'a HashMap<String, Vec<WeightedLane>> {
        &self.rt.pools
    }

    /// The direct-model index — a model name to its lane position.
    pub(crate) fn by_model(&self) -> &'a HashMap<String, usize> {
        &self.rt.by_model
    }

    /// The lane table — each resolved upstream (model, provider, dialect, credential, egress target).
    pub(crate) fn lanes(&self) -> &'a [Lane] {
        &self.rt.lanes
    }

    /// The global default failover config (the fallback for pools that set none), if configured.
    /// Returns the field as-is so a call site keeps its own `.as_ref()` (a drop-in for `app.failover_cfg`).
    pub(crate) fn failover_cfg(&self) -> &'a Option<busbar_core::config::FailoverCfg> {
        &self.rt.failover_cfg
    }

    /// Per-pool runtime (resolved members / per-pool `upstream_credentials:` override state).
    pub(crate) fn pool_runtime(&self) -> &'a HashMap<String, PoolRuntime> {
        &self.rt.pool_runtime
    }

    /// The ALL-POOLS upstream-credential default (the pool-less egress path's `Own`/`Passthrough`).
    pub(crate) fn upstream_creds(&self) -> busbar_core::auth::UpstreamCreds {
        self.rt.upstream_creds()
    }

    /// The upstream-credential mode for `pool` — its own `upstream_credentials:` override, else the
    /// all-pools default (the scalar combine rule).
    pub(crate) fn pool_upstream_creds(&self, pool: &str) -> busbar_core::auth::UpstreamCreds {
        self.rt.pool_upstream_creds(pool)
    }

    /// The fallback-pool routing table — a pool's `on_exhausted = fallback_pool:<name>` target set.
    pub(crate) fn fallback_pools(&self) -> &'a HashMap<String, Vec<WeightedLane>> {
        &self.rt.fallback_pools
    }

    /// The per-pool queue-depth gauge (the `on_exhausted = queue` waiter park counter).
    pub(crate) fn queued_depth(&self) -> &'a std::sync::Arc<QueuedDepth> {
        &self.rt.queued_depth
    }

    /// The per-pool `on_exhausted:` policy table (fallback-pool / queue / least-bad / 503).
    pub(crate) fn on_exhausted_cfgs(
        &self,
    ) -> &'a std::collections::HashMap<String, busbar_core::config::OnExhausted> {
        &self.rt.on_exhausted_cfgs
    }

    /// The health-probe schedule shared across snapshots of this lineage.
    pub(crate) fn probe_schedule(&self) -> &'a std::sync::Arc<crate::engine::health::ProbeSchedule> {
        &self.rt.probe_schedule
    }

    /// The shared upstream HTTP client pool (the LLM egress transport).
    pub(crate) fn client(&self) -> &'a UpstreamClients {
        &self.rt.client
    }
}
