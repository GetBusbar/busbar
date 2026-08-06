// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::Arc;

pub(crate) use crate::proto::Protocol;
pub(crate) use crate::store::now;
pub(crate) use crate::store::LaneRuntime;

use reqwest::Client;

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
    pub(crate) protocol: Arc<Protocol>,
    /// Outbound credential — how this lane presents Busbar's identity to the upstream. Resolved once
    /// at boot from (protocol, auth). See `crate::egress_auth`; the request path calls `headers_for`.
    pub(crate) credential: Arc<dyn crate::egress_auth::CredentialProvider>,
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
    pub(crate) health: Option<crate::config::HealthCfg>,
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
    /// `crate::proto::DEFAULT_MAX_TOKENS` when unset.
    pub(crate) default_max_tokens: Option<u32>,
    /// Optional upstream model name override. When set, this value is sent to the provider as the
    /// model identifier in the request body and URL path, instead of `self.model` (the config key).
    /// Useful when the provider expects a different model string (e.g. Bedrock model IDs).
    pub(crate) upstream_model: Option<String>,
}

impl Lane {
    /// The model name to send on the wire. Returns `upstream_model` when set,
    /// otherwise falls back to the config key (`self.model`).
    pub(crate) fn wire_model(&self) -> &str {
        self.upstream_model.as_deref().unwrap_or(&self.model)
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
    pub(crate) failover: Option<crate::config::FailoverCfg>,
    /// Per-pool OVERRIDE of the all-pools `pools.upstream_credentials:` default (1.5.3).
    /// `None` = inherit `App::upstream_credentials`. Read per request by
    /// [`App::pool_upstream_creds`].
    pub(crate) upstream_credentials: Option<crate::auth::UpstreamCreds>,
    /// Per-pool session-affinity settings (which request header pins a session to a lane).
    pub(crate) affinity: Option<crate::config::AffinityCfg>,
    /// Per-pool breaker settings (trip mode/thresholds + cooldown backoff), resolved into the
    /// runtime `store::BreakerCfg` the FSM evaluates. `None` falls back to ADR-0002 defaults.
    pub(crate) breaker: Option<crate::store::BreakerCfg>,
    /// Per-pool routing policy, resolved ONCE at config load. `None` is the ZERO-COST default
    /// (`route: weighted` / absent / explicit-native-weighted): no policy object, no projection, the
    /// unchanged inline SWRR hot path. `Some(_)` is a non-default policy whose ranked order feeds the
    /// failover loop: `proxy::decide_policy_order` invokes it per request and `pick_among` walks the
    /// resulting order.
    pub(crate) policy: Option<crate::hooks::ResolvedPolicy>,
    /// This pool's DECISION GATES (`hook:` / the non-strategy names in `hooks: [...]`), resolved once
    /// at config load, each with its `priority`, in config order. Fired in the phase-2 decision
    /// reconcile alongside the global gates (one priority-sorted chain; stable sort keeps
    /// globals-before-pool on ties, then config order). Empty (the default) = no pool gates — the
    /// phase-2 pass is skipped entirely when this and `global_gates` are both empty.
    pub(crate) gates: Vec<(u16, crate::hooks::ResolvedPolicy)>,
    /// This pool's REWRITE chain — the `prompt: rw` gates in its `hooks: [...]` list, resolved once
    /// at config load, ascending-priority order. Fired in the phase-1 transform pass AFTER the
    /// global rewrite chain, only for requests routed to this pool. Empty (the default) = no pool
    /// rewrites, zero cost.
    pub(crate) rewrite_hooks: Vec<(std::time::Duration, Arc<dyn crate::hooks::RoutingPolicy>)>,
}

/// The upstream HTTP client, SHARDED: N identical `reqwest::Client`s, each owning its own
/// connection pool, one selected per thread. ONE shared client meant one pool mutex that every
/// request crossed twice (connection checkout + checkin) across every worker — a lock convoy
/// that grows with core count (measured: throughput fell ~36% from concurrency 64 → 1024 on a
/// 4-core pin, and inverted busbar's standing against per-worker-sharded gateways on 32-thread
/// x86). Each worker thread is assigned one shard on first use and keeps it: warm connections
/// and TLS sessions stay worker-local, and each shard's pool lock is contended by ~1/Nth of the
/// threads. NOT configurable — the shard count derives from the machine (`min(cores, 16)`,
/// power of two) and the per-host idle budget is divided across shards so the TOTAL kept-alive
/// sockets toward any upstream are unchanged.
#[derive(Clone)]
pub(crate) struct UpstreamClients {
    shards: Arc<[Client]>,
}

impl UpstreamClients {
    /// The shard count for this machine: `min(available cores, 16)` rounded up to a power of two
    /// (so shard selection is a mask, not a modulo). 16 caps the idle-socket multiplication on
    /// very wide boxes; beyond ~16 shards the residual per-shard contention is negligible.
    pub(crate) fn shard_count() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .next_power_of_two()
            .min(16)
    }

    /// Build N shards from a builder factory (each shard is an IDENTICAL client; reqwest clients
    /// cannot be cloned into independent pools, so the builder runs once per shard).
    pub(crate) fn build(count: usize, mut make: impl FnMut() -> Client) -> Self {
        let shards: Arc<[Client]> = (0..count.max(1)).map(|_| make()).collect();
        UpstreamClients { shards }
    }

    /// This thread's client. Threads are assigned shards round-robin on FIRST use and keep the
    /// assignment for their lifetime (a tokio worker's requests always reuse its own shard's
    /// warm connections). The assignment counter is the only shared write, paid once per thread
    /// per process lifetime — never per request.
    pub(crate) fn get(&self) -> &Client {
        static NEXT_THREAD: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        thread_local! {
            static SHARD: std::cell::OnceCell<usize> = const { std::cell::OnceCell::new() };
        }
        let idx = SHARD.with(|s| {
            *s.get_or_init(|| NEXT_THREAD.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
        });
        // Mask, not modulo: the count is a power of two by construction (and >= 1).
        &self.shards[idx & (self.shards.len() - 1)]
    }
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

/// `Clone` is the config-apply enabler: cloning an `App` shares the live-state `Arc`s (store, auth,
/// governance, client — the things that must SURVIVE a config change) and deep-copies the
/// config-derived collections (lanes, pools, hooks, …). So `apply` builds the next snapshot as
/// `let mut next = (*current).clone(); /* mutate config-derived fields */` and `AppHandle::swap`s it,
/// while in-flight requests keep serving on the old snapshot and the SAME breaker/latency state.
#[derive(Clone)]
pub(crate) struct App {
    /// TELEMETRY BANK slots for THIS config generation (see `telemetry.rs`): every hot-path metric
    /// site resolves its pre-registered per-thread slot through this table instead of building a
    /// recorder key per emission. Rebuilt whenever a new snapshot changes the pool/lane label space
    /// (`build_app` / config apply); identical label sets re-intern to the same process-lifetime
    /// slots, so counts accumulate monotonically across generations. Observation only — THE RULE:
    /// enforcement counts never go through the bank.
    pub(crate) tslots: Arc<crate::telemetry::AppSlots>,
    pub(crate) lanes: Vec<Lane>,
    pub(crate) store: Arc<dyn LaneRuntime>,
    /// The health-probe schedule, shared by every clone-derived snapshot of this lineage so a swap
    /// does not reset the probe phase. See [`crate::health::ProbeSchedule`].
    pub(crate) probe_schedule: Arc<crate::health::ProbeSchedule>,
    pub(crate) by_model: HashMap<String, usize>,
    /// Pool members, each carrying a lane index and its configured weight.
    pub(crate) pools: HashMap<String, Vec<WeightedLane>>,
    /// The ALL-POOLS `upstream_credentials:` default — see [`App::upstream_creds`].
    pub(crate) upstream_credentials: crate::auth::UpstreamCreds,
    pub(crate) client: UpstreamClients,
    pub(crate) auth: Arc<crate::auth::AuthMiddleware>,
    /// GLOBAL rewrite hooks — the `prompt: rw` gates named in `global_hooks`, resolved to their
    /// transports and sorted by ascending `priority` (the transform-chain order). Fired before
    /// dispatch to mutate the request body (compression/redaction). Empty (the default) = no rewrite
    /// pass, zero cost. Only `rw` gates land here — the grant is enforced at RESOLUTION, so a
    /// `ro`/`no` hook can never rewrite (the bidirectional grant holds by construction). Each entry is
    /// `(per-hook transform deadline, transport)`.
    pub(crate) rewrite_hooks: Vec<(std::time::Duration, Arc<dyn crate::hooks::RoutingPolicy>)>,
    /// GLOBAL request-stage TAP hooks — the `kind: tap` hooks in `global_hooks` observing at the
    /// `request` stage, resolved to their transports. Fired FIRE-AND-FORGET (spawned off the request
    /// path) before dispatch — a tap can never delay or fail the request. Empty (the default) = no
    /// taps, zero cost. Each entry is `(per-hook deadline, send_prompt, transport)`: `send_prompt`
    /// carries the tap's `prompt: ro` grant so a granted tap receives the prompt-content projection and
    /// a `prompt: no` tap receives shape-only. Other stages (candidate/routing/response + synthetic
    /// rejected-completion) are follow-ups.
    pub(crate) tap_hooks: Vec<crate::hooks::TapEntry>,
    /// GLOBAL taps observing at the CANDIDATE stage (`at: candidate`) — fired once per request when the
    /// decision reconcile has produced the final candidate set. Same triple shape as `tap_hooks`.
    pub(crate) tap_hooks_candidate: Vec<crate::hooks::TapEntry>,
    /// GLOBAL taps observing at the ROUTING stage (`at: routing`) — fired per failover attempt with
    /// the attempt number / dispatched target / remaining candidates / previous failure.
    pub(crate) tap_hooks_routing: Vec<crate::hooks::TapEntry>,
    /// GLOBAL taps observing at the RESPONSE stage (`at: response`) — fired once per request
    /// with the outcome (`ok`/`failed`/`rejected_by_gate` — the SYNTHETIC completion, so audit taps
    /// see gate denials too) and response status.
    pub(crate) tap_hooks_response: Vec<crate::hooks::TapEntry>,
    /// GLOBAL DECISION gates — the non-rewrite `kind: gate` hooks in `global_hooks`, resolved to
    /// their full `ResolvedPolicy` (transport + on_error/on_empty/grants), each with its `priority`.
    /// Fired CONCURRENTLY on every request in the phase-2 decision reconcile, merged with the pool's
    /// own gates into one priority-sorted chain (reject wins / restricts intersect / order
    /// last-wins). Empty (the default) = no global gates, zero cost. Pre-sorted ascending by
    /// priority so the merge's stable sort keeps globals-first on ties.
    pub(crate) global_gates: Vec<(u16, crate::hooks::ResolvedPolicy)>,
    /// The raw `hooks:` registry (name → definition) as configured, for the Admin API v1 hooks READ
    /// surface (`GET /api/v1/admin/hooks`). This is the DEFINITION set, distinct
    /// from the RESOLVED transports in `rewrite_hooks`/`tap_hooks` (which the request path fires). Empty
    /// when no hooks are configured. Read-only after construction; the config-plane mutation surface
    /// swaps a new `App` snapshot rather than mutating this in place.
    /// The plugin-resolution environment for hooks: the validated plugin registry + the shared
    /// projectors. Threaded to the admin control-plane reads/writes (configure/status/schema) and the
    /// Prometheus scrape so they open a hook's `kind: hook` plugin the same way the request path's
    /// resolved transports did. Cheap to clone (Arc-backed). Replaces the retired webhook client the
    /// out-of-process transport needed.
    pub(crate) hook_env: crate::hooks::HookEnv,
    pub(crate) hook_registry: HashMap<String, crate::config::HookCfg>,
    /// The "decision observability" signal catalog's config-generation
    /// `RequestedSignals` bitmask — the UNION of every hook's declared `signals:` — built ONCE
    /// alongside `hook_registry` above, never per request. All-zero (the default) when no hook
    /// anywhere declares a catalog signal, which is the zero-cost path every `requested.wants(_)`
    /// check downstream short-circuits on.
    pub(crate) requested_signals: crate::hooks::RequestedSignals,
    /// The config generation's UNION OF EXPORT PROJECTIONS — the union across every configured
    /// `export:` instance of the streams (and fields) it subscribes to. Built ONCE per config apply
    /// from the resolved `export:` block, never per request.
    ///
    /// THE COMPUTE GATE, and deliberately the SAME mechanism as `requested_signals` directly above:
    /// the read runs ONLY when something declared it, never call-then-discard. Nothing subscribed ⇒
    /// core never assembles that stream's records at all. It supersedes the one-off
    /// `export::request_log_configured()` boolean this replaced — one mechanism for "did anybody ask
    /// for this", not two.
    pub(crate) export_projections: crate::export::projection::ProjectionUnion,
    /// The `global_hooks:` list — names fired on every request (plus any hook with inline `global:
    /// true`). Carried for the hooks read surface so a definition can report whether it is globally
    /// wired. Read-only after construction.
    pub(crate) global_hooks: Vec<String>,
    /// Hook names defined in the BASE config file (pre-overlay). `PUT /api/v1/admin/hooks/{name}` on a
    /// base hook is a 409 (edit the file, don't shadow it); API-registered (overlay) hooks replace
    /// freely. Immutable after boot.
    pub(crate) base_hook_names: std::collections::HashSet<String>,
    /// The raw `groups:` registry (name → definition) as the EFFECTIVE config resolves it (base +
    /// overlay), for the Admin API v1 groups READ + MUTATION surface (`GET/POST/PUT/DELETE
    /// /api/v1/admin/groups`). This is the source-of-truth `GroupCfg` map — distinct from the LOSSY
    /// projection in `cost.groups()` (which buckets limits per window and drops `child_default`).
    /// A group mutation swaps a new `App` snapshot (clone → mutate this map → re-validate → rebuild
    /// `cost` via `CostModel::with_groups`), never mutating in place. Empty when none configured.
    pub(crate) groups_registry: std::collections::BTreeMap<String, crate::config::GroupCfg>,
    /// Group names defined in the BASE config file (pre-overlay). A `PUT`/`DELETE` on a base group is
    /// a 409 (edit config.yaml — the API cannot silently shadow or subtract operator file config, and
    /// the additive overlay can't durably remove a base group); API-created (overlay) groups mutate
    /// freely. Immutable after boot — mirrors `base_hook_names`.
    // Read by the groups-CRUD PUT/DELETE base-shadow guard.
    #[allow(dead_code)]
    pub(crate) base_group_names: std::collections::HashSet<String>,
    /// The EFFECTIVE `identity-providers:` NAMED-DEFINITION map (base `config.yaml` + the overlay's
    /// API-applied entries). The READ side of the generic named-map admin CRUD
    /// (`GET /api/v1/admin/identity-providers[/{name}]`); the WRITE side never mutates this in place
    /// — it rewrites the overlay section and rebuilds a whole `App` from disk, exactly as
    /// `PUT /config/settings` does, because an IdP change re-resolves the auth + admin chains.
    pub(crate) identity_providers: crate::config::IdentityProviders,
    /// The EFFECTIVE `export:` NAMED-DEFINITION map — the exporter twin of `identity_providers`,
    /// serving `GET /api/v1/admin/export[/{name}]`. The lowered runtime projection lives in the
    /// recorder / plugin-route table, never here.
    pub(crate) export_defs: crate::config::ExportDefs,
    /// Per-principal ADMIN MUTATION rate limiter. Arc-shared across apply snapshots so the
    /// windows survive every swap.
    pub(crate) mutation_limiter: Arc<crate::admin::rate::MutationLimiter>,
    /// Idempotency-Key replay cache for key minting (bounded, ~10min TTL): a retried POST with the
    /// same key returns the FIRST response verbatim instead of double-creating. Arc-shared across
    /// swaps. Maps (principal id, Idempotency-Key) → (created_at, cached 201 body). The key is
    /// SCOPED TO THE PRINCIPAL: a different admin presenting the same Idempotency-Key value must
    /// NOT replay another principal's response (which carries a once-shown secret) — the header is
    /// a client-chosen string, not a cross-principal handle.
    #[allow(clippy::type_complexity)]
    pub(crate) idempotency_cache: Arc<
        std::sync::Mutex<std::collections::HashMap<(String, String), (u64, serde_json::Value)>>,
    >,
    /// Config VERSION HISTORY — every successful config-plane mutation records its snapshot here.
    /// Arc-shared across apply snapshots (survives every swap); bounded ring (see
    /// `admin::versions`).
    pub(crate) versions: Arc<crate::admin::versions::VersionLog>,
    /// The ADMIN auth chain (`admin_auth:` module names, default `[admin-tokens]`) — executed by
    /// the auth middleware for `/admin` paths. Empty = the explicit OPEN admin posture (dev).
    pub(crate) admin_chain: Vec<String>,
    /// The RESOLVED external admin auth PLUGINS — every non-builtin `admin_auth:` entry opened over
    /// the signed `kind: auth` ABI (1.5.2 admin-plane OIDC). Keyed by the config module name (the
    /// same string `admin_chain` names and `role_bindings.<module>` binds). `admin-tokens` is NOT
    /// here (it is an engine arm, dispatched by name in `run_admin_chain`). `has_plugin` gates the
    /// off-reactor offload of the admin chain (a plugin can do blocking JWKS/introspection I/O).
    /// Rebuilt on boot AND reload (`build_app_from_config`), Arc-shared so `App::clone` is cheap.
    pub(crate) admin_modules: Arc<crate::auth::AdminAuthChain>,
    /// The RESOLVED hosted-login methods (`auth.methods:`, 1.5.2) — each opened as a login
    /// capable `kind: auth` plugin over ABI v2, keyed by the config method/module name (insertion
    /// order = login-page button order). Carries the CORE-only confidential-client secret and the
    /// `browser_login` flag. `GET /auth/token` renders a button per method with a button and drives
    /// its begin/callback. Rebuilt on boot AND reload; Arc-shared for cheap `App::clone`.
    pub(crate) login_methods: Arc<crate::auth::token::LoginMethods>,
    /// busbar's PUBLIC base origin (top-level `public_url:`, 1.5.2) — the origin the hosted login
    /// page builds its `/auth/token` authorize/redirect links from and shows devs as their BYOK
    /// `base_url` (verbatim, no `/v1`). `None` ⇒ no hosted login (config_validate requires it when
    /// any `browser_login` method is configured). Rebuilt on every apply/reload.
    pub(crate) public_url: Option<String>,
    /// The credential cache — Arc-shared ACROSS config swaps (like the
    /// mutation limiter): an apply/reload must not silently re-open every cached-allow window.
    pub(crate) credential_cache: Arc<crate::auth_cache::CredentialCache>,
    /// Per-module `max_admin_scope:` ceilings (from the auth chain entries) - consulted at admin
    /// scope resolution.
    pub(crate) auth_scope_caps: std::collections::HashMap<String, String>,
    /// `auth.role_bindings:` - module -> role -> operator policy (S4: nested by module). Read by
    /// the admin authorization resolution and the governance re-key; an unbound role grants
    /// nothing (fail closed).
    pub(crate) role_bindings: crate::config::RoleBindings,
    /// The config.yaml path busbar booted from — `POST /api/v1/admin/config/reload` re-runs the boot
    /// disk-load pipeline against it. `None` (tests / ephemeral) ⇒ reload is `invalid_request`.
    pub(crate) config_path: Option<std::path::PathBuf>,
    /// The providers.yaml path (same role as `config_path`).
    pub(crate) providers_path: Option<std::path::PathBuf>,
    /// The config-overlay backend path, resolved from the `config.overlay` block (1.5.3). `Some` = a
    /// MUTABLE config: an API-applied change is written here so it survives a restart (re-merged onto
    /// base config at boot). `None` = a LOCKED config (`config.locked: true`): admin-API config
    /// mutations are refused (a persist against `None` errors — see `overlay::NO_WRITABLE_OVERLAY_MSG`).
    /// The boot invariant guarantees a mutable config always has a writable backend here. Carried on
    /// `App` (not a global) so it is testable + survives config swaps (`App::clone` copies it).
    pub(crate) overlay_path: Option<std::path::PathBuf>,
    /// Monotonic config version — `0` at boot, incremented by each API config apply (the swap builds
    /// the next snapshot with `config_version + 1`). Exposed on `GET /api/v1/admin/info` so drift-detection
    /// tooling can tell whether the running config changed since a prior read. Process-local (resets on
    /// restart); durable version history + rollback is a follow-up.
    pub(crate) config_version: u64,
    /// Anti-sprawl cap on keys BOUND TO ONE GROUP.
    /// Because a `user:<sub>` leaf IS the principal, this is effectively "max keys per principal".
    /// `0` = unlimited (default). Enforced at `POST /keys`; carried on the snapshot so a config apply
    /// can change it (survives `App::clone`).
    pub(crate) max_keys_per_principal: usize,
    /// Anti-sprawl cap on the NUMBER of groups a mint may AUTO-PROVISION
    /// (`limits.max_auto_provisioned_groups`). The key cap bounds a group's contents; this bounds
    /// the tree's SHAPE, which a `mint`-scope credential could otherwise grow without bound
    /// `0` = unlimited (default). Carried on the snapshot for the same reason as
    /// `max_keys_per_principal`.
    pub(crate) max_auto_provisioned_groups: usize,
    /// Default failover config (deadline_s and max_failover cap) when a pool has no override.
    pub(crate) failover_cfg: Option<crate::config::FailoverCfg>,
    /// Per-pool runtime config (failover/exclusions today; breaker/affinity as they're wired).
    pub(crate) pool_runtime: HashMap<String, PoolRuntime>,
    /// Fallback pools mapping (pool name -> WeightedLane vec) for fallback mode.
    pub(crate) fallback_pools: HashMap<String, Vec<WeightedLane>>,
    /// OnExhausted config per pool name.
    pub(crate) on_exhausted_cfgs: std::collections::HashMap<String, crate::config::OnExhausted>,
    /// Live per-pool `on_exhausted: queue` park depth — the source behind `busbar_pool_queued`.
    /// Arc-shared across config swaps so an in-flight parked request and a scrape agree (see
    /// [`QueuedDepth`]).
    pub(crate) queued_depth: Arc<QueuedDepth>,
    /// governance runtime (virtual keys + budgets/limits store). `None` = disabled.
    pub(crate) governance: Option<std::sync::Arc<crate::governance::GovState>>,
    /// The SECRET RESOLVER seam (P2): resolves a config [`crate::config::SecretRef`] to bytes via
    /// the built-in `env`/`file` modules or a loaded `kind: secret` plugin. Held so the TLS listener
    /// (built after `build_app` returns) resolves cert/key/CA references through the same seam that
    /// resolved provider keys and the admin token at build time.
    pub(crate) secret_resolver: std::sync::Arc<crate::config::secret::SecretResolver>,
    /// The resolved COST MODEL (rate card + budget groups + flat fee), rebuilt with the config on
    /// every apply/reload while `governance` (the token ledger) survives the swap - which is what
    /// makes a rate-card correction reprice every past and future derived figure on the next read.
    pub(crate) cost: std::sync::Arc<crate::cost::CostModel>,
    /// The directory the signed plugin tarballs live in (`plugins.dir`, default `plugins`). Carried
    /// on the snapshot so the Admin API plugin catalog (`GET /api/v1/admin/plugins?type=store`) and
    /// the install/remove/reload endpoints operate on the SAME directory the boot store-load
    /// resolves against — one source of truth, and it survives config swaps (`App::clone` copies it).
    pub(crate) plugins_dir: std::path::PathBuf,
    /// The whole `plugins.*` block (master switch + trust + floors) — re-used at admin-install to
    /// RE-VERIFY an uploaded plugin server-side (the client is never trusted) and to project each
    /// catalog entry's trust verdict. Carried on the snapshot (not a global) so it is testable and
    /// survives swaps.
    pub(crate) plugins_cfg: crate::config::PluginsCfg,
    /// Global fallback for the translation-injected `max_tokens` (`limits.default_max_tokens`), used
    /// at the cross-protocol seam when a lane has no per-lane `default_max_tokens`. Defaults to
    /// `proto::DEFAULT_MAX_TOKENS` (4096). Read by `IrReq::prepare_for_egress` at the cross-protocol seam.
    pub(crate) default_max_tokens: u32,
    /// Resolved effort-word → thinking-budget table for the cross-protocol reasoning carry
    /// (`limits.reasoning_effort_budgets`, defaults 1024/4096/8192/16384), ordered
    /// [minimal, low, medium, high]. Stamped onto the IR at the egress seam so writers project
    /// effort words and numeric budgets with the operator's numbers.
    pub(crate) reasoning_effort_budgets: [u32; 4],
    /// The self-serve (token-exchange) key lifetime in seconds, resolved from `auth.key_ttl`
    /// (`parse_duration_secs`, default [`crate::admin::DEFAULT_KEY_TTL_SECS`] = 90d). This is where
    /// the Step-1 `auth.key_ttl` field is finally READ: `POST /auth/token` mints every self key with
    /// `exp = now + self_key_ttl_secs`. Rebuilt on every apply/reload with the rest of the snapshot.
    pub(crate) self_key_ttl_secs: u64,
    /// Per-request correlation-id generator: `fetch_add(1, Relaxed)` stamps a fresh `u64` on every
    /// inbound request (see [`App::next_request_id`]), so a routing DECISION (the hook seam) can be
    /// joined to its OUTCOME (the response tap) and per-request log lines are correlatable — a
    /// single monotonic atomic, never a UUID/String, so it costs no per-request allocation, RNG
    /// draw, or syscall on the hot path.
    ///
    /// SEEDED ONCE AT BOOT from OS entropy (`state::seed_request_id_counter`), not zero, so ids are
    /// a real cross-restart join key (two runs of the process don't restamp the same small integers
    /// starting at 1) — see that function's doc for the entropy source + fallback.
    ///
    /// Lives on `App` (not a bare `static AtomicU64`) so it is Arc-shared like `store`/
    /// `probe_schedule`: a config apply's `(*current).clone()` and a REBUILD's carry-over from
    /// `prior` (`build_app_from_config`) both keep the SAME counter instance, so ids stay monotonic
    /// across a config reload the way `versions`/`mutation_limiter` already do — and it is
    /// constructible per-test (no hidden global), matching this file's existing "no global mutable
    /// state" convention for live per-process counters (see `QueuedDepth`, `VersionLog`).
    pub(crate) request_id_counter: Arc<std::sync::atomic::AtomicU64>,
    /// The live PLUGIN HTTP ROUTE TABLE: the collision-checked, namespace-confined
    /// `{path, method}` → owning-plugin index behind every registered plugin route (`/metrics`, a
    /// hook's `/feedback`). Carried on the snapshot (Arc-shared for cheap `App::clone`) so the mounted
    /// route handler resolves the CURRENT owner on every request — a hot-swapped telemetry plugin never
    /// leaves a stale route. Empty until an export/hook plugin declares a route; an empty table
    /// is inert (no mounts, `declared_auth` returns `None`, so the auth middleware is unaffected).
    pub(crate) plugin_routes: Arc<crate::plugin_routes::PluginRouteTable>,
    /// The plugin-route PATHS this PROCESS can actually serve: the [`plugin_routes`] table's path set
    /// as it stood at BOOT, carried forward byte-identical through every rebuild
    /// (`build_app_from_config` inherits it from `prior`; only a fresh boot, `prior == None`, seeds it).
    ///
    /// It is deliberately NOT `plugin_routes.paths()` of the current snapshot: each declared path is
    /// registered on the axum router once, at boot, and a config apply swaps only `Arc<App>` — the
    /// router is never rebuilt. So a config that ADDS a path (an `export:` prometheus instance where
    /// none existed at boot) is durably stored and live on the snapshot, yet the path keeps 404ing
    /// until a restart. This is the only thing that knows the difference, and it is what lets a config
    /// mutation tell the operator "restart required" instead of silently no-opping
    /// ([`crate::plugin_routes::paths_awaiting_restart`]).
    pub(crate) boot_route_paths: Arc<std::collections::HashSet<String>>,
}

impl App {
    /// The ALL-POOLS UPSTREAM-credential DEFAULT — whether the egress path signs with busbar's
    /// configured lane key (`Own`) or forwards the caller's credential (`Passthrough`). Resolved once
    /// at construction from the reserved `pools.upstream_credentials:` key (1.5.3 — it used to be
    /// `auth.upstream_credentials`), never mutated. Cheap: `Copy`.
    ///
    /// Prefer [`App::pool_upstream_creds`] on any path that knows its pool: a pool's own
    /// `upstream_credentials:` OVERRIDES this (the SCALAR combine rule). This accessor is
    /// the right one only where there IS no pool (direct/ad-hoc model routes, health probes).
    pub(crate) fn upstream_creds(&self) -> crate::auth::UpstreamCreds {
        self.upstream_credentials
    }

    /// The UPSTREAM-credential mode in force for `pool`: the pool's own `upstream_credentials:` when
    /// it sets one, else the all-pools default ([`App::upstream_creds`]). SCALAR override, never a
    /// union — the pool's value REPLACES the inherited one. An empty/unknown pool name
    /// (the direct-model and degraded ad-hoc routes) falls back to the default.
    pub(crate) fn pool_upstream_creds(&self, pool: &str) -> crate::auth::UpstreamCreds {
        self.pool_runtime
            .get(pool)
            .and_then(|rt| rt.upstream_credentials)
            .unwrap_or(self.upstream_credentials)
    }

    /// Stamp the NEXT per-request correlation id: one relaxed `fetch_add`, no allocation, no
    /// syscall. Called ONCE per inbound request, at the earliest point `RequestCtx` is built
    /// (`forward_with_pool_parsed`) — every failover hop of that request reuses the SAME id (it
    /// rides `RequestCtx::request_id`, not re-derived here per hop).
    pub(crate) fn next_request_id(&self) -> u64 {
        self.request_id_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
}

/// Boot-time seed for [`App::request_id_counter`]: one draw of OS randomness so per-request ids
/// differ across process restarts (a real join key in logs/cost records, not just unique within one
/// run — two `fetch_add`-from-zero runs would otherwise both hand out `0, 1, 2, …`). Falls back to
/// boot unix-nanos on the (practically unreachable — see the `getrandom::fill` call sites elsewhere
/// in this crate, e.g. `auth::token`) case the OS entropy source errors, rather than panicking boot
/// over a cosmetic collision-avoidance seed.
pub(crate) fn seed_request_id_counter() -> u64 {
    let mut buf = [0u8; 8];
    match getrandom::fill(&mut buf) {
        Ok(()) => u64::from_le_bytes(buf),
        Err(_) => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    }
}

/// A swappable handle to the current `App` snapshot — the seam that lets an admin config `apply`
/// replace the running configuration atomically WITHOUT restarting or blocking in-flight requests.
///
/// The router's state is `Arc<AppHandle>`. Every handler and the auth middleware call `load()` to get
/// the CURRENT snapshot at that instant (an owned `Arc<App>`, no lock held across any `.await`).
/// In-flight requests keep the snapshot they already loaded (the old `Arc<App>` stays alive until its
/// last reference drops); new requests see the new one. `swap()` replaces the pointer under a brief
/// write lock — the only writer is the admin apply path, so the read side is effectively uncontended
/// (a `RwLock` read + `Arc` clone, ~tens of nanoseconds). Behaviorally identical to a fixed
/// `Arc<App>` until something calls `swap()`.
pub(crate) struct AppHandle {
    current: std::sync::RwLock<Arc<App>>,
}

impl AppHandle {
    pub(crate) fn new(app: Arc<App>) -> Self {
        Self {
            current: std::sync::RwLock::new(app),
        }
    }

    /// The current `App` snapshot. Clones the `Arc` (cheap) and releases the read lock immediately.
    /// A poisoned lock (a panic in a prior holder) still guards a valid `Arc<App>` — recover it rather
    /// than propagate, since the guarded value is a single pointer with no inconsistent state to fear.
    pub(crate) fn load(&self) -> Arc<App> {
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Atomically replace the current snapshot (the admin config-mutation seam: reload, apply, and every
    /// hook/auth mutation). Re-spawns the health probers against `next`: probers hold a `Weak<App>` and
    /// exit once the App they were spawned against drops, so EVERY swap must re-attach them —
    /// otherwise the first admin mutation replaces the boot App, the boot App drops as in-flight requests
    /// drain, its probers exit, and active/dead health probing silently STOPS even though lanes/health are
    /// unchanged (before 1.4.0 only reload/apply re-spawned; the six hook/auth-mutation swaps did not).
    /// Doing it in `swap` itself makes it impossible for a future swap site to forget.
    pub(crate) fn swap(&self, next: Arc<App>) {
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = next.clone();
        crate::health::spawn_probers(&next);
    }

    /// Commit a live-config mutation as PERSIST-then-SWAP, FAIL-CLOSED — the ONE sanctioned way to
    /// apply a mutation that must survive a restart. `persist` writes the DESIRED overlay to disk; only
    /// if it succeeds do we `swap` the live engine to `next`. On a persist error nothing swaps and the
    /// error is returned (the caller records `OUTCOME_REJECTED` and returns a 4xx/5xx) — the running
    /// engine is left exactly as it was.
    ///
    /// Why this direction is the safe one, in ONE place so reset and rollback cannot diverge: a crash
    /// between persist and swap restarts ALREADY-APPLIED (disk carries the operator's change), the
    /// direction they asked for. The old swap-then-persist sites had the opposite failure window — a
    /// persist failure (or a crash before it) left the live engine AHEAD of disk, so a restart silently
    /// REVERTED the operator's applied change. `plugin.rollback` already used this discipline
    /// (persist-then-swap, fail-closed) because its rebuild re-reads the overlay; routing every mutation
    /// through here makes that discipline uniform rather than a rollback-only special case.
    pub(crate) fn commit_and_swap(
        &self,
        next: Arc<App>,
        persist: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        persist()?; // fail-closed: if disk didn't take it, do not swap.
        self.swap(next); // only after the desired state is durable.
        Ok(())
    }
}

/// An axum extractor that yields the CURRENT `App` snapshot from the router's `Arc<AppHandle>` state.
/// This is what lets every handler keep working with an `Arc<App>` while transparently reading the
/// post-apply configuration: a handler takes `CurrentApp(app): CurrentApp` instead of
/// `State(app): State<Arc<App>>`, and the rest of its body is unchanged (`app` is still `Arc<App>`).
/// A local newtype is required because the orphan rule forbids `impl FromRef<_> for Arc<App>`.
pub(crate) struct CurrentApp(pub(crate) Arc<App>);

impl<S> axum::extract::FromRequestParts<S> for CurrentApp
where
    Arc<AppHandle>: axum::extract::FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        // `State` extraction of the handle is Infallible (the handle is always present in state).
        let axum::extract::State(handle) =
            axum::extract::State::<Arc<AppHandle>>::from_request_parts(parts, state).await?;
        Ok(CurrentApp(handle.load()))
    }
}
