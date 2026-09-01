// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::Arc;

pub(crate) use crate::store::now;
pub(crate) use crate::store::LaneRuntime;

use crate::proxy::EgressClient as Client;


// ── DATA-PLANE TOPOLOGY, published once by the composition root ─────────────────────────────────
// The `busbar` binary spawns N per-worker data runtimes (thread-per-core; see main.rs) and tells
// core two things before any request is served: HOW MANY workers exist (sizes the client shards
// below, and the per-worker state stripes later stages add) and, on each worker thread, WHICH
// worker this thread is. Both are process-topology facts — set at boot, immutable, no config.

/// Total data-plane workers, set once by the composition root before serving. Unset (tests,
/// embedded uses) falls back to the machine-derived default at each consumer.
static DATA_WORKERS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// Publish the data-plane worker count. First call wins; later calls are ignored (boot runs once).
pub fn set_data_workers(n: usize) {
    let _ = DATA_WORKERS.set(n.max(1));
    // The egress engine's connect gate sizes its per-shard establishment share from this same
    // topology fact, and the engine lives in substrate, which cannot name core — so the publish
    // FORWARDS in the same boot act: one composition-root call, two subscribers, no second
    // source of the number.
    busbar_substrate::egress::engine::set_establishment_shards(n);
}

thread_local! {
    /// This thread's data-plane worker id (0..N), or `usize::MAX` on every non-worker thread
    /// (the control runtime, the blocking pool). A plain `Cell` read — no atomic — because the id
    /// is a per-thread constant after spawn.
    static WORKER_ID: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
}

/// Mark the current thread as data-plane worker `id`. Called exactly once per worker thread by the
/// composition root, after pinning and before the worker's runtime starts serving.
pub fn set_worker_id(id: usize) {
    WORKER_ID.with(|w| w.set(id));
}

/// The current thread's worker id, or `usize::MAX` for a non-worker thread.
pub(crate) fn worker_id() -> usize {
    WORKER_ID.with(|w| w.get())
}

/// Stripe count for per-worker striped store state: one stripe per data worker PLUS one shared
/// FALLBACK stripe (the last) for every non-worker thread. Constant for the process lifetime
/// (`set_data_workers` runs before anything builds; the machine-derived fallback is stable).
pub(crate) fn worker_stripes() -> usize {
    DATA_WORKERS.get().copied().unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(16)
    }) + 1
}

/// The current thread's stripe index in a `stripes`-slot stripe array: its worker id, or the
/// last (fallback) slot for a non-worker thread. `min`: defensive clamp only.
pub(crate) fn worker_stripe(stripes: usize) -> usize {
    let id = worker_id();
    if id == usize::MAX {
        stripes - 1
    } else {
        id.min(stripes - 1)
    }
}

/// The upstream HTTP client, SHARDED: N identical `reqwest::Client`s, each owning its own
/// connection pool, one selected per thread. ONE shared client meant one pool mutex that every
/// request crossed twice (connection checkout + checkin) across every worker — a lock convoy
/// that grows with core count (measured: throughput fell ~36% from concurrency 64 → 1024 on a
/// 4-core pin, and inverted busbar's standing against per-worker-sharded gateways on 32-thread
/// x86). Each worker thread is assigned one shard on first use and keeps it: warm connections
/// and TLS sessions stay worker-local, and each shard's pool lock is contended by ~1/Nth of the
/// threads. NOT configurable — the shard count is one per data-plane worker (published by the
/// composition root; machine-derived fallback for embedded/test uses) and the per-host idle
/// budget is divided across shards so the TOTAL kept-alive sockets toward any upstream are
/// unchanged.
#[derive(Clone)]
pub struct UpstreamClients {
    shards: Arc<[Client]>,
}

impl UpstreamClients {
    /// The shard count: ONE SHARD PER DATA-PLANE WORKER when the composition root published the
    /// count (`set_data_workers` — the thread-per-core binary always does), so every worker gets a
    /// pool of its own and shard selection is a direct index by worker id. Unset (tests, embedded
    /// uses that never call `set_data_workers`) falls back to the machine-derived
    /// `min(cores, 16).next_power_of_two()` the pre-topology sharding used.
    pub fn shard_count() -> usize {
        match DATA_WORKERS.get() {
            Some(&n) => n,
            None => {
                let n = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
                    .next_power_of_two()
                    .min(16);
                // UNPUBLISHED-TOPOLOGY UNIFICATION: the engine's
                // establishment machinery (connect gate permits + the pool's dial bound) divides
                // one GLOBAL per-authority budget by the shard count. When the composition root
                // never published a worker count (tests, embedded uses), this fallback is the
                // shard count — so it must ALSO be the establishment divisor, or an unpublished
                // build runs up to 16 pools × an undivided per-shard budget (16× the invariant).
                // Publishing the value HERE — from the one function that derives it — keeps a
                // single source instead of substrate re-deriving the formula cross-crate (the
                // exact drift shape the single-source rule forbids). First call wins on both
                // sides; the thread-per-core binary always publishes at boot and never gets here.
                busbar_substrate::egress::engine::set_establishment_shards(n);
                n
            }
        }
    }

    /// Build N shards from a builder factory (each shard is an IDENTICAL client; reqwest clients
    /// cannot be cloned into independent pools, so the builder runs once per shard).
    pub fn build(count: usize, mut make: impl FnMut() -> Client) -> Self {
        let shards: Arc<[Client]> = (0..count.max(1)).map(|_| make()).collect();
        UpstreamClients { shards }
    }

    /// This thread's client. A DATA-PLANE WORKER (id set at spawn) indexes its own shard directly —
    /// one thread-local `Cell` read, no shared write ever, and its warm connections/TLS sessions
    /// never cross another worker's pool lock. Any OTHER thread (the control runtime's prober,
    /// blocking-pool threads, non-unix workers without ids) keeps the prior behavior: assigned a
    /// shard round-robin on FIRST use for its lifetime — a once-per-thread counter bump, never a
    /// per-request write.
    pub fn get(&self) -> &Client {
        let id = crate::state::worker_id();
        if id != usize::MAX {
            // min: defensive only — the composition root sizes shards to the worker count, so a
            // worker id is always in range.
            return &self.shards[id.min(self.shards.len() - 1)];
        }
        static NEXT_THREAD: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        thread_local! {
            static SHARD: std::cell::OnceCell<usize> = const { std::cell::OnceCell::new() };
        }
        let idx = SHARD.with(|s| {
            *s.get_or_init(|| NEXT_THREAD.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
        });
        // Modulo, not mask: with worker-published counts the shard count is exact (= N workers),
        // not a power of two. Cold path — the result is cached per thread above.
        &self.shards[idx % self.shards.len()]
    }

    /// Do two `UpstreamClients` share the SAME underlying shard set (`Arc::ptr_eq`)? True exactly
    /// when one was cloned from the other (a config apply that REUSED the prior client for pool
    /// warmth); false when the shards were freshly built. Lets the apply path — and its tests —
    /// distinguish "carried the warm pool forward" from "rebuilt with new client settings".
    #[cfg(test)]
    pub(crate) fn shares_pool_with(&self, other: &UpstreamClients) -> bool {
        Arc::ptr_eq(&self.shards, &other.shards)
    }
}

/// The subset of resolved limits that FEEDS the upstream reqwest client build — every setting
/// whose change must produce a different client. On a config apply the prior client is reused (for
/// its warm connection pool) ONLY when this snapshot is UNCHANGED; if any field here changed, the
/// client is REBUILT so the new setting actually takes effect (a reused client would silently pin
/// the old timeout / pool sizing / protocol posture until a full process restart). Every OTHER
/// input to the builder (`connect_timeout`, `tcp_keepalive`, `tcp_nodelay`, the h2 keep-alive
/// timers, and the `redirect: none` SSRF posture) is a compile-time constant, so this snapshot is
/// exhaustive over the client-affecting configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamClientSettings {
    /// Overall streaming request timeout (`limits.upstream_request_timeout_secs`). Security-relevant:
    /// a looser timeout is a resource-exhaustion surface, so a change here MUST rebuild.
    pub upstream_request_timeout_secs: u64,
    /// Per-host idle keep-alive socket budget (`limits.pool_max_idle_per_host`).
    pub(crate) pool_max_idle_per_host: usize,
    /// Idle keep-alive lifetime (`limits.pool_idle_timeout_secs`).
    pub(crate) pool_idle_timeout_secs: u64,
    /// Pin to HTTP/1.1 (`advanced.upstream_http1_only`).
    pub(crate) upstream_http1_only: bool,
    /// Force cleartext h2 prior-knowledge (`advanced.upstream_h2_prior_knowledge`).
    pub(crate) upstream_h2_prior_knowledge: bool,
}

impl UpstreamClientSettings {
    /// Project the client-affecting subset out of the fully-resolved limits.
    pub(crate) fn from_limits(limits: &crate::config::LimitsResolved) -> Self {
        Self {
            upstream_request_timeout_secs: limits.upstream_request_timeout_secs,
            pool_max_idle_per_host: limits.pool_max_idle_per_host,
            pool_idle_timeout_secs: limits.pool_idle_timeout_secs,
            upstream_http1_only: limits.upstream_http1_only,
            upstream_h2_prior_knowledge: limits.upstream_h2_prior_knowledge,
        }
    }
}


/// Re-export the neutral companion-slot key DERIVER: a plane's ALWAYS-PRESENT per-generation runtime
/// object is carried in [`App::plane_slots`] under `runtime_slot_key(plane_key)` — the neutral
/// `"<key>:runtime"` convention — DISTINCT from the plane's own decl key, under which the
/// CONFIG-CONDITIONAL dispatch resource lives (the runtime bundle exists on every generation whereas
/// the dispatch slot is absent when the plane's config block is unspecified, so folding them onto one
/// key would change the bare key's presence semantics, and with it the dispatch table
/// `build_dispatch` derives from it). Composed into `plane_slots` by `appbuild` and read back by the
/// owning plane, each passing its decl key — so this crate names no plane runtime type or token.
pub use busbar_substrate::plane_host::runtime_slot_key;

/// One plane's per-container resolved submission-gate map: container name → resolved
/// `(hook_id, ResolvedPolicy)` gate list. The value half of [`App::plane_gates`].
pub(crate) type ContainerGateMap = HashMap<String, Vec<(u16, crate::hooks::ResolvedPolicy)>>;

/// THE GENERIC per-plane submission-gate map, keyed by each plane's stable decl key (the opaque
/// registry key) — the registry-keyed structure that replaced the former per-plane
/// `mcp_server_gates`/`a2a_agent_gates` fields, so core names no plane vocabulary in its field types.
pub(crate) type PlaneGateMap = std::collections::BTreeMap<&'static str, ContainerGateMap>;

/// `Clone` is the config-apply enabler: cloning an `App` shares the live-state `Arc`s (store, auth,
/// governance, client — the things that must SURVIVE a config change) and deep-copies the
/// config-derived collections (lanes, pools, hooks, …). So `apply` builds the next snapshot as
/// `let mut next = (*current).clone(); /* mutate config-derived fields */` and `AppHandle::swap`s it,
/// while in-flight requests keep serving on the old snapshot and the SAME breaker/latency state.
#[derive(Clone)]
pub struct App {
    /// TELEMETRY BANK slots for THIS config generation (see `telemetry.rs`): every hot-path metric
    /// site resolves its pre-registered per-thread slot through this table instead of building a
    /// recorder key per emission. Rebuilt whenever a new snapshot changes the pool/lane label space
    /// (`build_app` / config apply); identical label sets re-intern to the same process-lifetime
    /// slots, so counts accumulate monotonically across generations. Observation only — THE RULE:
    /// enforcement counts never go through the bank.
    pub(crate) tslots: Arc<crate::telemetry::AppSlots>,
    /// THE LLM DATA-PLANE RUNTIME'S SLOT KEY — the interned `runtime_slot_key(<llm plane key>)` under
    /// which THIS config generation's [`NativeRuntime`] rides in [`App::plane_slots`], the same opaque
    /// slot MCP/A2A already carry their runtimes in (R3/R4 sub-phase B — the LLM runtime moved off the
    /// flat `llm_runtime` field it was bundled into by sub-phase A). Resolved ONCE at build
    /// (`appbuild` / the test fixture) so the money-path read ([`App::engine_tables`] →
    /// [`App::llm_runtime`]) is a single cheap `plane_slots` lookup + ONE downcast, never the interning
    /// `runtime_slot_key` call. An ABSENT slot — the featureless binary boots with no LLM plane, so
    /// none was inserted — reads as an empty default (the same emptiness the always-present-but-empty
    /// flat field encoded), never a panic. Neutral: names no dialect.
    pub(crate) llm_runtime_key: &'static str,
    pub store: Arc<dyn LaneRuntime>,
    /// THE NON-LLM PLANES' BREAKER CELLS — the degenerate single-member cell per registered MCP
    /// server / A2A agent (the breaker-all-planes audit's closing design). Live state, shared by every
    /// clone-derived snapshot and REUSED across `build_app_from_config` applies exactly like
    /// `store`: learned reliability must survive a snapshot swap, or every apply un-trips every
    /// dead upstream. See [`crate::store::PlaneBreakers`] for why it is not the LLM store itself.
    pub plane_breakers: Arc<crate::store::PlaneBreakers>,
    /// THE NEUTRAL PER-SESSION SUBSTRATE ([`crate::session::SessionStore`]) — PROCESS-LIFETIME, reused
    /// across `build_app_from_config` applies exactly like `plane_breakers`, because a session's state
    /// (today the gate's cleared-scan set; tomorrow any tenant) must survive a config swap or every
    /// apply would forget every live session. Present unconditionally (an empty bounded map is cheap);
    /// whether the gate hot path CONSULTS it is the operator opt-in `incremental_scan`.
    pub(crate) session_store: Arc<crate::session::SessionStore>,
    /// Operator opt-in (env `BUSBAR_INCREMENTAL_SCAN`) for the gate's incremental-scan tenant. `false`
    /// (the default) ⇒ every gate screens the full projection every turn, byte-identical to 1.5.4; the
    /// firing sites pass `incremental: None`. Env-driven, not config, so activating it does not touch
    /// the frozen `config-schema.snapshot.json` / config-stability gate.
    // Read only by the plane request gate's incremental-scan tenant; with BOTH planes compiled out
    // nothing fires that gate, so the field goes unread in that config alone.
    #[allow(dead_code)]
    pub(crate) incremental_scan: bool,
    /// The `tool_pools:` failover pools — operator-declared interchangeable MCP server sets,
    /// carried resolved-verbatim onto the snapshot so the dispatch path's route builder
    /// (`mcp::reroute`) reads the SAME generation the request was admitted on. Empty ⇒ every
    /// server keeps its degenerate single-member cell and no reroute exists to be had.
    // MCP-only: read by the MCP dispatch route builder (`mcp::reroute`); with `plane-mcp` off (and
    // A2A on) it is carried on the snapshot but never read.
    #[allow(dead_code)]
    pub tool_pools: std::collections::BTreeMap<String, crate::failover::CandidatePoolCfg>,
    /// THE PER-PLANE FAILOVER POOL MAPS reached through the GENERIC pool-member seam
    /// ([`busbar_substrate::plane_host::EngineHost::plane_pool_members`]), keyed by the plane's stable
    /// decl key (the opaque registry key) — a registry-keyed map in place of the former plane-named
    /// `agent_pools` field, so core carries no plane vocabulary in its own field names. Each plane's
    /// entry is its `<section>.pools:` set (member selection derives lanes from member position). Read
    /// on the plane's submission/route path through [`App::plane_pools`]. (The MCP `tool_pools:` set
    /// keeps its own dedicated field + 3-tuple `tool_pool_members` seam, which also carries the pool's
    /// `repeatable:` list.)
    // Read on a plane's route/admission path; with `plane-a2a` off (and MCP on) it is never read.
    #[allow(dead_code)]
    pub(crate) plane_pools: std::collections::BTreeMap<
        &'static str,
        std::collections::BTreeMap<String, crate::failover::CandidatePoolCfg>,
    >,
    /// The client-affecting resolved-limits snapshot THIS `client` was built from. Carried so the
    /// next config apply can tell whether reusing `client` (warm pool) is safe: reuse only when this
    /// is unchanged, else rebuild so a changed timeout / pool sizing / protocol posture takes effect.
    pub client_settings: UpstreamClientSettings,
    pub(crate) auth: Arc<crate::auth::AuthMiddleware>,
    /// GLOBAL rewrite hooks — the `prompt: rw` gates named in `global_hooks`, resolved to their
    /// transports and sorted by ascending `priority` (the transform-chain order). Fired before
    /// dispatch to mutate the request body (compression/redaction). Empty (the default) = no rewrite
    /// pass, zero cost. Only `rw` gates land here — the grant is enforced at RESOLUTION, so a
    /// `ro`/`no` hook can never rewrite (the bidirectional grant holds by construction). Each entry is
    /// `(per-hook transform deadline, transport)`.
    pub rewrite_hooks: Vec<(std::time::Duration, Arc<dyn crate::hooks::RoutingPolicy>)>,
    /// GLOBAL request-stage TAP hooks — the `kind: tap` hooks in `global_hooks` observing at the
    /// `request` stage, resolved to their transports. Fired FIRE-AND-FORGET (spawned off the request
    /// path) before dispatch — a tap can never delay or fail the request. Empty (the default) = no
    /// taps, zero cost. Each entry is `(per-hook deadline, send_prompt, transport)`: `send_prompt`
    /// carries the tap's `prompt: ro` grant so a granted tap receives the prompt-content projection and
    /// a `prompt: no` tap receives shape-only. Other stages (candidate/routing/response + synthetic
    /// rejected-completion) are follow-ups.
    pub tap_hooks: Vec<crate::hooks::TapEntry>,
    /// GLOBAL taps observing at the CANDIDATE stage (`at: candidate`) — fired once per request when the
    /// decision reconcile has produced the final candidate set. Same triple shape as `tap_hooks`.
    pub tap_hooks_candidate: Vec<crate::hooks::TapEntry>,
    /// GLOBAL taps observing at the ROUTING stage (`at: routing`) — fired per failover attempt with
    /// the attempt number / dispatched target / remaining candidates / previous failure.
    pub tap_hooks_routing: Vec<crate::hooks::TapEntry>,
    /// GLOBAL taps observing at the RESPONSE stage (`at: response`) — fired once per request
    /// with the outcome (`ok`/`failed`/`rejected_by_gate` — the SYNTHETIC completion, so audit taps
    /// see gate denials too) and response status.
    pub tap_hooks_response: Vec<crate::hooks::TapEntry>,
    /// GLOBAL DECISION gates — the non-rewrite `kind: gate` hooks in `global_hooks`, resolved to
    /// their full `ResolvedPolicy` (transport + on_error/on_empty/grants), each with its `priority`.
    /// Fired CONCURRENTLY on every request in the phase-2 decision reconcile, merged with the pool's
    /// own gates into one priority-sorted chain (reject wins / restricts intersect / order
    /// last-wins). Empty (the default) = no global gates, zero cost. Pre-sorted ascending by
    /// priority so the merge's stable sort keeps globals-first on ties.
    pub global_gates: Vec<(u16, crate::hooks::ResolvedPolicy)>,
    /// THE PER-POOL ROUTING POLICY / DECISION GATES / REWRITE CHAINS, resolved ONCE at config apply
    /// (money-path Phase 3-4 C — the RATIFIED pool-hook facade). These USED to live on the LLM plane's
    /// `PoolRuntime`, but their resolved values are the core-owned `ResolvedPolicy` / `Arc<dyn
    /// RoutingPolicy>` (an Arc over a dlopen plugin), which the plane's `build_runtime` cannot resolve
    /// (no `hook_env`, no usable current-`&App`). So they stay resolved-and-read CORE-SIDE, keyed by
    /// pool, and the relocated engine reaches them through the [`App::pool_policy`] / [`App::pool_gates`]
    /// / [`App::pool_rewrites`] down-facades — byte-identical objects (the SAME resolution
    /// `hooks::resolve_pool_*` produced), read via the facade instead of stored across the plane seam.
    /// Absent pool ⇒ the zero-cost default (no policy / empty chain).
    pub(crate) pool_orderings: std::collections::HashMap<String, crate::hooks::ResolvedPolicy>,
    pub(crate) pool_decision_gates:
        std::collections::HashMap<String, Vec<(u16, crate::hooks::ResolvedPolicy)>>,
    #[allow(clippy::type_complexity)]
    pub(crate) pool_rewrite_chains: std::collections::HashMap<
        String,
        Vec<(std::time::Duration, std::sync::Arc<dyn crate::hooks::RoutingPolicy>)>,
    >,
    /// THE MCP DISPATCH GATES, per registered server: `tools.hooks:` ∪ `tools.<server>.hooks:`,
    /// resolved to their transports ONCE per config generation and keyed by server name.
    ///
    /// Keyed by CONTAINER rather than held as one list because the grammar is per-container and
    /// additive: a hook attached to one server must not fire for another. A server with no attached
    /// hook has NO ENTRY (not an empty vector), so the dispatch path's lookup answers `None` and the
    /// firing site costs one hash lookup on the default deployment.
    ///
    /// Resolved here, at config apply, for the reason every other hook list is: resolution `dlopen`s
    /// the plugin, and doing that per request would put a library load on the dispatch path.
    /// THE PER-PLANE PER-CONTAINER SUBMISSION GATES, keyed by the plane's stable decl key (the opaque
    /// registry key) — one generic registry-keyed map in place of the former per-plane
    /// `mcp_server_gates`/`a2a_agent_gates` fields, so core carries no plane vocabulary in its own
    /// field names. Each plane's entry maps container → resolved `(hook_id, ResolvedPolicy)` gate list
    /// (`<section>.hooks:` ∪ `<section>.<container>.hooks:`), same combine rule and zero-cost absence
    /// as before. Composed at config apply by `appbuild` (and re-resolved on swap through
    /// [`busbar_substrate::plane_host::ContainerGateSink`]); read on the dispatch path by
    /// [`App::plane_gates`]. Empty for a plane that attaches nothing — the lookup costs one probe.
    // Read on the plane dispatch/admission gate paths; with BOTH planes compiled out nothing fires a
    // gate, so the map goes unread in that config alone.
    #[allow(dead_code)]
    pub(crate) plane_gates: PlaneGateMap,
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
    pub hook_env: crate::hooks::HookEnv,
    pub hook_registry: HashMap<String, crate::config::HookCfg>,
    /// The "decision observability" signal catalog's config-generation
    /// `RequestedSignals` bitmask — the UNION of every hook's declared `signals:` — built ONCE
    /// alongside `hook_registry` above and recomputed by `admin::v1::service::rebuild_hook_derived`
    /// on every snapshot that rewrites that registry (so a hook registered through the admin API
    /// declaring `signals:` is honoured on the very next request, not only after a restart) — never
    /// per request. All-zero (the default) when no hook
    /// anywhere declares a catalog signal, which is the zero-cost path every `requested.wants(_)`
    /// check downstream short-circuits on.
    pub requested_signals: crate::hooks::RequestedSignals,
    /// Does this config generation grant ANY hook access to prompt CONTENT (`prompt: ro` / `rw`)?
    /// Built ONCE alongside `requested_signals` above by `hooks::any_content_hook`, and recomputed
    /// on every snapshot that rewrites `hook_registry` — never per request.
    ///
    /// This is the gate on building the request IR for the hook seam: `false` (the default, and
    /// every deployment that runs no content hook) means the IR is never built and the request path
    /// pays nothing at all. See `hooks::any_content_hook` for why the gate keys on the deployment's
    /// grants rather than on the request's protocols.
    pub any_content_hook: bool,
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
    pub global_hooks: Vec<String>,
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
    pub groups_registry: std::collections::BTreeMap<String, crate::config::GroupCfg>,
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
    /// The EFFECTIVE `agents:` NAMED-DEFINITION map — THE A2A plane, serving
    /// `GET /api/v1/admin/agents[/{name}]`. Operator INTENT only: everything that accumulates about
    /// a registered agent (observed cards, the drift queue, anomaly counters, task rows) is store
    /// state and is deliberately not reachable from a config snapshot.
    // TYPE-ERASED so `App` names no `crate::a2a` config type — the same opaque-plane-state shape the
    // MCP registry rides (`crate::mcp::runtime`'s slot). It carries the resolved `AgentsCfg` when the
    // A2A plane is compiled in and the neutral `RawPlaneSection` raw capture when it is not; either
    // way the type here is `Arc<dyn Any>`, so this field survives the A2A extraction unchanged. The
    // A2A plane downcasts it back inside its own module (`crate::a2a::agent_cfg`), and no core reader
    // outside `crate::a2a` reads it. Erasing rather than reparsing keeps the exact resolved object, so
    // the admin view and gate resolution are byte-identical to the typed field this replaced.
    // With `plane-a2a` off the whole A2A module (its only reader) is compiled out, so the field is set
    // at build and never read — allow it dead in exactly that config.
    #[allow(dead_code)]
    pub(crate) agent_defs: Arc<dyn std::any::Any + Send + Sync>,
    // THE RUNNING A2A PLANE — the registry `agent_defs` lowers to, plus everything accumulated against
    // it — has NO typed `App` field. Like its MCP sibling it lives ONLY in the type-erased
    // `plane_slots` map, and `crate::a2a::runtime(app)`/`runtime_arc(app)` downcast that slot back to
    // `A2aPlane` inside the a2a module. So `App` names no `crate::a2a` type for the runtime object, and
    // its absence — no `agents:` this generation, the gate for "is this an A2A plane?" — is read
    // straight off the slot the same way MCP reads its own, not off a typed field or a flag.
    //
    // THE A2A VERIFY-ON-CALL GATE and the boot-resolved CARD-FETCH TRANSPORTS likewise have NO `App`
    // field any more: they moved ONTO the `A2aPlane` runtime object (`A2aPlane::verify` / `::cards`),
    // exactly as MCP holds `verify` on `McpRuntime`. Verify-on-call reads them off the plane slot, and
    // `carried_a2a_gates` carries both `Arc`s across a config apply off the prior generation's plane —
    // so the coalescing epochs and the boot-set transports survive an apply without a shared-`App`
    // field, and are dropped whole when the `agents:` block is removed (no plane, no delegation).
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
    pub versions: Arc<crate::admin::versions::VersionLog>,
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
    /// THE AUTHORIZATION SERVER (`oauth_as:`), or `None` when this deployment is not one.
    ///
    /// `None` is the whole zero-cost-when-off property: nothing is constructed, nothing is
    /// allocated, no signing key exists, no sweeper runs and no route is mounted. See
    /// `crate::oauth_as`.
    pub(crate) oauth_as: Option<Arc<crate::oauth_as::plane::AsPlane>>,
    // THE MCP PLANE'S PER-GENERATION CLIENT-DIRECTION RUNTIME (`crate::mcp::McpRuntime`, which now also
    // carries the verify-on-call coalescer that was the former flat `mcp_verify` field) is no longer a
    // flat `App` field: it lives in `plane_slots` under `runtime_slot_key(<mcp decl key>)`, reached by the plane
    // through `crate::mcp::runtime` (which downcasts the slot inside the plane), so this `App` names no
    // `crate::mcp` runtime type and holds no plane-specific runtime field for it.
    /// APPROVALS ALREADY SPENT — the record that makes an operator-configured confirmation
    /// single-use.
    ///
    /// Arc-shared ACROSS config applies, for the same correctness reason the sightings cache and the
    /// mutation limiter are: this is ACCUMULATED evidence rather than intent, and rebuilding it on
    /// every apply would re-open every outstanding approval the instant an operator touched an
    /// unrelated section of config — which is the moment a caller holding a spent approval would
    /// like it rebuilt. See [`crate::plane::approvals::SpentTokenLedger`] for what a RESTART does to it
    /// and why that trade was taken.
    pub spent_token_ledger: Arc<crate::plane::approvals::SpentTokenLedger>,
    /// DEMOTIONS THAT OUTLIVE THE PROCESS THAT TOOK THEM — the write side of the durable quarantine
    /// record, and the reason a restart no longer hands a demoted upstream its approval back.
    ///
    /// Arc-shared across config applies for the same reason the two fields above are, and with one
    /// extra: the durable sink is attached to it ONCE at boot, so an instance rebuilt on an apply
    /// would be an instance with no sink — a quarantine that stopped being written down because
    /// somebody edited an unrelated section of config. See [`crate::plane::quarantine`].
    pub demotion_record: Arc<crate::plane::quarantine::DemotionRecord>,
    /// PLANE DISPATCH for this config generation: which plane an inbound path belongs to, and — for
    /// an audience-bound plane — what a token presented there must carry and where a refused caller
    /// is told to go. Consulted by the auth middleware on every request, which is why it is a
    /// prebuilt table rather than a per-request derivation.
    pub planes: Arc<crate::plane::PlaneDispatch>,
    /// THE TYPE-ERASED PLANE SLOT MAP, keyed by plane key (`"mcp"`, `"a2a"`, …) — the app-state seam
    /// an extracted plane crate contributes its runtime object through, without core naming that
    /// object's type. `PlaneDecl::claims`/`admission` already read a plane's object through exactly
    /// this kind of erasure (`&dyn Any`), and this map generalises it to an owned, `App`-carried slot.
    ///
    /// The MCP plane reads its runtime object ONLY through this map: `App::mcp` was deleted and
    /// `crate::mcp::resource(app)` downcasts this slot inside the plane, so nothing OUTSIDE the mcp
    /// module names `McpResource`. The A2A plane reads its own object the SAME way — `App::a2a` was
    /// deleted too, and `crate::a2a::runtime(app)` downcasts this map's `"a2a"` slot inside the a2a
    /// module (the D4 step, now complete, mirrored the MCP one).
    ///
    /// Absent from this map is the same fact as an unconfigured plane: a plane the operator did not
    /// configure contributes no slot (see [`crate::plane::registry::PlaneDecl::build`]).
    pub(crate) plane_slots:
        std::collections::BTreeMap<&'static str, Arc<dyn std::any::Any + Send + Sync>>,
    /// The credential cache — Arc-shared ACROSS config swaps (like the
    /// mutation limiter): an apply/reload must not silently re-open every cached-allow window.
    pub(crate) credential_cache: Arc<crate::auth_cache::CredentialCache>,
    /// Per-module `max_admin_scope:` ceilings (from the auth chain entries) - consulted at admin
    /// scope resolution.
    pub(crate) auth_scope_caps: std::collections::HashMap<String, String>,
    /// `auth.role_bindings:` - module -> role -> operator policy (nested by module). Read by
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
    pub config_version: u64,
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
    /// governance runtime (virtual keys + budgets/limits store). `None` = disabled.
    pub governance: Option<std::sync::Arc<crate::governance::GovState>>,
    /// The SECRET RESOLVER seam: resolves a config [`crate::config::SecretRef`] to bytes via
    /// the built-in `env`/`file` modules or a loaded `kind: secret` plugin. Held so the TLS listener
    /// (built after `build_app` returns) resolves cert/key/CA references through the same seam that
    /// resolved provider keys and the admin token at build time.
    pub secret_resolver: std::sync::Arc<crate::config::secret::SecretResolver>,
    /// The resolved COST MODEL (rate card + budget groups + flat fee), rebuilt with the config on
    /// every apply/reload while `governance` (the token ledger) survives the swap - which is what
    /// makes a rate-card correction reprice every past and future derived figure on the next read.
    pub cost: std::sync::Arc<crate::cost::CostModel>,
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
    pub default_max_tokens: u32,
    /// Resolved effort-word → thinking-budget table for the cross-protocol reasoning carry
    /// (`limits.reasoning_effort_budgets`, defaults 1024/4096/8192/16384), ordered
    /// [minimal, low, medium, high]. Stamped onto the IR at the egress seam so writers project
    /// effort words and numeric budgets with the operator's numbers.
    pub reasoning_effort_budgets: [u32; 4],
    /// The self-serve (token-exchange) key lifetime in seconds, resolved from `auth.key_ttl`
    /// (`parse_duration_secs`, default [`crate::admin::DEFAULT_KEY_TTL_SECS`] = 90d). This is where
    /// the Step-1 `auth.key_ttl` field is finally READ: `POST /auth/token` mints every self key with
    /// `exp = now + self_key_ttl_secs`. Rebuilt on every apply/reload with the rest of the snapshot.
    pub(crate) self_key_ttl_secs: u64,
    /// The RESOLVED mint policy (`auth.policy:`, 1.6.0), built once at boot from the config and read
    /// on every mint: the deployment-wide TTL ceiling (`max_ttl`) + allowed binding modes + the
    /// per-role `mint_ceilings` (the delegated-app-admin caps, review H2/H3). `Default` (empty) = no
    /// policy ⇒ byte-identical pre-1.6.0 behavior. See [`crate::admin::MintPolicy`].
    pub(crate) mint_policy: std::sync::Arc<crate::admin::MintPolicy>,
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
    /// Borrow this snapshot's data-plane routing tables through the NEUTRAL [`EngineTablesView`]
    /// (`busbar_substrate::plane_host`) read seam — the projection the core-resident scrape/discovery
    /// readers (`/metrics`, `/v1/models`, telemetry label bank) name so they need not relocate when the
    /// tables move into `busbar-llm` (1.6.0 money-path Phase 3-4 B). This commit still SOURCES the view
    /// by downcasting the in-core `NativeRuntime` slot (the pivot swaps this for the plane's viewer
    /// fn-pointer); an ABSENT slot — the featureless zero-plane boot — yields the substrate-resident
    /// [`EMPTY_VIEW`](busbar_substrate::plane_host::EMPTY_VIEW) (zero pools/models), so a scrape or
    /// discovery probe on a plane-less binary reads empty tables rather than panicking. Cold path: one
    /// `plane_slots` lookup + one downcast, then the neutral (allocating) projections.
    pub(crate) fn engine_tables_view(&self) -> &dyn busbar_substrate::plane_host::EngineTablesView {
        // THE PIVOT (1.6.0 money-path Phase 3-4 C): the runtime type now lives in `busbar-llm`, so core
        // no longer names it. Project the plane's opaque runtime slot into the neutral view through the
        // fallback plane decl's `viewer` fn-pointer (the plane downcasts its OWN runtime inside). An
        // absent slot — the featureless zero-plane boot, or a decl with no viewer — yields the
        // substrate-resident EMPTY_VIEW (zero pools/models).
        let key = self.llm_runtime_key;
        match (
            crate::plane::registry::plane_decl_for(crate::plane::fallback_key())
                .and_then(|d| d.viewer),
            self.plane_slot(key),
        ) {
            (Some(viewer), Some(slot)) => viewer(slot.as_ref()),
            _ => &busbar_substrate::plane_host::EMPTY_VIEW,
        }
    }
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
    pub fn upstream_creds(&self) -> crate::auth::UpstreamCreds {
        // The plane runtime relocated out of core (money-path Phase 3-4 C), so this pool-less default
        // is read through the NEUTRAL view seam rather than by downcasting the plane's `NativeRuntime`.
        // Byte-identical: the view projects the same `upstream_credentials` field, and the zero-plane
        // EMPTY_VIEW returns the type default the always-present-but-empty runtime carried.
        self.engine_tables_view().upstream_creds()
    }

    /// Stamp the NEXT per-request correlation id: one relaxed `fetch_add`, no allocation, no
    /// syscall. Called ONCE per inbound request, at the earliest point `RequestCtx` is built
    /// (`forward_with_pool_parsed`) — every failover hop of that request reuses the SAME id (it
    /// rides `RequestCtx::request_id`, not re-derived here per hop).
    pub fn next_request_id(&self) -> u64 {
        self.request_id_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Look up a plane's type-erased runtime object by plane key. `None` when the plane is not
    /// registered for this key, OR the plane is registered but this config generation did not
    /// configure it (see `App::plane_slots`) — the same absence a typed field's `None`/no-entry
    /// already means, reached through the key instead of the field name.
    ///
    /// THE SEAM BOTH PLANES READ THROUGH: the MCP plane reads its runtime object through this accessor
    /// (`crate::mcp::resource`) and the A2A plane through it too (`crate::a2a::runtime`), each having
    /// deleted its typed `App::mcp` / `App::a2a` field in the D4 step.
    // Reached unconditionally through the `PlaneSlots` trait impl below (`App::plane_slot`), so the
    // inherent fn is never truly dead; the `allow(dead_code)` gate is legacy from when MCP was its
    // only direct reader.
    #[allow(dead_code)]
    pub fn plane_slot(&self, key: &str) -> Option<&Arc<dyn std::any::Any + Send + Sync>> {
        self.plane_slots.get(key)
    }

    /// The per-container submission-gate map for the plane identified by the opaque registry
    /// `plane_key`, or `None` when the plane attached no gates this generation — a pure
    /// [`App::plane_gates`](Self::plane_gates) map read, reached through the key instead of a
    /// plane-named field. The dispatch/admission gate paths read it; `None` and an empty inner map are
    /// both "no gate attached" (the zero-cost `Proceed` early-out).
    #[allow(dead_code)]
    pub(crate) fn plane_gates(&self, plane_key: &str) -> Option<&ContainerGateMap> {
        self.plane_gates.get(plane_key)
    }

    // THE POOL-HOOK DOWN-FACADES (money-path Phase 3-4 C). The relocated LLM engine reads each pool's
    // resolved routing policy / decision gates / rewrite chain through these instead of off the plane's
    // `PoolRuntime` (which no longer stores them — the resolved `ResolvedPolicy`/`Arc<dyn RoutingPolicy>`
    // cannot cross the `build_runtime` downcast). Byte-identical: the SAME objects `appbuild` resolved
    // via `hooks::resolve_pool_*`, read by pool name. `pub` — the plane names them; the allowed
    // plane→core edge (no core type crosses a downcast, the plane just calls these directly).

    /// This pool's resolved routing policy, or `None` for the zero-cost SWRR default (no `route:`/hook).
    pub fn pool_policy(&self, pool: &str) -> Option<&crate::hooks::ResolvedPolicy> {
        self.pool_orderings.get(pool)
    }

    /// This pool's resolved DECISION GATES `(priority, policy)` in config order (empty ⇒ no pool gates).
    pub fn pool_gates(&self, pool: &str) -> &[(u16, crate::hooks::ResolvedPolicy)] {
        self.pool_decision_gates
            .get(pool)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// This pool's resolved REWRITE chain `(timeout, policy)` (empty ⇒ no pool rewrites, zero cost).
    #[allow(clippy::type_complexity)]
    pub fn pool_rewrites(
        &self,
        pool: &str,
    ) -> &[(std::time::Duration, std::sync::Arc<dyn crate::hooks::RoutingPolicy>)] {
        self.pool_rewrite_chains
            .get(pool)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// The failover pool map for the plane identified by the opaque registry `plane_key`, or `None`
    /// when the plane declared no pools this generation — a pure [`App::plane_pools`](Self::plane_pools)
    /// map read, reached through the key instead of a plane-named field.
    #[allow(dead_code)]
    pub(crate) fn plane_pools(
        &self,
        plane_key: &str,
    ) -> Option<&std::collections::BTreeMap<String, crate::failover::CandidatePoolCfg>> {
        self.plane_pools.get(plane_key)
    }

    /// Resolve a container plane's per-registration hook gates against THIS snapshot's hook registry,
    /// env and config version — the core-side of a container plane's config-swap gate rebuild. An
    /// extracted plane hands its neutral `(container, own-hooks)` inputs + the reserved section attach
    /// list across, and gets back the keyed gate map to store in its own gate field, so the plane
    /// names no `crate::hooks::resolve_container_gates`. Same resolution as `appbuild`'s build-time
    /// pass and the in-core A2A twin.
    // Called only from a container plane's gate rebuild (MCP/A2A); with BOTH planes compiled out it
    // has no caller, exactly like the `crate::hooks::resolve_container_gates` it wraps.
    #[allow(dead_code)]
    pub fn resolve_container_gates<'a>(
        &self,
        containers: impl Iterator<Item = (&'a str, &'a [String])>,
        section_hooks: &[String],
    ) -> HashMap<String, Vec<(u16, crate::hooks::ResolvedPolicy)>> {
        crate::hooks::resolve_container_gates(
            containers,
            section_hooks,
            &self.hook_registry,
            &self.hook_env,
            self.config_version,
        )
    }

    /// Resolve a POOL's base ordering against THIS snapshot's hook registry, env and config version —
    /// the core-side of the LLM plane's per-pool base-ordering resolution. The MONEY-PATH twin of
    /// [`App::resolve_container_gates`]: the extracted LLM plane hands the neutral `(&PoolCfg,
    /// default_hook)` inputs across and gets back the resolved policy to store in busbar-llm's
    /// `PoolRuntime`, so the plane names no `crate::hooks::resolve_pool_ordering` and never constructs
    /// a `HookEnv`. Byte-identical to `appbuild`'s build-time `hooks::resolve_pool_ordering` pass
    /// (`self.hook_registry` == the built `cfg.hooks`, `self.hook_env` == the built env,
    /// `self.config_version` == the build's `app_config_version`).
    // Called only from the extracted LLM plane's pool lowering (Commit C); with the plane compiled out
    // it has no caller, exactly like the `crate::hooks::resolve_pool_ordering` it wraps.
    #[allow(dead_code)]
    pub fn resolve_pool_ordering(
        &self,
        cfg: &crate::config::PoolCfg,
        default_hook: Option<&str>,
    ) -> Option<crate::hooks::ResolvedPolicy> {
        crate::hooks::resolve_pool_ordering(
            cfg,
            &self.hook_registry,
            &self.hook_env,
            default_hook,
            self.config_version,
        )
    }

    /// Resolve a POOL's decision GATES against THIS snapshot — the money-path twin of
    /// [`App::resolve_container_gates`] for the priority-carrying phase-2 gate chain. Byte-identical to
    /// `appbuild`'s `hooks::resolve_pool_gates` pass; the plane stores the returned rank in busbar-llm's
    /// `PoolRuntime` without naming `crate::hooks::resolve_pool_gates` or building a `HookEnv`.
    #[allow(dead_code)]
    pub fn resolve_pool_gates(
        &self,
        cfg: &crate::config::PoolCfg,
    ) -> Vec<(u16, crate::hooks::ResolvedPolicy)> {
        crate::hooks::resolve_pool_gates(
            cfg,
            &self.hook_registry,
            &self.hook_env,
            self.config_version,
        )
    }

    /// Resolve a POOL's phase-1 REWRITE gates against THIS snapshot — the money-path twin of
    /// [`App::resolve_container_gates`] for the pool rewrite chain. Byte-identical to `appbuild`'s
    /// `hooks::resolve_pool_rewrites` pass; the plane stores the returned chain in busbar-llm's
    /// `PoolRuntime` without naming `crate::hooks::resolve_pool_rewrites` or building a `HookEnv`.
    #[allow(dead_code)]
    pub fn resolve_pool_rewrites(
        &self,
        cfg: &crate::config::PoolCfg,
    ) -> Vec<(std::time::Duration, Arc<dyn crate::hooks::RoutingPolicy>)> {
        crate::hooks::resolve_pool_rewrites(
            cfg,
            &self.hook_registry,
            &self.hook_env,
            self.config_version,
        )
    }
}

/// THE NEUTRAL SLOT-READ SEAM the plane `PlaneDecl` callbacks name instead of `&App`. A thin delegate
/// to the inherent [`App::plane_slot`]; [`as_any`](busbar_substrate::plane_host::PlaneSlots::as_any)
/// hands the concrete snapshot back to the in-core A2A twin for the field (`agent_defs`) that is not
/// a `plane_slots` entry.
impl busbar_substrate::plane_host::PlaneSlots for App {
    fn plane_slot(&self, key: &str) -> Option<&Arc<dyn std::any::Any + Send + Sync>> {
        App::plane_slot(self, key)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// THE NEUTRAL `&mut` GATE-REBUILD SINK the plane `PlaneDecl::reresolve_gates` callback names instead
/// of `&mut App`. Resolves the plane's per-container gates host-side (through the inherent
/// [`App::resolve_container_gates`]) and stores them in the generic [`App::plane_gates`] map under the
/// opaque registry `plane_key` — byte-identical to the old inline
/// `next.plane_gates.insert(plane_key, next.resolve_container_gates(...))`.
impl busbar_substrate::plane_host::ContainerGateSink for App {
    fn reresolve_container_gates(
        &mut self,
        plane_key: &str,
        containers: &[(&str, &[String])],
        section_hooks: &[String],
    ) {
        let gates = self.resolve_container_gates(containers.iter().copied(), section_hooks);
        // The map key is the plane's stable decl key. `reresolve` is only ever called for an installed
        // plane, whose key is `&'static`; recover that static key from the registry so the map's
        // `&'static str` key type is satisfied without leaking (the `plane_key` argument is a borrow).
        if let Some(static_key) = crate::plane::registry::plane_decl_for(plane_key).map(|d| d.key) {
            self.plane_gates.insert(static_key, gates);
        }
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
/// (an `ArcSwap` read — no lock, and on the `snapshot()` path no refcount write either).
/// Behaviorally identical to a fixed `Arc<App>` until something calls `swap()`.
pub struct AppHandle {
    current: arc_swap::ArcSwap<App>,
    /// Debug-only overlap detector for [`swap`](Self::swap) — see the convention note there.
    #[cfg(debug_assertions)]
    swapping: std::sync::atomic::AtomicBool,
}

impl AppHandle {
    pub fn new(app: Arc<App>) -> Self {
        Self {
            current: arc_swap::ArcSwap::new(app),
            #[cfg(debug_assertions)]
            swapping: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// The current `App` snapshot as an OWNED `Arc` (one refcount bump). For a caller that only
    /// READS within a scope, prefer [`snapshot`] — it takes no refcount write at all, which
    /// matters on the request path where a shared refcount cache line ping-pongs across every
    /// worker.
    pub fn load(&self) -> Arc<App> {
        self.current.load_full()
    }

    /// The current `App` snapshot as a BORROW guard: lock-free and refcount-free on the fast path
    /// (arc-swap's debt slots). The guard pins the snapshot for its scope; derefs to `App`.
    pub fn snapshot(&self) -> arc_swap::Guard<Arc<App>> {
        self.current.load()
    }

    /// Atomically replace the current snapshot (the admin config-mutation seam: reload, apply, and every
    /// hook/auth mutation). Re-spawns the health probers against `next`: probers hold a `Weak<App>` and
    /// exit once the App they were spawned against drops, so EVERY swap must re-attach them —
    /// otherwise the first admin mutation replaces the boot App, the boot App drops as in-flight requests
    /// drain, its probers exit, and active/dead health probing silently STOPS even though lanes/health are
    /// unchanged (before 1.4.0 only reload/apply re-spawned; the six hook/auth-mutation swaps did not).
    /// Doing it in `swap` itself makes it impossible for a future swap site to forget.
    /// Also lets each PLANE carry its engine-owned live state across the apply, through the plane's
    /// own [`PlaneDecl::on_swap`](crate::plane::registry::PlaneDecl::on_swap) hook. Today the MCP
    /// plane is the only one with such state: it RETIRES every stdio MCP child whose registration is
    /// gone from `next`. Same reasoning as the probers, one plane over: an MCP connection pool
    /// deliberately outlives an apply, so deleting a `tools:` entry would otherwise leave its child
    /// process running forever — unreferenced, unreachable, and with nothing on any surface an
    /// operator reads to say so. Doing it here, once, over the registered decls rather than by naming
    /// each plane's concrete types makes it impossible for a future swap site to forget AND keeps this
    /// method free of any one plane's types — the reconciliation lives beside the plane it belongs to.
    pub fn swap(&self, next: Arc<App>) {
        // WRITER SERIALIZATION IS A CONVENTION, NOT A TYPE GUARANTEE (audit F9): `ArcSwap` made
        // reads lock-free, but unlike the old `RwLock` write lock, nothing here mutually excludes
        // two concurrent swaps — the load-prior → on_swap-diff → store sequence below is only
        // correct because every mutation site funnels through the admin plane's single
        // apply/persist path (persist-then-swap under its own serialization). A future swap
        // caller OUTSIDE that path could interleave two diffs and lose one plane reconciliation.
        // This debug counter makes that regression loud in tests: overlapping swaps panic in
        // debug builds instead of silently racing in release.
        #[cfg(debug_assertions)]
        let _swap_guard =
            {
                struct Guard<'a>(&'a std::sync::atomic::AtomicBool);
                impl Drop for Guard<'_> {
                    fn drop(&mut self) {
                        self.0.store(false, std::sync::atomic::Ordering::Release);
                    }
                }
                assert!(
                !self.swapping.swap(true, std::sync::atomic::Ordering::AcqRel),
                "AppHandle::swap ran concurrently with another swap on the same handle — every \
                 mutation must funnel through the serialized persist-then-swap path"
            );
                Guard(&self.swapping)
            };
        // The snapshot being replaced, so a plane that must DIFF the two generations can; the MCP
        // hook reconciles only `next` (its pool is Arc-carried onto `next` already).
        let prior = self.load();
        for decl in crate::plane::registry::plane_decls() {
            if let Some(on_swap) = decl.on_swap {
                on_swap(
                    &*prior as &dyn busbar_substrate::plane_host::PlaneSlots,
                    &*next as &dyn busbar_substrate::plane_host::PlaneSlots,
                );
            }
        }
        self.current.store(next.clone());
        // The active-probe prober spawn RELOCATED into the LLM plane with `health.rs` (1.6.0 money-path
        // Phase 3-4 C): the probers read the plane's own `Lane`/`NativeRuntime` tables, so the plane
        // spawns them off its freshly-stored runtime through the `PlaneDecl::on_swap` seam fired in the
        // loop above — core no longer names `crate::health::spawn_probers`.
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
pub struct CurrentApp(pub(crate) Arc<App>);

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

#[cfg(test)]
#[path = "tests/worker_shard_tests.rs"]
mod worker_shard_tests;

// ── DETACHED-WORK DRAIN — RELOCATED to `busbar-substrate::detached` so the plane crates (which
// deliberately never link busbar-core) reach the same seam. Re-exported here for core callers
// and the composition root.
pub use busbar_substrate::detached::{
    set_worker_detached, set_worker_shutdown, spawn_detached, DetachedTasks, DETACHED_DRAIN_GRACE,
};
