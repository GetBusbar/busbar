// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL READ-SIDE PROJECTION of a data-plane's routing tables — the seam the core-resident
//! scrape/discovery readers name instead of the plane's concrete `Lane`/`WeightedLane`/`PoolRuntime`
//! types (1.6.0 money-path Phase 3-4 B, read-side decoupling).
//!
//! ## Why this lives in the substrate
//!
//! The LLM money path (its `NativeRuntime` bundle + the `Lane`/`WeightedLane` routing tables) is being
//! relocated into `busbar-llm`. A handful of core readers that STAY — the `/metrics` lane-state scrape,
//! the `/v1/models` discovery listing, and the boot-time telemetry label bank — read those tables only
//! for NEUTRAL facts: pool label spaces, per-pool member lane indices, the direct-model index, one
//! lane's wire identity ([`LaneView`]), and a pool's live queue-park depth. Expressed through this
//! trait, those readers name no plane type, so they need not move when the tables do.
//!
//! It lives in `busbar-substrate` (not `busbar-llm`) so a zero-plane binary — one that `git-rm`'d
//! `busbar-llm` (the `plane-delete-test --all` posture) — still boots: core reaches an
//! [`EMPTY_VIEW`] (zero pools, zero models) when no plane contributed a runtime slot, and never names a
//! `busbar-llm` type to do it.
//!
//! ## What this is NOT
//!
//! This is the COLD/scrape read seam, reached at most once per scrape or discovery call and free to
//! allocate its neutral projections. It is not the hot engine path: the engine downcasts its own
//! concrete runtime once and reads plain fields. The table-object-coupled readers (health probing over
//! `client()`/`probe_schedule()`, admin `pool_detail` over `&[WeightedLane]`) are deliberately NOT
//! expressed here — they move into the plane with the tables.

/// A neutral, read-only projection of ONE lane's wire identity, borrowed from the plane's lane table
/// for the duration of a scrape/discovery read. Carries only protocol-neutral scalars (no plane
/// routing type), so a core reader can label a metric or render a `/stats`-adjacent fact without
/// naming the plane's `Lane`.
///
/// Today's core readers consume only [`LaneView::model`] (the metric `lane` label / the discovery
/// name); `provider` and `base_url` round out the neutral identity for the readers that relocate with
/// the tables in the pivot, so the projection shape is settled before the move.
pub struct LaneView<'a> {
    /// The lane's configured model name — the value the `/metrics` `lane` label and the counter sites
    /// carry, so a gauge and its counters PromQL-join.
    pub model: &'a str,
    /// The lane's provider name.
    pub provider: &'a str,
    /// The lane's upstream base URL.
    pub base_url: &'a str,
}

/// THE NEUTRAL READ SEAM over a data-plane's routing tables. Implemented by the plane's concrete
/// runtime (today the still-in-core `NativeRuntime`; after the pivot, `busbar-llm`'s own runtime,
/// reached via a viewer fn-pointer). Every accessor returns a NEUTRAL projection — never the plane's
/// `Lane`/`WeightedLane` — so the staying `/metrics`, `/v1/models`, and telemetry readers name no
/// plane type. Cold/scrape paths only; the projections allocate.
pub trait EngineTablesView {
    /// The pool label space paired with each pool's member lane indices — one entry per configured
    /// pool. Drives the `/metrics` per-pool lane-state loop, the `/v1/models` visible-pool filter, and
    /// the telemetry engine-label bank.
    fn pools(&self) -> Vec<(&str, Vec<usize>)>;

    /// The direct-model index: every `(model name, lane index)` reachable without a pool.
    fn model_indices(&self) -> Vec<(&str, usize)>;

    /// The lane index a direct model routes to, if the model is configured.
    fn model_index(&self, model: &str) -> Option<usize>;

    /// A neutral view of the lane at `idx`, or `None` when the index is out of range.
    fn lane_view(&self, idx: usize) -> Option<LaneView<'_>>;

    /// The total number of configured lanes — the upper bound the staying `/stats` and telemetry
    /// readers iterate `0..lane_count()` over (each index then read through [`Self::lane_view`] /
    /// the neutral store cell). Zero for the empty view.
    fn lane_count(&self) -> usize;

    /// The `(lane index, member weight)` pairs of `pool`'s members, in config order — the NEUTRAL
    /// projection the core-resident admin pool listing (`GET /admin/pools[/{name}][?detail]`) renders
    /// each member's weight and (via [`Self::lane_view`]) model from, so it names no plane
    /// `WeightedLane`. Empty for an unknown pool. Cold admin path; allocates.
    fn pool_members(&self, pool: &str) -> Vec<(usize, u32)>;

    /// The live `on_exhausted: queue` park depth for `pool` (0 when the pool never queues).
    fn queued_depth(&self, pool: &str) -> u64;

    /// The FALLBACK-POOL target `pool` fails over to on exhaustion, if its `on_exhausted:` policy is
    /// `fallback_pool:<name>` — else `None` (every other policy, `503`/`least_bad`/`queue`, stays
    /// within the pool and introduces no new pool name; an unconfigured pool defaults to `503`). A
    /// NEUTRAL projection of the plane's `on_exhausted` config (the config enum is a plane type this
    /// seam must not name), used by the staying ingress ACL walk (`fallback_pools_authorized`) to
    /// re-enforce a key's `allowed_pools` against every reachable fallback pool.
    fn on_exhausted_fallback(&self, pool: &str) -> Option<String>;

    /// The ALL-POOLS upstream-credential DEFAULT (`Own` vs `Passthrough`) — a NEUTRAL scalar the
    /// staying pool-less core readers (`auth::open_door` keys-in-chain guard, the admin
    /// upstream-credentials render) consult after the plane's runtime relocated out of core. A pure
    /// projection of the plane runtime's `upstream_credentials` field; the empty view returns the
    /// type's default, byte-identical to the always-present-but-empty zero-plane runtime.
    fn upstream_creds(&self) -> busbar_api::UpstreamCreds;
}

/// THE ZERO-PLANE EMPTY VIEW: a core/substrate-resident [`EngineTablesView`] with zero pools and zero
/// models, reached when no plane contributed a runtime slot (the featureless binary). Substrate-owned
/// so core boots — and its scrape/discovery readers see empty tables rather than panicking — even with
/// every plane crate compiled out (the `plane-delete-test --all` posture). Byte-identical in output to
/// the always-present-but-empty runtime the zero-plane build used to carry.
pub struct EmptyEngineTablesView;

/// The process-lifetime [`EmptyEngineTablesView`] singleton the core read seam falls back to on an
/// absent plane runtime slot.
pub static EMPTY_VIEW: EmptyEngineTablesView = EmptyEngineTablesView;

impl EngineTablesView for EmptyEngineTablesView {
    fn pools(&self) -> Vec<(&str, Vec<usize>)> {
        Vec::new()
    }
    fn model_indices(&self) -> Vec<(&str, usize)> {
        Vec::new()
    }
    fn model_index(&self, _model: &str) -> Option<usize> {
        None
    }
    fn lane_view(&self, _idx: usize) -> Option<LaneView<'_>> {
        None
    }
    fn lane_count(&self) -> usize {
        0
    }
    fn pool_members(&self, _pool: &str) -> Vec<(usize, u32)> {
        Vec::new()
    }
    fn queued_depth(&self, _pool: &str) -> u64 {
        0
    }
    fn on_exhausted_fallback(&self, _pool: &str) -> Option<String> {
        None
    }
    fn upstream_creds(&self) -> busbar_api::UpstreamCreds {
        busbar_api::UpstreamCreds::default()
    }
}
