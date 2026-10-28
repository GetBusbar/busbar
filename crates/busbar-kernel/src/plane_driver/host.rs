// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GENERATION'S ENGINE HOST, as the plane driver's units read it: the [`EngineHost`] seam over
//! one config generation's live [`App`], and the constructors the composition root and the routers
//! mint it with.
//!
//! A door plane's unit binds its hooks through this host ([`super::HostHooks`],
//! [`super::HostGatedHooks`]): the generation's resolved rewrite chains, decision gates, taps,
//! policies and requested signals, its one request-id counter, the group walk a tap's `groups:`
//! scope reads, and the caller's rate headroom and budget chain through the generation's meter pin.
//! Every read is kind-neutral — the host names no plane and no plane type (BUSBAR-1.6.0.md Part 1
//! Law 1; Part 3 §0, core names ZERO plane types). It moved here from the kernel's retired plane
//! hosting (`plane_host`, status row 82): the door path is the only reader left.

use crate::state::App;
use std::sync::Arc;

/// The kernel's implementation of the [`EngineHost`] seam over one live [`App`] generation.
///
/// Owns an `Arc<App>` (the config generation the reads run against) so the handle is
/// `Send + Sync + 'static` and safe to carry across `.await`: each method reads the bound snapshot
/// for the duration of the call and returns a borrow of it or an owned value.
#[derive(Clone)]
pub struct EngineHostImpl {
    /// The BOUND engine snapshot the host reads run against — loaded once at mint.
    app: Arc<App>,
}

impl EngineHostImpl {
    /// Build the host implementation over the live `app`.
    #[must_use]
    pub fn new(app: Arc<App>) -> Self {
        EngineHostImpl { app }
    }

    /// Build the host over a live [`AppHandle`](crate::state::AppHandle): the bound snapshot is the
    /// handle's CURRENT load, byte-identical to `new(handle.load())`.
    #[must_use]
    pub fn from_handle(handle: Arc<crate::state::AppHandle>) -> Self {
        EngineHostImpl { app: handle.load() }
    }
}

/// THE ENGINE HOST: the generation's hook configuration, its request-id counter, the caller's
/// budget reads through the generation's meter pin, and the mount reads a body-model arrival shapes
/// its answer with. `Send + Sync` because a unit carries the handle across `.await`.
pub trait EngineHost: Send + Sync {
    /// Whether `caller_group` sits within (any ancestor of) one of `hook_groups` — the group-membership
    /// walk a hook's `groups:` filter consults, resolved against this deployment's group registry.
    /// Identical to `busbar_kernel::config::caller_in_hook_groups(caller_group, hook_groups, &App::groups_registry)`.
    fn caller_in_hook_groups(&self, caller_group: Option<&str>, hook_groups: &[String]) -> bool;

    /// This pool's resolved REWRITE chain `(timeout, policy)`; empty ⇒ no pool rewrites. The borrow
    /// of `App::pool_rewrites(pool)`.
    fn pool_rewrites(
        &self,
        pool: &str,
    ) -> &[(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )];

    /// The GLOBAL (all-pools) rewrite chain `(timeout, policy)` fired BEFORE any pool rewrites — the
    /// borrow of `App::rewrite_hooks`. Empty ⇒ no globals.
    fn rewrite_hooks(
        &self,
    ) -> &[(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )];

    /// A hook was handed a unit's content (and the caller's identity, when `identity`): leave the
    /// one access amendment the kernel's own gate and rewrite seams leave, on the node journal.
    /// `principal` is whose content it was; `op` the ingress label — data, never branched on.
    fn hook_read(&self, name: &str, principal: Option<&str>, op: &str, identity: bool) {
        crate::audit::amend::hook_read(name, principal, op, identity);
    }

    /// The DECISION GATES the plane `plane_key` attached to its entry `container` this generation
    /// (the plane's per-entry `hooks:`), as resolved; empty = none. A gate-first plane's units are
    /// screened by them (`abi::plane::TAIL_HOOKS_GATED`).
    fn plane_gates_of(
        &self,
        plane_key: &str,
        container: &str,
    ) -> Vec<(u16, crate::hooks::ResolvedPolicy)>;

    /// The REWRITE chain the plane `plane_key` attached to its entry `container` this generation;
    /// empty = none.
    fn plane_rewrites_of(
        &self,
        plane_key: &str,
        container: &str,
    ) -> Vec<(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )>;

    /// Whether the deployment attached any hook to the plane `plane_key`'s section or entries this
    /// generation: its units bind the hooks of the entry the kernel recorded for them
    /// ([`super::HookBinder::entry_scoped`]).
    fn plane_attaches(&self, plane_key: &str) -> bool;

    /// The gate's INCREMENTAL-SCAN substrate under the operator's opt-in: the node's session store
    /// and the hook-config generation a clearance is bound to; `None` = every request is screened
    /// whole.
    fn gate_scan(&self) -> Option<(Arc<crate::session::SessionStore>, u64)>;

    /// The GLOBAL request-stage `kind: tap` observers — the borrow of `App::tap_hooks`.
    fn tap_hooks(&self) -> &[crate::hooks::TapEntry];

    /// The RESPONSE-stage tap observers — the borrow of `App::tap_hooks_response`.
    fn tap_hooks_response(&self) -> &[crate::hooks::TapEntry];

    /// The ROUTING-stage tap observers — the borrow of `App::tap_hooks_routing`.
    fn tap_hooks_routing(&self) -> &[crate::hooks::TapEntry];

    /// The CANDIDATE-stage tap observers — the borrow of `App::tap_hooks_candidate`.
    fn tap_hooks_candidate(&self) -> &[crate::hooks::TapEntry];

    /// This pool's resolved DECISION GATES `(priority, policy)` in config order — the borrow of
    /// `App::pool_gates(pool)`. Empty ⇒ no pool gates.
    fn pool_gates(&self, pool: &str) -> &[(u16, crate::hooks::ResolvedPolicy)];

    /// The GLOBAL decision gates `(priority, policy)` — the borrow of `App::global_gates`.
    fn global_gates(&self) -> &[(u16, crate::hooks::ResolvedPolicy)];

    /// This pool's resolved routing POLICY, or `None` for the weighted default — the borrow of
    /// `App::pool_policy(pool)`.
    fn pool_policy(&self, pool: &str) -> Option<&crate::hooks::ResolvedPolicy>;

    /// The config generation's declared-signal bitmask — the borrow of `App::requested_signals`.
    fn requested_signals(&self) -> &crate::hooks::RequestedSignals;

    /// Stamp the NEXT per-request correlation id — one relaxed `fetch_add` on the host-owned counter.
    /// Identical to `busbar_kernel::state::App::next_request_id`.
    fn next_request_id(&self) -> u64;

    /// Mint the OPAQUE [`GovHandle`] for this deployment's governance state — `Some` iff governance is
    /// configured. One `Arc` bump. Byte-identical to cloning `App::governance`.
    fn governance(&self) -> Option<GovHandle>;

    /// PIN this request's metering context — `Some` iff governance is configured: the generation's
    /// governance state and the card in force, which [`rate_headroom`](Self::rate_headroom) and
    /// [`budget_state`](Self::budget_state) read.
    fn meter_pin(&self) -> Option<MeterPin>;

    /// The per-caller RATE HEADROOM (min fraction of remaining request/token budget across the key's
    /// chain, `None` when unconstrained) over the governance state and card `pin` carries — the pure
    /// observation `gov.rate_headroom(&cost, key, pool, now)`.
    fn rate_headroom(
        &self,
        pin: &MeterPin,
        key: &busbar_contract::records::VirtualKey,
        pool: Option<&str>,
        now: u64,
    ) -> Option<f64>;

    /// The hook-seam budget projection for `key` over the governance state and card `pin` carries —
    /// `gov.budget_state(&cost, key, now)`; empty when the key has no chain.
    fn budget_state(
        &self,
        pin: &MeterPin,
        key: &busbar_contract::records::VirtualKey,
        now: u64,
    ) -> Vec<busbar_contract::hooks::BudgetBucketState>;

    /// The mount-aware dialect an answer to `path` is SHAPED in —
    /// `busbar_kernel::ingress::native::envelope_dialect(App::planes.ingress_of(path))`. A body-model
    /// arrival's read.
    fn arrival_envelope_dialect(&self, path: &str) -> &'static str;

    /// The fallback error SHAPE by `path` — `busbar_kernel::fallback_error_response(&App::planes, path,
    /// status, kind, message)`, the unmatched-path envelope in the dialect the deployment mounted
    /// `path` under. A body-model arrival's read.
    fn arrival_fallback_error(
        &self,
        path: &str,
        status: axum::http::StatusCode,
        kind: &str,
        message: &str,
    ) -> axum::response::Response;

    /// NOT-CHARGED (pre-charge turn-away) finish: emit metrics + the request-log webhook with NO
    /// refund, for a request rejected BEFORE the admission charge ran. Identical to
    /// `busbar_kernel::ingress::finish_rejected` over the bound snapshot + `gov` scope.
    fn finish_rejected(
        &self,
        gov: &busbar_contract::records::PlaneRequestCtx,
        ingress_protocol: &str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
        resp: axum::response::Response,
    ) -> axum::response::Response;
}

impl EngineHost for EngineHostImpl {
    fn caller_in_hook_groups(&self, caller_group: Option<&str>, hook_groups: &[String]) -> bool {
        crate::config::caller_in_hook_groups(caller_group, hook_groups, &self.app.groups_registry)
    }

    fn pool_rewrites(
        &self,
        pool: &str,
    ) -> &[(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )] {
        self.app.pool_rewrites(pool)
    }

    fn rewrite_hooks(
        &self,
    ) -> &[(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )] {
        &self.app.rewrite_hooks
    }

    fn plane_gates_of(
        &self,
        plane_key: &str,
        container: &str,
    ) -> Vec<(u16, crate::hooks::ResolvedPolicy)> {
        // The set the previous release's gate seam fired, as resolved (`gate::decide_over` orders it).
        self.app
            .plane_gates(plane_key)
            .and_then(|m| m.get(container))
            .cloned()
            .unwrap_or_default()
    }

    fn plane_rewrites_of(
        &self,
        plane_key: &str,
        container: &str,
    ) -> Vec<(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )> {
        self.app
            .plane_rewrites(plane_key)
            .and_then(|m| m.get(container))
            .cloned()
            .unwrap_or_default()
    }

    fn plane_attaches(&self, plane_key: &str) -> bool {
        self.app
            .plane_gates(plane_key)
            .is_some_and(|m| !m.is_empty())
            || self
                .app
                .plane_rewrites(plane_key)
                .is_some_and(|m| !m.is_empty())
    }

    fn gate_scan(&self) -> Option<(Arc<crate::session::SessionStore>, u64)> {
        self.app
            .incremental_scan
            .then(|| (Arc::clone(&self.app.session_store), self.app.config_version))
    }

    fn tap_hooks(&self) -> &[crate::hooks::TapEntry] {
        &self.app.tap_hooks
    }

    fn tap_hooks_response(&self) -> &[crate::hooks::TapEntry] {
        &self.app.tap_hooks_response
    }

    fn tap_hooks_routing(&self) -> &[crate::hooks::TapEntry] {
        &self.app.tap_hooks_routing
    }

    fn tap_hooks_candidate(&self) -> &[crate::hooks::TapEntry] {
        &self.app.tap_hooks_candidate
    }

    fn pool_gates(&self, pool: &str) -> &[(u16, crate::hooks::ResolvedPolicy)] {
        self.app.pool_gates(pool)
    }

    fn global_gates(&self) -> &[(u16, crate::hooks::ResolvedPolicy)] {
        &self.app.global_gates
    }

    fn pool_policy(&self, pool: &str) -> Option<&crate::hooks::ResolvedPolicy> {
        self.app.pool_policy(pool)
    }

    fn requested_signals(&self) -> &crate::hooks::RequestedSignals {
        &self.app.requested_signals
    }

    fn next_request_id(&self) -> u64 {
        self.app.next_request_id()
    }

    fn governance(&self) -> Option<GovHandle> {
        // One Arc bump, erased to `dyn Any` — byte-identical to `app.governance.clone()`.
        self.app
            .governance
            .clone()
            .map(|g| GovHandle(g as Arc<dyn std::any::Any + Send + Sync>))
    }

    // The pin carries THIS snapshot's card (one Arc bump) — the card a request's money is settled
    // against for its whole life, whatever a reload does meanwhile. Only the kernel's host pins one.
    fn meter_pin(&self) -> Option<MeterPin> {
        let cost = CostHandle(self.app.cost.clone());
        self.governance().map(|gov| MeterPin { gov, cost })
    }

    fn rate_headroom(
        &self,
        pin: &MeterPin,
        key: &busbar_contract::records::VirtualKey,
        pool: Option<&str>,
        now: u64,
    ) -> Option<f64> {
        // Recover the concrete gov/cost the pin was minted over and drive the SAME pure observation
        // `gov.rate_headroom(&app.cost, …)` does. A downcast miss reads as no constraint.
        pin_models(pin).and_then(|(g, c)| g.rate_headroom(&c, key, pool, now))
    }

    fn budget_state(
        &self,
        pin: &MeterPin,
        key: &busbar_contract::records::VirtualKey,
        now: u64,
    ) -> Vec<busbar_contract::hooks::BudgetBucketState> {
        pin_models(pin).map_or_else(Vec::new, |(g, c)| g.budget_state(&c, key, now))
    }

    fn arrival_envelope_dialect(&self, path: &str) -> &'static str {
        crate::ingress::native::envelope_dialect(self.app.planes.ingress_of(path))
    }

    fn arrival_fallback_error(
        &self,
        path: &str,
        status: axum::http::StatusCode,
        kind: &str,
        message: &str,
    ) -> axum::response::Response {
        crate::fallback_error_response(&self.app.planes, path, status, kind, message)
    }

    fn finish_rejected(
        &self,
        gov: &busbar_contract::records::PlaneRequestCtx,
        ingress_protocol: &str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
        resp: axum::response::Response,
    ) -> axum::response::Response {
        crate::ingress::finish_rejected(
            &self.app,
            gov,
            ingress_protocol,
            pool,
            started,
            charged_at,
            resp,
        )
    }
}

/// An OPAQUE, cheaply-cloned (one `Arc` bump) handle to the deployment's governance state — minted
/// by [`EngineHost::governance`]. Its holder never names `busbar_kernel::governance::GovState`.
#[derive(Clone)]
pub struct GovHandle(pub Arc<dyn std::any::Any + Send + Sync>);

/// The cost-model twin of [`GovHandle`] — an opaque handle to a resolved `CostModel`. It rides
/// inside a [`MeterPin`] and no signature outside the kernel names it (#43).
#[derive(Clone)]
pub struct CostHandle(pub Arc<dyn std::any::Any + Send + Sync>);

/// THE METER PIN — the governance state AND the rate card that were in force when a request was
/// admitted. OPAQUE: the fields are private and only the kernel's host pins a card
/// ([`EngineHost::meter_pin`]); [`EngineHost::rate_headroom`] and [`EngineHost::budget_state`] read
/// it kernel-side, so its holder carries its request's pricing context without naming a cost or
/// price type (#43).
#[derive(Clone)]
pub struct MeterPin {
    gov: GovHandle,
    cost: CostHandle,
}

impl MeterPin {
    /// Pin `gov` and the card `cost` names. Kernel-side; a TEST that hand-builds a card pins it here.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(gov: GovHandle, cost: CostHandle) -> Self {
        MeterPin { gov, cost }
    }

    /// The governance handle the pin carries.
    pub fn gov(&self) -> &GovHandle {
        &self.gov
    }
}

/// Recover the concrete `CostModel` an opaque [`CostHandle`] was minted over; `None` on a handle the
/// kernel's host did not mint.
fn cost_model(cost: &CostHandle) -> Option<Arc<crate::cost::CostModel>> {
    cost.0.clone().downcast().ok()
}

/// The `(GovState, CostModel)` pair behind a [`MeterPin`]; `None` when either handle misses.
fn pin_models(
    pin: &MeterPin,
) -> Option<(
    Arc<crate::governance::GovState>,
    Arc<crate::cost::CostModel>,
)> {
    Some((pin.gov.0.clone().downcast().ok()?, cost_model(&pin.cost)?))
}

/// Mint an `Arc<dyn EngineHost>` over the live `app`. Cheap: one `Arc` clone.
#[must_use]
pub fn engine_host(app: &Arc<App>) -> Arc<dyn EngineHost> {
    Arc::new(EngineHostImpl::new(Arc::clone(app)))
}

/// An owned [`EngineHost`] value the caller keeps on its STACK and coerces to `&dyn EngineHost`, so
/// it reaches the host WITHOUT the `Arc::new` heap allocation [`engine_host`] pays: one `Arc::clone`
/// of the snapshot. Returned opaque (`impl EngineHost`).
#[must_use]
pub fn engine_host_value(app: &Arc<App>) -> impl EngineHost + 'static {
    EngineHostImpl::new(Arc::clone(app))
}

/// Mint an `Arc<dyn EngineHost>` over the CURRENT snapshot of a live
/// [`AppHandle`](crate::state::AppHandle) — the form the routers reach for, which hold a swappable
/// handle rather than a pinned `Arc<App>`. Loads the handle once.
#[must_use]
pub fn engine_host_from_handle(handle: &Arc<crate::state::AppHandle>) -> Arc<dyn EngineHost> {
    Arc::new(EngineHostImpl::from_handle(Arc::clone(handle)))
}

/// A source of freshly live-bound hosts: each call returns a host reading the current snapshot, so a
/// config swap between calls is seen.
pub type LiveHostFactory = Arc<dyn Fn() -> Arc<dyn EngineHost> + Send + Sync>;

/// A [`LiveHostFactory`] closing over a live [`AppHandle`](crate::state::AppHandle): each call
/// returns a fresh `from_handle` host whose BOUND snapshot is the handle's CURRENT load.
#[must_use]
pub fn live_host_factory(handle: Arc<crate::state::AppHandle>) -> LiveHostFactory {
    Arc::new(move || {
        Arc::new(EngineHostImpl::from_handle(Arc::clone(&handle))) as Arc<dyn EngineHost>
    })
}

/// THE LIVE RE-RESOLUTION a door unit's entitlement asks through (`entitlement.check`, ARCHITECT
/// round 4 Q-L3B-SURFACES (a)): an admitted principal re-resolved against the CURRENT snapshot's
/// governance registry (a registry key, by id) and `role_bindings` (a role-bound key), through
/// [`Standing::still_permitted`](busbar_kernel::trust::validate::Standing::still_permitted). `None`
/// when it no longer stands; a deployment with governance off stands as admitted.
#[must_use]
pub fn live_standing(handle: Arc<crate::state::AppHandle>) -> crate::host_services::Standing {
    Arc::new(move |admitted, now| {
        let app = handle.load();
        standing_in(&app, admitted, now)
    })
}

/// [`live_standing`] over one fixed generation `app` (a composition with no live handle).
#[must_use]
pub fn standing_over(app: Arc<App>) -> crate::host_services::Standing {
    Arc::new(move |admitted, now| standing_in(&app, admitted, now))
}

/// `admitted` as it stands in `app` at `now`.
fn standing_in(
    app: &App,
    admitted: &Arc<busbar_contract::records::VirtualKey>,
    now: u64,
) -> Option<Arc<busbar_contract::records::VirtualKey>> {
    let resolve = crate::governance::LiveResolve {
        governance: app.governance.as_deref(),
        role_bindings: &app.role_bindings,
    };
    let standing = busbar_kernel::trust::validate::Standing::opened(
        Some(admitted),
        busbar_kernel::trust::validate::Snapshot::Watching,
        std::time::Duration::MAX,
    );
    match standing.still_permitted(
        Some(&resolve as &dyn busbar_kernel::trust::validate::GovResolve),
        0,
        now,
    ) {
        Ok(Some(live)) => Some(live),
        Ok(None) => Some(Arc::clone(admitted)),
        Err(_) => None,
    }
}

#[cfg(test)]
#[path = "tests/host_tests.rs"]
mod tests;
