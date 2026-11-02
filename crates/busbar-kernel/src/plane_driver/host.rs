// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
    #[must_use]
    pub fn new(app: Arc<App>) -> Self {
        EngineHostImpl { app }
    }

    #[must_use]
    pub fn from_handle(handle: Arc<crate::state::AppHandle>) -> Self {
        EngineHostImpl { app: handle.load() }
    }
}

pub trait EngineHost: Send + Sync {
    fn caller_in_hook_groups(&self, caller_group: Option<&str>, hook_groups: &[String]) -> bool;

    fn pool_rewrites(
        &self,
        pool: &str,
    ) -> &[(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )];

    fn rewrite_hooks(
        &self,
    ) -> &[(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )];

    fn hook_read(&self, name: &str, principal: Option<&str>, op: &str, identity: bool);

    fn plane_gates_of(
        &self,
        plane_key: &str,
        container: &str,
    ) -> Vec<(u16, crate::hooks::ResolvedPolicy)>;

    fn plane_rewrites_of(
        &self,
        plane_key: &str,
        container: &str,
    ) -> Vec<(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )>;

    fn gate_scan(&self) -> Option<(Arc<crate::session::SessionStore>, u64)>;

    fn tap_hooks(&self) -> &[crate::hooks::TapEntry];

    fn tap_hooks_response(&self) -> &[crate::hooks::TapEntry];

    fn tap_hooks_routing(&self) -> &[crate::hooks::TapEntry];

    fn tap_hooks_candidate(&self) -> &[crate::hooks::TapEntry];

    fn pool_gates(&self, pool: &str) -> &[(u16, crate::hooks::ResolvedPolicy)];

    fn global_gates(&self) -> &[(u16, crate::hooks::ResolvedPolicy)];

    fn pool_policy(&self, pool: &str) -> Option<&crate::hooks::ResolvedPolicy>;

    fn requested_signals(&self) -> &crate::hooks::RequestedSignals;

    fn next_request_id(&self) -> u64;

    fn governance(&self) -> Option<GovHandle>;

    fn meter_pin(&self) -> Option<MeterPin>;

    fn rate_headroom(
        &self,
        pin: &MeterPin,
        key: &busbar_contract::records::VirtualKey,
        pool: Option<&str>,
        now: u64,
    ) -> Option<f64>;

    fn budget_state(
        &self,
        pin: &MeterPin,
        key: &busbar_contract::records::VirtualKey,
        now: u64,
    ) -> Vec<busbar_contract::hooks::BudgetBucketState>;

    fn arrival_envelope_dialect(&self, path: &str) -> &'static str;

    fn arrival_fallback_error(
        &self,
        path: &str,
        status: axum::http::StatusCode,
        kind: &str,
        message: &str,
    ) -> axum::response::Response;

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
    fn hook_read(&self, name: &str, principal: Option<&str>, op: &str, identity: bool) {
        crate::audit::amend::hook_read(&self.app.amendments, name, principal, op, identity);
    }

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
        self.app
            .governance
            .clone()
            .map(|g| GovHandle(g as Arc<dyn std::any::Any + Send + Sync>))
    }

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
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(gov: GovHandle, cost: CostHandle) -> Self {
        MeterPin { gov, cost }
    }

    pub fn gov(&self) -> &GovHandle {
        &self.gov
    }
}

fn cost_model(cost: &CostHandle) -> Option<Arc<crate::cost::CostModel>> {
    cost.0.clone().downcast().ok()
}

fn pin_models(
    pin: &MeterPin,
) -> Option<(
    Arc<crate::governance::GovState>,
    Arc<crate::cost::CostModel>,
)> {
    Some((pin.gov.0.clone().downcast().ok()?, cost_model(&pin.cost)?))
}

#[must_use]
pub fn engine_host(app: &Arc<App>) -> Arc<dyn EngineHost> {
    Arc::new(EngineHostImpl::new(Arc::clone(app)))
}

#[must_use]
pub fn engine_host_value(app: &Arc<App>) -> impl EngineHost + 'static {
    EngineHostImpl::new(Arc::clone(app))
}

#[must_use]
pub fn engine_host_from_handle(handle: &Arc<crate::state::AppHandle>) -> Arc<dyn EngineHost> {
    Arc::new(EngineHostImpl::from_handle(Arc::clone(handle)))
}

pub type LiveHostFactory = Arc<dyn Fn() -> Arc<dyn EngineHost> + Send + Sync>;

#[must_use]
pub fn live_host_factory(handle: Arc<crate::state::AppHandle>) -> LiveHostFactory {
    Arc::new(move || {
        Arc::new(EngineHostImpl::from_handle(Arc::clone(&handle))) as Arc<dyn EngineHost>
    })
}

#[must_use]
pub fn live_standing(handle: Arc<crate::state::AppHandle>) -> crate::host_services::Standing {
    Arc::new(move |admitted, now| {
        let app = handle.load();
        standing_in(&app, admitted, now)
    })
}

#[must_use]
pub fn standing_over(app: Arc<App>) -> crate::host_services::Standing {
    Arc::new(move |admitted, now| standing_in(&app, admitted, now))
}

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
