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
    fn from_handle(handle: &crate::state::AppHandle) -> Self {
        EngineHostImpl { app: handle.load() }
    }
}

pub trait EngineHost: Send + Sync {
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

#[must_use]
pub fn engine_host(app: &Arc<App>) -> Arc<dyn EngineHost> {
    Arc::new(EngineHostImpl::new(Arc::clone(app)))
}

#[must_use]
pub fn engine_host_from_handle(handle: &Arc<crate::state::AppHandle>) -> Arc<dyn EngineHost> {
    Arc::new(EngineHostImpl::from_handle(handle))
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
    standing_with(app.governance.as_deref(), &app.role_bindings, admitted, now)
}

/// A complete immutable governance policy; it contains no application back-reference.
pub fn policy_standing(
    governance: Option<Arc<crate::governance::GovState>>,
    role_bindings: crate::config::RoleBindings,
) -> crate::host_services::Standing {
    Arc::new(move |admitted, now| {
        standing_with(governance.as_deref(), &role_bindings, admitted, now)
    })
}

fn standing_with(
    governance: Option<&crate::governance::GovState>,
    role_bindings: &crate::config::RoleBindings,
    admitted: &Arc<busbar_contract::records::VirtualKey>,
    now: u64,
) -> Option<Arc<busbar_contract::records::VirtualKey>> {
    let resolve = crate::governance::LiveResolve {
        governance,
        role_bindings,
    };
    // Asked once per call and held by nobody: no standing is opened, so no lifetime clock is read.
    busbar_kernel::trust::validate::standing_now(
        admitted,
        Some(&resolve as &dyn busbar_kernel::trust::validate::GovResolve),
        now,
    )
    .ok()
}

#[cfg(test)]
#[path = "tests/host_tests.rs"]
mod tests;
