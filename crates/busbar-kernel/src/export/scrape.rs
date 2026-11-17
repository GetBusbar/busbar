// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::plugin_routes::PluginHttpDispatch;
use crate::state::App;
use busbar_contract::abi::host::service::{SNAPSHOT_SCOPE_HOOKS, SNAPSHOT_SCOPE_WHOLE};
use busbar_contract::abi::mechanism::endpoint::*;
use busbar_contract::services::Snapshot;
use std::cell::RefCell;
use std::sync::Arc;

pub(crate) const NOT_GRANTED: &str = "the snapshot is lent only to the crossing granted it";

const UNKNOWN_SCOPE: &str = "no such snapshot scope";

/// The refusal `/metrics` answers (503, reason `telemetry_disabled`) when the operator set
/// `telemetry.enabled: false`.
pub(crate) const TELEMETRY_DISABLED: &str = "telemetry_disabled";

struct Lend {
    app: Option<Arc<App>>,
}

thread_local! {
    /// The snapshot lent to the crossing running on this thread, if one is.
    static LENT: RefCell<Option<Lend>> = const { RefCell::new(None) };
}

fn lend<R>(app: Option<Arc<App>>, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<Lend>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let prior = self.0.take();
            LENT.with(|l| *l.borrow_mut() = prior);
        }
    }
    let prior = LENT.with(|l| l.borrow_mut().replace(Lend { app }));
    let _restore = Restore(prior);
    f()
}

pub(crate) struct Granted(pub(crate) Arc<dyn PluginHttpDispatch>);

impl PluginHttpDispatch for Granted {
    fn handle_http(&self, req: &EndpointRequest) -> EndpointResponse {
        lend(None, || self.0.handle_http(req))
    }

    fn handle_http_with_app(&self, app: &Arc<App>, req: &EndpointRequest) -> EndpointResponse {
        lend(Some(Arc::clone(app)), || {
            self.0.handle_http_with_app(app, req)
        })
    }
}

#[cfg(test)]
pub(crate) fn crossing_is_granted() -> bool {
    LENT.with(|held| held.borrow().is_some())
}

/// Capture the crossing's lend synchronously, before the host schedules native work.
/// No thread-local grant survives an await or migrates to an unrelated request.
pub(crate) fn read(scope: u32) -> impl std::future::Future<Output = Snapshot> + Send + 'static {
    let lent = LENT.with(|held| held.borrow().as_ref().map(|lent| lent.app.clone()));
    async move {
        let Some(app) = lent else {
            return Snapshot::Refused(NOT_GRANTED);
        };
        match scope {
            SNAPSHOT_SCOPE_WHOLE => whole(app.as_deref()).await,
            SNAPSHOT_SCOPE_HOOKS => {
                Snapshot::Families(app.as_deref().map(hook_families).unwrap_or_default())
            }
            _ => Snapshot::Refused(UNKNOWN_SCOPE),
        }
    }
}

/// Why the admin `/metrics` read produced no families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrapeRefusal {
    /// The operator set `telemetry.enabled: false`: 503, reason `telemetry_disabled`.
    TelemetryDisabled,
    /// The recorder is not installed yet.
    NotReady,
    /// A scrape-time refresh failed, for this reason.
    Failed(&'static str),
}

async fn collect(
    app: Option<&App>,
) -> Result<Vec<busbar_contract::export_calls::Family>, ScrapeRefusal> {
    prepare(app).await?;
    crate::snapshot::snapshot().ok_or(ScrapeRefusal::NotReady)
}

async fn prepare(app: Option<&App>) -> Result<(), ScrapeRefusal> {
    if crate::snapshot::explicitly_off() {
        return Err(ScrapeRefusal::TelemetryDisabled);
    }
    let installed = crate::snapshot::recorder_installed();
    if let Some(app) = app.filter(|_| installed) {
        if let Err(error) = crate::snapshot::refresh_scrape_gauges(app).await {
            return Err(ScrapeRefusal::Failed(error));
        }
        super::plugin::status_if_stale(&app.exports);
    }
    if installed {
        metrics::gauge!(crate::snapshot::BUILD_INFO, "version" => env!("CARGO_PKG_VERSION"))
            .set(1.0);
    }
    Ok(())
}

/// Source availability and output-capacity failure keep their distinct refusal meanings.
#[derive(Debug)]
pub enum BudgetedScrapeRefusal {
    Source(ScrapeRefusal),
    Output(crate::limits::output::OutputError),
}

pub async fn app_families_budgeted(
    app: &App,
    request: &crate::limits::process_admission::RequestLease,
) -> Result<
    crate::limits::output::Captured<Vec<busbar_contract::export_calls::Family>>,
    BudgetedScrapeRefusal,
> {
    // Refresh/drain maintenance is explicitly excluded; owned output projection is not.
    prepare(Some(app))
        .await
        .map_err(BudgetedScrapeRefusal::Source)?;
    crate::snapshot::snapshot_budgeted(request)
        .map_err(BudgetedScrapeRefusal::Output)?
        .ok_or(BudgetedScrapeRefusal::Source(ScrapeRefusal::NotReady))
}

pub fn hook_families_budgeted(
    _app: &App,
    request: &crate::limits::process_admission::RequestLease,
) -> Result<
    crate::limits::output::Captured<Vec<busbar_contract::export_calls::Family>>,
    crate::limits::output::OutputError,
> {
    Ok(crate::limits::output::CaptureScope::new(request)?.finish(Vec::new()))
}

/// The whole-registry families for the admin `/metrics` (the same read the snapshot service gives
/// an exporter), or why there are none.
pub async fn app_families(
    app: &App,
) -> Result<Vec<busbar_contract::export_calls::Family>, ScrapeRefusal> {
    collect(Some(app)).await
}

/// The hook-reported families for the admin `/metrics/hooks`. The kernel opens no hook (the native
/// bindings are the only hook path) and no native hook reports status families, so a generation
/// holds none.
#[must_use]
pub fn hook_families(_app: &App) -> Vec<busbar_contract::export_calls::Family> {
    Vec::new()
}

async fn whole(app: Option<&App>) -> Snapshot {
    match collect(app).await {
        Ok(families) => Snapshot::Families(families),
        Err(ScrapeRefusal::TelemetryDisabled) => Snapshot::Refused(TELEMETRY_DISABLED),
        Err(ScrapeRefusal::NotReady) => Snapshot::NotReady,
        Err(ScrapeRefusal::Failed(error)) => Snapshot::Refused(error),
    }
}

#[cfg(test)]
#[path = "tests/scrape_tests.rs"]
pub(crate) mod tests;
