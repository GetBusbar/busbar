// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::projection::{Projection, Rendered};
use crate::limits::admission::AdmissionGate;
use crate::plugin_routes::PluginHttpDispatch;
use busbar_contract::abi::mechanism::endpoint::*;
use busbar_contract::export_calls::{
    Delivered, ExportAxis, ExportCalls, ExportLossKind, ServeRequest,
};
use busbar_contract::export_stream::ExportStream;
use std::sync::Arc;

// The export sinks' config admission, boot (open, start), reload refresh and route table run off
// the request path; the request path below only delivers to and serves from what they opened.
#[cfg(test)]
use super::projection::resolve_projection;
#[cfg(test)]
use crate::config::ExportCfg;
pub(crate) use crate::off_path::export::{
    check, check_one_instance, configured_instance, linked_modules, one_instance, probe,
    queue_refresh, refresh_pending, scrape_instance,
};
#[cfg(test)]
use crate::off_path::export::{
    declared_streams, definition_requires_restart, instance_opened, project_routes,
    route_decls_from, sink_settings_with_resolver, start_one, word_one_instance,
};
pub use crate::off_path::export::{open_prepared, requires_restart, start};
#[cfg(test)]
use busbar_contract::abi::mechanism::route::Route;

pub(crate) const MAX_INFLIGHT_PLUGIN_DELIVERIES: usize = 64;

pub(crate) fn axis() -> Option<&'static dyn ExportAxis> {
    crate::preflight::root_rows().export_axis
}

pub(crate) struct PluginSink {
    pub(crate) name: String,
    pub(crate) module: Arc<str>,
    pub(crate) sink: Arc<dyn ExportCalls>,

    pub(crate) scrape: bool,
    /// The recorder grant this sink opened with (DES-NATIVE-FIRST-PARTY r3 §3.2): `requires_restart` compares a
    /// candidate's judgement with it, never re-judges the open sink.
    pub(crate) granted: Option<busbar_contract::export_calls::RecorderRequirements>,
    pub(crate) projection: Projection,

    pub(crate) span_record: bool,

    pub(crate) admission: Admission,
    pub(crate) started: std::sync::atomic::AtomicBool,

    pub(crate) reads: Option<Arc<crate::audit::amend::NodeAmendments>>,
}

pub(crate) struct Admission {
    pub(crate) live: bool,
    pub(crate) gate: AdmissionGate,
}

/// The opened exports retained by an application generation. All dependencies are present
/// before this owner is returned; starting a pump only changes its lifecycle state.
#[derive(Default)]
pub struct Exports {
    pub(crate) sinks: Vec<PluginSink>,
    pub(crate) refreshes: std::sync::Mutex<crate::off_path::export::Refreshes>,
    pub(crate) status_at: std::sync::Mutex<Option<std::time::Instant>>,
    pub(crate) captures: Arc<Captures>,
}

/// Completion of the actual admitted capture producers, including native read confirmations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureReport {
    /// A producer was destroyed or panicked before it completed its work.
    pub interrupted: bool,
}

#[derive(Default)]
struct CaptureState {
    closed: bool,
    active: usize,
    interrupted: bool,
}

#[derive(Default)]
pub(crate) struct Captures {
    state: std::sync::Mutex<CaptureState>,
    settled: tokio::sync::Notify,
}

impl Captures {
    fn enter(self: &Arc<Self>) -> Option<CapturePermit> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.closed {
            return None;
        }
        let Some(active) = state.active.checked_add(1) else {
            state.interrupted = true;
            return None;
        };
        state.active = active;
        Some(CapturePermit {
            owner: self.clone(),
            completed: false,
        })
    }
}

struct CapturePermit {
    owner: Arc<Captures>,
    completed: bool,
}

impl Drop for CapturePermit {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock().unwrap_or_else(|p| p.into_inner());
        state.interrupted |= !self.completed;
        state.active -= 1;
        drop(state);
        self.owner.settled.notify_waiters();
    }
}

impl Exports {
    /// Fence capture before projection or enqueue, while retaining every previously admitted producer.
    /// This does not stop pumps or close the bound observer; root does those after capture settlement.
    pub fn close_capture(&self) {
        self.captures
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .closed = true;
    }

    /// Close intake and await all admitted capture work, including detached native read confirmations.
    /// Cancelling this waiter never cancels a producer. Root supplies its existing shutdown deadline.
    pub async fn drain_capture(&self) -> CaptureReport {
        self.close_capture();
        loop {
            let settled = self.captures.settled.notified();
            tokio::pin!(settled);
            settled.as_mut().enable();
            {
                let state = self
                    .captures
                    .state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                if state.active == 0 {
                    return CaptureReport {
                        interrupted: state.interrupted,
                    };
                }
            }
            settled.await;
        }
    }
}

/// Connect the complete generation's audit observer after AppHandle and routes exist.
pub fn publish_observers(app: &crate::state::App) -> Result<(), String> {
    crate::audit::auditlog::publish_export_observers(app)
}

pub(super) fn deliver_to(
    exports: &Exports,
    stream: ExportStream,
    op: &str,
    mut f: impl FnMut(Projection, bool) -> Rendered,
) {
    let Some(capture) = exports.captures.enter() else {
        return;
    };
    let mut handed = Handed {
        completion: CaptureCompletion {
            capture: Some(capture),
            sinks: Vec::new(),
            finished: false,
        },
        ..Handed::default()
    };
    for s in exports
        .sinks
        .iter()
        .filter(|s| s.projection.wants_stream(stream))
    {
        deliver_one(s, stream, &mut f, &mut handed);
    }
    handed.record(op);
}

pub(crate) fn deliver_on(
    exports: &Exports,
    stream: ExportStream,
    op: &str,
    mut f: impl FnMut(Projection) -> Rendered,
) {
    let Some(capture) = exports.captures.enter() else {
        return;
    };
    let mut handed = Handed {
        completion: CaptureCompletion {
            capture: Some(capture),
            sinks: Vec::new(),
            finished: false,
        },
        ..Handed::default()
    };
    for sink in exports
        .sinks
        .iter()
        .filter(|s| s.projection.wants_stream(stream))
    {
        deliver_one(
            sink,
            stream,
            &mut |projection, _| f(projection),
            &mut handed,
        );
    }
    handed.record(op);
}

/// The sinks of one event that queued their line and still owe a durable access amendment.
/// They are recorded together: one amendment per sink, one durable commit per event.
#[derive(Default)]
struct Handed {
    amendments: Option<Arc<crate::audit::amend::NodeAmendments>>,
    runtime: Option<tokio::runtime::Handle>,
    reads: Vec<(Arc<str>, crate::export::projection::Members)>,
    permits: Vec<Arc<tokio::sync::OwnedSemaphorePermit>>,
    // Last: callbacks and permit custody are released before the capture count reaches zero.
    completion: CaptureCompletion,
}

#[derive(Default)]
struct CaptureCompletion {
    sinks: Vec<Arc<dyn ExportCalls>>,
    capture: Option<CapturePermit>,
    finished: bool,
}

impl CaptureCompletion {
    fn finish(&mut self, integrity_failed: bool) {
        if integrity_failed {
            for sink in &self.sinks {
                sink.shed(ExportLossKind::IntegrityFailed);
            }
        }
        self.finished = true;
        if let Some(capture) = &mut self.capture {
            capture.completed = true;
        }
    }
}

impl Drop for CaptureCompletion {
    fn drop(&mut self) {
        if !self.finished {
            // Covers panic, runtime shutdown, and destruction before the task's first poll.
            // The callback precedes capture permit release, so drain cannot race past evidence.
            for sink in &self.sinks {
                sink.shed(ExportLossKind::IntegrityFailed);
            }
        }
        self.sinks.clear();
    }
}

impl Handed {
    fn record(mut self, op: &str) {
        if self.reads.is_empty() {
            self.completion.finish(false);
            return;
        }
        let Some(runtime) = self.runtime.clone() else {
            return; // CaptureCompletion records any already accepted read as interrupted.
        };
        let op = op.to_owned();
        // The future owns the complete work object before spawning, including its final release
        // guard. Even destruction before its first poll reports integrity and releases ownership.
        runtime.spawn(async move {
            let mut work = self;
            let failed = match &work.amendments {
                Some(amendments) => crate::audit::amend::export_reads(amendments, &op, &work.reads)
                    .await
                    .is_err(),
                None => true,
            };
            work.completion.finish(failed);
        });
    }
}

fn deliver_one(
    s: &PluginSink,
    stream: ExportStream,
    f: &mut impl FnMut(Projection, bool) -> Rendered,
    handed: &mut Handed,
) {
    if !s.started.load(std::sync::atomic::Ordering::Acquire) {
        s.sink.shed(ExportLossKind::CaptureRefused);
        return;
    }
    let admission = &s.admission;
    if !admission.live {
        return;
    }
    let Some(permit) = admission.gate.try_enter() else {
        s.sink.shed(ExportLossKind::CaptureRefused);
        return;
    };
    let Rendered { line, members } = f(s.projection, s.span_record);
    let amendments = s.reads.clone();
    let runtime = if amendments.is_some() {
        match handed
            .runtime
            .clone()
            .map_or_else(tokio::runtime::Handle::try_current, Ok)
        {
            Ok(runtime) => Some(runtime),
            Err(_) => {
                s.sink.shed(ExportLossKind::CaptureRefused);
                return;
            }
        }
    } else {
        None
    };
    // Retain admission through both actual delivery and its durable access
    // amendment, even if the sink releases its delivery permit immediately.
    let permit = Arc::new(permit);
    match s.sink.deliver(stream as u8, line, Box::new(permit.clone())) {
        Delivered::Queued => {
            let (Some(amendments), Some(runtime)) = (amendments, runtime) else {
                return;
            };
            handed.amendments.get_or_insert(amendments);
            handed.runtime.get_or_insert(runtime);
            handed.reads.push((Arc::clone(&s.module), members));
            handed.completion.sinks.push(s.sink.clone());
            handed.permits.push(permit);
        }
        Delivered::Shed => {} // The adapter already reported its exact refusal or loss.
    }
}

/// How often a scrape crosses into every export sink's STATUS. A scrape arrives every few
/// seconds per scraper and its answer is not read here, so crossing on every scrape is waste.
pub(crate) const STATUS_REFRESH: std::time::Duration = std::time::Duration::from_secs(15);

/// Whether a STATUS round is due at `now` given the last one in `at`; marks `now` when it is.
fn status_due(at: &std::sync::Mutex<Option<std::time::Instant>>, now: std::time::Instant) -> bool {
    let mut at = at.lock().unwrap_or_else(|p| p.into_inner());
    if at.is_some_and(|last| now.saturating_duration_since(last) < STATUS_REFRESH) {
        return false;
    }
    *at = Some(now);
    true
}

/// Cross every export sink's STATUS, at most once per [`STATUS_REFRESH`].
pub(crate) fn status_if_stale(exports: &Exports) {
    // The host monotonic clock's one reading for this scrape, as the Instant the window compares.
    let now = busbar_contract::mono_instant::instant_at(crate::store::monotonic_ns());
    if !status_due(&exports.status_at, now) {
        return;
    }
    exports.sinks.iter().for_each(|s| {
        let _ = s.sink.status();
    });
}

pub(crate) struct Unopened;

impl PluginHttpDispatch for Unopened {
    fn handle_http(&self, _: &EndpointRequest) -> EndpointResponse {
        EndpointResponse {
            status: 502,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn served(sink: Arc<dyn ExportCalls>) -> Arc<dyn PluginHttpDispatch> {
    Arc::new(Served(sink))
}

pub(crate) struct Served(pub(crate) Arc<dyn ExportCalls>);

impl PluginHttpDispatch for Served {
    fn handle_http_with_app(
        &self,
        app: &Arc<crate::state::App>,
        req: &EndpointRequest,
    ) -> EndpointResponse {
        let Some(scope) = self.0.scope(&req.path) else {
            return self.handle_http(req);
        };
        // Plugin HTTP dispatch runs on the blocking lane. Collect under the request's
        // exact App generation before making the one synchronous render call.
        let families = match scope {
            busbar_plugin_abi::kinds::export::export::SCOPE_METRICS => {
                let Ok(runtime) = tokio::runtime::Handle::try_current() else {
                    return EndpointResponse {
                        status: 503,
                        headers: Vec::new(),
                        body: Vec::new(),
                    };
                };
                match runtime.block_on(super::scrape::app_families(app)) {
                    Ok(families) => families,
                    Err(_) => {
                        return EndpointResponse {
                            status: 503,
                            headers: Vec::new(),
                            body: Vec::new(),
                        }
                    }
                }
            }
            busbar_plugin_abi::kinds::export::export::SCOPE_HOOKS => {
                super::scrape::hook_families(app)
            }
            _ => {
                return EndpointResponse {
                    status: 404,
                    headers: Vec::new(),
                    body: Vec::new(),
                }
            }
        };
        match self.0.render_scope(scope, &families) {
            Ok(response) => EndpointResponse {
                status: response.status,
                headers: response.headers,
                body: response.body,
            },
            Err(error) => {
                tracing::warn!(%error, "export scope render failed");
                EndpointResponse {
                    status: 502,
                    headers: Vec::new(),
                    body: Vec::new(),
                }
            }
        }
    }

    fn handle_http(&self, req: &EndpointRequest) -> EndpointResponse {
        let request = ServeRequest {
            method: &req.method,
            path: &req.path,
            query: Some(req.query.as_str()).filter(|q| !q.is_empty()),
            headers: &req.headers,
            body: &req.body,
        };
        match self.0.serve(&request) {
            Ok(r) => EndpointResponse {
                status: r.status,
                headers: r.headers,
                body: r.body,
            },
            Err(e) => {
                tracing::warn!(error = %e, "export plugin route failed");
                EndpointResponse {
                    status: 502,
                    headers: Vec::new(),
                    body: Vec::new(),
                }
            }
        }
    }
}

/// Complete the unpublished application's export routes from the instances opened in S8.
/// ListenerPlan freezes its physical mounts only after this assembly succeeds.
pub fn assemble_routes(
    mut app: crate::state::App,
    cfg: &crate::config::ExportCfg,
    seats: Vec<crate::plane_driver::port::PortSeat>,
    exports: Exports,
) -> Result<crate::state::App, String> {
    let (routes, withheld) = crate::off_path::export::project_routes(cfg, &exports.sinks);
    let routes = app
        .plugin_routes
        .with_export_routes(routes)?
        .with_withheld_public_exports(withheld);
    app.boot_route_paths = Arc::new(routes.paths());
    app.plugin_routes = Arc::new(routes);
    app.port_seats = seats.into();
    app.exports = Arc::new(exports);
    Ok(app)
}

#[cfg(test)]
#[path = "tests/plugin_tests.rs"]
mod tests;
