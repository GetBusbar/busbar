// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Built-in observability EXPORTERS: the distribution half of the observability
//! streams, lifted OUT of core into compiled-in modules that CONSUME the `export` plugin kind + the
//! plugin HTTP endpoint registration. PRESENCE + settings (the `export:` config block,
//! [`crate::config::ExportCfg`]) is the on/off switch, exactly like the built-in `env`/`file` secret
//! modules — no config boolean, no dynamic tarball.
//!
//! The COLLECTION half stays core: the Prometheus recorder + the ~57 emit sites + the
//! scrape-time gauge derivation live in [`crate::metrics`]; the request-log projection is still built
//! in the request-finish path. These modules move only the DISTRIBUTION:
//!
//! - [`prometheus`] — PULL. Serves `/metrics` via the endpoint-registration `handle_http` path (the
//!   well-known-`/metrics` exception), rendering the recorder registry. When `export.prometheus` is
//!   present the recorder is installed (collection on) and a `GET /metrics` plugin route is
//!   registered; absent ⇒ no recorder, `/metrics` unmounted, every emit site a true no-op.
//! - [`webhook`] — PUSH per-request. The `request-log-webhook` + `generic-webhook` sinks POST the
//!   built request-log line behind the relocated SSRF guard.
//! - [`file`] — PUSH per-request. The `request-log-file` sink appends the line as JSONL.
//!
//! WHAT LEFT. The FAN-OUT is not here any more: the composition root builds one payload per
//! distinct projection, sheds for each sink against a gate it owns, and calls the sink. Each PUSH
//! module below therefore states itself as a [`BuiltinPushSink`] — its projection, its capacity,
//! its gate label, its drop counter and the one call that ships a payload — and carries no
//! semaphore, no `OnceLock` and no knowledge of its siblings. That is the shape a `busbar-export-*`
//! crate presents over the ABI, reached here without one.

pub(crate) mod file;
pub mod prometheus;
pub(crate) mod webhook;

use crate::config::ExportCfg;
use crate::plugin_routes::{RouteDecl, RouteKind};
/// The projection grammar, re-exported for the COMPOSITION ROOT. The grammar itself lives in the
/// plugin ABI beside its vocabulary (`busbar_plugin::cold::export::projection`); the root reaches it
/// through here rather than naming the ABI crate directly, because the root's edge into this crate
/// is the one the retirement already accounts for and a second one into the ABI would be a new
/// undeclared dependency for a re-export.
pub use busbar_plugin::cold::export::projection::{build_request_log, Projection, RequestLogFacts};
use busbar_plugin_loader::ExportStream;
use busbar_plugin_loader::Route;
use serde_json::Value;
use std::sync::OnceLock;
use tokio::sync::OwnedSemaphorePermit;

/// The streams the `otlp` sink carries. It has no module of its own in this crate — its config
/// surface is `ExportCfg::otlp` and its span pipeline is the tracing subscriber — so its
/// declaration sits here beside its siblings'. It moves to `busbar-export-otlp` with the pipeline.
pub(crate) const OTLP_STREAMS: &[ExportStream] = &[ExportStream::Traces];

/// The live plugin-route declarations the built-in exporters contribute — today just the
/// `prometheus` exporter's `GET /metrics`. Built at App construction from the resolved `export:` block
/// and folded into the [`crate::plugin_routes::PluginRouteTable`] on the App snapshot.
///
/// **A config apply UNMOUNTS but cannot MOUNT.** The two directions are not symmetric, and an earlier
/// version of this comment claimed they were:
///
/// - **Removing** `export.prometheus` takes effect immediately. The path stays registered on the
///   router, but [`crate::plugin_routes::plugin_route_dispatch`] resolves the owner from the CURRENT
///   snapshot on every request, finds nothing, and 404s. No rebuild needed.
/// - **Adding** it does NOT take effect until restart. Each declared PATH is registered on the axum
///   router once, at boot (`plugin_routes.rs`, `on(filter, plugin_route_dispatch)`), and a config
///   apply swaps only `Arc<App>` — the router is never rebuilt. If no `prometheus` instance existed
///   at boot, `/metrics` was never registered, so it keeps 404ing however many times the operator
///   PUTs the config. The metrics recorder is additionally `OnceLock`-guarded and installed once.
///
/// This is the SAME boot-frozen mechanism already documented for `max_inbound_concurrent` in
/// [`crate::admin::v1::json::handlers`]'s `reload_to_apply_fields`, and the
/// `export:` named map REPORTS it the same way: a mutation that introduces a route path the router
/// never registered at boot answers with `reload_to_apply` naming that path plus a `note` saying a
/// restart is required ([`crate::plugin_routes::paths_awaiting_restart`]). The apply is still a no-op
/// for the route itself — genuinely hot-mounting one is a router rebuild, not done here — but it is no
/// longer a SILENT one.
pub(crate) fn route_decls(cfg: &ExportCfg) -> Vec<RouteDecl> {
    prometheus::route_decl(cfg).into_iter().collect()
}

/// The manifest-level `(owner, kind, route)` mirror of [`route_decls`] for the `--validate`/boot
/// collision preflight — WITHOUT the live dispatchers, so a loaded third-party export plugin claiming
/// a path a built-in exporter already owns (e.g. `GET /metrics`) fails loudly before boot.
pub(crate) fn route_owners(cfg: &ExportCfg) -> Vec<(String, RouteKind, Route)> {
    prometheus::route_owner(cfg).into_iter().collect()
}

/// Ship one payload, already built to the sink's projection, taking the permit that holds this
/// delivery's slot. Named so the sink declaration below reads as the five facts it is, rather than
/// as one line of type.
pub type Ship = Box<dyn Fn(&Value, OwnedSemaphorePermit) + Send + Sync>;

/// One configured built-in PUSH sink, handed to the COMPOSITION ROOT as data.
///
/// The root composes the export sinks and fans the built request-log line out to them; this struct
/// is how a sink that has not yet become its own `busbar-export-*` crate presents itself to that
/// fan-out. Everything on it except [`ship`](Self::ship) is a POLICY the root enforces, stated by
/// the sink rather than guessed: how deep this instance's in-flight queue may get, what its gate is
/// called on `busbar_admission_denied_total{gate}`, and which counter its shed lands on. The root
/// takes the permit and only then calls `ship` — the sink never sees a delivery it has no room for,
/// and never carries a semaphore of its own.
pub struct BuiltinPushSink {
    /// The streams + fields THIS instance was granted. The root builds its payload to exactly this,
    /// so an ungranted field is never serialized for it.
    pub projection: Projection,
    /// How many deliveries of this instance may be in flight at once.
    pub max_inflight: usize,
    /// This sink's own `busbar_admission_denied_total{gate="..."}` label — supplied BY THE SINK, so
    /// the label is never a string the fan-out invented about an instance it is shedding for.
    pub gate: &'static str,
    /// This sink's own drop counter, incremented by the root on a shed (the admission counter above
    /// fires for every gate; this one is the sink's policy-specific one).
    pub dropped_total: &'static str,
    /// Ship one payload, already built to [`projection`](Self::projection). Fire-and-forget: the
    /// root has already shed for it and hands over the permit that holds its slot, which the sink
    /// releases by dropping when the delivery ends.
    pub ship: Ship,
}

/// Every configured built-in PUSH sink from the resolved `export:` block, in config order. Called
/// ONCE at boot by the composition root, which holds the result — the process-global `OnceLock`s
/// these sinks used to hide behind are gone, because "exactly one of these, built at boot" is a
/// statement the root makes about everything it composes and not a thing each sink re-invents.
/// Empty when no PUSH sink is configured (the zero-config default), which is the root's signal to
/// install no fan-out at all.
pub fn builtin_push_sinks(cfg: &ExportCfg) -> Vec<BuiltinPushSink> {
    let mut sinks = webhook::sinks(cfg);
    sinks.extend(file::sinks(cfg));
    sinks
}

/// The composition root's request-log fan-out, installed once at boot.
///
/// THE SEAM. The distribution half of observability is not core's: the root loads the export sinks,
/// sheds for them and fans one line out to each. What stays here is the request-finish path's
/// single call and the compute gate in front of it — core still decides whether a `logs` record is
/// produced at all (`ExportCfg::projection_union`), because that is a decision about work core
/// would otherwise do, and it still owns the facts. Where those facts GO is behind this pointer.
static REQUEST_LOG_SINK: OnceLock<fn(&RequestLogFacts<'_>)> = OnceLock::new();

/// Install the root's fan-out. Called once, at boot, before the listener binds. A second call is
/// ignored rather than fatal, the same posture the sinks' own boot-once locks had.
pub fn install_request_log_sink(sink: fn(&RequestLogFacts<'_>)) {
    let _ = REQUEST_LOG_SINK.set(sink);
}

/// The projection a test sink is given, minted THROUGH the real path: an instance that subscribes
/// to `logs` and overrides nothing, which resolves to the produced default set — exactly what
/// `build_request_log` fills in, so a test that is not ABOUT the projection sees the same payload
/// the pre-projection code produced.
///
/// It goes through `projection::resolve_projection` rather than a mint-from-parts hatch because
/// resolution is now the only public way to obtain a `Projection` at all: the parts constructor is
/// private to the grammar and its test-only door does not leave that crate. A test helper that
/// could widen a projection would be the one hole in "the operator grants, nothing else does".
#[cfg(test)]
pub(crate) fn test_logs_projection() -> Projection {
    let mut errors = Vec::new();
    let p = busbar_plugin::cold::export::projection::resolve_projection(
        "test",
        "request-log-file",
        Some(file::STREAMS),
        Some(&["logs".to_string()]),
        None,
        false,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:#?}");
    p
}

/// Hand the request-log facts to the composition root's fan-out. A single pointer read when
/// nothing is installed (`--validate`, a test binary, a deployment with no PUSH sink), which is the
/// same "the read runs ONLY when declared" posture the compute gate in front of this call keeps.
pub(crate) fn deliver_request_log(facts: &RequestLogFacts<'_>) {
    if let Some(sink) = REQUEST_LOG_SINK.get() {
        sink(facts);
    }
}

#[cfg(test)]
#[path = "tests/seam_tests.rs"]
mod tests;
