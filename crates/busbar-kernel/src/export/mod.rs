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
//!
//! Every other module — `request-log-file` and `request-log-webhook` among them — is a row of the
//! EXPORT AXIS ([`plugin`]). A row subscribed to `traces` is fed by [`traces`], the kernel's record
//! producer for that stream (K9a S7): one record per closed span, built to the sink's projection.

pub mod plugin;
pub(crate) mod projection;
pub mod prometheus;
pub mod traces;

use crate::config::ExportCfg;
use crate::export::projection::ProjectedRecord;
use crate::plugin_routes::RouteDecl;
use busbar_plugin_loader::{ExportField, ExportStream};
use serde_json::Value;
use std::sync::Arc;

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
    let built_in = prometheus::route_decl(cfg).into_iter();
    built_in.chain(plugin::route_decls(cfg)).collect()
}

/// Whether the kernel serves `module` itself — a module an export-axis row may not spell, since
/// every instance naming it would reach the built-in.
pub fn built_in(module: &str) -> bool {
    projection::module_streams(module).is_some()
}

/// The raw per-request facts the `logs` stream is built FROM — everything core knows at
/// request-finish, before any projection is applied. Deliberately NOT a payload: it is the producer's
/// output, and [`build_request_log`] is the only thing that turns it into one, per sink, bounded by
/// that sink's projection.
pub(crate) struct RequestLogFacts<'a> {
    pub(crate) ts: u64,
    pub(crate) ingress_protocol: &'a str,
    pub(crate) pool: &'a str,
    pub(crate) outcome: &'a str,
    pub(crate) latency_ms: u64,
}

/// Build ONE sink's request-log payload, TO ITS PROJECTION. Pure (no I/O) so it is unit-testable.
///
/// Every field goes through [`ProjectedRecord::set`], which writes it only if the projection grants
/// it — so an ungranted field is never serialized and never crosses the ABI. There is no
/// `json!` literal here on purpose: a literal plus a filter is a step someone can forget, and its
/// failure mode is silent over-disclosure.
pub(crate) fn build_request_log(projection: projection::Projection, f: &RequestLogFacts) -> Value {
    let mut rec = ProjectedRecord::new(projection, ExportStream::Logs);
    rec.set(ExportField::Ts, f.ts)
        .set(ExportField::IngressProtocol, f.ingress_protocol)
        .set(ExportField::Pool, f.pool)
        .set(ExportField::Outcome, f.outcome)
        .set(ExportField::LatencyMs, f.latency_ms);
    rec.finish()
}

/// A per-delivery cache of already-built payloads, keyed by PROJECTION. Instances with IDENTICAL
/// projections share one payload, so the build cost is per DISTINCT PROJECTION, not per sink (design
/// `export-projection-grammar.md`, "Implementation note"). A `Vec` because the number of distinct
/// projections in a deployment is tiny and a linear scan beats hashing at that size.
pub(crate) struct PayloadCache<'a> {
    facts: &'a RequestLogFacts<'a>,
    built: Vec<(projection::Projection, Arc<Value>)>,
}

impl<'a> PayloadCache<'a> {
    pub(crate) fn new(facts: &'a RequestLogFacts<'a>) -> PayloadCache<'a> {
        PayloadCache {
            facts,
            built: Vec::new(),
        }
    }

    /// This sink's payload, built to `projection` (and reused for any sibling with the same one).
    pub(crate) fn get(&mut self, projection: projection::Projection) -> Arc<Value> {
        if let Some((_, v)) = self.built.iter().find(|(p, _)| *p == projection) {
            return v.clone();
        }
        let v = Arc::new(build_request_log(projection, self.facts));
        self.built.push((projection, v.clone()));
        v
    }
}

/// Fan the request-log facts out to every configured PUSH sink, each receiving a payload built TO
/// ITS OWN PROJECTION. Fire-and-forget; never blocks the request path and never surfaces errors —
/// telemetry must not affect serving.
///
/// The PAYLOAD IS BUILT PER SINK, not built once and broadcast: that is what makes a narrower sink's
/// exclusion real rather than advisory. Sinks sharing a projection share one build (see
/// [`PayloadCache`]).
pub(crate) fn deliver_request_log(facts: &RequestLogFacts<'_>) {
    let mut cache = PayloadCache::new(facts);
    plugin::deliver_logs(&mut cache);
}
