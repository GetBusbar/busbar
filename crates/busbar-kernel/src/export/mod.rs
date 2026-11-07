// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub mod plugin;
pub(crate) mod projection;
pub(crate) mod scrape;
pub mod traces;

use crate::config::ExportCfg;
use crate::export::projection::ProjectedRecord;
use crate::plugin_routes::RouteDecl;
use busbar_contract::abi::export::{ExportField, ExportStream};
use serde_json::Value;
use std::sync::Arc;

/// Read the real host snapshot service from a test-support crossing. The existing snapshot grant
/// still decides whether this caller may read; an ungranted caller receives its normal refusal.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn read_test_snapshot(
    scope: u32,
) -> impl std::future::Future<Output = busbar_contract::services::Snapshot> + Send + 'static {
    scrape::read(scope)
}

/// Dispatch a test-support sink through the real served-sink adapter and snapshot grant. The grant
/// is lent only for each HTTP crossing and restored by the same guard used for live scrape routes.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn serve_test_sink(
    sink: Arc<dyn busbar_contract::export_calls::ExportCalls>,
) -> Arc<dyn crate::plugin_routes::PluginHttpDispatch> {
    Arc::new(scrape::Granted(plugin::served(sink)))
}

/// Host-owned user configuration capabilities, derived from the same producer tables used by
/// export projection resolution. Module-specific carried streams remain an admission check.
#[cfg(feature = "openapi-schema")]
pub fn configuration_capabilities() -> Value {
    serde_json::json!({
        "durable": false,
        "request_timing": {
            "profile": "observed-pump-v1",
            "stream": "traces",
            "record": "span.attributes",
            "requires": "enabled hot-path tracing and an exporter taking full span records",
            "coverage": "selected request-pump attempts, including normal, degraded and retry attempts; not pre-route refusals or session traffic outside the request pump",
            "identity": "trace_id/parent_span_id link the request; the request_attempts parent span scopes attempt ordinals, including separate session turns; retry_of_attempt names its predecessor",
            "clock": "monotonic elapsed microseconds from the attempt timing guard after member selection; route_wait_us is the preceding member selection duration",
            "intervals": {
                "route_wait_us": "member selection, including waits within selection; not an isolated queue duration",
                "response_ready_us": "first observed far-end status or nonempty bytes; not stream completion",
                "first_body_us": "first nonempty non-trailer far-end bytes; not a token event or TTFT",
                "far_end_last_us": "far-end terminal piece or end-of-pieces without cut/failover",
                "producer_complete_us": "pump completed its output writes; not proof of remote client consumption",
                "cancelled_us": "pump observed cancellation; cancel_reason is the engine reason code",
                "attempt_end_us": "pump attempt terminated, retried, or was abandoned"
            },
            "unknown": ["first_token", "provider_internal_cpu", "isolated_queue_wait", "client_consumption"],
            "missing_fields": "unobserved; never zero or inferred",
            "aggregation": "offsets overlap; never sum them as disjoint durations; busy_ns/idle_ns are span entry accounting, not CPU profiling",
            "sampling": "no producer probabilistic sampling; disabled/level-filtered tracing omits records; exporter sampling is exporter-specific",
            "loss": "bounded best-effort exporter admission and queue; host refusals call exporter shed; inspect exporter status for loss, absence is not zero loss or complete coverage",
            "privacy": "added timing fields contain generated identity, destination index, fixed outcomes and timings only; no body, headers, prompt, credential or provider error text; other span attributes retain the existing exporter policy",
            "metrics": "existing producer_drive and response_ready cumulative distributions are unchanged"
        },
        "streams": projection::PRODUCED_STREAMS.iter().map(|stream| {
            let produced = projection::produced_fields(*stream);
            serde_json::json!({
                "name": stream.as_token(),
                "default_fields": if *stream == ExportStream::Traces {
                    stream.default_fields()
                } else { produced }.iter().map(|field| field.as_token()).collect::<Vec<_>>(),
                "produced_fields": produced.iter().map(|field| field.as_token()).collect::<Vec<_>>(),
                "pinned_fields": stream.pinned_fields().iter().map(|field| field.as_token()).collect::<Vec<_>>(),
                "fields_override": !stream.default_fields().is_empty()
                    && stream.pinned_fields().iter().all(|field| produced.contains(field))
            })
        }).collect::<Vec<_>>()
    })
}

/// Exercise the owning projection resolver without loading an exporter in focused schema tests.
#[cfg(all(feature = "openapi-schema", any(test, feature = "test-support")))]
#[doc(hidden)]
pub fn validate_configuration_projection(
    def: &crate::config::ExportDefCfg,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    projection::resolve_projection(
        "schema-test",
        &def.module,
        None,
        def.streams.as_deref(),
        def.fields.as_deref(),
        def.durable,
        &mut errors,
    );
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

pub(crate) fn route_decls(cfg: &ExportCfg) -> Vec<RouteDecl> {
    plugin::route_decls(cfg)
}

pub(crate) fn route_projection(
    cfg: &ExportCfg,
) -> (Vec<RouteDecl>, std::collections::HashSet<String>) {
    plugin::route_projection(cfg)
}

pub(crate) struct RequestLogFacts<'a> {
    pub(crate) ts: u64,
    pub(crate) ingress_protocol: &'a str,
    pub(crate) pool: &'a str,
    pub(crate) outcome: &'a str,
    pub(crate) latency_ms: u64,
}

pub(crate) fn build_request_log(projection: projection::Projection, f: &RequestLogFacts) -> Value {
    let mut rec = ProjectedRecord::new(projection, ExportStream::Logs);
    rec.set(ExportField::Ts, f.ts)
        .set(ExportField::IngressProtocol, f.ingress_protocol)
        .set(ExportField::Pool, f.pool)
        .set(ExportField::Outcome, f.outcome)
        .set(ExportField::LatencyMs, f.latency_ms);
    rec.finish()
}

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

    pub(crate) fn get(&mut self, projection: projection::Projection) -> Arc<Value> {
        if let Some((_, v)) = self.built.iter().find(|(p, _)| *p == projection) {
            return v.clone();
        }
        let v = Arc::new(build_request_log(projection, self.facts));
        self.built.push((projection, v.clone()));
        v
    }
}

pub(crate) fn deliver_request_log(facts: &RequestLogFacts<'_>) {
    let mut cache = PayloadCache::new(facts);
    plugin::deliver_logs(&mut cache);
}
