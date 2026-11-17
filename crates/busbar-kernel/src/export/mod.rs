// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub mod delivery;
pub mod plugin;
pub(crate) mod projection;
pub(crate) mod scrape;
pub use scrape::{
    app_families, app_families_budgeted, hook_families, hook_families_budgeted,
    BudgetedScrapeRefusal, ScrapeRefusal,
};
pub mod traces;

use crate::export::projection::{ProjectedRecord, Rendered};
use busbar_contract::abi::export::ExportField;
use busbar_contract::export_stream::ExportStream;
#[cfg(any(test, feature = "test-support"))]
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

/// Host-owned user configuration capabilities (the admin configuration schema), built off the
/// request path.
#[cfg(feature = "openapi-schema")]
pub use crate::off_path::export::configuration_capabilities;

/// Exercise the owning projection resolver without loading an exporter in focused schema tests.
#[cfg(all(feature = "openapi-schema", any(test, feature = "test-support")))]
#[doc(hidden)]
pub use crate::off_path::export::validate_configuration_projection;

/// The export route table, built once per configuration generation.
pub(crate) use crate::off_path::export::{route_decls, route_projection};

pub(crate) struct RequestLogFacts<'a> {
    /// The unit's node-qualified id (the reply's `X-Request-Id`); `None` where no unit was minted.
    pub(crate) correlation_id: Option<&'a str>,
    pub(crate) ts: u64,
    pub(crate) ingress_protocol: &'a str,
    pub(crate) pool: &'a str,
    pub(crate) outcome: &'a str,
    pub(crate) latency_ms: u64,
}

/// The request-log record for one sink, written straight to its projection.
pub(crate) fn build_request_log(
    projection: projection::Projection,
    f: &RequestLogFacts,
) -> Rendered {
    let mut rec = ProjectedRecord::new(projection, ExportStream::Logs);
    if let Some(id) = f.correlation_id {
        rec.set(ExportField::CorrelationId, id);
    }
    rec.set(ExportField::Ts, f.ts)
        .set(ExportField::IngressProtocol, f.ingress_protocol)
        .set(ExportField::Pool, f.pool)
        .set(ExportField::Outcome, f.outcome)
        .set(ExportField::LatencyMs, f.latency_ms);
    rec.finish()
}

pub(crate) fn deliver_request_log(exports: &plugin::Exports, facts: &RequestLogFacts<'_>) {
    plugin::deliver_on(
        exports,
        ExportStream::Logs,
        facts.ingress_protocol,
        |projection| build_request_log(projection, facts),
    );
}

#[cfg(test)]
#[path = "tests/snapshot_crossings.rs"]
mod snapshot_crossings;
