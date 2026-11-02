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
pub fn read_test_snapshot(scope: u32) -> busbar_contract::services::Snapshot {
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

pub(crate) fn route_decls(cfg: &ExportCfg) -> Vec<RouteDecl> {
    plugin::route_decls(cfg)
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
