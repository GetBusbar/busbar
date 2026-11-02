// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::export_calls::{ExportAxis, ExportCalls, Probed};
use std::sync::Arc;

use crate::root::loader::export_axis::ExportRows;

/// The root's export axis.
#[derive(Debug)]
pub struct RootExports;

pub static EXPORTS: RootExports = RootExports;

fn rows() -> Option<ExportRows<'static>> {
    let registry = crate::root::linked::dropped()?;
    Some(ExportRows::new(
        registry,
        crate::root::dispatch::dispatcher(),
    ))
}

impl ExportAxis for RootExports {
    fn probe(&self, module: &str, instance: &str, settings: &serde_json::Value) -> Option<Probed> {
        rows()?.probe(module, instance, settings)
    }

    fn check(
        &self,
        module: &str,
        phase: u32,
        instances: &[(String, &serde_json::Value)],
    ) -> Option<Vec<String>> {
        rows()?.check(module, phase, instances)
    }

    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn ExportCalls>, String> {
        let rows =
            rows().ok_or_else(|| format!("no `kind: export` plugin answers to '{module}'"))?;
        let conns: Arc<dyn busbar_contract::conn::DeclaredConns> =
            crate::root::connector::the().clone();
        rows.with_logs(crate::root::linked::logs())
            .with_conns(conns)
            .open(module, label, settings)
    }

    fn linked(&self, module: &str) -> bool {
        rows().is_some_and(|r| r.linked(module))
    }

    fn first_party(&self, module: &str) -> bool {
        rows().is_some_and(|r| r.first_party(module))
    }

    fn one_instance(&self, module: &str) -> bool {
        rows().is_some_and(|r| r.one_instance(module))
    }

    fn linked_modules(&self) -> Vec<String> {
        rows().map(|r| r.linked_modules()).unwrap_or_default()
    }

    fn routes(&self, module: &str) -> Vec<busbar_contract::abi::mechanism::route::Route> {
        rows().map(|r| r.routes(module)).unwrap_or_default()
    }

    fn public_routes(&self, module: &str) -> Vec<String> {
        rows().map(|r| r.public_routes(module)).unwrap_or_default()
    }

    fn persistent_routes(&self, module: &str) -> Vec<String> {
        rows()
            .map(|r| r.persistent_routes(module))
            .unwrap_or_default()
    }

    fn secret_refs(&self, module: &str) -> Vec<String> {
        use busbar_contract::plugin_rows::PluginRows;
        crate::root::linked::dropped()
            .map(|registry| registry.secret_slots(module))
            .unwrap_or_default()
    }

    fn reference_fields(&self, module: &str) -> Vec<String> {
        use busbar_contract::plugin_rows::PluginRows;
        crate::root::linked::dropped()
            .map(|registry| registry.reference_slots(module))
            .unwrap_or_default()
    }
}
