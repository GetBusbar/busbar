// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::observe`: the names and series a first-party instance takes when it loads,
//! the refusals of a series grant, and the shed-series listing an export reports under.

use std::sync::Arc;

use busbar_contract::abi::mechanism::observe::SeriesDecl;

/// An instance's envelope observer keeps its plugin name, shared by every observation.
#[cold]
pub(crate) fn shared_name(plugin: &str) -> Arc<str> {
    Arc::from(plugin)
}

/// A plugin declares a series the host itself emits.
#[cold]
pub(crate) fn host_series_refused(plugin: &str, series: &str) -> String {
    format!("plugin '{plugin}' declares the series '{series}', which the host itself emits")
}

/// A plugin declares a series already granted to another.
#[cold]
pub(crate) fn series_taken_refused(plugin: &str, series: &str, owner: &str) -> String {
    format!("plugin '{plugin}' declares the series '{series}', already granted to plugin '{owner}'")
}

/// The plugin name a first-party instance's grant is filed and held under, taken once at load.
#[cold]
pub(crate) fn granted_name(plugin: &str) -> String {
    plugin.to_owned()
}

/// The series a first-party instance's grant holds, taken once at load.
#[cold]
pub(crate) fn granted_series(declared: &[SeriesDecl]) -> Vec<SeriesDecl> {
    declared.to_vec()
}

/// The shed counter series a plugin was granted: the names an export that shed lines reports them
/// under.
#[cold]
pub(crate) fn shed_series(plugin: &str) -> Vec<String> {
    crate::observe::with_granted_series(plugin, |series| {
        series
            .iter()
            .filter(|d| d.shed && d.kind == "counter")
            .map(|d| d.name.clone())
            .collect()
    })
}
