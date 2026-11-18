// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::observe`: the names and series a first-party instance takes when it loads,
//! the refusals of a series grant, and the shed-series listing an export reports under.

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
