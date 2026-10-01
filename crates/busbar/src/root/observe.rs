// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN OBSERVABILITY ENVELOPE, COMPOSED (DECISIONS #85): the loader hands every plugin
//! response's metrics and diagnostics to an observer, and the kernel's observer decides what a
//! plugin is allowed to have said. The composition root joins the two, so neither names the other:
//! the loader's observer calls the kernel's fold, and the kernel's fold asks the loader's grants
//! (first-party, granted series), handed in on every call: the kernel holds no installed seam.
//!
//! Installed once, before the first plugin loads: a plugin's own constructor is exactly where it
//! has something worth reporting. Unconditional: the `metrics` facade is a no-op without a
//! recorder, and the diagnostics half has to work whether or not an exporter is configured.

use busbar_kernel::metrics::observe::{Grants, KernelPluginObserver};

use crate::root::loader::observe::{first_party, first_party_series, PluginObserver};

/// The loader's observer: every plugin response's back-channel, into the kernel's fold.
struct Observer;

impl PluginObserver for Observer {
    fn observe(
        &self,
        plugin: &str,
        kind: &str,
        metrics: &[serde_json::Value],
        diagnostics: &[serde_json::Value],
    ) {
        KernelPluginObserver.observe(&LoaderGrants, plugin, kind, metrics, diagnostics);
    }
}

/// The loader's grants, as the kernel's observer asks them.
struct LoaderGrants;

impl Grants for LoaderGrants {
    fn first_party(&self, plugin: &str) -> bool {
        first_party(plugin)
    }
    fn first_party_series(&self, plugin: &str, name: &str, kind: &str) -> bool {
        first_party_series(plugin, name, kind)
    }
}

/// Join the loader's observer to the kernel's fold. The first install wins; a second boot inside
/// one test binary installs nothing, which is not an error.
pub fn install() {
    let _ = crate::root::loader::observe::install_plugin_observer(&Observer);
}
