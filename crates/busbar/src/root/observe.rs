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

use busbar_kernel::snapshot::observe::{Grants, KernelPluginObserver};

use busbar_kernel::audit::auditlog::{record_plugin_refusal, PluginRefusal};

use crate::root::loader::observe::{first_party, first_party_series, BindRefusal, PluginObserver};

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

    fn dropped(&self, observations: u64) {
        KernelPluginObserver.dropped(observations);
    }

    /// A refusal made while a plugin bound, onto the kernel's audit chain (BIND-AUDIT).
    fn refused(&self, kind: &str, instance: &str, refusal: BindRefusal<'_>) {
        match refusal {
            BindRefusal::Need { need, reason } => record_plugin_refusal(
                PluginRefusal::Need,
                kind,
                instance,
                &format!("need.{need}.{reason}"),
            ),
            BindRefusal::Open { code } => {
                record_plugin_refusal(PluginRefusal::Open, kind, instance, code);
            }
        }
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

/// Join the loader's observer to the kernel's fold, on the process's one dispatcher (every door
/// binds on it, so every door's envelope folds through it). The first install wins; a second boot
/// inside one test binary installs nothing, which is not an error.
pub fn install() {
    let _ = crate::root::dispatch::dispatcher()
        .observing()
        .install_observer(&Observer);
}
