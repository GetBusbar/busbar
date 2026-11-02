// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::snapshot::observe::{Grants, KernelPluginObserver};

use busbar_kernel::audit::auditlog::{record_plugin_refusal, PluginRefusal};

use crate::root::loader::observe::{first_party, first_party_series, BindRefusal, PluginObserver};

struct Observer(KernelPluginObserver);

impl PluginObserver for Observer {
    fn observe(
        &self,
        plugin: &str,
        kind: &str,
        metrics: &[serde_json::Value],
        diagnostics: &[serde_json::Value],
    ) {
        self.0
            .observe(&LoaderGrants, plugin, kind, metrics, diagnostics);
    }

    fn dropped(&self, observations: u64) {
        self.0.dropped(observations);
    }

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
            BindRefusal::Op { code } => {
                record_plugin_refusal(PluginRefusal::Op, kind, instance, code);
            }
        }
    }
}

struct LoaderGrants;

impl Grants for LoaderGrants {
    fn first_party(&self, plugin: &str) -> bool {
        first_party(plugin)
    }
    fn first_party_series(&self, plugin: &str, name: &str, kind: &str) -> bool {
        first_party_series(plugin, name, kind)
    }
}

pub fn install(catalogue: busbar_kernel::diagnostics::Catalogue) {
    let observer: &'static Observer =
        Box::leak(Box::new(Observer(KernelPluginObserver::lent(catalogue))));
    let _ = crate::root::dispatch::dispatcher()
        .observing()
        .install_observer(observer);
}
