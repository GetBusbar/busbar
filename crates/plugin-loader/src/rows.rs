// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REGISTRY AS THE KERNEL READS IT: [`PluginRegistry`] answers the contract's
//! [`PluginRows`], so the composition root hands the kernel its registry without the kernel naming
//! this crate (`BUSBAR-1.6.0.md` THE DESIGN, "One dispatcher"). The root's per-kind axes get their
//! registry back through [`registry_of`] / [`registry_arc`].

use std::any::Any;
use std::sync::Arc;

use busbar_contract::plugin_rows::{PluginRows, Row, Skipped, Trust};

use crate::registry::{LoadablePlugin, SkippedPlugin};
use crate::sign::Verdict;
use crate::PluginRegistry;

/// A row as the kernel reads it.
fn row(p: &LoadablePlugin) -> Row {
    let m = &p.manifest;
    Row {
        file: p.file.clone(),
        name: m.name.clone(),
        alias: m.alias.clone(),
        kind: m.kind.clone(),
        version: m.version.clone(),
        abi_version: m.abi_version,
        trust: match &p.verdict {
            Verdict::Trusted {
                publisher,
                first_party,
            } => Trust::Trusted {
                publisher: publisher.clone(),
                first_party: *first_party,
            },
            Verdict::Allowed { reason, .. } => Trust::Allowed {
                reason: reason.clone(),
            },
        },
        ephemeral: p.ephemeral,
        in_process: p.in_process(),
        linked: p.linked(),
        needs_prompt: m.needs.prompt,
        needs_user: m.needs.user,
        settings_schema: m.settings_schema.clone(),
    }
}

/// A skipped plugin as the kernel reads it.
fn skipped(s: &SkippedPlugin) -> Skipped {
    Skipped {
        file: s.file.clone(),
        name: s.manifest.name.clone(),
        alias: s.manifest.alias.clone(),
        reason: s.reason.clone(),
    }
}

impl PluginRows for PluginRegistry {
    fn resolve(&self, name_or_alias: &str) -> Option<Row> {
        PluginRegistry::resolve(self, name_or_alias).map(row)
    }

    fn unresolved_reason(&self, name_or_alias: &str) -> Option<Skipped> {
        PluginRegistry::unresolved_reason(self, name_or_alias).map(skipped)
    }

    fn loadable(&self) -> Vec<Row> {
        PluginRegistry::loadable(self).iter().map(row).collect()
    }

    fn linked(&self) -> Vec<Row> {
        PluginRegistry::linked(self).iter().map(row).collect()
    }

    fn skipped(&self) -> Vec<Skipped> {
        PluginRegistry::skipped(self).iter().map(skipped).collect()
    }

    fn store_door(
        &self,
        name_or_alias: &str,
    ) -> Result<busbar_contract::store_calls::StoreDoor, String> {
        PluginRegistry::store_door(self, name_or_alias)
    }

    fn secret_refusal(&self, name_or_alias: &str) -> String {
        PluginRegistry::secret_refusal(self, name_or_alias)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

/// The registry behind `rows`, when this crate built it (every build's rows are).
#[must_use]
pub fn registry_of(rows: &dyn PluginRows) -> Option<&PluginRegistry> {
    rows.as_any().downcast_ref::<PluginRegistry>()
}

/// [`registry_of`], owned.
#[must_use]
pub fn registry_arc(rows: Arc<dyn PluginRows>) -> Option<Arc<PluginRegistry>> {
    rows.into_any().downcast::<PluginRegistry>().ok()
}

#[cfg(test)]
#[path = "tests/rows_tests.rs"]
mod tests;
