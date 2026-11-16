// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::any::Any;
use std::sync::Arc;

use busbar_contract::plugin_rows::{PluginRows, Row, Skipped};

use crate::cold::rows::{archive_sha256, linked_rows, loadable_rows, row, skipped, skipped_rows};
use crate::PluginRegistry;

impl PluginRows for PluginRegistry {
    fn resolve(&self, name_or_alias: &str) -> Option<Row> {
        PluginRegistry::resolve(self, name_or_alias).map(row)
    }

    fn archive_sha256(&self, name_or_alias: &str) -> Option<String> {
        PluginRegistry::resolve(self, name_or_alias).and_then(archive_sha256)
    }

    fn verification(
        &self,
        name_or_alias: &str,
    ) -> Option<busbar_contract::plugin_rows::Verification> {
        PluginRegistry::resolve(self, name_or_alias).map(|image| image.verification.clone())
    }

    fn unresolved_reason(&self, name_or_alias: &str) -> Option<Skipped> {
        PluginRegistry::unresolved_reason(self, name_or_alias).map(skipped)
    }

    fn loadable(&self) -> Vec<Row> {
        loadable_rows(self)
    }

    fn linked(&self) -> Vec<Row> {
        linked_rows(self)
    }

    fn skipped(&self) -> Vec<Skipped> {
        skipped_rows(self)
    }

    fn store_door(
        &self,
        name_or_alias: &str,
    ) -> Result<busbar_contract::persistence::axis::StoreDoor, String> {
        PluginRegistry::store_door(self, name_or_alias)
    }

    fn secret_refusal(&self, name_or_alias: &str) -> String {
        PluginRegistry::secret_refusal(self, name_or_alias)
    }

    fn kind_refusal(&self, kind: &str, purpose: &str, name_or_alias: &str) -> String {
        PluginRegistry::kind_refusal(self, kind, purpose, name_or_alias)
    }

    fn secret_slots(&self, name_or_alias: &str) -> Vec<String> {
        PluginRegistry::resolve(self, name_or_alias)
            .and_then(crate::registry::LoadablePlugin::statement)
            .and_then(|bytes| busbar_contract::abi::mechanism::rendering::read(&bytes).ok())
            .map(|stated| stated.secret_refs)
            .unwrap_or_default()
    }

    fn reference_slots(&self, name_or_alias: &str) -> Vec<String> {
        PluginRegistry::resolve(self, name_or_alias)
            .and_then(crate::registry::LoadablePlugin::statement)
            .and_then(|bytes| busbar_contract::abi::mechanism::rendering::read(&bytes).ok())
            .and_then(|stated| stated.reference_fields().ok())
            .unwrap_or_default()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

#[must_use]
pub fn registry_of(rows: &dyn PluginRows) -> Option<&PluginRegistry> {
    rows.as_any().downcast_ref::<PluginRegistry>()
}

#[must_use]
pub fn registry_arc(rows: Arc<dyn PluginRows>) -> Option<Arc<PluginRegistry>> {
    rows.into_any().downcast::<PluginRegistry>().ok()
}

#[cfg(test)]
#[path = "tests/rows_tests.rs"]
mod tests;
