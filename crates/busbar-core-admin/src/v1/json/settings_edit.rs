// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit edits to an opaque settings bag. Omission preserves a setting, including secrets;
//! removal is deliberate, and JSON null remains a value rather than a deletion sentinel.

use crate::v1::contract::AdminError;

#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(crate) struct SettingsEdit {
    /// Replace the named top-level settings with these complete values. Other settings survive.
    #[serde(default)]
    #[cfg_attr(
        feature = "openapi-schema",
        schemars(with = "serde_json::Map<String, serde_json::Value>")
    )]
    pub(crate) set: busbar_contract::plugin_settings::Settings,
    /// Remove these top-level settings. Missing names are harmless; set/remove overlap is invalid.
    #[serde(default)]
    pub(crate) remove: Vec<String>,
}

impl SettingsEdit {
    pub(crate) fn validate(&self) -> Result<(), AdminError> {
        if self
            .remove
            .iter()
            .any(|key| self.set.key_names().contains(key))
        {
            return Err(AdminError::Validation(
                "a settings edit cannot both set and remove the same key".into(),
            ));
        }
        crate::v1::service::validate_hook_settings_size(&self.set)
    }

    pub(crate) fn apply(
        &self,
        existing: busbar_contract::plugin_settings::Settings,
    ) -> Result<busbar_contract::plugin_settings::Settings, AdminError> {
        self.validate()?;
        let existing = existing
            .edit(&self.set, &self.remove)
            .map_err(AdminError::Validation)?;
        crate::v1::service::validate_hook_settings_size(&existing)?;
        Ok(existing)
    }
}
