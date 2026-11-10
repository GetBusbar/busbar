// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admission of configuration fields owned by the export kind.

use crate::plugin_settings::{Resolution, ResolvedSettings, Settings};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An export opening's opaque owner settings and normalized kind-owned delivery bound.
/// The original object is retained unchanged for document roundtrip and plugin delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOpening {
    settings: Settings,
    max_inflight: u32,
}

/// Prepared exporter input: sealed owner settings plus already admitted kind metadata.
#[derive(Debug, Clone)]
pub struct PreparedExport {
    settings: ResolvedSettings,
    max_inflight: u32,
}
impl PreparedExport {
    /// Opaque settings for the final ABI encoding.
    pub fn settings(&self) -> &ResolvedSettings {
        &self.settings
    }
    /// The host delivery bound admitted before resolving owner settings.
    pub fn max_inflight(&self) -> u32 {
        self.max_inflight
    }
}

impl ExportOpening {
    /// Admit the export kind's common host field. Owner-specific settings stay opaque.
    pub fn new(settings: Settings) -> Self {
        let max_inflight = settings
            .0
             .0
            .get(super::INFLIGHT_KEY)
            .and_then(serde_json::Value::as_u64)
            .map_or(super::DEFAULT_INFLIGHT, |value| {
                u32::try_from(value).unwrap_or(u32::MAX).max(1)
            });
        Self {
            settings,
            max_inflight,
        }
    }

    /// The host delivery bound, preserving the export kind's established normalization.
    pub fn max_inflight(&self) -> u32 {
        self.max_inflight
    }

    /// The original owner settings, still opaque.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Pair resolved settings with the original kind admission.
    pub fn with_settings(&self, settings: ResolvedSettings) -> PreparedExport {
        PreparedExport {
            settings,
            max_inflight: self.max_inflight,
        }
    }

    /// Prepare written settings for owner validation/opening when no references need resolution.
    pub fn prepare(&self) -> PreparedExport {
        self.with_settings(self.settings.prepare())
    }

    /// Resolve admitted references under the export kind's existing inline-value policy.
    pub fn resolve(
        &self,
        rules: &Resolution<'_>,
        resolver: &dyn crate::secret::SecretResolve,
        scope: &crate::config_time::ConfigScope,
    ) -> Result<ResolvedSettings, String> {
        self.settings
            .resolve_with_literals(rules, resolver, scope, true)
    }
}
impl Default for ExportOpening {
    fn default() -> Self {
        Self::new(Settings::default())
    }
}
impl Serialize for ExportOpening {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.settings.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for ExportOpening {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Settings::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kind_delivery_admission_preserves_normalization_and_wire() {
        for (value, expected) in [
            (serde_json::json!({}), 64),
            (serde_json::json!({"max_inflight_deliveries":null}), 64),
            (serde_json::json!({"max_inflight_deliveries":"9"}), 64),
            (serde_json::json!({"max_inflight_deliveries":[]}), 64),
            (serde_json::json!({"max_inflight_deliveries":true}), 64),
            (serde_json::json!({"max_inflight_deliveries":-1}), 64),
            (serde_json::json!({"max_inflight_deliveries":1.5}), 64),
            (serde_json::json!({"max_inflight_deliveries":0}), 1),
            (serde_json::json!({"max_inflight_deliveries":9}), 9),
            (
                serde_json::json!({"max_inflight_deliveries":u64::MAX}),
                u32::MAX,
            ),
        ] {
            let opening: ExportOpening = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(opening.max_inflight(), expected);
            assert_eq!(serde_json::to_value(&opening).unwrap(), value);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&opening.settings.encode().unwrap().0)
                    .unwrap(),
                value
            );
        }
        assert!(serde_json::from_str::<ExportOpening>("{broken").is_err());
    }
}
