// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Config grammar evidence is independent of native Store format or product version.
use serde_yaml::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoricalShape {
    RootGrammar,
    PluginSettings,
}

/// Minted only by a recognized historical grammar or a registered settings conversion.
#[derive(Clone, Debug)]
pub struct HistoricalConfigProof {
    shape: HistoricalShape,
    binding: [u8; 32],
}
impl HistoricalConfigProof {
    pub fn shape(&self) -> HistoricalShape {
        self.shape
    }
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
    pub(super) fn settings(site: &str, settings: &serde_json::Value) -> Result<Self, String> {
        let bytes = zeroize::Zeroizing::new(
            serde_json::to_vec(settings).map_err(|_| "settings evidence could not be encoded")?,
        );
        let mut hash = Sha256::new();
        hash.update(b"busbar.config.settings-shape.1\0");
        hash.update(site.as_bytes());
        hash.update(bytes.as_slice());
        Ok(Self {
            shape: HistoricalShape::PluginSettings,
            binding: hash.finalize().into(),
        })
    }
}

/// These are actual retired grammar forms, rather than a failed current parse or empty DB.
pub fn recognize_authored_schema(raw: &str) -> Result<Option<HistoricalConfigProof>, String> {
    let doc: Value = serde_yaml::from_str(raw).map_err(|_| "configuration is not valid YAML")?;
    let Some(root) = doc.as_mapping() else {
        return Ok(None);
    };
    let legacy_root = root.get("governance").is_some_and(Value::is_mapping)
        || root.get("group_map").is_some_and(Value::is_mapping)
        || root
            .get("auth")
            .and_then(|auth| auth.get("mode"))
            .and_then(Value::as_str)
            .is_some_and(|mode| matches!(mode, "none" | "token" | "apikey" | "passthrough"))
        || root
            .get("auth")
            .and_then(|auth| auth.get("client_tokens"))
            .is_some()
        || root
            .get("config")
            .and_then(|config| config.get("overlay"))
            .is_some();
    if !legacy_root {
        return Ok(None);
    }
    let mut hash = Sha256::new();
    hash.update(b"busbar.config.root-grammar.1\0");
    hash.update(raw.as_bytes());
    Ok(Some(HistoricalConfigProof {
        shape: HistoricalShape::RootGrammar,
        binding: hash.finalize().into(),
    }))
}

/// A Store-only non-serving projection. Entries removed here cannot name any destination
/// under the historical matcher, so this creates no egress exception or authorization.
/// The full authored lists must remain intact for final source-aware validation.
pub fn bootstrap_metadata_projection(entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .filter(|entry| {
            busbar_kernel::config_validate::metadata_entry_names_no_host(entry).is_none()
        })
        .cloned()
        .collect()
}
