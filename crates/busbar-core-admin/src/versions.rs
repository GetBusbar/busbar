// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::Serialize;

/// One recorded config version: the metadata the versions LIST shows, plus the full hook-surface
/// snapshot rollback restores. Never contains a secret (hook definitions are operator config:
/// transports, grants, deadlines).
#[derive(Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct ConfigVersion {
    /// The `App.config_version` this snapshot corresponds to (monotonic per process).
    pub version: u64,
    /// Unix seconds when the mutation committed.
    pub ts: u64,
    /// The acting principal (audit attribution, same handle as the audit log).
    pub principal: String,
    /// Human summary of the mutation that produced this version (e.g. `hook.register hook:x`).
    pub summary: String,
    /// The hook registry at this version (the rollback payload), as the serialized snapshot
    /// (`serde_json` object keyed by hook name), so this store names no kernel config type.
    #[serde(skip)]
    pub hook_registry: serde_json::Value,
    /// The global wiring at this version.
    #[serde(skip)]
    pub global_hooks: Vec<String>,
}

const MAX_VERSIONS: usize = 100;

#[derive(Default)]
pub struct VersionLog {
    entries: std::sync::Mutex<std::collections::VecDeque<ConfigVersion>>,
}

impl VersionLog {
    pub fn record(
        &self,
        version: u64,
        principal: &str,
        summary: &str,
        hook_registry: serde_json::Value,
        global_hooks: &[String],
    ) {
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());

        q.retain(|v| v.version != version);
        while q.len() >= MAX_VERSIONS {
            q.pop_front();
        }
        q.push_back(ConfigVersion {
            version,
            ts: busbar_kernel::store::now(),
            principal: principal.to_string(),
            summary: summary.to_string(),
            hook_registry,
            global_hooks: global_hooks.to_vec(),
        });
    }

    pub fn list(&self, offset: usize, limit: usize) -> Vec<ConfigVersion> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().rev().skip(offset).take(limit).cloned().collect()
    }

    pub fn get(&self, version: u64) -> Option<ConfigVersion> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().find(|v| v.version == version).cloned()
    }
}

#[cfg(test)]
#[path = "tests/versions_tests.rs"]
mod tests;
