// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::plugin_rows::{PluginRows, Trust};
use busbar_kernel::persistence::plugin_floor::Candidate;
pub use busbar_kernel::persistence::plugin_floor::{AdmissionProof, PluginFloor};
#[cfg(test)]
pub use busbar_kernel::persistence::plugin_floor::{
    PLUGIN_FLOOR_SCHEMA, RELEASE_KEYS_FLOOR_SCHEMA,
};
use std::collections::BTreeMap;

#[cfg(test)]
pub async fn release_keys_floor(owner: &PluginFloor, host: &str) -> Result<u64, String> {
    owner.release_keys_floor(host).await
}
#[cfg(test)]
pub async fn check(
    owner: &PluginFloor,
    host: &str,
    rows: &dyn PluginRows,
    pins: &BTreeMap<String, String>,
) -> Result<(), String> {
    enforce(owner, host, rows, pins, false).await
}
pub async fn hold(
    owner: &PluginFloor,
    host: &str,
    rows: &dyn PluginRows,
    pins: &BTreeMap<String, String>,
) -> Result<(), String> {
    enforce(owner, host, rows, pins, true).await
}
fn candidate<'a>(
    row: &'a busbar_contract::plugin_rows::Row,
    pins: &BTreeMap<String, String>,
) -> Candidate<'a> {
    Candidate {
        name: &row.name,
        version: &row.version,
        file: &row.file,
        first_party: matches!(
            row.trust,
            Trust::Trusted {
                first_party: true,
                ..
            }
        ),
        linked: row.linked,
        rollback_pinned: pins.get(&row.name) == Some(&row.version),
    }
}
async fn enforce(
    owner: &PluginFloor,
    host: &str,
    rows: &dyn PluginRows,
    pins: &BTreeMap<String, String>,
    raise: bool,
) -> Result<(), String> {
    let registry = crate::root::loader::rows::registry_of(rows);
    let versions: Vec<_> = rows
        .loadable()
        .iter()
        .filter_map(|row| registry?.resolve(&row.name)?.release_keys_version())
        .collect();
    owner.enforce_release_keys(host, &versions, false).await?;
    for row in rows.loadable() {
        owner
            .enforce_candidate(host, candidate(&row, pins), raise)
            .await?;
    }
    owner.enforce_release_keys(host, &versions, raise).await
}
#[cfg(test)]
pub async fn check_candidate(
    owner: &PluginFloor,
    host: &str,
    row: &busbar_contract::plugin_rows::Row,
    release_keys_version: Option<u64>,
    pins: &BTreeMap<String, String>,
) -> Result<(), String> {
    if let Some(version) = release_keys_version {
        owner.enforce_release_keys(host, &[version], false).await?;
    }
    owner
        .enforce_candidate(host, candidate(row, pins), false)
        .await
}

pub async fn prepare_candidate(
    owner: &PluginFloor,
    host: &str,
    row: &busbar_contract::plugin_rows::Row,
    release_keys_version: Option<u64>,
    pins: &BTreeMap<String, String>,
    archive_sha256: &str,
) -> Result<AdmissionProof, String> {
    owner
        .prepare_admission(
            host,
            candidate(row, pins),
            release_keys_version,
            archive_sha256,
        )
        .await
}

pub fn check_prepared_candidate(
    proof: &AdmissionProof,
    host: &str,
    row: &busbar_contract::plugin_rows::Row,
    release_keys_version: Option<u64>,
    pins: &BTreeMap<String, String>,
    archive_sha256: &str,
) -> Result<(), String> {
    proof.check(
        host,
        candidate(row, pins),
        release_keys_version,
        archive_sha256,
    )
}

#[cfg(test)]
#[path = "../tests/plugin_floor.rs"]
mod tests;
