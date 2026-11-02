// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;

use busbar_contract::abi::sdk::store::conditional::{Decision, Expected, Mutation, Predicate};
use busbar_contract::plugin_rows::{PluginRows, Trust};
use busbar_contract::store_calls::StoreCalls;

use super::store_chain::wait_for;
use crate::root::loader::sign::{valid_semver, version_at_least};

pub const PLUGIN_FLOOR_SCHEMA: &str = "busbar.plugin_floor.v1";

pub const RELEASE_KEYS_FLOOR_SCHEMA: &str = "busbar.release_keys_floor.v1";

fn release_keys_key(host: &str) -> Vec<u8> {
    floor_key(host, "busbar-release-keys")
}

pub fn release_keys_floor(calls: &dyn StoreCalls, host: &str) -> Result<u64, String> {
    let held = wait_for(calls.record_get(RELEASE_KEYS_FLOOR_SCHEMA, &release_keys_key(host)))
        .map_err(|e| format!("the release keys-document floor: {e}"))?;
    decode_release_keys_floor(held.as_ref().map(|bytes| bytes.as_slice()))
}

fn decode_release_keys_floor(held: Option<&[u8]>) -> Result<u64, String> {
    held.map_or(Ok(0), |bytes| {
        let bytes: [u8; 8] = bytes
            .try_into()
            .map_err(|_| "the release keys-document floor is malformed".to_string())?;
        Ok(u64::from_be_bytes(bytes))
    })
}

fn enforce_release_keys(
    calls: &dyn StoreCalls,
    host: &str,
    versions: &[u64],
    raise: bool,
) -> Result<(), String> {
    let Some(&lowest) = versions.iter().min() else {
        return Ok(());
    };
    let highest = versions.iter().copied().max().unwrap_or(lowest);
    let key = release_keys_key(host);
    loop {
        let held = wait_for(calls.record_get(RELEASE_KEYS_FLOOR_SCHEMA, &key))
            .map_err(|e| format!("the release keys-document floor: {e}"))?;
        let floor = decode_release_keys_floor(held.as_ref().map(|bytes| bytes.as_slice()))?;
        if lowest < floor {
            return Err(format!(
                "keys-rollback: release keys-document version {lowest} is below {floor}, the \
                 highest this host has accepted; no plugin rollback pin or trust opt-in lowers \
                 this floor"
            ));
        }
        if !raise || highest <= floor {
            return Ok(());
        }
        let request = super::conditional::candidate(
            vec![Predicate {
                schema: RELEASE_KEYS_FLOOR_SCHEMA.into(),
                key: key.clone(),
                expected: held.map_or(Expected::Absent, |v| Expected::Bytes(v.as_slice().to_vec())),
            }],
            vec![Mutation::Put {
                schema: RELEASE_KEYS_FLOOR_SCHEMA.into(),
                key: key.clone(),
                value: highest.to_be_bytes().to_vec(),
            }],
        );
        match super::conditional::decide(calls, &request)? {
            Decision::Applied => return Ok(()),
            Decision::ConditionConflict => continue,
        }
    }
}

fn floor_key(host: &str, name: &str) -> Vec<u8> {
    let mut key = Vec::new();
    for part in [host, name] {
        key.extend_from_slice(&(part.len() as u32).to_be_bytes());
        key.extend_from_slice(part.as_bytes());
    }
    key
}

pub fn check(
    calls: &dyn StoreCalls,
    host: &str,
    rows: &dyn PluginRows,
    pins: &BTreeMap<String, String>,
) -> Result<(), String> {
    enforce(calls, host, rows, pins, false)
}

pub fn hold(
    calls: &dyn StoreCalls,
    host: &str,
    rows: &dyn PluginRows,
    pins: &BTreeMap<String, String>,
) -> Result<(), String> {
    enforce(calls, host, rows, pins, true)
}

fn enforce(
    calls: &dyn StoreCalls,
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
    enforce_release_keys(calls, host, &versions, false)?;
    for row in rows.loadable() {
        enforce_candidate(calls, host, &row, pins, raise)?;
    }
    enforce_release_keys(calls, host, &versions, raise)?;
    Ok(())
}

pub fn check_candidate(
    calls: &dyn StoreCalls,
    host: &str,
    row: &busbar_contract::plugin_rows::Row,
    release_keys_version: Option<u64>,
    pins: &BTreeMap<String, String>,
) -> Result<(), String> {
    if let Some(version) = release_keys_version {
        enforce_release_keys(calls, host, &[version], false)?;
    }
    enforce_candidate(calls, host, row, pins, false)
}

fn enforce_candidate(
    calls: &dyn StoreCalls,
    host: &str,
    row: &busbar_contract::plugin_rows::Row,
    pins: &BTreeMap<String, String>,
    raise: bool,
) -> Result<(), String> {
    let first_party = matches!(
        row.trust,
        Trust::Trusted {
            first_party: true,
            ..
        }
    );
    if !first_party || row.linked || !valid_semver(&row.version) {
        return Ok(());
    }
    let key = floor_key(host, &row.name);
    loop {
        let held = wait_for(calls.record_get(PLUGIN_FLOOR_SCHEMA, &key))
            .map_err(|e| format!("the first-party floor of `{}`: {e}", row.name))?;
        let floor = held
            .as_ref()
            .map(|v| {
                std::str::from_utf8(v.as_slice())
                    .ok()
                    .filter(|v| valid_semver(v))
                    .ok_or_else(|| format!("the first-party floor of `{}` is malformed", row.name))
            })
            .transpose()?;
        if let Some(floor) = floor {
            if pins.get(&row.name) != Some(&row.version) && !version_at_least(&row.version, floor) {
                return Err(format!(
                    "the first-party plugin `{}` {} is below {floor}, the highest version of it this \
                     host has loaded: an old signed release does not load in its place. To roll it \
                     back on purpose, call the audited `POST /api/v1/admin/plugins/rollback` with \
                     `{{\"file\": \"{}\"}}`; it pins `{}` in the overlay's `plugin_versions`",
                    row.name, row.version, row.file, row.name
                ));
            }
            if version_at_least(floor, &row.version) {
                break;
            }
        }
        if !raise {
            break;
        }
        let request = super::conditional::candidate(
            vec![Predicate {
                schema: PLUGIN_FLOOR_SCHEMA.into(),
                key: key.clone(),
                expected: held.map_or(Expected::Absent, |v| Expected::Bytes(v.as_slice().to_vec())),
            }],
            vec![Mutation::Put {
                schema: PLUGIN_FLOOR_SCHEMA.into(),
                key: key.clone(),
                value: row.version.as_bytes().to_vec(),
            }],
        );
        match super::conditional::decide(calls, &request)? {
            Decision::Applied => break,
            Decision::ConditionConflict => continue,
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/plugin_floor.rs"]
mod tests;
