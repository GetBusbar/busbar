// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FIRST-PARTY ANTI-DOWNGRADE FLOOR IN THE STORE, per host (`docs/plugins.md` security-model
//! item 3).
//!
//! The plugin scan floors a dropped-in first-party plugin at the highest version of its name this
//! deployment has loaded, from the marks kept beside a data directory
//! (`crate::root::loader::HighWaterMarks`). Without a data directory those marks lived in memory,
//! so a restart forgot them and a genuine but OLD signed release dropped into `plugins.dir` loaded
//! again with no warning. The store opens after the scan, so the floor the store keeps is held here,
//! once the store is open: every loadable dropped-in first-party plugin is checked against the mark
//! the store keeps for its name on this host, and the marks rise to what loaded.
//!
//! Keyed per HOST, so one upgraded node never refuses its siblings' boots during a rolling rollback.
//! An explicit rollback pin (`plugins.trust.first_party_floors`) replaces a name's mark, as it does
//! in the scan. A compiled-in row is the binary's own and is never floored.

use std::collections::BTreeMap;

use busbar_contract::kinds::RecordBytes;
use busbar_contract::plugin_rows::{PluginRows, Trust};
use busbar_contract::store_calls::StoreCalls;

use super::store_chain::wait_for;
use crate::root::loader::sign::{valid_semver, version_at_least};

/// The host record schema the marks are kept under: one record per `(host, plugin name)`.
pub const PLUGIN_FLOOR_SCHEMA: &str = "busbar.plugin_floor.v1";

/// The key of `name`'s mark on `host`: each length-prefixed.
fn floor_key(host: &str, name: &str) -> Vec<u8> {
    let mut key = Vec::new();
    for part in [host, name] {
        key.extend_from_slice(&(part.len() as u32).to_be_bytes());
        key.extend_from_slice(part.as_bytes());
    }
    key
}

/// HOLD THE FLOOR on `host`: refuse a loadable dropped-in first-party plugin below the mark the
/// store keeps for its name (unless `pins` names it), then raise each name's mark to what loaded.
///
/// # Errors
///
/// A plugin below its floor, named with the way past it; or the store would not answer.
pub fn hold(
    calls: &dyn StoreCalls,
    host: &str,
    rows: &dyn PluginRows,
    pins: &BTreeMap<String, String>,
) -> Result<(), String> {
    for row in rows.loadable() {
        let first_party = matches!(
            row.trust,
            Trust::Trusted {
                first_party: true,
                ..
            }
        );
        if !first_party || row.linked || !valid_semver(&row.version) {
            continue;
        }
        let key = floor_key(host, &row.name);
        let held = wait_for(calls.record_get(PLUGIN_FLOOR_SCHEMA, &key))
            .map_err(|e| format!("the first-party floor of `{}`: {e}", row.name))?
            .and_then(|v| String::from_utf8(v.as_slice().to_vec()).ok())
            .filter(|v| valid_semver(v));
        if let Some(floor) = &held {
            if !pins.contains_key(&row.name) && !version_at_least(&row.version, floor) {
                return Err(format!(
                    "the first-party plugin `{}` {} is below {floor}, the highest version of it this \
                     host has loaded: an old signed release does not load in its place. To roll it \
                     back on purpose, pin `plugins.trust.first_party_floors.{}`",
                    row.name, row.version, row.name
                ));
            }
            if version_at_least(floor, &row.version) {
                continue;
            }
        }
        let value = RecordBytes::new(row.version.clone().into_bytes())
            .map_err(|n| format!("a {n}-byte first-party floor of `{}`", row.name))?;
        wait_for(calls.record_put(PLUGIN_FLOOR_SCHEMA, &key, &value))
            .map_err(|e| format!("the first-party floor of `{}`: {e}", row.name))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/plugin_floor.rs"]
mod tests;
