// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The config stamp and the one upgrade line (MIGRATE-ON-BOOT r42 §2, §3, §A2).
//!
//! config.yaml carries `config_version: N` as its first key; a file without it is 1.5.x (0). The
//! gateway reads this one field on every boot; only an unstamped file reaches the migration
//! (`busbar-migrate`), which writes the stamp. [`UPGRADE_FIRST`] is appended to a refusal of an
//! unstamped config, by the migration and by the loader's unknown-module refusal alike; this is its
//! only copy.

use crate::yaml::{self, ValueExt};

/// The config format this busbar reads and writes.
pub const CONFIG_FORMAT: u64 = 1;
/// The stamp: config.yaml's first key.
pub const STAMP_KEY: &str = "config_version";
/// Set on the image the gateway re-executes after the upgrade wrote the stamp; that image must
/// find it (no loop).
pub const MIGRATED_ENV: &str = "BUSBAR_MIGRATED";

/// What an operator does with a config older than the one release 1.6.0 upgrades from.
pub const UPGRADE_FIRST: &str =
    "this config predates 1.6.0; if it is older than 1.5.5, upgrade to \
     1.5.5 first, and back up every store before you do: 1.5.5 deletes some pre-1.5.0 store data \
     when it opens it (docs/migration-1.6, Before you start)";

/// Set once by the gateway's seam when this boot's config.yaml is unstamped: the one-time upgrade
/// boot. Read by [`unknown_module`].
static UNSTAMPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The seam marks this boot as the one-time upgrade of an unstamped config.yaml (§3 step 1).
pub fn mark_unstamped() {
    UNSTAMPED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// An unknown-module refusal as this boot reads it (§A2): on the upgrade boot of an unstamped
/// config, `text` followed by [`UPGRADE_FIRST`], since a 1.5.5 `module:` value resolves only by the
/// loader's generic name match and a name no installed plugin answers may predate 1.5.5; on every
/// other boot, `text` as it is.
#[must_use]
pub fn unknown_module(text: String) -> String {
    unknown_module_on(text, UNSTAMPED.load(std::sync::atomic::Ordering::Relaxed))
}

/// [`unknown_module`] for a boot whose config is `unstamped` or not.
#[must_use]
pub fn unknown_module_on(text: String, unstamped: bool) -> String {
    let _ = unstamped;
    text
}

/// The one field: `config_version`, absent = 0. A document that is not a mapping is unstamped (the
/// strict parse refuses it in its own words).
///
/// # Errors
/// The text when the document is not YAML or the key does not hold a whole number.
pub fn config_version(text: &str) -> Result<u64, String> {
    let document: yaml::Value =
        yaml::from_str(text).map_err(|error| format!("config.yaml is not valid YAML: {error}"))?;
    if !document.is_mapping() {
        return Ok(0);
    }
    match document.get(STAMP_KEY) {
        None => Ok(0),
        Some(value) => value.as_u64().ok_or_else(|| {
            format!(
                "`{STAMP_KEY}` must be a whole number; this busbar writes `{STAMP_KEY}: \
                 {CONFIG_FORMAT}`"
            )
        }),
    }
}

#[cfg(test)]
#[path = "tests/upgrade_tests.rs"]
mod tests;
