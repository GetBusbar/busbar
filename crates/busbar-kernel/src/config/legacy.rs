// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT LEGACY TABLE, as the kernel reads it (`BUSBAR-1.6.0.md` §2: "Retired names … and
//! migrations for plugins that are not in the build … live in the root legacy table,
//! `[package.metadata.busbar.legacy]`, generated from `plugins.yaml`").
//!
//! The rows name plugins no crate in the kernel declares, so the kernel spells none of them: the
//! composition root owns its table and LENDS it ([`Legacy`]) to every path that reads it — the
//! config load and parse, `--migrate-config` and the registry link — and the resolved configuration
//! and the generation built from it keep the table they were lent. A row is `key = "value"`:
//!
//! - `retired.<kind root>.<word>` → the alias a retired `module:` spelling now answers to;
//! - `manifest.<alias>` / `asset.<alias>` → that plugin's manifest name and release-asset stem;
//! - `former.<alias>` → the manifest names the plugin's earlier releases carried (plugins.yaml
//!   `former_names:`, space-separated), which a LINKED row answers to as its dropped-in copy's
//!   signed manifest does ([`Legacy::former_names`]);
//! - `name_1_5_5.<repo>` → the frozen manifest name a plugin repo's 1.5.5-era release carried (the
//!   table `former.<alias>` is gated against; read by no runtime code);
//! - every other key is frozen 1.5.5 operator text, verbatim.
//!
//! [`Legacy::rewrite_retired`] is the ONE rewrite over the table: boot's 1.x detector and
//! `--migrate-config` both call it, so the refusal and the rewrite cannot disagree about which
//! spellings are retired.

use serde_yaml::{Mapping, Value};

/// The rows a root hands in: `(key, value)`, in table order.
pub type Rows = &'static [(&'static str, &'static str)];

/// THE ROOT LEGACY TABLE, LENT: the composition root owns its rows and lends this value to every
/// reader — the config load and parse ([`crate::config::resolve_in`], which keeps it on the resolved
/// configuration and the generation built from it), the migrator and the registry link. No static
/// of the kernel holds it (`BUSBAR-1.6.0.md`: "add no new kernel `OnceLock` seam beyond the two R6
/// exempts"), so two compositions in one process read their own tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Legacy {
    rows: Rows,
}

impl Legacy {
    /// The table `rows` lend.
    #[must_use]
    pub const fn new(rows: Rows) -> Self {
        Self { rows }
    }

    /// The table a TEST build with no root reads: the frozen 1.5.5 rows the kernel tests pin
    /// (`tests/fixtures/frozen_customer_text.yaml`, `legacy_rows`). A shipped build has no such
    /// table: its rows are the root's, lent through [`Legacy::new`].
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn stand_in() -> Self {
        Self::new(stand_in())
    }

    /// The value of `key`; empty when the table has no such row.
    #[must_use]
    pub fn text(self, key: &str) -> &'static str {
        self.rows
            .iter()
            .find(|(k, _)| *k == key)
            .map_or("", |(_, v)| v)
    }

    /// The `left:right` pairs of a `left:right | left:right` row, in row order; none when the table
    /// has no such row.
    #[must_use]
    pub fn pairs(self, key: &str) -> Vec<(&'static str, &'static str)> {
        self.text(key)
            .split(" | ")
            .filter_map(|pair| pair.split_once(':'))
            .collect()
    }

    /// The FORMER NAMES the plugin config names `alias` by is declared to answer to (its
    /// `former.<alias>` row, space-separated); none when the table has no such row.
    #[must_use]
    pub fn former_names(self, alias: &str) -> Vec<String> {
        self.text(&["former.", alias].concat())
            .split_whitespace()
            .map(str::to_string)
            .collect()
    }

    /// THE ONE REWRITE over the legacy table: when the `module:` of the `kind_root` section
    /// `section` is a retired spelling (a `retired.<kind_root>.<word>` row), the spelling and the
    /// alias it answers to now. With `apply` the value is rewritten to the alias in place; without,
    /// the section is left as written (boot and `--validate` refuse with the marker instead).
    pub fn rewrite_retired(
        self,
        kind_root: &str,
        section: &mut Mapping,
        apply: bool,
    ) -> Option<(String, &'static str)> {
        let old = section.get("module").and_then(Value::as_str)?.to_string();
        let key = ["retired.", kind_root, ".", &old].concat();
        let alias = self.text(&key);
        if alias.is_empty() {
            return None;
        }
        if apply {
            section.insert("module".into(), alias.into());
        }
        Some((old, alias))
    }
}

#[cfg(any(test, feature = "test-support"))]
fn stand_in() -> Rows {
    // The parsed rows live in one static and the borrowed table in a second, so every `&'static
    // str` points into a static rather than into a leaked allocation.
    static OWNED: std::sync::OnceLock<Vec<(String, String)>> = std::sync::OnceLock::new();
    static STAND_IN: std::sync::OnceLock<Vec<(&'static str, &'static str)>> =
        std::sync::OnceLock::new();
    STAND_IN.get_or_init(|| {
        OWNED
            .get_or_init(|| {
                let doc: Value = serde_yaml::from_str(include_str!(
                    "../../tests/fixtures/frozen_customer_text.yaml"
                ))
                .expect("the frozen-text fixture parses");
                doc.get("legacy_rows")
                    .and_then(Value::as_mapping)
                    .expect("the frozen-text fixture carries `legacy_rows`")
                    .iter()
                    .filter_map(|(k, v)| Some((k.as_str()?.to_owned(), v.as_str()?.to_owned())))
                    .collect()
            })
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    })
}

#[cfg(test)]
#[path = "tests/legacy_table_tests.rs"]
mod legacy_table_tests;
