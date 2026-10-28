// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SETTINGS EACH PLUGIN DECLARES PUBLIC, as the kernel reads them: every plugin setting is
//! sensitive unless its plugin's settings schema marks it `x-busbar-public`
//! (`busbar_contract::settings_public`). The composition root hands the table in once, before the
//! first configuration is read, with the plugins' setting renames (`super::plugin_renames`). A
//! surface that renders a settings bag shows the public keys' values and every other key alone.

use std::collections::BTreeSet;
use std::sync::OnceLock;

/// The public settings of every plugin a build can load, by `module:` word.
pub trait PublicSettings: Send + Sync {
    /// The settings `module` declares public; empty when it declares none or no plugin answers
    /// to `module`.
    fn public(&self, module: &str) -> BTreeSet<String>;
}

static TABLE: OnceLock<&'static dyn PublicSettings> = OnceLock::new();

/// Install the root's table; the first install stands.
pub fn install(table: &'static dyn PublicSettings) {
    let _ = TABLE.set(table);
}

/// The settings `module` declares public (none installed: none; every setting sensitive).
#[must_use]
pub fn public(module: &str) -> BTreeSet<String> {
    TABLE
        .get()
        .map(|t| t.public(module.trim()))
        .unwrap_or_default()
}
