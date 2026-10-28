// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNDECLARED-REFERENCE REFUSAL (OWNER RULING, CHIP-REVIEW-v4 change 2; overturns Q123).
//!
//! A secret reference (`{env:}`, `{file:}`, `{module:, settings:}`) at any position in a PLUGIN'S
//! settings block that the plugin has not declared secret (its Statement's `secret_refs`, `*` = any
//! key or index) is refused, at boot and at `--validate` alike: busbar never resolves a secret into
//! a field the plugin did not ask to hold one. The sentence names the field, the plugin and the
//! instance, and says to write the value itself.
//!
//! Core's own typed config fields (`auth.signing_key`, `providers.<name>.api_key`, a TLS key, an
//! identity provider's `token:` and `browser_login.client_secret`, …) are not plugin settings and
//! are not looked at here.
//!
//! Self-contained: the registry's declared paths and the config in, the first refusal out. The one
//! validator (`config_validate::check`) runs it on every path: boot, `--validate` and the dry run.

use busbar_contract::plugin_rows::PluginRows;
use busbar_contract::secret_fields::{undeclared_reference, undeclared_refusal};

use super::RootCfg;

/// The first secret reference in a plugin's settings that the plugin did not declare secret, as
/// the refusal sentence.
///
/// # Errors
/// That sentence: `<field>: … the plugin '<plugin>' did not declare it as a secret …`.
pub(crate) fn undeclared_secret_refs(
    registry: &dyn PluginRows,
    cfg: &RootCfg,
) -> Result<(), String> {
    let check = |at: String,
                 module: &str,
                 settings: &serde_json::Map<String, serde_json::Value>|
     -> Result<(), String> {
        let tree = serde_json::Value::Object(settings.clone());
        match undeclared_reference(&tree, &registry.secret_slots(module)) {
            Some(field) => Err(undeclared_refusal(&format!("{at}.{field}"), module)),
            None => Ok(()),
        }
    };
    if let Some(store) = &cfg.store {
        check("store.settings".into(), &store.module, &store.settings)?;
    }
    for (module, m) in &cfg.secrets {
        check(format!("secrets.{module}.settings"), module, &m.settings)?;
    }
    let mut hooks: Vec<_> = cfg.hooks.iter().collect();
    hooks.sort_by(|a, b| a.0.cmp(b.0));
    for (name, h) in hooks {
        check(format!("hooks.{name}.settings"), &h.plugin, &h.settings)?;
    }
    for (name, e) in &cfg.export_defs {
        check(format!("export.{name}.settings"), &e.module, &e.settings)?;
    }
    for (name, p) in &cfg.identity_providers {
        check(
            format!("identity-providers.{name}.settings"),
            &p.module,
            &p.settings,
        )?;
    }
    if let Some(auth) = &cfg.auth {
        for (plane, entries) in [("chain", &auth.chain), ("admin_auth", &auth.admin_auth)] {
            for e in entries {
                check(
                    format!("auth.{plane}.{}.settings", e.name),
                    &e.module,
                    &e.settings,
                )?;
            }
        }
        for (name, m) in &auth.methods {
            check(
                format!("auth.methods.{name}.settings"),
                &m.module,
                &m.settings,
            )?;
        }
    }
    for plane in cfg.plane_defs.values() {
        if let Some(refusal) = plane.undeclared_secret_ref() {
            return Err(refusal);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/undeclared_secret_refs_tests.rs"]
mod tests;
