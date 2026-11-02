// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::plugin_rows::PluginRows;
use busbar_contract::secret_fields::{undeclared_reference, undeclared_refusal};

use super::RootCfg;

pub(crate) fn undeclared_secret_refs(
    registry: &dyn PluginRows,
    cfg: &RootCfg,
) -> Result<(), String> {
    let declared = |module: &str| {
        let mut paths = registry.secret_slots(module);
        paths.extend(registry.reference_slots(module));
        paths
    };
    let policed = |at: String,
                   module: &str,
                   settings: &serde_json::Map<String, serde_json::Value>,
                   paths: &[String]|
     -> Result<(), String> {
        let tree = serde_json::Value::Object(settings.clone());
        match undeclared_reference(&tree, paths) {
            Some(field) => Err(undeclared_refusal(&format!("{at}.{field}"), module)),
            None => Ok(()),
        }
    };
    let check = |at: String,
                 module: &str,
                 settings: &serde_json::Map<String, serde_json::Value>|
     -> Result<(), String> { policed(at, module, settings, &declared(module)) };
    if let Some(store) = &cfg.store {
        check("store.settings".into(), &store.module, &store.settings)?;
    }
    for (module, m) in &cfg.secrets {
        policed(
            format!("secrets.{module}.settings"),
            module,
            &m.settings,
            &registry.secret_slots(module),
        )?;
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
