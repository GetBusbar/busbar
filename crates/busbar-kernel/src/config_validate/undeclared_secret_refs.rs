// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::plugin_rows::PluginRows;
use busbar_contract::secret_fields::undeclared_refusal;

use super::RootCfg;

pub(crate) fn undeclared_secret_refs(
    registry: &dyn PluginRows,
    cfg: &RootCfg,
) -> Result<(), String> {
    check_declared_paths(
        cfg,
        |module| registry.secret_slots(module),
        |module| registry.reference_slots(module),
    )
}

fn check_declared_paths(
    cfg: &RootCfg,
    secret_slots: impl Fn(&str) -> Vec<String>,
    reference_slots: impl Fn(&str) -> Vec<String>,
) -> Result<(), String> {
    let declared = |module: &str| {
        let mut paths = secret_slots(module);
        paths.extend(reference_slots(module));
        paths
    };
    let policed = |at: String,
                   module: &str,
                   settings: &busbar_contract::plugin_settings::Settings,
                   paths: &[String]|
     -> Result<(), String> {
        match settings.undeclared_reference(paths, &crate::config::secret::sugars())? {
            Some(field) => Err(undeclared_refusal(&format!("{at}.{field}"), module)),
            None => Ok(()),
        }
    };
    let check = |at: String,
                 module: &str,
                 settings: &busbar_contract::plugin_settings::Settings|
     -> Result<(), String> { policed(at, module, settings, &declared(module)) };
    if let Some(store) = &cfg.store {
        check("store.settings".into(), &store.module, &store.settings)?;
    }
    for (module, m) in &cfg.secrets {
        policed(
            format!("secrets.{module}.settings"),
            module,
            &m.settings,
            &secret_slots(module),
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
