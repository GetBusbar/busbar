// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIGRATE-ON-BOOT r41 §9 C1 red (j2), as AGREED QM2 (owner, 2026-11-15T20:54Z) rules it: 1.6.0 has
//! no absent-store default. The one-time upgrade writes the block a store-less 1.5.5 config implied;
//! a config already stamped for 1.6.0 that names no store is refused with its code page and a text
//! that says why.

use super::validate;

#[test]
fn a_stamped_config_with_no_store_is_refused_with_its_code_page() {
    let deploy = crate::config::deploy_from_yaml_str(
        "config_version: 1\nlisten: 127.0.0.1:8080\nproviders: {}\nmodels: {}\n",
        &crate::config::Grammar::empty(),
    )
    .expect("a store-less stamped document parses; validation refuses it");
    assert_eq!(deploy.config_version, Some(1));
    assert!(deploy.store.is_none());
    let cfg = crate::config::resolve(&deploy, &std::collections::HashMap::new())
        .expect("resolve the config");
    let errors = validate(&cfg).expect_err("a stamped config with no store is refused");
    let page = format!("{}BUSBAR-3120", crate::diagnostics::ERROR_DOCS_BASE);
    let refusal = errors
        .iter()
        .find(|line| line.starts_with("BUSBAR-3120: "))
        .unwrap_or_else(|| panic!("BUSBAR-3120 among the refusals: {errors:?}"));
    for part in [
        "store is required; add a `store:` block with the configured Store module and settings",
        "1.6.0 has no default store",
        "stamped `config_version: 1` must name its store itself",
        page.as_str(),
    ] {
        assert!(refusal.contains(part), "{part}: {refusal}");
    }
}
