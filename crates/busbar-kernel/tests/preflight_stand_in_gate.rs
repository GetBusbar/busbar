// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::{IdentityProviderCfg, IdentityProviders};

#[test]
fn a_test_support_build_accepts_the_identity_provider_stand_ins_its_auth_chain_registers() {
    busbar_kernel_testkit::test_support::root::ensure();
    for module in ["test-scope-module", "test-groups-module"] {
        let mut providers = IdentityProviders::default();
        providers.insert(
            "dev".to_string(),
            IdentityProviderCfg {
                module: module.to_string(),
                max_admin_scope: None,
                token: None,
                browser_login: None,
                settings: Default::default(),
            },
        );
        if let Err(refusal) = busbar_kernel::plugins_preflight(
            None,
            None,
            &providers,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        ) {
            panic!(
                "identity-providers.dev (module '{module}') is registered in this build and was \
                 refused by the pre-flight: {refusal}"
            );
        }
    }
}

#[test]
fn a_real_plugin_module_is_still_refused_with_plugins_off() {
    let mut providers = IdentityProviders::default();
    providers.insert(
        "corp".to_string(),
        IdentityProviderCfg {
            module: "test-idp-double".to_string(),
            max_admin_scope: None,
            token: None,
            browser_login: None,
            settings: Default::default(),
        },
    );
    let refusal = busbar_kernel::plugins_preflight(
        None,
        None,
        &providers,
        &Default::default(),
        &Default::default(),
        &Default::default(),
    )
    .expect_err("a plugin module with plugins disabled is refused");
    assert!(
        refusal.contains("identity-providers.corp") && refusal.contains("plugins.enabled"),
        "the refusal names the definition and the switch: {refusal}"
    );
}
