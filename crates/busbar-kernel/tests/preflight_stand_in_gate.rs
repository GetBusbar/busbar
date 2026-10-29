// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ITEM 292: the plugin pre-flight exempts the test auth modules exactly where the build's auth axis
//! answers them in process (the install record's `in_process_auth`), the same answer the chain
//! build opens them by.
//!
//! This file is an integration test on purpose: it links `busbar_kernel` WITHOUT `cfg(test)`, as a
//! downstream crate's test binary does, so it proves the answer comes from the install record and
//! not from how the kernel was compiled.

use busbar_kernel::config::{IdentityProviderCfg, IdentityProviders};

/// An `identity-providers:` definition naming a test auth module is accepted by the pre-flight in
/// a build whose auth axis answers it in process. The definition-side exemption once read
/// `cfg!(test)` alone, so a downstream test binary treated the module as a `kind: auth` plugin
/// reference and refused the config ("requires the plugin subsystem") that the same binary's auth
/// chain accepts.
#[test]
fn a_test_support_build_accepts_the_identity_provider_stand_ins_its_auth_chain_registers() {
    // Only compiles where the stand-ins are registered: this build IS a `test-support` build.
    let _registered_here = busbar_kernel::auth::AdminAuthChain::empty();
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

/// The control: a module that is NOT a stand-in is still a real plugin reference in the same build,
/// so the test above passes because the gate moved and not because the check stopped running.
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
