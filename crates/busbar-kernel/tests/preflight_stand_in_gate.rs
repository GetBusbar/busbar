// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ITEM 292: the plugin pre-flight exempts the compiled-in auth stand-ins under the SAME gate the
//! auth chain registers them under.
//!
//! This file is an integration test on purpose. An integration test links `busbar_kernel` WITHOUT
//! `cfg(test)` and WITH the `test-support` feature (the dev-dependency cycle through the plane
//! crates turns it on) — exactly how a downstream crate's test binary links it, and the one build
//! flavour in which `cfg!(test)` and `cfg!(any(test, feature = "test-support"))` answer differently.
//! A unit test inside the crate cannot tell the two gates apart: both are true there.

use busbar_kernel::config::{IdentityProviderCfg, IdentityProviders};

/// An `identity-providers:` definition naming a test stand-in is accepted by the pre-flight in the
/// build that registers the stand-in.
///
/// `AdminAuthChain::build` skips `test-scope-module` / `test-groups-module` as inline stand-ins under
/// `#[cfg(any(test, feature = "test-support"))]`. The definition-side exemption in
/// `plugins_preflight` read `cfg!(test)` alone, so here — `test-support` on, `cfg(test)` off — it
/// treated the stand-in as a `kind: auth` plugin reference and refused the config ("requires the
/// plugin subsystem") that the same binary's auth chain accepts.
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
            module: "oidc".to_string(),
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
