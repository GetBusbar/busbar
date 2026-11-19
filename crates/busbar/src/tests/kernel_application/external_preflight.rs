// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::test_common as common;
use busbar_kernel::config::{IdentityProviderCfg, IdentityProviders};

#[test]
fn a_real_plugin_module_is_still_refused_with_plugins_off() {
    crate::dist_root_install::install();
    let path = common::plugins::token_verifier_cdylib_path()
        .expect("the actual freshly built OIDC product is required");
    let module = crate::root::test_plugins::native_image(&path).name;
    let mut providers = IdentityProviders::default();
    providers.insert(
        "corp".to_string(),
        IdentityProviderCfg {
            module,
            max_admin_scope: None,
            token: None,
            browser_login: None,
            settings: Default::default(),
            insecure_transport: None,
            provisioning: None,
            issued_kinds: None,
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
