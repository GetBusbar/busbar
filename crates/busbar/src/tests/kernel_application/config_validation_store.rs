// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::yaml;
use busbar_kernel::config;
use busbar_kernel::config_validate::validate;

#[test]
fn a_config_without_a_store_block_is_refused() {
    crate::dist_root_install::install();
    // Bind the linked operator: the config takes the closed default admin chain.
    busbar_kernel::preflight::install_operator(crate::root::auth_bindings::operator_binding());

    let deploy: config::DeployCfg = yaml::from_str(
        "providers: {}\nmodels: {}\nstore: {module: inert-store-metadata}\nauth: {chain: []}\n",
    )
    .expect("host-only fixture parses");
    let mut cfg = config::resolve(&deploy, &std::collections::HashMap::new())
        .expect("host-only fixture resolves");
    assert!(
        validate(&cfg).is_ok(),
        "the fixture validates with its store"
    );
    cfg.store = None;
    let errs = validate(&cfg).expect_err("a config with no store: block must be refused");
    assert_eq!(
        errs,
        vec![config::store_required()],
        "the absent store is the one refusal"
    );
    let line = config::store_required();
    for part in ["store is required", "configured Store module"] {
        assert!(line.contains(part), "the refusal names `{part}`: {line}");
    }
}
