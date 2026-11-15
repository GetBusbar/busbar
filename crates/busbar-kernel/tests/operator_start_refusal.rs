// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPERATOR-FROM-ADMITTED-AUTH R7: when process start could not judge the operator credential (two
//! first-party claimants, an unreadable statement), every config read refuses with that text. The
//! words are process-global: this test owns its binary.

use busbar_kernel_identity::operator::{install_operator, Judged, OperatorBinding};

const START_REFUSAL: &str = "the operator start refusal of this fixture";

#[test]
fn every_config_read_refuses_with_the_start_refusal() {
    install_operator(OperatorBinding::Bound(Judged {
        words: Err(START_REFUSAL.to_owned()),
        inert: Vec::new(),
    }));
    for yaml in [
        "{}\n",
        "auth:\n  chain: []\n  admin_auth: []\n",
        "auth:\n  admin_auth: []\nidentity-providers:\n  idp: { module: some-idp }\n",
    ] {
        let deploy = busbar_kernel::config::deploy_from_yaml_str(
            yaml,
            &busbar_kernel::config::Grammar::empty(),
        )
        .expect("the config parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &std::collections::HashMap::new())
            .expect("the config resolves");
        let errors = busbar_kernel::config_validate::validate(&cfg)
            .err()
            .unwrap_or_default();
        assert!(
            errors.iter().any(|e| e.contains(START_REFUSAL)),
            "{yaml:?}: the start refusal: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains(START_REFUSAL) && e.contains("BUSBAR-3115")),
            "{yaml:?}: refused as config-auth-chain-invalid: {errors:?}"
        );
    }
}
