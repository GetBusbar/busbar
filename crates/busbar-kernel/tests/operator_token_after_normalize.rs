// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPERATOR-FROM-ADMITTED-AUTH R21 (kernel half): the 1.5.5 configuration as normalization leaves
//! it (its `token:` definition passed through untouched, `fixtures/operator_token_after_normalize
//! .yaml`) is refused with the one named remedy, `operator_token("admin-tokens")` plus the install
//! remedy (no operator row is admitted in this binary), and never with the generic no-mint-path
//! refusal. No words are installed: this test owns its binary.

const FIXTURE: &str = include_str!("fixtures/operator_token_after_normalize.yaml");

#[test]
fn a_normalized_1_5_5_token_config_is_refused_with_its_named_remedy() {
    let deploy = busbar_kernel::config::deploy_from_yaml_str(FIXTURE).expect("the fixture parses");
    let errors = match busbar_kernel::config::resolve(&deploy, &std::collections::HashMap::new()) {
        Err(errors) => errors,
        Ok(cfg) => busbar_kernel::config_validate::validate(&cfg)
            .err()
            .unwrap_or_default(),
    };
    let remedy = busbar_kernel_identity::operator::operator_token("admin-tokens");
    let install = busbar_kernel_identity::operator::operator_install_remedy();
    assert!(
        errors
            .iter()
            .any(|e| e.contains(&remedy) && e.contains(&install)),
        "refused with operator_token(\"admin-tokens\") and the install remedy: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .all(|e| !e.contains("no admin credential can mint") && !e.contains("``")),
        "never the generic no-mint-path refusal, never an empty word: {errors:?}"
    );
}
