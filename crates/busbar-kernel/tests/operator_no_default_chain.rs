// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPERATOR-FROM-ADMITTED-AUTH R19: with no admitted operator row, an absent `admin_auth` (or an
//! absent `auth:` block) is refused with a named remedy. It never resolves to an empty chain, which
//! is the open posture, and an explicit `admin_auth: []` stays the opt-in open dev posture. No
//! words are installed in this binary.

const NO_DEFAULT: &str = "no admitted first-party auth plugin states the operator credential";

fn resolved(yaml: &str) -> busbar_kernel::config::RootCfg {
    let deploy =
        busbar_kernel::config::deploy_from_yaml_str(yaml, &busbar_kernel::config::Grammar::empty())
            .expect("the config parses");
    busbar_kernel::config::resolve(&deploy, &std::collections::HashMap::new())
        .expect("the config resolves")
}

fn errors_of(cfg: &busbar_kernel::config::RootCfg) -> Vec<String> {
    busbar_kernel::config_validate::validate(cfg)
        .err()
        .unwrap_or_default()
}

#[test]
fn an_absent_admin_auth_with_no_operator_row_is_refused() {
    for yaml in ["auth:\n  chain: []\n", "{}\n"] {
        let cfg = resolved(yaml);
        assert!(
            !cfg.admin_auth.is_empty(),
            "{yaml:?}: the default never resolves to the open (empty) chain"
        );
        let errors = errors_of(&cfg);
        assert!(
            errors.iter().any(|e| e.contains(NO_DEFAULT)),
            "{yaml:?}: refused with the remedy: {errors:?}"
        );
    }

    let open = errors_of(&resolved("auth:\n  chain: []\n  admin_auth: []\n"));
    assert!(
        open.iter().all(|e| !e.contains(NO_DEFAULT)),
        "an explicit admin_auth: [] is the opt-in open posture: {open:?}"
    );
}
