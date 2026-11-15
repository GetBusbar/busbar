// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPERATOR-FROM-ADMITTED-AUTH R4 (the headline): on a root that links no operator row, the
//! admitted first-party row stating the operator fact IS the operator credential. Its role-less
//! `admin` principal holds `Full`, and an operator entry configured with its own `settings` is a
//! mint path, so `chain: [keys]` validates. The words are process-global: this test owns its binary.

use busbar_contract::auth_calls::OperatorClaim;
use busbar_kernel_identity::operator::{install_operator, Judged, OperatorBinding};

const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

fn install() {
    install_operator(OperatorBinding::Bound(Judged {
        words: Ok(Some(OperatorClaim {
            provider: "dropped-op".to_owned(),
            canonical: "busbar-auth-dropped-op".to_owned(),
            principal: "admin".to_owned(),
            first_party: true,
            version: "1.6.0".to_owned(),
            signer: "busbar".to_owned(),
        })),
        inert: Vec::new(),
    }));
}

fn errors_of(yaml: &str) -> Vec<String> {
    let deploy =
        busbar_kernel::config::deploy_from_yaml_str(yaml, &busbar_kernel::config::Grammar::empty())
            .expect("the config parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &std::collections::HashMap::new())
        .expect("the config resolves");
    busbar_kernel::config_validate::validate(&cfg)
        .err()
        .unwrap_or_default()
}

#[test]
fn a_dropped_operator_with_settings_is_a_mint_path_and_holds_full() {
    install();
    assert!(busbar_kernel::config::names_operator("dropped-op"));
    assert!(busbar_kernel::config::names_operator(
        "busbar-auth-dropped-op"
    ));
    let op = busbar_kernel::auth::Operator::new("dropped-op");
    assert!(
        op.mints(
            Some("dropped-op"),
            "admin",
            busbar_kernel::config::operator_principal_id()
        ),
        "the role-less principal the operator row states is the operator: Full"
    );

    let errors = errors_of(&format!(
        "auth:\n  chain: [keys]\n  admin_auth: [dropped-op]\nidentity-providers:\n  dropped-op:\n    \
         module: dropped-op\n    settings: {{ sha256: \"{DIGEST}\" }}\n"
    ));
    assert!(
        errors
            .iter()
            .all(|e| !e.contains("no admin credential can mint")),
        "an operator entry with its own settings is a mint path: {errors:?}"
    );
}
