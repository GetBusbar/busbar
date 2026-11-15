// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPERATOR-FROM-ADMITTED-AUTH R6: a 1.5 `token:` on the operator credential is refused with the
//! one named remedy, whatever the chain, and is never read as an unset (locked) operator. The words
//! are process-global: this test owns its binary.

use busbar_contract::auth_calls::OperatorClaim;
use busbar_kernel_identity::operator::{install_operator, Judged, OperatorBinding};

const TOKEN_REMEDY: &str = "is the 1.5 operator credential";

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

fn config(chain: &str) -> String {
    format!(
        "auth:\n  chain: {chain}\n  admin_auth: [dropped-op]\nidentity-providers:\n  dropped-op:\n    \
         module: dropped-op\n    token: {{ module: fixture-source, settings: {{ slot: BUSBAR_ADMIN_TOKEN }} }}\n"
    )
}

#[test]
fn a_1_5_operator_token_is_refused_with_its_remedy() {
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

    let with_keys = errors_of(&config("[keys]"));
    assert!(
        with_keys.iter().any(|e| e.contains(TOKEN_REMEDY)),
        "chain [keys]: the token: refusal: {with_keys:?}"
    );
    assert!(
        with_keys
            .iter()
            .all(|e| !e.contains("no admin credential can mint")),
        "chain [keys]: the token: refusal replaces no_mint_path: {with_keys:?}"
    );

    let without_keys = errors_of(&config("[]"));
    assert!(
        without_keys.iter().any(|e| e.contains(TOKEN_REMEDY)),
        "chain []: a 1.5 token: never validates into a locked admin plane: {without_keys:?}"
    );
}
