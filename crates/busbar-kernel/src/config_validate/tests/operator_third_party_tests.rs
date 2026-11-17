// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPERATOR-FROM-ADMITTED-AUTH R8/R9: a row that states the operator fact but is not first-party
//! never becomes the operator. Referenced, the config is refused by name; unreferenced, it is inert
//! and boot continues with its audit row. The words are process-global (nextest runs each test in
//! its own process).

use busbar_contract::auth_calls::OperatorClaim;
use busbar_kernel_identity::operator::{Judged, OperatorBinding};

const NOT_FIRST_PARTY: &str = "which states the operator credential but is not first-party";

fn rogue() -> OperatorClaim {
    OperatorClaim {
        provider: "rogue-op".to_owned(),
        canonical: "busbar-auth-rogue-op".to_owned(),
        principal: "admin".to_owned(),
        first_party: false,
        version: "9.9.9".to_owned(),
        signer: "acme".to_owned(),
    }
}

fn install_inert() {
    crate::preflight::install_operator(OperatorBinding::Bound(Judged {
        words: Ok(None),
        inert: vec![rogue()],
    }));
}

fn errors_of(yaml: &str) -> Vec<String> {
    let deploy = crate::config::deploy_from_yaml_str(yaml, &crate::config::Grammar::empty())
        .expect("the config parses");
    let cfg = crate::config::resolve(&deploy, &std::collections::HashMap::new())
        .expect("the config resolves");
    super::validate(&cfg).err().unwrap_or_default()
}

#[test]
fn a_referenced_third_party_claimant_is_refused_by_name() {
    install_inert();
    for yaml in [
        "identity-providers:\n  idp: { module: rogue-op }\n",
        "auth:\n  chain: [idp]\nidentity-providers:\n  idp: { module: busbar-auth-rogue-op }\n",
    ] {
        let errors = errors_of(yaml);
        assert!(
            errors
                .iter()
                .any(|e| e.contains(NOT_FIRST_PARTY) && e.contains("rogue-op")),
            "{yaml:?}: refused naming the row: {errors:?}"
        );
    }
}

#[test]
fn an_unreferenced_third_party_claimant_boots_with_its_audit_row() {
    install_inert();
    let errors = errors_of("identity-providers:\n  idp: { module: some-idp }\n");
    assert!(
        errors.iter().all(|e| !e.contains(NOT_FIRST_PARTY)),
        "an unreferenced claimant is inert, not refused: {errors:?}"
    );
    let held = crate::audit::auditlog::held_operator_rows();
    assert!(
        held.iter()
            .any(|row| row.starts_with("auth.operator.inert ") && row.contains("rogue-op")),
        "the inert claimant leaves its audit row: {held:?}"
    );
}
