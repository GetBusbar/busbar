// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Metadata injection never claims an auth row, linking a row never makes it the operator, and the
//! operator judged from an admitted row remains authoritative (OPERATOR-FROM-ADMITTED-AUTH §3.3).

use crate::operator::{self, Judged, LinkedAuth, OperatorBinding, OperatorWords};

extern "C" fn unopened_door() -> &'static busbar_contract::abi::mechanism::door::Door {
    panic!("this metadata control never opens the linked door")
}

#[test]
fn explicit_metadata_keeps_auth_unanswered_until_a_judged_operator_overrides_it() {
    assert_eq!(operator::words(), OperatorWords::default());
    assert!(operator::linked().is_empty());
    let metadata = OperatorWords {
        provider: "fixture-operator",
        principal_id: "fixture-principal",
        ..OperatorWords::default()
    };
    operator::install_test_words(metadata);
    assert_eq!(operator::words(), metadata);
    assert!(operator::linked().is_empty());
    assert!(operator::linked_names().is_empty());
    assert!(!operator::answered(metadata.provider));

    static ROWS: &[LinkedAuth] = &[("linked-operator", "linked-canonical", unopened_door)];
    operator::install_linked(ROWS);
    assert_eq!(operator::linked_names(), vec!["linked-operator"]);
    assert_eq!(
        operator::words(),
        metadata,
        "linking a row never makes it the operator"
    );

    operator::install_operator(OperatorBinding::Bound(Judged {
        words: Ok(Some(busbar_contract::auth_calls::OperatorClaim {
            provider: "linked-operator".into(),
            canonical: "linked-canonical".into(),
            principal: "linked-principal".into(),
            first_party: true,
            version: "1.6.0".into(),
            signer: "busbar".into(),
        })),
        inert: Vec::new(),
    }));
    let actual = OperatorWords {
        provider: "linked-operator",
        principal_id: "linked-principal",
        canonical: "linked-canonical",
        first_party: true,
    };
    assert_eq!(operator::words(), actual);
    assert!(operator::answered(actual.provider));
    assert!(operator::answered("linked-canonical"));
    assert!(!operator::answered(metadata.provider));
    operator::install_test_words(metadata);
    assert_eq!(operator::words(), actual);
}
