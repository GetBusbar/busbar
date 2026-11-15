// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPERATOR-FROM-ADMITTED-AUTH R3: the operator credential's words come from the admitted row that
//! states the operator fact, not from a linked row. The words are process-global, so this test owns
//! its binary.

use busbar_contract::auth_calls::OperatorClaim;
use busbar_kernel_identity::operator::{self, install_operator, Judged, OperatorBinding};

#[test]
fn a_dropped_operator_row_answers_with_no_linked_row() {
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
    assert!(operator::linked().is_empty(), "no row is linked");
    assert_eq!(operator::provider(), "dropped-op");
    assert_eq!(operator::principal_id(), "admin");
    assert!(
        operator::answered("dropped-op"),
        "the admitted row answers its key"
    );
    assert!(
        operator::answered("busbar-auth-dropped-op"),
        "the admitted row answers its canonical name"
    );
    assert!(
        operator::names("dropped-op", "busbar-auth-dropped-op"),
        "`module:` may name the operator row by its canonical name"
    );
    assert!(!operator::answered(""), "the empty word is never answered");
    assert!(!operator::names("dropped-op", "someone-else"));
}
