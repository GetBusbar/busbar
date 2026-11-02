// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Metadata injection never claims an auth row, and a real root remains authoritative.

use crate::operator::{self, LinkedAuth, OperatorWords};

extern "C" fn unopened_door() -> &'static busbar_contract::abi::mechanism::door::Door {
    panic!("this metadata control never opens the linked door")
}

#[test]
fn explicit_metadata_keeps_auth_unanswered_until_a_linked_root_overrides_it() {
    assert_eq!(operator::words(), OperatorWords::default());
    assert!(operator::linked().is_empty());
    let metadata = OperatorWords {
        provider: "fixture-operator",
        principal_id: "fixture-principal",
    };
    operator::install_test_words(metadata);
    assert_eq!(operator::words(), metadata);
    assert!(operator::linked().is_empty());
    assert!(operator::linked_names().is_empty());
    assert!(!operator::answered(metadata.provider));

    let actual = OperatorWords {
        provider: "linked-operator",
        principal_id: "linked-principal",
    };
    static ROWS: &[LinkedAuth] = &[("linked-operator", "linked-canonical", unopened_door)];
    operator::install_linked(ROWS, actual);
    assert_eq!(operator::words(), actual);
    assert!(operator::answered(actual.provider));
    assert!(operator::answered("linked-canonical"));
    assert!(!operator::answered(metadata.provider));
    assert_eq!(operator::linked_names(), vec![actual.provider]);
    operator::install_test_words(metadata);
    assert_eq!(operator::words(), actual);
}
