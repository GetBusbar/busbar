// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPERATOR-FROM-ADMITTED-AUTH R10: the operator's config key is a reserved hook name exactly while
//! an operator row is admitted, so dropping the operator plugin in reserves its alias. The words
//! are process-global: this test owns its binary (`operator_no_default_chain.rs` holds the
//! no-words half, where nothing is reserved).

use busbar_contract::auth_calls::OperatorClaim;
use busbar_kernel_identity::operator::{install_operator, Judged, OperatorBinding};

#[test]
fn a_dropped_operators_alias_is_a_reserved_hook_name() {
    assert!(
        !busbar_kernel::config::is_reserved_hook_name("dropped-op"),
        "with no operator words the alias is an ordinary hook name"
    );
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
    assert!(busbar_kernel::config::is_reserved_hook_name("dropped-op"));
    assert!(!busbar_kernel::config::is_reserved_hook_name(""));
}
