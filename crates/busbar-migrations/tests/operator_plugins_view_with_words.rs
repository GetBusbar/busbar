// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! R16a, with operator words installed: pass 1 gives the same golden `plugins:` subtree as
//! without words.

mod common;

use busbar_kernel_identity::operator::{install_operator, Judged, OperatorBinding};

#[test]
fn plugins_view_matches_golden_with_operator_words() {
    install_operator(OperatorBinding::Bound(Judged {
        words: Ok(Some(busbar_contract::auth_calls::OperatorClaim {
            provider: "admin-tokens".into(),
            canonical: "busbar-auth-admin-tokens".into(),
            principal: "admin".into(),
            first_party: true,
            version: "1.6.0".into(),
            signer: "busbar".into(),
        })),
        inert: Vec::new(),
    }));
    assert_eq!(busbar_kernel_identity::operator::provider(), "admin-tokens");
    common::check_view_properties(common::FIXTURE);
}
