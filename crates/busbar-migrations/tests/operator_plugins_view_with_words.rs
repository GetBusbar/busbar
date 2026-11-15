// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! R16a, with operator words installed: pass 1 gives the same golden `plugins:` subtree as
//! without words.

mod common;

use busbar_kernel_identity::operator::{install_linked, OperatorWords};

#[test]
fn plugins_view_matches_golden_with_operator_words() {
    install_linked(
        &[],
        OperatorWords {
            provider: "admin-tokens",
            principal_id: "admin",
        },
    );
    assert_eq!(busbar_kernel_identity::operator::provider(), "admin-tokens");
    common::check_view_properties(common::FIXTURE);
}
