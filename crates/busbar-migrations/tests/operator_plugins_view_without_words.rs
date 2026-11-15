// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! R16a, without operator words: pass 1 over a 1.5 fixture with a historical `plugins:` block
//! gives the golden `plugins:` subtree (see `operator_plugins_view_with_words.rs` for the other
//! half).

mod common;

#[test]
fn plugins_view_matches_golden_without_operator_words() {
    assert_eq!(busbar_kernel_identity::operator::provider(), "");
    common::check_view_properties(common::FIXTURE);
}
