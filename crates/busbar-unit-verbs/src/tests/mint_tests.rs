// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ported assertions from `busbar-core::admin::v1::json::handlers::plan_mint_group`'s tests:
//! mint under an existing parent is checked for EXISTENCE ONLY (no containment rule), a mint never
//! silently re-homes an existing group, and a missing group with no parent has nowhere to root.

use crate::mint::{plan_mint_group, GroupLookup, MintPlan};
use crate::refusal::ReasonCode;
use std::collections::HashMap;

struct FakeTree(HashMap<&'static str, Option<&'static str>>);

impl GroupLookup for FakeTree {
    fn group_exists(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }
    fn actual_parent(&self, name: &str) -> Option<String> {
        self.0.get(name).and_then(|p| *p).map(str::to_string)
    }
}

const MAX_LEN: usize = 253;

#[test]
fn no_group_named_is_a_no_op() {
    let tree = FakeTree(HashMap::new());
    assert_eq!(
        plan_mint_group(&tree, None, None, MAX_LEN).unwrap(),
        MintPlan::BindAsIs
    );
}

#[test]
fn existing_group_with_no_parent_named_binds_as_is() {
    let mut m = HashMap::new();
    m.insert("team-payments", None);
    let tree = FakeTree(m);
    assert_eq!(
        plan_mint_group(&tree, Some("team-payments"), None, MAX_LEN).unwrap(),
        MintPlan::BindAsIs
    );
}

#[test]
fn existing_group_with_matching_parent_named_binds_as_is() {
    let mut m = HashMap::new();
    m.insert("leaf", Some("team-payments"));
    m.insert("team-payments", None);
    let tree = FakeTree(m);
    assert_eq!(
        plan_mint_group(&tree, Some("leaf"), Some("team-payments"), MAX_LEN).unwrap(),
        MintPlan::BindAsIs
    );
}

#[test]
fn existing_group_with_a_different_named_parent_is_a_conflict_not_a_rehome() {
    let mut m = HashMap::new();
    m.insert("leaf", Some("team-payments"));
    m.insert("team-payments", None);
    m.insert("team-other", None);
    let tree = FakeTree(m);
    let err = plan_mint_group(&tree, Some("leaf"), Some("team-other"), MAX_LEN).unwrap_err();
    assert_eq!(err.reason, ReasonCode::Conflict);
}

#[test]
fn missing_group_with_no_parent_is_refused() {
    let tree = FakeTree(HashMap::new());
    let err = plan_mint_group(&tree, Some("nonexistent"), None, MAX_LEN).unwrap_err();
    assert_eq!(err.reason, ReasonCode::Validation);
}

#[test]
fn missing_group_with_a_dangling_parent_is_refused() {
    let tree = FakeTree(HashMap::new());
    let err =
        plan_mint_group(&tree, Some("leaf"), Some("nonexistent-parent"), MAX_LEN).unwrap_err();
    assert_eq!(err.reason, ReasonCode::Validation);
}

#[test]
fn missing_group_under_any_existing_parent_is_provisioned_existence_only() {
    // The parity clause: there is no containment/ownership rule on the named parent, only
    // existence. Any pre-existing group — even one with no relationship whatsoever to the caller
    // — is a valid root.
    let mut m = HashMap::new();
    m.insert("completely-unrelated-team", None);
    let tree = FakeTree(m);
    assert_eq!(
        plan_mint_group(
            &tree,
            Some("brand-new-leaf"),
            Some("completely-unrelated-team"),
            MAX_LEN
        )
        .unwrap(),
        MintPlan::ProvisionLeaf {
            parent: "completely-unrelated-team".to_string()
        }
    );
}

#[test]
fn overlong_parent_name_is_refused() {
    let tree = FakeTree(HashMap::new());
    let long_parent: String = "p".repeat(MAX_LEN + 1);
    let err = plan_mint_group(&tree, Some("leaf"), Some(&long_parent), MAX_LEN).unwrap_err();
    assert_eq!(err.reason, ReasonCode::Validation);
}
