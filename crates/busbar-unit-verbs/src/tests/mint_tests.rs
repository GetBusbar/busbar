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

const MAX_LEN: usize = 256;

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

/// THE CEILING IS 1.5.5'S, AND 1.5.5'S IS 256.
///
/// The shipped bound lives in `busbar-core`'s admin service as
/// `MAX_GROUP_NAME_LEN = 256`, which this crate's constant documents itself as mirroring — and
/// then spelled 253. A parent name of 254, 255 or 256 characters that 1.5.5 accepted would have
/// been refused. The core constant is `pub(crate)`, so the source cannot be imported and the
/// literal is pinned here instead, with the same names on it that the doc carries.
///
/// A boundary either side of the ceiling, so this measures the accept/refuse edge rather than only
/// the number.
#[test]
fn the_group_name_ceiling_is_the_one_the_admin_service_pins() {
    assert_eq!(
        crate::verbs::MAX_GROUP_NAME_LEN,
        256,
        "the ceiling must be busbar-core::admin::v1::service::MAX_GROUP_NAME_LEN"
    );
    assert_eq!(MAX_LEN, crate::verbs::MAX_GROUP_NAME_LEN);

    // The at-cap parent has to EXIST for the length arm to be the one under test — a missing
    // parent refuses with the same reason for a different cause.
    let at_cap: &'static str = Box::leak(
        "p".repeat(crate::verbs::MAX_GROUP_NAME_LEN)
            .into_boxed_str(),
    );
    let tree = FakeTree(HashMap::from([(at_cap, None)]));
    assert!(
        plan_mint_group(
            &tree,
            Some("leaf"),
            Some(at_cap),
            crate::verbs::MAX_GROUP_NAME_LEN
        )
        .is_ok(),
        "a name of exactly the ceiling is accepted, as it was"
    );
    let over: String = "p".repeat(crate::verbs::MAX_GROUP_NAME_LEN + 1);
    assert!(plan_mint_group(
        &tree,
        Some("leaf"),
        Some(&over),
        crate::verbs::MAX_GROUP_NAME_LEN
    )
    .is_err());
}
