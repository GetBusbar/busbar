// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The row identity an enforced key charges through.

use crate::rows::{
    attribution_bucket, group_bucket, group_bucket_scoped, is_bucket_of_group, GROUP_BUCKET_PREFIX,
};

/// The five window words the configuration's `LimitWindow` spells, in its own order. Passed in
/// rather than known by the ledger, because the vocabulary is configuration's.
const WINDOWS: &[&str] = &["minute", "hour", "day", "month", "total"];

#[test]
fn a_principal_is_attributed_to_its_own_id_verbatim() {
    // Attribution, never a limit. A deployment with no `groups:` section still has one figure per
    // principal, and it is named by the principal and nothing else.
    assert_eq!(attribution_bucket("vk_alice").as_str(), "vk_alice");
}

#[test]
fn a_group_window_bucket_is_the_shipped_spelling() {
    // These are the SAME ROWS the shipped release writes. A node that resolved its groups through
    // one projection and one that resolved them through another must charge the same cell, or one
    // release's usage reads as another release's silence.
    assert_eq!(GROUP_BUCKET_PREFIX, "group:");
    assert_eq!(group_bucket("team", "month").as_str(), "group:team@month");
    assert_eq!(group_bucket("team", "total").as_str(), "group:team@total");
}

#[test]
fn a_scope_qualified_bucket_is_its_own_row() {
    // Folding a pool-narrowed limit back into the plain row would let one pool's spend exhaust
    // another's allowance.
    assert_eq!(
        group_bucket_scoped("team", "day", "pool", "blue").as_str(),
        "group:team@day#pool:blue"
    );
    assert_ne!(
        group_bucket_scoped("team", "day", "pool", "blue"),
        group_bucket("team", "day")
    );
}

#[test]
fn reading_a_name_back_is_anchored_at_both_ends() {
    assert!(is_bucket_of_group(
        &group_bucket("team", "month"),
        "team",
        WINDOWS
    ));
    assert!(is_bucket_of_group(
        &group_bucket_scoped("team", "day", "pool", "blue"),
        "team",
        WINDOWS
    ));
    // A different group, and a prefix of the right one, both answer no.
    assert!(!is_bucket_of_group(
        &group_bucket("team", "month"),
        "tea",
        WINDOWS
    ));
    assert!(!is_bucket_of_group(
        &group_bucket("teamwork", "month"),
        "team",
        WINDOWS
    ));
    // A word that is not a window is not a window, however plausible it looks.
    assert!(!is_bucket_of_group(
        &crate::totals::BucketId::new("group:team@fortnight"),
        "team",
        WINDOWS
    ));
}

#[test]
fn a_group_name_containing_an_at_sign_is_the_ordinary_case() {
    // An IdP subject is normally an EMAIL, so `user:alice@corp.com` is the common deployment and
    // not a pathological one. Any code that splits a bucket id on `@` gets it wrong for exactly
    // that deployment — which is why the match is anchored at both ends rather than searching for
    // a separator.
    let alice = group_bucket("user:alice@corp.com", "total");
    assert_eq!(alice.as_str(), "group:user:alice@corp.com@total");
    assert!(is_bucket_of_group(&alice, "user:alice@corp.com", WINDOWS));
    // …and it does NOT belong to `user:alice`: the window word would have to be `corp.com`.
    assert!(!is_bucket_of_group(&alice, "user:alice", WINDOWS));
}
