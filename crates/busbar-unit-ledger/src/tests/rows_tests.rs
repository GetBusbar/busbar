// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The row identity an enforced key charges through.

use crate::rows::{group_bucket, group_bucket_scoped};

#[test]
fn a_group_window_bucket_is_the_shipped_spelling() {
    // These are the SAME ROWS the shipped release writes. A node that resolved its groups through
    // one projection and one that resolved them through another must charge the same cell, or one
    // release's usage reads as another release's silence.
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
