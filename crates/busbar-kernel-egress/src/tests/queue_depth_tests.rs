// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A pool counts its own waiters (`pool::QueueDepth`): the depth gauge looks no pool name up.

use crate::pool::QueueDepth;

/// Moved from the root's `the_counters_label_a_member_by_name_and_keep_each_pools_depth`: the
/// depth is now the pool's own count.
#[test]
fn a_pools_depth_follows_its_waiters_and_never_reads_below_empty() {
    let depth = QueueDepth::default();
    assert_eq!(depth.change(1), 1);
    assert_eq!(depth.change(1), 2);
    assert_eq!(depth.change(-1), 1);
    assert_eq!(depth.change(-5), 0, "a depth never reads below empty");
    assert_eq!(depth.change(1), 1);
}

/// Two pools keep separate counts, and a copy of a pool (a configuration copy) starts at zero.
#[test]
fn each_pool_keeps_its_own_count_and_a_copy_starts_empty() {
    let p = QueueDepth::default();
    let q = QueueDepth::default();
    assert_eq!(p.change(1), 1);
    assert_eq!(q.change(1), 1);
    assert_eq!(p.change(1), 2);
    assert_eq!(p.clone().change(0), 0);
    assert_eq!(p, q, "the depth is not part of what a pool is");
}
