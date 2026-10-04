// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Settlement, and the dual write onto the previous release's rows.

use crate::legacy::{opening_balances, LegacyHead};

#[test]
fn an_empty_legacy_head_opens_at_zero_rather_than_refusing() {
    // A store that keeps nothing across a restart, and an older store that cannot answer, both give
    // an empty head. Neither may stop the node.
    let head = LegacyHead::empty();
    assert!(head.is_empty());
    assert!(opening_balances(&head, 7).is_empty());
}

#[test]
fn a_legacy_head_with_balances_opens_one_entry_per_bucket_at_the_named_card() {
    let head = LegacyHead {
        seq: Some(9_182),
        hash: Some("abc".into()),
        balances: vec![("free".into(), 0), ("paid".into(), 12_345)],
        cells_read: 2,
    };
    let opened = opening_balances(&head, 3);
    assert_eq!(opened.len(), 2);
    assert_eq!(opened[1].bucket, "paid");
    assert_eq!(opened[1].amount, 12_345);
    assert!(opened.iter().all(|o| o.rate_card_version == 3));
}
