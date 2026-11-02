// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The posting's flags. A posting carries a count, never money, and its flags say how far that

use crate::caps::*;

/// Every flag `PostingFlags` declares. Hand-kept, so the cell below holds it to the type's own
const FLAGS: &[PostingFlags] = &[
    PostingFlags::ESTIMATED,
    PostingFlags::METER_DISPUTED,
    PostingFlags::LATE_ACCRUAL,
    PostingFlags::DOWNGRADED,
    PostingFlags::UNDECLARED,
];

#[test]
fn every_posting_flag_is_a_distinct_bit() {
    let flags = FLAGS;
    assert!(PostingFlags::NONE.is_clean());
    assert!(PostingFlags::default().is_clean());
    for (i, flag) in flags.iter().enumerate() {
        assert!(!flag.is_clean(), "a flag that is set is not a clean set");
        assert!(flag.contains(*flag));
        assert!(
            flag.contains(PostingFlags::NONE),
            "every set contains nothing"
        );
        assert!(!PostingFlags::NONE.contains(*flag));
        for other in &flags[..i] {
            assert_ne!(flag, other, "two flags share a bit");
            assert!(!flag.contains(*other), "a flag answers for its neighbour");
        }
    }

    let both = PostingFlags::LATE_ACCRUAL.with(PostingFlags::ESTIMATED);
    assert!(both.contains(PostingFlags::LATE_ACCRUAL));
    assert!(both.contains(PostingFlags::ESTIMATED));
    assert!(both.contains(PostingFlags::LATE_ACCRUAL.with(PostingFlags::ESTIMATED)));
    assert!(!both.contains(PostingFlags::DOWNGRADED));
    assert!(!both.contains(PostingFlags::LATE_ACCRUAL.with(PostingFlags::DOWNGRADED)));
    assert_eq!(
        both.with(PostingFlags::LATE_ACCRUAL),
        both,
        "adding twice adds once"
    );
}
