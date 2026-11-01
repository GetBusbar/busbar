// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The posting's flags. A posting carries a count, never money, and its flags say how far that
//! count is believed. The flags are a bitset, which means every one of them is a claim that can be
//! silently merged with its neighbour; they are checked here as distinct bits, every one the type
//! declares, and as a set that only ever grows.

use crate::caps::*;

/// Every flag `PostingFlags` declares. Hand-kept, so the cell below holds it to the type's own
/// declarations (Law 8: a list somebody typed is checked against the thing it enumerates).
const FLAGS: &[PostingFlags] = &[
    PostingFlags::ESTIMATED,
    PostingFlags::METER_DISPUTED,
    PostingFlags::LATE_ACCRUAL,
    PostingFlags::DOWNGRADED,
    PostingFlags::UNDECLARED,
];

#[test]
fn every_posting_flag_is_a_distinct_bit() {
    // A bitset is where two claims quietly become one. Each flag puts the posting on a report
    // somebody reads, so two that shared a bit would put a unit on the wrong one.
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

    // `with` only ever adds, and `contains` is every-flag-of rather than any-flag-of.
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
