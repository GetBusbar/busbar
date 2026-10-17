// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The arithmetic a posting is made of, at the edges where it stops being obvious.
//!
//! Three edges, and money is wrong at every one of them if they are not pinned. The priced total
//! arrives as a `u128` and the reservation is a `u64`, so there is a width the two do not share and
//! a wrap there would post nearly nothing for the most expensive unit the node has ever run. The
//! overdraft flag has two independent causes — a hold whose own counter is non-zero, and a
//! settlement above what was ever held back — so the boundary between "spent exactly the
//! reservation" and "spent one nano-unit more" is the line between a clean posting and a disputed
//! one. And a unit that runs past the end more than once must carry each share once: a second spend
//! that re-recorded the first one's shortfall would bill the same overdraft twice.
//!
//! The flags are a bitset, which means every one of them is a claim that can be silently merged with
//! its neighbour; they are checked here as eight distinct bits and as a set that only ever grows.
//!
//! The tests in this file that have to MINT a token live in the kernel, under the same file name
//! in `busbar-kernel/src/tests/caps_tests/` (construction `token-sealed`); what stays here needs
//! no seal.

use crate::caps::*;

#[test]
fn the_eight_posting_flags_are_eight_distinct_bits() {
    // A bitset is where two claims quietly become one. Each flag puts the posting on a report
    // somebody reads, so two that shared a bit would put a unit on the wrong one.
    let flags = [
        PostingFlags::ESTIMATED,
        PostingFlags::METER_DISPUTED,
        PostingFlags::OVERDRAFT,
        PostingFlags::LATE_ACCRUAL,
        PostingFlags::RECOVERED,
        PostingFlags::VOIDED,
        PostingFlags::UNPOSTED,
        PostingFlags::DOWNGRADED,
    ];
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
    let both = PostingFlags::OVERDRAFT.with(PostingFlags::ESTIMATED);
    assert!(both.contains(PostingFlags::OVERDRAFT));
    assert!(both.contains(PostingFlags::ESTIMATED));
    assert!(both.contains(PostingFlags::OVERDRAFT.with(PostingFlags::ESTIMATED)));
    assert!(!both.contains(PostingFlags::VOIDED));
    assert!(!both.contains(PostingFlags::OVERDRAFT.with(PostingFlags::VOIDED)));
    assert_eq!(
        both.with(PostingFlags::OVERDRAFT),
        both,
        "adding twice adds once"
    );
}
