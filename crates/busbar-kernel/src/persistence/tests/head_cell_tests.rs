// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The head cell's single-threaded contract (SEALING-FIX §3.2): publish and read round-trip, the
//! park answer, and recovery's `publish_max`.

use crate::persistence::journal::head_cell::{Head, HeadCell};

fn head(seq: u64) -> Head {
    let mut fp = [0u8; 32];
    for (i, byte) in fp.iter_mut().enumerate() {
        *byte = (seq as u8).wrapping_add(i as u8);
    }
    Head {
        seq,
        node_seq: seq + 100,
        fp,
        wall_ms: seq * 1000,
    }
}

#[test]
fn a_published_head_reads_back_whole() {
    let cell = HeadCell::new();
    assert_eq!(cell.read().1, Head::default());
    assert!(!cell.publish(&head(7)), "nobody is parked");
    let (version, read) = cell.read();
    assert_eq!(read, head(7));
    assert_eq!(version, 2, "one publish moves the version by two");
}

#[test]
fn park_sleeps_only_when_nothing_moved() {
    let cell = HeadCell::new();
    let (seen, _) = cell.read();
    assert!(cell.park(seen), "nothing moved: the reader may sleep");
    assert!(cell.publish(&head(1)), "a parked reader must be woken");
    cell.unpark();
    assert!(!cell.publish(&head(2)), "an awake reader needs no wake");
    assert!(
        !cell.park(seen),
        "the version moved: the reader works instead"
    );
    assert!(
        !cell.publish(&head(3)),
        "a refused park leaves the reader awake"
    );
}

#[test]
fn publish_max_never_moves_the_head_back() {
    let cell = HeadCell::new();
    let _ = cell.publish(&head(9));
    assert!(!cell.publish_max(&head(4)));
    assert_eq!(
        cell.read().1,
        head(9),
        "a lower recovery line does not replace the head"
    );
    let _ = cell.publish_max(&head(10));
    assert_eq!(cell.read().1, head(10));
}
