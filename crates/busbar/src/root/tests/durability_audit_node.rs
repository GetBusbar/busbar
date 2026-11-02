// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Every record the book seals names this node, before a restart and after it.

use super::tests::{open, seal, Scratch};
use super::*;

/// Every record names the Store-assigned node, and a restarted book on that same Store resumes it.
#[test]
fn every_record_the_book_seals_names_this_node() {
    let node = 7;
    let scratch = Scratch::new("seals-as-node");
    let slots = crate::root::store_double::RecordSlots::new();
    let before = {
        let mut book = open(&scratch.0, &slots);
        assert_eq!(book.record.node(), node);
        let before = seal(&mut book, 1..=2);
        assert!(book
            .lane()
            .unwrap()
            .drain(std::time::Duration::from_secs(5)));
        before
    };
    assert!(before.iter().all(|r| r.node == node), "{before:?}");

    let mut restarted = open(&scratch.0, &slots);
    assert_eq!(
        restarted.record.node(),
        node,
        "a restart forgot which node seals"
    );
    assert_eq!(
        restarted.audit_window(1, 2),
        Some(before),
        "the journal lost the sealing node"
    );
    let after = seal(&mut restarted, 3..=3);
    assert_eq!(after[0].node, node);
    let window = restarted
        .audit_window(1, 3)
        .expect("the journal reads back");
    assert!(AuditChain::verify_chain(&window).is_ok());
}
