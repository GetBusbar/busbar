// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Every record the book seals names this node, before a restart and after it.

use super::tests::{open, seal, Scratch};
use super::*;

/// THE BOOK SEALS AS THE KERNEL'S NODE (THE DESIGN §1: "when (wall + monotonic, node)"): every
/// record names the node half of the op ids this process mints, it survives the journal, and a
/// restarted book seals as the node it runs as.
#[test]
fn every_record_the_book_seals_names_this_node() {
    let node = busbar_kernel::door::node();
    assert_ne!(node, 0, "the kernel's node is a non-zero draw");
    let scratch = Scratch::new("seals-as-node");
    let before = {
        let mut book = open(&scratch.0);
        assert_eq!(book.record.node(), node);
        seal(&mut book, 1..=2)
    };
    assert!(before.iter().all(|r| r.node == node), "{before:?}");

    let mut restarted = open(&scratch.0);
    assert_eq!(
        restarted.record.node(),
        node,
        "a restart forgot which node seals"
    );
    assert_eq!(
        restarted.audit_window(1, 2),
        before,
        "the journal lost the sealing node"
    );
    let after = seal(&mut restarted, 3..=3);
    assert_eq!(after[0].node, node);
    assert!(AuditChain::verify_chain(&restarted.audit_window(1, 3)).is_ok());
}
