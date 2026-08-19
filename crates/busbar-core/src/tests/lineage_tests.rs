// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral cross-plane lineage id: roots, induced children, and the trust-boundary shape.

use crate::lineage::Lineage;

#[test]
fn a_root_is_its_own_tree_top_with_no_parent() {
    let l = Lineage::root(100);
    assert_eq!(l.id(), 100);
    assert_eq!(l.root_id(), 100);
    assert_eq!(l.parent_id(), None);
    assert!(l.is_root());
}

#[test]
fn inducing_a_child_keeps_the_root_and_sets_the_parent() {
    let root = Lineage::root(1);
    let child = root.induce(2);
    assert_eq!(child.id(), 2);
    assert_eq!(child.parent_id(), Some(1));
    assert_eq!(child.root_id(), 1);
    assert!(!child.is_root());
}

/// A cross-plane chain (LLM 1 → MCP tool-call 2 → sampling completion 3) shares ONE root and threads
/// parents — the causal tree the ledger joins on, naming no plane.
#[test]
fn a_multi_hop_chain_shares_one_root_and_threads_parents() {
    let llm = Lineage::root(1);
    let tool = llm.induce(2);
    let sampled = tool.induce(3);
    assert_eq!(sampled.root_id(), 1);
    assert_eq!(sampled.parent_id(), Some(2));
    assert_eq!(sampled.id(), 3);
    // Every node in the tree agrees on the root.
    assert_eq!(llm.root_id(), tool.root_id());
    assert_eq!(tool.root_id(), sampled.root_id());
}

/// `adopt` continues a trusted inbound lineage verbatim (the trust check is the caller's, at the wire
/// edge); `root` is what untrusted ingress uses so a forged root can't join another tenant's tree.
#[test]
fn adopt_continues_a_trusted_lineage_verbatim() {
    let continued = Lineage::adopt(10, Some(11), 12);
    assert_eq!(continued.root_id(), 10);
    assert_eq!(continued.parent_id(), Some(11));
    assert_eq!(continued.id(), 12);
    assert!(!continued.is_root());
}
