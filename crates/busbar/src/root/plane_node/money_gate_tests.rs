// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A billable unit does not open while the node's journal cannot record money, and opens again as
//! soon as it can.

use crate::root::durability::node_book;
use crate::root::plane_node::Node;
use crate::root::store_double::NativeFaults;
use busbar_kernel::persistence::journal::{BufferBudget, RuntimeJournal};
use busbar_kernel_wal::{Entry, RecordClass};
use std::sync::Arc;

const BUDGET: BufferBudget = BufferBudget {
    records: 3,
    bytes: 1024 * 1024,
};
const HISTORY: BufferBudget = BufferBudget {
    records: 64,
    bytes: 1024 * 1024,
};

async fn fixture(node_id: u64) -> (Arc<RuntimeJournal>, Arc<Node>) {
    let faults = NativeFaults::open().await;
    let core = crate::root::real_store::core_over(faults).await;
    let journal = RuntimeJournal::open(core, node_id, BUDGET).await.unwrap();
    let book = node_book(journal.clone(), HISTORY)
        .await
        .unwrap()
        .durability;
    let node = Arc::new(Node::new());
    node.bind_book(book);
    (journal, node)
}

/// Fill the journal's custody buffer: it can record no more money until it drains.
fn fill(journal: &RuntimeJournal) {
    for index in 0..3 {
        journal
            .stage_run(&[Entry::new(RecordClass::Load, vec![index])])
            .unwrap();
    }
    assert!(journal.refuses_money().is_some());
}

#[tokio::test]
async fn unit_open_is_refused_while_the_journal_cannot_record_money() {
    let (journal, node) = fixture(881).await;
    assert!(node.money_gate().is_ok(), "a healthy journal admits");
    assert_eq!(node.money_refusals(), 0);

    fill(&journal);
    let why = journal.refuses_money().unwrap();
    let refusal = node
        .money_gate()
        .expect_err("a journal that cannot record money refuses the unit open");
    assert_eq!(refusal.status, 503);
    assert_eq!(
        refusal.code,
        busbar_plugin_abi::fail::failed::F_UNAVAILABLE,
        "durability_unavailable renders as the plane's unavailable failure"
    );
    assert_eq!(
        &*refusal.text,
        why.as_str(),
        "the old path's text: the journal's reason"
    );
    assert!(node.money_gate().is_err());
    assert_eq!(node.money_refusals(), 2, "every refused open is counted");

    node.retry_held_journal().await.unwrap();
    assert!(journal.refuses_money().is_none());
    assert!(
        node.money_gate().is_ok(),
        "the journal draining re-admits at once, before any tick"
    );
    node.close_money_episode(&journal);
    assert_eq!(node.money_refusals(), 2);
}

#[tokio::test]
async fn unit_open_is_refused_once_journal_staging_is_closed() {
    let (journal, node) = fixture(882).await;
    assert!(node.money_gate().is_ok());
    journal.stop_staging().unwrap();
    assert_eq!(node.money_gate().unwrap_err().status, 503);
}

#[test]
fn a_node_with_no_journal_bound_admits_as_the_old_path_did() {
    assert!(Node::new().money_gate().is_ok());
}
