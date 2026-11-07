// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::tests::seal;
use super::*;
use crate::root::durability::tests::NativeFixture;
use std::sync::{Arc, Mutex};
#[tokio::test]
async fn every_record_the_book_seals_names_this_node() {
    let node = 7;
    let fixture = NativeFixture::new(node).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    assert_eq!(book.lock().unwrap().record.node(), node);
    let before = seal(&book, 1..=2).await;
    assert!(before.iter().all(|r| r.node == node), "{before:?}");
    let restarted = fixture.reopen().await;
    assert_eq!(restarted.record.node(), node);
    assert_eq!(restarted.audit_window(1, 2).await, Some(before));
    let restarted = Arc::new(Mutex::new(restarted));
    let after = seal(&restarted, 3..=3).await;
    assert_eq!(after[0].node, node);
    let chain = restarted.lock().unwrap().chain_at();
    let window = chain.audit_window(1, 3).await.unwrap();
    assert!(AuditChain::verify_chain(&window).is_ok());
}
