// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 7: the `/audit` feed reads the ring by `seq`, strictly after a cursor.

use super::*;

fn append(log: &PlaneAuditLog, seq: u64, action: &str) {
    log.push_entry(
        AuditEntry {
            seq,
            ts: seq,
            action: action.into(),
            resource: "r".into(),
            outcome: "applied".into(),
            principal: "test".into(),
            prev_hash: String::new(),
            hash: seq.to_string(),
            scheme: crate::audit_ring::AUDIT_SCHEME_PIPE,
            recorded_here: false,
        },
        "admin",
        Vec::new(),
        false,
    );
}

fn query<'a>(after: Option<u64>, descending: bool, actions: &'a [&'a str]) -> AuditQuery<'a> {
    AuditQuery {
        after,
        descending,
        limit: 100,
        actions,
        resource: None,
    }
}

fn seqs(page: &crate::audit_ring::AuditPage) -> Vec<u64> {
    page.items.iter().map(|e| e.seq).collect()
}

#[test]
fn audit_action_filter_exact_and_noun() {
    let log = PlaneAuditLog::new();
    append(&log, 1, "hook.register");
    append(&log, 2, "hook.delete");
    append(&log, 3, "hooks.other");
    append(&log, 4, "key.mint");
    let exact = log
        .list_after(&query(None, false, &["hook.delete"]))
        .unwrap();
    assert_eq!(seqs(&exact), vec![2], "a dotted entry matches exactly");
    let noun = log.list_after(&query(None, false, &["hook"])).unwrap();
    assert_eq!(
        seqs(&noun),
        vec![1, 2],
        "a bare noun matches its family only"
    );
    let csv = log
        .list_after(&query(None, false, &["hook", "key.mint"]))
        .unwrap();
    assert_eq!(seqs(&csv), vec![1, 2, 4]);
}

#[test]
fn audit_keyset_resumes_strictly_after_and_never_skips() {
    let log = PlaneAuditLog::new();
    for seq in 1..=5 {
        append(&log, seq, "hook.register");
    }
    let asc = log.list_after(&query(Some(2), false, &[])).unwrap();
    assert_eq!(seqs(&asc), vec![3, 4, 5]);
    assert!(
        asc.complete,
        "an ascending read that reached the tail is caught up"
    );
    append(&log, 6, "hook.register");
    let more = log.list_after(&query(Some(5), false, &[])).unwrap();
    assert_eq!(
        seqs(&more),
        vec![6],
        "an append between pages is not skipped or repeated"
    );
    let desc = log.list_after(&query(Some(4), true, &[])).unwrap();
    assert_eq!(seqs(&desc), vec![3, 2, 1]);
    assert!(!desc.truncated, "a descending list terminates");
    assert_eq!(desc.semantics, "keyset");
}

#[test]
fn audit_cursor_below_the_ring_is_expired() {
    let log = PlaneAuditLog::new();
    for seq in 1..=(MAX_AUDIT_ENTRIES as u64 + 10) {
        append(&log, seq, "hook.register");
    }
    let oldest = 11;
    assert_eq!(
        log.list_after(&query(Some(3), false, &[])).err(),
        Some(oldest - 1),
        "rows between the cursor and the ring were evicted"
    );
    assert!(log.list_after(&query(Some(oldest - 1), false, &[])).is_ok());
    assert!(
        log.list_after(&query(Some(3), true, &[])).is_ok(),
        "a descending list just ends"
    );
}

#[tokio::test]
async fn audit_wait_wakes_on_mutation() {
    let log = std::sync::Arc::new(PlaneAuditLog::new());
    let waiter = log.clone();
    let woke = tokio::spawn(async move {
        let notified = waiter.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        tokio::time::timeout(std::time::Duration::from_secs(5), notified)
            .await
            .is_ok()
    });
    tokio::task::yield_now().await;
    append(&log, 1, "hook.register");
    assert!(woke.await.unwrap(), "an append pulses the waiting feed");
}
