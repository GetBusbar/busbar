// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALING-FIX r20 §3.6.2 (MR-5): the predecessor sealer's own rules that need no second process.

use std::sync::Arc;

use busbar_kernel_audit::{BreakReason, TailItem, WalkOutcome};

use super::{budget_break, run, SealerDone};
use crate::root::durability::tests::{audit_inputs, audit_pass, token, NativeFixture};

/// A walk that keeps more lines than its budget without an anchor stops with a `budget` break over
/// exactly the walked range, never a restart page.
#[tokio::test]
async fn a_walk_over_budget_is_a_budget_break_over_the_walked_range() {
    let fixture = NativeFixture::new(71).await;
    let mut book = fixture.book().await;
    for unit in 1..=5u64 {
        book.stage_line(audit_inputs(unit), audit_pass(), &token())
            .unwrap();
    }
    let items: Vec<TailItem> = book
        .audit_records()
        .iter()
        .enumerate()
        .map(|(i, record)| TailItem::Line {
            record: record.clone(),
            node_seq: 100 + i as u64,
        })
        .collect();
    let WalkOutcome::Break(at) = budget_break(&items[1..]) else {
        panic!("a budget break");
    };
    assert_eq!(at.reason, BreakReason::Budget);
    assert_eq!((at.last_good, at.unsealed_from, at.unsealed_to), (1, 2, 5));
    assert_eq!((at.journal_from, at.journal_to), (101, 104));
    book.journal.flush().await.unwrap();
}

/// With no deployment key or Bootstrap handle (a keyless book) the task seals nothing and runs
/// only SHUTDOWN-HANG F5; a stop flag already set ends it before F5.
#[tokio::test]
async fn a_keyless_task_seals_nothing_and_stops_at_the_flag() {
    let fixture = NativeFixture::new(72).await;
    let fence = busbar_kernel::persistence::boot_identity::PredecessorFence::new(
        Arc::clone(&fixture.core),
        "predecessor-test-host",
    )
    .unwrap();
    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    stop_tx.send(true).unwrap();
    let done = run(fence, None, None, stop).await;
    assert_eq!(done, SealerDone::default());
}

/// A real signature is insufficient when a store writer transplants a live page into a
/// predecessor row or relabels its unsigned outer sealer (SEALING-FIX §3.6.2, #364).
#[tokio::test]
async fn a_present_seal_row_binds_its_outcome_kind_and_sealer() {
    use super::{PredecessorInputs, Sealer};
    use crate::root::durability::signer;
    use busbar_kernel::persistence::boot_identity::{PredecessorFence, SealOutcome, SealRow};
    use busbar_kernel_audit::{
        stamp_body, AuditSigningKey, AuditVerifyingKey, BootstrapSigner, Fingerprint, LiveSigner,
        Notary, Stamp, StampKind,
    };
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;

    let fixture = NativeFixture::new(73).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let seed = [0x62; 32];
    let key_hex = AuditSigningKey::from_seed(&seed).public_key_hex();
    let key = AuditVerifyingKey::from_hex(&key_hex).unwrap();
    let (live, boot) = AuditSigningKey::from_seed(&seed)
        .into_grants(LiveSigner::SameAsBootstrap)
        .unwrap();
    let live = Notary::new(live);
    let boot = BootstrapSigner::new(boot);
    let page = Stamp {
        node: 11,
        from: 1,
        to: 2,
        fingerprint: Fingerprint([0x31; 32]),
        kind: StampKind::AfterRestart,
        sealer: 12,
        host: "seal-row-test".into(),
        every: 1,
        stamped_ms: 100,
        down_from_ms: 90,
        down_to_ms: 100,
        crypto: String::new(),
        sig_alg: String::new(),
        key_id: String::new(),
        key_cert: 0,
        signature: Vec::new(),
    };
    let restart = boot.sign_restart_page(page.clone()).unwrap();
    let mut live_page = page;
    live_page.kind = StampKind::Live;
    live_page.sealer = live_page.node;
    live_page.down_from_ms = 0;
    live_page.down_to_ms = 0;
    let live_page = live.sign_stamp(live_page).unwrap();
    let handles = signer::spawn(live, boot, Arc::new(OnceLock::new())).unwrap();
    let (_stop_tx, stop) = tokio::sync::watch::channel(false);
    let mut sealer = Sealer {
        fence: PredecessorFence::new(Arc::clone(&fixture.core), "seal-row-test").unwrap(),
        inputs: PredecessorInputs {
            own: 12,
            taken_at_ms: 100,
            key_hex,
        },
        key,
        host: "seal-row-test".into(),
        handle: handles.boot,
        book: Some(Arc::clone(&book)),
        stop,
        alerted: Default::default(),
        done: Default::default(),
        listed_ms: 100,
        listed_at: Instant::now(),
    };
    for (row, accepted) in [
        (
            SealRow {
                sealer: 12,
                outcome: SealOutcome::Stamp(stamp_body(&restart).unwrap()),
            },
            true,
        ),
        (
            SealRow {
                sealer: 99,
                outcome: SealOutcome::Stamp(stamp_body(&restart).unwrap()),
            },
            false,
        ),
        (
            SealRow {
                sealer: 11,
                outcome: SealOutcome::Stamp(stamp_body(&live_page).unwrap()),
            },
            false,
        ),
    ] {
        book.lock().unwrap().restart_findings.clear();
        sealer.check_row(11, &row.bytes());
        assert_eq!(
            book.lock().unwrap().restart_findings.is_empty(),
            accepted,
            "{row:?}"
        );
    }
}
