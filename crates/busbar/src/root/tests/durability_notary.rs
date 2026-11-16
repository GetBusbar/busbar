// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALING-FIX r20 §9 tests 3, 33 and §5.3 layer 1: the notary stamps pages over linked lines,
//! parks when idle and wakes on the next line; the request path moves its record and signs
//! nothing; the book holds no signing capability.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use busbar_kernel_audit::{
    stamp_from_journal_body, AuditSigningKey, AuditVerifyingKey, BootstrapSigner, Fingerprint,
    LiveSigner, Notary as NotaryCap, Stamp, StampKind,
};

use crate::root::durability::notary::{spawn, NotaryConfig, NotaryTask};
use crate::root::durability::tests::{audit_inputs, audit_pass, token, NativeFixture};
use crate::root::durability::{signer, Durability};

const SEED: [u8; 32] = [0x5f; 32];

fn verifying_key() -> AuditVerifyingKey {
    AuditVerifyingKey::from_hex(&AuditSigningKey::from_seed(&SEED).public_key_hex()).unwrap()
}

/// A book over a fresh journal, and a running notary over it (`seal_every` = `every_ms`).
async fn notarised(every_ms: u64) -> (NativeFixture, Arc<Mutex<Durability>>, NotaryTask) {
    let fixture = NativeFixture::new(41).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let (notary, bootstrap) = AuditSigningKey::from_seed(&SEED)
        .into_grants(LiveSigner::SameAsBootstrap)
        .unwrap();
    let signers = signer::spawn(
        NotaryCap::new(notary),
        BootstrapSigner::new(bootstrap),
        Arc::new(OnceLock::new()),
    )
    .unwrap();
    let (journal, feed, start) = {
        let held = book.lock().unwrap();
        (
            held.journal.clone(),
            Arc::clone(&held.head),
            held.notary_start(),
        )
    };
    let task = spawn(
        NotaryConfig {
            node: journal.node(),
            host: "notary-test-host".into(),
            every_ms,
            key_cert: 0,
        },
        start,
        journal,
        feed,
        signers.live,
    );
    (fixture, book, task)
}

async fn seal_n(book: &Arc<Mutex<Durability>>, from: u64, n: u64) {
    for unit in from..from + n {
        Durability::seal_unit(book, audit_inputs(unit), audit_pass(), &token())
            .await
            .unwrap();
    }
}

async fn stamped_through(task: &NotaryTask, at_least: u64) -> u64 {
    for _ in 0..500 {
        let through = task
            .progress()
            .stamped_through
            .load(std::sync::atomic::Ordering::Relaxed);
        if through >= at_least {
            return through;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the notary did not stamp through line {at_least} within 5 s");
}

async fn stamps(book: &Arc<Mutex<Durability>>) -> Vec<Stamp> {
    let journal = book.lock().unwrap().journal.clone();
    journal.flush().await.unwrap();
    journal
        .read_records(busbar_kernel::persistence::journal::BufferBudget {
            records: 65_536,
            bytes: 64 * 1024 * 1024,
        })
        .await
        .unwrap()
        .iter()
        .filter_map(|record| stamp_from_journal_body(&record.body).unwrap())
        .collect()
}

/// Test 3, `page_stamp_covers_lines`: every line is covered by exactly one `live` page, pages are
/// contiguous and never overlap, each verifies under the bound key, and the last page's
/// fingerprint is line `to`'s hash.
#[tokio::test]
async fn page_stamp_covers_lines() {
    let (_fixture, book, task) = notarised(1).await;
    seal_n(&book, 1, 40).await;
    assert_eq!(stamped_through(&task, 40).await, 40);
    let end = task.stop().await.unwrap();
    assert_eq!(end.committed_through, 40);
    assert!(end.halted.is_none(), "{:?}", end.halted);
    let pages = stamps(&book).await;
    assert!(!pages.is_empty(), "at least one page was stamped");
    let key = verifying_key();
    let mut next = 1;
    for page in &pages {
        assert_eq!(page.kind, StampKind::Live);
        assert_eq!(
            page.from, next,
            "pages are contiguous and never overlap (G10)"
        );
        assert!(page.to >= page.from);
        assert_eq!(
            page.key_cert, 0,
            "the Bootstrap key signs with no certificate"
        );
        assert_eq!(page.every, 1);
        page.verify(&key)
            .expect("each page verifies under the bound key");
        next = page.to + 1;
    }
    assert_eq!(next, 41, "the pages cover lines 1..=40 exactly");
    let held = book.lock().unwrap();
    let last = held.audit_records().last().unwrap();
    assert_eq!(last.seq, 40);
    assert_eq!(
        Fingerprint::from_hex(&last.hash),
        Some(pages.last().unwrap().fingerprint),
        "the last page vouches for line 40's fingerprint"
    );
    let walk: Vec<_> = held
        .audit_records()
        .iter()
        .filter(|line| line.seq >= pages.last().unwrap().from)
        .cloned()
        .collect();
    pages
        .last()
        .unwrap()
        .covers(&walk)
        .expect("the page covers its walk");
}

/// An idle notary parks (no new pages without new lines) and the next line wakes it.
#[tokio::test]
async fn idle_notary_parks_and_wakes_on_the_next_line() {
    let (_fixture, book, task) = notarised(1).await;
    seal_n(&book, 1, 3).await;
    stamped_through(&task, 3).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    let before = stamps(&book).await.len();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        stamps(&book).await.len(),
        before,
        "nothing new, nothing stamped"
    );
    seal_n(&book, 4, 1).await;
    assert_eq!(stamped_through(&task, 4).await, 4, "the next line wakes it");
    let end = task.stop().await.unwrap();
    assert_eq!(end.committed_through, 4);
}

/// Test 33, `stage_line_moves_the_record`: the request path returns the line's hint (its chain
/// seq, the WAL `node_seq` of its run's record, its fingerprint), and the ring holds the record by
/// move; a v8 line carries no signature.
#[tokio::test]
async fn stage_line_moves_the_record() {
    let fixture = NativeFixture::new(42).await;
    let mut book = fixture.book().await;
    for unit in 1..=2_048u64 {
        let (line, run) = book
            .stage_line(audit_inputs(unit), audit_pass(), &token())
            .unwrap();
        assert_eq!(line.chain_seq, unit);
        assert_eq!(line.node_seq, run.records()[0].node_seq);
        let last = book.audit_records().last().unwrap();
        assert_eq!(last.seq, unit);
        assert_eq!(Fingerprint::from_hex(&last.hash), Some(line.fp));
        assert!(last.signature.is_none() && last.key_id.is_none());
        assert_eq!(
            book.head.head().seq,
            unit,
            "the head feed follows the chain"
        );
        assert_eq!(book.head.head().node_seq, line.node_seq);
    }
    assert_eq!(
        book.audit_records().len(),
        crate::root::durability::AUDIT_RING
    );
    book.journal.flush().await.unwrap();
}

/// §5.3 layer 1: the book's fields are all signer-free types. A new field fails this destructure
/// until it is listed, and listing a signing capability fails `NoSigner`.
#[test]
fn the_book_holds_no_signing_capability() {
    trait NoSigner {}
    impl NoSigner for u64 {}
    impl NoSigner for bool {}
    impl NoSigner for String {}
    impl NoSigner for busbar_kernel::persistence::journal::runtime::RuntimeJournal {}
    impl NoSigner for busbar_kernel::persistence::journal::BufferBudget {}
    impl NoSigner for busbar_kernel_audit::AuditChain {}
    impl NoSigner for crate::root::durability::AuditRing {}
    impl NoSigner for crate::root::durability::HeadFeed {}
    impl NoSigner for busbar_kernel::governance::GovState {}
    impl<T: NoSigner> NoSigner for Arc<T> {}
    impl<T: NoSigner> NoSigner for std::sync::Weak<T> {}
    impl<T: NoSigner> NoSigner for Option<T> {}
    impl<T: NoSigner> NoSigner for Vec<T> {}
    fn no_signer<T: NoSigner>(_: &T) {}
    #[expect(dead_code, reason = "compile-time field audit only")]
    fn audit(book: &Durability) {
        let Durability {
            journal,
            record,
            audit_ring,
            audit_findings,
            audit_signed_from,
            incarnation,
            restart_findings,
            voided_claims,
            amendments_through,
            history_budget,
            resumed,
            audit_hints,
            head,
            resumed_head_node_seq,
        } = book;
        no_signer(journal);
        no_signer(record);
        no_signer(audit_ring);
        no_signer(audit_findings);
        no_signer(audit_signed_from);
        no_signer(incarnation);
        no_signer(restart_findings);
        no_signer(voided_claims);
        no_signer(amendments_through);
        no_signer(history_budget);
        no_signer(resumed);
        no_signer(audit_hints);
        no_signer(head);
        no_signer(resumed_head_node_seq);
    }
}
