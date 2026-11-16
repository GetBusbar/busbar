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

use crate::root::durability::notary::{NotaryConfig, NotaryTask};
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
    let task = notary_over(&book, every_ms);
    (fixture, book, task)
}

/// A running notary over `book` (`seal_every` = `every_ms`).
fn notary_over(book: &Arc<Mutex<Durability>>, every_ms: u64) -> NotaryTask {
    notary_over_clock(book, every_ms, None)
}

fn notary_over_clock(
    book: &Arc<Mutex<Durability>>,
    every_ms: u64,
    clock: Option<Arc<busbar_kernel::governance::drain::DrainClock>>,
) -> NotaryTask {
    notary_over_signer(book, every_ms, clock, LiveSigner::SameAsBootstrap)
}

fn notary_over_signer(
    book: &Arc<Mutex<Durability>>,
    every_ms: u64,
    clock: Option<Arc<busbar_kernel::governance::drain::DrainClock>>,
    live: LiveSigner,
) -> NotaryTask {
    let (notary, bootstrap) = AuditSigningKey::from_seed(&SEED).into_grants(live).unwrap();
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
    crate::root::durability::notary::spawn_with_floor(
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
        None,
        clock,
    )
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
    impl NoSigner for busbar_kernel_wal::JournalRecord {}
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
            boot_records,
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
        no_signer(boot_records);
    }
}

/// Journal rows held past the base once the notary's cut has caught up (polled for up to 5 s):
/// head − base, every row at or below the base being deleted by the cut that moved it.
async fn rows_past_base(
    journal: &busbar_kernel::persistence::journal::RuntimeJournal,
    bound: u64,
) -> u64 {
    let mut held = u64::MAX;
    for _ in 0..500 {
        let head = journal.ordinal_of(journal.next_seq().saturating_sub(1));
        held = head.saturating_sub(journal.base_count());
        if held <= bound {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    held
}

/// Test 30 (a), root part, `ephemeral_journal_is_bounded_after_n_requests` (SEALING-FIX §3.9):
/// N units sealed through `seal_unit` and confirmed, with the notary running (`seal_every: 1`) on
/// a store that reports `Durability::Ephemeral`. At N/2 and N the journal holds at most
/// `RETAIN_TAIL + 2 × CUT_BATCH` rows past a base that has moved, and the notary's stop reports
/// the cut settled. RSS is not asserted (receipts, §3.9 "Receipts").
#[tokio::test]
async fn ephemeral_journal_is_bounded_after_n_requests() {
    use busbar_kernel::persistence::journal::{RuntimeJournal, CUT_BATCH, RETAIN_TAIL};
    const N: u64 = 200_000;
    let budget = crate::root::durability::tests::BUDGET;
    let backend =
        crate::root::real_store::EphemeralInfo(crate::root::real_store::native_backend().await);
    let core = crate::root::real_store::core_over(Arc::new(backend)).await;
    let journal = RuntimeJournal::open(core, 43, budget).await.unwrap();
    assert!(journal.is_cut_capable());
    let book = Arc::new(Mutex::new(
        crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig::default(),
            43,
            journal.clone(),
            None,
            budget,
        )
        .await
        .unwrap(),
    ));
    let task = notary_over(&book, 1);
    let mut sealed = 0;
    for sample in [N / 2, N] {
        seal_n(&book, sealed + 1, sample - sealed).await;
        sealed = sample;
        stamped_through(&task, sample).await;
        let bound = RETAIN_TAIL + 2 * CUT_BATCH;
        let held = rows_past_base(&journal, bound).await;
        assert!(
            held <= bound,
            "{held} journal rows held past the base after {sample} units"
        );
        assert!(journal.base_count() > 0, "the base moved");
        assert!(journal.base_tail().is_some_and(|tail| tail.chain_seq > 0));
        let chain = book.lock().unwrap().chain_at();
        assert!(
            chain.read().await.unwrap().is_ok(),
            "the retained WAL is verified from its base, never as a new genesis"
        );
        let plan = book
            .lock()
            .unwrap()
            .prepare_audit_page(1, sample, None)
            .unwrap();
        let page: busbar_contract::json::Value =
            busbar_contract::json::from_slice(&plan.finish().await.unwrap()).unwrap();
        let base_seq = page["truncated_below_base"]["base_seq"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(base_seq > 0);
        assert_eq!(page["returned_from"], (base_seq + 1).to_string());
        assert!(page["gaps"].as_array().unwrap().is_empty());
    }
    let end = task.stop().await.unwrap();
    assert!(end.halted.is_none(), "{:?}", end.halted);
}

/// §3.9: stamp work continues during request drain, but the first broadcast admits no new cut.
#[tokio::test]
async fn first_shutdown_broadcast_stops_new_cuts_before_notary_stop() {
    use busbar_kernel::persistence::journal::{RuntimeJournal, CUT_BATCH, RETAIN_TAIL};
    let budget = crate::root::durability::tests::BUDGET;
    let backend =
        crate::root::real_store::EphemeralInfo(crate::root::real_store::native_backend().await);
    let core = crate::root::real_store::core_over(Arc::new(backend)).await;
    let journal = RuntimeJournal::open(core, 44, budget).await.unwrap();
    let book = Arc::new(Mutex::new(
        crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig::default(),
            44,
            journal.clone(),
            None,
            budget,
        )
        .await
        .unwrap(),
    ));
    let clock = busbar_kernel::governance::drain::DrainClock::new(Duration::from_secs(20));
    let task = notary_over_clock(&book, 1, Some(clock.clone()));
    clock.arm(tokio::time::Instant::now() + clock.budget());
    let count = RETAIN_TAIL + 3 * CUT_BATCH;
    seal_n(&book, 1, count).await;
    stamped_through(&task, count).await;
    assert_eq!(
        journal.base_count(),
        0,
        "stamp confirmation after the first broadcast cannot start a cut"
    );
    task.stop().await.unwrap();
    assert_eq!(
        journal.base_count(),
        0,
        "stop settles existing work but starts no new cut"
    );
}

/// A real signer with a forced 5 ms KMS round trip, on the detached signer thread.
struct SlowNotary {
    inner: busbar_contract::crypto::LocalSigner,
    signs: Arc<std::sync::atomic::AtomicU64>,
    paused: Arc<std::sync::atomic::AtomicBool>,
}
impl busbar_contract::crypto::Signer for SlowNotary {
    fn public_key(&self) -> &busbar_contract::crypto::PublicKey {
        busbar_contract::crypto::Signer::public_key(&self.inner)
    }
    fn sign(
        &self,
        msg: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), busbar_contract::crypto::SignError> {
        std::thread::sleep(Duration::from_millis(5));
        while self.paused.load(std::sync::atomic::Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        }
        self.signs
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        busbar_contract::crypto::Signer::sign(&self.inner, msg, out)
    }
}

/// Release even when a fixture assertion unwinds, so no detached test signer remains blocked.
struct SigningPause(Arc<std::sync::atomic::AtomicBool>);
impl Drop for SigningPause {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Test 30(g): non-audit originals make the WAL advance much faster than the audit chain.
/// The live cut must follow the stamp's WAL position, without passing its audit target.
#[tokio::test]
async fn interleaved_non_audit_rows_do_not_stop_the_retention_floor() {
    use busbar_kernel::persistence::journal::{RuntimeJournal, CUT_BATCH, RETAIN_TAIL};
    use busbar_kernel_wal::{Entry, RecordClass};
    let budget = crate::root::durability::tests::BUDGET;
    let backend =
        crate::root::real_store::EphemeralInfo(crate::root::real_store::native_backend().await);
    let core = crate::root::real_store::core_over(Arc::new(backend)).await;
    let journal = RuntimeJournal::open(core, 45, budget).await.unwrap();
    let book = Arc::new(Mutex::new(
        crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig::default(),
            45,
            journal.clone(),
            None,
            budget,
        )
        .await
        .unwrap(),
    ));
    let signs = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let pause = SigningPause(Arc::new(std::sync::atomic::AtomicBool::new(false)));
    let task = notary_over_signer(
        &book,
        1,
        None,
        LiveSigner::Delegated(Box::new(SlowNotary {
            inner: busbar_contract::crypto::LocalSigner::from_seed(&SEED).unwrap(),
            signs: signs.clone(),
            paused: pause.0.clone(),
        })),
    );
    let count = 3 * RETAIN_TAIL;
    let mut observed_unstamped = false;
    for unit in 1..=count {
        let other = journal
            .stage_run(&[
                Entry::new(RecordClass::Checkpoint, vec![1]),
                Entry::new(RecordClass::Checkpoint, vec![2]),
                Entry::new(RecordClass::Reconciliation, vec![3]),
            ])
            .unwrap();
        journal.confirm(&other).await.unwrap();
        drop(other);
        if unit % (CUT_BATCH / 4) == 0 {
            pause.0.store(true, std::sync::atomic::Ordering::Release);
        }
        seal_n(&book, unit, 1).await;
        if unit % (CUT_BATCH / 4) == 0 {
            let records = journal
                .read_records(busbar_kernel::persistence::journal::BufferBudget {
                    records: 65_536,
                    bytes: 64 * 1024 * 1024,
                })
                .await
                .unwrap();
            let readable: std::collections::BTreeSet<_> = records
                .iter()
                .filter(|record| record.class == RecordClass::Transaction)
                .filter_map(|record| {
                    busbar_kernel_audit::from_journal_body(
                        &record.body,
                        &busbar_kernel::Registration::meter_class,
                    )
                    .unwrap()
                })
                .map(|audit| audit.seq)
                .collect();
            // Read the confirmed frontier after the snapshot: a page confirmed during the read
            // may legitimately permit a later cut; every line still unstamped must be present.
            let stamped = task
                .progress()
                .stamped_through
                .load(std::sync::atomic::Ordering::Acquire);
            for sequence in stamped + 1..=unit {
                observed_unstamped = true;
                assert!(
                    readable.contains(&sequence),
                    "unstamped line {sequence} remains readable"
                );
            }
        }
        pause.0.store(false, std::sync::atomic::Ordering::Release);
        if unit > count / 3 && unit % (CUT_BATCH / 4) == 0 {
            stamped_through(&task, unit).await;
            let bound = RETAIN_TAIL + 2 * CUT_BATCH;
            assert!(
                rows_past_base(&journal, bound).await <= bound,
                "retention stays bounded even after WAL and chain seq drift apart"
            );
            if let Some(base) = journal.base_tail() {
                assert!(
                    base.chain_seq
                        <= task
                            .progress()
                            .stamped_through
                            .load(std::sync::atomic::Ordering::Relaxed()),
                    "no cut passes the newest durable stamp's audit target"
                );
            }
        }
    }
    assert!(
        observed_unstamped,
        "the delayed signer leaves a measurable unstamped tail"
    );
    stamped_through(&task, count).await;
    let base = journal.base_tail().unwrap();
    assert!(base.node_seq - base.chain_seq >= 3 * RETAIN_TAIL);
    assert!(
        base.node_seq
            <= task
                .progress()
                .stamped_node_seq
                .load(std::sync::atomic::Ordering::Acquire)
    );
    assert!(signs.load(std::sync::atomic::Ordering::Acquire) > 1);

    task.stop().await.unwrap();
}

/// Test 6, `clean_shutdown_stamps_final_page` (notary half, §3.6.3 step 3): lines left unstamped at
/// stop get one `final` page from `committed_through + 1` to the head, made by the notary task
/// itself on the notary signer thread, staged before the journal's final flush; pages stay
/// contiguous and never overlap. A notary stopped with nothing unstamped makes no final page.
#[tokio::test]
async fn clean_stop_stamps_a_final_page() {
    let fixture = NativeFixture::new(43).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    seal_n(&book, 1, 12).await;
    let (notary, bootstrap) = AuditSigningKey::from_seed(&SEED)
        .into_grants(LiveSigner::SameAsBootstrap)
        .unwrap();
    let signers = signer::spawn(
        NotaryCap::new(notary),
        BootstrapSigner::new(bootstrap),
        Arc::new(OnceLock::new()),
    )
    .unwrap();
    let (journal, feed) = {
        let held = book.lock().unwrap();
        (held.journal.clone(), Arc::clone(&held.head))
    };
    // Spawned and stopped before its first poll (current-thread runtime): no live page is ever
    // signed, so the whole tail is the final page.
    let task = crate::root::durability::notary::spawn_with_floor(
        NotaryConfig {
            node: journal.node(),
            host: "notary-test-host".into(),
            every_ms: 1,
            key_cert: 0,
        },
        crate::root::durability::notary::NotaryStart::default(),
        journal,
        feed,
        signers.live,
        None,
        None,
    );
    let end = task.stop().await.unwrap();
    assert_eq!(end.final_staged, Some(true));
    assert_eq!(end.committed_through, 12);
    let pages = stamps(&book).await;
    assert_eq!(pages.len(), 1, "{pages:?}");
    let last = &pages[0];
    assert_eq!(last.kind, StampKind::Final);
    assert_eq!((last.from, last.to), (1, 12));
    last.verify(&verifying_key())
        .expect("the final page verifies under the bound key");
    let held = book.lock().unwrap();
    assert_eq!(
        Fingerprint::from_hex(&held.audit_records().last().unwrap().hash),
        Some(last.fingerprint)
    );
    drop(held);

    // Nothing unstamped: no final page.
    let (_fixture, quiet, task) = notarised(1).await;
    seal_n(&quiet, 1, 3).await;
    stamped_through(&task, 3).await;
    let end = task.stop().await.unwrap();
    assert_eq!(end.final_staged, None);
    assert!(stamps(&quiet)
        .await
        .iter()
        .all(|page| page.kind == StampKind::Live));
}

#[tokio::test]
async fn final_page_is_not_staged_after_the_seal_cut() {
    let fixture = NativeFixture::new(46).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    seal_n(&book, 1, 12).await;
    let clock = busbar_kernel::governance::drain::DrainClock::new(Duration::from_secs(20));
    clock.arm(tokio::time::Instant::now());
    let task = notary_over_clock(&book, 1, Some(clock));
    let end = task.stop().await.unwrap();
    assert_eq!(end.final_staged, Some(false));
    assert!(
        stamps(&book).await.is_empty(),
        "a detached notary cannot stage a page after C3"
    );
}
