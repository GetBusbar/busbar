// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALING-FIX r20 §3.6.1 (MR-5), own-node restart sealing on a same-holder re-take: a clean crash
//! leftover gets one `after_restart` page signed on the Bootstrap thread and staged before the
//! notary starts; a tail with no anchor gets a signed break notice, a finding and an alert; boot
//! never fails on either; a second walk finds nothing to seal.

use std::sync::{Arc, Mutex, OnceLock};

use busbar_kernel_audit::{
    break_from_journal_body, stamp_body, stamp_from_journal_body, AuditSigningKey,
    AuditVerifyingKey, BootstrapSigner, BreakReason, Fingerprint, LiveSigner, Notary as NotaryCap,
    Stamp, StampKind,
};
use busbar_kernel_wal::{Entry, RecordClass};

use super::{prepare_own_node, OwnSeal};
use crate::root::durability::tests::{audit_inputs, audit_pass, token, NativeFixture};
use crate::root::durability::{signer, Durability};

const SEED: [u8; 32] = [0x6a; 32];
const HOST: &str = "restart-seal-host";

fn public() -> AuditVerifyingKey {
    AuditVerifyingKey::from_hex(&AuditSigningKey::from_seed(&SEED).public_key_hex()).unwrap()
}

fn caps() -> (NotaryCap, BootstrapSigner) {
    let (notary, bootstrap) = AuditSigningKey::from_seed(&SEED)
        .into_grants(LiveSigner::SameAsBootstrap)
        .unwrap();
    (NotaryCap::new(notary), BootstrapSigner::new(bootstrap))
}

fn signers() -> signer::Signers {
    let (notary, bootstrap) = caps();
    signer::spawn(notary, bootstrap, Arc::new(OnceLock::new())).unwrap()
}

async fn seal_n(book: &Arc<Mutex<Durability>>, from: u64, n: u64) {
    for unit in from..from + n {
        Durability::seal_unit(book, audit_inputs(unit), audit_pass(), &token())
            .await
            .unwrap();
    }
}

/// Stage and confirm a `live` page over lines `from..=to` of `book`, as the notary would.
async fn live_page(book: &Arc<Mutex<Durability>>, from: u64, to: u64) {
    let (line, node, journal) = {
        let held = book.lock().unwrap();
        let line = held
            .audit_records()
            .iter()
            .find(|line| line.seq == to)
            .unwrap()
            .clone();
        (line, held.record.node(), held.journal.clone())
    };
    let (notary, _) = caps();
    let page = notary
        .sign_stamp(Stamp {
            node,
            from,
            to,
            fingerprint: Fingerprint::from_hex(&line.hash).unwrap(),
            kind: StampKind::Live,
            sealer: node,
            host: HOST.into(),
            every: 1,
            stamped_ms: line.linked_ms,
            down_from_ms: 0,
            down_to_ms: 0,
            crypto: String::new(),
            sig_alg: String::new(),
            key_id: String::new(),
            key_cert: 0,
            signature: Vec::new(),
        })
        .unwrap();
    let entry = Entry::new(RecordClass::Transaction, stamp_body(&page).unwrap())
        .at(page.stamped_ms / 1000, 0);
    let run = journal.stage_run(&[entry]).unwrap();
    journal.confirm(&run).await.unwrap();
}

async fn retake(fixture: &NativeFixture) -> (Durability, OwnSeal) {
    let mut book = fixture.reopen().await;
    let records = book.take_boot_records();
    let signers = signers();
    let (sealed, pending) =
        prepare_own_node(&mut book, &records, &signers.boot, &public(), HOST).await;
    assert!(pending.is_none());
    (book, sealed)
}

/// Test 5's clean counterpart: lines 1-6, a live page over 1-4, the process stops before stamping
/// 5-6. The re-take seals exactly 5-6 with one `after_restart` page under the deployment key,
/// sealer = the node itself, and a second re-take finds nothing to seal.
#[tokio::test]
async fn a_same_holder_retake_seals_its_own_crash_leftover() {
    let fixture = NativeFixture::new(61).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    seal_n(&book, 1, 4).await;
    live_page(&book, 1, 4).await;
    seal_n(&book, 5, 2).await;
    let journal = book.lock().unwrap().journal.clone();
    journal.flush().await.unwrap();

    let (reopened, sealed) = retake(&fixture).await;
    assert_eq!(sealed, OwnSeal::Sealed { from: 5, to: 6 });
    assert!(
        reopened.restart_findings.is_empty(),
        "{:?}",
        reopened.restart_findings
    );
    let records = fixture.reopen().await.take_boot_records();
    let pages: Vec<Stamp> = records
        .iter()
        .filter_map(|r| stamp_from_journal_body(&r.body).ok().flatten())
        .collect();
    let restart = pages
        .iter()
        .find(|p| p.kind == StampKind::AfterRestart)
        .expect("the restart page is in the node's journal");
    assert_eq!((restart.from, restart.to), (5, 6));
    assert_eq!(restart.sealer, restart.node);
    assert_eq!(restart.host, HOST);
    assert_eq!(restart.key_cert, 0);
    assert!(restart.down_from_ms <= restart.down_to_ms);
    restart
        .verify(&public())
        .expect("signed by the deployment key");

    let (_, again) = retake(&fixture).await;
    assert_eq!(
        again,
        OwnSeal::Nothing,
        "the restart page is the new anchor"
    );
}

/// Test 4(j) on the own node: link lines and no stamp at all. No restart page; a signed
/// `unanchored` break notice is staged, the finding is recorded, and the walk never fails boot.
#[tokio::test]
async fn an_unanchored_own_tail_is_recorded_broken_not_sealed() {
    let fixture = NativeFixture::new(62).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    seal_n(&book, 1, 3).await;
    let journal = book.lock().unwrap().journal.clone();
    journal.flush().await.unwrap();

    let (reopened, sealed) = retake(&fixture).await;
    let OwnSeal::Broken(at) = sealed else {
        panic!("expected a break, got {sealed:?}");
    };
    assert_eq!(at.reason, BreakReason::Unanchored);
    assert_eq!((at.last_good, at.unsealed_from, at.unsealed_to), (0, 1, 3));
    assert!(
        reopened
            .restart_findings
            .iter()
            .any(|f| f.contains("audit chain broken after line 0")),
        "{:?}",
        reopened.restart_findings
    );
    let records = fixture.reopen().await.take_boot_records();
    let notice = records
        .iter()
        .find_map(|r| break_from_journal_body(&r.body).ok().flatten())
        .expect("the break notice is in the node's journal");
    assert_eq!(notice.reason, BreakReason::Unanchored);
    notice
        .verify(&public())
        .expect("signed by the deployment key");
    assert!(records
        .iter()
        .filter_map(|r| stamp_from_journal_body(&r.body).ok().flatten())
        .all(|p| p.kind != StampKind::AfterRestart));
}

/// A fresh node (every production start takes one) has nothing to walk: nothing is signed or
/// staged, and no finding is recorded.
#[tokio::test]
async fn a_fresh_node_seals_nothing() {
    let fixture = NativeFixture::new(63).await;
    let (book, sealed) = retake(&fixture).await;
    assert_eq!(sealed, OwnSeal::Nothing);
    assert!(book.restart_findings.is_empty());
}

/// Failed confirmation retains the original restart/break run ahead of the boot certificate.
/// Retrying must confirm those same bytes, never append another terminal record.
#[tokio::test]
async fn failed_own_seal_confirmation_preserves_original_before_certificate() {
    use crate::root::durability::boot_jobs::{BootPreparation, PendingBootJob};
    use busbar_contract::crypto::{LocalSigner, Signer};
    use busbar_kernel_audit::notary_key::notary_key_from_journal_body;
    use std::sync::atomic::Ordering;

    for anchored in [false, true] {
        let fixture = NativeFixture::new(if anchored { 65 } else { 64 }).await;
        let book = Arc::new(Mutex::new(fixture.book().await));
        seal_n(&book, 1, 1).await;
        if anchored {
            live_page(&book, 1, 1).await;
        }
        seal_n(&book, 2, 1).await;
        let journal = book.lock().unwrap().journal.clone();
        journal.flush().await.unwrap();
        let mut reopened = fixture.reopen().await;
        let records = reopened.take_boot_records();
        let signers = signers();
        fixture.faults.refusing.store(true, Ordering::Release);
        let (_, pending) =
            super::prepare_own_node(&mut reopened, &records, &signers.boot, &public(), HOST).await;
        fixture.faults.refusing.store(false, Ordering::Release);
        let Some(PendingBootJob::Staged(original)) = pending else {
            panic!("failed confirmation must transfer its exact staged original");
        };
        let original_row = original.records()[0].clone();
        let reopened = Arc::new(Mutex::new(reopened));
        let delegated = LocalSigner::from_seed(&[0x45; 32]).unwrap();
        let mut boot = BootPreparation::new(
            signers.boot,
            reopened.clone(),
            vec![PendingBootJob::Staged(original)],
            Some(delegated.public_key().clone()),
        );
        let certificate_at = tokio::time::timeout(std::time::Duration::from_secs(5), boot.run())
            .await
            .unwrap()
            .unwrap();
        let journal = reopened.lock().unwrap().journal.clone();
        let rows = journal
            .read_records(crate::root::durability::tests::BUDGET)
            .await
            .unwrap();
        let terminals: Vec<_> = rows
            .iter()
            .filter(|row| {
                stamp_from_journal_body(&row.body)
                    .ok()
                    .flatten()
                    .is_some_and(|stamp| stamp.kind == StampKind::AfterRestart)
                    || break_from_journal_body(&row.body).ok().flatten().is_some()
            })
            .collect();
        assert_eq!(
            terminals.len(),
            1,
            "retry must not append another terminal record"
        );
        // The staged original holds wal `Record`s, the journal reads back `JournalRecord`s: the one
        // terminal is the original by its identity and its bytes.
        assert_eq!(
            (terminals[0].node, terminals[0].node_seq, &terminals[0].body),
            (original_row.node, original_row.node_seq, &original_row.body)
        );
        assert!(original_row.node_seq < certificate_at);
        assert_eq!(
            rows.iter()
                .filter(|row| {
                    notary_key_from_journal_body(&row.body)
                        .ok()
                        .flatten()
                        .is_some()
                })
                .count(),
            1
        );
        assert_eq!(boot.run().await.unwrap(), certificate_at);
    }
}
