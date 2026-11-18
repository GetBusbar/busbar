// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALING-FIX r20 §3.6.2 (MR-5): the predecessor sealer's own rules that need no second process.

use std::sync::Arc;

use busbar_kernel_audit::{BreakReason, TailItem, WalkOutcome};

use super::{run, SealerDone};
use crate::root::durability::tests::{audit_inputs, audit_pass, token, NativeFixture};

/// A changed fence mark must not discard a predecessor for the lifetime of the process.
/// Missing/listed marks require a fresh walk; an open mark from a sibling seal reuses the
/// already signed normal outcome (§3.6.2, decision193).
#[test]
fn lost_seal_comparisons_restart_when_the_fence_mark_changed_meaning() {
    use super::{after_lost_seal, LostSeal};
    use busbar_kernel::persistence::boot_identity::{FenceMark, SealState};
    let mut state = SealState::default();
    assert_eq!(after_lost_seal(7, &state, true), LostSeal::Restart);
    state.mark = Some(FenceMark {
        lease_expires_ms: 1,
        sealed: vec![7],
    });
    assert_eq!(after_lost_seal(7, &state, true), LostSeal::Restart);
    state.mark = Some(FenceMark {
        lease_expires_ms: 1,
        sealed: vec![8],
    });
    assert_eq!(after_lost_seal(7, &state, true), LostSeal::RetrySigned);
    assert_eq!(after_lost_seal(7, &state, false), LostSeal::Restart);
    state.row = Some(busbar_contract::secure::SecureVec::from(vec![1]));
    assert_eq!(after_lost_seal(7, &state, true), LostSeal::ExistingRow);
}

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
            record: Box::new(record.clone()),
            node_seq: 100 + i as u64,
        })
        .collect();
    let key = busbar_kernel_audit::AuditVerifyingKey::from_hex(
        &busbar_kernel_audit::AuditSigningKey::from_seed(&[0x63; 32]).public_key_hex(),
    )
    .unwrap();
    let cx = busbar_kernel_audit::WalkContext {
        node: 71,
        host: "host",
        key: &key,
        complete: false,
    };
    let mut walk = busbar_kernel_audit::restart::BackwardWalk::default();
    for item in items[1..].iter().rev() {
        assert_eq!(walk.push(item, &cx), WalkOutcome::NeedMore);
    }
    let WalkOutcome::Break(at) = walk.budget_break() else {
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

/// The assignment can name an older writer than the journal owner. Both must be fenced,
/// and the journal owner/head must be reread after the second fence before signing (§3.6.2).
#[tokio::test]
async fn a_successor_rereads_the_journal_after_fencing_a_different_owner() {
    use super::{PredecessorInputs, Sealer};
    use crate::root::durability::tests::BUDGET;
    use crate::root::durability::{signer, Durability};
    use busbar_contract::persistence::{Candidate, Decision, Mutation, PreparedCandidate};
    use busbar_kernel::persistence::{
        boot_identity::{BootIdentity, PredecessorFence, SealOutcome, SealRow},
        journal::RuntimeJournal,
    };
    use busbar_kernel_audit::{
        stamp_body, stamp_from_journal_body, AuditSigningKey, AuditVerifyingKey, BootstrapSigner,
        Fingerprint, LiveSigner, Notary, Stamp, StampKind,
    };
    use busbar_kernel_wal::{Entry, RecordClass};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, OnceLock,
    };
    use std::time::Instant;
    let (backend, advance_clock) = crate::root::real_store::clocked_native_backend();
    let faults = crate::root::store_double::NativeFaults::over(backend);
    let core_a = crate::root::real_store::core_over(faults.clone()).await;
    let identity_a = Arc::new(BootIdentity::new(core_a.clone()).unwrap());
    let node_a = identity_a.take_node("owner-reread").await.unwrap();
    let authority_a = core_a.authority().unwrap();
    let journal = RuntimeJournal::open(core_a.clone(), node_a.id, BUDGET)
        .await
        .unwrap();
    let fixture = NativeFixture {
        faults: faults.clone(),
        core: core_a,
        journal: journal.clone(),
    };
    let book = Arc::new(Mutex::new(fixture.book().await));
    let seed = [0x64; 32];
    let key_hex = AuditSigningKey::from_seed(&seed).public_key_hex();
    let key = AuditVerifyingKey::from_hex(&key_hex).unwrap();
    let (live, boot) = AuditSigningKey::from_seed(&seed)
        .into_grants(LiveSigner::SameAsBootstrap)
        .unwrap();
    let live = Notary::new(live);
    let boot = BootstrapSigner::new(boot);
    let line = Durability::seal_unit(&book, audit_inputs(1), audit_pass(), &token())
        .await
        .unwrap();
    let page = live
        .sign_stamp(Stamp {
            node: node_a.id,
            from: 1,
            to: 1,
            fingerprint: Fingerprint::from_hex(&line.hash).unwrap(),
            kind: StampKind::Live,
            sealer: node_a.id,
            host: "owner-reread".into(),
            every: 1,
            stamped_ms: line.linked_ms,
            down_from_ms: 0,
            down_to_ms: 0,
            crypto: String::new(),
            sig_alg: String::new(),
            key_id: String::new(),
            key_cert: 0,
            signature: vec![],
        })
        .unwrap();
    let run = journal
        .stage_run(&[Entry::new(
            RecordClass::Transaction,
            stamp_body(&page).unwrap(),
        )])
        .unwrap();
    journal.confirm(&run).await.unwrap();
    Durability::seal_unit(&book, audit_inputs(2), audit_pass(), &token())
        .await
        .unwrap();
    journal.flush().await.unwrap();

    // A second admitted writer owns the journal; the original host assignment is unchanged.
    let core_c = crate::root::real_store::core_over(faults.clone()).await;
    Arc::new(BootIdentity::new(core_c.clone()).unwrap())
        .take_node("owner-other")
        .await
        .unwrap();
    let authority_c = core_c.authority().unwrap();
    let (mut id, address) = faults
        .requests
        .lock()
        .unwrap()
        .iter()
        .find_map(|request| {
            request.candidate().mutations.iter().find_map(|mutation| {
                let Mutation::Put { address, .. } = mutation else {
                    return None;
                };
                (address.key.get(24) == Some(&b'O')
                    && address.key.get(16..24) == Some(node_a.id.to_be_bytes().as_slice()))
                .then(|| (request.candidate().id, address.clone()))
            })
        })
        .unwrap();
    id.operation = busbar_kernel::door::op_id().0;
    let owner = [
        b"BBJOWN01".as_slice(),
        &authority_c.writer_epoch.to_le_bytes(),
        &authority_c.writer,
    ]
    .concat();
    let changed = PreparedCandidate::new(Candidate {
        id,
        codec: 1,
        predicates: vec![],
        mutations: vec![Mutation::Put {
            address,
            value: busbar_contract::Secret::new(owner),
        }],
        time: None,
        result: busbar_contract::Secret::default(),
    })
    .unwrap();
    let commit_key = busbar_contract::persistence::CommitKey::slotted(
        0,
        1,
        &busbar_contract::caps::SlotSeal::acquire_for_tests(),
    )
    .unwrap();
    assert!(matches!(
        faults.actual.commit(changed, commit_key).await.unwrap(),
        Decision::Applied(_)
    ));
    advance_clock(30);

    let core_b = crate::root::real_store::core_over(faults.clone()).await;
    let node_b = Arc::new(BootIdentity::new(core_b.clone()).unwrap())
        .take_node("owner-reread")
        .await
        .unwrap();
    assert_ne!(node_a.id, node_b.id);
    let fence = PredecessorFence::new(core_b, "owner-reread").unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let observed = reads.clone();
    let old_node = node_a.id;
    *faults.on_read.lock().unwrap() = Some(Arc::new(move |request| {
        if request.addresses.iter().any(|address| {
            address.key.get(24) == Some(&b'O')
                && address.key.get(16..24) == Some(old_node.to_be_bytes().as_slice())
        }) {
            observed.fetch_add(1, Ordering::SeqCst);
        }
        Box::pin(async { Ok(()) })
    }));
    let handles = signer::spawn(live, boot, Arc::new(OnceLock::new())).unwrap();
    let (_stop_tx, stop) = tokio::sync::watch::channel(false);
    let mut sealer = Sealer {
        fence: fence.clone(),
        inputs: PredecessorInputs {
            own: node_b.id,
            taken_at_ms: node_b.taken_at_ms,
            key_hex,
        },
        key,
        host: "owner-reread".into(),
        handle: handles.boot,
        book: None,
        stop,
        alerted: Default::default(),
        done: Default::default(),
        listed_ms: 0,
        listed_at: Instant::now(),
    };
    sealer.seal_all().await;
    assert!(
        reads.load(Ordering::SeqCst) >= 2,
        "a changed owner must be reread after its fence"
    );
    let state = fence
        .seal_state(node_a.id, authority_a.writer_epoch, authority_a.writer)
        .await
        .unwrap();
    let row = SealRow::parse(state.row.as_deref().expect("the predecessor was sealed")).unwrap();
    let SealOutcome::Stamp(body) = row.outcome else {
        panic!("clean crash tail must receive a restart stamp")
    };
    let stamp = stamp_from_journal_body(&body).unwrap().unwrap();
    assert_eq!((stamp.from, stamp.to, stamp.sealer), (2, 2, node_b.id));
    stamp.verify(&sealer.key).unwrap();
}
