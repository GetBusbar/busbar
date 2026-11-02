// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, TryLockError};

use super::audit::tests::inputs;
use super::*;
use crate::root::store_double::RecordSlots;
use crate::root::units_admin::{AuditView, NodeAudit};

const NODE: u64 = 47;

const NOW: u64 = 1_700_000_000;

fn token() -> Grant<DurableWrite> {
    busbar_kernel_testkit::test_support::tokens::grant::<DurableWrite>()
}

/// What the probe saw: every scan the store answered, and those made while the book's lock was held.
#[derive(Default)]
struct Scans {
    all: AtomicUsize,
    locked: AtomicUsize,
}

impl Scans {
    fn assert_unlocked(&self, read: &str) {
        let all = self.all.load(Ordering::Acquire);
        assert!(all > 0, "{read} reads the chain the store keeps");
        assert_eq!(
            self.locked.load(Ordering::Acquire),
            0,
            "{read} scanned the store while holding the book's lock ({all} scans in all): every \
             unit's open, settle and seal waited on the store plugin for the whole chain"
        );
    }
}

fn node_over(
    slots: &RecordSlots,
    ready: impl FnOnce(&mut Durability),
) -> (Arc<Mutex<Durability>>, Arc<Scans>) {
    let lane = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    let mut durability = build_on_store(
        &DurabilityConfig {
            data_dir: Some(std::path::PathBuf::from("/dev/null/legacy-journal")),
        },
        NODE,
        lane,
        None,
    )
    .expect("the store reads back");
    ready(&mut durability);
    assert!(
        durability
            .lane()
            .expect("a journal over the store")
            .drain(std::time::Duration::from_secs(5)),
        "the store takes the seeded records before the read probe is armed"
    );
    let book = Arc::new(Mutex::new(durability));
    let scans = Arc::new(Scans::default());
    let (seen, held) = (Arc::clone(&scans), Arc::downgrade(&book));
    slots.on_scan(move || {
        seen.all.fetch_add(1, Ordering::AcqRel);
        let locked = match held.upgrade() {
            Some(book) => {
                let probe = book.try_lock();
                matches!(probe, Err(TryLockError::WouldBlock))
            }
            None => false,
        };
        if locked {
            seen.locked.fetch_add(1, Ordering::AcqRel);
        }
    });
    (book, scans)
}

fn seal(durability: &mut Durability, unit: u64) {
    durability
        .seal_unit(
            inputs(unit),
            busbar_kernel_testkit::test_support::tokens::pass(),
            &token(),
        )
        .expect("sealed");
}

fn audit_inputs(unit: u64) -> busbar_kernel_audit::AuditInputs {
    use busbar_contract::caps::{OriginKind, Outcome, UnitKey};
    use busbar_kernel_audit::{
        AuditInputs, Controls, FinishClass, OpClassId, OutcomeFacts, Subject, Usage, What,
    };
    AuditInputs {
        subject: Subject::PrincipalId(format!("pseudonym-{unit}")),
        what: What {
            unit_key: UnitKey::new(unit),
            incarnation: 0,
            op_class: OpClassId::new("chat.completion"),
            destination: None,
            parent: None,
            pre_hook_head: None,
            post_hook_head: None,
        },
        wall: NOW + unit,
        mono: unit * 1_000,
        origin: busbar_kernel_testkit::test_support::tokens::origin(OriginKind::Client),
        outcome: OutcomeFacts {
            unit_end: Outcome::Completed,
            step: None,
            finish: FinishClass::Complete,
            hook_failed: false,
            emission_delta: 0,
            stale_policy: false,
        },
        usage: Usage {
            lines: Vec::new(),
            tier_bp: 10_000,
            fee_count: 0,
            rate_card_version: 1,
            bucket_chain_ref: String::new(),
        },
        controls: Controls::default(),
        correlation_label: None,
    }
}

#[test]
fn the_verify_walk_scans_the_store_without_the_book_lock() {
    let slots = RecordSlots::new();
    let (book, scans) = node_over(&slots, |durability| seal(durability, 1));
    let findings = NodeAudit::new(Arc::clone(&book)).stored_chain_findings();
    assert!(findings.is_empty(), "{findings:?}");
    scans.assert_unlocked("the verify walk");
}

#[test]
fn an_audit_window_older_than_the_cache_scans_the_store_without_the_book_lock() {
    let slots = RecordSlots::new();
    let (book, scans) = node_over(&slots, |durability| {
        for unit in 1..=(AUDIT_RING as u64 + 5) {
            seal(durability, unit);
        }
    });
    let mut answered = None;
    NodeAudit::new(Arc::clone(&book)).read_window(1, 3, &mut |_, records| {
        answered = records.map(|records| records.iter().map(|r| r.seq).collect::<Vec<_>>());
    });
    assert_eq!(
        answered,
        Some(vec![1, 2, 3]),
        "the window is read off the chain"
    );
    scans.assert_unlocked("an audit window older than the cache");
}

#[test]
fn a_unit_sealed_while_a_window_reads_the_store_is_in_that_window() {
    let slots = RecordSlots::new();
    let (book, _scans) = node_over(&slots, |durability| {
        for unit in 1..=3 {
            seal(durability, unit);
        }
    });
    let sealed_meanwhile = Arc::new(AtomicBool::new(false));
    let (flag, held) = (Arc::clone(&sealed_meanwhile), Arc::downgrade(&book));
    slots.on_scan(move || {
        if flag.load(Ordering::Acquire) {
            return;
        }
        let Some(book) = held.upgrade() else {
            return;
        };
        let Ok(mut durability) = book.try_lock() else {
            return;
        };
        seal(&mut durability, 4);
        flag.store(true, Ordering::Release);
    });
    let mut answered = None;

    NodeAudit::new(Arc::clone(&book)).read_window(0, u64::MAX, &mut |chain, records| {
        answered = Some((
            records.map(|records| records.iter().map(|r| r.seq).collect::<Vec<_>>()),
            chain.heads().anchor_at(u64::MAX).map(|head| head.seq),
        ));
    });
    assert!(
        sealed_meanwhile.load(Ordering::Acquire),
        "a unit was sealed while the store was read: the read let go of the book's lock"
    );
    assert_eq!(
        answered,
        Some((Some(vec![1, 2, 3, 4]), Some(4))),
        "the window holds every record up to the head the read folds in"
    );
}
