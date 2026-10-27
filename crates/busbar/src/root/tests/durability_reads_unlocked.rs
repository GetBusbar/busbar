// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN READS SCAN THE STORE WITHOUT THE BOOK'S LOCK (audit root B-5, row 159). A node with no
//! data directory keeps its chain in the configured store, and a read of the whole chain scans it
//! through the store plugin, one wait per block of 256 sequence numbers. The book's lock is the one
//! every unit's open, settle and seal takes on the request path, so a read that held it across the
//! scan stalled all serving for as long as the chain took to read, and longer as the chain grew
//! (`docs/design/BUSBAR-1.6.0.md:1285`, THE DESIGN §11.2: no blocking on the hot path; l.2182,
//! Part 2 #5: admin is off the hot path). Each read takes what it needs under the lock and reads the
//! store after letting go of it. A probe on the store double counts every scan, and every scan made
//! while the lock was held.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, TryLockError};

use super::audit::tests::inputs;
use super::*;
use crate::root::store_double::RecordSlots;
use crate::root::units_admin::{AuditView, LedgerView, NodeAudit, NodeLedger};

/// The node the store-kept chain is written under.
const NODE: u64 = 47;

/// Wall seconds the tests run at.
const NOW: u64 = 1_700_000_000;

fn token() -> Grant<DurableWrite> {
    busbar_kernel::test_support::tokens::grant::<DurableWrite>()
}

/// What the probe saw: every scan the store answered, and those made while the book's lock was held.
#[derive(Default)]
struct Scans {
    all: AtomicUsize,
    locked: AtomicUsize,
}

impl Scans {
    /// `read` went to the store, and never with the book's lock held.
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

/// A book with NO DATA DIRECTORY over `slots`, as `root::boot::compose_book` builds it, made ready by
/// `ready` and put behind the lock a settlement takes. From then on every scan of the store is
/// counted, and counted again when that lock is held.
fn node_over(
    slots: &RecordSlots,
    ready: impl FnOnce(&mut Durability),
) -> (Arc<Mutex<Durability>>, Arc<Scans>) {
    let lane = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    let mut durability = build_on_store(
        &DurabilityConfig { data_dir: None },
        NODE,
        lane,
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
        Box::new(|| None),
        None,
    )
    .expect("the store reads back");
    ready(&mut durability);
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

/// The ledger views over `book`.
fn ledger_over(book: &Arc<Mutex<Durability>>) -> NodeLedger {
    NodeLedger::new(
        Arc::clone(book),
        Arc::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
    )
}

/// Seal checkpoint 1.
fn sealed_once(durability: &mut Durability) {
    let sealed = durability
        .seal_checkpoint(&token(), StepName::Meter, NOW)
        .expect("sealed");
    assert_eq!(sealed.checkpoint_seq, 1);
}

/// Seal unit `unit`'s one audit record.
fn seal(durability: &mut Durability, unit: u64) {
    durability
        .seal_unit(
            inputs(unit),
            busbar_kernel::test_support::tokens::pass(),
            &token(),
        )
        .expect("sealed");
}

/// THE CHECKPOINTS READ scans the store without the book's lock, and still serves the held
/// checkpoint re-derived from the whole chain (`docs/design/BUSBAR-1.6.0.md:1285`).
///
/// RED before the fix: `NodeLedger::each_checkpoint` re-derived the checkpoints under the lock, and
/// `Durability::chain` scanned the store there.
#[test]
fn the_checkpoints_read_scans_the_store_without_the_book_lock() {
    let slots = RecordSlots::new();
    let (book, scans) = node_over(&slots, sealed_once);
    let mut served = Vec::new();
    ledger_over(&book)
        .each_checkpoint(&mut |checkpoint| served.push(checkpoint.checkpoint_seq))
        .expect("the held checkpoint re-derives");
    assert_eq!(served, vec![1], "the held checkpoint is served");
    scans.assert_unlocked("the checkpoints read");
}

/// BOTH VERIFY READS scan the store without the book's lock, and still answer the held checkpoint,
/// the book and the anchor's head as of one moment (`docs/design/BUSBAR-1.6.0.md:1285`).
///
/// RED before the fix: `verify_snapshot` and `verify_snapshot_anchored` re-derived the checkpoints
/// under the lock they read the book under.
#[test]
fn the_verify_reads_scan_the_store_without_the_book_lock() {
    let slots = RecordSlots::new();
    let (book, scans) = node_over(&slots, sealed_once);
    let view = ledger_over(&book);
    let mut served = Vec::new();
    let plain = view.verify_snapshot(&mut |checkpoint| served.push(checkpoint.checkpoint_seq));
    assert!(plain.read.is_ok(), "the held checkpoint re-derives");
    assert!(plain.book.is_some(), "the book is read");
    let anchored =
        view.verify_snapshot_anchored(&mut |checkpoint| served.push(checkpoint.checkpoint_seq));
    assert!(anchored.read.is_ok(), "the held checkpoint re-derives");
    assert_eq!(
        anchored.anchored.map(|head| head.checkpoint_seq),
        Some(1),
        "the anchor's head is the checkpoint sealed"
    );
    assert_eq!(served, vec![1, 1], "each read serves the held checkpoint");
    scans.assert_unlocked("the verify reads");
}

/// THE MIGRATION READ scans the store without the book's lock, and still answers the marker on the
/// chain (`docs/design/BUSBAR-1.6.0.md:1285`).
///
/// RED before the fix: `NodeLedger::migration_marker` read the whole chain under the lock.
#[test]
fn the_migration_read_scans_the_store_without_the_book_lock() {
    let marker = MigrationMarker {
        checkpoint_seq: 1,
        node: NODE,
        sealed_at: NOW,
        body_hash: [7; 32],
        balances: 2,
        cells_read: 3,
        rate_card_version: 1,
    };
    let slots = RecordSlots::new();
    let (book, scans) = node_over(&slots, |durability| {
        let entry = Entry::new(RecordClass::Migration, migration_body(&marker)).at(NOW, 0);
        durability
            .journal
            .append(&token(), StepName::Meter, &[entry])
            .expect("the marker goes on the chain");
    });
    assert_eq!(
        ledger_over(&book).migration_marker(),
        Some(marker),
        "the marker on the chain is answered"
    );
    scans.assert_unlocked("the migration read");
}

/// THE `adjust` VERB'S LOOKUP of what the book recorded scans the store without the book's lock
/// (`docs/design/BUSBAR-1.6.0.md:1285`).
///
/// RED before the fix: `NodeLedger::recorded_counts` replayed the whole chain under the lock.
#[test]
fn the_adjust_lookup_scans_the_store_without_the_book_lock() {
    let slots = RecordSlots::new();
    let (book, scans) = node_over(&slots, |_| {});
    assert_eq!(
        ledger_over(&book).recorded_counts(&"ab".repeat(32)),
        None,
        "the chain holds no such entry"
    );
    scans.assert_unlocked("the adjust verb's lookup");
}

/// AN AUDIT WINDOW OLDER THAN THE CACHE scans the store without the book's lock, and still answers
/// the window off the chain (`docs/design/BUSBAR-1.6.0.md:1285`).
///
/// RED before the fix: `NodeAudit::read_window` read the window back off the chain under the lock.
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

/// A UNIT SEALED WHILE AN AUDIT WINDOW READS THE STORE IS IN THAT WINDOW, and the anchor the range
/// read folds in is the head after it: the records and the anchor still answer as of one moment
/// (`AuditView::read`), though the store is read between the two holds of the lock.
///
/// RED before the fix: the window was read with the lock held, so no unit could be sealed while the
/// store was read.
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
    // From 0, before the first position: the cache does not cover it, so the chain is read.
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
