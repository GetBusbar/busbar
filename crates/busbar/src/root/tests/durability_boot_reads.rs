// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STORE THAT STOPS READING THE JOURNAL BACK is never taken for an empty chain (audit R1#3, row
//! 159). A node with no data directory keeps its chain in the configured store; the boot reads it
//! once to rebuild the book, and the boot steps after that read it again. When that second read
//! fails, the amendment rebuild, the keyset binding and the checkpoint numbering must not go on as
//! if the chain held nothing, and an audit window must not be answered as empty.

use super::*;
use crate::root::store_double::RecordSlots;

/// The node the store-kept chain is written under.
const NODE: u64 = 47;

/// Wall seconds the tests run at.
const NOW: u64 = 1_700_000_000;

fn token() -> Grant<DurableWrite> {
    busbar_kernel::test_support::tokens::grant::<DurableWrite>()
}

/// A book with NO DATA DIRECTORY over `slots`, as `root::boot::compose_book` builds it: the chain
/// the store kept is resumed (and read back once, whole, to rebuild the book).
fn over_store(slots: &RecordSlots) -> Durability {
    let lane = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    build_on_store(
        &DurabilityConfig { data_dir: None },
        NODE,
        lane,
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
        Box::new(|| None),
        None,
    )
    .expect("the store reads back")
}

/// Wait until the store took everything the book's lane holds.
fn drained(durability: &Durability) {
    assert!(
        durability
            .lane()
            .expect("a book over the store")
            .drain(std::time::Duration::from_secs(120)),
        "the store takes the journal's records"
    );
}

/// A unit's audit inputs, numbered `unit`.
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
        origin: busbar_kernel::test_support::tokens::origin(OriginKind::Client),
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

/// THE AMENDMENT REBUILD REFUSES THE BOOT when the store will not read the chain back. Taking the
/// failed read for an empty chain rebuilt no amendment and bound no journal: every signed count
/// correction reverted for the life of the process, and none sealed afterwards was journalled.
#[test]
fn an_amendment_rebuild_the_store_will_not_read_refuses_the_boot() {
    let slots = RecordSlots::new();
    let token = token();
    {
        let mut first = over_store(&slots);
        first
            .journal
            .append(
                &token,
                StepName::Meter,
                &[Entry::new(RecordClass::Load, vec![0x5a; 64]).at(NOW, 0)],
            )
            .expect("a record goes on the chain");
        drained(&first);
    }
    let mut restarted = over_store(&slots);
    slots.fail_reads(true);
    let answered = format!("{:?}", restarted.restore_amendments());
    assert!(
        answered.starts_with("Err(") && answered.contains("could not be read back"),
        "a store that would not read the chain back at the amendment rebuild must refuse the \
         boot, naming the read; the rebuild answered {answered}"
    );
    assert_eq!(restarted.amendments_through, None, "nothing was rebuilt");
}

/// THE KEYSET BINDING REFUSES THE BOOT when the store will not read the chain back. Taking the
/// failed read for a chain with no `Bootstrap` sealed a second one.
#[test]
fn a_keyset_binding_the_store_will_not_read_refuses_the_boot() {
    let slots = RecordSlots::new();
    let token = token();
    {
        let mut first = over_store(&slots);
        crate::root::keyset::bind(&mut first, None, &token, StepName::Meter, NOW)
            .expect("the first boot mints the deployment keyset and seals it");
        drained(&first);
    }
    let mut restarted = over_store(&slots);
    let head = restarted.journal.head();
    slots.fail_reads(true);
    let bound = crate::root::keyset::bind(&mut restarted, None, &token, StepName::Meter, NOW);
    assert!(
        bound.is_err(),
        "a store that would not read the chain back must refuse the keyset binding; it bound \
         {bound:?}"
    );
    assert_eq!(
        restarted.journal.head(),
        head,
        "no second Bootstrap went on the chain"
    );
}

/// THE CHECKPOINT NUMBERING CONTINUES from the chain the boot rebuilt the book from, whatever the
/// store answers when it is read again. Taking a failed read for an empty chain numbered from one
/// again, re-using sequence numbers the chain already carries.
#[test]
fn checkpoint_numbering_survives_a_store_that_stops_reading() {
    let slots = RecordSlots::new();
    let token = token();
    {
        let mut first = over_store(&slots);
        first.arm_checkpoints(NOW);
        for seq in [1, 2] {
            let sealed = first
                .seal_checkpoint(&token, StepName::Meter, NOW)
                .expect("sealed");
            assert_eq!(sealed.checkpoint_seq, seq);
        }
        drained(&first);
    }
    let mut restarted = over_store(&slots);
    slots.fail_reads(true);
    restarted.arm_checkpoints(NOW);
    assert_eq!(
        restarted.cadence().expect("armed").next_checkpoint_seq(),
        3,
        "the next checkpoint follows the highest the chain carries"
    );
}

/// AN AUDIT WINDOW THE STORE WILL NOT READ BACK IS NEVER ANSWERED AS EMPTY: the view answers
/// nothing, which the range read renders as the store failure it is (`GovernanceError::Store`),
/// never as a window with no records in it.
#[cfg(feature = "root-admin")]
#[test]
fn an_audit_window_the_store_will_not_read_is_never_answered_empty() {
    use crate::root::units_admin::{AuditView, NodeAudit};
    let slots = RecordSlots::new();
    let token = token();
    let mut durability = over_store(&slots);
    let sealed = (AUDIT_RING + 5) as u64;
    for unit in 1..=sealed {
        durability
            .seal_unit(
                audit_inputs(unit),
                busbar_kernel::test_support::tokens::pass(),
                &token,
            )
            .expect("sealed");
    }
    assert!(
        durability.audit_records.first().is_some_and(|r| r.seq > 1),
        "the cache let the oldest records go"
    );
    slots.fail_reads(true);
    let view = NodeAudit::new(std::sync::Arc::new(std::sync::Mutex::new(durability)));
    let mut answered: Option<usize> = None;
    view.read_window(1, 3, &mut |_, records| {
        answered = Some(records.map_or(0, <[_]>::len));
    });
    assert_eq!(
        answered, None,
        "a window older than the cache that the store would not read back was answered with \
         records (an empty window is a false answer)"
    );
}
