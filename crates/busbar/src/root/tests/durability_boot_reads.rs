// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::audit::tests::inputs;
use super::*;
use crate::root::store_double::RecordSlots;

const NODE: u64 = 47;

const NOW: u64 = 1_700_000_000;

fn token() -> Grant<DurableWrite> {
    busbar_kernel_testkit::test_support::tokens::grant::<DurableWrite>()
}

fn over_store(slots: &RecordSlots) -> Durability {
    rebuilt_over(slots).expect("the store reads back")
}

fn rebuilt_over(slots: &RecordSlots) -> Result<Durability, OpenError> {
    let lane = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    build_on_store(
        &DurabilityConfig {
            data_dir: Some(std::path::PathBuf::from("/dev/null/legacy-journal")),
        },
        NODE,
        lane,
        None,
    )
}

fn drained(durability: &Durability) {
    assert!(
        durability
            .lane()
            .expect("a book over the store")
            .drain(std::time::Duration::from_secs(120)),
        "the store takes the journal's records"
    );
}

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
    let journal = busbar_kernel_audit::amend::NodeAmendments::new();
    let answered = format!("{:?}", restarted.restore_amendments(&journal, &token));
    assert!(
        answered.starts_with("Err(") && answered.contains("could not be read back"),
        "a store that would not read the chain back at the amendment rebuild must refuse the \
         boot, naming the read; the rebuild answered {answered}"
    );
    assert_eq!(restarted.amendments_through, None, "nothing was rebuilt");
}

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
                inputs(unit),
                busbar_kernel_testkit::test_support::tokens::pass(),
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

fn two_records(slots: &RecordSlots) {
    let token = token();
    let mut first = over_store(slots);
    for unit in [1, 2] {
        first
            .seal_unit(
                inputs(unit),
                busbar_kernel_testkit::test_support::tokens::pass(),
                &token,
            )
            .expect("sealed");
    }
    drained(&first);
}

#[test]
fn a_stored_chain_that_does_not_verify_refuses_the_boot() {
    let slots = RecordSlots::new();
    two_records(&slots);
    let intact = over_store(&slots);
    assert_eq!(intact.audit_records.len(), 2, "the unedited chain rebuilds");
    drop(intact);

    slots.corrupt(JOURNAL_SCHEMA, &part_key(NODE, 1, 0));
    let refused = rebuilt_over(&slots).err().map(|e| e.to_string());
    assert!(
        refused
            .as_deref()
            .is_some_and(|why| why.contains("does not verify")),
        "a stored chain that does not verify must refuse the boot, naming the break; the build \
         answered {refused:?}"
    );
}

#[test]
fn an_amendment_rebuild_over_a_chain_that_does_not_verify_refuses_the_boot() {
    let slots = RecordSlots::new();
    two_records(&slots);
    let mut restarted = over_store(&slots);
    slots.corrupt(JOURNAL_SCHEMA, &part_key(NODE, 1, 0));
    let journal = busbar_kernel_audit::amend::NodeAmendments::new();
    let answered = format!("{:?}", restarted.restore_amendments(&journal, &token()));
    assert!(
        answered.starts_with("Err(") && answered.contains("does not verify"),
        "a chain that does not verify at the amendment rebuild must refuse the boot, naming the \
         break; the rebuild answered {answered}"
    );
    assert_eq!(restarted.amendments_through, None, "nothing was rebuilt");
}

#[test]
fn a_keyset_binding_over_a_chain_that_does_not_verify_refuses_without_a_second_bootstrap() {
    let slots = RecordSlots::new();
    let mut first = over_store(&slots);
    crate::root::keyset::bind(&mut first, None, &token(), StepName::Meter, NOW).unwrap();
    drained(&first);
    drop(first);
    let mut restarted = over_store(&slots);
    let next = restarted.journal.next_seq();
    slots.corrupt(JOURNAL_SCHEMA, &part_key(NODE, 1, 0));
    let bound = crate::root::keyset::bind(
        &mut restarted,
        Some(std::path::Path::new("/dev/null/legacy-journal")),
        &token(),
        StepName::Meter,
        NOW,
    );
    assert!(bound.is_err_and(|why| why.to_string().contains("does not verify")));
    assert_eq!(restarted.journal.next_seq(), next);
    assert!(restarted.record.signing_key_id().is_none());
}
