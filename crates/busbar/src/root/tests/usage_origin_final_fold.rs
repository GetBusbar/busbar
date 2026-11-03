// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::tests::{intent, linked_events, opened, retire, transition};
use super::*;
use crate::root::durability::store_chain::{part_key, JOURNAL_SCHEMA};
use crate::root::store_double::RecordSlots;

fn adapter(book: &Arc<Mutex<Durability>>) -> StoreRecovery {
    StoreRecovery {
        book: Arc::clone(book),
        token: busbar_kernel::teller::Kernel::new().durability_token(),
        state: Mutex::new(DriverState::default()),
    }
}

#[test]
fn final_origin_fold_accepts_the_actual_selected_parent_and_child() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "origin-final-positive");
    let sink = adapter(&book);
    let (parent, checkpoint, child) = linked_events();
    for event in [&parent, &checkpoint, &child] {
        sink.persist(event).unwrap();
    }
    sink.read_origin_for_final_fold(&child)
        .unwrap()
        .expect("local bounded proof")
        .finish()
        .unwrap();
    sink.verify_origin(&child).unwrap();
}

#[test]
fn final_origin_fold_rejects_a_head_advanced_between_read_and_finish() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "origin-final-head");
    let sink = adapter(&book);
    let initial = intent();
    sink.persist(&initial).unwrap();
    let read = sink.read_origin_for_final_fold(&initial).unwrap().unwrap();
    sink.persist(&transition(&initial, RecoveryState::LandedUnknown))
        .unwrap();
    assert!(matches!(read.finish(), Err(RecoveryError::Conflict(_))));
}

#[test]
fn final_origin_fold_rejects_retired_authority_between_read_and_finish() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "origin-final-fence");
    let sink = adapter(&book);
    let initial = intent();
    sink.persist(&initial).unwrap();
    let read = sink.read_origin_for_final_fold(&initial).unwrap().unwrap();
    retire(&book);
    assert!(read.finish().is_err());
}

#[test]
fn final_origin_fold_rejects_corrupt_or_missing_actual_store_facts() {
    for missing in [false, true] {
        let slots = RecordSlots::new();
        let book = opened(
            &slots,
            if missing {
                "origin-final-missing"
            } else {
                "origin-final-corrupt"
            },
        );
        let sink = adapter(&book);
        let initial = intent();
        sink.persist(&initial).unwrap();
        let read = sink.read_origin_for_final_fold(&initial).unwrap().unwrap();
        let (tip, _) = head(slots.calls().as_ref(), &initial.operation_id)
            .unwrap()
            .unwrap();
        let key = part_key(tip.node, tip.sequence, 0);
        if missing {
            let request = super::super::conditional::candidate(
                vec![Predicate {
                    schema: JOURNAL_SCHEMA.into(),
                    key: key.to_vec(),
                    expected: Expected::Bytes(
                        wait_for(slots.calls().record_get(JOURNAL_SCHEMA, &key))
                            .unwrap()
                            .unwrap()
                            .as_slice()
                            .to_vec(),
                    ),
                }],
                vec![Mutation::DeleteRange {
                    schema: JOURNAL_SCHEMA.into(),
                    prefix: key[..16].to_vec(),
                    exact_key_length: 18,
                }],
            );
            assert_eq!(
                wait_for(slots.calls().record_transaction(&request)).unwrap(),
                busbar_contract::abi::sdk::store::conditional::Decision::Applied
            );
        } else {
            slots.corrupt(JOURNAL_SCHEMA, &key);
        }
        assert!(
            read.finish().is_err(),
            "a changed Store fact must invalidate the read proof"
        );
    }
}

fn replace_record(slots: &RecordSlots, record: &busbar_kernel_wal::JournalRecord) {
    let bytes = record.encode();
    let chunks: Vec<_> = bytes
        .chunks(super::super::store_chain::PART_BYTES)
        .collect();
    for (index, chunk) in chunks.iter().enumerate() {
        let mut value = (chunks.len() as u16).to_be_bytes().to_vec();
        value.extend_from_slice(chunk);
        slots.put_row(
            JOURNAL_SCHEMA,
            &part_key(record.node, record.node_seq, index as u16),
            &value,
        );
    }
}

#[test]
fn final_origin_fold_rejects_transient_resealed_pointer_even_after_store_restoration() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "origin-final-transient-pointer");
    let sink = adapter(&book);
    let (parent, checkpoint, child) = linked_events();
    sink.persist(&parent).unwrap();
    let lane = book.lock().unwrap().lane().unwrap().clone();
    let node = book.lock().unwrap().journal.node();
    let alternate = sink
        .append_candidate(
            &lane,
            node,
            Candidate {
                event: parent.clone(),
                previous_head: None,
                adoption: None,
            },
        )
        .unwrap();
    lane.wait_acked(node, alternate.head.sequence, ACK_DEADLINE)
        .unwrap();
    sink.persist(&checkpoint).unwrap();
    sink.persist(&child).unwrap();
    let (checkpoint_head, _) = head(slots.calls().as_ref(), &checkpoint.operation_id)
        .unwrap()
        .unwrap();
    let original =
        read_record_exact(slots.calls().as_ref(), node, checkpoint_head.sequence).unwrap();
    let mut edited = original.clone();
    let mut altered = candidate(&edited).unwrap().unwrap();
    altered.previous_head = Some(alternate.head);
    assert_eq!(
        altered.event.fingerprint().unwrap(),
        checkpoint.fingerprint().unwrap()
    );
    edited.body = body(&altered).unwrap();
    edited.body_hash = edited.digest_of_body();
    edited.hash = edited.digest_of_chain();
    replace_record(&slots, &edited);
    let read = sink
        .read_origin_for_final_fold(&child)
        .unwrap()
        .expect("bounded ancestry traversal sees the transient valid pointer");
    replace_record(&slots, &original);
    assert!(
        read.finish().is_err(),
        "restoring canonical bytes cannot erase the different full seal observed during traversal"
    );
    sink.verify_origin(&child).unwrap();
}

#[test]
fn final_origin_fold_uses_cold_verification_for_foreign_and_adopted_ancestry() {
    let slots = RecordSlots::new();
    let old = opened(&slots, "origin-final-foreign-old");
    let new = opened(&slots, "origin-final-foreign-new");
    let old_sink = adapter(&old);
    let sink = adapter(&new);
    let initial = intent();
    let unknown = transition(&initial, RecoveryState::LandedUnknown);
    old_sink.persist(&initial).unwrap();
    old_sink.persist(&unknown).unwrap();
    assert!(sink.read_origin_for_final_fold(&unknown).unwrap().is_none());
    sink.verify_origin(&unknown).unwrap();
    retire(&old);
    let verdict = transition(&unknown, RecoveryState::VerdictNotLanded);
    let resolution = RecoveryResolution {
        operation_id: unknown.operation_id,
        body_fingerprint: unknown.body_fingerprint,
        expected_revision: unknown.revision,
        verdict: RecoveryVerdict::NotLanded,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "operator".into(),
        reason: "old sender and backend quiesced".into(),
    };
    sink.adopt_verdict_selection(&resolution, std::slice::from_ref(&verdict))
        .unwrap();
    assert!(sink.read_origin_for_final_fold(&verdict).unwrap().is_none());
    sink.verify_origin(&verdict).unwrap();
}

#[test]
fn final_origin_fold_overflow_falls_back_to_fresh_full_tamper_verification() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "origin-final-overflow");
    let sink = adapter(&book);
    let lane = book.lock().unwrap().lane().unwrap().clone();
    let node = book.lock().unwrap().journal.node();
    let initial = intent();
    let mut unrelated = initial.clone();
    unrelated.operation_id = [44; 16];
    let unrelated = sink
        .append_candidate(
            &lane,
            node,
            Candidate {
                event: unrelated,
                previous_head: None,
                adoption: None,
            },
        )
        .unwrap();
    lane.wait_acked(node, unrelated.head.sequence, ACK_DEADLINE)
        .unwrap();
    let mut event = initial.clone();
    let mut prior = None;
    for _ in 0..130 {
        let appended = sink
            .append_candidate(
                &lane,
                node,
                Candidate {
                    event: event.clone(),
                    previous_head: prior.clone(),
                    adoption: None,
                },
            )
            .unwrap();
        lane.wait_acked(node, appended.head.sequence, ACK_DEADLINE)
            .unwrap();
        prior = Some(appended.head);
        if event.revision != 129 {
            event = transition(&event, RecoveryState::LandedUnknown);
        }
    }
    let tip = prior.unwrap();
    // Select this entirely real, durably appended ancestry in the actual Store.
    let select = super::super::conditional::candidate(
        vec![Predicate {
            schema: HEAD_SCHEMA.into(),
            key: event.operation_id.to_vec(),
            expected: Expected::Absent,
        }],
        vec![Mutation::Put {
            schema: HEAD_SCHEMA.into(),
            key: event.operation_id.to_vec(),
            value: serde_json::to_vec(&tip).unwrap(),
        }],
    );
    assert_eq!(
        wait_for(slots.calls().record_transaction(&select)).unwrap(),
        busbar_contract::abi::sdk::store::conditional::Decision::Applied
    );
    assert!(sink.read_origin_for_final_fold(&event).unwrap().is_none());
    sink.verify_origin(&event).unwrap();
    // Corrupt an unselected operation outside the bounded transcript. Fresh cold proof
    // must still inspect it, rather than trusting the previously successful run.
    slots.corrupt(JOURNAL_SCHEMA, &part_key(node, unrelated.head.sequence, 0));
    assert!(sink.verify_origin(&event).is_err());
}

#[test]
fn final_origin_fold_rejects_parent_head_advanced_between_read_and_finish() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "origin-final-parent-head");
    let sink = adapter(&book);
    let (parent, checkpoint, child) = linked_events();
    for event in [&parent, &checkpoint, &child] {
        sink.persist(event).unwrap();
    }
    let read = sink.read_origin_for_final_fold(&child).unwrap().unwrap();
    sink.persist(&transition(&checkpoint, RecoveryState::Settled))
        .unwrap();
    assert!(matches!(read.finish(), Err(RecoveryError::Conflict(_))));
    sink.verify_origin(&child).unwrap();
}

#[test]
fn final_origin_fold_verifies_unselected_tail_after_all_facts_are_found() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "origin-final-tail");
    let sink = adapter(&book);
    let initial = intent();
    sink.persist(&initial).unwrap();
    let read = sink.read_origin_for_final_fold(&initial).unwrap().unwrap();
    let lane = book.lock().unwrap().lane().unwrap().clone();
    let node = book.lock().unwrap().journal.node();
    let mut unrelated = initial.clone();
    unrelated.operation_id = [45; 16];
    let tail = sink
        .append_candidate(
            &lane,
            node,
            Candidate {
                event: unrelated,
                previous_head: None,
                adoption: None,
            },
        )
        .unwrap();
    lane.wait_acked(node, tail.head.sequence, ACK_DEADLINE)
        .unwrap();
    slots.corrupt(JOURNAL_SCHEMA, &part_key(node, tail.head.sequence, 0));
    assert!(
        read.finish().is_err(),
        "finding all selected facts cannot skip an unrelated corrupt tail"
    );
}
