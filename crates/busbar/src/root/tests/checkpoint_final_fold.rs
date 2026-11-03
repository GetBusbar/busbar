// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn checkpoint_final_fold_proves_selected_ancestor_and_its_actual_parent_origin() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "checkpoint-final-positive");
    let sink = adapter(&book);
    let (parent, checkpoint, child) = linked_events();
    let applied = transition(&child, RecoveryState::Applied);
    let settled = transition(&applied, RecoveryState::Settled);
    for event in [&parent, &checkpoint, &child, &applied, &settled] {
        sink.persist(event).unwrap();
    }
    for event in [&child, &applied, &settled] {
        for owned in [false, true] {
            sink.read_checkpoint_for_final_fold(event, owned)
                .unwrap()
                .expect("bounded local checkpoint and origin")
                .finish()
                .unwrap();
        }
        sink.verify_checkpoint(event).unwrap();
        sink.confirm_owned_checkpoint(event).unwrap();
    }
}

#[test]
fn checkpoint_final_fold_rejects_raw_head_advance_and_retired_authority() {
    for retire_authority in [false, true] {
        let slots = RecordSlots::new();
        let book = opened(
            &slots,
            if retire_authority {
                "checkpoint-final-fence"
            } else {
                "checkpoint-final-head"
            },
        );
        let sink = adapter(&book);
        let initial = intent();
        sink.persist(&initial).unwrap();
        let read = sink
            .read_checkpoint_for_final_fold(&initial, true)
            .unwrap()
            .unwrap();
        if retire_authority {
            retire(&book);
        } else {
            sink.persist(&transition(&initial, RecoveryState::LandedUnknown))
                .unwrap();
        }
        assert!(read.finish().is_err());
    }
}

#[test]
fn checkpoint_final_fold_rejects_changed_materialized_fact_after_read() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "checkpoint-final-corruption");
    let sink = adapter(&book);
    let initial = intent();
    sink.persist(&initial).unwrap();
    let read = sink
        .read_checkpoint_for_final_fold(&initial, false)
        .unwrap()
        .unwrap();
    let (tip, _) = head(slots.calls().as_ref(), &initial.operation_id)
        .unwrap()
        .unwrap();
    slots.corrupt(JOURNAL_SCHEMA, &part_key(tip.node, tip.sequence, 0));
    assert!(read.finish().is_err());
}

#[test]
fn checkpoint_final_fold_binds_transient_resealed_ancestor_pointer_after_restoration() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "checkpoint-final-transient");
    let sink = adapter(&book);
    let initial = intent();
    sink.persist(&initial).unwrap();
    let lane = book.lock().unwrap().lane().unwrap().clone();
    let node = book.lock().unwrap().journal.node();
    let alternate = sink
        .append_candidate(
            &lane,
            node,
            Candidate {
                event: initial.clone(),
                previous_head: None,
                adoption: None,
            },
        )
        .unwrap();
    lane.wait_acked(node, alternate.head.sequence, ACK_DEADLINE)
        .unwrap();
    let ancestor = transition(&initial, RecoveryState::Applied);
    sink.persist(&ancestor).unwrap();
    let (ancestor_head, _) = head(slots.calls().as_ref(), &initial.operation_id)
        .unwrap()
        .unwrap();
    sink.persist(&transition(&ancestor, RecoveryState::Settled))
        .unwrap();
    let original = read_record_exact(slots.calls().as_ref(), node, ancestor_head.sequence).unwrap();
    let mut altered_record = original.clone();
    let mut altered = candidate(&altered_record).unwrap().unwrap();
    altered.previous_head = Some(alternate.head);
    assert_eq!(
        altered.event, ancestor,
        "the checkpoint event itself is unchanged"
    );
    altered_record.body = body(&altered).unwrap();
    altered_record.body_hash = altered_record.digest_of_body();
    altered_record.hash = altered_record.digest_of_chain();
    replace_record(&slots, &altered_record);
    let read = sink
        .read_checkpoint_for_final_fold(&ancestor, true)
        .unwrap()
        .expect("transient pointer still names a valid selected event predecessor");
    replace_record(&slots, &original);
    assert!(read.finish().is_err(), "a shared transcript must bind the full seal read while materializing the requested ancestor");
    sink.confirm_owned_checkpoint(&ancestor).unwrap();
}

#[test]
fn checkpoint_final_fold_uses_fresh_cold_proof_for_foreign_adopted_history() {
    let slots = RecordSlots::new();
    let old = opened(&slots, "checkpoint-final-foreign-old");
    let new = opened(&slots, "checkpoint-final-foreign-new");
    let old_sink = adapter(&old);
    let sink = adapter(&new);
    let initial = intent();
    let unknown = transition(&initial, RecoveryState::LandedUnknown);
    old_sink.persist(&initial).unwrap();
    old_sink.persist(&unknown).unwrap();
    assert!(sink
        .read_checkpoint_for_final_fold(&initial, false)
        .unwrap()
        .is_none());
    sink.verify_checkpoint(&initial).unwrap();
    assert!(matches!(
        sink.read_checkpoint_for_final_fold(&initial, true),
        Err(RecoveryError::Conflict(_))
    ));
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
    assert!(sink
        .read_checkpoint_for_final_fold(&initial, true)
        .unwrap()
        .is_none());
    sink.confirm_owned_checkpoint(&initial).unwrap();
}

#[test]
fn checkpoint_final_fold_overflow_restarts_cold_and_checks_unrelated_journal_tamper() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "checkpoint-final-overflow");
    let sink = adapter(&book);
    let lane = book.lock().unwrap().lane().unwrap().clone();
    let node = book.lock().unwrap().journal.node();
    let mut unrelated = intent();
    unrelated.operation_id = [44; 16];
    let unselected = sink
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
    lane.wait_acked(node, unselected.head.sequence, ACK_DEADLINE)
        .unwrap();
    let initial = intent();
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
    let select = crate::root::durability::conditional::candidate(
        vec![Predicate {
            schema: HEAD_SCHEMA.into(),
            key: event.operation_id.to_vec(),
            expected: Expected::Absent,
        }],
        vec![Mutation::Put {
            schema: HEAD_SCHEMA.into(),
            key: event.operation_id.to_vec(),
            value: serde_json::to_vec(&prior.unwrap()).unwrap(),
        }],
    );
    assert_eq!(
        wait_for(slots.calls().record_transaction(&select)).unwrap(),
        busbar_contract::abi::sdk::store::conditional::Decision::Applied
    );
    assert!(sink
        .read_checkpoint_for_final_fold(&initial, true)
        .unwrap()
        .is_none());
    sink.confirm_owned_checkpoint(&initial).unwrap();
    slots.corrupt(JOURNAL_SCHEMA, &part_key(node, unselected.head.sequence, 0));
    assert!(
        sink.confirm_owned_checkpoint(&initial).is_err(),
        "cold fallback must not reuse the earlier proof or ignore unrelated journal records"
    );
}
