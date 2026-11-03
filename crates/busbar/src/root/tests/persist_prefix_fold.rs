// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn assert_pure_failure(slots: &RecordSlots, sink: &StoreRecovery, read: PersistPrefixRead) {
    let before = slots.puts();
    let pending = sink.state.lock().unwrap().pending.len();
    assert!(read.finish().is_err());
    assert_eq!(
        slots.puts(),
        before,
        "failed preflight neither appends a candidate nor selects a head"
    );
    assert_eq!(
        sink.state.lock().unwrap().pending.len(),
        pending,
        "pure proof cannot remove or insert pending custody"
    );
}

#[test]
fn persist_prefix_proves_local_predecessor_parent_and_same_digest_without_effects() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "persist-prefix-positive");
    let sink = adapter(&book);
    let (parent, checkpoint, child) = linked_events();
    for event in [&parent, &checkpoint, &child] {
        sink.persist(event).unwrap();
    }
    let next = transition(&child, RecoveryState::Applied);
    let before = slots.puts();
    let prefix = sink
        .read_persist_prefix_for_final_fold(&next)
        .unwrap()
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(prefix.run.as_ref().unwrap().selected, child);
    assert_eq!(
        prefix.current.as_ref().unwrap().0.event_digest,
        child.fingerprint().unwrap()
    );
    assert_eq!(slots.puts(), before);
    assert!(sink.state.lock().unwrap().pending.is_empty());
    sink.persist(&next).unwrap();
    let before = slots.puts();
    sink.persist(&next).unwrap();
    assert_eq!(
        slots.puts(),
        before,
        "same-digest confirmation does not append or select another candidate"
    );
}

#[test]
fn persist_prefix_brackets_initially_absent_head_as_an_exact_option() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "persist-prefix-absent");
    let sink = adapter(&book);
    let initial = intent();
    let read = sink
        .read_persist_prefix_for_final_fold(&initial)
        .unwrap()
        .unwrap();
    assert!(read.prefix.current.is_none());
    assert!(read.origin.child.is_none());
    assert!(
        read.origin.facts.seals.is_empty(),
        "a truly empty genesis inherits the no-facts path"
    );
    let before = slots.puts();
    let prefix = read.finish().unwrap();
    assert!(prefix.current.is_none());
    assert!(prefix.run.is_none());
    assert_eq!(slots.puts(), before);
    assert!(sink.state.lock().unwrap().pending.is_empty());
    let read = sink
        .read_persist_prefix_for_final_fold(&initial)
        .unwrap()
        .unwrap();
    assert!(read.prefix.current.is_none());
    assert!(read.origin.child.is_none());
    sink.persist(&initial).unwrap();
    assert_pure_failure(&slots, &sink, read);
    sink.persist(&initial).unwrap();
}

#[test]
fn persist_prefix_rejects_changed_child_parent_or_fence_before_any_effects() {
    for change in 0..3 {
        let slots = RecordSlots::new();
        let book = opened(&slots, &format!("persist-prefix-change-{change}"));
        let sink = adapter(&book);
        let (parent, checkpoint, child) = linked_events();
        for event in [&parent, &checkpoint, &child] {
            sink.persist(event).unwrap();
        }
        let next = transition(&child, RecoveryState::Applied);
        let read = sink
            .read_persist_prefix_for_final_fold(&next)
            .unwrap()
            .unwrap();
        match change {
            0 => sink
                .persist(&transition(&child, RecoveryState::LandedUnknown))
                .unwrap(),
            1 => sink
                .persist(&transition(&checkpoint, RecoveryState::Settled))
                .unwrap(),
            _ => retire(&book),
        }
        assert_pure_failure(&slots, &sink, read);
    }
}

#[test]
fn persist_prefix_missing_or_corrupt_sealed_fact_fails_before_pending_or_store_publication() {
    for missing in [false, true] {
        let slots = RecordSlots::new();
        let book = opened(
            &slots,
            if missing {
                "persist-prefix-missing"
            } else {
                "persist-prefix-corrupt"
            },
        );
        let sink = adapter(&book);
        let initial = intent();
        sink.persist(&initial).unwrap();
        let next = transition(&initial, RecoveryState::LandedUnknown);
        let read = sink
            .read_persist_prefix_for_final_fold(&next)
            .unwrap()
            .unwrap();
        let (tip, _) = head(slots.calls().as_ref(), &initial.operation_id)
            .unwrap()
            .unwrap();
        let key = part_key(tip.node, tip.sequence, 0);
        if missing {
            let raw = wait_for(slots.calls().record_get(JOURNAL_SCHEMA, &key))
                .unwrap()
                .unwrap();
            let request = crate::root::durability::conditional::candidate(
                vec![Predicate {
                    schema: JOURNAL_SCHEMA.into(),
                    key: key.to_vec(),
                    expected: Expected::Bytes(raw.as_slice().to_vec()),
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
        assert_pure_failure(&slots, &sink, read);
        let before = slots.puts();
        assert!(sink.persist(&next).is_err());
        assert_eq!(slots.puts(), before);
        assert!(sink.state.lock().unwrap().pending.is_empty());
    }
}

#[test]
fn persist_prefix_binds_transient_full_candidate_seal_even_when_original_is_restored() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "persist-prefix-transient");
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
    let (tip, _) = head(slots.calls().as_ref(), &checkpoint.operation_id)
        .unwrap()
        .unwrap();
    let original = read_record_exact(slots.calls().as_ref(), node, tip.sequence).unwrap();
    let mut altered_record = original.clone();
    let mut altered = candidate(&altered_record).unwrap().unwrap();
    altered.previous_head = Some(alternate.head);
    assert_eq!(altered.event, checkpoint);
    altered_record.body = body(&altered).unwrap();
    altered_record.body_hash = altered_record.digest_of_body();
    altered_record.hash = altered_record.digest_of_chain();
    replace_record(&slots, &altered_record);
    let next = transition(&child, RecoveryState::Applied);
    let read = sink
        .read_persist_prefix_for_final_fold(&next)
        .unwrap()
        .unwrap();
    replace_record(&slots, &original);
    assert_pure_failure(&slots, &sink, read);
    sink.persist_prefix_at(&next).unwrap();
}

#[test]
fn persist_prefix_final_fold_checks_an_unselected_tail_before_effects() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "persist-prefix-unselected-tail");
    let sink = adapter(&book);
    let initial = intent();
    sink.persist(&initial).unwrap();
    let next = transition(&initial, RecoveryState::LandedUnknown);
    let read = sink
        .read_persist_prefix_for_final_fold(&next)
        .unwrap()
        .unwrap();
    let lane = book.lock().unwrap().lane().unwrap().clone();
    let node = book.lock().unwrap().journal.node();
    let mut unrelated = intent();
    unrelated.operation_id = [44; 16];
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
    assert_pure_failure(&slots, &sink, read);
    let before = slots.puts();
    assert!(sink.persist(&next).is_err());
    assert_eq!(slots.puts(), before);
}

#[test]
fn persist_prefix_preproof_cannot_replace_fresh_post_cas_origin_verification() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "persist-prefix-post-cas-origin");
    let sink = adapter(&book);
    let (parent, checkpoint, child) = linked_events();
    for event in [&parent, &checkpoint] {
        sink.persist(event).unwrap();
    }
    let (parent_tip, _) = head(slots.calls().as_ref(), &parent.operation_id)
        .unwrap()
        .unwrap();
    let corrupted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = corrupted.clone();
    let actual = slots.clone();
    let child_id = child.operation_id;
    slots.on_transaction(move |request| {
        if request.mutations.iter().any(|m| matches!(m, Mutation::Put { schema, key, .. } if schema == HEAD_SCHEMA && key == &child_id))
            && !flag.swap(true, std::sync::atomic::Ordering::SeqCst) {
            actual.corrupt(JOURNAL_SCHEMA, &part_key(parent_tip.node, parent_tip.sequence, 0));
        }
        None
    });
    let result = sink.persist(&child);
    slots.on_transaction(|_| None);
    assert!(corrupted.load(std::sync::atomic::Ordering::SeqCst));
    assert!(
        result.is_err(),
        "the earlier shared preproof cannot authorize stale success after a later Store mutation"
    );
    assert!(
        sink.state
            .lock()
            .unwrap()
            .pending
            .contains_key(&child.operation_id),
        "failed fresh post-CAS proof retains pending custody"
    );
}

#[test]
fn persist_prefix_foreign_parent_and_adopted_predecessor_restart_a_fresh_cold_preflight() {
    let slots = RecordSlots::new();
    let old = opened(&slots, "persist-prefix-foreign-old");
    let new = opened(&slots, "persist-prefix-foreign-new");
    let old_sink = adapter(&old);
    let sink = adapter(&new);
    let (parent, checkpoint, child) = linked_events();
    for event in [&parent, &checkpoint] {
        old_sink.persist(event).unwrap();
    }
    assert!(sink
        .read_persist_prefix_for_final_fold(&child)
        .unwrap()
        .is_none());
    let before = slots.puts();
    let prefix = sink.persist_prefix_at(&child).unwrap();
    assert!(prefix.current.is_none());
    assert!(prefix.run.is_none());
    assert_eq!(slots.puts(), before);
    let initial = intent();
    let unknown = transition(&initial, RecoveryState::LandedUnknown);
    old_sink.persist(&initial).unwrap();
    old_sink.persist(&unknown).unwrap();
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
    let next = transition(&verdict, RecoveryState::Settled);
    assert!(sink
        .read_persist_prefix_for_final_fold(&next)
        .unwrap()
        .is_none());
    let before = slots.puts();
    let prefix = sink.persist_prefix_at(&next).unwrap();
    assert_eq!(prefix.run.unwrap().selected, verdict);
    assert_eq!(slots.puts(), before);
}

#[test]
fn persist_prefix_overflow_cold_restart_rechecks_unrelated_actual_journal_records() {
    let slots = RecordSlots::new();
    let book = opened(&slots, "persist-prefix-overflow");
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
    let mut event = intent();
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
    let next = transition(&event, RecoveryState::LandedUnknown);
    assert!(sink
        .read_persist_prefix_for_final_fold(&next)
        .unwrap()
        .is_none());
    let before = slots.puts();
    assert_eq!(
        sink.persist_prefix_at(&next).unwrap().run.unwrap().selected,
        event
    );
    assert_eq!(slots.puts(), before);
    slots.corrupt(JOURNAL_SCHEMA, &part_key(node, unselected.head.sequence, 0));
    let before = slots.puts();
    assert!(sink.persist_prefix_at(&next).is_err());
    assert!(sink.persist(&next).is_err());
    assert_eq!(slots.puts(), before);
    assert!(sink.state.lock().unwrap().pending.is_empty());
}
