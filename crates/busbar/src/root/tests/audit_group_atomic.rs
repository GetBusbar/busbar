// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::durability::store_chain::{
    confirm_record_bytes, part_key, prepare_audit_group, JOURNAL_SCHEMA, PART_BYTES,
};
use crate::root::durability::store_identity::{
    lease_row, set_lease_expiry, take_node, NODE_SCHEMA,
};

fn identity(slots: &RecordSlots, host: &str) -> (u64, HeldLease) {
    let taken = take_node(slots, host).unwrap();
    let lease = HeldLease::default();
    lease.hold(taken.lease.unwrap());
    (taken.id, lease)
}

fn group_records(sealed: &mut Sealed, count: usize) -> Vec<JournalRecord> {
    (0..count)
        .map(|index| {
            let mut inputs = crate::root::durability::audit::tests::inputs(sealed.audit.next_seq());
            inputs.wall = START + index as u64 * HEAD_SAMPLE_SECONDS;
            inputs.what.destination = Some("actual-group-destination".repeat(100));
            let audit = sealed.audit.seal(
                inputs,
                &busbar_kernel::teller::verb_audit_pass(&crate::root::kernel::new_kernel()),
            );
            let record = sealed.append(crate::root::durability::audit_entry(&audit).unwrap());
            assert!(record.encode().len() > PART_BYTES);
            record
        })
        .collect()
}

fn final_request(request: &Request) -> bool {
    request.mutations.iter().any(
        |m| matches!(m, Mutation::Put { schema, key, .. } if schema == SCHEMA && key.len() == 9),
    )
}

fn assert_group_final(request: &Request, records: &[JournalRecord]) {
    assert!(!request
        .mutations
        .iter()
        .any(|m| matches!(m, Mutation::DeleteRange { .. })));
    let expected_parts: usize = records
        .iter()
        .map(|r| r.encode().chunks(PART_BYTES).count())
        .sum();
    assert_eq!(
        request
            .mutations
            .iter()
            .filter(|m| matches!(m, Mutation::Put { schema, .. } if schema == JOURNAL_SCHEMA))
            .count(),
        expected_parts
    );
    for record in records {
        let encoded = record.encode();
        let chunks: Vec<_> = encoded.chunks(PART_BYTES).collect();
        for (index, chunk) in chunks.iter().enumerate() {
            let key = part_key(record.node, record.node_seq, index as u16).to_vec();
            let mut expected = (chunks.len() as u16).to_be_bytes().to_vec();
            expected.extend_from_slice(chunk);
            assert!(request.mutations.iter().any(|m| matches!(m, Mutation::Put { schema, key: written, value } if schema == JOURNAL_SCHEMA && written == &key && value == &expected)));
        }
        assert!(request.mutations.iter().any(|m| matches!(m, Mutation::Put { schema, key, .. } if schema == SCHEMA && key == &sample_key(record.node, record.node_seq))));
    }
    let last = records.last().unwrap();
    assert_eq!(request.mutations.iter().filter(|m| matches!(m, Mutation::Put { schema, key, .. } if schema == SCHEMA && key == &tip_key(last.node))).count(), 1);
}

#[test]
fn group_publishes_every_record_part_sample_and_tip_with_one_cleanup_and_one_final() {
    let slots = RecordSlots::new();
    let (node, lease) = identity(&slots, "audit-group-all");
    let mut sealed = Sealed::for_node(node);
    let records = group_records(&mut sealed, 3);
    let raw_records: Vec<_> = records.iter().map(raw).collect();
    let group = prepare_audit_group(&slots, &lease, &raw_records)
        .unwrap()
        .unwrap();
    assert_eq!(group.len(), records.len());
    let observed = Arc::new(Mutex::new(Vec::<Request>::new()));
    let capture = observed.clone();
    slots.on_transaction(move |r| {
        capture.lock().unwrap().push(r.clone());
        None
    });
    group.commit(&slots, &lease).unwrap();
    let requests = observed.lock().unwrap();
    assert_eq!(requests.len(), 2);
    let cleanup = &requests[0];
    assert_eq!(cleanup.mutations.len(), records.len());
    assert!(cleanup.mutations.iter().all(|m| matches!(m, Mutation::DeleteRange { schema, exact_key_length: 18, .. } if schema == JOURNAL_SCHEMA)));
    assert!(cleanup
        .predicates
        .iter()
        .any(|p| p.schema == SCHEMA && p.key == tip_key(node) && p.expected == Expected::Absent));
    assert!(cleanup.predicates.iter().any(|p| p.schema == NODE_SCHEMA));
    assert_group_final(&requests[1], &records);
    for record in &raw_records {
        confirm_record_bytes(&slots, record).unwrap();
    }
    assert_eq!(
        load(&slots, node).unwrap().unwrap().anchors(),
        sealed.audit.heads().anchors()
    );
}

#[test]
fn refused_group_final_leaves_no_parts_or_heads_and_retries_after_cleanup() {
    let slots = RecordSlots::new();
    let (node, lease) = identity(&slots, "audit-group-refusal");
    let mut sealed = Sealed::for_node(node);
    let records = group_records(&mut sealed, 3);
    let offered: Vec<_> = records.iter().map(raw).collect();
    let group = prepare_audit_group(&slots, &lease, &offered)
        .unwrap()
        .unwrap();
    let refused = Arc::new(AtomicBool::new(false));
    let flag = refused.clone();
    slots.on_transaction(move |r| {
        if final_request(r) {
            flag.store(true, Ordering::SeqCst);
            Some(StoreFailure::Refused(
                "definitive group final refusal".into(),
            ))
        } else {
            None
        }
    });
    assert!(group.commit(&slots, &lease).is_err());
    assert!(refused.load(Ordering::SeqCst));
    assert_eq!(slots.rows_under(JOURNAL_SCHEMA), 0);
    assert_eq!(slots.rows_under(SCHEMA), 0);
    slots.on_transaction(|_| None);
    prepare_audit_group(&slots, &lease, &offered)
        .unwrap()
        .unwrap()
        .commit(&slots, &lease)
        .unwrap();
    for record in &offered {
        confirm_record_bytes(&slots, record).unwrap();
    }
    assert_eq!(
        load(&slots, node).unwrap().unwrap().anchors(),
        sealed.audit.heads().anchors()
    );
}

#[test]
fn lost_group_final_reply_reuses_exact_request_and_reconstructed_reoffer_has_no_cleanup() {
    let slots = RecordSlots::new();
    let (node, lease) = identity(&slots, "audit-group-lost");
    let mut sealed = Sealed::for_node(node);
    let records = group_records(&mut sealed, 3);
    let offered: Vec<_> = records.iter().map(raw).collect();
    let observed = Arc::new(Mutex::new(Vec::<Request>::new()));
    let capture = observed.clone();
    slots.on_transaction(move |r| {
        capture.lock().unwrap().push(r.clone());
        None
    });
    slots.lose_acks(true);
    prepare_audit_group(&slots, &lease, &offered)
        .unwrap()
        .unwrap()
        .commit(&slots, &lease)
        .unwrap();
    let before = observed.lock().unwrap().len();
    let puts = slots.puts();
    let reoffer = prepare_audit_group(&slots, &lease, &offered)
        .unwrap()
        .unwrap();
    assert_eq!(reoffer.len(), offered.len());
    reoffer.commit(&slots, &lease).unwrap();
    assert_eq!(
        observed.lock().unwrap().len(),
        before,
        "fresh reconstruction must prove the already-applied prefix before any cleanup"
    );
    assert_eq!(slots.puts(), puts);
    let requests = observed.lock().unwrap();
    let finals: Vec<_> = requests.iter().filter(|r| final_request(r)).collect();
    assert!(finals.len() >= 2);
    assert!(
        finals.iter().all(|r| *r == finals[0]),
        "an unknown result retains the same operation id and all request bytes"
    );
    assert_group_final(finals[0], &records);
}

#[test]
fn reconstructed_group_reoffer_rejects_corrupt_parts_or_samples_without_cleanup() {
    for (corrupt_sample, missing) in [(false, false), (true, false), (false, true), (true, true)] {
        let slots = RecordSlots::new();
        let (node, lease) = identity(
            &slots,
            if corrupt_sample {
                "audit-group-reoffer-sample"
            } else {
                "audit-group-reoffer-part"
            },
        );
        let mut sealed = Sealed::for_node(node);
        let records = group_records(&mut sealed, 3);
        let offered: Vec<_> = records.iter().map(raw).collect();
        prepare_audit_group(&slots, &lease, &offered)
            .unwrap()
            .unwrap()
            .commit(&slots, &lease)
            .unwrap();
        let (schema, key) = if corrupt_sample {
            (SCHEMA, sample_key(node, 2))
        } else {
            (
                JOURNAL_SCHEMA,
                part_key(node, records[1].node_seq, 1).to_vec(),
            )
        };
        if missing {
            let current = wait_for(slots.record_get(schema, &key)).unwrap().unwrap();
            let delete = crate::root::durability::conditional::candidate(
                vec![Predicate {
                    schema: schema.into(),
                    key: key.clone(),
                    expected: Expected::Bytes(current.as_slice().to_vec()),
                }],
                vec![Mutation::DeleteRange {
                    schema: schema.into(),
                    prefix: key.clone(),
                    exact_key_length: key.len() as u64,
                }],
            );
            assert_eq!(slots.apply_transaction(&delete), Decision::Applied);
        } else {
            slots.corrupt(schema, &key);
        }
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = attempts.clone();
        slots.on_transaction(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            None
        });
        let failed = match prepare_audit_group(&slots, &lease, &offered) {
            Err(_) => true,
            Ok(Some(group)) => group.commit(&slots, &lease).is_err(),
            Ok(None) => false,
        };
        assert!(failed, "a divergent already-applied member cannot be acknowledged or fall back to destructive cleanup");
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn final_group_same_holder_renewal_retries_with_fresh_fence_without_recleanup() {
    const HOST: &str = "audit-group-renewal";
    let slots = RecordSlots::new();
    let (node, lease) = identity(&slots, HOST);
    let mut sealed = Sealed::for_node(node);
    let records = group_records(&mut sealed, 3);
    let offered: Vec<_> = records.iter().map(raw).collect();
    let group = prepare_audit_group(&slots, &lease, &offered)
        .unwrap()
        .unwrap();
    let observed = Arc::new(Mutex::new(Vec::<Request>::new()));
    let capture = observed.clone();
    let actual = slots.clone();
    slots.on_transaction(move |r| {
        let mut seen = capture.lock().unwrap();
        seen.push(r.clone());
        if final_request(r) && seen.iter().filter(|r| final_request(r)).count() == 1 {
            let (holder, expires) = lease_row(&actual, HOST).unwrap();
            set_lease_expiry(&actual, HOST, expires + 10_000);
            assert_eq!(lease_row(&actual, HOST).unwrap().0, holder);
        }
        None
    });
    let result = group.commit(&slots, &lease);
    slots.on_transaction(|_| None);
    result.unwrap();
    let requests = observed.lock().unwrap();
    assert_eq!(requests.iter().filter(|r| !final_request(r)).count(), 1);
    let finals: Vec<_> = requests.iter().filter(|r| final_request(r)).collect();
    assert_eq!(finals.len(), 2);
    let fence = |r: &Request| {
        r.predicates
            .iter()
            .find(|p| p.schema == NODE_SCHEMA)
            .unwrap()
            .expected
            .clone()
    };
    assert_ne!(fence(finals[0]), fence(finals[1]));
    for request in finals {
        assert_group_final(request, &records);
    }
    for record in &offered {
        confirm_record_bytes(&slots, record).unwrap();
    }
}

#[test]
fn group_bounds_and_mixed_records_fall_back_before_any_cleanup() {
    let slots = RecordSlots::new();
    let (node, lease) = identity(&slots, "audit-group-fallback");
    let mut sealed = Sealed::for_node(node);
    let records = group_records(&mut sealed, 17);
    let offered: Vec<_> = records.iter().map(raw).collect();
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = attempts.clone();
    slots.on_transaction(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        None
    });
    let bounded = prepare_audit_group(&slots, &lease, &offered).unwrap();
    if let Some(group) = bounded {
        assert!(group.len() <= 16);
    } // Bounded prefix selection is also legitimate.
    let mut mixed: Vec<_> = records[..2].iter().map(raw).collect();
    mixed.insert(1, Record::new(node, 999, b"ordinary record".to_vec()));
    assert!(prepare_audit_group(&slots, &lease, &mixed)
        .unwrap()
        .is_none());
    let mut large_sealed = Sealed::for_node(node);
    let mut large_inputs =
        crate::root::durability::audit::tests::inputs(large_sealed.audit.next_seq());
    large_inputs.what.destination =
        Some("x".repeat(busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize));
    let audit = large_sealed.audit.seal(
        large_inputs,
        &busbar_kernel::teller::verb_audit_pass(&crate::root::kernel::new_kernel()),
    );
    let oversized = large_sealed.append(crate::root::durability::audit_entry(&audit).unwrap());
    let next = large_sealed.audit(START + HEAD_SAMPLE_SECONDS);
    assert!(
        prepare_audit_group(&slots, &lease, &[raw(&oversized), raw(&next)])
            .unwrap()
            .is_none(),
        "a group frame beyond the ABI byte bound falls back before cleanup"
    );
    let mut framed = Sealed::for_node(node);
    let mut encoded_bound_records = Vec::new();
    for index in 0..2 {
        let mut inputs = crate::root::durability::audit::tests::inputs(framed.audit.next_seq());
        inputs.wall = START + index * HEAD_SAMPLE_SECONDS;
        inputs.what.destination = Some(
            "x".repeat(busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize * 15 / 32),
        );
        let audit = framed.audit.seal(
            inputs,
            &busbar_kernel::teller::verb_audit_pass(&crate::root::kernel::new_kernel()),
        );
        encoded_bound_records.push(raw(
            &framed.append(crate::root::durability::audit_entry(&audit).unwrap())
        ));
    }
    let raw_bytes: usize = encoded_bound_records
        .iter()
        .map(|record| record.body.len())
        .sum();
    assert!((raw_bytes as u64) < busbar_contract::abi::mechanism::check::HARD_MAX_BYTES,
        "raw bodies fit; only the actual all-parts conditional envelope exceeds the ABI frame bound");
    assert!(
        prepare_audit_group(&slots, &lease, &encoded_bound_records)
            .unwrap()
            .is_none(),
        "encoded part/schema/key/predicate overhead must be preflighted before cleanup"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
    assert_eq!(slots.rows_under(JOURNAL_SCHEMA), 0);
    assert_eq!(slots.rows_under(SCHEMA), 0);
}

#[test]
fn prepared_group_cleanup_cas_cannot_delete_a_newly_checkpointed_member() {
    use crate::root::durability::store_chain::put_record;
    let slots = RecordSlots::new();
    let (node, lease) = identity(&slots, "audit-group-cleanup-head-race");
    let mut sealed = Sealed::for_node(node);
    let records = group_records(&mut sealed, 3);
    let offered: Vec<_> = records.iter().map(raw).collect();
    let prepared = prepare_audit_group(&slots, &lease, &offered)
        .unwrap()
        .unwrap();
    put_record(&slots, &lease, &offered[0]).unwrap();
    let before = load(&slots, node).unwrap().unwrap().anchors();
    assert!(prepared.commit(&slots, &lease).is_err());
    confirm_record_bytes(&slots, &offered[0]).unwrap();
    assert_eq!(load(&slots, node).unwrap().unwrap().anchors(), before);
    for record in &records[1..] {
        assert!(
            wait_for(slots.record_get(JOURNAL_SCHEMA, &part_key(node, record.node_seq, 0)))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn final_group_head_or_sample_conflict_publishes_no_record_parts() {
    for sample in [false, true] {
        let slots = RecordSlots::new();
        let (node, lease) = identity(
            &slots,
            if sample {
                "audit-group-sample-race"
            } else {
                "audit-group-head-race"
            },
        );
        let mut sealed = Sealed::for_node(node);
        let records = group_records(&mut sealed, 3);
        let offered: Vec<_> = records.iter().map(raw).collect();
        let group = prepare_audit_group(&slots, &lease, &offered)
            .unwrap()
            .unwrap();
        let raced = Arc::new(AtomicBool::new(false));
        let race = raced.clone();
        let actual = slots.clone();
        slots.on_transaction(move |request| {
            if final_request(request) && !race.swap(true, Ordering::SeqCst) {
                let key = if sample {
                    sample_key(node, 2)
                } else {
                    tip_key(node)
                };
                let bytes = request
                    .mutations
                    .iter()
                    .find_map(|m| match m {
                        Mutation::Put {
                            schema,
                            key: written,
                            value,
                        } if schema == SCHEMA && written == &key => Some(value),
                        _ => None,
                    })
                    .unwrap();
                let replacement = if sample {
                    let mut head: Head = serde_json::from_slice(bytes).unwrap();
                    head.wall += 1;
                    serde_json::to_vec(&head).unwrap()
                } else {
                    let mut checkpoint: Checkpoint = serde_json::from_slice(bytes).unwrap();
                    checkpoint.tip.wall += 1;
                    serde_json::to_vec(&checkpoint).unwrap()
                };
                actual.put_row(SCHEMA, &key, &replacement);
            }
            None
        });
        let result = group.commit(&slots, &lease);
        slots.on_transaction(|_| None);
        assert!(result.is_err());
        assert!(raced.load(Ordering::SeqCst));
        assert_eq!(slots.rows_under(JOURNAL_SCHEMA), 0);
        assert_eq!(
            slots.rows_under(SCHEMA),
            1,
            "only the independently injected conflicting row exists"
        );
    }
}

#[test]
fn group_loses_authority_after_cleanup_without_publishing_any_member() {
    for replace in [false, true] {
        let slots = RecordSlots::new();
        let host = if replace {
            "audit-group-takeover"
        } else {
            "audit-group-release"
        };
        let (node, lease) = identity(&slots, host);
        let old_holder = lease_row(&slots, host).unwrap().0;
        let mut sealed = Sealed::for_node(node);
        let records = group_records(&mut sealed, 3);
        let offered: Vec<_> = records.iter().map(raw).collect();
        let group = prepare_audit_group(&slots, &lease, &offered)
            .unwrap()
            .unwrap();
        let cleaned = Arc::new(AtomicBool::new(false));
        let cleanup = cleaned.clone();
        let finals = Arc::new(AtomicUsize::new(0));
        let final_calls = finals.clone();
        let actual = slots.clone();
        slots.on_transaction(move |request| {
            if final_request(request) {
                final_calls.fetch_add(1, Ordering::SeqCst);
            }
            if request
                .mutations
                .iter()
                .any(|m| matches!(m, Mutation::DeleteRange { .. }))
                && !cleanup.swap(true, Ordering::SeqCst)
            {
                assert_eq!(actual.apply_transaction(request), Decision::Applied);
                set_lease_expiry(&actual, host, 0);
                if replace {
                    assert_eq!(take_node(&actual, host).unwrap().id, node);
                    assert_ne!(lease_row(&actual, host).unwrap().0, old_holder);
                }
                return Some(StoreFailure::Failed(
                    "group cleanup applied but reply lost".into(),
                ));
            }
            None
        });
        let result = group.commit(&slots, &lease);
        slots.on_transaction(|_| None);
        assert!(result.is_err());
        assert!(cleaned.load(Ordering::SeqCst));
        assert_eq!(finals.load(Ordering::SeqCst), 0);
        assert_eq!(slots.rows_under(JOURNAL_SCHEMA), 0);
        assert_eq!(slots.rows_under(SCHEMA), 0);
    }
}

#[test]
fn reconstructed_prefix_reoffer_preserves_prior_sample_reducer_and_unacknowledged_tail() {
    use crate::root::durability::store_chain::put_record;
    let slots = RecordSlots::new();
    let (node, lease) = identity(&slots, "audit-group-prior-samples");
    let mut sealed = Sealed::for_node(node);
    let first = sealed.audit(START);
    let unsampled = sealed.audit(START + 1);
    for record in [&first, &unsampled] {
        put_record(&slots, &lease, &raw(record)).unwrap();
    }
    let records = [
        START + 2,
        START + HEAD_SAMPLE_SECONDS + 1,
        START + HEAD_SAMPLE_SECONDS + 2,
    ]
    .map(|wall| sealed.audit(wall));
    let offered: Vec<_> = records.iter().map(raw).collect();
    let group = prepare_audit_group(&slots, &lease, &offered)
        .unwrap()
        .unwrap();
    assert_eq!(group.len(), 3);
    group.commit(&slots, &lease).unwrap();
    let expected = sealed.audit.heads().anchors();
    assert_eq!(load(&slots, node).unwrap().unwrap().anchors(), expected);
    let future = sealed.audit(START + HEAD_SAMPLE_SECONDS + 3);
    let reoffered = vec![raw(&records[1]), raw(&records[2]), raw(&future)];
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = attempts.clone();
    slots.on_transaction(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        None
    });
    let puts = slots.puts();
    let reconstructed = prepare_audit_group(&slots, &lease, &reoffered)
        .unwrap()
        .unwrap();
    assert_eq!(
        reconstructed.len(),
        2,
        "only the already-applied members through the current tip may be acknowledged"
    );
    reconstructed.commit(&slots, &lease).unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
    assert_eq!(slots.puts(), puts);
    assert_eq!(load(&slots, node).unwrap().unwrap().anchors(), expected);
    assert!(
        wait_for(slots.record_get(JOURNAL_SCHEMA, &part_key(node, future.node_seq, 0)))
            .unwrap()
            .is_none()
    );
}

#[test]
fn wholly_foreign_same_node_audit_run_falls_back_under_the_local_host_lease() {
    let slots = RecordSlots::new();
    let (local, lease) = identity(&slots, "audit-group-foreign-node");
    let mut foreign = Sealed::for_node(local.checked_add(1).unwrap());
    let records = group_records(&mut foreign, 3);
    let offered: Vec<_> = records.iter().map(raw).collect();
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = attempts.clone();
    slots.on_transaction(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        None
    });
    assert!(prepare_audit_group(&slots, &lease, &offered)
        .unwrap()
        .is_none());
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
    assert_eq!(slots.rows_under(JOURNAL_SCHEMA), 0);
    assert_eq!(slots.rows_under(SCHEMA), 0);
}

#[test]
fn registry_replacement_during_cleanup_conflicts_and_fails_without_publication() {
    let slots = RecordSlots::new();
    let (node, lease) = identity(&slots, "audit-group-registry-race");
    let mut sealed = Sealed::for_node(node);
    let records = group_records(&mut sealed, 3);
    let offered: Vec<_> = records.iter().map(raw).collect();
    let group = prepare_audit_group(&slots, &lease, &offered)
        .unwrap()
        .unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = attempts.clone();
    let actual = slots.clone();
    slots.on_transaction(move |request| {
        count.fetch_add(1, Ordering::SeqCst);
        if request
            .mutations
            .iter()
            .any(|m| matches!(m, Mutation::DeleteRange { .. }))
        {
            let registry = request
                .predicates
                .iter()
                .find(|p| p.schema == NODE_SCHEMA && p.key.starts_with(b"host:"))
                .expect("cleanup binds the exact host-to-node registry row");
            assert_eq!(
                registry.expected,
                Expected::Bytes(node.to_be_bytes().to_vec())
            );
            actual.put_row(
                NODE_SCHEMA,
                &registry.key,
                &node.checked_add(1).unwrap().to_be_bytes(),
            );
        }
        None
    });
    let result = group.commit(&slots, &lease);
    slots.on_transaction(|_| None);
    assert!(result.is_err());
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "a lost registry identity cannot spin a cleanup retry or reach final publication"
    );
    assert_eq!(slots.rows_under(JOURNAL_SCHEMA), 0);
    assert_eq!(slots.rows_under(SCHEMA), 0);
}

#[test]
fn reconstructed_group_reoffer_validates_retained_history_before_the_offered_prefix() {
    for remove_genesis in [false, true] {
        let slots = RecordSlots::new();
        let (node, lease) = identity(
            &slots,
            if remove_genesis {
                "audit-group-history-genesis"
            } else {
                "audit-group-history-spacing"
            },
        );
        let mut sealed = Sealed::for_node(node);
        let records = group_records(&mut sealed, 4);
        let offered: Vec<_> = records.iter().map(raw).collect();
        prepare_audit_group(&slots, &lease, &offered)
            .unwrap()
            .unwrap()
            .commit(&slots, &lease)
            .unwrap();
        if remove_genesis {
            let key = sample_key(node, 1);
            let raw = wait_for(slots.record_get(SCHEMA, &key)).unwrap().unwrap();
            let delete = crate::root::durability::conditional::candidate(
                vec![Predicate {
                    schema: SCHEMA.into(),
                    key: key.clone(),
                    expected: Expected::Bytes(raw.as_slice().to_vec()),
                }],
                vec![Mutation::DeleteRange {
                    schema: SCHEMA.into(),
                    prefix: key,
                    exact_key_length: 17,
                }],
            );
            assert_eq!(slots.apply_transaction(&delete), Decision::Applied);
            let raw_head = wait_for(slots.record_get(SCHEMA, &tip_key(node)))
                .unwrap()
                .unwrap();
            let mut checkpoint: Checkpoint = serde_json::from_slice(raw_head.as_slice()).unwrap();
            checkpoint.samples -= 1;
            slots.put_row(
                SCHEMA,
                &tip_key(node),
                &serde_json::to_vec(&checkpoint).unwrap(),
            );
        } else {
            let key = sample_key(node, 2);
            let raw = wait_for(slots.record_get(SCHEMA, &key)).unwrap().unwrap();
            let mut prior: Head = serde_json::from_slice(raw.as_slice()).unwrap();
            prior.wall = START + 1;
            slots.put_row(SCHEMA, &key, &serde_json::to_vec(&prior).unwrap());
        }
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = attempts.clone();
        slots.on_transaction(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            None
        });
        let prefix = [raw(&records[2]), raw(&records[3])];
        assert!(prepare_audit_group(&slots, &lease, &prefix).is_err(), "matching current tip and relevant group samples cannot excuse malformed earlier retained history");
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
    }
}
