// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::durability::store_chain::{
    confirm_record_bytes, part_key, put_record, JOURNAL_SCHEMA, PART_BYTES,
};
use crate::root::durability::store_identity::{lease_row, set_lease_expiry, take_node};

fn identity(slots: &RecordSlots, host: &str) -> (u64, HeldLease) {
    let taken = take_node(slots, host).unwrap();
    let lease = HeldLease::default();
    lease.hold(taken.lease.unwrap());
    (taken.id, lease)
}

fn multipart(sealed: &mut Sealed, destination_bytes: usize) -> JournalRecord {
    let mut inputs = crate::root::durability::audit::tests::inputs(sealed.audit.next_seq());
    inputs.wall = START;
    inputs.what.destination = Some("x".repeat(destination_bytes));
    let record = sealed.audit.seal(
        inputs,
        &busbar_kernel::teller::verb_audit_pass(&crate::root::kernel::new_kernel()),
    );
    let journal = sealed.append(crate::root::durability::audit_entry(&record).unwrap());
    assert!(journal.encode().len() > PART_BYTES);
    journal
}

fn is_final(request: &Request) -> bool {
    request
        .mutations
        .iter()
        .any(|m| matches!(m, Mutation::Put { schema, .. } if schema == SCHEMA))
}

fn assert_whole_final(request: &Request, record: &JournalRecord) {
    let encoded = record.encode();
    let chunks: Vec<_> = encoded.chunks(PART_BYTES).collect();
    assert!(!request
        .mutations
        .iter()
        .any(|m| matches!(m, Mutation::DeleteRange { .. })));
    let parts: Vec<_> = request
        .mutations
        .iter()
        .filter_map(|m| match m {
            Mutation::Put { schema, key, value } if schema == JOURNAL_SCHEMA => Some((key, value)),
            _ => None,
        })
        .collect();
    assert_eq!(parts.len(), chunks.len());
    for (index, (key, value)) in parts.iter().enumerate() {
        assert_eq!(
            **key,
            part_key(record.node, record.node_seq, index as u16).to_vec()
        );
        let mut expected = (chunks.len() as u16).to_be_bytes().to_vec();
        expected.extend_from_slice(chunks[index]);
        assert_eq!(**value, expected);
    }
    assert!(request.mutations.iter().any(|m| matches!(m, Mutation::Put { schema, key, .. } if schema == SCHEMA && key == &tip_key(record.node))));
    assert!(request.mutations.iter().any(|m| matches!(m, Mutation::Put { schema, key, .. } if schema == SCHEMA && key == &sample_key(record.node, 1))));
}

#[test]
fn multipart_audit_publishes_all_parts_and_head_in_one_actual_store_transaction() {
    let slots = RecordSlots::new();
    let (node, lease) = identity(&slots, "audit-parts-whole");
    let mut sealed = Sealed::for_node(node);
    let record = multipart(&mut sealed, 2_000);
    let observed = Arc::new(Mutex::new(Vec::<Request>::new()));
    let capture = observed.clone();
    slots.on_transaction(move |request| {
        capture.lock().unwrap().push(request.clone());
        None
    });
    put_record(&slots, &lease, &raw(&record)).unwrap();
    confirm_record_bytes(&slots, &raw(&record)).unwrap();
    let requests = observed.lock().unwrap();
    assert_eq!(
        requests.len(),
        2,
        "one fenced cleanup and one whole-record publication are the only conditional crossings"
    );
    assert!(
        matches!(requests[0].mutations.as_slice(), [Mutation::DeleteRange { schema, .. }] if schema == JOURNAL_SCHEMA)
    );
    let finals: Vec<_> = requests.iter().filter(|r| is_final(r)).collect();
    assert_eq!(finals.len(), 1);
    assert_whole_final(finals[0], &record);
    assert_eq!(
        load(&slots, node).unwrap().unwrap().anchors(),
        sealed.audit.heads().anchors()
    );
}

#[test]
fn refused_whole_audit_transaction_publishes_no_parts_or_head() {
    let slots = RecordSlots::new();
    let (node, lease) = identity(&slots, "audit-parts-refused");
    let mut sealed = Sealed::for_node(node);
    let record = multipart(&mut sealed, 2_000);
    let final_seen = Arc::new(AtomicBool::new(false));
    let seen = final_seen.clone();
    slots.on_transaction(move |request| {
        if is_final(request) {
            seen.store(true, Ordering::SeqCst);
            Some(StoreFailure::Refused(
                "definitive final transaction refusal".into(),
            ))
        } else {
            None
        }
    });
    assert!(put_record(&slots, &lease, &raw(&record)).is_err());
    assert!(final_seen.load(Ordering::SeqCst));
    assert_eq!(slots.rows_under(JOURNAL_SCHEMA), 0);
    assert_eq!(slots.rows_under(SCHEMA), 0);
    slots.on_transaction(|_| None);
    put_record(&slots, &lease, &raw(&record)).unwrap();
    confirm_record_bytes(&slots, &raw(&record)).unwrap();
    assert_eq!(
        load(&slots, node).unwrap().unwrap().anchors(),
        sealed.audit.heads().anchors()
    );
}

#[test]
fn lost_whole_audit_reply_retries_exact_request_and_recorded_replay_skips_cleanup() {
    let slots = RecordSlots::new();
    let (node, lease) = identity(&slots, "audit-parts-lost");
    let mut sealed = Sealed::for_node(node);
    let record = multipart(&mut sealed, 2_000);
    let observed = Arc::new(Mutex::new(Vec::<Request>::new()));
    let capture = observed.clone();
    slots.on_transaction(move |request| {
        capture.lock().unwrap().push(request.clone());
        None
    });
    slots.lose_acks(true);
    put_record(&slots, &lease, &raw(&record)).unwrap();
    let before = observed.lock().unwrap().len();
    let puts = slots.puts();
    put_record(&slots, &lease, &raw(&record)).unwrap();
    assert_eq!(
        observed.lock().unwrap().len(),
        before,
        "Recorded is recognized before destructive cleanup"
    );
    assert_eq!(slots.puts(), puts);
    let requests = observed.lock().unwrap();
    let finals: Vec<_> = requests.iter().filter(|r| is_final(r)).collect();
    assert!(
        finals.len() >= 2,
        "the actual Store loses its first applied final reply"
    );
    assert!(
        finals.iter().all(|request| *request == finals[0]),
        "retry retains operation id and all bytes"
    );
    assert_whole_final(finals[0], &record);
    confirm_record_bytes(&slots, &raw(&record)).unwrap();
    assert_eq!(
        load(&slots, node).unwrap().unwrap().anchors(),
        sealed.audit.heads().anchors()
    );
}

#[test]
fn authority_lost_after_actual_cleanup_cannot_publish_any_audit_part_or_head() {
    for replace in [false, true] {
        let slots = RecordSlots::new();
        let host = if replace {
            "audit-parts-replaced"
        } else {
            "audit-parts-released"
        };
        let (node, lease) = identity(&slots, host);
        let old_holder = lease_row(&slots, host).unwrap().0;
        let mut sealed = Sealed::for_node(node);
        let record = multipart(&mut sealed, 2_000);
        let cleaned = Arc::new(AtomicBool::new(false));
        let cleanup = cleaned.clone();
        let finals = Arc::new(AtomicUsize::new(0));
        let final_calls = finals.clone();
        let actual = slots.clone();
        slots.on_transaction(move |request| {
            if is_final(request) {
                final_calls.fetch_add(1, Ordering::SeqCst);
            }
            if request.mutations.iter().any(
                |m| matches!(m, Mutation::DeleteRange { schema, .. } if schema == JOURNAL_SCHEMA),
            ) && !cleanup.swap(true, Ordering::SeqCst)
            {
                assert_eq!(actual.apply_transaction(request), Decision::Applied);
                set_lease_expiry(&actual, host, 0);
                if replace {
                    let successor = take_node(&actual, host).unwrap();
                    assert_eq!(successor.id, node);
                    assert_ne!(lease_row(&actual, host).unwrap().0, old_holder);
                }
                return Some(StoreFailure::Failed(
                    "cleanup applied but reply lost".into(),
                ));
            }
            None
        });
        let result = put_record(&slots, &lease, &raw(&record));
        // Drop the callback's actual-Store clone before asserting or unwinding.
        slots.on_transaction(|_| None);
        assert!(result.is_err());
        assert!(cleaned.load(Ordering::SeqCst));
        assert_eq!(finals.load(Ordering::SeqCst), 0);
        assert_eq!(slots.rows_under(JOURNAL_SCHEMA), 0);
        assert_eq!(slots.rows_under(SCHEMA), 0);
    }
}

#[test]
fn oversized_whole_audit_frame_is_preflighted_before_cleanup_and_uses_split_fallback() {
    let slots = RecordSlots::new();
    let (node, lease) = identity(&slots, "audit-parts-oversized");
    let mut sealed = Sealed::for_node(node);
    let record = multipart(
        &mut sealed,
        busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize,
    );
    let cleanup_seen = Arc::new(AtomicBool::new(false));
    let cleaned = cleanup_seen.clone();
    let split_seen = Arc::new(AtomicBool::new(false));
    let split = split_seen.clone();
    slots.on_transaction(move |request| {
        assert!(
            request.encode_held().is_ok(),
            "no oversized conditional request may reach the Store"
        );
        if request
            .mutations
            .iter()
            .any(|m| matches!(m, Mutation::DeleteRange { schema, .. } if schema == JOURNAL_SCHEMA))
        {
            cleaned.store(true, Ordering::SeqCst);
            return None;
        }
        assert!(cleaned.load(Ordering::SeqCst));
        assert!(!is_final(request));
        assert_eq!(
            request.mutations.len(),
            1,
            "the preserved fallback writes one ordinary part at a time"
        );
        split.store(true, Ordering::SeqCst);
        Some(StoreFailure::Refused(
            "stop after proving the original split fallback".into(),
        ))
    });
    assert!(put_record(&slots, &lease, &raw(&record)).is_err());
    assert!(cleanup_seen.load(Ordering::SeqCst));
    assert!(split_seen.load(Ordering::SeqCst));
    assert_eq!(slots.rows_under(SCHEMA), 0);
}

#[test]
fn whole_audit_final_renews_the_exact_same_holder_fence_after_actual_conflict() {
    use crate::root::durability::store_identity::NODE_SCHEMA;
    const HOST: &str = "audit-parts-renewed-final";
    let slots = RecordSlots::new();
    let (node, lease) = identity(&slots, HOST);
    let mut sealed = Sealed::for_node(node);
    let record = multipart(&mut sealed, 2_000);
    let finals = Arc::new(Mutex::new(Vec::<Request>::new()));
    let capture = finals.clone();
    let actual = slots.clone();
    slots.on_transaction(move |request| {
        if !is_final(request) {
            return None;
        }
        let mut observed = capture.lock().unwrap();
        observed.push(request.clone());
        if observed.len() == 1 {
            let (holder, expires) = lease_row(&actual, HOST).unwrap();
            set_lease_expiry(&actual, HOST, expires + 10_000);
            assert_eq!(lease_row(&actual, HOST).unwrap().0, holder);
        } else {
            assert_eq!(
                actual.rows_under(JOURNAL_SCHEMA),
                0,
                "the stale-fence conflict published no part"
            );
            assert_eq!(
                actual.rows_under(SCHEMA),
                0,
                "the stale-fence conflict published no head or sample"
            );
        }
        None
    });
    let result = put_record(&slots, &lease, &raw(&record));
    slots.on_transaction(|_| None);
    result.unwrap();
    let requests = finals.lock().unwrap();
    assert_eq!(
        requests.len(),
        2,
        "one real conflict is followed by one fresh-fence publication"
    );
    let fence = |request: &Request| {
        request
            .predicates
            .iter()
            .find(|p| p.schema == NODE_SCHEMA)
            .unwrap()
            .expected
            .clone()
    };
    assert_ne!(fence(&requests[0]), fence(&requests[1]));
    assert_whole_final(&requests[0], &record);
    assert_whole_final(&requests[1], &record);
    confirm_record_bytes(&slots, &raw(&record)).unwrap();
    assert_eq!(
        load(&slots, node).unwrap().unwrap().anchors(),
        sealed.audit.heads().anchors()
    );
}

#[test]
fn immutable_sample_conflict_in_whole_final_publishes_no_parts_or_tip() {
    let slots = RecordSlots::new();
    let (node, lease) = identity(&slots, "audit-parts-sample-conflict");
    let mut sealed = Sealed::for_node(node);
    let record = multipart(&mut sealed, 2_000);
    let raced = Arc::new(AtomicBool::new(false));
    let race = raced.clone();
    let actual = slots.clone();
    slots.on_transaction(move |request| {
        if is_final(request) && !race.swap(true, Ordering::SeqCst) {
            let (key, bytes) = request
                .mutations
                .iter()
                .find_map(|m| match m {
                    Mutation::Put { schema, key, value }
                        if schema == SCHEMA && key == &sample_key(node, 1) =>
                    {
                        Some((key, value))
                    }
                    _ => None,
                })
                .expect("the whole final includes the immutable sample");
            let mut conflicting: Head = serde_json::from_slice(bytes).unwrap();
            conflicting.wall += 1;
            actual.put_row(SCHEMA, key, &serde_json::to_vec(&conflicting).unwrap());
        }
        None
    });
    let result = put_record(&slots, &lease, &raw(&record));
    slots.on_transaction(|_| None);
    assert!(result.is_err());
    assert!(raced.load(Ordering::SeqCst));
    assert_eq!(slots.rows_under(JOURNAL_SCHEMA), 0);
    assert!(wait_for(slots.record_get(SCHEMA, &tip_key(node)))
        .unwrap()
        .is_none());
    assert_eq!(
        slots.rows_under(SCHEMA),
        1,
        "only the independently injected conflicting sample exists"
    );
}
