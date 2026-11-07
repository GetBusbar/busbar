// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::sdk::door::blank_in;
use crate::redacted::Secret;

fn prepared() -> owned::PreparedCandidate {
    owned::PreparedCandidate::new(owned::Candidate {
        id: owned::AttemptId {
            dataset: owned::DatasetId([1; 16]),
            writer_epoch: 3,
            writer: [2; 16],
            execution_epoch: 4,
            operation: [5; 16],
        },
        codec: owned::CANDIDATE_VERSION,
        predicates: vec![owned::Predicate {
            address: owned::Address {
                namespace: [6; 16],
                key: vec![0, 255],
            },
            expected: ExpectedValue::Exact(Secret::new(vec![9; 600])),
        }],
        mutations: vec![
            Mutation::Put {
                address: owned::Address {
                    namespace: [6; 16],
                    key: vec![0, 255],
                },
                value: Secret::new(vec![7; 1024]),
            },
            Mutation::DeleteRange {
                namespace: owned::NamespaceId([6; 16]),
                prefix: vec![1],
                exact_key_length: 4,
            },
        ],
        time: Some(owned::TimeGuard {
            not_before: Some(10),
            before: Some(100),
        }),
        result: Secret::new(b"receipt".to_vec()),
    })
    .unwrap()
}

#[test]
fn v4_commit_marshalling_roundtrip_preserves_complete_candidate_across_move() {
    let prepared = prepared();
    let marshalled = Commit::new(&prepared, 4096).unwrap();
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let frame = marshalled.frame(
                    blank_in::<wire::CommitIn>().head,
                    HostBuf {
                        ptr: std::ptr::null_mut(),
                        cap: 0,
                    },
                );
                // SAFETY: the immutable marshaller retains every descriptor and payload.
                let decoded = unsafe { decode::candidate(&frame.candidate, 65536) }.unwrap();
                assert_eq!(decoded.fingerprint(), marshalled.candidate.fingerprint());
                assert_eq!(frame.candidate.result.flags, BLOB_SECRET);
            })
            .join()
            .unwrap();
    });
}

#[test]
fn v4_descriptor_budget_refuses_before_submission_without_changing_candidate() {
    let prepared = prepared();
    let digest = prepared.fingerprint();
    assert!(matches!(
        Commit::new(&prepared, 0),
        Err(MarshalError::Budget)
    ));
    assert_eq!(prepared.fingerprint(), digest);
    assert!(Commit::new(&prepared, 4096).is_ok());
}

#[test]
fn v4_read_and_scan_marshalling_keep_binary_cursors_and_time_boundaries() {
    let source = owned::Read {
        dataset: owned::DatasetId([3; 16]),
        addresses: vec![owned::Address {
            namespace: [4; 16],
            key: vec![0, 255],
        }],
        time: Some(owned::TimeGuard {
            not_before: None,
            before: Some(1),
        }),
    };
    let source = std::sync::Arc::new(source);
    let marshal = Read::new(source.clone(), 4096).unwrap();
    let blank = blank_in::<wire::ReadIn>();
    let frame = marshal.frame(blank.head, blank.values);
    // SAFETY: the marshaller and source retain all immutable input spans.
    let decoded = unsafe { decode::read(&frame, 4096) }.unwrap();
    assert_eq!(source.addresses, decoded.addresses);
    assert_eq!(source.time, decoded.time);
    let source = owned::Scan {
        dataset: source.dataset,
        namespace: owned::NamespaceId([4; 16]),
        prefix: vec![0],
        after: Some(vec![0, 255]),
        generation: Some(7),
        allow_change: false,
        max_items: 20,
        max_bytes: 16384,
    };
    let blank = blank_in::<wire::ScanIn>();
    let frame = scan(&source, blank.head, blank.rows);
    // SAFETY: source retains prefix and cursor allocations.
    let decoded = unsafe { decode::scan(&frame, 4096) }.unwrap();
    assert_eq!(source.after, decoded.after);
    assert_eq!(source.generation, decoded.generation);
    assert_eq!(source.prefix, decoded.prefix);
}
