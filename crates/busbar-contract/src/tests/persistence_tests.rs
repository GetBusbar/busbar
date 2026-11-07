// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::TimeGuard;
use super::{
    Address, AttemptId, Candidate, DatasetId, ExpectedValue, InvalidCandidate, Mutation,
    NamespaceId, Predicate, CANDIDATE_VERSION,
};
use crate::redacted::Secret;

fn candidate(mutations: Vec<Mutation>) -> Candidate {
    Candidate {
        id: AttemptId {
            dataset: DatasetId([1; 16]),
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
            operation: [3; 16],
        },
        codec: CANDIDATE_VERSION,
        predicates: Vec::new(),
        mutations,
        time: None,
        result: Secret::new(Vec::new()),
    }
}

fn address(key: &[u8]) -> Address {
    Address {
        namespace: [4; 16],
        key: key.to_vec(),
    }
}

fn range(prefix: &[u8], length: u64) -> Mutation {
    Mutation::DeleteRange {
        namespace: NamespaceId([4; 16]),
        prefix: prefix.to_vec(),
        exact_key_length: length,
    }
}

#[test]
fn persistence_rejects_overlapping_ranges_and_points_but_preserves_exact_lengths() {
    for mutations in [
        vec![range(&[0xff], 3), range(&[0xff, 0x00], 3)],
        vec![
            range(&[0xff], 3),
            Mutation::Delete(address(&[0xff, 0x00, 0x01])),
        ],
        vec![
            Mutation::Delete(address(b"x")),
            Mutation::Put {
                address: address(b"x"),
                value: Secret::new(vec![1]),
            },
        ],
    ] {
        assert_eq!(
            candidate(mutations).validate(),
            Err(InvalidCandidate::Overlap)
        );
    }
    assert_eq!(
        candidate(vec![
            range(&[0xff], 3),
            range(&[0xff], 4),
            Mutation::Delete(address(&[0xff, 0x00]))
        ])
        .validate(),
        Ok(())
    );
    assert_eq!(
        candidate(vec![range(b"long", 3)]).validate(),
        Err(InvalidCandidate::RangeLength)
    );
}

#[test]
fn persistence_allows_predicate_mutation_overlap_and_large_typed_batches() {
    let mut request = candidate(
        (0u32..1001)
            .map(|n| Mutation::Put {
                address: address(&n.to_be_bytes()),
                value: Secret::new(vec![7; 1024]),
            })
            .collect(),
    );
    request.predicates.push(Predicate {
        address: address(&0u32.to_be_bytes()),
        expected: ExpectedValue::Absent,
    });
    assert_eq!(request.validate(), Ok(()));
    request.predicates.push(Predicate {
        address: address(&0u32.to_be_bytes()),
        expected: ExpectedValue::Exact(Secret::new(vec![9])),
    });
    assert_eq!(
        request.validate(),
        Err(InvalidCandidate::DuplicatePredicate)
    );
}

#[test]
fn persistence_unknown_codec_and_unregistered_execution_authority_refuse() {
    let mut request = candidate(vec![Mutation::Delete(address(b"key"))]);
    request.codec += 1;
    assert_eq!(request.validate(), Err(InvalidCandidate::Version));
    request.codec = CANDIDATE_VERSION;
    request.id.execution_epoch = 0;
    assert_eq!(request.validate(), Err(InvalidCandidate::Identity));
}

#[test]
fn persistence_sealed_candidate_identity_covers_epochs_payloads_and_result() {
    use super::PreparedCandidate;
    let make = || {
        candidate(vec![Mutation::Put {
            address: address(b"key"),
            value: Secret::new(b"confidential-value".to_vec()),
        }])
    };
    let original = PreparedCandidate::new(make()).unwrap();
    assert_eq!(
        original.fingerprint(),
        PreparedCandidate::new(make()).unwrap().fingerprint()
    );
    let shared = original.clone();
    assert!(std::ptr::eq(original.candidate(), shared.candidate()));
    assert!(!format!("{original:?}").contains("confidential-value"));
    for change in 0..8 {
        let mut altered = make();
        match change {
            0 => altered.id.dataset.0[0] += 1,
            1 => altered.id.writer_epoch += 1,
            2 => altered.id.writer[0] += 1,
            3 => altered.id.execution_epoch += 1,
            4 => altered.id.operation[0] += 1,
            5 => {
                altered.time = Some(TimeGuard {
                    not_before: None,
                    before: Some(100),
                })
            }
            6 => altered.result = Secret::new(vec![1]),
            7 => altered.mutations = vec![Mutation::Delete(address(b"key"))],
            _ => unreachable!(),
        }
        assert_ne!(
            original.fingerprint(),
            PreparedCandidate::new(altered).unwrap().fingerprint()
        );
    }
}

#[test]
fn persistence_fingerprint_frames_variable_fields_and_preserves_order() {
    use super::PreparedCandidate;
    let put = |key: &[u8], value: &[u8]| Mutation::Put {
        address: address(key),
        value: Secret::new(value.to_vec()),
    };
    let digest = |mutations| {
        PreparedCandidate::new(candidate(mutations))
            .unwrap()
            .fingerprint()
    };
    assert_ne!(
        digest(vec![put(b"a", b"bc")]),
        digest(vec![put(b"ab", b"c")])
    );
    assert_ne!(
        digest(vec![put(b"a", b"1"), put(b"b", b"2")]),
        digest(vec![put(b"b", b"2"), put(b"a", b"1")])
    );
    assert_ne!(digest(vec![range(b"a", 2)]), digest(vec![range(b"a", 3)]));
}

#[test]
fn persistence_unguarded_time_has_one_wire_fingerprint() {
    use super::PreparedCandidate;
    let make = || candidate(vec![Mutation::Delete(address(b"key"))]);
    let none = PreparedCandidate::new(make()).unwrap();
    let mut explicit = make();
    explicit.time = Some(TimeGuard {
        not_before: None,
        before: None,
    });
    assert_eq!(
        none.fingerprint(),
        PreparedCandidate::new(explicit).unwrap().fingerprint()
    );
}

#[test]
fn persistence_expiry_is_exclusive_even_at_largest_timestamp() {
    let guard = TimeGuard {
        not_before: Some(u64::MAX - 1),
        before: Some(u64::MAX),
    };
    assert!(!guard.permits(u64::MAX - 2));
    assert!(guard.permits(u64::MAX - 1));
    assert!(!guard.permits(u64::MAX));
}

#[test]
fn persistence_empty_or_inverted_interval_never_admits() {
    for (lower, upper) in [(42, 42), (43, 42)] {
        let guard = TimeGuard {
            not_before: Some(lower),
            before: Some(upper),
        };
        for now in [0, 41, 42, 43, u64::MAX] {
            assert!(!guard.permits(now));
        }
    }
}
