// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::plugin::TestKernelSeal;

fn candidate(items: usize) -> PreparedCandidate {
    PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: DatasetId([1; 16]),
            writer_epoch: 2,
            writer: [3; 16],
            execution_epoch: 4,
            operation: [5; 16],
        },
        codec: CANDIDATE_VERSION,
        predicates: vec![
            Predicate {
                address: Address {
                    namespace: [6; 16],
                    key: vec![0, 255],
                },
                expected: ExpectedValue::Absent,
            },
            Predicate {
                address: Address {
                    namespace: [6; 16],
                    key: vec![1, 0],
                },
                expected: ExpectedValue::Exact(Secret::new(vec![42; 513])),
            },
        ],
        mutations: (0..items)
            .map(|i| Mutation::Put {
                address: Address {
                    namespace: [7; 16],
                    key: (i as u64).to_le_bytes().to_vec(),
                },
                value: Secret::new(vec![i as u8; 1024]),
            })
            .chain([
                Mutation::Delete(Address {
                    namespace: [8; 16],
                    key: vec![0],
                }),
                Mutation::DeleteRange {
                    namespace: NamespaceId([9; 16]),
                    prefix: vec![0, 255],
                    exact_key_length: 4,
                },
            ])
            .collect(),
        time: Some(TimeGuard {
            not_before: Some(123),
            before: Some(456),
        }),
        result: Secret::new(vec![0, 255, 1]),
    })
    .unwrap()
}

#[test]
fn roundtrip_preserves_exact_bytes_order_identity_and_large_candidates() {
    for items in [0, 1, 101] {
        let original = candidate(items);
        let wire = encode(&original, usize::MAX, &TestKernelSeal).unwrap();
        let restored = decode(&wire, usize::MAX, &TestKernelSeal).unwrap();
        assert_eq!(restored.fingerprint(), original.fingerprint());
        assert_eq!(restored.candidate().id, original.candidate().id);
        assert_eq!(restored.candidate().time, original.candidate().time);
        assert_eq!(restored.candidate().codec, original.candidate().codec);
        assert_eq!(
            encode(&restored, usize::MAX, &TestKernelSeal).unwrap(),
            wire
        );
    }
}

#[test]
fn optional_time_shapes_and_empty_values_roundtrip_exactly() {
    for time in [
        None,
        Some(TimeGuard {
            not_before: None,
            before: None,
        }),
        Some(TimeGuard {
            not_before: Some(0),
            before: None,
        }),
        Some(TimeGuard {
            not_before: None,
            before: Some(u64::MAX),
        }),
    ] {
        let mut value = Candidate {
            id: candidate(0).candidate().id,
            codec: CANDIDATE_VERSION,
            predicates: Vec::new(),
            mutations: vec![Mutation::Put {
                address: Address {
                    namespace: [0; 16],
                    key: vec![],
                },
                value: Secret::default(),
            }],
            time,
            result: Secret::default(),
        };
        value.predicates.push(Predicate {
            address: Address {
                namespace: [0; 16],
                key: vec![],
            },
            expected: ExpectedValue::Exact(Secret::default()),
        });
        let wire = encode(
            &PreparedCandidate::new(value).unwrap(),
            usize::MAX,
            &TestKernelSeal,
        )
        .unwrap();
        let restored = decode(&wire, usize::MAX, &TestKernelSeal).unwrap();
        assert_eq!(restored.candidate().time, time);
        assert_eq!(
            encode(&restored, usize::MAX, &TestKernelSeal).unwrap(),
            wire
        );
    }
}

#[test]
fn detects_identity_value_order_and_fingerprint_corruption() {
    let original = candidate(2);
    let wire = encode(&original, usize::MAX, &TestKernelSeal).unwrap();
    for position in [12, 48, wire.expose(&TestKernelSeal).len() - 1] {
        let mut corrupted = wire.expose(&TestKernelSeal).clone();
        corrupted[position] ^= 1;
        assert_eq!(
            decode(&Secret::new(corrupted), usize::MAX, &TestKernelSeal).unwrap_err(),
            CodecError::Fingerprint
        );
    }
    let mut corrupted = wire.expose(&TestKernelSeal).clone();
    let mut reader = Reader {
        bytes: &corrupted,
        offset: 0,
    };
    reader.header().unwrap();
    for _ in 0..reader.count().unwrap() {
        reader.predicate().unwrap();
    }
    reader.count().unwrap();
    let start = reader.offset;
    reader.mutation().unwrap();
    let middle = reader.offset;
    reader.mutation().unwrap();
    let end = reader.offset;
    assert_eq!(middle - start, end - middle);
    corrupted[start..end].rotate_left(middle - start);
    assert_eq!(
        decode(&Secret::new(corrupted), usize::MAX, &TestKernelSeal).unwrap_err(),
        CodecError::Fingerprint
    );
}

#[test]
fn refuses_every_truncation_trailing_bytes_unknown_versions_and_flags() {
    let wire = encode(&candidate(0), usize::MAX, &TestKernelSeal).unwrap();
    let bytes = wire.expose(&TestKernelSeal);
    for length in 0..bytes.len() {
        assert!(
            decode(
                &Secret::new(bytes[..length].to_vec()),
                usize::MAX,
                &TestKernelSeal
            )
            .is_err(),
            "length {length}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        decode(&Secret::new(trailing), usize::MAX, &TestKernelSeal).unwrap_err(),
        CodecError::Malformed
    );
    for position in [8, 44] {
        let mut version = bytes.clone();
        version[position] = 255;
        assert_eq!(
            decode(&Secret::new(version), usize::MAX, &TestKernelSeal).unwrap_err(),
            CodecError::Version
        );
    }
    // Time-presence and both bound-presence flags must be canonical booleans.
    for position in [112, 113, 122] {
        let mut flag = bytes.clone();
        flag[position] = 2;
        assert_eq!(
            decode(&Secret::new(flag), usize::MAX, &TestKernelSeal).unwrap_err(),
            CodecError::Malformed
        );
    }
}

#[test]
fn admission_uses_the_actual_encoded_and_decoded_allocation_boundaries() {
    let original = candidate(101);
    let wire = encode(&original, usize::MAX, &TestKernelSeal).unwrap();
    let length = wire.expose(&TestKernelSeal).len();
    assert_eq!(
        encode(&original, length - 1, &TestKernelSeal).unwrap_err(),
        CodecError::Budget
    );
    assert_eq!(encode(&original, length, &TestKernelSeal).unwrap(), wire);
    let layout = preflight(wire.expose(&TestKernelSeal)).unwrap();
    let allocation = layout.owned_bytes().unwrap();
    assert!(allocation > layout.payload);
    assert_eq!(
        decode(&wire, allocation - 1, &TestKernelSeal).unwrap_err(),
        CodecError::Budget
    );
    assert!(decode(&wire, allocation, &TestKernelSeal).is_ok());
}

#[test]
fn counted_length_and_allocation_arithmetic_cannot_wrap() {
    let wire = encode(&candidate(0), usize::MAX, &TestKernelSeal).unwrap();
    let mut bytes = wire.expose(&TestKernelSeal).clone();
    let mut reader = Reader {
        bytes: &bytes,
        offset: 0,
    };
    reader.header().unwrap();
    let predicate_count = reader.offset;
    bytes[predicate_count..predicate_count + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(decode(&Secret::new(bytes), usize::MAX, &TestKernelSeal).is_err());
    let mut output = Output::Count(usize::MAX);
    assert_eq!(output.put(&[1]), Err(CodecError::Overflow));
    assert_eq!(
        Layout {
            predicates: usize::MAX,
            mutations: 0,
            payload: 0
        }
        .owned_bytes(),
        Err(CodecError::Overflow)
    );
    assert_eq!(
        Layout {
            predicates: 0,
            mutations: 1,
            payload: usize::MAX
        }
        .owned_bytes(),
        Err(CodecError::Overflow)
    );
    let mut reader = Reader {
        bytes: &[0],
        offset: 1,
    };
    assert_eq!(reader.take(usize::MAX), Err(CodecError::Overflow));
}

#[test]
fn matching_digest_does_not_bypass_candidate_validation() {
    let wire = encode(&candidate(2), usize::MAX, &TestKernelSeal).unwrap();
    for (position, replacement, expected) in [
        (48, vec![0; 16], InvalidCandidate::Identity),
        (
            114,
            456_u64.to_le_bytes().to_vec(),
            InvalidCandidate::TimeInterval,
        ),
    ] {
        let mut bytes = wire.expose(&TestKernelSeal).clone();
        bytes[position..position + replacement.len()].copy_from_slice(&replacement);
        let mut reader = Reader {
            bytes: &bytes,
            offset: 0,
        };
        let header = reader.header().unwrap();
        let digest = semantic_fingerprint(&header, &bytes[reader.offset..]);
        bytes[12..44].copy_from_slice(&digest);
        assert_eq!(
            decode(&Secret::new(bytes), usize::MAX, &TestKernelSeal).unwrap_err(),
            CodecError::Invalid(expected)
        );
    }
}
