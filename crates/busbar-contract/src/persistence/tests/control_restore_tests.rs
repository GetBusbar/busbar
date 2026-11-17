// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-331 r3.2 §B2: the restore row (`b"r"` in the control namespace). Built from raw bytes so
//! the shape, not a helper, is what is checked: `"BSR1\0\0\0\0" ‖ epoch u64 LE ‖ state u8
//! (1 pending, 2 declared) ‖ 7 zero bytes ‖ declared_at u64 LE ‖ declaration digest [32]`.

use super::super::{Address, AttemptId, Candidate, Predicate};
use super::*;

const DATASET: DatasetId = DatasetId([1; 16]);
const STAMP: [u8; 16] = [2; 16];
const PENDING: u8 = 1;
const DECLARED: u8 = 2;

fn row(epoch: u64, state: u8, declared_at: u64, digest: [u8; 32]) -> Vec<u8> {
    let mut value = b"BSR1\0\0\0\0".to_vec();
    value.extend_from_slice(&epoch.to_le_bytes());
    value.push(state);
    value.extend_from_slice(&[0; 7]);
    value.extend_from_slice(&declared_at.to_le_bytes());
    value.extend_from_slice(&digest);
    value
}

fn at() -> Address {
    Address {
        namespace: NAMESPACE.0,
        key: b"r".to_vec(),
    }
}

/// One candidate stamped by a live writer that replaces the restore row `previous` with `next`.
fn put(previous: Option<Vec<u8>>, next: Vec<u8>) -> Candidate {
    Candidate {
        id: AttemptId {
            dataset: DATASET,
            writer_epoch: 1,
            writer: STAMP,
            execution_epoch: 1,
            operation: [3; 16],
        },
        codec: CANDIDATE_VERSION,
        predicates: vec![Predicate {
            address: at(),
            expected: previous.map_or(ExpectedValue::Absent, |old| {
                ExpectedValue::Exact(Secret::new(old))
            }),
        }],
        mutations: vec![Mutation::Put {
            address: at(),
            value: Secret::new(next),
        }],
        time: None,
        result: Secret::new(Vec::new()),
    }
}

fn admitted(candidate: Candidate) -> Result<(), Failure> {
    admit(&PreparedCandidate::new(candidate).unwrap())
}

#[test]
fn the_restore_row_moves_absent_to_pending_to_declared_and_back_to_pending() {
    let digest = [9; 32];
    assert_eq!(admitted(put(None, row(0, PENDING, 0, [0; 32]))), Ok(()));
    assert_eq!(
        admitted(put(
            Some(row(0, PENDING, 0, [0; 32])),
            row(1, DECLARED, 1_800_000_000, digest)
        )),
        Ok(())
    );
    assert_eq!(
        admitted(put(
            Some(row(1, DECLARED, 1_800_000_000, digest)),
            row(1, PENDING, 1_800_000_000, digest)
        )),
        Ok(())
    );
}

#[test]
fn the_restore_row_refuses_every_other_transition_and_shape() {
    let digest = [9; 32];
    let pending0 = row(0, PENDING, 0, [0; 32]);
    let declared1 = row(1, DECLARED, 1_800_000_000, digest);
    let refused = [
        // A first row is pending at epoch 0, never declared and never a later epoch.
        put(None, row(1, PENDING, 0, [0; 32])),
        put(None, row(1, DECLARED, 1_800_000_000, digest)),
        // A declaration advances the epoch by exactly one.
        put(
            Some(pending0.clone()),
            row(0, DECLARED, 1_800_000_000, digest),
        ),
        put(
            Some(pending0.clone()),
            row(2, DECLARED, 1_800_000_000, digest),
        ),
        // A declaration names its time and digest.
        put(Some(pending0.clone()), row(1, DECLARED, 0, digest)),
        put(
            Some(pending0.clone()),
            row(1, DECLARED, 1_800_000_000, [0; 32]),
        ),
        // No pending -> normal, no re-declaring, no pending at another epoch.
        put(Some(pending0.clone()), pending0.clone()),
        put(
            Some(declared1.clone()),
            row(2, DECLARED, 1_900_000_000, digest),
        ),
        put(
            Some(declared1.clone()),
            row(2, PENDING, 1_800_000_000, digest),
        ),
        // Unknown state, nonzero reserved bytes, a wrong magic or length.
        put(None, row(0, 3, 0, [0; 32])),
        put(None, {
            let mut value = row(0, PENDING, 0, [0; 32]);
            value[17] = 1;
            value
        }),
        put(None, {
            let mut value = row(0, PENDING, 0, [0; 32]);
            value[3] = b'2';
            value
        }),
        put(None, row(0, PENDING, 0, [0; 32])[..63].to_vec()),
    ];
    for candidate in refused {
        assert_eq!(admitted(candidate), Err(Failure::Refused));
    }
    // Never deleted.
    let mut delete = put(Some(declared1.clone()), declared1);
    delete.mutations = vec![Mutation::Delete(at())];
    assert_eq!(admitted(delete), Err(Failure::Refused));
    // Never put without its own guard.
    let mut unguarded = put(None, pending0);
    unguarded.predicates.clear();
    assert_eq!(admitted(unguarded), Err(Failure::Refused));
}
