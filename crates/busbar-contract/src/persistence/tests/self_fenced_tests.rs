// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STORE-TRANSACTIONS 8.16: the witness rule, from the candidate alone.

use super::*;
use crate::persistence::{AttemptId, DatasetId, Predicate, TimeGuard, CANDIDATE_VERSION};
use crate::Secret;

const DATASET: DatasetId = DatasetId([1; 16]);
const OP: [u8; 16] = [7; 16];
const M: [u8; 16] = [9; 16];

fn open() -> Vec<u8> {
    control::Writer {
        retired_through: 0,
        admitted_through: 1,
    }
    .encode()
    .unwrap()
    .to_vec()
}

fn writer(w: u8) -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key: control::writer_key([w; 16]).to_vec(),
    }
}

fn root() -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key: control::DATASET_KEY.to_vec(),
    }
}

fn manifest() -> Address {
    Address {
        namespace: witness::FORMAT_NAMESPACE.0,
        key: b"active".to_vec(),
    }
}

fn absent(address: Address) -> Predicate {
    Predicate {
        address,
        expected: ExpectedValue::Absent,
    }
}

fn exact(address: Address, value: &[u8]) -> Predicate {
    Predicate {
        address,
        expected: ExpectedValue::Exact(Secret::new(value.to_vec())),
    }
}

fn put(address: Address, value: &[u8]) -> Mutation {
    Mutation::Put {
        address,
        value: Secret::new(value.to_vec()),
    }
}

fn prepared(predicates: Vec<Predicate>, mutations: Vec<Mutation>) -> PreparedCandidate {
    PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: DATASET,
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
            operation: OP,
        },
        codec: CANDIDATE_VERSION,
        predicates,
        mutations,
        time: None,
        result: Secret::new(Vec::new()),
    })
    .unwrap()
}

fn guard(op: [u8; 16], state: u8) -> Vec<u8> {
    let mut bytes = vec![0; witness::GUARD_LEN];
    bytes[..8].copy_from_slice(b"BSMIGD1\0");
    bytes[8..24].copy_from_slice(&M);
    bytes[24..40].copy_from_slice(&op);
    bytes[40] = state;
    bytes
}

fn payload(op: [u8; 16]) -> Vec<u8> {
    let mut bytes = vec![0; 160];
    bytes[..8].copy_from_slice(b"BSMINT1\0");
    bytes[24..40].copy_from_slice(&M);
    bytes[40..56].copy_from_slice(&op);
    bytes
}

#[test]
fn initialize_and_register_pick_the_fresh_writer_row() {
    let birth = witness::birth();
    let root_value = control::Dataset {
        id: DATASET,
        writer_epoch: 1,
    }
    .encode()
    .unwrap();
    let initialize = prepared(
        vec![
            absent(root()),
            absent(writer(2)),
            absent(control::epoch_row([2; 16], 1)),
            absent(manifest()),
            absent(birth.clone()),
        ],
        vec![
            put(root(), &root_value),
            put(writer(2), &open()),
            put(control::epoch_row([2; 16], 1), control::EPOCH_VALUE),
            put(manifest(), b"m"),
            put(birth.clone(), b"b"),
        ],
    );
    let proof = SelfFenced::check(&initialize).unwrap();
    assert_eq!(proof.kind(), WitnessKind::Absent);
    assert_eq!(proof.witness_puts(), (1, None));
    assert!(proof.no_aba());

    let register = prepared(
        vec![
            exact(root(), &root_value),
            exact(manifest(), b"m"),
            exact(writer(2), &open()),
            absent(writer(3)),
            exact(birth.clone(), b"b"),
        ],
        vec![put(writer(3), &open()), put(birth, b"owned")],
    );
    let proof = SelfFenced::check(&register).unwrap();
    assert_eq!(
        (proof.kind(), proof.witness_puts()),
        (WitnessKind::Absent, (0, None))
    );
    assert!(proof.no_aba());
}

#[test]
fn cold_registration_picks_the_cold_writer_not_the_shared_owner_row() {
    let owner = witness::intent(b'w', M);
    let cold = prepared(
        vec![absent(owner.clone()), absent(writer(4))],
        vec![put(owner, b"binding"), put(writer(4), &open())],
    );
    let proof = SelfFenced::check(&cold).unwrap();
    assert_eq!(
        (proof.kind(), proof.witness_puts()),
        (WitnessKind::Absent, (1, None))
    );
}

#[test]
fn intent_journal_first_write_and_clear_use_the_value_pair() {
    let g = witness::intent(b'g', M);
    let p = witness::intent(b'p', M);
    let first = prepared(
        vec![
            exact(writer(4), &open()),
            absent(g.clone()),
            absent(p.clone()),
        ],
        vec![put(g.clone(), &guard(OP, 1)), put(p.clone(), &payload(OP))],
    );
    let proof = SelfFenced::check(&first).unwrap();
    assert_eq!(
        (proof.kind(), proof.witness_puts()),
        (WitnessKind::Value, (0, Some(1)))
    );
    assert!(proof.no_aba());
    let clear = prepared(
        vec![
            exact(g.clone(), &guard(OP, 1)),
            exact(p.clone(), &payload(OP)),
        ],
        vec![put(g, &guard(OP, 2)), put(p, &payload(OP))],
    );
    assert_eq!(
        SelfFenced::check(&clear).unwrap().kind(),
        WitnessKind::Value
    );
}

#[test]
fn recovery_transition_is_exact_on_the_original_writer() {
    let closed = control::Writer {
        retired_through: 1,
        admitted_through: 1,
    }
    .encode()
    .unwrap();
    let g = witness::intent(b'g', M);
    let transition = prepared(
        vec![exact(g, &guard(OP, 1)), exact(writer(5), &open())],
        vec![put(writer(5), &closed)],
    );
    let proof = SelfFenced::check(&transition).unwrap();
    assert_eq!(
        (proof.kind(), proof.witness_puts()),
        (WitnessKind::Exact, (0, None))
    );
}

#[test]
fn a_coordinator_step_is_absent_witnessed_but_not_no_aba() {
    let generation = Address {
        namespace: control::GENERATION_NAMESPACE.0,
        key: witness::MIGRATION_NAMESPACE.0.to_vec(),
    };
    let step = witness::step(M, OP);
    let candidate = prepared(
        vec![exact(generation, &3u64.to_le_bytes()), absent(step.clone())],
        vec![
            put(witness::intent(b'x', M), b"domain"),
            put(step, b"marker"),
        ],
    );
    let proof = SelfFenced::check(&candidate).unwrap();
    assert_eq!(
        (proof.kind(), proof.witness_puts()),
        (WitnessKind::Absent, (1, None))
    );
    assert!(!proof.no_aba());
}

#[test]
fn non_witnesses_are_refused() {
    let root_value = control::Dataset {
        id: DATASET,
        writer_epoch: 1,
    }
    .encode()
    .unwrap();
    let only = |address: Address| prepared(vec![absent(address.clone())], vec![put(address, b"v")]);
    assert_eq!(
        SelfFenced::check(&prepared(
            vec![absent(root())],
            vec![put(root(), &root_value)]
        )),
        Err(NotSelfFenced)
    );
    for address in [manifest(), witness::birth(), witness::intent(b'w', M)] {
        assert_eq!(SelfFenced::check(&only(address)), Err(NotSelfFenced));
    }
    // A step witness whose key embeds another operation is not fresh for this attempt.
    assert_eq!(
        SelfFenced::check(&only(witness::step(M, [8; 16]))),
        Err(NotSelfFenced)
    );
    let g = witness::intent(b'g', M);
    let p = witness::intent(b'p', M);
    assert_eq!(
        SelfFenced::check(&prepared(
            vec![absent(g.clone())],
            vec![put(g.clone(), &guard(OP, 1))]
        )),
        Err(NotSelfFenced),
        "a guard Put without its payload pair"
    );
    assert_eq!(
        SelfFenced::check(&prepared(
            vec![absent(g.clone()), absent(p.clone())],
            vec![put(g, &guard(OP, 1)), put(p, &payload([8; 16]))],
        )),
        Err(NotSelfFenced),
        "the guard op differs from the payload header op"
    );
    assert_eq!(
        SelfFenced::check(&prepared(
            vec![exact(writer(5), &open())],
            vec![put(writer(5), &open())]
        )),
        Err(NotSelfFenced),
        "an Exact witness with x == v"
    );
    let mut timed = prepared(vec![absent(writer(6))], vec![put(writer(6), &open())])
        .candidate()
        .id;
    timed.operation = [1; 16];
    let timed = PreparedCandidate::new(Candidate {
        id: timed,
        codec: CANDIDATE_VERSION,
        predicates: vec![absent(writer(6))],
        mutations: vec![put(writer(6), &open())],
        time: Some(TimeGuard {
            not_before: None,
            before: Some(10),
        }),
        result: Secret::new(Vec::new()),
    })
    .unwrap();
    assert_eq!(SelfFenced::check(&timed), Err(NotSelfFenced));
}

#[test]
fn keys_carry_the_wire_slot_fields() {
    let seal = crate::caps::SlotSeal::acquire_for_tests();
    assert_eq!(CommitKey::slotted(3, 9, &seal).unwrap().wire(), (3, 9));
    assert_eq!(CommitKey::slotted(MAX_SLOTS, 1, &seal), None);
    assert_eq!(CommitKey::slotted(0, 0, &seal), None);
    let initialize = prepared(vec![absent(writer(2))], vec![put(writer(2), &open())]);
    let key = CommitKey::self_fenced(&SelfFenced::check(&initialize).unwrap());
    assert_eq!(key.wire(), (SLOT_SELF_FENCED, 0));
    assert!(key.is_self_fenced());
}
