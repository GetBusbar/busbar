// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Decision 299's core rules (STORE-TRANSACTIONS §2.5, §8 "S2-ST-CTRL"): the epoch window,
//! `writer_put` per transition, the `fences` shape, and `admit`'s refusals and golden candidates.
//! The goldens are synthetic, one per writer-Put site other than Initialize, each built through
//! `writer_put`; the real builders are the wiring part's reds.

use super::super::{AttemptId, Candidate};
use super::*;

const DATASET: DatasetId = DatasetId([1; 16]);
/// The registrar: it stamps every startup and `abandon` candidate.
const REGISTRAR: [u8; 16] = [2; 16];
/// The writer a transition targets.
const TARGET: [u8; 16] = [4; 16];
/// A prior first-start owner, retired by a takeover Register.
const PRIOR: [u8; 16] = [5; 16];
const MAX: u64 = u64::MAX;

fn writer(retired_through: u64, admitted_through: u64) -> Writer {
    Writer {
        retired_through,
        admitted_through,
    }
}

fn control(key: &[u8]) -> Address {
    Address {
        namespace: NAMESPACE.0,
        key: key.to_vec(),
    }
}

fn root_value(writer_epoch: u64) -> Vec<u8> {
    Dataset {
        id: DATASET,
        writer_epoch,
    }
    .encode()
    .unwrap()
    .to_vec()
}

fn exact(address: Address, value: Vec<u8>) -> Predicate {
    Predicate {
        address,
        expected: ExpectedValue::Exact(Secret::new(value)),
    }
}

/// A mutation as plain bytes, so expected and built mutations compare.
#[derive(Debug, PartialEq)]
enum Seen {
    Put(Address, Vec<u8>),
    Delete(Address),
    Range([u8; 16], Vec<u8>, u64),
}

fn seen(mutations: &[Mutation]) -> Vec<Seen> {
    mutations
        .iter()
        .map(|mutation| match mutation {
            Mutation::Put { address, value } => Seen::Put(address.clone(), value.0.clone()),
            Mutation::Delete(address) => Seen::Delete(address.clone()),
            Mutation::DeleteRange {
                namespace,
                prefix,
                exact_key_length,
            } => Seen::Range(namespace.0, prefix.clone(), *exact_key_length),
        })
        .collect()
}

/// One writer-row transition: its guard on the row and its `writer_put` mutations.
struct Step {
    target: [u8; 16],
    old: Option<Writer>,
    next: Writer,
}

const fn step(target: [u8; 16], old: Option<Writer>, next: Writer) -> Step {
    Step { target, old, next }
}

/// A candidate stamped by `stamp` at `execution_epoch`, carrying `steps` built through
/// `writer_put`, the root guard most sites carry, and one domain record.
fn golden(stamp: [u8; 16], execution_epoch: u64, steps: &[Step]) -> Candidate {
    let mut predicates = vec![exact(control(DATASET_KEY), root_value(1))];
    let mut mutations = Vec::new();
    for step in steps {
        predicates.push(Predicate {
            address: control(&writer_key(step.target)),
            expected: match step.old {
                None => ExpectedValue::Absent,
                Some(old) => ExpectedValue::Exact(Secret::new(old.encode().unwrap().to_vec())),
            },
        });
        mutations.extend(writer_put(step.target, step.old, step.next).unwrap());
    }
    mutations.push(Mutation::Put {
        address: Address {
            namespace: [8; 16],
            key: b"domain".to_vec(),
        },
        value: Secret::new(vec![1]),
    });
    Candidate {
        id: AttemptId {
            dataset: DATASET,
            writer_epoch: 1,
            writer: stamp,
            execution_epoch,
            operation: [3; 16],
        },
        codec: CANDIDATE_VERSION,
        predicates,
        mutations,
        time: None,
        result: Secret::new(Vec::new()),
    }
}

/// Slot 0 of [`TARGET`].
fn slot_key() -> Vec<u8> {
    let mut key = TARGET.to_vec();
    key.extend_from_slice(&0u32.to_be_bytes());
    key
}

fn admitted(candidate: Candidate) -> Result<(), Failure> {
    admit(&PreparedCandidate::new(candidate).unwrap())
}

#[test]
fn a_window_of_three_epochs_does_not_encode_or_decode() {
    assert!(writer(0, 3).encode().is_none());
    let mut bytes = writer(0, 2).encode().unwrap();
    bytes[16..].copy_from_slice(&3u64.to_le_bytes());
    assert!(Writer::decode(&bytes).is_none());
    for fits in [
        writer(0, 1),
        writer(0, 2),
        writer(1, 3),
        writer(7, 7),
        writer(MAX, MAX),
    ] {
        assert_eq!(
            Writer::decode(&fits.encode().unwrap()),
            Some(fits),
            "{fits:?}"
        );
    }
    assert_eq!(MAX_LIVE_EPOCHS, 2);
}

#[test]
fn live_is_the_window_above_the_retired_floor() {
    assert_eq!(writer(0, 1).live(), 1..=1);
    assert_eq!(writer(1, 3).live(), 2..=3);
    assert!(writer(7, 7).live().is_empty());
    assert!(writer(MAX, MAX).live().is_empty());
    assert!(live(None).is_empty());
    assert_eq!(live(Some(writer(0, 2))), 1..=2);
}

#[test]
fn epoch_rows_have_one_key_shape() {
    let key = epoch_key(TARGET, 0x0102);
    assert_eq!(key[0], b'e');
    assert_eq!(&key[1..17], &TARGET);
    assert_eq!(&key[17..], &0x0102u64.to_be_bytes());
    assert_eq!(Key::decode(&key), Some(Key::Epoch(TARGET, 0x0102)));
    assert_eq!(epoch_row(TARGET, 0x0102), control(&key));
    assert!(Key::decode(&epoch_key([0; 16], 1)).is_none());
    assert!(Key::decode(&epoch_key(TARGET, 0)).is_none());
    assert!(Key::decode(&key[..24]).is_none());
    let mut long = key.to_vec();
    long.push(0);
    assert!(Key::decode(&long).is_none());
    assert_eq!(Key::decode(&writer_key(TARGET)), Some(Key::Writer(TARGET)));
    assert_eq!(&SLOT_NS.0, b"busbar.slot.v1\0\0");
    assert_eq!(
        replacement(Key::Epoch(TARGET, 1), DATASET, None, EPOCH_VALUE),
        Ok(())
    );
    assert_eq!(
        replacement(
            Key::Epoch(TARGET, 1),
            DATASET,
            Some(EPOCH_VALUE),
            EPOCH_VALUE
        ),
        Err(Failure::Refused)
    );
    assert_eq!(
        replacement(Key::Epoch(TARGET, 1), DATASET, None, b""),
        Err(Failure::Refused)
    );
}

#[test]
fn writer_put_moves_epoch_rows_with_the_window_and_closes_slots_once_closed() {
    let admit = |epoch| Seen::Put(epoch_row(TARGET, epoch), EPOCH_VALUE.to_vec());
    let retire = |epoch| Seen::Delete(epoch_row(TARGET, epoch));
    let close = || Seen::Range(SLOT_NS.0, TARGET.to_vec(), 20);
    let cases = [
        (None, writer(0, 1), vec![admit(1)]),
        (Some(writer(0, 1)), writer(0, 2), vec![admit(2)]),
        (Some(writer(0, 2)), writer(1, 2), vec![retire(1)]),
        (Some(writer(1, 2)), writer(2, 2), vec![retire(2), close()]),
        (
            Some(writer(0, 2)),
            writer(MAX, MAX),
            vec![retire(1), retire(2), close()],
        ),
        (
            Some(writer(1, 2)),
            writer(MAX, MAX),
            vec![retire(2), close()],
        ),
        (Some(writer(0, 1)), writer(1, 1), vec![retire(1), close()]),
        (Some(writer(0, 1)), writer(1, 2), vec![admit(2), retire(1)]),
        (Some(writer(7, 7)), writer(7, 8), vec![admit(8)]),
        (Some(writer(7, 7)), writer(7, 7), vec![close()]),
    ];
    for (old, next, effects) in cases {
        let mut expected = vec![Seen::Put(
            control(&writer_key(TARGET)),
            next.encode().unwrap().to_vec(),
        )];
        expected.extend(effects);
        assert_eq!(
            seen(&writer_put(TARGET, old, next).unwrap()),
            expected,
            "{old:?} -> {next:?}"
        );
    }
    assert!(writer_put(TARGET, None, writer(0, 3)).is_none());
    assert!(writer_put(TARGET, Some(writer(0, 3)), writer(1, 3)).is_none());
    assert!(writer_put([0; 16], None, writer(0, 1)).is_none());
}

#[test]
fn fences_are_the_absent_root_for_initialize_and_root_plus_epoch_row_otherwise() {
    let shape = |fences: Vec<Predicate>| {
        fences
            .into_iter()
            .map(|fence| match fence.expected {
                ExpectedValue::Absent => (fence.address, None),
                ExpectedValue::Exact(value) => (fence.address, Some(value.0.clone())),
            })
            .collect::<Vec<_>>()
    };
    let initialize = PreparedCandidate::new(super::tests::initial()).unwrap();
    assert_eq!(
        shape(fences(&initialize)),
        vec![(control(DATASET_KEY), None)]
    );
    let mut register = golden(REGISTRAR, 1, &[step(TARGET, None, writer(0, 1))]);
    register.id.writer_epoch = 3;
    register.id.execution_epoch = 2;
    assert_eq!(
        shape(fences(&PreparedCandidate::new(register).unwrap())),
        vec![
            (control(DATASET_KEY), Some(root_value(3))),
            (epoch_row(REGISTRAR, 2), Some(EPOCH_VALUE.to_vec())),
        ]
    );
}

#[test]
fn initialization_requires_exactly_the_registrars_initial_epoch() {
    let valid = || super::tests::initial();
    assert_eq!(admitted(valid()), Ok(()));
    let mut missing = valid();
    missing.predicates.pop();
    missing.mutations.pop();
    assert_eq!(admitted(missing), Err(Failure::Refused));

    for epoch in [epoch_row(TARGET, 1), epoch_row(REGISTRAR, 2)] {
        let mut wrong = valid();
        wrong.predicates[2].address = epoch.clone();
        wrong.mutations[2] = Mutation::Put {
            address: epoch,
            value: Secret::new(EPOCH_VALUE.to_vec()),
        };
        assert_eq!(admitted(wrong), Err(Failure::Refused));
    }
    let mut wrong_value = valid();
    wrong_value.mutations[2] = Mutation::Put {
        address: epoch_row(REGISTRAR, 1),
        value: Secret::new(b"invalid epoch".to_vec()),
    };
    assert_eq!(admitted(wrong_value), Err(Failure::Refused));

    let mut unguarded = valid();
    unguarded.predicates.pop();
    assert_eq!(admitted(unguarded), Err(Failure::Refused));
}

#[test]
fn admit_accepts_one_golden_candidate_per_writer_put_site() {
    let cold = [6; 16];
    let bootstrap = [7; 16];
    let current = [9; 16];
    let sites = [
        // startup.rs Register: a fresh writer, open, stamped by the registrar.
        (
            "register",
            golden(REGISTRAR, 1, &[step(TARGET, None, writer(0, 1))]),
        ),
        // Register retiring the prior first-start owner (the takeover branch).
        (
            "takeover",
            golden(
                REGISTRAR,
                1,
                &[
                    step(TARGET, None, writer(0, 1)),
                    step(PRIOR, Some(writer(0, 1)), writer(1, 1)),
                ],
            ),
        ),
        // writer_transition: Grant (roll), RetireEpoch (drain), Retiring (close).
        (
            "roll",
            golden(
                REGISTRAR,
                1,
                &[step(TARGET, Some(writer(0, 1)), writer(0, 2))],
            ),
        ),
        (
            "drain",
            golden(
                REGISTRAR,
                1,
                &[step(TARGET, Some(writer(0, 2)), writer(1, 2))],
            ),
        ),
        (
            "close",
            golden(
                REGISTRAR,
                1,
                &[step(TARGET, Some(writer(1, 2)), writer(2, 2))],
            ),
        ),
        // FirstStart::abandon: the owner's exit handover, stamped by the registrar.
        (
            "abandon",
            golden(
                REGISTRAR,
                1,
                &[step(TARGET, Some(writer(0, 1)), writer(1, 1))],
            ),
        ),
        // boot_identity adoption, stamped by the current writer.
        (
            "adoption",
            golden(
                current,
                2,
                &[step(TARGET, Some(writer(0, 2)), writer(MAX, MAX))],
            ),
        ),
        // Cold-writer bootstrap, retire, reopen; stamped by the caller and the cold writer.
        (
            "cold bootstrap",
            golden(bootstrap, 1, &[step(cold, None, writer(0, 1))]),
        ),
        (
            "migration retire",
            golden(cold, 1, &[step(TARGET, Some(writer(2, 3)), writer(3, 3))]),
        ),
        (
            "migration reopen",
            golden(cold, 1, &[step(TARGET, Some(writer(3, 3)), writer(3, 4))]),
        ),
        // fences::dataset: a root advance with its exact guard.
        ("dataset advance", {
            let mut candidate = golden(REGISTRAR, 1, &[]);
            candidate.mutations.push(Mutation::Put {
                address: control(DATASET_KEY),
                value: Secret::new(root_value(2)),
            });
            candidate
        }),
    ];
    for (site, candidate) in sites {
        assert_eq!(admitted(candidate), Ok(()), "{site}");
    }
    assert_eq!(
        admit(&PreparedCandidate::new(super::tests::initial()).unwrap()),
        Ok(())
    );
}

#[test]
fn admit_refuses_every_breach() {
    let register = || golden(REGISTRAR, 1, &[step(TARGET, None, writer(0, 1))]);
    let mutated = |change: fn(&mut Candidate)| {
        let mut candidate = register();
        change(&mut candidate);
        admitted(candidate)
    };
    // (ii) the root is never deleted, and no range deletes control records.
    assert_eq!(
        mutated(|c| c.mutations.push(Mutation::Delete(control(DATASET_KEY)))),
        Err(Failure::Refused),
        "root Delete"
    );
    assert_eq!(
        mutated(|c| c.mutations.push(Mutation::DeleteRange {
            namespace: NAMESPACE,
            prefix: vec![b'x'],
            exact_key_length: 17,
        })),
        Err(Failure::Refused),
        "control DeleteRange"
    );
    assert_eq!(
        mutated(|c| c
            .mutations
            .push(Mutation::Delete(control(&writer_key(PRIOR))))),
        Err(Failure::Refused),
        "writer Delete"
    );
    // (iii) a writer Put travels with exactly its epoch rows.
    assert_eq!(
        mutated(|c| {
            c.mutations.retain(
                |m| !matches!(m, Mutation::Put { address, .. } if *address == epoch_row(TARGET, 1)),
            );
        }),
        Err(Failure::Refused),
        "writer Put without its epoch rows"
    );
    assert_eq!(
        mutated(|c| c.mutations.push(Mutation::Put {
            address: epoch_row(TARGET, 2),
            value: Secret::new(EPOCH_VALUE.to_vec()),
        })),
        Err(Failure::Refused),
        "an epoch row no transition admits"
    );
    assert_eq!(
        mutated(|c| {
            for mutation in &mut c.mutations {
                if let Mutation::Put { address, value } = mutation {
                    if *address == epoch_row(TARGET, 1) {
                        *value = Secret::new(Vec::new());
                    }
                }
            }
        }),
        Err(Failure::Refused),
        "an epoch row with other bytes"
    );
    // (ii) a writer row stays within the window.
    let mut wide = golden(
        REGISTRAR,
        1,
        &[step(TARGET, Some(writer(0, 2)), writer(0, 2))],
    );
    for mutation in &mut wide.mutations {
        if let Mutation::Put { address, value } = mutation {
            if *address == control(&writer_key(TARGET)) {
                let mut bytes = writer(0, 2).encode().unwrap();
                bytes[16..].copy_from_slice(&3u64.to_le_bytes());
                *value = Secret::new(bytes.to_vec());
            }
        }
    }
    wide.mutations.push(Mutation::Put {
        address: epoch_row(TARGET, 3),
        value: Secret::new(EPOCH_VALUE.to_vec()),
    });
    assert_eq!(admitted(wide), Err(Failure::Refused), "a window of 3");
    // (iii) SLOT_NS: only the closure's range, never a predicate.
    assert_eq!(
        mutated(|c| c.mutations.push(Mutation::DeleteRange {
            namespace: SLOT_NS,
            prefix: TARGET.to_vec(),
            exact_key_length: 20,
        })),
        Err(Failure::Refused),
        "a closure range on an open writer"
    );
    assert_eq!(
        mutated(|c| c.mutations.push(Mutation::Put {
            address: Address {
                namespace: SLOT_NS.0,
                key: slot_key(),
            },
            value: Secret::new(vec![1]),
        })),
        Err(Failure::Refused),
        "a SLOT_NS Put"
    );
    assert_eq!(
        mutated(|c| c.mutations.push(Mutation::DeleteRange {
            namespace: SLOT_NS,
            prefix: TARGET[..15].to_vec(),
            exact_key_length: 20,
        })),
        Err(Failure::Refused),
        "a SLOT_NS range of another shape"
    );
    assert_eq!(
        mutated(|c| c.predicates.push(Predicate {
            address: Address {
                namespace: SLOT_NS.0,
                key: slot_key(),
            },
            expected: ExpectedValue::Absent,
        })),
        Err(Failure::Refused),
        "a PREDICATE on SLOT_NS"
    );
    // (iii) the generation namespace is never mutated.
    for generation in [
        Mutation::Put {
            address: Address {
                namespace: GENERATION_NAMESPACE.0,
                key: vec![8; 16],
            },
            value: Secret::new(1u64.to_le_bytes().to_vec()),
        },
        Mutation::Delete(Address {
            namespace: GENERATION_NAMESPACE.0,
            key: vec![8; 16],
        }),
        Mutation::DeleteRange {
            namespace: GENERATION_NAMESPACE,
            prefix: Vec::new(),
            exact_key_length: 16,
        },
    ] {
        let mut candidate = register();
        candidate.mutations.push(generation);
        assert_eq!(
            admitted(candidate),
            Err(Failure::Refused),
            "a generation mutation"
        );
    }
    // (iv) no transition closes the writer that stamps it.
    assert_eq!(
        admitted(golden(
            TARGET,
            1,
            &[step(TARGET, Some(writer(0, 1)), writer(1, 1))]
        )),
        Err(Failure::Refused),
        "a self-closing writer Put"
    );
    assert_eq!(
        admitted(golden(
            TARGET,
            1,
            &[step(TARGET, Some(writer(0, 1)), writer(1, 2))]
        )),
        Err(Failure::Refused),
        "a writer Put retiring its own executing epoch"
    );
    // (ii) guards and successors.
    assert_eq!(
        mutated(|c| {
            c.predicates
                .retain(|p| p.address != control(&writer_key(TARGET)));
        }),
        Err(Failure::Refused),
        "an unguarded writer Put"
    );
    assert_eq!(
        admitted(golden(
            REGISTRAR,
            1,
            &[step(TARGET, Some(writer(1, 2)), writer(0, 2))]
        )),
        Err(Failure::Refused),
        "a backwards writer Put"
    );
    assert_eq!(
        admitted(golden(REGISTRAR, 1, &[step(TARGET, None, writer(1, 2))])),
        Err(Failure::Refused),
        "a fresh writer that is not open"
    );
    assert_eq!(
        mutated(|c| {
            c.predicates[0].expected = ExpectedValue::Absent;
            c.mutations.push(Mutation::Put {
                address: control(DATASET_KEY),
                value: Secret::new(root_value(1)),
            });
        }),
        Err(Failure::Refused),
        "a root created outside Initialize"
    );
    assert_eq!(
        mutated(|c| c.mutations.push(Mutation::Put {
            address: control(b"unknown"),
            value: Secret::new(vec![1]),
        })),
        Err(Failure::Refused),
        "an unknown control key"
    );
    // (i), (iii) an Initialize carries no slot record: its Absent guard is a SLOT_NS predicate.
    let mut initialize = super::tests::initial();
    let slot = Address {
        namespace: SLOT_NS.0,
        key: slot_key(),
    };
    initialize.predicates.push(Predicate {
        address: slot.clone(),
        expected: ExpectedValue::Absent,
    });
    initialize.mutations.push(Mutation::Put {
        address: slot,
        value: Secret::new(vec![1]),
    });
    assert_eq!(
        admitted(initialize),
        Err(Failure::Refused),
        "an Initialize slot record"
    );
}
