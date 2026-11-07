// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core prepares authority changes; Stores evaluate their generic control records
//! atomically. These constructors neither submit nor acknowledge the transition.

use busbar_contract::persistence::{
    control, Address, AttemptId, Candidate, DatasetId, ExpectedValue, InvalidCandidate, Mutation,
    NamespaceId, Predicate, PreparedCandidate, CANDIDATE_VERSION,
};
use busbar_contract::Secret;

/// Invalid authority plan; diagnostics contain no record payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidFence {
    /// A supplied identity or current dataset generation is inconsistent.
    Identity,
    /// The transition would reopen retired authority or skip initial registration.
    Transition,
    /// Retire from a successor execution epoch, never the epoch doing the work.
    ExecutingEpoch,
    /// Candidate validation failed before any submission.
    Candidate(InvalidCandidate),
}

fn address(key: Vec<u8>) -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key,
    }
}

type Change = (Address, Option<Vec<u8>>, Secret<Vec<u8>>);

fn prepare(id: AttemptId, changes: Vec<Change>) -> Result<PreparedCandidate, InvalidFence> {
    let mut predicates = Vec::new();
    let mut mutations = Vec::new();
    for (address, before, after) in changes {
        predicates.push(Predicate {
            address: address.clone(),
            expected: before.map_or(ExpectedValue::Absent, |value| {
                ExpectedValue::Exact(Secret::new(value))
            }),
        });
        mutations.push(Mutation::Put {
            address,
            value: after,
        });
    }
    PreparedCandidate::new(Candidate {
        id,
        codec: CANDIDATE_VERSION,
        predicates,
        mutations,
        time: None,
        result: Secret::new(Vec::new()),
    })
    .map_err(InvalidFence::Candidate)
}

/// Prepare the first authority records for a separately classified fresh dataset.
/// The backend must still prove the complete logical dataset is empty during COMMIT.
pub fn initialize(
    dataset: DatasetId,
    writer: [u8; 16],
    operation: [u8; 16],
) -> Result<PreparedCandidate, InvalidFence> {
    initialize_with_records(dataset, writer, operation, Vec::new())
}

/// Initialize authority and its opaque metadata in one atomic candidate. Every
/// supplied record is guarded Absent; the backend still proves the whole dataset
/// empty at COMMIT. Opaque values retain wiping custody throughout construction;
/// this builder grants no additional control authority.
pub fn initialize_with_records(
    dataset: DatasetId,
    writer: [u8; 16],
    operation: [u8; 16],
    records: Vec<(Address, Secret<Vec<u8>>)>,
) -> Result<PreparedCandidate, InvalidFence> {
    let root = control::Dataset {
        id: dataset,
        writer_epoch: 1,
    }
    .encode()
    .ok_or(InvalidFence::Identity)?;
    let registered = control::Writer {
        retired_through: 0,
        admitted_through: 1,
    }
    .encode()
    .ok_or(InvalidFence::Transition)?;
    let mut changes = vec![
        (
            address(control::DATASET_KEY.to_vec()),
            None,
            Secret::new(root.to_vec()),
        ),
        (
            address(control::writer_key(writer).to_vec()),
            None,
            Secret::new(registered.to_vec()),
        ),
    ];
    for (at, value) in records {
        if at.namespace == control::NAMESPACE.0 || at.namespace == control::GENERATION_NAMESPACE.0 {
            return Err(InvalidFence::Transition);
        }
        changes.push((at, None, value));
    }
    prepare(
        AttemptId {
            dataset,
            writer,
            operation,
            writer_epoch: 1,
            execution_epoch: 1,
        },
        changes,
    )
}

/// Prepare an exact conditional writer registration, extension or retirement.
/// A successful return is a plan, not evidence that a delayed command is fenced.
pub fn writer(
    id: AttemptId,
    target: [u8; 16],
    current: Option<control::Writer>,
    next: control::Writer,
) -> Result<PreparedCandidate, InvalidFence> {
    if target == [0; 16] {
        return Err(InvalidFence::Identity);
    }
    if id.writer == target && !next.admits(id.execution_epoch) {
        return Err(InvalidFence::ExecutingEpoch);
    }
    let previous = match current {
        Some(value) => Some(value.encode().ok_or(InvalidFence::Transition)?),
        None => None,
    };
    let next = next.encode().ok_or(InvalidFence::Transition)?;
    control::replacement(
        control::Key::Writer(target),
        id.dataset,
        previous.as_ref().map(|v| v.as_slice()),
        &next,
    )
    .map_err(|_| InvalidFence::Transition)?;
    prepare(
        id,
        vec![(
            address(control::writer_key(target).to_vec()),
            previous.map(|v| v.to_vec()),
            Secret::new(next.to_vec()),
        )],
    )
}

/// Prepare a dataset generation advance. Publication waits for its Applied receipt.
pub fn dataset(
    id: AttemptId,
    current: control::Dataset,
    next_epoch: u64,
) -> Result<PreparedCandidate, InvalidFence> {
    if current.id != id.dataset || current.writer_epoch != id.writer_epoch {
        return Err(InvalidFence::Identity);
    }
    if next_epoch <= current.writer_epoch {
        return Err(InvalidFence::Transition);
    }
    let before = current.encode().ok_or(InvalidFence::Identity)?;
    let after = control::Dataset {
        writer_epoch: next_epoch,
        ..current
    }
    .encode()
    .ok_or(InvalidFence::Transition)?;
    prepare(
        id,
        vec![(
            address(control::DATASET_KEY.to_vec()),
            Some(before.to_vec()),
            Secret::new(after.to_vec()),
        )],
    )
}

/// Guard a subsequent commit against any write since the observed scan generation.
#[must_use]
pub fn scan_guard(namespace: NamespaceId, generation: u64) -> Predicate {
    Predicate {
        address: Address {
            namespace: control::GENERATION_NAMESPACE.0,
            key: namespace.0.to_vec(),
        },
        expected: if generation == 0 {
            ExpectedValue::Absent
        } else {
            ExpectedValue::Exact(Secret::new(generation.to_le_bytes().to_vec()))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialization_records_are_absent_puts_outside_reserved_namespaces() {
        let dataset = DatasetId([1; 16]);
        let at = Address {
            namespace: [8; 16],
            key: b"format".to_vec(),
        };
        let prepared = initialize_with_records(
            dataset,
            [2; 16],
            [3; 16],
            vec![(at.clone(), Secret::new(b"opaque".to_vec()))],
        )
        .unwrap();
        assert!(control::initialization(prepared.candidate(), dataset));
        assert_eq!(prepared.candidate().mutations.len(), 3);
        for namespace in [control::NAMESPACE.0, control::GENERATION_NAMESPACE.0] {
            assert!(matches!(
                initialize_with_records(
                    dataset,
                    [2; 16],
                    [3; 16],
                    vec![(
                        Address {
                            namespace,
                            key: vec![]
                        },
                        Secret::new(vec![])
                    )]
                ),
                Err(InvalidFence::Transition)
            ));
        }
        assert!(matches!(
            initialize_with_records(
                dataset,
                [2; 16],
                [3; 16],
                vec![(at.clone(), Secret::new(vec![])), (at, Secret::new(vec![]))]
            ),
            Err(InvalidFence::Candidate(_))
        ));
    }

    #[test]
    fn retirement_must_run_from_successor_and_initialization_is_exact() {
        let initial = initialize(DatasetId([1; 16]), [2; 16], [3; 16]).unwrap();
        assert!(control::initialization(
            initial.candidate(),
            DatasetId([1; 16])
        ));
        let mut id = initial.candidate().id;
        let current = control::Writer {
            retired_through: 0,
            admitted_through: 2,
        };
        let next = control::Writer {
            retired_through: 1,
            admitted_through: 2,
        };
        assert!(matches!(
            writer(id, id.writer, Some(current), next),
            Err(InvalidFence::ExecutingEpoch)
        ));
        id.execution_epoch = 2;
        assert!(writer(id, id.writer, Some(current), next).is_ok());
        assert!(matches!(
            writer(id, id.writer, Some(next), current),
            Err(InvalidFence::Transition)
        ));
    }
}
