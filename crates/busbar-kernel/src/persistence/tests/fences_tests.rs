// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn initialization_declares_the_registrar_epoch_required_by_register() {
    let prepared = initialize(DatasetId([1; 16]), [2; 16], [3; 16]).unwrap();
    let epoch = control::epoch_row([2; 16], 1);
    assert!(prepared.candidate().predicates.iter().any(|predicate| {
        predicate.address == epoch && matches!(predicate.expected, ExpectedValue::Absent)
    }));
    assert!(prepared.candidate().mutations.iter().any(|mutation| {
        matches!(mutation, Mutation::Put { address, value }
            if *address == epoch && value.expose(&crate::seal::lend()) == control::EPOCH_VALUE)
    }));
    assert!(control::initialization(&prepared, DatasetId([1; 16])));
    assert_eq!(control::admit(&prepared), Ok(()));
    assert_eq!(control::fences(&prepared).len(), 1);
}

#[test]
fn writer_transitions_declare_every_native_control_effect() {
    let id = AttemptId {
        dataset: DatasetId([1; 16]),
        writer: [2; 16],
        operation: [3; 16],
        writer_epoch: 1,
        execution_epoch: 1,
    };
    let row = |retired_through, admitted_through| control::Writer {
        retired_through,
        admitted_through,
    };
    for (current, next) in [
        (None, row(0, 1)),
        (Some(row(0, 1)), row(0, 2)),
        (Some(row(0, 2)), row(1, 2)),
        (Some(row(1, 2)), row(2, 2)),
        (Some(row(2, 2)), row(2, 2)),
    ] {
        let prepared = writer(id, [4; 16], current, next).unwrap();
        assert_eq!(control::admit(&prepared), Ok(()), "{current:?} -> {next:?}");
        let mut mutations = control::writer_put([4; 16], current, next).unwrap();
        assert!(mutations.pop().is_some());
        let missing_effect = PreparedCandidate::new(Candidate {
            id,
            codec: CANDIDATE_VERSION,
            predicates: vec![Predicate {
                address: address(control::writer_key([4; 16]).to_vec()),
                expected: current.map_or(ExpectedValue::Absent, |value| {
                    ExpectedValue::Exact(Secret::new(value.encode().unwrap().to_vec()))
                }),
            }],
            mutations,
            time: None,
            result: Secret::new(Vec::new()),
        })
        .unwrap();
        assert_eq!(
            control::admit(&missing_effect),
            Err(busbar_contract::persistence::Failure::Refused)
        );
    }
}

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
    assert!(control::initialization(&prepared, dataset));
    assert_eq!(prepared.candidate().mutations.len(), 4);
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
    assert!(control::initialization(&initial, DatasetId([1; 16])));
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
