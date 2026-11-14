// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
    assert!(control::initialization(&prepared, dataset));
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
