// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

crate::own_seal!(Own);
const BOUNDS: Bounds = Bounds {
    items: 128,
    bytes: 16384,
};
fn reader() -> SourceReader {
    SourceReader::new(
        SourceCodec::HistoricalV1,
        DocumentSemantics::Historical,
        [8; 32],
    )
    .unwrap()
}

#[test]
fn historical_registration_requires_a_valid_typed_reader_on_the_wire() {
    assert!(SourceReader::new(
        SourceCodec::HistoricalV1,
        DocumentSemantics::Historical,
        [0; 32]
    )
    .is_err());
    for state in [
        InspectionState::Legacy(reader()),
        InspectionState::InProgress(reader()),
    ] {
        let response: Response = Response::Inspected(Inspection {
            state,
            source: Some(source()),
            admission_marker: None,
            catalogue: vec![],
            capabilities: vec![NativeCapability::Snapshot],
        });
        let encoded = encode_response(&Ok(response), BOUNDS).unwrap();
        let decoded = decode_response(&encoded.0, BOUNDS).unwrap();
        let Response::Inspected(inspected) = decoded else {
            panic!("inspection");
        };
        assert_eq!(inspected.state, state);
        let mut missing = encoded.0.clone();
        missing.drain(17..51);
        assert!(decode_response(&missing, BOUNDS).is_err());
        let mut unknown = encoded.0.clone();
        unknown[17] = 255;
        assert!(matches!(
            decode_response(&unknown, BOUNDS),
            Err(Error::UnsupportedFormat)
        ));
        let mut invalid = encoded.0.clone();
        invalid[19..51].fill(0);
        assert!(decode_response(&invalid, BOUNDS).is_err());
    }
    request_roundtrip(Request::SourcePage {
        upgrade: reference(),
        snapshot: [4; 16],
        family: INTERPRETED_SOURCE,
        selector: SourceSelector::Interpret {
            reader: reader(),
            bounds: InterpretationBounds {
                semantic_bytes: 8192,
                index_bytes: 4096,
                storage_bytes: 16 * 1024 * 1024,
            },
        },
        cursor: None,
        bounds: BOUNDS,
    });
    let invalid: Request = Request::SourcePage {
        upgrade: reference(),
        snapshot: [4; 16],
        family: INTERPRETED_SOURCE,
        selector: SourceSelector::Interpret {
            reader: reader(),
            bounds: InterpretationBounds {
                semantic_bytes: 0,
                index_bytes: 4096,
                storage_bytes: 16 * 1024 * 1024,
            },
        },
        cursor: None,
        bounds: BOUNDS,
    };
    assert!(matches!(
        encode_request(&invalid, BOUNDS),
        Err(Error::Bounds)
    ));
}
fn source() -> SourceIdentity {
    SourceIdentity {
        native_anchor: [1; 32],
        dataset: DatasetId([2; 16]),
        format: Some(Format {
            owner: [3; 16],
            physical: 3,
            logical: 1,
            codec: 1,
        }),
        catalogue_digest: [4; 32],
        layout_digest: [5; 32],
    }
}
fn reference() -> UpgradeRef {
    UpgradeRef {
        id: [6; 16],
        authority: Secret::new(vec![0, 255, 9]),
    }
}
fn info() -> BackendInfo {
    BackendInfo {
        dataset: DatasetId([7; 16]),
        atomic_domain: [8; 16],
        clock_authority: [9; 16],
        physical_version: 4,
        durability: Durability::Local,
    }
}
fn receipt(phase: CompletionPhase) -> ActivationReceipt {
    ActivationReceipt {
        attempt: AttemptId {
            dataset: DatasetId([7; 16]),
            writer_epoch: 1,
            writer: [8; 16],
            execution_epoch: 2,
            operation: [9; 16],
        },
        candidate_fingerprint: [10; 32],
        original_result: Secret::new(vec![0, 255, 128]),
        checkpoint_address: Address {
            namespace: [11; 16],
            key: vec![0, 255],
        },
        checkpoint_value_digest: [12; 32],
        phase,
    }
}
fn recovery() -> RecoveryReady {
    RecoveryReady {
        upgrade: [6; 16],
        target: DatasetId([7; 16]),
        activation_receipt_digest: [10; 32],
        selector_digest: [11; 32],
    }
}
fn request_roundtrip(request: Request) {
    let encoded = encode_request(&request, BOUNDS).unwrap();
    let decoded = decode_request(&encoded.0, BOUNDS).unwrap();
    assert_eq!(encoded.0, encode_request(&decoded, BOUNDS).unwrap().0);
    let owned = decode_request_owned::<Own>(&encoded.0, BOUNDS).unwrap();
    assert_eq!(encoded.0, encode_request(&owned, BOUNDS).unwrap().0);
    for cut in 0..encoded.0.len() {
        assert!(decode_request(&encoded.0[..cut], BOUNDS).is_err());
    }
}
fn response_roundtrip(response: Response) {
    let encoded = encode_response(&Ok(response), BOUNDS).unwrap();
    let decoded = decode_response(&encoded.0, BOUNDS).unwrap();
    assert_eq!(encoded.0, encode_response(&Ok(decoded), BOUNDS).unwrap().0);
    let owned = decode_response_owned::<Own>(&encoded.0, BOUNDS).unwrap();
    assert_eq!(encoded.0, encode_response(&Ok(owned), BOUNDS).unwrap().0);
    for cut in 0..encoded.0.len() {
        assert!(decode_response(&encoded.0[..cut], BOUNDS).is_err());
    }
}
#[test]
fn request_roundtrips_all_tags_and_receipt_phases() {
    request_roundtrip(Request::Inspect { bounds: BOUNDS });
    request_roundtrip(Request::BeginOrResume {
        expected_source: source(),
        route_digest: [1; 32],
        target_format: source().format.unwrap(),
        operation_id: [2; 16],
    });
    for selector in [
        SourceSelector::Scan { table: 0 },
        SourceSelector::Exact {
            table: 1,
            key: Secret::new(vec![255, 0]),
        },
        SourceSelector::IndexPrefix {
            table: 2,
            index: 3,
            prefix: Secret::new(vec![128, 0]),
        },
    ] {
        request_roundtrip(Request::SourcePage {
            upgrade: reference(),
            snapshot: [3; 16],
            family: [4; 16],
            selector,
            cursor: Some(Secret::new(vec![0, 255])),
            bounds: BOUNDS,
        });
    }
    request_roundtrip(Request::Target {
        upgrade: reference(),
    });
    request_roundtrip(Request::CheckFence {
        upgrade: reference(),
    });
    for phase in [CompletionPhase::Activation, CompletionPhase::Complete] {
        request_roundtrip(Request::Finish {
            upgrade: reference(),
            activation_receipt: receipt(phase),
        });
    }
}
#[test]
fn finish_roundtrips_exact_empty_applied_results_for_both_phases() {
    for phase in [CompletionPhase::Activation, CompletionPhase::Complete] {
        let mut proof = receipt(phase);
        proof.original_result = Secret::new(Vec::new());
        let request = Request::Finish {
            upgrade: reference(),
            activation_receipt: proof,
        };
        let encoded = encode_request(&request, BOUNDS).unwrap();
        let Request::Finish {
            activation_receipt, ..
        } = decode_request(&encoded.0, BOUNDS).unwrap()
        else {
            panic!("Finish changed its request tag");
        };
        assert!(activation_receipt.original_result.0.is_empty());
        assert_eq!(activation_receipt.phase, phase);
        assert_eq!(activation_receipt.candidate_fingerprint, [10; 32]);
        assert_eq!(activation_receipt.checkpoint_value_digest, [12; 32]);
        request_roundtrip(request);
    }
}
#[test]
fn response_roundtrips_preserve_native_bytes_and_metadata() {
    response_roundtrip(Response::Inspected(Inspection {
        state: InspectionState::Legacy(reader()),
        source: Some(source()),
        admission_marker: None,
        catalogue: vec![super::super::super::archive::Table {
            name: "table".into(),
            columns: vec!["z".into(), "a".into()],
            native_layout: vec![255, 0, 1],
        }],
        capabilities: vec![
            NativeCapability::Snapshot,
            NativeCapability::PersistentFence,
        ],
    }));
    let mut current = source();
    current.format = None;
    response_roundtrip(Response::Inspected(Inspection {
        state: InspectionState::Current,
        source: Some(current),
        admission_marker: Some(Secret::new(vec![255, 0])),
        catalogue: vec![],
        capabilities: vec![NativeCapability::CurrentOpen],
    }));
    response_roundtrip(Response::Inspected(Inspection {
        state: InspectionState::Empty,
        source: None,
        admission_marker: None,
        catalogue: vec![],
        capabilities: vec![],
    }));
    response_roundtrip(Response::Begun(Upgrade {
        reference: reference(),
        source: source(),
        snapshot: [1; 16],
        target: info(),
        native_step: 7,
        catalogue: vec![],
    }));
    let row = super::super::super::legacy_row::encode::<Own>(
        &[
            super::super::super::legacy_row::Cell::RealBits(0x7ff8000000000001),
            super::super::super::legacy_row::Cell::Text(&[255, 0]),
        ],
        1024,
    )
    .unwrap();
    response_roundtrip(Response::SourcePage(SourcePage {
        snapshot: [1; 16],
        family: [2; 16],
        rows: vec![SourceRow {
            table: 3,
            native_key: Secret::new(vec![255, 0]),
            value: Secret::new(row.0.clone()),
        }],
        next: Some(Secret::new(vec![0, 255])),
        source_digest: [3; 32],
        coverage_digest: [4; 32],
    }));
    response_roundtrip(Response::Target(TargetBinding {
        upgrade: [1; 16],
        info: info(),
        binding: Secret::new(vec![1, 255, 0]),
    }));
    response_roundtrip(Response::Fence(Fence {
        upgrade: [1; 16],
        source: source(),
        enforcement_digest: [2; 32],
        observation_digest: [3; 32],
        snapshot: [4; 16],
    }));
    response_roundtrip(Response::RecoveryReady(recovery()));
    response_roundtrip(Response::ServingReady(ServingReady {
        recovery: recovery(),
        completed_checkpoint_digest: [12; 32],
    }));
}
#[test]
fn strict_envelopes_and_remote_errors() {
    let encoded = encode_request(&Request::<Kernel>::Inspect { bounds: BOUNDS }, BOUNDS).unwrap();
    for at in [0, 8, 12, 13, 14, 15] {
        let mut bad = encoded.0.clone();
        bad[at] = 255;
        assert!(decode_request(&bad, BOUNDS).is_err());
    }
    let mut extra = encoded.0.clone();
    extra.push(0);
    assert!(decode_request(&extra, BOUNDS).is_err());
    for error in [
        Error::Busy,
        Error::Pending,
        Error::UnsupportedFormat,
        Error::MissingCapability,
        Error::SourceChanged,
        Error::Corrupt,
        Error::Refused,
        Error::Unavailable,
        Error::Unknown,
        Error::Bounds,
    ] {
        let encoded = encode_response::<Kernel>(&Err(error), BOUNDS).unwrap();
        assert_eq!(decode_response(&encoded.0, BOUNDS).unwrap_err(), error);
        let mut extra = encoded.0.clone();
        extra.push(0);
        assert_eq!(decode_response(&extra, BOUNDS).unwrap_err(), Error::Corrupt);
    }
    let mut unknown = encode_response::<Kernel>(&Err(Error::Busy), BOUNDS).unwrap();
    unknown.0[13] = 138;
    assert_eq!(
        decode_response(&unknown.0, BOUNDS).unwrap_err(),
        Error::Corrupt
    );
}
#[test]
fn budgets_include_collection_metadata_and_secret_bytes() {
    let reply = Ok(Response::<Kernel>::Inspected(Inspection {
        state: InspectionState::Legacy(reader()),
        source: Some(source()),
        admission_marker: None,
        catalogue: vec![super::super::super::archive::Table {
            name: "t".into(),
            columns: (0..32).map(|i| format!("c{i}")).collect(),
            native_layout: vec![1],
        }],
        capabilities: vec![],
    }));
    let encoded = encode_response(&reply, BOUNDS).unwrap();
    let too_few = Bounds {
        items: 32,
        ..BOUNDS
    };
    assert_eq!(encode_response(&reply, too_few).unwrap_err(), Error::Bounds);
    assert_eq!(
        decode_response(&encoded.0, too_few).unwrap_err(),
        Error::Bounds
    );
    // The frame fits, but owned String element metadata does not.
    let metadata = Bounds {
        bytes: encoded.0.len() as u32,
        ..BOUNDS
    };
    assert_eq!(
        encode_response(&reply, metadata).unwrap_err(),
        Error::Bounds
    );
    assert_eq!(
        decode_response(&encoded.0, metadata).unwrap_err(),
        Error::Bounds
    );
    let tiny = Bounds {
        bytes: 15,
        ..BOUNDS
    };
    assert_eq!(
        encode_open_binding(&OpenBinding::Empty, tiny).unwrap_err(),
        Error::Bounds
    );
    let request = Request::Target {
        upgrade: reference(),
    };
    let encoded = encode_request(&request, BOUNDS).unwrap();
    let tiny = Bounds {
        bytes: (encoded.0.len() - 1) as u32,
        ..BOUNDS
    };
    assert_eq!(decode_request(&encoded.0, tiny).unwrap_err(), Error::Bounds);
}
#[test]
fn open_bindings_roundtrip_and_reject_extra() {
    for b in [
        OpenBinding::Empty,
        OpenBinding::Current {
            source: source(),
            admission_marker_digest: [6; 32],
        },
        OpenBinding::Recovery(recovery()),
    ] {
        let encoded = encode_open_binding(&b, BOUNDS).unwrap();
        assert_eq!(decode_open_binding(&encoded.0, BOUNDS).unwrap(), b);
        for cut in 0..encoded.0.len() {
            assert!(decode_open_binding(&encoded.0[..cut], BOUNDS).is_err());
        }
        let mut extra = encoded.0.clone();
        extra.push(0);
        assert_eq!(
            decode_open_binding(&extra, BOUNDS).unwrap_err(),
            Error::Corrupt
        );
    }
}

#[test]
fn reject_inconsistent_inspections_catalogues_and_native_rows() {
    let make = |state, source, marker, catalogue| {
        Ok(Response::<Kernel>::Inspected(Inspection {
            state,
            source,
            admission_marker: marker,
            catalogue,
            capabilities: vec![],
        }))
    };
    assert_eq!(
        encode_response(
            &make(InspectionState::Empty, Some(source()), None, vec![]),
            BOUNDS
        )
        .unwrap_err(),
        Error::Corrupt
    );
    assert_eq!(
        encode_response(
            &make(InspectionState::Current, Some(source()), None, vec![]),
            BOUNDS
        )
        .unwrap_err(),
        Error::Corrupt
    );
    let mut unknown = source();
    unknown.format = None;
    assert_eq!(
        encode_response(
            &make(
                InspectionState::Legacy(reader()),
                Some(unknown),
                None,
                vec![]
            ),
            BOUNDS
        )
        .unwrap_err(),
        Error::Corrupt
    );
    let table = |name: &str, columns: Vec<String>| super::super::super::archive::Table {
        name: name.into(),
        columns,
        native_layout: vec![0, 255],
    };
    for catalogue in [
        vec![table("z", vec!["a".into()]), table("a", vec!["b".into()])],
        vec![table("a", vec!["b".into(), "b".into()])],
    ] {
        assert_eq!(
            encode_response(
                &make(
                    InspectionState::Legacy(reader()),
                    Some(source()),
                    None,
                    catalogue
                ),
                BOUNDS
            )
            .unwrap_err(),
            Error::Corrupt
        );
    }
    let bad = Ok(Response::<Kernel>::SourcePage(SourcePage {
        snapshot: [1; 16],
        family: [2; 16],
        rows: vec![SourceRow {
            table: 0,
            native_key: Secret::new(vec![0]),
            value: Secret::new(vec![255]),
        }],
        next: None,
        source_digest: [3; 32],
        coverage_digest: [4; 32],
    }));
    assert_eq!(encode_response(&bad, BOUNDS).unwrap_err(), Error::Corrupt);
}

#[test]
fn completion_markers_preserve_phase_address_and_reject_invalid_framing() {
    for phase in [CompletionPhase::Activation, CompletionPhase::Complete] {
        let marker = CompletionMarker {
            version: VERSION,
            phase,
            upgrade: [1; 16],
            source: DatasetId([2; 16]),
            target: DatasetId([3; 16]),
            checkpoint_address: Address {
                namespace: [4; 16],
                key: vec![255, 0, 3],
            },
            checkpoint_value_digest: [5; 32],
        };
        let encoded = encode_completion_marker(&marker, BOUNDS).unwrap();
        assert_eq!(
            decode_completion_marker(&encoded.0, BOUNDS).unwrap(),
            marker
        );
        assert!(decode_request(&encoded.0, BOUNDS).is_err());
        for cut in 0..encoded.0.len() {
            assert!(decode_completion_marker(&encoded.0[..cut], BOUNDS).is_err());
        }
        for at in [0, 8, 12, 13, 14, 15] {
            let mut bad = encoded.0.clone();
            bad[at] = 255;
            assert_eq!(
                decode_completion_marker(&bad, BOUNDS).unwrap_err(),
                Error::Corrupt
            );
        }
        let mut extra = encoded.0.clone();
        extra.push(0);
        assert_eq!(
            decode_completion_marker(&extra, BOUNDS).unwrap_err(),
            Error::Corrupt
        );
        let mut bad_address = encoded.0.clone();
        bad_address[64..80].fill(0);
        assert_eq!(
            decode_completion_marker(&bad_address, BOUNDS).unwrap_err(),
            Error::Corrupt
        );
        let mut bad = marker.clone();
        bad.checkpoint_address.key.clear();
        assert_eq!(
            encode_completion_marker(&bad, BOUNDS).unwrap_err(),
            Error::Corrupt
        );
        bad = marker.clone();
        bad.version = 2;
        assert_eq!(
            encode_completion_marker(&bad, BOUNDS).unwrap_err(),
            Error::Corrupt
        );
        // Valid phase/address changes survive decoding for native evidence comparison.
        let mut changed = marker.clone();
        changed.phase = if phase == CompletionPhase::Activation {
            CompletionPhase::Complete
        } else {
            CompletionPhase::Activation
        };
        changed.checkpoint_address.key.push(9);
        let changed_bytes = encode_completion_marker(&changed, BOUNDS).unwrap();
        assert_ne!(encoded.0, changed_bytes.0);
        assert_ne!(
            decode_completion_marker(&changed_bytes.0, BOUNDS).unwrap(),
            marker
        );
    }
}
#[test]
fn writer_grows_geometrically_so_secret_bytes_are_not_recopied_per_field() {
    let mut w = Writer::new(
        Bounds {
            items: 8,
            bytes: 4096,
        },
        1,
        1,
    )
    .unwrap();
    let mut grows = 0;
    let mut cap = w.out.0.capacity();
    for _ in 0..200 {
        w.put(&[7u8; 4]).unwrap();
        if w.out.0.capacity() != cap {
            grows += 1;
            cap = w.out.0.capacity();
        }
    }
    assert!(grows <= 8, "{grows} reallocations for 200 small puts");
}

#[test]
fn inspect_allocation_bound_reads_the_declared_bytes_of_an_encoded_inspect() {
    let inspect = encode_request(&Request::<Kernel>::Inspect { bounds: BOUNDS }, BOUNDS).unwrap();
    assert_eq!(
        inspect_allocation_bound(&inspect.0),
        Some(BOUNDS.bytes as usize)
    );
    let target = encode_request(
        &Request::<Kernel>::Target {
            upgrade: reference(),
        },
        BOUNDS,
    )
    .unwrap();
    assert_eq!(inspect_allocation_bound(&target.0), None);
    assert_eq!(inspect_allocation_bound(&inspect.0[..23]), None);
}
