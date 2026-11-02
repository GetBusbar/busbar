// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real conditional codecs and output leases retain raw record custody on every exit.

use super::*;
use crate::alloc_counter::InitializedPayloadProbe;

fn request() -> Request {
    let material = b"conditional-CANARY-raw-credential".repeat(512);
    Request {
        capability: Capability {
            ticket: Ticket {
                slot: 7,
                generation: 11,
            },
            epoch: 13,
        },
        candidate: ConditionalCandidate {
            correlation: 17,
            predicates: vec![
                RecordPredicate {
                    kind: 0,
                    key: b"old".to_vec(),
                    expected: Expected::Bytes(material.clone()),
                },
                RecordPredicate {
                    kind: 1,
                    key: b"absent".to_vec(),
                    expected: Expected::Absent,
                },
            ],
            mutations: vec![
                RecordMutation::Put {
                    kind: 0,
                    key: b"new".to_vec(),
                    value: material.clone(),
                },
                RecordMutation::Delete {
                    kind: 1,
                    key: b"delete".to_vec(),
                },
            ],
            chains: vec![
                ChainMutation::Check {
                    kind: 2,
                    scope: b"check".to_vec(),
                    life: Expected::Bytes(vec![1; 8]),
                },
                ChainMutation::Drop {
                    kind: 2,
                    scope: b"drop".to_vec(),
                    life: Expected::Absent,
                },
                ChainMutation::Append {
                    kind: 2,
                    scope: b"append".to_vec(),
                    life: Expected::Bytes(vec![2; 8]),
                    content: material,
                },
            ],
        },
    }
}

fn probe() -> InitializedPayloadProbe {
    // SAFETY: all registered codec allocations remain live and initialized on this thread
    // until their owning guard wipes/frees them or this observation scope finishes.
    unsafe { InitializedPayloadProbe::start().expect("open initialized-payload observer") }
}

fn wiped(probe: InitializedPayloadProbe, minimum: usize) {
    let observations = probe.finish();
    assert!(!observations.reentered);
    assert!(
        observations.payloads.len() >= minimum,
        "the actual owned copies were registered"
    );
    for payload in observations.payloads {
        assert!(payload.freed, "owned codec bytes survived: {payload:?}");
        assert!(!payload.reallocated, "unwiped ordinary Vec growth");
        #[cfg(target_os = "linux")]
        {
            assert_eq!(payload.read_error, None);
            assert!(payload.complete_read);
            assert_eq!(payload.bytes_read, payload.len);
            assert!(
                payload.wiped,
                "owned codec bytes reached free unwiped: {payload:?}"
            );
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(payload.read_error, Some(std::io::ErrorKind::Unsupported));
    }
}

#[test]
fn growth_digest_result_and_settlement_temporaries_wipe_without_changing_identity() {
    let request = Decoding(request());
    let result = ConditionalResult {
        correlation: 17,
        decision: Ok(Decision::Applied),
    };
    let observer = probe();
    let encoded = Zeroizing::new(encode_request(&request.0).unwrap());
    let digest = crate::abi::sdk::digest::sha256(&encoded);
    let receipt = encode_result(&request.0, &result).unwrap();
    assert_eq!(
        read_result(&receipt, &request.0).unwrap(),
        Some(result.clone())
    );
    let settlement = read_settlement(&encode_settlement(&request.0, &result).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(settlement.request_digest, digest);
    assert!(settlement.matches(&request.0).unwrap());
    let ack = read_settlement_ack(&encode_settlement_ack(&settlement))
        .unwrap()
        .unwrap();
    assert!(ack.matches(&request.0).unwrap());
    let mut changed = Decoding(request.0.clone());
    changed.0.candidate.correlation += 1;
    assert!(!ack.matches(&changed.0).unwrap());
    assert!(!settlement.matches(&changed.0).unwrap());
    drop(encoded);
    wiped(observer, 12);
}

#[test]
fn decoded_raw_fields_wipe_on_trailing_input_truncation_and_unwind() {
    let original = Decoding(request());
    let encoded = Zeroizing::new(encode_request(&original.0).unwrap());
    let header = 2 + INTENT.len() + 4;
    for removed in [0, 1, 8, 32] {
        let mut broken = Zeroizing::new(encoded.to_vec());
        if removed == 0 {
            broken.push(0);
        } else {
            let len = broken.len() - removed;
            broken.truncate(len);
        }
        let body_len = (broken.len() - header) as u32;
        broken[header - 4..header].copy_from_slice(&body_len.to_le_bytes());
        let observer = probe();
        assert!(read_request(&broken).is_err());
        wiped(observer, 4);
    }
    let observer = probe();
    let unwind = std::panic::catch_unwind(|| {
        let decoded = Decoding(read_request(&encoded).unwrap().unwrap());
        assert_eq!(decoded.0, original.0);
        panic!("consumer unwound after taking decoded custody");
    });
    assert!(unwind.is_err());
    wiped(observer, 10);
}

#[test]
fn an_unflagged_intent_and_rejected_repeats_keep_wiping_custody_until_release() {
    use crate::abi::mechanism::call::{OutHead, Outcome, BLOB_SECRET};
    use crate::abi::sdk::{life::Leases, Out};
    let request = Decoding(request());
    let mut changed = Decoding(request.0.clone());
    changed.0.candidate.correlation += 1;
    let observer = probe();
    let leases = Leases::default();
    // SAFETY: OutHead contains only all-zero-valid scalar and raw pointer ABI fields.
    let mut output: OutHead = unsafe { std::mem::zeroed() };
    Out::new(&mut output)
        .conditional_request(&leases, &request.0)
        .unwrap();
    assert_eq!(output.extensions.flags, BLOB_SECRET);
    let identity = (output.lease, output.extensions.ptr, output.extensions.len);
    Out::new(&mut output)
        .conditional_request(&leases, &request.0)
        .unwrap();
    assert!(Out::new(&mut output)
        .conditional_request(&leases, &changed.0)
        .is_err());
    assert_eq!(
        (output.lease, output.extensions.ptr, output.extensions.len),
        identity
    );
    assert_eq!(leases.release(output.lease), Outcome::Ready);
    drop(leases);
    wiped(observer, 8);
}
