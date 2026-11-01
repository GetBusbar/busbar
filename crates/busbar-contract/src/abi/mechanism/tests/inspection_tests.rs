// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn work() -> InspectionRequest {
    InspectionRequest {
        ticket: Ticket {
            slot: 7,
            generation: 4,
        },
        epoch: 8,
        id: 1,
        query: InspectionQuery::Work {
            reference: b"public-work-reference".to_vec(),
        },
    }
}

#[test]
fn full_u64_work_facts_and_explicit_live_or_terminal_are_preserved() {
    for settled_ms in [None, Some(u64::MAX)] {
        let receipt = InspectionReceipt {
            request: work(),
            result: Ok(InspectionObservation::Work(WorkObservation {
                observed_ms: u64::MAX,
                opened_ms: u64::MAX - 2,
                retain_ms: u64::MAX - 1,
                settled_ms,
            })),
        };
        assert_eq!(
            decode_receipt(&encode_receipt(&receipt).unwrap()),
            Ok(receipt)
        );
    }
    for error in [
        InspectionError::Unsupported,
        InspectionError::NotFound,
        InspectionError::Refused,
        InspectionError::Invalid,
    ] {
        let receipt = InspectionReceipt {
            request: work(),
            result: Err(error),
        };
        assert_eq!(
            decode_receipt(&encode_receipt(&receipt).unwrap()),
            Ok(receipt)
        );
    }
}

#[test]
fn batched_carriers_are_exact_and_zero_duplicate_or_reordered_ids_are_refused() {
    let mut request = work();
    request.query = InspectionQuery::CarrierSessions {
        sessions: vec![u64::MAX, 7],
    };
    let receipt = InspectionReceipt {
        request: request.clone(),
        result: Ok(InspectionObservation::CarrierSessions(vec![
            SessionObservation {
                session: u64::MAX,
                live: false,
            },
            SessionObservation {
                session: 7,
                live: true,
            },
        ])),
    };
    assert_eq!(
        decode_receipt(&encode_receipt(&receipt).unwrap()),
        Ok(receipt.clone())
    );
    for ids in [vec![0], vec![7, 7], vec![]] {
        request.query = InspectionQuery::CarrierSessions { sessions: ids };
        assert_eq!(encode_request(&request), Err(InspectionError::Invalid));
    }
    let mut changed = receipt;
    if let Ok(InspectionObservation::CarrierSessions(found)) = &mut changed.result {
        found.reverse();
    }
    assert_eq!(encode_receipt(&changed), Err(InspectionError::Correlation));
}

#[test]
fn truncated_extra_unknown_version_and_impossible_lengths_never_decode() {
    let encoded = encode_request(&work()).unwrap();
    for end in 0..encoded.len() {
        assert!(decode_request(&encoded[..end]).is_err());
    }
    let mut extra = encoded.clone();
    extra.push(0);
    assert_eq!(decode_request(&extra), Err(InspectionError::Invalid));
    let mut version = encoded;
    version[0] = VERSION + 1;
    assert_eq!(decode_request(&version), Err(InspectionError::Unsupported));
    let mut request = work();
    request.query = InspectionQuery::CarrierSessions { sessions: vec![1] };
    let mut impossible = encode_request(&request).unwrap();
    impossible[26..30].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode_request(&impossible), Err(InspectionError::Invalid));
    request.epoch = 0;
    assert_eq!(encode_request(&request), Err(InspectionError::Unticketed));
    assert_eq!(encode_capability(0), Err(InspectionError::Unticketed));
}

#[test]
fn unknown_extensions_survive_and_duplicate_or_truncated_inspection_is_refused() {
    let before = extensions::encode(&[("other", b"kept\0bytes")]);
    let combined = append_request(&before, &work()).unwrap();
    assert!(combined.starts_with(&before));
    assert_eq!(read_request(&combined), Ok(Some(work())));
    assert_eq!(
        extensions::get(&combined, "other"),
        Some(&b"kept\0bytes"[..])
    );
    let mut duplicate = combined.clone();
    duplicate.extend_from_slice(&extensions::encode(&[(
        EXT_REQUEST,
        &encode_request(&work()).unwrap(),
    )]));
    assert_eq!(read_request(&duplicate), Err(InspectionError::Invalid));
    let mut truncated = before;
    truncated.push(0);
    assert_eq!(
        append_request(&truncated, &work()),
        Err(InspectionError::Invalid)
    );
}

#[test]
fn batch_fit_accounts_for_full_echo_reply_capability_and_existing_extensions() {
    for existing in [0, 100, MAX_BYTES - 1, MAX_BYTES, usize::MAX] {
        let count = max_carrier_sessions(existing);
        if count != 0 {
            let request_size = existing + extensions::entry_len(EXT_REQUEST, &[]) + 30 + count * 8;
            let reply_size = existing
                + extensions::entry_len(EXT_REPLY, &[])
                + 40
                + count * 17
                + extensions::entry_len(EXT_CAPABILITY, &[0; 9]);
            assert!(request_size <= MAX_BYTES);
            assert!(reply_size <= MAX_BYTES);
            assert!(reply_size + 17 > MAX_BYTES);
        }
    }
}
