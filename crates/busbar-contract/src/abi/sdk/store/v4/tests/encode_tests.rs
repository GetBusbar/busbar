// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::sdk::door::blank_in;
use crate::abi::sdk::store::v4::response::{self, ResponseError};
use crate::redacted::Secret;

crate::own_seal!(Own);

fn observed() -> owned::ClockObservation {
    owned::ClockObservation {
        authority: [1; 16],
        unix_seconds: 123,
    }
}

fn read_input(items: &mut [wire::ReadValue], bytes: &mut [u8]) -> wire::ReadIn {
    let mut input = blank_in::<wire::ReadIn>();
    input.addresses_len = 3;
    input.values = wire::HostValues {
        items: items.as_mut_ptr(),
        items_cap: items.len(),
        bytes: HostBuf {
            ptr: bytes.as_mut_ptr(),
            cap: bytes.len(),
        },
    };
    input
}

#[test]
fn read_short_then_full_preserves_opaque_owner_empty_and_absent() {
    let value = owned::ReadResult::Values {
        observed_at: observed(),
        values: vec![
            Some(Secret::<_, Own>::held(vec![4, 5])),
            Some(Secret::held(vec![])),
            None,
        ],
    };
    let mut items = [wire::ReadValue {
        found: 99,
        _reserved: 17,
        value: Blob::ABSENT,
    }; 3];
    let mut short = [42];
    let input = read_input(&mut items, &mut short);
    let out = read(&input, Ok(&value), &mut items, &mut short).unwrap();
    assert_eq!(short, [42]);
    assert_eq!(items[0].found, 99);
    assert_eq!(
        response::read(Outcome::Failed, &input, &out, &items, &short, 1000).unwrap_err(),
        ResponseError::Short {
            needed_items: 3,
            needed_bytes: 2
        }
    );
    let mut bytes = [42; 2];
    let input = read_input(&mut items, &mut bytes);
    let out = read(&input, Ok(&value), &mut items, &mut bytes).unwrap();
    let owned::ReadResult::Values {
        values,
        observed_at,
    } = response::read(Outcome::Ready, &input, &out, &items, &bytes, 1000).unwrap()
    else {
        panic!()
    };
    assert_eq!(observed_at, observed());
    assert_eq!(values[0].as_ref().unwrap().0, [4, 5]);
    assert!(values[1].as_ref().unwrap().0.is_empty());
    assert!(values[2].is_none());
    assert_eq!(items[0].value.flags, BLOB_SECRET);
    assert_eq!(items[1].value.flags, BLOB_SECRET);
}

#[test]
fn read_bad_bindings_and_counts_never_write() {
    let value = owned::ReadResult::Values {
        observed_at: observed(),
        values: vec![Some(Secret::new(vec![4, 5]))],
    };
    let mut items = [wire::ReadValue {
        found: 99,
        _reserved: 17,
        value: Blob::ABSENT,
    }; 3];
    let mut bytes = [42; 2];
    let mut input = read_input(&mut items, &mut bytes);
    assert_eq!(
        read(&input, Ok(&value), &mut items, &mut bytes).unwrap_err(),
        EncodeError::Malformed
    );
    input.addresses_len = 1;
    input.values.bytes.cap = 1;
    assert_eq!(
        read(&input, Ok(&value), &mut items, &mut bytes).unwrap_err(),
        EncodeError::Buffer
    );
    input.values.bytes.cap = 2;
    input.values.items = core::ptr::null_mut();
    assert_eq!(
        read(&input, Ok(&value), &mut items, &mut bytes).unwrap_err(),
        EncodeError::Buffer
    );
    assert_eq!(items[0].found, 99);
    assert_eq!(bytes, [42; 2]);
}

fn scan_source() -> owned::Scan {
    owned::Scan {
        dataset: owned::DatasetId([1; 16]),
        namespace: owned::NamespaceId([2; 16]),
        prefix: b"a".to_vec(),
        after: None,
        generation: Some(3),
        allow_change: false,
        max_items: 2,
        max_bytes: 6,
    }
}

fn page() -> owned::Page<Own> {
    owned::Page {
        generation: 3,
        rows: vec![(
            owned::Address {
                namespace: [2; 16],
                key: b"a1".to_vec(),
            },
            Secret::held(vec![8]),
        )],
        next: Some(b"a1".to_vec()),
    }
}

fn rows() -> [wire::ScanRow; 1] {
    [wire::ScanRow {
        key: wire::Bytes {
            ptr: core::ptr::null(),
            len: 99,
        },
        value: Blob::ABSENT,
    }]
}

fn scan_input(source: &owned::Scan, items: &mut [wire::ScanRow], bytes: &mut [u8]) -> wire::ScanIn {
    super::super::scan(
        source,
        blank_in::<wire::ScanIn>().head,
        wire::HostRows {
            items: items.as_mut_ptr(),
            items_cap: items.len(),
            bytes: HostBuf {
                ptr: bytes.as_mut_ptr(),
                cap: bytes.len(),
            },
        },
    )
}

#[test]
fn scan_short_roundtrip_and_stale_are_explicit() {
    let source = scan_source();
    let page = page();
    let mut items = rows();
    let mut short = [42; 4];
    let input = scan_input(&source, &mut items, &mut short);
    let out = scan(&source, &input, Ok(&page), &mut items, &mut short).unwrap();
    assert_eq!(short, [42; 4]);
    assert_eq!(items[0].key.len, 99);
    assert_eq!(
        response::scan(Outcome::Failed, &source, &input, &out, &items, &short, 1000).unwrap_err(),
        ResponseError::Short {
            needed_items: 1,
            needed_bytes: 5
        }
    );
    let mut bytes = [42; 5];
    let input = scan_input(&source, &mut items, &mut bytes);
    let out = scan(&source, &input, Ok(&page), &mut items, &mut bytes).unwrap();
    let result =
        response::scan(Outcome::Ready, &source, &input, &out, &items, &bytes, 1000).unwrap();
    assert_eq!(result.rows[0].0.key, b"a1");
    assert_eq!(result.rows[0].1 .0, [8]);
    assert_eq!(result.next, Some(b"a1".to_vec()));
    let out = scan::<Own>(
        &source,
        &input,
        Err(owned::Failure::StaleScan),
        &mut items,
        &mut bytes,
    )
    .unwrap();
    assert_eq!(
        response::scan(Outcome::Ready, &source, &input, &out, &items, &bytes, 1000).unwrap_err(),
        ResponseError::Failure(owned::Failure::StaleScan)
    );
}

#[test]
fn scan_semantic_errors_never_write() {
    let source = scan_source();
    let mut page = page();
    let mut items = rows();
    let mut bytes = [42; 10];
    let input = scan_input(&source, &mut items, &mut bytes);
    page.next = Some(b"a2".to_vec());
    assert_eq!(
        scan(&source, &input, Ok(&page), &mut items, &mut bytes).unwrap_err(),
        EncodeError::Malformed
    );
    page.next = None;
    page.generation = 4;
    assert_eq!(
        scan(&source, &input, Ok(&page), &mut items, &mut bytes).unwrap_err(),
        EncodeError::Malformed
    );
    page.generation = 3;
    page.rows[0].0.namespace = [9; 16];
    assert_eq!(
        scan(&source, &input, Ok(&page), &mut items, &mut bytes).unwrap_err(),
        EncodeError::Malformed
    );
    assert_eq!(bytes, [42; 10]);
    assert_eq!(items[0].key.len, 99);
}

#[test]
fn commit_short_replay_retains_observation_and_failure_uncertainty() {
    let decision = owned::Decision::Applied(Secret::<_, Own>::held(vec![4, 5]));
    let mut short = [42];
    let mut input = blank_in::<wire::CommitIn>();
    input.result = HostBuf {
        ptr: short.as_mut_ptr(),
        cap: short.len(),
    };
    let out = commit(&input, observed(), Ok(&decision), &mut short).unwrap();
    assert_eq!(short, [42]);
    assert_eq!(
        response::commit(Outcome::Failed, &input, &out, &short, 1000).unwrap_err(),
        ResponseError::Short {
            needed_items: 0,
            needed_bytes: 2
        }
    );
    let mut bytes = [42; 2];
    input.result = HostBuf {
        ptr: bytes.as_mut_ptr(),
        cap: bytes.len(),
    };
    let out = commit(&input, observed(), Ok(&decision), &mut bytes).unwrap();
    assert_eq!(out.observed_at, 123);
    let owned::Decision::Applied(value) =
        response::commit(Outcome::Ready, &input, &out, &bytes, 1000).unwrap()
    else {
        panic!()
    };
    assert_eq!(value.0, [4, 5]);
    let out = commit::<Own>(&input, observed(), Err(owned::Failure::Unknown), &mut bytes).unwrap();
    assert_eq!(
        response::commit(Outcome::Failed, &input, &out, &bytes, 1000).unwrap_err(),
        ResponseError::Failure(owned::Failure::Unknown)
    );
    let out = commit::<Own>(&input, observed(), Err(owned::Failure::Refused), &mut bytes).unwrap();
    assert_eq!(
        response::commit(Outcome::Refused, &input, &out, &bytes, 1000).unwrap_err(),
        ResponseError::Failure(owned::Failure::Refused)
    );
}

#[test]
fn clock_and_commit_require_valid_agreed_observation() {
    let out = clock(Ok(observed())).unwrap();
    assert_eq!(response::clock(Outcome::Ready, &out).unwrap(), observed());
    assert_eq!(
        clock(Ok(owned::ClockObservation {
            authority: [0; 16],
            unix_seconds: 0
        }))
        .unwrap_err(),
        EncodeError::Malformed
    );
    let mut input = blank_in::<wire::CommitIn>();
    let mut bytes = [42];
    input.result = HostBuf {
        ptr: bytes.as_mut_ptr(),
        cap: 1,
    };
    let decision: owned::Decision = owned::Decision::TimeGuardFailed {
        observed_at: observed(),
    };
    let other = owned::ClockObservation {
        unix_seconds: 124,
        ..observed()
    };
    assert_eq!(
        commit(&input, other, Ok(&decision), &mut bytes).unwrap_err(),
        EncodeError::Malformed
    );
    assert_eq!(bytes, [42]);
}

#[test]
fn read_and_commit_validate_guard_before_writing() {
    let value = owned::ReadResult::Values {
        observed_at: observed(),
        values: vec![Some(Secret::new(vec![7]))],
    };
    let failed: owned::ReadResult = owned::ReadResult::TimeGuardFailed {
        observed_at: observed(),
    };
    let mut items = [wire::ReadValue {
        found: 99,
        _reserved: 0,
        value: Blob::ABSENT,
    }];
    let mut bytes = [42];
    let mut input = read_input(&mut items, &mut bytes);
    input.addresses_len = 1;
    assert_eq!(
        read(&input, Ok(&failed), &mut items, &mut bytes).unwrap_err(),
        EncodeError::Malformed
    );
    input.time = wire::TimeGuard {
        flags: wire::TIME_BEFORE,
        _reserved: 0,
        not_before: 0,
        before: 123,
    };
    assert_eq!(
        read(&input, Ok(&value), &mut items, &mut bytes).unwrap_err(),
        EncodeError::Malformed
    );
    let out = read(&input, Ok(&failed), &mut items, &mut bytes).unwrap();
    assert!(matches!(
        response::read(Outcome::Ready, &input, &out, &items, &bytes, 1000).unwrap(),
        owned::ReadResult::TimeGuardFailed { .. }
    ));
    input.time._reserved = 1;
    assert_eq!(
        read(&input, Ok(&failed), &mut items, &mut bytes).unwrap_err(),
        EncodeError::Malformed
    );
    assert_eq!(items[0].found, 99);
    assert_eq!(bytes, [42]);
    let mut commit_input = blank_in::<wire::CommitIn>();
    commit_input.result = HostBuf {
        ptr: bytes.as_mut_ptr(),
        cap: bytes.len(),
    };
    commit_input.candidate.time = wire::TimeGuard {
        flags: wire::TIME_BEFORE,
        _reserved: 0,
        not_before: 0,
        before: 123,
    };
    let applied = owned::Decision::Applied(Secret::new(vec![7]));
    assert_eq!(
        commit(&commit_input, observed(), Ok(&applied), &mut bytes).unwrap_err(),
        EncodeError::Malformed
    );
    let failed: owned::Decision = owned::Decision::TimeGuardFailed {
        observed_at: observed(),
    };
    let out = commit(&commit_input, observed(), Ok(&failed), &mut bytes).unwrap();
    assert!(matches!(
        response::commit(Outcome::Ready, &commit_input, &out, &bytes, 1000).unwrap(),
        owned::Decision::TimeGuardFailed { .. }
    ));
    assert_eq!(bytes, [42]);
}

#[test]
fn scan_validates_all_rows_before_writing_and_preserves_empty_cursor() {
    let mut source = scan_source();
    source.prefix.clear();
    let mut page = owned::Page {
        generation: 3,
        rows: vec![
            (
                owned::Address {
                    namespace: [2; 16],
                    key: vec![],
                },
                Secret::<_, Own>::held(vec![]),
            ),
            (
                owned::Address {
                    namespace: [2; 16],
                    key: vec![],
                },
                Secret::held(vec![1]),
            ),
        ],
        next: None,
    };
    let mut items = [rows()[0]; 2];
    let mut bytes = [42; 10];
    let input = scan_input(&source, &mut items, &mut bytes);
    assert_eq!(
        scan(&source, &input, Ok(&page), &mut items, &mut bytes).unwrap_err(),
        EncodeError::Malformed
    );
    assert_eq!(items[0].key.len, 99);
    assert_eq!(bytes, [42; 10]);
    page.rows.pop();
    page.next = Some(vec![]);
    let out = scan(&source, &input, Ok(&page), &mut items, &mut bytes).unwrap();
    assert!(!out.next.ptr.is_null());
    assert_eq!(out.next.len, 0);
    let result =
        response::scan(Outcome::Ready, &source, &input, &out, &items, &bytes, 1000).unwrap();
    assert_eq!(result.next, Some(vec![]));
    assert!(result.rows[0].1 .0.is_empty());
}

#[test]
fn descriptor_short_reports_full_dimensions_without_writes() {
    let value = owned::ReadResult::Values {
        observed_at: observed(),
        values: vec![Some(Secret::new(vec![4])), None, None],
    };
    let mut items = [];
    let mut bytes = [42; 2];
    let input = read_input(&mut items, &mut bytes);
    let out = read(&input, Ok(&value), &mut items, &mut bytes).unwrap();
    assert_eq!(
        response::read(Outcome::Failed, &input, &out, &items, &bytes, 1000).unwrap_err(),
        ResponseError::Short {
            needed_items: 3,
            needed_bytes: 1
        }
    );
    assert_eq!(bytes, [42; 2]);
}

#[test]
fn stale_requires_an_actual_generation_comparison() {
    let mut source = scan_source();
    source.generation = None;
    let mut items = rows();
    let mut bytes = [42; 5];
    let input = scan_input(&source, &mut items, &mut bytes);
    assert_eq!(
        scan::<Own>(
            &source,
            &input,
            Err(owned::Failure::StaleScan),
            &mut items,
            &mut bytes
        )
        .unwrap_err(),
        EncodeError::Malformed
    );
    let mut out: wire::ScanOut = output();
    head::<wire::ScanOut>(&mut out.head, Outcome::Ready);
    out.code = wire::SCAN_STALE;
    assert_eq!(
        response::scan(Outcome::Ready, &source, &input, &out, &items, &bytes, 1000).unwrap_err(),
        ResponseError::Malformed
    );
    assert_eq!(items[0].key.len, 99);
    assert_eq!(bytes, [42; 5]);
}
