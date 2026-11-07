// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::mechanism::call::RawOutcome;
use crate::abi::sdk::door::{blank_in, blank_out};

fn ready<T: crate::abi::sdk::door::AbiOut>() -> T {
    blank_out::<T>()
}

#[test]
fn read_copies_only_host_written_bytes_and_preserves_empty_vs_absent() {
    let bytes = [7u8, 8];
    let mut items = [
        wire::ReadValue {
            found: wire::VALUE_FOUND,
            _reserved: 0,
            value: Blob {
                ptr: bytes.as_ptr(),
                len: 2,
                fmt: BLOB_OCTETS,
                flags: BLOB_SECRET,
            },
        },
        wire::ReadValue {
            found: wire::VALUE_ABSENT,
            _reserved: 0,
            value: Blob::ABSENT,
        },
    ];
    let mut input = blank_in::<wire::ReadIn>();
    input.addresses_len = 2;
    input.values = wire::HostValues {
        items: items.as_mut_ptr(),
        items_cap: items.len(),
        bytes: HostBuf {
            ptr: bytes.as_ptr().cast_mut(),
            cap: bytes.len(),
        },
    };
    let mut out = ready::<wire::ReadOut>();
    out.head.size = core::mem::size_of::<wire::ReadOut>() as u32;
    out.head.outcome = RawOutcome::of(Outcome::Ready);
    out.code = wire::READ_VALUES;
    out.authority = [1; 16];
    // Envelope/diagnostic leases remain the loader's responsibility.
    out.head.lease = 9;
    out.items_written = 2;
    out.bytes_written = 2;
    let owned::ReadResult::Values { values, .. } =
        read(Outcome::Ready, &input, &out, &items, &bytes, 1024).unwrap()
    else {
        panic!()
    };
    assert_eq!(values[0].as_ref().unwrap().0, bytes);
    assert!(values[1].is_none());
    assert_eq!(
        read(Outcome::Ready, &input, &out, &items, &bytes, 0).unwrap_err(),
        ResponseError::Budget
    );
    items[1].value.flags = BLOB_SECRET;
    assert_eq!(
        read(Outcome::Ready, &input, &out, &items, &bytes, 1024).unwrap_err(),
        ResponseError::Malformed
    );
    items[1].value.flags = 0;
    items[0].value.len = 0;
    let owned::ReadResult::Values { values, .. } =
        read(Outcome::Ready, &input, &out, &items, &bytes, 1024).unwrap()
    else {
        panic!()
    };
    assert!(values[0].as_ref().unwrap().0.is_empty());
    items[0].value.ptr = usize::MAX as *const u8;
    assert_eq!(
        read(Outcome::Ready, &input, &out, &items, &bytes, 1024).unwrap_err(),
        ResponseError::Malformed
    );
    items[0].value.ptr = bytes.as_ptr();
    items[0].value.len = 2;
    out.bytes_written = 1;
    assert!(read(Outcome::Ready, &input, &out, &items, &bytes, 1024).is_err());
}

#[test]
fn commit_failed_short_and_refused_are_distinct() {
    let input = blank_in::<wire::CommitIn>();
    let mut out = blank_out::<wire::CommitOut>();
    out.head.size = core::mem::size_of::<wire::CommitOut>() as u32;
    out.head.outcome = RawOutcome::of(Outcome::Failed);
    assert_eq!(
        commit(Outcome::Failed, &input, &out, &[], 0).unwrap_err(),
        ResponseError::Failure(owned::Failure::Unknown)
    );
    out.needed = 12;
    assert_eq!(
        commit(Outcome::Failed, &input, &out, &[], 0).unwrap_err(),
        ResponseError::Short {
            needed_items: 0,
            needed_bytes: 12
        }
    );
    out.needed = 0;
    out.head.outcome = RawOutcome::of(Outcome::Refused);
    assert_eq!(
        commit(Outcome::Refused, &input, &out, &[], 0).unwrap_err(),
        ResponseError::Failure(owned::Failure::Refused)
    );
}

#[test]
fn clock_requires_nonzero_authority_and_mirrored_status() {
    let mut out = blank_out::<wire::ClockOut>();
    out.head.size = core::mem::size_of::<wire::ClockOut>() as u32;
    out.head.outcome = RawOutcome::of(Outcome::Ready);
    assert_eq!(
        clock(Outcome::Ready, &out).unwrap_err(),
        ResponseError::Malformed
    );
    out.authority = [1; 16];
    assert_eq!(clock(Outcome::Ready, &out).unwrap().authority, [1; 16]);
    assert_eq!(
        clock(Outcome::Failed, &out).unwrap_err(),
        ResponseError::Malformed
    );
}

#[test]
fn scan_checks_order_progress_generation_and_payload_budget() {
    let source = owned::Scan {
        dataset: owned::DatasetId([1; 16]),
        namespace: owned::NamespaceId([2; 16]),
        prefix: b"a".to_vec(),
        after: None,
        generation: Some(3),
        allow_change: false,
        max_items: 2,
        max_bytes: 4,
    };
    let bytes = *b"a1va1";
    let mut items = [wire::ScanRow {
        key: wire::Bytes {
            ptr: bytes.as_ptr(),
            len: 2,
        },
        value: Blob {
            ptr: bytes[2..].as_ptr(),
            len: 1,
            fmt: BLOB_OCTETS,
            flags: 0,
        },
    }];
    let input = super::super::scan(
        &source,
        blank_in::<wire::ScanIn>().head,
        wire::HostRows {
            items: items.as_mut_ptr(),
            items_cap: items.len(),
            bytes: HostBuf {
                ptr: bytes.as_ptr().cast_mut(),
                cap: bytes.len(),
            },
        },
    );
    let mut out = blank_out::<wire::ScanOut>();
    out.head.size = core::mem::size_of::<wire::ScanOut>() as u32;
    out.head.outcome = RawOutcome::of(Outcome::Ready);
    out.code = wire::SCAN_PAGE;
    out.generation = 3;
    out.continuation = wire::SCAN_CONTINUE;
    out.next = wire::Bytes {
        ptr: bytes[3..].as_ptr(),
        len: 2,
    };
    out.items_written = 1;
    out.bytes_written = bytes.len() as u64;
    let page = scan(Outcome::Ready, &source, &input, &out, &items, &bytes, 1024).unwrap();
    assert_eq!(page.next, Some(b"a1".to_vec()));
    out.generation = 4;
    assert!(scan(Outcome::Ready, &source, &input, &out, &items, &bytes, 1024).is_err());
    out.generation = 3;
    out.next.len = 1;
    assert!(scan(Outcome::Ready, &source, &input, &out, &items, &bytes, 1024).is_err());
    out.next.len = 2;
    assert_eq!(
        scan(Outcome::Ready, &source, &input, &out, &items, &bytes, 0).unwrap_err(),
        ResponseError::Budget
    );
    items[0].value.flags = 2;
    assert_eq!(
        scan(Outcome::Ready, &source, &input, &out, &items, &bytes, 1024).unwrap_err(),
        ResponseError::Malformed
    );
}

#[test]
fn temporal_verdicts_must_match_the_returned_serialization_observation() {
    let mut read_in = blank_in::<wire::ReadIn>();
    read_in.time.flags = wire::TIME_BEFORE;
    read_in.time.before = 10;
    let mut read_out = blank_out::<wire::ReadOut>();
    read_out.head.size = core::mem::size_of::<wire::ReadOut>() as u32;
    read_out.head.outcome = RawOutcome::of(Outcome::Ready);
    read_out.authority = [1; 16];
    read_out.observed_at = 10;
    read_out.code = wire::READ_VALUES;
    assert!(read(Outcome::Ready, &read_in, &read_out, &[], &[], 0).is_err());
    read_out.code = wire::READ_TIME_GUARD_FAILED;
    assert!(matches!(
        read(Outcome::Ready, &read_in, &read_out, &[], &[], 0),
        Ok(owned::ReadResult::TimeGuardFailed { .. })
    ));
    read_out.observed_at = 9;
    assert!(read(Outcome::Ready, &read_in, &read_out, &[], &[], 0).is_err());
    let mut commit_in = blank_in::<wire::CommitIn>();
    commit_in.candidate.time = read_in.time;
    let mut commit_out = blank_out::<wire::CommitOut>();
    commit_out.head.size = core::mem::size_of::<wire::CommitOut>() as u32;
    commit_out.head.outcome = RawOutcome::of(Outcome::Ready);
    commit_out.authority = [1; 16];
    commit_out.observed_at = 10;
    commit_out.code = wire::COMMIT_APPLIED;
    assert!(commit(Outcome::Ready, &commit_in, &commit_out, &[], 0).is_err());
    commit_out.observed_at = 9;
    assert!(matches!(
        commit(Outcome::Ready, &commit_in, &commit_out, &[], 0),
        Ok(owned::Decision::Applied(_))
    ));
    commit_out.code = wire::COMMIT_TIME_GUARD_FAILED;
    assert!(commit(Outcome::Ready, &commit_in, &commit_out, &[], 0).is_err());
}
