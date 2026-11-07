// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Primitive failures cannot masquerade as the removed business trait's empty
//! reads, successful no-op writes or ungoverned defaults. Business atomicity is
//! exercised by the native identity/ledger tests; this gate covers the real ABI.

use busbar_contract::abi::mechanism::call::{Blob, Outcome, RawOutcome, BLOB_OCTETS, BLOB_SECRET};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::sdk::store::v4::response::{self, ResponseError};
use busbar_contract::abi::store::{v4 as wire, HostBuf};
use busbar_contract::persistence::{self as owned, Failure};
use busbar_contract::records::{PlaneRequestCtx, RecordStoreError, VirtualKey};

fn sample_key() -> VirtualKey {
    VirtualKey {
        id: "vk_1".to_string(),
        generation_hash: "h".to_string(),
        name: "n".to_string(),
        enabled: true,
        created_at: 1,
        ..Default::default()
    }
}

#[test]
fn store_error_from_string_and_str_preserve_the_message() {
    let from_string: RecordStoreError = "disk full".to_string().into();
    assert_eq!(from_string.to_string(), "store error: disk full");

    let from_str: RecordStoreError = "disk full".into();
    assert_eq!(from_str.to_string(), "store error: disk full");
}

#[test]
fn plane_request_ctx_default_is_ungoverned() {
    let ctx = PlaneRequestCtx::default();
    assert!(!ctx.is_governed());
    assert!(ctx.key().is_none());
}

#[test]
fn plane_request_ctx_with_key_is_governed() {
    let ctx = PlaneRequestCtx {
        key: Some(std::sync::Arc::new(sample_key())),
    };
    assert!(ctx.is_governed());
    assert_eq!(ctx.key().map(|k| k.id.as_str()), Some("vk_1"));
}

fn error(outcome: Outcome, write: bool) -> ResponseError {
    match outcome {
        Outcome::Failed => ResponseError::Failure(if write {
            Failure::Unknown
        } else {
            Failure::Unavailable
        }),
        Outcome::Refused => ResponseError::Failure(Failure::Refused),
        Outcome::Pending => ResponseError::Pending,
        _ => unreachable!(),
    }
}
#[test]
fn failed_reads_never_become_absent_records_or_empty_credential_lists() {
    let input = blank_in::<wire::ReadIn>();
    for outcome in [Outcome::Failed, Outcome::Refused, Outcome::Pending] {
        let mut out = blank_out::<wire::ReadOut>();
        out.head.outcome = RawOutcome::of(outcome);
        out.head.size = std::mem::size_of_val(&out) as u32;
        assert_eq!(
            response::read(outcome, &input, &out, &[], &[], 0).unwrap_err(),
            error(outcome, false)
        );
    }
}
#[test]
fn failed_scans_never_become_empty_audit_denylist_or_parent_history() {
    let source = owned::Scan {
        dataset: owned::DatasetId([1; 16]),
        namespace: owned::NamespaceId([2; 16]),
        prefix: vec![],
        after: None,
        generation: None,
        allow_change: true,
        max_items: 1,
        max_bytes: 512,
    };
    let input = busbar_contract::abi::sdk::store::v4::scan(
        &source,
        blank_in::<wire::ScanIn>().head,
        wire::HostRows {
            items: std::ptr::null_mut(),
            items_cap: 0,
            bytes: HostBuf {
                ptr: std::ptr::null_mut(),
                cap: 0,
            },
        },
    );
    for outcome in [Outcome::Failed, Outcome::Refused, Outcome::Pending] {
        let mut out = blank_out::<wire::ScanOut>();
        out.head.outcome = RawOutcome::of(outcome);
        out.head.size = std::mem::size_of_val(&out) as u32;
        assert_eq!(
            response::scan(outcome, &source, &input, &out, &[], &[], 0).unwrap_err(),
            error(outcome, false)
        );
    }
}
#[test]
fn failed_writes_never_claim_credential_revocation_deletion_or_token_success() {
    let input = blank_in::<wire::CommitIn>();
    for outcome in [Outcome::Failed, Outcome::Refused, Outcome::Pending] {
        let mut out = blank_out::<wire::CommitOut>();
        out.head.outcome = RawOutcome::of(outcome);
        out.head.size = std::mem::size_of_val(&out) as u32;
        assert_eq!(
            response::commit(outcome, &input, &out, &[], 0).unwrap_err(),
            error(outcome, true)
        );
    }
}
#[test]
fn read_preserves_arbitrary_opaque_body_bytes() {
    let bytes = b"not json at all, on purpose";
    let mut items = [wire::ReadValue {
        found: wire::VALUE_FOUND,
        _reserved: 0,
        value: Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: BLOB_OCTETS,
            flags: BLOB_SECRET,
        },
    }];
    let mut input = blank_in::<wire::ReadIn>();
    input.addresses_len = 1;
    input.values = wire::HostValues {
        items: items.as_mut_ptr(),
        items_cap: 1,
        bytes: HostBuf {
            ptr: bytes.as_ptr().cast_mut(),
            cap: bytes.len(),
        },
    };
    let mut out = blank_out::<wire::ReadOut>();
    out.head.outcome = RawOutcome::of(Outcome::Ready);
    out.head.size = std::mem::size_of_val(&out) as u32;
    out.authority = [1; 16];
    out.code = wire::READ_VALUES;
    out.items_written = 1;
    out.bytes_written = bytes.len() as u64;
    let owned::ReadResult::Values { values, .. } =
        response::read(Outcome::Ready, &input, &out, &items, bytes, 4096).unwrap()
    else {
        panic!("original opaque bytes expected")
    };
    assert_eq!(
        values[0].as_ref().unwrap(),
        &busbar_contract::Secret::new(bytes.to_vec())
    );
}
