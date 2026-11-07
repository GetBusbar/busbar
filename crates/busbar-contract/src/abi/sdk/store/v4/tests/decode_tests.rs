// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::sdk::door::blank_in;

fn bytes(value: &[u8]) -> wire::Bytes {
    wire::Bytes {
        ptr: value.as_ptr(),
        len: value.len(),
    }
}

fn octets(value: &[u8]) -> Blob {
    Blob {
        ptr: value.as_ptr(),
        len: value.len(),
        fmt: BLOB_OCTETS,
        flags: BLOB_SECRET,
    }
}

fn at(key: &[u8]) -> wire::Address {
    wire::Address {
        namespace: [2; 16],
        key: bytes(key),
    }
}

fn unguarded() -> wire::TimeGuard {
    wire::TimeGuard {
        flags: 0,
        _reserved: 0,
        not_before: 0,
        before: 0,
    }
}

fn put(key: &[u8], value: &[u8]) -> wire::Mutation {
    wire::Mutation {
        address: at(key),
        tag: wire::MUTATION_PUT,
        _reserved: 0,
        exact_length: 0,
        value: octets(value),
    }
}

fn commit(mutations: &[wire::Mutation]) -> wire::Candidate {
    wire::Candidate {
        id: wire::AttemptId {
            dataset: [1; 16],
            writer: [3; 16],
            operation: [4; 16],
            writer_epoch: 1,
            execution_epoch: 2,
        },
        codec: wire::CODEC_VERSION,
        _reserved: 0,
        time: unguarded(),
        predicates: core::ptr::null(),
        predicates_len: 0,
        mutations: mutations.as_ptr(),
        mutations_len: mutations.len(),
        result: octets(b"receipt"),
    }
}

#[test]
fn decode_copies_binary_keys_large_values_and_redacts_payloads() {
    let value = vec![0x87; 513];
    let mutations = [put(b"\0\xff", &value)];
    let raw = commit(&mutations);
    // SAFETY: all nested spans borrow the live local allocations above.
    let prepared = unsafe { candidate(&raw, 4096) }.unwrap();
    let owned::Mutation::Put {
        address,
        value: copied,
    } = &prepared.candidate().mutations[0]
    else {
        panic!()
    };
    assert_eq!(address.key, b"\0\xff");
    assert_eq!(copied.0, value);
    assert_ne!(copied.0.as_ptr(), value.as_ptr());
    assert_eq!(prepared.candidate().result.0, b"receipt");
    assert_eq!(format!("{copied}"), "[REDACTED]");
}

#[test]
fn item_counts_do_not_have_a_hundred_item_cap() {
    let keys: Vec<_> = (0u32..101).map(u32::to_be_bytes).collect();
    let mutations: Vec<_> = keys.iter().map(|key| put(key, b"v")).collect();
    // SAFETY: local keys/mutations and static values remain live and immutable.
    let prepared = unsafe { candidate(&commit(&mutations), 100_000) }.unwrap();
    assert_eq!(prepared.candidate().mutations.len(), 101);
}

#[test]
fn aggregate_read_budget_counts_owned_descriptors_and_keys_exactly() {
    let addresses = [at(b"abcd"), at(b"ef")];
    let mut raw = blank_in::<wire::ReadIn>();
    raw.dataset = [1; 16];
    raw.addresses = addresses.as_ptr();
    raw.addresses_len = addresses.len();
    let required = size_of::<owned::Address>() * 2 + 6;
    // SAFETY: addresses and keys are live for both calls.
    assert_eq!(
        unsafe { read(&raw, required - 1) }.unwrap_err(),
        DecodeError::Budget
    );
    // SAFETY: same retained inputs.
    assert_eq!(unsafe { read(&raw, required) }.unwrap().addresses.len(), 2);
}

#[test]
fn span_checks_null_alignment_multiplication_and_address_wrap() {
    assert_eq!(
        span::<wire::Mutation>(core::ptr::null(), 1),
        Err(DecodeError::Span)
    );
    assert_eq!(
        span::<wire::Mutation>(core::ptr::null(), usize::MAX),
        Err(DecodeError::Span)
    );
    assert_eq!(
        span::<u8>(core::ptr::null(), isize::MAX as usize + 1),
        Err(DecodeError::Span)
    );
    assert_eq!(
        span::<wire::Mutation>(core::ptr::dangling::<u8>().cast(), 1),
        Err(DecodeError::Span)
    );
    assert_eq!(
        span::<u8>(usize::MAX as *const _, 1),
        Err(DecodeError::Span)
    );
    assert_eq!(span::<u8>(core::ptr::null(), 0), Ok(()));
}

#[test]
fn rejects_bad_tags_flags_unflagged_lengths_and_formats() {
    let mut mutation = put(b"key", b"value");
    for change in 0..6 {
        let mut item = mutation;
        match change {
            0 => item.tag = 999,
            1 => item._reserved = 1,
            2 => item.exact_length = 1,
            3 => item.value.flags = 2,
            4 => item.value.fmt = crate::abi::mechanism::call::BLOB_JSON,
            _ => item.value = Blob::ZERO,
        }
        // SAFETY: borrowed inputs refer to static bytes and the local descriptor.
        assert!(unsafe { candidate(&commit(&[item]), 4096) }.is_err());
    }
    mutation.tag = wire::MUTATION_DELETE;
    // SAFETY: input spans remain live; deletion incorrectly carries a value.
    assert_eq!(
        unsafe { candidate(&commit(&[mutation]), 4096) }.unwrap_err(),
        DecodeError::Blob
    );
}

#[test]
fn absence_requires_canonical_absent_or_empty_octets() {
    let mutations = [put(b"key", b"v")];
    let mut predicate = wire::Predicate {
        address: at(b"key"),
        tag: wire::PREDICATE_ABSENT,
        _reserved: 0,
        expected: Blob::ZERO,
    };
    for expected in [Blob::ZERO, octets(b"")] {
        predicate.expected = expected;
        let mut raw = commit(&mutations);
        raw.predicates = &predicate;
        raw.predicates_len = 1;
        // SAFETY: descriptors and their nested static payloads are live.
        assert!(unsafe { candidate(&raw, 4096) }.is_ok());
    }
    predicate.expected = Blob {
        fmt: BLOB_ABSENT,
        ..octets(b"")
    };
    let mut raw = commit(&mutations);
    raw.predicates = &predicate;
    raw.predicates_len = 1;
    // SAFETY: valid spans but deliberately inconsistent blob metadata.
    assert_eq!(
        unsafe { candidate(&raw, 4096) }.unwrap_err(),
        DecodeError::Blob
    );
}

#[test]
fn neutral_validation_rejects_overlap_and_zero_identity() {
    let mutations = [
        put(b"same", b"first-secret"),
        put(b"same", b"second-secret"),
    ];
    let mut raw = commit(&mutations);
    // SAFETY: all nested spans retain their local/static backing allocations.
    assert_eq!(
        unsafe { candidate(&raw, 4096) }.unwrap_err(),
        DecodeError::Candidate(owned::InvalidCandidate::Overlap)
    );
    raw.id.dataset = [0; 16];
    // SAFETY: same retained input backing allocations.
    assert_eq!(
        unsafe { candidate(&raw, 4096) }.unwrap_err(),
        DecodeError::Identity
    );
}

#[test]
fn failed_validation_retires_every_copied_payload_in_wiping_custody() {
    use crate::alloc_counter::InitializedPayloadProbe;
    // SAFETY: watched decoder allocations remain initialized until their owners drop.
    let probe = unsafe { InitializedPayloadProbe::start().unwrap() };
    let mutations = [
        put(b"same", b"first-private-value"),
        put(b"same", b"second-private-value"),
    ];
    // SAFETY: all input spans borrow retained local descriptors and static bytes.
    assert_eq!(
        unsafe { candidate(&commit(&mutations), 4096) }.unwrap_err(),
        DecodeError::Candidate(owned::InvalidCandidate::Overlap)
    );
    let observed = probe.finish();
    assert!(!observed.reentered);
    assert_eq!(observed.payloads.len(), 3);
    for payload in observed.payloads {
        assert!(payload.freed);
        assert!(!payload.reallocated);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(payload.read_error, None);
            assert!(payload.complete_read);
            assert!(payload.wiped);
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(payload.read_error, Some(std::io::ErrorKind::Unsupported));
    }
}

#[test]
fn candidate_budget_is_aggregate_and_checked_before_payload_copies() {
    let mutations = [put(b"key", b"payload")];
    let raw = commit(&mutations);
    let required = size_of::<owned::Mutation>()
        + owned::Candidate::<crate::redacted::Kernel>::validation_workspace_bytes(0, 1).unwrap()
        + 3
        + 7
        + b"receipt".len();
    // SAFETY: all spans borrow retained local descriptors and static bytes.
    assert_eq!(
        unsafe { candidate(&raw, required - 1) }.unwrap_err(),
        DecodeError::Budget
    );
    // SAFETY: same retained backing allocations.
    assert!(unsafe { candidate(&raw, required) }.is_ok());
}

#[test]
fn storage_value_is_not_limited_by_the_conditional_extension_ceiling() {
    let value = vec![0xA5; 16 * 1024 * 1024 + 1];
    let mutations = [put(b"key", &value)];
    // SAFETY: descriptor array and nested value remain live for the copy.
    let result = unsafe { candidate(&commit(&mutations), value.len() + 4096) }.unwrap();
    let owned::Mutation::Put { value: copied, .. } = &result.candidate().mutations[0] else {
        panic!()
    };
    assert_eq!(copied.0.len(), value.len());
}

#[test]
fn time_guards_reject_unknown_bits_unflagged_values_and_empty_intervals() {
    assert_eq!(
        time(wire::TimeGuard {
            flags: 4,
            ..unguarded()
        }),
        Err(DecodeError::Flags)
    );
    assert_eq!(
        time(wire::TimeGuard {
            before: 1,
            ..unguarded()
        }),
        Err(DecodeError::Time)
    );
    assert_eq!(
        time(wire::TimeGuard {
            flags: 3,
            not_before: 4,
            before: 4,
            ..unguarded()
        }),
        Err(DecodeError::Time)
    );
    assert_eq!(
        time(wire::TimeGuard {
            flags: 3,
            not_before: 0,
            before: 1,
            ..unguarded()
        })
        .unwrap(),
        Some(owned::TimeGuard {
            not_before: Some(0),
            before: Some(1)
        })
    );
}

#[test]
fn scan_preserves_empty_cursor_generation_and_explicit_display_mode() {
    let mut raw = blank_in::<wire::ScanIn>();
    raw.dataset = [1; 16];
    raw.namespace = [2; 16];
    raw.prefix = bytes(b"prefix");
    raw.after = bytes(b"");
    raw.max_items = 101;
    raw.max_bytes = 32 * 1024 * 1024;
    raw.flags = wire::SCAN_AFTER | wire::SCAN_GENERATION;
    // SAFETY: all spans borrow static bytes.
    let result = unsafe { scan(&raw, 6) }.unwrap();
    assert_eq!(result.after, Some(vec![]));
    assert_eq!(result.generation, Some(0));
    assert!(!result.allow_change);
    raw.flags = wire::SCAN_AFTER;
    // SAFETY: static prefix/cursor are retained.
    assert_eq!(unsafe { scan(&raw, 6) }.unwrap_err(), DecodeError::Scan);
    raw.flags |= wire::SCAN_ALLOW_CHANGE;
    // SAFETY: static prefix/cursor are retained.
    assert!(unsafe { scan(&raw, 6) }.unwrap().allow_change);
    raw.flags |= wire::SCAN_GENERATION;
    // SAFETY: static prefix/cursor are retained.
    assert_eq!(unsafe { scan(&raw, 6) }.unwrap_err(), DecodeError::Scan);
}

crate::own_seal!(StoreOwner);

#[test]
fn backend_decode_seals_values_to_its_owner_without_changing_identity() {
    let mutations = [put(b"key", b"opaque storage value")];
    let raw = commit(&mutations);
    // SAFETY: all spans borrow the live local descriptors and static bytes.
    let kernel = unsafe { candidate(&raw, 4096) }.unwrap();
    // SAFETY: same live spans; only the output owner changes.
    let backend = unsafe { candidate_owned(&raw, 4096, &StoreOwner::here()) }.unwrap();
    assert_eq!(backend.fingerprint(), kernel.fingerprint());
    let cloned = backend.clone();
    assert!(std::ptr::eq(backend.candidate(), cloned.candidate()));
    let owned::Mutation::Put { value, .. } = &backend.candidate().mutations[0] else {
        panic!("expected put")
    };
    assert_eq!(
        value.expose_own(&StoreOwner::here()),
        b"opaque storage value"
    );
    assert_eq!(
        backend.candidate().result.expose_own(&StoreOwner::here()),
        b"receipt"
    );
    assert!(!format!("{backend:?}").contains("opaque storage value"));
}
