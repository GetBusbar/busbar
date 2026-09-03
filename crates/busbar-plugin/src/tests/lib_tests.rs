// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plugin/src/lib.rs`.

use super::*;
use crate::hot::Facts;

#[test]
fn preamble_layout_is_frozen() {
    // The three frozen offsets. A change here is a MAJOR event and also trips the layout golden.
    assert_eq!(core::mem::offset_of!(AbiPreamble, magic), 0);
    assert_eq!(core::mem::offset_of!(AbiPreamble, abi_major), 8);
    assert_eq!(core::mem::offset_of!(AbiPreamble, abi_minor), 12);
    assert_eq!(core::mem::size_of::<AbiPreamble>(), 16);
}

#[test]
fn check_preamble_accepts_current_and_newer_minor() {
    assert_eq!(check_preamble(&AbiPreamble::CURRENT), Ok(()));
    let newer_minor = AbiPreamble {
        abi_minor: ABI_MINOR + 7,
        ..AbiPreamble::CURRENT
    };
    assert_eq!(check_preamble(&newer_minor), Ok(()));
}

#[test]
fn check_preamble_fails_closed_on_magic_and_major() {
    let bad_magic = AbiPreamble {
        magic: 0xDEAD_BEEF,
        ..AbiPreamble::CURRENT
    };
    assert_eq!(
        check_preamble(&bad_magic),
        Err(PreambleError::BadMagic { found: 0xDEAD_BEEF })
    );
    let bad_major = AbiPreamble {
        abi_major: ABI_MAJOR + 1,
        ..AbiPreamble::CURRENT
    };
    assert_eq!(
        check_preamble(&bad_major),
        Err(PreambleError::MajorMismatch {
            ours: ABI_MAJOR,
            theirs: ABI_MAJOR + 1,
        })
    );
}

#[test]
fn sized_field_guard_hides_truncated_tail() {
    let g = Facts::new(10, 100, 1, 0, 0, b"pool");
    // A full-size struct reveals a tail field.
    assert_eq!(read_sized_field!(&*g, Facts, flags), Some(0));
    // A sender that advertised only the preamble reveals nothing past it.
    let mut truncated = *g;
    truncated.size = 6; // size(u32)=4 + version(u16)=2 — preamble only
    assert_eq!(read_sized_field!(&truncated, Facts, flags), None);
}

#[test]
fn write_out_publishes_on_ok_and_tolerates_null() {
    let mut slot = MaybeUninit::<u64>::uninit();
    // SAFETY: `slot` is a live, writable MaybeUninit.
    unsafe { write_out(&mut slot as *mut MaybeUninit<u64>, 0x1234_u64) };
    // SAFETY: we just wrote it on the Ok path.
    assert_eq!(unsafe { slot.assume_init() }, 0x1234);
    // A null out-slot must not fault.
    // SAFETY: null is explicitly tolerated by the contract.
    unsafe { write_out(core::ptr::null_mut::<MaybeUninit<u64>>(), 99_u64) };
}

// ── The minor-20 Usage keyed-unit tail (1.6.0 M1): pack/decode + sized-guard back-compat ────────

#[test]
fn usage_units_pack_decode_round_trips() {
    use crate::hot::pod::{decode_usage_units, pack_usage_units};
    use crate::hot::{AdmissionId, Usage, UsageComponent};

    let mut units = std::collections::BTreeMap::new();
    units.insert("classifications".to_string(), 3u64);
    units.insert("search".to_string(), 42u64);
    let packed = pack_usage_units(&units);

    let key = b"vk_1";
    let model = b"cmd-r";
    let provider = b"cohere";
    let guard = Usage::with_units(
        UsageComponent::Queries,
        1,
        0,
        AdmissionId(7),
        key,
        model,
        provider,
        &packed,
    );
    // A full minor-20 Usage decodes the exact map back.
    assert_eq!(decode_usage_units(&guard), units);
}

#[test]
fn usage_units_tail_hidden_from_a_pre_minor_20_sender() {
    use crate::hot::pod::{decode_usage_units, pack_usage_units};
    use crate::hot::{AdmissionId, Usage, UsageComponent};

    let mut units = std::collections::BTreeMap::new();
    units.insert("search".to_string(), 9u64);
    let packed = pack_usage_units(&units);
    let guard = Usage::with_units(
        UsageComponent::Queries,
        1,
        0,
        AdmissionId(1),
        b"k",
        b"m",
        b"p",
        &packed,
    );

    // Simulate an older peer that advertised only the minor-5 size (pre-units __size = 80): the
    // sized-struct guard must hide `units_ptr`/`units_len`, so the host bills via the legacy scalar.
    let mut old = *guard;
    old.size = 80;
    assert_eq!(read_sized_field!(&old, Usage, units_ptr), None);
    assert!(
        decode_usage_units(&old).is_empty(),
        "a pre-minor-20 sender must expose NO keyed units (append-only back-compat)"
    );

    // The current sender (full size) still exposes them.
    assert_eq!(decode_usage_units(&guard), units);
}
