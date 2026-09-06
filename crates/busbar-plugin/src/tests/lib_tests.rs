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
    assert_eq!(read_sized_field!(&*g, g.size, Facts, flags), Some(0));
    // A sender that advertised only the preamble reveals nothing past it.
    let mut truncated = *g;
    truncated.size = 6; // size(u32)=4 + version(u16)=2 — preamble only
    assert_eq!(
        read_sized_field!(&truncated, truncated.size, Facts, flags),
        None
    );
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
    assert_eq!(unsafe { decode_usage_units(&*guard) }, units);
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
    assert_eq!(read_sized_field!(&old, old.size, Usage, units_ptr), None);
    assert!(
        unsafe { decode_usage_units(&old) }.is_empty(),
        "a pre-minor-20 sender must expose NO keyed units (append-only back-compat)"
    );

    // The current sender (full size) still exposes them.
    assert_eq!(unsafe { decode_usage_units(&*guard) }, units);
}

/// The sized-field guard must be safe to point at a peer buffer that is SHORTER than the struct it
/// describes. Reading through a `&Usage` cannot be: the reference asserts the full 96 bytes are a
/// valid, dereferenceable `Usage` the instant it is formed, which over a 64-byte peer buffer is a
/// claim about memory that does not exist. The pointer form makes the advertised size the only thing
/// consulted, and touches nothing past it.
#[test]
fn sized_field_guard_reads_a_buffer_shorter_than_the_struct() {
    use crate::hot::pod::decode_usage_units;
    use crate::hot::Usage;

    // A peer that advertises only the pre-units prefix, in a buffer that is only that long — there
    // are no bytes at all where `units_ptr`/`units_len` would sit.
    const PREFIX: usize = 64;
    // Deliberately a HEAP buffer, not the array clippy would prefer: the point of the test is that
    // the allocation ENDS at `PREFIX`, so a read past it is a real out-of-bounds access that Miri or
    // ASan will flag. A stack array is surrounded by other live stack bytes and would swallow it.
    #[allow(clippy::useless_vec)]
    let mut buf = vec![0u8; PREFIX];
    buf[..4].copy_from_slice(&(PREFIX as u32).to_ne_bytes());
    let p = buf.as_ptr().cast::<Usage>();

    // `p` addresses `PREFIX` live bytes whose leading `size` says exactly that; the guard reads
    // nothing beyond it.
    assert_eq!(read_sized_field!(p, PREFIX as u32, Usage, units_ptr), None);
    assert_eq!(read_sized_field!(p, PREFIX as u32, Usage, units_len), None);
    // SAFETY: as above — the hidden tail means the decoder yields an empty map without a read.
    assert!(unsafe { decode_usage_units(p) }.is_empty());
}
