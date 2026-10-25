// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plugin/src/lib.rs`.

use super::*;

/// A sized POD of the shape the guard reads: a leading `size`, then fields appended in order.
#[repr(C)]
#[derive(Clone, Copy)]
struct Pod {
    size: u32,
    _version: u16,
    _reserved: u16,
    tokens: u64,
    flags: u32,
    tail_ptr: *const u8,
    tail_len: usize,
}

impl Pod {
    fn whole() -> Pod {
        Pod {
            size: core::mem::size_of::<Pod>() as u32,
            _version: 1,
            _reserved: 0,
            tokens: 10,
            flags: 0,
            tail_ptr: core::ptr::null(),
            tail_len: 0,
        }
    }
}

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

/// ITEM 410 — THE PRE-RESIZE LAYOUT IS REFUSED, NOT ACCEPTED. Minor 21 RESIZED an interior field
/// (`BuildCtx.host_ctx`, 8 → 16 bytes) and shifted every field after it, so a peer stamped with the
/// major that layout change left behind (`1`, at minor 20 or at the 21 that carried the resize under
/// the old major) reads `config_ptr`/`config_len`/`resolved_refs_*` from the wrong offsets. A layout
/// change is a MAJOR event: the airlock must refuse every such peer before a sized struct is read.
#[test]
fn check_preamble_refuses_a_peer_of_the_pre_resize_layout() {
    for abi_minor in [20, 21] {
        let old = AbiPreamble {
            magic: ABI_MAGIC,
            abi_major: 1,
            abi_minor,
        };
        assert_eq!(
            check_preamble(&old),
            Err(PreambleError::MajorMismatch {
                ours: ABI_MAJOR,
                theirs: 1,
            }),
            "a 1.{abi_minor} peer predates the BuildCtx resize and must be refused"
        );
    }
}

#[test]
fn sized_field_guard_hides_truncated_tail() {
    let g = Pod::whole();
    // A full-size struct reveals a tail field.
    assert_eq!(read_sized_field!(&g, g.size, Pod, flags), Some(0));
    // A sender that advertised only the preamble reveals nothing past it.
    let mut truncated = g;
    truncated.size = 6; // size(u32)=4 + version(u16)=2 — preamble only
    assert_eq!(
        read_sized_field!(&truncated, truncated.size, Pod, flags),
        None
    );
}

/// A peer's attested size is CLAMPED to this build's struct: an over-claim never widens the read
/// window, and a shorter claim is honoured verbatim (the append-only rule).
#[test]
fn an_over_large_attested_size_is_clamped_to_this_builds_struct() {
    let ours = core::mem::size_of::<Pod>();
    assert_eq!(honoured_size(u32::MAX, ours), ours as u32);
    assert_eq!(honoured_size(ours as u32 + 1, ours), ours as u32);
    // A shorter claim is honoured verbatim — that is the append-only rule, untouched.
    assert_eq!(honoured_size(16, ours), 16);
    assert_eq!(honoured_size(ours as u32, ours), ours as u32);
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

/// The sized-field guard must be safe to point at a peer buffer that is SHORTER than the struct it
/// describes. Reading through a reference cannot be: a `&Pod` asserts the whole struct is valid and
/// dereferenceable the instant it is formed, which over a shorter peer buffer is a claim about memory
/// that does not exist. The pointer form makes the advertised size the only thing consulted, and
/// touches nothing past it.
#[test]
fn sized_field_guard_reads_a_buffer_shorter_than_the_struct() {
    // A peer that advertises only the prefix before `tail_ptr`, in a buffer that is only that long —
    // there are no bytes at all where `tail_ptr`/`tail_len` would sit.
    const PREFIX: usize = core::mem::offset_of!(Pod, tail_ptr);
    // Deliberately a HEAP buffer, not the array clippy would prefer: the point of the test is that
    // the allocation ENDS at `PREFIX`, so a read past it is a real out-of-bounds access that Miri or
    // ASan will flag. A stack array is surrounded by other live stack bytes and would swallow it.
    #[allow(clippy::useless_vec)]
    let mut buf = vec![0u8; PREFIX];
    buf[..4].copy_from_slice(&(PREFIX as u32).to_ne_bytes());
    let p = buf.as_ptr().cast::<Pod>();

    // `p` addresses `PREFIX` live bytes whose leading `size` says exactly that; the guard reads
    // nothing beyond it.
    assert_eq!(read_sized_field!(p, PREFIX as u32, Pod, tail_ptr), None);
    assert_eq!(read_sized_field!(p, PREFIX as u32, Pod, tail_len), None);
    // A field inside the prefix still reads.
    assert_eq!(read_sized_field!(p, PREFIX as u32, Pod, tokens), Some(0));
}

/// THE AUTH TAIL'S FACT BITS are distinct single bits, the default inbound style among them (row
/// 159, K3#1: the host's default inbound style is a stated fact, so the kernel names no line).
#[test]
fn the_auth_fact_bits_are_distinct_and_name_the_default_inbound_style() {
    use crate::abi::auth::{
        FACT_CACHEABLE, FACT_DEFAULT_INBOUND_STYLE, FACT_INBOUND_ALL_HEADERS,
        FACT_INBOUND_NEEDS_BODY_HASH, FACT_OPERATOR, FACT_READS_CREDENTIALS,
    };
    let bits = [
        FACT_CACHEABLE,
        FACT_INBOUND_NEEDS_BODY_HASH,
        FACT_INBOUND_ALL_HEADERS,
        FACT_OPERATOR,
        FACT_READS_CREDENTIALS,
        FACT_DEFAULT_INBOUND_STYLE,
    ];
    let mut seen = 0u32;
    for bit in bits {
        assert_eq!(bit.count_ones(), 1, "fact {bit:#x} is one bit");
        assert_eq!(seen & bit, 0, "fact {bit:#x} is distinct");
        seen |= bit;
    }
    assert_eq!(FACT_DEFAULT_INBOUND_STYLE, 32);
}
