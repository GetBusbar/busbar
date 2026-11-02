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
    assert_eq!(core::mem::offset_of!(AbiPreamble, magic), 0);
    assert_eq!(core::mem::offset_of!(AbiPreamble, abi_major), 8);
    assert_eq!(core::mem::offset_of!(AbiPreamble, abi_minor), 12);
    assert_eq!(core::mem::size_of::<AbiPreamble>(), 16);
}

#[test]
fn sized_field_guard_hides_truncated_tail() {
    let g = Pod::whole();
    // A full-size struct reveals a tail field.
    // SAFETY: `g` is a live initialized whole `Pod` and its scalar field is `Copy`.
    assert_eq!(
        unsafe { read_sized_field!(&g, g.size, Pod, flags) },
        Some(0)
    );

    let mut truncated = g;

    truncated.size = 6;
    // SAFETY: the whole initialized `Pod` also covers the shorter advertised prefix.
    assert_eq!(
        unsafe { read_sized_field!(&truncated, truncated.size, Pod, flags) },
        None
    );
}

/// A peer's attested size is CLAMPED to this build's struct: an over-claim never widens the read
#[test]
fn an_over_large_attested_size_is_clamped_to_this_builds_struct() {
    let ours = core::mem::size_of::<Pod>();
    assert_eq!(honoured_size(u32::MAX, ours), ours as u32);
    assert_eq!(honoured_size(ours as u32 + 1, ours), ours as u32);

    assert_eq!(honoured_size(16, ours), 16);
    assert_eq!(honoured_size(ours as u32, ours), ours as u32);
}

/// The sized-field guard must be safe to point at a peer buffer that is SHORTER than the struct it
#[test]
fn sized_field_guard_reads_a_buffer_shorter_than_the_struct() {
    const PREFIX: usize = core::mem::offset_of!(Pod, tail_ptr);

    #[allow(clippy::useless_vec)]
    let mut buf = vec![0u8; PREFIX];
    buf[..4].copy_from_slice(&(PREFIX as u32).to_ne_bytes());
    let p = buf.as_ptr().cast::<Pod>();

    assert_eq!(
        unsafe { read_sized_field!(p, PREFIX as u32, Pod, tail_ptr) },
        None
    );
    assert_eq!(
        unsafe { read_sized_field!(p, PREFIX as u32, Pod, tail_len) },
        None
    );

    assert_eq!(
        unsafe { read_sized_field!(p, PREFIX as u32, Pod, tokens) },
        Some(0)
    );
}

/// THE AUTH TAIL'S FACT BITS are distinct single bits, the default inbound style among them (row
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
