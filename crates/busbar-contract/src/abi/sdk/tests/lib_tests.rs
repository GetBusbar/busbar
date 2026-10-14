// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract/src/abi/sdk/mod.rs` (the former `busbar-plugin-sdk`).

use super::*;
use crate::abi::cold::STATUS_OK;
use std::ptr;

/// `OutBuf::commit` (the successor to `write_buf`) with a null `out` must DROP the owned `Vec`, not
/// leak it: the alloc (`into_boxed_slice`/`Box::into_raw`) lives INSIDE the non-null branch, so the
/// null path never realizes a raw box — the leak is made structurally impossible. `out_len` is left
/// untouched; a non-null slot returns a freeable (ptr, len) pair. Under Miri/ASan this flags the
/// leak the old ordering caused.
#[test]
fn outbuf_commit_null_out_drops_without_leaking_or_writing() {
    unsafe {
        // Null `out`: nothing is written, `out_len` is left untouched, no crash (Vec dropped).
        let mut len_slot: usize = 0xDEAD;
        boundary::OutBuf::new(vec![1u8, 2, 3]).commit(STATUS_OK, ptr::null_mut(), &mut len_slot);
        assert_eq!(
            len_slot, 0xDEAD,
            "out_len must be untouched when out is null"
        );

        // Non-null `out`: the (ptr, len) pair is returned and is freeable (round-trip through
        // free_boundary proves the allocation is intact and owned by the same allocator).
        let mut ptr_slot: *mut u8 = ptr::null_mut();
        let mut len2: usize = 0;
        boundary::OutBuf::new(vec![7u8, 8, 9, 10]).commit(STATUS_OK, &mut ptr_slot, &mut len2);
        assert!(!ptr_slot.is_null());
        assert_eq!(len2, 4);
        assert_eq!(std::slice::from_raw_parts(ptr_slot, len2), &[7, 8, 9, 10]);
        boundary::free_boundary(ptr_slot, len2);
    }
}
