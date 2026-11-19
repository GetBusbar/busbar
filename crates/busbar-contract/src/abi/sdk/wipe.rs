// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Wiping byte buffers: the whole allocation is zeroed with volatile stores before it is freed.

/// Wipe every byte of `bytes`' allocation, its whole capacity as `Zeroize for Vec<u8>` does, and
/// leave it empty. The same guarantee (volatile zero stores the compiler may not elide, then a
/// fence), stored a word at a time: `Vec<u8>`'s own `zeroize` stores and fences byte by byte,
/// which is what a 4 KiB per-call output buffer spends most of its life on.
pub fn wipe_bytes(bytes: &mut Vec<u8>) {
    bytes.clear();
    wipe_spare(bytes.spare_capacity_mut());
}

fn wipe_spare(spare: &mut [core::mem::MaybeUninit<u8>]) {
    use core::mem::MaybeUninit;
    // SAFETY: `MaybeUninit<u8>` and `MaybeUninit<u64>` carry no validity invariant, so viewing the
    // aligned middle of the region as words is sound; `align_to_mut` puts every byte in exactly
    // one of the three parts and borrows the region exclusively.
    let (head, words, tail) = unsafe { spare.align_to_mut::<MaybeUninit<u64>>() };
    for byte in head.iter_mut().chain(tail.iter_mut()) {
        // SAFETY: an exclusive, aligned reference into the live allocation.
        unsafe { core::ptr::write_volatile(byte, MaybeUninit::new(0)) };
    }
    for word in words {
        // SAFETY: an exclusive, aligned reference into the live allocation.
        unsafe { core::ptr::write_volatile(word, MaybeUninit::new(0)) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// A conditional plane request is secret in every instance: it wipes its candidate on drop.
impl Drop for super::plane::conditional::Request {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl zeroize::ZeroizeOnDrop for super::plane::conditional::Request {}
