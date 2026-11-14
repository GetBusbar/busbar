// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use zeroize::Zeroize as _;

/// `wipe_bytes` zeroes the WHOLE allocation, initialized length and spare capacity alike, at every
/// alignment of the region's start and end, and leaves the buffer empty but allocated.
#[test]
fn wipe_bytes_zeroes_every_byte_of_the_allocation() {
    for cap in [0usize, 1, 7, 8, 9, 63, 4096, 4099] {
        for len in [0, cap / 2, cap] {
            let mut bytes = Vec::with_capacity(cap);
            bytes.resize(cap, 0xA5u8);
            bytes.truncate(len);
            let (ptr, capacity) = (bytes.as_ptr(), bytes.capacity());
            wipe_bytes(&mut bytes);
            assert!(bytes.is_empty());
            assert_eq!((bytes.as_ptr(), bytes.capacity()), (ptr, capacity));
            // SAFETY: every byte of the capacity was written (0xA5, then zero) above.
            let all = unsafe { std::slice::from_raw_parts(bytes.as_ptr(), capacity) };
            assert!(all.iter().all(|b| *b == 0), "cap {cap} len {len}");
        }
    }
    for offset in 0..9 {
        let mut region = [core::mem::MaybeUninit::new(0x5Au8); 40];
        wipe_spare(&mut region[offset..offset + 21]);
        // SAFETY: every element was initialized above.
        let bytes: Vec<u8> = region.iter().map(|b| unsafe { b.assume_init() }).collect();
        assert!(bytes[..offset].iter().all(|b| *b == 0x5A));
        assert!(bytes[offset..offset + 21].iter().all(|b| *b == 0));
        assert!(bytes[offset + 21..].iter().all(|b| *b == 0x5A));
    }
}

#[test]
fn wiped_bytes_wipes_on_zeroize_and_derefs_to_its_vec() {
    let mut held = WipedBytes::new(vec![7u8; 100]);
    held[3] = 9;
    assert_eq!(held.len(), 100);
    let capacity = held.capacity();
    held.zeroize();
    assert!(held.is_empty());
    // SAFETY: the capacity was fully initialized and then wiped.
    let all = unsafe { std::slice::from_raw_parts(held.as_ptr(), capacity) };
    assert!(all.iter().all(|b| *b == 0));
}
