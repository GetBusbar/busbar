// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's zeroizing byte holder a secret plugin's `resolve` writes into (the credential chip,
//! row 6: host-owned secret bytes): its type-level guarantees, and that keeping and converting it
//! never copies the value. Here, beside the secret ABI, because a test writes the lent buffer as a
//! plugin would (raw pointer, the ABI module's `unsafe`).

use crate::plugin::TestKernelSeal;
use crate::redacted::{NotText, Secret};

/// TYPE LEVEL: the holder the loader and kernel keep resolved bytes in wipes itself on drop
/// (`ZeroizeOnDrop`), and so does its text form; neither formats its value.
#[test]
fn the_byte_holder_is_zeroize_on_drop_and_prints_nothing() {
    fn zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    zeroize_on_drop::<Secret<Vec<u8>>>();
    zeroize_on_drop::<Secret<String>>();
    let mut held = Secret::<Vec<u8>>::zeroed(8);
    let (p, cap) = held.lend_mut();
    assert_eq!(cap, 8);
    // SAFETY: `p` is the holder's own buffer of `cap` bytes; this test is the plugin writing it.
    unsafe { std::ptr::copy_nonoverlapping(b"hunter2".as_ptr(), p, 7) };
    held.keep(7);
    assert_eq!(format!("{held:?}"), "[REDACTED]");
    assert_eq!(format!("{held}"), "[REDACTED]");
    assert_eq!(held.expose(&TestKernelSeal), b"hunter2");
}

/// The holder a host lends a plugin starts zeroed, and `keep` wipes what lies past the value
/// in place: nothing the plugin wrote beyond it survives, and nothing is reallocated (copied).
#[test]
fn keep_wipes_the_tail_in_place() {
    let mut held = Secret::<Vec<u8>>::zeroed(6);
    let (p, _) = held.lend_mut();
    // SAFETY: as above.
    unsafe { std::ptr::copy_nonoverlapping(b"abcdef".as_ptr(), p, 6) };
    held.keep(3);
    let v = held.expose(&TestKernelSeal);
    assert_eq!(v.as_slice(), b"abc");
    assert_eq!(v.as_ptr(), p, "kept in place: the same allocation");
    // SAFETY: the tail is the same live allocation's spare capacity, read as bytes.
    let tail = unsafe { std::slice::from_raw_parts(p.add(3), 3) };
    assert_eq!(tail, [0, 0, 0], "the tail is wiped");
}

/// A text secret is the same bytes, MOVED into a `Secret<String>` (one allocation, never a
/// copy), its trailing newline trimmed in place; non-UTF-8 and an empty value are refused.
#[test]
fn into_text_moves_and_trims() {
    let mut held = Secret::<Vec<u8>>::zeroed(8);
    let (p, _) = held.lend_mut();
    // SAFETY: as above.
    unsafe { std::ptr::copy_nonoverlapping(b"tok\r\n".as_ptr(), p, 5) };
    held.keep(5);
    let text = held.into_text().expect("text");
    let s = text.expose(&TestKernelSeal);
    assert_eq!(s, "tok");
    assert_eq!(s.as_ptr(), p.cast_const(), "moved, not copied");
    assert_eq!(
        Secret::new(vec![0xff, 0xfe]).into_text().err(),
        Some(NotText::NotUtf8)
    );
    assert_eq!(
        Secret::new(b"\n".to_vec()).into_text().err(),
        Some(NotText::Empty)
    );
}
