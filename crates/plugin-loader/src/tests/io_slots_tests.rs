// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host I/O slots' reading of a caller's ranges (THE DESIGN §11.13 M1).

use super::*;

/// RED (THE DESIGN §11.13 M1, "Every slice built from a plugin-reported length is capped and
/// validated before it is formed"; audit PL1 #1): an I/O slot's list or buffer stated over the hard
/// byte maximum (`u32::MAX`) is refused before any slice is formed over it, as NULL with a count is.
#[test]
fn red_an_io_range_over_the_byte_cap_is_refused_before_any_slice() {
    let b = [0_u8; 8];
    let over = u32::MAX as usize + 1;
    // SAFETY: the range is refused before any slice is formed; nothing reads it.
    let formed = unsafe { list(b.as_ptr(), over) }.map(<[u8]>::len);
    assert_eq!(
        formed, None,
        "a range stated over the byte cap was formed into a slice"
    );
    // SAFETY: the test's own eight bytes.
    let within = unsafe { list(b.as_ptr(), b.len()) }.map(<[u8]>::len);
    assert_eq!(within, Some(8), "a range within the cap is the caller's");
    // SAFETY: NULL with a count is refused before anything is formed.
    assert!(unsafe { list::<u8>(std::ptr::null(), 1) }.is_none());
}
