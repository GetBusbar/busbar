// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn an_envelope_array_misaligned_for_its_entries_is_a_bad_array() {
    let entry = size_of::<Diag>().max(size_of::<MetricEntry>());
    let buf = vec![0_u64; entry.div_ceil(8) + 2];
    let at = buf.as_ptr().cast::<u8>().wrapping_add(1).cast::<Diag>();
    assert!(!at.is_aligned());
    // SAFETY: a range that passed the checks would name zeroed bytes inside `buf`.
    assert!(
        unsafe { array(at, 1) }.is_none(),
        "a misaligned array is refused before it is formed"
    );
    let metrics = buf
        .as_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<MetricEntry>();
    // SAFETY: as above.
    assert!(unsafe { array(metrics, 1) }.is_none());

    let diags = [Diag::ZERO];
    // SAFETY: `diags` holds one live `Diag`.
    let read = unsafe { array(diags.as_ptr(), diags.len()) };
    assert_eq!(read.map(<[Diag]>::len), Some(1));
    drop(buf);
}
