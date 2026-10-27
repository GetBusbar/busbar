// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The observability envelope's arrays are formed only through the one capped, validated reader.

use super::*;

/// AN ENVELOPE ARRAY IS FORMED ONLY THROUGH THE ONE CAPPED, VALIDATED READER (THE DESIGN
/// `docs/design/BUSBAR-1.6.0.md` §11.13 M1: "Every slice built from a plugin-reported length is
/// capped and validated before it is formed"). A metrics, diagnostics or label-values array whose
/// pointer is not aligned for its entries is a bad array, dropped and never read; an aligned one
/// reads as it stands. RED before `array` went through `validate::lent`: only NULL and the entry
/// count were checked, so a misaligned plugin pointer was formed into a slice (undefined
/// behaviour; std's precondition check aborts the test process).
#[test]
fn an_envelope_array_misaligned_for_its_entries_is_a_bad_array() {
    // Zeroed bytes hold one entry of either kind, one byte past an aligned start.
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
    // The GREEN twin: an aligned array reads.
    let diags = [Diag::ZERO];
    // SAFETY: `diags` holds one live `Diag`.
    let read = unsafe { array(diags.as_ptr(), diags.len()) };
    assert_eq!(read.map(<[Diag]>::len), Some(1));
    drop(buf);
}
