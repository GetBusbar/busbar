// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/proto/stream.rs`.

use super::merge_trailing_usage;
use crate::ir::IrUsage;

fn usage(i: u64, o: u64, cc: Option<u64>, cr: Option<u64>) -> IrUsage {
    IrUsage {
        input_tokens: i,
        output_tokens: o,
        cache_creation_input_tokens: cc,
        cache_read_input_tokens: cr,
        detail: crate::ir::IrUsageDetail::default(),
    }
}

// 1.4.0 (streaming-billing): the terminal-usage fold merges a trailing usage-only chunk into
// the deferred terminal delta. A non-zero/Some trailing field OVERRIDES; a zero/None trailing field
// LEAVES the accumulator intact so a protocol that already carried usage on its terminal delta is
// never clobbered by an absent trailing chunk. (Billing reads the merged accumulator.)
#[test]
fn trailing_nonzero_overrides_zero_leaves_intact() {
    // A terminal delta that carried zeros gets the real counts from the trailing usage chunk.
    let mut acc = usage(0, 0, None, None);
    merge_trailing_usage(&mut acc, &usage(120, 45, Some(7), Some(9)));
    assert_eq!((acc.input_tokens, acc.output_tokens), (120, 45));
    assert_eq!(acc.cache_creation_input_tokens, Some(7));
    assert_eq!(acc.cache_read_input_tokens, Some(9));

    // A terminal delta that ALREADY carried usage is NOT clobbered by an absent/zero trailing chunk.
    let mut acc = usage(200, 80, Some(3), Some(5));
    merge_trailing_usage(&mut acc, &usage(0, 0, None, None));
    assert_eq!((acc.input_tokens, acc.output_tokens), (200, 80));
    assert_eq!(acc.cache_creation_input_tokens, Some(3));
    assert_eq!(acc.cache_read_input_tokens, Some(5));

    // Field-by-field: only the non-zero/Some trailing fields win; the rest are preserved.
    let mut acc = usage(200, 0, Some(3), None);
    merge_trailing_usage(&mut acc, &usage(0, 90, None, Some(11)));
    assert_eq!(
        acc.input_tokens, 200,
        "zero trailing input preserves the accumulator"
    );
    assert_eq!(acc.output_tokens, 90, "non-zero trailing output overrides");
    assert_eq!(
        acc.cache_creation_input_tokens,
        Some(3),
        "None trailing preserves Some"
    );
    assert_eq!(
        acc.cache_read_input_tokens,
        Some(11),
        "Some trailing overrides None"
    );
}
