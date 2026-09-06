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

/// The DETAIL sub-buckets ride the same Some-wins rule: a trailing chunk's `Some` overrides, a
/// trailing `None` never clobbers a detail the terminal delta already carried. (The fold used to
/// merge only the four totals — the reasoning attribution went to zero on every streamed
/// cross-protocol reasoning call while the buffered twin carried it.)
#[test]
fn trailing_detail_sub_buckets_merge_some_wins() {
    let detail = |r: Option<u64>, c5: Option<u64>, c1: Option<u64>, s: Option<u64>| {
        crate::ir::IrUsageDetail {
            reasoning_tokens: r,
            cache_creation_5m_input_tokens: c5,
            cache_creation_1h_input_tokens: c1,
            search_units: s,
            // ADDITIVE per-dialect usage-attribution fields (anthropic web_search_requests/
            // service_tier, openai audio/prediction sub-buckets, gemini tool_use_prompt_tokens,
            // cohere billed_* buckets, and the other dialect carriers) default here — this fold
            // exercises the four reasoning/cache/search sub-buckets only.
            ..Default::default()
        }
    };
    // Trailing Some fills a zeroed terminal.
    let mut acc = usage(0, 0, None, None);
    let mut trailing = usage(120, 45, None, None);
    trailing.detail = detail(Some(9), Some(10), Some(20), Some(2));
    merge_trailing_usage(&mut acc, &trailing);
    assert_eq!(acc.detail.reasoning_tokens, Some(9));
    assert_eq!(acc.detail.cache_creation_5m_input_tokens, Some(10));
    assert_eq!(acc.detail.cache_creation_1h_input_tokens, Some(20));
    assert_eq!(acc.detail.search_units, Some(2));

    // A trailing chunk with no detail leaves an already-carried detail intact.
    let mut acc = usage(200, 80, None, None);
    acc.detail = detail(Some(7), Some(1), Some(2), Some(3));
    merge_trailing_usage(&mut acc, &usage(0, 0, None, None));
    assert_eq!(acc.detail.reasoning_tokens, Some(7), "None never clobbers");
    assert_eq!(acc.detail.cache_creation_5m_input_tokens, Some(1));
    assert_eq!(acc.detail.cache_creation_1h_input_tokens, Some(2));
    assert_eq!(acc.detail.search_units, Some(3));
}

/// EVERY `IrUsageDetail` bucket rides the Some-wins fold, not just the handful that had a bug filed
/// against them. The fold is written as a no-`..` destructure of the detail struct precisely so a
/// future field cannot be added without landing here; this test pins the current full census so a
/// silently-dropped bucket is a red test rather than an attribution hole a customer finds on a bill.
#[test]
fn trailing_detail_merge_is_exhaustive_over_every_bucket() {
    let full = crate::ir::IrUsageDetail {
        reasoning_tokens: Some(1),
        cache_creation_5m_input_tokens: Some(2),
        cache_creation_1h_input_tokens: Some(3),
        search_units: Some(4),
        web_search_requests: Some(5),
        service_tier: Some("priority".to_string()),
        input_audio_tokens: Some(6),
        output_audio_tokens: Some(7),
        accepted_prediction_tokens: Some(8),
        rejected_prediction_tokens: Some(9),
        tool_use_prompt_tokens: Some(10),
        billed_input_tokens: Some(11),
        billed_output_tokens: Some(12),
        billed_classifications: Some(13),
    };
    let mut acc = usage(0, 0, None, None);
    let mut trailing = usage(50, 20, None, None);
    trailing.detail = full.clone();
    merge_trailing_usage(&mut acc, &trailing);
    assert_eq!(
        acc.detail, full,
        "every trailing detail bucket must land on the accumulator"
    );

    // The mirror direction: a trailing chunk with NO detail never clobbers what the accumulator
    // already carried, for every bucket.
    let mut acc = usage(50, 20, None, None);
    acc.detail = full.clone();
    merge_trailing_usage(&mut acc, &usage(0, 0, None, None));
    assert_eq!(
        acc.detail, full,
        "an empty trailing detail must clobber no bucket"
    );
}
