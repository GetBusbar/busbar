// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MUTATION-HARDENING for the dialect-neutral TAIL-USAGE ISOLATION (`crate::usage_tail`) — the
//! byte-scan every reader's `recover_truncated_usage` runs when a same-protocol non-stream billing
//! buffer was HEAD-truncated at `max_translated_body_bytes()`.
//!
//! WHY THIS FILE EXISTS. This scan is the only thing standing between a truncated 200 and a bill of
//! ZERO: its two guards (`find_last`'s length precondition and `balanced_object_after`'s
//! whitespace-skip) decide whether the usage object is found at all. A mutation run over
//! `src/usage_tail.rs` left both of those comparisons ALIVE — no test in the suite could tell
//! `hay.len() < needle.len()` from `==`, and none fed a body with whitespace around the `usage`
//! key's colon. A surviving mutant there is a silently unbilled request, so the guards get direct
//! tests here.
//!
//! SPEC ANCHOR. The JSON forms exercised here are the ones the PINNED provider specifications
//! recorded in `testing/llm-conformance/spec-digests.tsv` permit — in particular the Cohere v2
//! OpenAPI document pinned there (row `cohere`, digest `6f64ec87…`), which types every count in
//! `Usage` — `tokens.input_tokens`, `tokens.output_tokens` and the whole `billed_units` bucket — as
//! `type: number` rather than `integer`, so a JSON *double* is a spec-valid way to report a token
//! count. Whitespace around a `:` is permitted by JSON itself (RFC 8259), which every one of the
//! six pinned specs is written in terms of.

use super::*;

/// The keys the six readers pass in (`"usage"` for five dialects, `"usageMetadata"` for Gemini).
const USAGE_KEY: &[u8] = b"\"usage\"";
const GEMINI_USAGE_KEY: &[u8] = b"\"usageMetadata\"";

/// A retained tail SHORTER than the key being searched for must answer `None` — the scan may never
/// index past the buffer while computing its search range.
///
/// This is the degenerate-but-reachable case: `max_translated_body_bytes()` is a byte cap, and a
/// pathologically small cap (or a body whose retained tail is a handful of bytes) hands this scan a
/// slice shorter than the 15-byte `"usageMetadata"` key. The length precondition is what keeps the
/// range arithmetic in bounds; without it the `hay.len() - needle.len()` below it underflows.
#[test]
fn tail_shorter_than_the_usage_key_is_no_usage_and_never_indexes_out_of_range() {
    let fixtures: &[(&[u8], &[u8])] = &[
        (&b""[..], USAGE_KEY),
        (&b"{"[..], USAGE_KEY),
        (&b"}"[..], USAGE_KEY),
        (&b"\"usa"[..], USAGE_KEY),
        (&b""[..], GEMINI_USAGE_KEY),
        (&b"\"usa"[..], GEMINI_USAGE_KEY),
        (&b"\"usageMeta"[..], GEMINI_USAGE_KEY),
        (&b"\"usageMetadata"[..], GEMINI_USAGE_KEY),
    ];
    for &(tail, key) in fixtures {
        {
            assert!(
                tail.len() < key.len(),
                "fixture must be shorter than the key it is searched with"
            );
            assert_eq!(
                usage_tail::isolate_tail_usage_object(tail, key),
                None,
                "a tail shorter than the usage key carries no usage object"
            );
        }
    }
}

/// A tail whose ONLY content is the bare key (equal length, no `:` and no object after it) is also
/// "no usage object" — the boundary case immediately above the short-tail guard, pinned so the
/// precondition cannot be widened into `<=` without a test noticing the scan stops one byte early.
#[test]
fn tail_that_is_exactly_the_usage_key_carries_no_object() {
    assert_eq!(
        usage_tail::isolate_tail_usage_object(USAGE_KEY, USAGE_KEY),
        None
    );
    assert_eq!(
        usage_tail::isolate_tail_usage_object(GEMINI_USAGE_KEY, GEMINI_USAGE_KEY),
        None
    );
}

/// WHITESPACE AROUND THE COLON. JSON (RFC 8259) allows any amount of whitespace between a member's
/// name and its value, and a pretty-printed provider body — or any upstream/proxy that
/// re-serializes with an indenting encoder — puts it there. The scan must skip it on BOTH sides of
/// the `:` and still isolate the usage object; a scan that only accepts `"usage":{` bills a
/// pretty-printed truncated body ZERO.
#[test]
fn whitespace_around_the_colon_still_isolates_the_usage_object() {
    // Every whitespace form JSON permits between the key, the `:` and the `{`.
    for sep in [
        &b":"[..],
        &b" :"[..],
        &b": "[..],
        &b" : "[..],
        &b"\n  :\n  "[..],
        &b"\t:\t"[..],
        &b"\r\n:\r\n"[..],
    ] {
        let mut tail: Vec<u8> = b"assistant\"}],\"usage\"".to_vec();
        tail.extend_from_slice(sep);
        tail.extend_from_slice(br#"{"input_tokens":11,"output_tokens":7}}"#);
        let v = usage_tail::isolate_tail_usage_object(&tail, USAGE_KEY)
            .expect("a pretty-printed usage member is still a usage object");
        assert_eq!(v.get("input_tokens").and_then(|t| t.as_u64()), Some(11));
        assert_eq!(v.get("output_tokens").and_then(|t| t.as_u64()), Some(7));
    }
}

/// A `usage` key with NO value after it (the truncation cut between the key and its object) is
/// `None`, not a fabricated empty usage — "bill zero, counted+warned" is the caller's documented
/// handling, and it must be reached rather than a zero silently manufactured here.
#[test]
fn usage_key_without_a_following_object_is_none() {
    assert_eq!(
        usage_tail::isolate_tail_usage_object(b"...,\"usage\"", USAGE_KEY),
        None
    );
    assert_eq!(
        usage_tail::isolate_tail_usage_object(b"...,\"usage\":", USAGE_KEY),
        None
    );
    assert_eq!(
        usage_tail::isolate_tail_usage_object(b"...,\"usage\": ", USAGE_KEY),
        None
    );
    // A non-object value is not a usage object either.
    assert_eq!(
        usage_tail::isolate_tail_usage_object(b"...,\"usage\":null", USAGE_KEY),
        None
    );
    assert_eq!(
        usage_tail::isolate_tail_usage_object(b"...,\"usage\":11", USAGE_KEY),
        None
    );
    // An object the truncation cut off mid-way never closes, so it is not isolatable.
    assert_eq!(
        usage_tail::isolate_tail_usage_object(b"...,\"usage\":{\"input_tokens\":1", USAGE_KEY),
        None
    );
}

/// THE LAST occurrence wins. The word `usage` can appear inside DELIVERED ASSISTANT TEXT, and the
/// real usage object is always at the tail; anchoring on an earlier occurrence would parse the
/// model's prose as a bill.
#[test]
fn the_trailing_usage_object_wins_over_one_quoted_in_content() {
    let tail = br#"text":"see \"usage\":{\"input_tokens\":999999} in the docs"}],"usage":{"input_tokens":11,"output_tokens":7}}"#;
    let v = usage_tail::isolate_tail_usage_object(tail, USAGE_KEY)
        .expect("the trailing usage object is isolatable");
    assert_eq!(
        v.get("input_tokens").and_then(|t| t.as_u64()),
        Some(11),
        "the LAST usage key is the billing one; an earlier one quoted in content must not win"
    );
}

/// The bracket match is STRING- and ESCAPE-AWARE: a `}` inside a quoted string value (Anthropic's
/// `usage.service_tier` is a string member of `Usage` in the pinned Anthropic OpenAPI document,
/// `testing/llm-conformance/spec-digests.tsv` row `anthropic`, digest `d1d189d7…`) must not close
/// the object early and truncate the counts that follow it.
#[test]
fn a_brace_inside_a_string_value_does_not_close_the_usage_object() {
    let tail = br#"}],"usage":{"service_tier":"stan}dard","input_tokens":11,"output_tokens":7}}"#;
    let v = usage_tail::isolate_tail_usage_object(tail, USAGE_KEY).expect("isolatable");
    assert_eq!(v.get("input_tokens").and_then(|t| t.as_u64()), Some(11));
    assert_eq!(v.get("output_tokens").and_then(|t| t.as_u64()), Some(7));
    assert_eq!(
        v.get("service_tier").and_then(|t| t.as_str()),
        Some("stan}dard")
    );

    // An ESCAPED quote inside that string keeps the scanner inside the string.
    let tail = br#"}],"usage":{"service_tier":"a\"}b","input_tokens":12,"output_tokens":8}}"#;
    let v = usage_tail::isolate_tail_usage_object(tail, USAGE_KEY).expect("isolatable");
    assert_eq!(v.get("input_tokens").and_then(|t| t.as_u64()), Some(12));
    assert_eq!(v.get("output_tokens").and_then(|t| t.as_u64()), Some(8));

    // A trailing BACKSLASH inside the string (an escaped backslash, so the following quote really
    // does close the string) still ends the object where JSON says it does.
    let tail = br#"}],"usage":{"service_tier":"back\\","input_tokens":13,"output_tokens":9}}"#;
    let v = usage_tail::isolate_tail_usage_object(tail, USAGE_KEY).expect("isolatable");
    assert_eq!(v.get("input_tokens").and_then(|t| t.as_u64()), Some(13));
    assert_eq!(v.get("output_tokens").and_then(|t| t.as_u64()), Some(9));
}

/// NESTED sub-objects (every dialect's usage carries them: Anthropic `cache_creation`, OpenAI
/// `prompt_tokens_details`, Cohere `billed_units`, Responses `input_tokens_details`) are matched to
/// the OUTER closing brace, so the nested counts survive and the object does not end at the first
/// inner `}`.
#[test]
fn nested_usage_sub_objects_are_matched_to_the_outer_brace() {
    let tail = br#"}],"usage":{"billed_units":{"input_tokens":120,"output_tokens":50,"search_units":3},"tokens":{"input_tokens":100,"output_tokens":40}}}"#;
    let v = usage_tail::isolate_tail_usage_object(tail, USAGE_KEY).expect("isolatable");
    assert_eq!(
        v.get("billed_units")
            .and_then(|b| b.get("search_units"))
            .and_then(|t| t.as_u64()),
        Some(3),
    );
    assert_eq!(
        v.get("tokens")
            .and_then(|b| b.get("output_tokens"))
            .and_then(|t| t.as_u64()),
        Some(40),
        "the isolated span must reach the OUTER closing brace, not the first inner one"
    );
}

/// Gemini's key is `usageMetadata`, and the scan must not confuse it with the five dialects'
/// `usage` (nor match the `usage` PREFIX inside `usageMetadata`).
#[test]
fn the_gemini_usage_metadata_key_is_matched_whole() {
    let tail = br#"}],"usageMetadata":{"promptTokenCount":15,"candidatesTokenCount":4,"totalTokenCount":19}}"#;
    let v = usage_tail::isolate_tail_usage_object(tail, GEMINI_USAGE_KEY).expect("isolatable");
    assert_eq!(v.get("promptTokenCount").and_then(|t| t.as_u64()), Some(15));
    // The five-dialect key is a PREFIX of Gemini's, and `"usage"` (with its closing quote) is not
    // present in this body at all — so a Gemini body searched with the plain key finds nothing.
    assert_eq!(usage_tail::isolate_tail_usage_object(tail, USAGE_KEY), None);
}

// ── `token_count`: the double-tolerant reader ───────────────────────────────────────────────────

/// An INTEGER count reads exactly as it always did.
#[test]
fn token_count_reads_an_integer_unchanged() {
    for n in [0u64, 1, 11, 4096, u64::MAX] {
        assert_eq!(
            usage_tail::token_count(&serde_json::json!(n)),
            Some(n),
            "an integer token count is itself"
        );
    }
}

/// A count the provider's spec types as `number` (the pinned Cohere v2 document,
/// `testing/llm-conformance/spec-digests.tsv` row `cohere`, digest `6f64ec87…`, types every `Usage`
/// count that way) arrives as a JSON DOUBLE. `11.0` is ELEVEN tokens — reading it with an
/// integer-only accessor answers `None` and ledgers a real, billed count as ZERO.
#[test]
fn token_count_reads_a_spec_valid_double_as_the_count_it_states() {
    let f: f64 = 11.0;
    assert_eq!(usage_tail::token_count(&serde_json::json!(f)), Some(11));
    assert_eq!(
        usage_tail::token_count(&serde_json::json!(0.0_f64)),
        Some(0)
    );
    assert_eq!(
        usage_tail::token_count(&serde_json::json!(4096.0_f64)),
        Some(4096)
    );
}

/// A NON-INTEGRAL double rounds UP: a partially-consumed billing unit is still a whole unit
/// charged, and this reader must never bill LESS than the provider reported.
#[test]
fn token_count_rounds_a_fractional_count_up_never_down() {
    assert_eq!(
        usage_tail::token_count(&serde_json::json!(0.1_f64)),
        Some(1)
    );
    assert_eq!(
        usage_tail::token_count(&serde_json::json!(10.000_1_f64)),
        Some(11)
    );
    assert_eq!(
        usage_tail::token_count(&serde_json::json!(10.999_f64)),
        Some(11)
    );
}

/// A value that is NOT a token count stays `None` rather than saturating into a fabricated one: a
/// negative count, a non-finite one, one beyond `u64`, and a non-numeric JSON value. `None` reaches
/// the reader's documented "absent" handling; a fabricated number would be an invented bill.
#[test]
fn token_count_refuses_values_that_are_not_token_counts() {
    for v in [
        serde_json::json!(-1.0_f64),
        serde_json::json!(-0.5_f64),
        serde_json::json!(f64::NAN),
        serde_json::json!(f64::INFINITY),
        serde_json::json!(f64::NEG_INFINITY),
        // Beyond the u64 range: `2^64` exactly, and a value far above it.
        serde_json::json!(18_446_744_073_709_551_616.0_f64),
        serde_json::json!(1.0e30_f64),
        serde_json::json!("11"),
        serde_json::json!(null),
        serde_json::json!({"input_tokens": 11}),
        serde_json::json!([11]),
        serde_json::json!(true),
    ] {
        assert_eq!(
            usage_tail::token_count(&v),
            None,
            "{v} is not a token count and must not be turned into one"
        );
    }
    // `-0.0` is not a negative count — it is zero — and must not be refused.
    assert_eq!(
        usage_tail::token_count(&serde_json::json!(-0.0_f64)),
        Some(0)
    );
}

/// A NEGATIVE integer (a `serde_json` `i64`) is likewise not a token count. It reaches the `f64`
/// arm, whose sign check must hold: a wrapped/saturated `u64` here would be an astronomically
/// wrong bill.
#[test]
fn token_count_refuses_a_negative_integer() {
    assert_eq!(usage_tail::token_count(&serde_json::json!(-1_i64)), None);
    assert_eq!(
        usage_tail::token_count(&serde_json::json!(i64::MIN)),
        None,
        "a negative count must not wrap into a u64"
    );
}
