// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `usage_count.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so the `use
//! super::…` below reaches the private items it always did.

use super::{billed_count, read_count_u64, SPELLING_BUDGET};
use serde_json::json;

#[test]
fn a_float_spelled_integer_is_the_integer() {
    // The exact defect: Cohere sends 27.0, `as_u64()` alone says None, and `unwrap_or(0)`
    // then bills zero for 27 tokens of real work.
    assert_eq!(read_count_u64(&json!(27.0)), Some(27));
    assert_eq!(
        json!(27.0).as_u64(),
        None,
        "the bare read this module replaces"
    );
}

#[test]
fn a_plain_integer_still_reads_directly() {
    assert_eq!(read_count_u64(&json!(27)), Some(27));
    assert_eq!(read_count_u64(&json!(0)), Some(0));
}

#[test]
fn a_fractional_count_is_refused_not_rounded() {
    // Rounding would invent a quantity the provider never reported.
    assert_eq!(read_count_u64(&json!(27.5)), None);
    assert_eq!(read_count_u64(&json!(0.5)), None);
}

#[test]
fn negatives_and_non_numbers_are_refused() {
    assert_eq!(read_count_u64(&json!(-1)), None);
    assert_eq!(read_count_u64(&json!(-1.0)), None);
    assert_eq!(read_count_u64(&json!("27")), None);
    assert_eq!(read_count_u64(&json!(null)), None);
    assert_eq!(read_count_u64(&json!({})), None);
}

#[test]
fn beyond_2_53_is_refused_because_the_fractional_test_goes_blind() {
    // Every f64 at or above 2^53 has fract() == 0.0, so admitting them would accept values
    // whose integrality was never actually verified.
    assert_eq!(read_count_u64(&json!(9_007_199_254_740_992.0_f64)), None);
    assert_eq!(read_count_u64(&json!(1.0e30_f64)), None);
    // But an integer-typed value that large is a real integer on the wire, not a float
    // guess, so the integer path still accepts it.
    assert_eq!(
        read_count_u64(&json!(9_007_199_254_740_993_u64)),
        Some(9_007_199_254_740_993)
    );
}

#[test]
fn infinities_and_nan_are_refused() {
    // serde_json cannot hold these natively, so build them through f64 conversion.
    let inf = serde_json::Number::from_f64(f64::INFINITY);
    assert!(
        inf.is_none(),
        "serde_json refuses non-finite numbers at construction"
    );
    assert_eq!(read_count_u64(&json!(f64::MAX)), None);
}

// ── `billed_count`: absent is zero, unreadable is a refusal (#81/#42) ──────────────────────

/// THE DEFECT, STATED AS THE DIFFERENCE BETWEEN THE TWO SEAMS.
///
/// This is the red-before-green in one assertion: the old idiom and the new one are handed the
/// SAME wire value, and the old one says "no work happened" while the new one refuses.
#[test]
fn an_unreadable_count_was_a_silent_zero_and_is_now_a_refusal() {
    let usage = json!({ "output_tokens": "27" });

    // THE OLD IDIOM, reproduced exactly: `None` from the seam, then a default of zero. A
    // provider sent us a count and the ledger recorded that it sent nothing.
    let old = usage
        .get("output_tokens")
        .and_then(read_count_u64)
        .unwrap_or(0);
    assert_eq!(
        old, 0,
        "the defect: a count that would not read billed ZERO"
    );

    // THE NEW SEAM: a refusal that names the field and quotes what arrived.
    let new = billed_count(&usage, "output_tokens");
    let err = new.expect_err("a count that will not read must refuse, never default");
    assert_eq!(err.field, "output_tokens");
    assert!(err.to_string().contains("output_tokens"), "{err}");
    assert!(
        err.to_string().contains("27"),
        "the refusal quotes what arrived: {err}"
    );
}

#[test]
fn an_absent_count_is_zero_and_stays_zero() {
    // Absence is a real fact and it really is worth zero: an embeddings response reports no
    // output tokens because there are none. This is the v1.5.5 behaviour and it does not move.
    let usage = json!({ "prompt_tokens": 27 });
    assert_eq!(billed_count(&usage, "completion_tokens"), Ok(0));
    assert_eq!(billed_count(&json!({}), "prompt_tokens"), Ok(0));
}

#[test]
fn a_null_count_reads_as_absent_not_as_a_refusal() {
    // `null` is how a provider spells "nothing here", and it must not fail a request that works
    // today. It is absence, not an unreadable value.
    let usage = json!({ "output_tokens": null });
    assert_eq!(billed_count(&usage, "output_tokens"), Ok(0));
}

#[test]
fn a_readable_count_is_the_count_however_it_was_spelled() {
    assert_eq!(billed_count(&json!({ "n": 27 }), "n"), Ok(27));
    // The float-spelled integer this module exists for.
    assert_eq!(billed_count(&json!({ "n": 27.0 }), "n"), Ok(27));
    assert_eq!(billed_count(&json!({ "n": 0 }), "n"), Ok(0));
}

#[test]
fn everything_that_is_not_a_count_refuses_rather_than_defaulting() {
    for bad in [
        json!({ "n": "27" }),
        json!({ "n": 27.5 }),
        json!({ "n": -1 }),
        json!({ "n": {} }),
        json!({ "n": [] }),
        json!({ "n": true }),
        json!({ "n": 1.0e30 }),
    ] {
        assert!(
            billed_count(&bad, "n").is_err(),
            "{bad} must refuse, not bill zero"
        );
    }
}

#[test]
fn a_hostile_spelling_cannot_write_an_essay_into_the_refusal() {
    let long = "x".repeat(10_000);
    let err = billed_count(&json!({ "n": long }), "n").expect_err("a string is not a count");
    assert!(
        err.spelling.chars().count() <= SPELLING_BUDGET + 1,
        "the quoted spelling is bounded, got {} chars",
        err.spelling.chars().count()
    );
}

/// NO DIALECT MAY REINTRODUCE THE BARE READ.
///
/// This is the regression that actually matters. Fixing the six dialects once does nothing for
/// the seventh: the defect was never a typo, it was the house idiom, so the next dialect added
/// reaches for `.as_u64().unwrap_or(0)` because that is what the neighbouring code looked like.
/// A count read that way is silently zero for any provider that spells it as a float, and a
/// zeroed ledger row is invisible downstream — every view over it is faithfully consistent and
/// faithfully wrong.
///
/// Scanning our own source is the cheap, durable guard, and this crate is the right place for
/// it: the rule is about THIS crate's dialects and nothing else. Comment lines are skipped so
/// the prose above (and the Bedrock writer's explanation of why its adds saturate) does not
/// trip the check that the prose describes.
#[test]
fn no_dialect_reads_a_count_with_the_bare_defaulting_idiom() {
    use std::path::Path;

    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                // A test's own fixture may spell a wire value any way it likes.
                if p.file_name().is_some_and(|n| n == "tests") {
                    continue;
                }
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && !p.file_name().is_some_and(|n| {
                    let n = n.to_string_lossy();
                    n.ends_with("_tests.rs") || n == "usage_count.rs"
                })
            {
                out.push(p);
            }
        }
    }

    let mut files = Vec::new();
    walk(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path(),
        &mut files,
    );
    assert!(
        files.len() > 20,
        "the scan found only {} source files, so it is not actually looking at the dialects",
        files.len()
    );

    let mut offenders = Vec::new();
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        // Join non-comment lines so the idiom is caught whether or not rustfmt split it.
        let code: String = text
            .lines()
            .map(|l| {
                let t = l.trim_start();
                if t.starts_with("//") {
                    ""
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        let flat: String = code.split_whitespace().collect::<Vec<_>>().join(" ");
        for bad in [
            "as_u64() . unwrap_or(0)",
            "as_u64() . unwrap_or_default()",
            "as_u64() .unwrap_or(0)",
            "as_u64().unwrap_or(0)",
            "as_u64().unwrap_or_default()",
        ] {
            if flat.contains(bad) {
                offenders.push(format!("{}: {bad}", f.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a count must be read through read_count_u64, which accepts a float that exactly \
         denotes an integer. `.as_u64()` alone returns None for 27.0 and the default then \
         records zero tokens for work that really happened:\n  {}",
        offenders.join("\n  ")
    );
}

/// THE SAME RULE, FOR THE OTHER SPELLING — the one that let the defect come back.
///
/// The sibling test above bans the METHOD form (`x.as_u64().unwrap_or(0)`). The house idiom has
/// a second spelling, the PATH form — `.and_then(Value::as_u64).unwrap_or(0)` — which reads
/// identically, defaults identically, and was invisible to that scan. It is not a hypothetical
/// gap: the leaf-op handlers were fixed once, the fix was lost, and sixteen live billed reads
/// came back in the path form precisely because nothing was watching it.
///
/// A BLANKET ban on the path form would be wrong — `.and_then(Value::as_u64)` is the correct,
/// unremarkable way to read `dimensions`, `n`, `seed`, `top_n`, an array `index` or an image
/// width, none of which are money. So this scans a VOCABULARY instead: the wire field names that
/// are counts busbar bills on, across all six dialects. A bare read of one of THOSE is a defect;
/// a bare read of anything else is not this test's business.
///
/// Adding a dialect with a new count field means adding its wire name here. That is the point:
/// the list is the explicit, reviewable statement of what busbar considers a billed count.
#[test]
fn no_dialect_reads_a_billed_count_field_with_a_bare_as_u64() {
    use std::path::Path;

    /// Wire field names that carry a BILLED count, in every dialect's own spelling.
    const BILLED_COUNT_FIELDS: &[&str] = &[
        // OpenAI Chat / Responses / images / embeddings / transcription
        "prompt_tokens",
        "completion_tokens",
        "input_tokens",
        "output_tokens",
        "cached_tokens",
        "cache_write_tokens",
        "reasoning_tokens",
        "audio_tokens",
        "accepted_prediction_tokens",
        "rejected_prediction_tokens",
        // Anthropic
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
        "ephemeral_5m_input_tokens",
        "ephemeral_1h_input_tokens",
        "web_search_requests",
        "thinking_tokens",
        // Gemini
        "promptTokenCount",
        "candidatesTokenCount",
        "thoughtsTokenCount",
        "cachedContentTokenCount",
        "toolUsePromptTokenCount",
        "totalTokenCount",
        // Bedrock
        "inputTokens",
        "outputTokens",
        "totalTokens",
        "cacheReadInputTokens",
        "cacheWriteInputTokens",
        "inputTextTokenCount",
        // Cohere
        "search_units",
        "classifications",
        "billed_units",
    ];

    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                // A test may spell a wire value however it likes; this rule is about the
                // production readers.
                if p.file_name().is_some_and(|n| n == "tests") {
                    continue;
                }
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && !p.file_name().is_some_and(|n| {
                    let n = n.to_string_lossy();
                    n.ends_with("_tests.rs") || n == "usage_count.rs"
                })
            {
                out.push(p);
            }
        }
    }

    let mut files = Vec::new();
    walk(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path(),
        &mut files,
    );
    assert!(
        files.len() > 20,
        "the scan found only {} source files, so it is not actually looking at the dialects",
        files.len()
    );

    let mut offenders = Vec::new();
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        // Flatten non-comment code so rustfmt's line breaks cannot hide the pair, and so the
        // prose in this file's own siblings is never scanned.
        let code: String = text
            .lines()
            .map(|l| {
                let t = l.trim_start();
                if t.starts_with("//") {
                    ""
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        let flat: String = code.split_whitespace().collect::<Vec<_>>().join(" ");
        for field in BILLED_COUNT_FIELDS {
            let needle = format!("\"{field}\")");
            let mut from = 0;
            while let Some(hit) = flat[from..].find(&needle) {
                let at = from + hit;
                from = at + needle.len();
                // The read follows the key closely; a generous window still cannot reach the
                // NEXT field lookup, because that lookup would contain its own `get("…")`.
                let window = &flat[from..flat.len().min(from + 120)];
                let stop = window.find(".get(").unwrap_or(window.len());
                let window = &window[..stop];
                if window.contains("as_u64") || window.contains("as_i64") {
                    offenders.push(format!("{}: {field}", f.display()));
                }
            }
        }
    }
    offenders.sort();
    offenders.dedup();
    assert!(
        offenders.is_empty(),
        "these BILLED count fields are read with a bare `as_u64`/`as_i64` instead of \
         `read_count_u64`. A provider that spells the count as a float (Cohere types every one \
         of its counts as JSON `number`) then reads as `None`, and the `unwrap_or(0)` beside it \
         ledgers real, billed work as ZERO:\n  {}",
        offenders.join("\n  ")
    );
}

/// A MULTI-BYTE UNREADABLE SPELLING REFUSES; IT DOES NOT PANIC THE CUT.
///
/// The bound on the quoted spelling was a byte `truncate(64)`, which panics when byte 64 lands
/// inside a character. `"` + forty `é` puts every `é` on an odd byte offset, so byte 64 is the
/// middle of one: the read that exists to REFUSE an unreadable count panicked instead — reachable
/// from the Gemini and OpenAI transcription/image readers, and from every dialect helper now
/// routed through `billed_count`.
#[test]
fn a_multi_byte_unreadable_spelling_refuses_rather_than_panicking() {
    let hostile = "é".repeat(40);
    let err = billed_count(&json!({ "n": hostile }), "n")
        .expect_err("a string is not a count, however it is spelled");
    assert_eq!(err.field, "n");
    assert!(
        err.spelling.len() <= SPELLING_BUDGET + '…'.len_utf8(),
        "the quoted spelling stays bounded in bytes, got {} bytes",
        err.spelling.len()
    );
    assert!(
        err.spelling.ends_with('…'),
        "a cut spelling says it was cut: {}",
        err.spelling
    );
    assert!(err.spelling.starts_with("\"é"), "{}", err.spelling);
}
