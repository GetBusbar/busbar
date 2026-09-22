//! The ONE seam every usage/billing count read in this crate goes through.
//!
//! # Why this module exists
//!
//! [`serde_json::Value::as_u64`] returns `None` for ANY float-backed `Number` — including `27.0`,
//! which is exactly representable as an integer. The house idiom across this crate's dialects was
//! `.as_u64().unwrap_or(0)`, so a provider that spells a count as a float turned a genuine count of
//! 27 into a recorded count of **zero**. Cohere's published spec types every usage count as a JSON
//! `number`, which PERMITS a float spelling — so a reader that cannot read one is a reader that can
//! bill zero for real work. (This module used to assert that Cohere's *real wire responses* do
//! spell them as floats. Measured 2026-09-22, nothing in this tree supports that: the only
//! float-spelled counts under `crates/busbar-llm-codec/` are this crate's own hand-written test
//! fixtures. The spec claim is weaker, checkable, and already sufficient; the wire claim was not
//! ours to make.)
//!
//! Under the locked money model this is not a money bug — it is a **ledger** bug, which is worse.
//! Money is a view over `ledger x ratecard` and cannot be wrong on its own; if the ledger says the
//! provider returned nothing, then every view derived from it faithfully reports nothing, and the
//! error is invisible at every downstream layer. The only place it can be caught is here, at the
//! read.
//!
//! Every dialect reads its counts through [`read_count_u64`]. A bare `.as_u64()` on a usage or
//! billing field is a defect; use this.

/// Read a JSON number as an exact, non-negative integer, or `None` if it is not one.
///
/// Tries the integer representation first — the cheap, common path for an already-integer payload —
/// and falls back to the float representation only when it provably denotes an exact integer. The
/// float is merely how the wire happened to spell it.
///
/// # What is rejected, and why
///
/// - **A fractional value** (`27.5`) is not a token count. It is rejected, never rounded: rounding
///   would invent a quantity the provider never reported, and an invented ledger row is the thing
///   this module exists to prevent.
/// - **A negative value** is not a count.
/// - **Infinity and NaN** are not counts.
/// - **Anything at or above 2^53** is rejected even though it "looks" integral. Past 2^53 an `f64`
///   cannot represent consecutive integers, so `fract() == 0.0` is trivially true for *every*
///   remaining value and the fractional test stops carrying any information at all. A number that
///   large cannot be trusted to be the count the provider actually sent, and no honest token count
///   approaches it. (This bound is deliberately tighter than `u64::MAX`, which would admit values
///   whose integrality the check can no longer actually verify.)
pub fn read_count_u64(v: &serde_json::Value) -> Option<u64> {
    if let Some(u) = v.as_u64() {
        return Some(u);
    }
    let f = v.as_f64()?;
    // 2^53 — the largest magnitude at which an f64 still represents every integer distinctly, and
    // therefore the largest at which `fract() == 0.0` still proves anything.
    const EXACT_INTEGER_LIMIT: f64 = 9_007_199_254_740_992.0;
    // `contains` also rejects NaN and both infinities, since neither compares inside any range —
    // so the bound check and the finiteness check are the same check.
    if (0.0..EXACT_INTEGER_LIMIT).contains(&f) && f.fract() == 0.0 {
        Some(f as u64)
    } else {
        None
    }
}

/// A usage field that was THERE and could not be read as a count.
///
/// Distinct from absence on purpose: "the provider reported nothing" and "the provider reported
/// something this build does not understand" are different facts, and only the first of them is
/// honestly worth zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableCount {
    /// Which usage field it was.
    pub field: &'static str,
    /// How it was spelled on the wire, so the operator can see what arrived. Bounded, because a
    /// hostile body must not be able to write an unbounded string into a log line.
    pub spelling: String,
}

impl std::fmt::Display for UnreadableCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "usage field `{}` is present but is not a count: {}",
            self.field, self.spelling
        )
    }
}

impl std::error::Error for UnreadableCount {}

/// How much of an unreadable value is quoted back. Enough to diagnose, bounded so a hostile body
/// cannot write an essay into an operator's log.
const SPELLING_BUDGET: usize = 64;

/// READ ONE BILLED COUNT OUT OF A USAGE OBJECT — ABSENT IS ZERO, UNREADABLE IS A REFUSAL.
///
/// # Why this exists rather than `.and_then(read_count_u64).unwrap_or(0)`
///
/// That idiom collapses two different facts into one number. A usage field the provider did not
/// send is genuinely zero of that unit — an embeddings response reports no output tokens because
/// there are none, and billing zero for it is correct and is what v1.5.5 did. But a field that IS
/// there and cannot be read is the provider telling us something this build does not understand,
/// and writing zero for it is the worst available answer: the ledger records that no work happened,
/// every money view over that row is faithfully derived and faithfully wrong, and nothing anywhere
/// downstream can tell. Money is a VIEW over `ledger x ratecard`, so a zeroed count is not a
/// display bug — it is a book that disagrees with reality and says nothing about it.
///
/// So the three cases are kept apart:
///
/// * **absent, or JSON `null`** — no such quantity was reported. `Ok(0)`, exactly as before. `null`
///   counts as absence because that is what `null` means, and because a provider spelling "nothing"
///   that way must not fail a request that works today.
/// * **readable** — the count, through [`read_count_u64`], including the float-spelled integer that
///   the bare `as_u64` reads as nothing at all.
/// * **present, not `null`, unreadable** — [`UnreadableCount`], which the caller turns into a
///   refusal (#42: money-sacred, never a silent 0).
///
/// # Errors
/// The field is present, is not `null`, and is not a count.
pub fn billed_count(
    usage: &serde_json::Value,
    field: &'static str,
) -> Result<u64, UnreadableCount> {
    match usage.get(field) {
        None => Ok(0),
        Some(v) if v.is_null() => Ok(0),
        Some(v) => read_count_u64(v).ok_or_else(|| UnreadableCount {
            field,
            spelling: {
                let mut s = v.to_string();
                if s.len() > SPELLING_BUDGET {
                    s.truncate(SPELLING_BUDGET);
                    s.push('…');
                }
                s
            },
        }),
    }
}

#[cfg(test)]
mod tests {
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
}
