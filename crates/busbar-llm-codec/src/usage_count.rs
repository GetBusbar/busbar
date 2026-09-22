//! The ONE seam every usage/billing count read in this crate goes through.
//!
//! # Why this module exists
//!
//! [`serde_json::Value::as_u64`] returns `None` for ANY float-backed `Number` — including `27.0`,
//! which is exactly representable as an integer. The house idiom across this crate's dialects was
//! `.as_u64().unwrap_or(0)`, so a provider that spells a count as a float turned a genuine count of
//! 27 into a recorded count of **zero**. Cohere's real wire responses do exactly that.
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

#[cfg(test)]
mod tests {
    use super::read_count_u64;
    use serde_json::json;

    #[test]
    fn a_float_spelled_integer_is_the_integer() {
        // The exact defect: Cohere sends 27.0, `as_u64()` alone says None, and `unwrap_or(0)`
        // then bills zero for 27 tokens of real work.
        assert_eq!(read_count_u64(&json!(27.0)), Some(27));
        assert_eq!(json!(27.0).as_u64(), None, "the bare read this module replaces");
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
        assert!(inf.is_none(), "serde_json refuses non-finite numbers at construction");
        assert_eq!(read_count_u64(&json!(f64::MAX)), None);
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
        walk(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path(), &mut files);
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
                    if t.starts_with("//") { "" } else { l }
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
}
