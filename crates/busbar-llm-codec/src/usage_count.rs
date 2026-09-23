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
#[path = "tests/usage_count_tests.rs"]
mod tests;
