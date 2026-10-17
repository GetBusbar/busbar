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
                    // Cut on a CHARACTER boundary at or below the byte budget. `truncate` panics
                    // when its offset lands inside a multi-byte character, so a byte cut let a
                    // hostile spelling (forty `é`) panic the read that exists to refuse it.
                    let mut cut = SPELLING_BUDGET;
                    while !s.is_char_boundary(cut) {
                        cut -= 1;
                    }
                    s.truncate(cut);
                    s.push('…');
                }
                s
            },
        }),
    }
}

/// [`billed_count`] for a count whose ABSENCE is kept distinct from zero (a cache tier, a per-TTL
/// split): an absent usage object, an absent field or a JSON `null` is `None` (never a spurious
/// `Some(0)`), a readable count is `Some(n)`, and a present-but-UNREADABLE count is the same
/// [`UnreadableCount`] refusal — never the `None` that reads as "the provider reported no cache".
///
/// # Errors
/// The field is present, is not `null`, and is not a count.
pub fn billed_count_opt(
    usage: Option<&serde_json::Value>,
    field: &'static str,
) -> Result<Option<u64>, UnreadableCount> {
    match usage {
        Some(u) if u.get(field).is_some_and(|v| !v.is_null()) => billed_count(u, field).map(Some),
        _ => Ok(None),
    }
}

/// A RECORDED count (one the ledger notes and never bills): absent or `null` is `Some(0)` (nothing
/// reported, as [`billed_count`] reads it), a readable count is `Some(n)`, and a present count this
/// build cannot read is UNKNOWN, `None`. It is never a zero, because a zero records no work for
/// work that happened (#81, OWNER rule 21). It is never a refusal either, because a count nothing
/// bills does not justify refusing an answer. The unreadable field is named on `warnings` and in a
/// warning log line, so the gap is visible where the record is read.
pub fn recorded_count(
    usage: &serde_json::Value,
    field: &'static str,
    warnings: &mut Vec<String>,
) -> Option<u64> {
    match billed_count(usage, field) {
        Ok(n) => Some(n),
        Err(unreadable) => {
            ::tracing::warn!(
                field = unreadable.field,
                spelling = %unreadable.spelling,
                "a recorded usage count is unreadable: recorded as unknown, never as 0"
            );
            warnings.push(unreadable.to_string());
            None
        }
    }
}

// ── THE USAGE TABLE WALK (#42) ───────────────────────────────────────────────────────────────

/// Where one usage count lands in the IR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountSlot {
    /// `IrUsage::input_tokens` (uncached input).
    Input,
    /// `IrUsage::output_tokens`.
    Output,
    /// `IrUsage::cache_creation_input_tokens`.
    CacheWrite,
    /// `IrUsage::cache_read_input_tokens`.
    CacheRead,
    /// `IrUsageDetail::reasoning_tokens`.
    Reasoning,
    /// `IrUsageDetail::cache_creation_5m_input_tokens`.
    CacheWrite5m,
    /// `IrUsageDetail::cache_creation_1h_input_tokens`.
    CacheWrite1h,
    /// `IrUsageDetail::web_search_requests`.
    WebSearchRequests,
    /// `IrUsageDetail::web_fetch_requests`.
    WebFetchRequests,
    /// `IrUsageDetail::search_units`.
    SearchUnits,
    /// `IrUsageDetail::billed_input_tokens`.
    ProviderInput,
    /// `IrUsageDetail::billed_output_tokens`.
    ProviderOutput,
    /// `IrUsageDetail::billed_classifications`.
    Classifications,
    /// `IrUsageDetail::tool_use_prompt_tokens`.
    ToolUsePrompt,
    /// `IrUsageDetail::input_audio_tokens`.
    InputAudio,
    /// `IrUsageDetail::output_audio_tokens`.
    OutputAudio,
    /// `IrUsageDetail::accepted_prediction_tokens`.
    AcceptedPrediction,
    /// `IrUsageDetail::rejected_prediction_tokens`.
    RejectedPrediction,
}

const SLOTS: usize = 18;

/// How one count is read off the usage object and folded into its slot. A path names the member
/// from the usage object down; every member before the last is a parent object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountRead {
    /// A required counter: absent or `null` is 0, unreadable REFUSES. Sets the slot.
    Zero(&'static [&'static str]),
    /// An optional counter: absent or `null` is `None` (never `Some(0)`), unreadable REFUSES.
    /// Sets the slot.
    Opt(&'static [&'static str]),
    /// An attribution slice inside a total that is already read: unreadable is `None`, never a
    /// refusal. Sets the slot.
    Lenient(&'static [&'static str]),
    /// A slice the provider counts INSIDE the slot's total (a cached prefix inside the prompt):
    /// read as [`CountRead::Opt`] and SUBTRACTED (saturating) from the slot.
    Less(&'static [&'static str]),
    /// A term the provider reports BESIDE the slot's total (thinking beside the visible answer):
    /// read as [`CountRead::Opt`] and ADDED (saturating) to the slot.
    More(&'static [&'static str]),
    /// The sum of `count` over every entry of the list at `list` whose `key` member is `value`;
    /// `None` when no such entry reports one, unreadable REFUSES (a per-TTL cache list).
    ListSum {
        /// The path to the list.
        list: &'static [&'static str],
        /// The member that names an entry.
        key: &'static str,
        /// The name this slot takes.
        value: &'static str,
        /// The entry's count member.
        count: &'static str,
    },
    /// `count` of the FIRST entry of the list at `list` whose `key` member is `value`, as an
    /// attribution slice: unreadable is `None` (a per-modality list).
    ListFirst {
        /// The path to the list.
        list: &'static [&'static str],
        /// The member that names an entry.
        key: &'static str,
        /// The name this slot takes.
        value: &'static str,
        /// The entry's count member.
        count: &'static str,
    },
}

/// One row of a dialect's usage table.
pub type UsageCount = (CountSlot, CountRead);

/// The member at `path` under `usage` (`None` when any step is absent).
fn at<'a>(usage: Option<&'a serde_json::Value>, path: &[&str]) -> Option<&'a serde_json::Value> {
    path.iter().try_fold(usage?, |v, k| v.get(*k))
}

/// The parent object of the last member of `path`, and that member's name.
fn parent<'a>(
    usage: Option<&'a serde_json::Value>,
    path: &'static [&'static str],
) -> (Option<&'a serde_json::Value>, &'static str) {
    match path.split_last() {
        Some((last, up)) => (at(usage, up), last),
        None => (None, ""),
    }
}

/// One OPTIONAL counter: absent or `null` is `None`, a readable count is `Some`, unreadable is the
/// [`UnreadableCount`] the walk refuses on.
fn opt(
    usage: Option<&serde_json::Value>,
    path: &'static [&'static str],
) -> Result<Option<u64>, UnreadableCount> {
    let (up, field) = parent(usage, path);
    billed_count_opt(up, field)
}

/// THE ONE USAGE READER. Walks a dialect's usage table over one wire usage object (`None` when the
/// response carried none) and builds the IR usage it states. Each row is read under
/// [`billed_count`]'s contract: absent is zero (or `None`), a readable count is the count, and a
/// present-but-UNREADABLE count is REFUSED.
///
/// THE REFUSAL IS PER FIELD (ARCHITECT ruling 2026-10-15, #878 vs #892): each usage field is judged
/// on its own. A readable field bills as stated; an unreadable one (a stringified `"1500"`) is
/// refused, so IT bills nothing, and the refusal is loud (the warn line below, naming the protocol,
/// the field and its spelling; #42/#81 "refuse loudly"). Nothing is substituted for it: it is never
/// read as a zero count and no floor stands in for it (#77(2)). The answer and its readable counts
/// are not refused with it: `{"prompt_tokens":"1500","completion_tokens":9}` bills (0, 9), v1.5.5's
/// figure for that body (v1.5.5 `proto/openai_chat/reader.rs:678`), reached without reading the
/// unreadable count as anything. A dialect supplies only the table and its `protocol` label; it
/// never reads a count itself.
///
/// # Errors
/// None today: an unreadable count refuses only itself. The `Result` stays the readers' seam.
pub fn read_usage(
    protocol: &'static str,
    usage: Option<&serde_json::Value>,
    table: &[UsageCount],
) -> Result<crate::codec::ir::IrUsage, busbar_contract::protocol::IrError> {
    // One refused field: said loudly, and it bills nothing. The readable fields bill as stated.
    let kept = |read: Result<Option<u64>, UnreadableCount>| match read {
        Ok(n) => n,
        Err(unreadable) => {
            tracing::warn!(
                protocol,
                field = unreadable.field,
                spelling = %unreadable.spelling,
                "usage count is present but unreadable: REFUSED, it bills nothing and is never \
                 read as zero (#42, #81); the readable counts bill as stated"
            );
            None
        }
    };
    let mut slots = [None::<u64>; SLOTS];
    for &(slot, read) in table {
        let s = &mut slots[slot as usize];
        match read {
            CountRead::Zero(path) => {
                let (up, field) = parent(usage, path);
                *s = kept(up.map_or(Ok(0), |u| billed_count(u, field)).map(Some));
            }
            CountRead::Opt(path) => *s = kept(opt(usage, path)),
            CountRead::Lenient(path) => *s = at(usage, path).and_then(read_count_u64),
            // A refused slice or term moves nothing: the total it adjusts stands as read.
            CountRead::Less(path) => {
                if let Some(n) = kept(opt(usage, path)) {
                    *s = Some(s.unwrap_or(0).saturating_sub(n));
                }
            }
            CountRead::More(path) => {
                if let Some(n) = kept(opt(usage, path)) {
                    *s = Some(s.unwrap_or(0).saturating_add(n));
                }
            }
            CountRead::ListSum {
                list,
                key,
                value,
                count,
            } => {
                let mut sum: Option<u64> = None;
                for entry in at(usage, list)
                    .and_then(|l| l.as_array())
                    .into_iter()
                    .flatten()
                {
                    if entry.get(key).and_then(|k| k.as_str()) != Some(value) {
                        continue;
                    }
                    if let Some(n) = kept(billed_count_opt(Some(entry), count)) {
                        sum = Some(sum.unwrap_or(0).saturating_add(n));
                    }
                }
                *s = sum;
            }
            CountRead::ListFirst {
                list,
                key,
                value,
                count,
            } => {
                *s = at(usage, list)
                    .and_then(|l| l.as_array())
                    .and_then(|l| {
                        l.iter()
                            .find(|e| e.get(key).and_then(|k| k.as_str()) == Some(value))
                    })
                    .and_then(|e| e.get(count))
                    .and_then(read_count_u64);
            }
        }
    }
    let get = |slot: CountSlot| slots[slot as usize];
    Ok(crate::codec::ir::IrUsage {
        input_tokens: get(CountSlot::Input).unwrap_or(0),
        output_tokens: get(CountSlot::Output).unwrap_or(0),
        cache_creation_input_tokens: get(CountSlot::CacheWrite),
        cache_read_input_tokens: get(CountSlot::CacheRead),
        detail: crate::codec::ir::IrUsageDetail {
            reasoning_tokens: get(CountSlot::Reasoning),
            cache_creation_5m_input_tokens: get(CountSlot::CacheWrite5m),
            cache_creation_1h_input_tokens: get(CountSlot::CacheWrite1h),
            web_search_requests: get(CountSlot::WebSearchRequests),
            web_fetch_requests: get(CountSlot::WebFetchRequests),
            search_units: get(CountSlot::SearchUnits),
            billed_input_tokens: get(CountSlot::ProviderInput),
            billed_output_tokens: get(CountSlot::ProviderOutput),
            billed_classifications: get(CountSlot::Classifications),
            tool_use_prompt_tokens: get(CountSlot::ToolUsePrompt),
            input_audio_tokens: get(CountSlot::InputAudio),
            output_audio_tokens: get(CountSlot::OutputAudio),
            accepted_prediction_tokens: get(CountSlot::AcceptedPrediction),
            rejected_prediction_tokens: get(CountSlot::RejectedPrediction),
            ..Default::default()
        },
    })
}

/// Whether [`read_usage`] REFUSED a count of `usage` under `table`: a billed row present, not
/// `null`, and not a count. A usage with a refused count has no stated-total gap to ledger: the
/// gap would be the refused count itself, priced back in under another name, which is exactly the
/// substitution a refusal forbids (#77(2); ARCHITECT ruling 2026-10-15). The caller skips
/// [`stated_total_note`] for it.
#[must_use]
pub fn refused_any(usage: Option<&serde_json::Value>, table: &[UsageCount]) -> bool {
    table.iter().any(|&(_, read)| match read {
        CountRead::Zero(path)
        | CountRead::Opt(path)
        | CountRead::Less(path)
        | CountRead::More(path) => opt(usage, path).is_err(),
        CountRead::ListSum {
            list,
            key,
            value,
            count,
        } => at(usage, list)
            .and_then(|l| l.as_array())
            .into_iter()
            .flatten()
            .filter(|entry| entry.get(key).and_then(|k| k.as_str()) == Some(value))
            .any(|entry| billed_count_opt(Some(entry), count).is_err()),
        CountRead::Lenient(_) | CountRead::ListFirst { .. } => false,
    })
}

/// THE STATED-TOTAL CROSS-CHECK: the total a provider states beside its itemized counts, against
/// what the dialect's usage table LEDGERS from those counts (the four meter classes: uncached
/// input, cache read, cache write, output). A provider's total is its own sum of the counts it
/// itemizes, never a unit: nothing is zeroed, clamped or back-filled to make the two agree, and
/// the itemized counts stay exactly as reported. A total ABOVE them is the open class
/// `unitemized_tokens` (`IrUsage::to_token_usage`, owner LEDGER-100).
///
/// `None` in the ordinary case — no total on the usage object (absent, `null`, or not a count: a
/// total is checked, never billed, so an unreadable one is not a refusal), or a total equal to the
/// ledgered sum. Otherwise the gap is WARN-logged with both figures and returned as the note the IR
/// carries beside the counts: a POSITIVE `unaccounted` is units the provider counted that land in
/// no meter class (a counter the table does not read, e.g. an OpenAI-compatible backend reporting
/// reasoning outside `completion_tokens`), a negative one is a total below its own terms.
///
/// `protocol` names the dialect on the log line, `identity` the usage object checked (stable, for
/// a caller to branch on), `total` the provider's stated total member.
#[must_use]
pub fn stated_total_note(
    protocol: &'static str,
    identity: &'static str,
    total: Option<&serde_json::Value>,
    ledgered: &crate::codec::ir::IrUsage,
) -> Option<crate::codec::ir::UsageIdentityNote> {
    let reported_total = total.and_then(read_count_u64)?;
    let summed_total = ledgered.billable_tokens();
    if summed_total == reported_total {
        return None;
    }
    let unaccounted = i64::try_from(reported_total).unwrap_or(i64::MAX)
        - i64::try_from(summed_total).unwrap_or(i64::MAX);
    tracing::warn!(
        protocol,
        identity,
        reported_total,
        summed_total,
        unaccounted,
        "usage does not reconcile: the provider's stated total disagrees with the sum of the \
         meter classes its itemized counts ledger (input, cache read, cache write, output). The \
         itemized counts are ledgered as reported; a positive gap is ledgered as the open class \
         unitemized_tokens, a count the provider reports that this dialect's usage table does not \
         itemize."
    );
    Some(crate::codec::ir::UsageIdentityNote {
        reported_total,
        summed_total,
        unaccounted,
        identity,
    })
}

#[cfg(test)]
#[path = "tests/usage_count_tests.rs"]
mod tests;
