//! THE G6 FREEZE WITNESS — `scripts/g6-freeze-witness.sh`, folded into `plane-purity` per
//! `docs/design/xtask-gates.md` section 1.2.
//!
//! The neutral-IR cutover is complete for a family only when busbar-core's PRODUCTION code
//! references none of that family's concrete IR types: core reads the request through the neutral
//! projection and drives translation through the plugin vtable. This counts what remains, split
//! into the definitions (the `ir/` module, which moves to busbar-llm as a unit) and the consumer
//! up-refs OUTSIDE it (which must invert onto the neutral projection or relocate) — the split is
//! the whole diagnostic value, because the two halves are paid down in completely different ways.
//!
//! The first-draft grep read GREEN while core still named `IrUsage` eleven times; this is the
//! broadened set, and the two DELIBERATE exclusions below are exclusions, not oversights.

use crate::ctx::SourceFile;

/// The roots the witness measures: EVERY neutral root [`crate::planes::neutral_src_roots`]
/// declares, not the kernel alone (1.6.0 item 218).
///
/// The claim is "core names zero concrete LLM-family IR type", and "core" is the neutral set, not
/// one crate of it. Walking `crates/busbar-kernel/src` only meant the freeze could be declared met
/// by a file move: a concrete IR type relocated into `busbar-contract` or `busbar-substrate-values`
/// (which already carries an `ir/` module) is still core naming the family, and the witness read
/// zero. The population is the SAME list every other plane-purity row scans, so a neutral crate
/// added there is measured here the day it lands.
pub fn roots() -> Vec<String> {
    crate::planes::neutral_src_roots()
}

/// The definitions half: a site under `<neutral root>/ir/` DEFINES the concrete types and relocates
/// as a unit. Any neutral crate's `ir/` module is a definitions module, not only the kernel's.
fn is_def(rel: &str, roots: &[String]) -> bool {
    roots.iter().any(|r| {
        rel.strip_prefix(r.as_str())
            .is_some_and(|t| t.starts_with("/ir/"))
    })
}

/// Concrete LLM-family IR types that MUST leave core. Whole-word matched.
///
/// EXCLUDED ON PURPOSE, and both exclusions are load-bearing:
///
/// * the neutral surface that STAYS — `IrFacts`, `ContentItem`, `Slot`, `Shape`, `Operation`,
///   `IrError`, and the genuinely cross-plane `InvokeReq`/`InvokeResp`/`SubscribeReq`/
///   `SubscribeResp`; plus `EgressPrep`, an all-primitives resolved-param bag naming no concrete
///   IR, which the dissolve places neutral-in-core. Counting it would hold the freeze open on a
///   type that correctly stays.
/// * the `IrReq`/`IrResp` hub enums, which do not relocate as a family — they DISSOLVE into a
///   neutral opaque handle plus core-owned leaves. Counting them conflates "enum dissolved" with
///   "concrete family named", inflating the number while it exists and masking per-leaf progress.
pub const TYPES: [&str; 39] = [
    "IrRequest",
    "IrResponse",
    "IrMessage",
    "IrBlock",
    "IrBlockMeta",
    "IrRole",
    "IrTool",
    "IrToolChoice",
    "IrUsage",
    "IrUsageDetail",
    "IrDelta",
    "IrStreamEvent",
    "IrStopReason",
    "IrMediaKind",
    "IrCitation",
    "IrResponseFormat",
    "CacheControl",
    "CacheKind",
    "StreamDecodeState",
    "IrImageSource",
    "IrReasoningAsk",
    "IrReasoningEffort",
    "IrTokenLogprob",
    "IrTopLogprob",
    "StreamTranslate",
    "StreamFraming",
    "JsonArrayFramer",
    "EmbeddingsReq",
    "EmbeddingsResp",
    "ModerationReq",
    "ModerationResp",
    "ImageReq",
    "ImageResp",
    "TranscriptionReq",
    "TranscriptionResp",
    "SpeechReq",
    "SpeechResp",
    "RerankReq",
    "RerankResp",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Freeze {
    /// Every remaining site, `file:line`, in walk order.
    pub sites: Vec<String>,
    pub count: usize,
    /// Sites under `ir/` — definitions, which relocate as a unit.
    pub defs: usize,
    /// Everything else — consumer up-refs, which invert or relocate one at a time.
    pub uprefs: usize,
}

/// Count the remaining concrete-family references in the neutral set's PRODUCTION code.
///
/// The scope exclusions are the ripgrep globs the shell preferred (`**/tests/**`, `**/*_test.rs`,
/// `**/test_support/**`), not the narrower grep fallback: the fallback dropped the `*_test.rs`
/// arm, so which of the two ran decided the number. One scope, named here.
pub fn measure(files: &[SourceFile]) -> Freeze {
    let roots = roots();
    let mut out = Freeze::default();
    for f in files {
        let rel = f.rel_str();
        if rel.contains("/tests/") || rel.ends_with("_test.rs") || rel.contains("/test_support/") {
            continue;
        }
        for (idx, raw) in f.text.lines().enumerate() {
            if !TYPES.iter().any(|t| whole_word(raw, t)) {
                continue;
            }
            // A comment-only mention carries no compile edge: drop from the first `//` to end of
            // line, then refuse a line that was nothing but a comment or doc line.
            let code = raw.split("//").next().unwrap_or("").trim_start();
            if code.is_empty() || code.starts_with("/*") || code.starts_with('*') {
                continue;
            }
            let site = format!("{rel}:{}", idx + 1);
            if is_def(&rel, &roots) {
                out.defs += 1;
            } else {
                out.uprefs += 1;
            }
            out.sites.push(site);
            out.count += 1;
        }
    }
    out
}

/// `(^|[^A-Za-z0-9_])<word>([^A-Za-z0-9_]|$)`. Byte-wise: every word is ASCII, so a match starts
/// and ends on a character boundary and no byte of a multi-byte character is an identifier byte —
/// the same answer the per-character scan gave, without a `Vec<char>` per type per line.
fn whole_word(hay: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let h = hay.as_bytes();
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    hay.match_indices(word).any(|(i, _)| {
        (i == 0 || !ident(h[i - 1])) && h.get(i + word.len()).is_none_or(|b| !ident(*b))
    })
}
