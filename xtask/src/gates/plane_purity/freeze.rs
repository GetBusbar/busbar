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

/// The root the witness measures. A neutral crate, so the shell's `$CORE`.
pub const CORE_ROOT: &str = "crates/busbar-core/src";

/// The definitions half: everything under here DEFINES the concrete types and relocates as a unit.
pub const DEFS_PREFIX: &str = "crates/busbar-core/src/ir/";

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

/// Count the remaining concrete-family references in core's PRODUCTION code.
///
/// The scope exclusions are the ripgrep globs the shell preferred (`**/tests/**`, `**/*_test.rs`,
/// `**/test_support/**`), not the narrower grep fallback: the fallback dropped the `*_test.rs`
/// arm, so which of the two ran decided the number. One scope, named here.
pub fn measure(files: &[SourceFile]) -> Freeze {
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
            if site.starts_with(DEFS_PREFIX) {
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

fn whole_word(hay: &str, word: &str) -> bool {
    let h: Vec<char> = hay.chars().collect();
    let w: Vec<char> = word.chars().collect();
    if w.is_empty() || h.len() < w.len() {
        return false;
    }
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    for i in 0..=(h.len() - w.len()) {
        if h[i..i + w.len()] == w[..]
            && (i == 0 || !ident(h[i - 1]))
            && h.get(i + w.len()).is_none_or(|c| !ident(*c))
        {
            return true;
        }
    }
    false
}
