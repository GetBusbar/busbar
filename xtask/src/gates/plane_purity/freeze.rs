//! THE G6 FREEZE WITNESS — `scripts/g6-freeze-witness.sh`, folded into `plane-purity` per
//! `docs/design/BUSBAR-1.6.0.md` Part 1 ("What this means for the gates").
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

// THE ROOTS THE WITNESS MEASURES are `plane-purity`'s derived neutral population (1.6.0 item 218,
// Q128): every neutral root, not the kernel alone. The claim is "core names zero concrete
// LLM-family IR type", and "core" is the neutral set, not one crate of it — a concrete IR type
// relocated into `busbar-contract` is still core naming the family. The caller passes the roots, so
// a neutral crate the kind table seats is measured here the day it lands.

/// The definitions half: a site under `<neutral root>/ir/` DEFINES the concrete types and relocates
/// as a unit. Any neutral crate's `ir/` module is a definitions module, not only the kernel's.
fn is_def(rel: &str, roots: &[String]) -> bool {
    roots.iter().any(|r| {
        rel.strip_prefix(r.as_str())
            .is_some_and(|t| t.starts_with("/ir/"))
    })
}

/// THE WRITTEN EXCLUSIONS, named below on [`TYPES`]: the neutral surface that stays and the hub
/// enums that dissolve. A declaration the LLM plane makes under one of these names is not counted.
pub const EXCLUDED: &[&str] = &[
    "IrFacts",
    "ContentItem",
    "Slot",
    "Shape",
    "Operation",
    "IrError",
    "InvokeReq",
    "InvokeResp",
    "SubscribeReq",
    "SubscribeResp",
    "EgressPrep",
    "IrReq",
    "IrResp",
];

/// THE LLM IR'S HOME: a `codec/ir/` module of an LLM-family plane crate (`busbar-plane-llm`, and
/// any `busbar-plane-llm-<dialect>` crate a split would add).
fn is_llm_ir_decl_file(rel: &str) -> bool {
    let mut parts = rel.split('/');
    let (Some("crates"), Some(dir)) = (parts.next(), parts.next()) else {
        return false;
    };
    (dir == "busbar-plane-llm" || dir.starts_with("busbar-plane-llm-"))
        && rel.contains("/src/codec/ir/")
        && !rel.contains("/tests/")
        && !rel.ends_with("_test.rs")
        && !rel.ends_with("_tests.rs")
}

/// THE FLOOR UNDER THE DERIVED DECLARATIONS: the `pub struct`/`pub enum`/`pub type` items the LLM
/// plane's `codec/ir/` declared on dev, measured (73). A derivation that fell under it read a
/// module that moved, not a family that shrank (Law 8 shape 2).
pub const DECLARED_FLOOR: usize = 73;

/// THE NEEDLE SET, DERIVED (Q128 part 22; Law 8: a roster "derived from the instances' own
/// declarations"). Every type the LLM plane's `codec/ir/` module declares, minus [`EXCLUDED`], plus
/// [`TYPES`] — the codec-side names (`StreamTranslate`, `JsonArrayFramer`, …) the hand list carries
/// that live outside `ir/`. The hand list alone held 39 of the module's 73 declarations, so
/// `IrWebSearch`, `IrHostedTool`, `IrUsageByModality` and thirty more could be named in core with
/// the freeze reading zero. Returns `(needles, declared)`; `declared` is held to [`DECLARED_FLOOR`].
pub fn derive_types(plane_files: &[SourceFile]) -> (Vec<String>, usize) {
    let mut declared: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for f in plane_files {
        if !is_llm_ir_decl_file(&f.rel_str()) {
            continue;
        }
        for raw in f.text.lines() {
            if let Some(name) = declared_type(raw) {
                declared.insert(name);
            }
        }
    }
    let n = declared.len();
    let mut out: std::collections::BTreeSet<String> = declared
        .into_iter()
        .filter(|t| !EXCLUDED.contains(&t.as_str()))
        .collect();
    out.extend(TYPES.iter().map(|t| (*t).to_string()));
    (out.into_iter().collect(), n)
}

/// THE NEUTRAL HOMONYMS: every name of `needles` that the neutral set BINDS ITSELF outside an
/// `ir/` module — declares (`struct`/`enum`/`type`/`trait`) or imports under that name
/// (`PathSeg as Segment`) — and that is not one of [`TYPES`]. A name is not a thing (Law 8): the
/// kernel's grammar binds `Segment` to the contract's `PathSeg`, and the LLM IR declares its own
/// transcription `Segment`; a whole-word witness cannot tell the two apart, so the derived name the
/// neutral set binds to something of its own is not counted, and the row names every such name.
/// [`TYPES`] is never excused this way: a neutral re-declaration of one of those is the family
/// moving into core, which is the very thing the witness exists to see.
pub fn neutral_homonyms(core: &[SourceFile], roots: &[String], needles: &[String]) -> Vec<String> {
    let mut bound: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for f in core {
        let rel = f.rel_str();
        if is_def(&rel, roots) {
            continue;
        }
        for raw in f.text.lines() {
            let code = raw.split("//").next().unwrap_or("");
            if let Some(name) = bound_type(code) {
                bound.insert(name);
            }
            let mut rest = code;
            while let Some(i) = rest.find(" as ") {
                let name: String = rest[i + 4..]
                    .trim_start()
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                    bound.insert(name);
                }
                rest = &rest[i + 4..];
            }
        }
    }
    needles
        .iter()
        .filter(|n| bound.contains(*n) && !TYPES.contains(&n.as_str()))
        .cloned()
        .collect()
}

/// `[pub [(…)]] struct|enum|type|trait Name` at the start of a line → `Name`.
fn bound_type(raw: &str) -> Option<String> {
    let t = raw.trim_start();
    let t = match t.strip_prefix("pub") {
        Some(rest) if rest.starts_with('(') => rest.split_once(')')?.1,
        Some(rest) => rest,
        None => t,
    };
    let t = t.trim_start();
    let t = ["struct ", "enum ", "type ", "trait "]
        .iter()
        .find_map(|kw| t.strip_prefix(kw))?;
    let name: String = t
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    name.chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase())
        .then_some(name)
}

/// `pub [(…)] struct|enum|type Name` at the start of a line → `Name`.
fn declared_type(raw: &str) -> Option<String> {
    let t = raw.trim_start().strip_prefix("pub")?;
    let t = if let Some(rest) = t.strip_prefix('(') {
        rest.split_once(')')?.1
    } else {
        t
    };
    let t = t.trim_start();
    let t = ["struct ", "enum ", "type "]
        .iter()
        .find_map(|kw| t.strip_prefix(kw))?;
    let name: String = t
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    name.chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase())
        .then_some(name)
}

/// Concrete LLM-family IR types that MUST leave core and that the derivation above cannot see from
/// `codec/ir/` alone. Whole-word matched.
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
pub fn measure(files: &[SourceFile], roots: &[String], types: &[String]) -> Freeze {
    let needles = Needles::of(types);
    let mut out = Freeze::default();
    for f in files {
        let rel = f.rel_str();
        if rel.contains("/tests/") || rel.ends_with("_test.rs") || rel.contains("/test_support/") {
            continue;
        }
        for (idx, raw) in f.text.lines().enumerate() {
            if !needles.any_in(raw) {
                continue;
            }
            // A comment-only mention carries no compile edge: drop from the first `//` to end of
            // line, then refuse a line that was nothing but a comment or doc line.
            let code = raw.split("//").next().unwrap_or("").trim_start();
            if code.is_empty() || code.starts_with("/*") || code.starts_with('*') {
                continue;
            }
            let site = format!("{rel}:{}", idx + 1);
            if is_def(&rel, roots) {
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

/// THE NEEDLE SET, ASKED ONCE PER LINE. A needle made only of identifier bytes occurs in a line
/// bounded by non-identifier bytes exactly when one of the line's maximal identifier runs IS that
/// needle, so those are looked up by run in a set: one pass over the line, not one substring search
/// per needle (the derived set is a hundred names, over every neutral line, on every run). Any other
/// needle is matched by [`whole_word`] as before; an empty one matches nothing, as there.
struct Needles<'a> {
    words: std::collections::HashSet<&'a str>,
    other: Vec<&'a str>,
}

impl<'a> Needles<'a> {
    fn of(types: &'a [String]) -> Needles<'a> {
        let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        let mut words = std::collections::HashSet::new();
        let mut other = Vec::new();
        for t in types.iter().map(String::as_str).filter(|t| !t.is_empty()) {
            if t.bytes().all(ident) {
                words.insert(t);
            } else {
                other.push(t);
            }
        }
        Needles { words, other }
    }

    fn any_in(&self, line: &str) -> bool {
        (!self.words.is_empty()
            && line
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(|run| self.words.contains(run)))
            || self.other.iter().any(|t| whole_word(line, t))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declaration_line_yields_its_type_name() {
        assert_eq!(
            declared_type("pub struct IrWebSearch {").as_deref(),
            Some("IrWebSearch")
        );
        assert_eq!(
            declared_type("    pub(crate) enum IrModality {").as_deref(),
            Some("IrModality")
        );
        assert_eq!(
            declared_type("pub type Alias = u8;").as_deref(),
            Some("Alias")
        );
        assert!(declared_type("pub fn ir() {}").is_none());
        assert!(declared_type("struct Private;").is_none());
        assert!(is_llm_ir_decl_file(
            "crates/busbar-plane-llm/src/codec/ir/types.rs"
        ));
        assert!(!is_llm_ir_decl_file(
            "crates/busbar-plane-llm/src/codec/ir/tests/a.rs"
        ));
        assert!(!is_llm_ir_decl_file(
            "crates/busbar-plane-mcp/src/codec/ir/types.rs"
        ));
    }

    #[test]
    fn the_needle_set_answers_as_the_whole_word_rule_does() {
        let types: Vec<String> = ["IrUsage", "Ir-Odd", "", "CacheKind"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let n = Needles::of(&types);
        for line in [
            "let u: IrUsage = x;",
            "IrUsage",
            "IrUsageDetail",
            "my_IrUsage",
            "x.IrUsage()",
            "é IrUsage é",
            "fooCacheKind",
            "(CacheKind)",
            "an Ir-Odd here",
            "an Ir-Oddity here",
            "",
        ] {
            assert_eq!(
                n.any_in(line),
                types.iter().any(|t| whole_word(line, t)),
                "{line}"
            );
        }
    }

    #[test]
    fn a_neutral_alias_is_a_homonym_and_a_hand_listed_type_never_is() {
        let f = |rel: &str, text: &str| SourceFile {
            abs: std::path::PathBuf::from(rel),
            rel: std::path::PathBuf::from(rel),
            text: text.to_string(),
        };
        let core = vec![
            f(
                "crates/k/src/g.rs",
                "use c::{PathSeg as Segment};\npub struct IrUsage;\n",
            ),
            f("crates/k/src/ir/x.rs", "pub struct Word;\n"),
        ];
        let needles: Vec<String> = ["Segment", "IrUsage", "Word", "IrWebSearch"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            neutral_homonyms(&core, &["crates/k/src".to_string()], &needles),
            vec!["Segment".to_string()]
        );
    }
}
