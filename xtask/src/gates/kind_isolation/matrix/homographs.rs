//! THE KERNEL'S OWN WORDS THAT ARE ALSO A PLANE'S ID (ARCHITECT ruling Q1, 2026-10-20, Law 0
//! burndown §3(d)).
//!
//! `decision` is the decisions plane's bare id, `streams` the streaming plane's section-key alias and
//! `streaming` its id. The same three words are the kernel's and the contract's own vocabulary: the
//! hook kind answers a `RoutingDecision`, the auth ABI's verdict is a `Decision` (continue / stop),
//! the trust book keeps a decision; an export entry projects `streams` (`ExportStream`); an HTTP
//! response is `streaming` or buffered. Measured on dev bc610c636a those homographs were 380 of the
//! Law 0 hits (kernel × plane 223, contract × plane 82), and none of those lines named a plane.
//!
//! The ruling: homographs are not instance references, so the matcher reads the SENSE — through an
//! explicit, reviewed list ([`HOMOGRAPHS`]), one row per word and sense, each with its one-line
//! justification. Nothing outside the list is masked, and the list never outranks an INSTANCE
//! POSITION. These always count, whatever the list says:
//!
//! * a string literal that IS the id (`"decision"`, `"streams"`): only a [`Sense::Compound`] is read
//!   inside a literal, and a compound is two segments or more;
//! * a crate or package name and a kind-qualified id (`busbar_plane_streaming`, `plane-decision`):
//!   the word beside the `plane` marker ([`beside_plane`]) is never masked, in any position;
//! * a module path segment (`crate::plane::decision::`, `mod streaming`, `use …::{streams}`): a
//!   [`Sense::Binding`] never applies to a lower-case path segment ([`module_path`]);
//! * prose that names the plane ("the streaming plane");
//! * every spelling the list does not name: a compound that is not a row (`route_to_decision`), a
//!   word inside a message literal, a word in a `.json`, `.yaml` or `.txt` file (this mask reads
//!   `.rs` files only).
//!
//! The frozen 1.5.x export key (`streams: [`) is the earlier ruling's row, [`super::EXPORT_STREAMS_KEY`],
//! and prose `decision` / `streams` stays [`super::ENGLISH_INSTANCE_WORDS`]'; this module adds the
//! code senses and `streaming` in prose. A plane crate is not read through this mask: a plane naming
//! `decision` may be naming its sibling.
//!
//! Masked with same-length `x` filler, so lines and columns hold; the context (literal, comment,
//! path, the neighbouring word) is read off the ORIGINAL text, so an earlier mask's filler never
//! changes what a neighbour says.

use std::borrow::Cow;

/// Where a homograph's non-instance sense is read.
#[derive(Debug, Clone, Copy)]
pub(super) enum Sense {
    /// The word as ONE SEGMENT of a longer name whose segments, adjacent and in order, are this run
    /// (`["routing", "decision"]` is `RoutingDecision`, `routing_decision`, `ROUTING_DECISION`),
    /// wherever the name is written: code, a literal, a comment.
    Compound(&'static [&'static str]),
    /// The word as a WHOLE identifier, exactly this spelling, in Rust code (outside every literal
    /// and comment) and not a module path ([`module_path`]): a field, a binding, a parameter, a
    /// function or a type.
    Binding(&'static str),
    /// The word standing alone in a comment: not joined to a neighbouring name by `-`, `_`, `.` or a
    /// letter, not quoted in backticks, and not in section-key position (followed by `:`).
    Prose,
}

/// One reviewed homograph: the word, the sense in which it is not the plane, and why.
pub(super) struct Homograph {
    pub(super) word: &'static str,
    pub(super) sense: Sense,
    /// Read by the reviewed-list test; it is the row's reason, written for its reviewer.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) why: &'static str,
}

/// THE REVIEWED LIST. A row is a word and ONE sense; a word with no row here is counted wherever it
/// is written, and a row cannot reach an instance position (module doc).
pub(super) const HOMOGRAPHS: &[Homograph] = &[
    // ---- decision: the decisions plane's bare id; the hook kind's, the auth ABI's and the trust
    // book's verdict.
    Homograph {
        word: "decision",
        sense: Sense::Compound(&["routing", "decision"]),
        why: "`RoutingDecision`: the hook kind's answer type (busbar-contract hooks.rs), not the plane",
    },
    Homograph {
        word: "decision",
        sense: Sense::Compound(&["decision", "gate"]),
        why: "`DECISION_GATE_*`: the hook kind's decision-gate stage and its diagnostics",
    },
    Homograph {
        word: "decision",
        sense: Sense::Compound(&["decision", "gates"]),
        why: "`pool_decision_gates`: a pool's decision-gate hooks (the hook kind's stage)",
    },
    Homograph {
        word: "decision",
        sense: Sense::Compound(&["trust", "decision"]),
        why: "`KIND_TRUST_DECISION` / `trust_decision`: the trust book's kept decision record",
    },
    Homograph {
        word: "decision",
        sense: Sense::Compound(&["keep", "decision"]),
        why: "`keep_decision`: the trust book's host service that keeps an approval",
    },
    Homograph {
        word: "decision",
        sense: Sense::Compound(&["decision", "unkept"]),
        why: "`DECISION_UNKEPT`: the trust book's refusal when a decision could not be kept",
    },
    Homograph {
        word: "decision",
        sense: Sense::Compound(&["decision", "continue"]),
        why: "`DECISION_CONTINUE`: the auth ABI's continue verdict constant",
    },
    Homograph {
        word: "decision",
        sense: Sense::Compound(&["decision", "stop"]),
        why: "`DECISION_STOP`: the auth ABI's stop verdict constant",
    },
    Homograph {
        word: "decision",
        sense: Sense::Compound(&["map", "decision"]),
        why: "`map_decision`: the hook driver mapping a hook's `RoutingDecision` onto the route",
    },
    Homograph {
        word: "decision",
        sense: Sense::Binding("decision"),
        why: "a field, binding or parameter `decision` holds a verdict (hook, auth ABI, trust book); \
              a plane is never a local",
    },
    Homograph {
        word: "decision",
        sense: Sense::Binding("Decision"),
        why: "`Decision`: the auth ABI's continue/stop verdict type (busbar-contract auth_calls.rs) \
              and its variant paths `Decision::Continue`",
    },
    // ---- streams: the streaming plane's section-key alias; the export kind's projection list.
    Homograph {
        word: "streams",
        sense: Sense::Compound(&["produced", "streams"]),
        why: "`PRODUCED_STREAMS`: the export streams the kernel produces (`ExportStream`)",
    },
    Homograph {
        word: "streams",
        sense: Sense::Compound(&["streams", "of"]),
        why: "`streams_of`: an export entry's projection read off its statement",
    },
    Homograph {
        word: "streams",
        sense: Sense::Compound(&["streams", "len"]),
        why: "`streams_len`: the export door ABI's projection-list length",
    },
    Homograph {
        word: "streams",
        sense: Sense::Compound(&["module", "streams"]),
        why: "`export_module_streams` / `released_module_streams`: a 1.5.x export module's streams",
    },
    Homograph {
        word: "streams",
        sense: Sense::Binding("streams"),
        why: "a field, binding or parameter `streams` holds an export projection (`ExportStream`s); \
              a plane is never a local",
    },
    // ---- streaming: the streaming plane's id; HTTP response streaming.
    Homograph {
        word: "streaming",
        sense: Sense::Compound(&["streaming", "content"]),
        why: "`streaming_content_type(s)`: the media types an HTTP response streams in",
    },
    Homograph {
        word: "streaming",
        sense: Sense::Binding("streaming"),
        why: "a field, binding or parameter `streaming` is an HTTP response mode flag \
              (streamed vs buffered)",
    },
    Homograph {
        word: "streaming",
        sense: Sense::Prose,
        why: "\"a streaming response\", \"non-streaming request\": HTTP response streaming in prose \
              (the plane is \"the streaming plane\", which still counts)",
    },
];

/// What part of a Rust file a byte is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Region {
    Code,
    Literal,
    Comment,
}

fn is_id(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Every byte of `b`, classified: code, inside a string / char literal, or inside a comment. String
/// state carries across lines (a continued literal is a literal), raw strings (`r#"…"#`) close only
/// on their own hashes, and block comments nest.
fn regions(b: &[u8]) -> Vec<Region> {
    let mut out = vec![Region::Code; b.len()];
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    out[i] = Region::Comment;
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut depth = 0usize;
                while i < b.len() {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        out[i] = Region::Comment;
                        out[i + 1] = Region::Comment;
                        i += 2;
                        continue;
                    }
                    if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth = depth.saturating_sub(1);
                        out[i] = Region::Comment;
                        out[i + 1] = Region::Comment;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                        continue;
                    }
                    out[i] = Region::Comment;
                    i += 1;
                }
            }
            b'"' => i = string_end(b, i + 1, 0, &mut out),
            b'r' if raw_string_head(b, i) => {
                let mut k = i + 1;
                while b.get(k) == Some(&b'#') {
                    k += 1;
                }
                // `raw_string_head` saw the quote at `k`.
                i = string_end(b, k + 1, k - i - 1, &mut out);
            }
            b'\'' => {
                let close = if b.get(i + 1) == Some(&b'\\') {
                    (i + 2..(i + 12).min(b.len())).find(|&k| b[k] == b'\'')
                } else if b.get(i + 2) == Some(&b'\'') {
                    Some(i + 2)
                } else if b.get(i + 1).is_some_and(|c| *c >= 0x80) {
                    (i + 2..(i + 6).min(b.len())).find(|&k| b[k] == b'\'')
                } else {
                    // A lifetime or a label: `'a`, `'static`.
                    None
                };
                match close {
                    Some(k) => {
                        for r in &mut out[i + 1..k] {
                            *r = Region::Literal;
                        }
                        i = k + 1;
                    }
                    None => i += 1,
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// Whether `b[i]` (an `r`) opens a raw string: `r"`, `r#"`, `br"`, not the tail of an identifier.
fn raw_string_head(b: &[u8], i: usize) -> bool {
    let free = |k: usize| k == 0 || !is_id(b[k - 1]);
    let starts = free(i) || (i >= 1 && b[i - 1] == b'b' && free(i - 1));
    if !starts {
        return false;
    }
    let mut k = i + 1;
    while b.get(k) == Some(&b'#') {
        k += 1;
    }
    b.get(k) == Some(&b'"')
}

/// Mark a string's content from `start` as [`Region::Literal`]; the index past its closing quote
/// (and `hashes` `#`s).
fn string_end(b: &[u8], start: usize, hashes: usize, out: &mut [Region]) -> usize {
    let mut k = start;
    while k < b.len() {
        if hashes == 0 && b[k] == b'\\' {
            out[k] = Region::Literal;
            if k + 1 < b.len() {
                out[k + 1] = Region::Literal;
            }
            k += 2;
            continue;
        }
        if b[k] == b'"' && (1..=hashes).all(|h| b.get(k + h) == Some(&b'#')) {
            return k + 1 + hashes;
        }
        out[k] = Region::Literal;
        k += 1;
    }
    k
}

/// The segments of the identifier `b[s..e]`, as byte ranges: split at `_` and at both camel-case
/// transitions (`routingDecision`, `HTTPDecision`), the scanners' own segmentation.
fn segments(b: &[u8], s: usize, e: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for k in s..e {
        let c = b[k];
        if c == b'_' {
            if let Some(st) = start.take() {
                out.push((st, k));
            }
            continue;
        }
        match start {
            None => start = Some(k),
            Some(st) => {
                let prev = b[k - 1];
                let next = if k + 1 < e { Some(b[k + 1]) } else { None };
                let camel = prev.is_ascii_lowercase() && c.is_ascii_uppercase();
                let acronym = prev.is_ascii_uppercase()
                    && c.is_ascii_uppercase()
                    && next.is_some_and(|n| n.is_ascii_lowercase());
                if camel || acronym {
                    out.push((st, k));
                    start = Some(k);
                }
            }
        }
    }
    if let Some(st) = start {
        out.push((st, e));
    }
    out
}

fn is_plane(word: &str) -> bool {
    word == "plane" || word == "planes"
}

/// The identifier ending just before `s` (past at most three spaces, `-` or backticks), lower-cased.
fn word_before(b: &[u8], s: usize) -> Option<String> {
    let mut k = s;
    let mut gap = 0;
    while k > 0 && matches!(b[k - 1], b' ' | b'-' | b'`') && gap < 3 {
        k -= 1;
        gap += 1;
    }
    let end = k;
    while k > 0 && is_id(b[k - 1]) {
        k -= 1;
    }
    (k < end).then(|| {
        let segs = segments(b, k, end);
        let (x, y) = *segs.last().expect("a non-empty identifier has a segment");
        String::from_utf8_lossy(&b[x..y]).to_ascii_lowercase()
    })
}

/// The identifier starting just after `e` (past at most three spaces, `-` or backticks), lower-cased.
fn word_after(b: &[u8], e: usize) -> Option<String> {
    let mut k = e;
    let mut gap = 0;
    while k < b.len() && matches!(b[k], b' ' | b'-' | b'`') && gap < 3 {
        k += 1;
        gap += 1;
    }
    let start = k;
    while k < b.len() && is_id(b[k]) {
        k += 1;
    }
    (start < k).then(|| {
        let segs = segments(b, start, k);
        let (x, y) = segs[0];
        String::from_utf8_lossy(&b[x..y]).to_ascii_lowercase()
    })
}

/// INSTANCE POSITION: the word beside the `plane` marker — inside its own identifier
/// (`busbar_plane_streaming`, `decision_plane`) or as the neighbouring word ("the streaming
/// plane", `plane-decision`). Never masked.
fn beside_plane(b: &[u8], names: &[String], k: usize, s: usize, e: usize) -> bool {
    (k > 0 && is_plane(&names[k - 1]))
        || names.get(k + 1).is_some_and(|n| is_plane(n))
        || (k == 0 && word_before(b, s).is_some_and(|w| is_plane(&w)))
        || (k + 1 == names.len() && word_after(b, e).is_some_and(|w| is_plane(&w)))
}

/// INSTANCE POSITION for a [`Sense::Binding`]: a lower-case MODULE path segment (`plane::decision`,
/// `decision::serve`), a `mod` item, or a name in a `use` line. A capitalised name followed by
/// `::` is a type's path (`Decision::Continue`), not a module.
fn module_path(b: &[u8], s: usize, e: usize) -> bool {
    let lower = b[s].is_ascii_lowercase();
    let before = s >= 2 && &b[s - 2..s] == b"::";
    let after = b[e..].starts_with(b"::");
    if lower && (before || after) {
        return true;
    }
    let line_start = b[..s]
        .iter()
        .rposition(|&c| c == b'\n')
        .map_or(0, |p| p + 1);
    let head = String::from_utf8_lossy(&b[line_start..s]);
    let tail = head.trim_end();
    if tail == "mod" || tail.ends_with(" mod") {
        return true;
    }
    let lead = head.trim_start();
    lower
        && ["use ", "pub use ", "pub(crate) use ", "pub(super) use "]
            .iter()
            .any(|p| lead.starts_with(p))
}

/// Whether the one-segment word at `b[s..e]`, in a comment, stands alone (see [`Sense::Prose`]).
fn standalone_in_prose(b: &[u8], s: usize, e: usize) -> bool {
    let name = |k: Option<&u8>| k.is_some_and(|c| c.is_ascii_alphanumeric());
    let joins = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'`');
    let joined_before = s > 0
        && (joins(b[s - 1]) || (b[s - 1] == b'.' && name(s.checked_sub(2).and_then(|k| b.get(k)))));
    let joined_after = b
        .get(e)
        .is_some_and(|&c| joins(c) || c == b':' || (c == b'.' && name(b.get(e + 1))));
    !joined_before && !joined_after
}

/// Whether segment `k` of `names` lies inside an adjacent run equal to `run`.
fn compound_covers(names: &[String], k: usize, run: &[&str]) -> bool {
    let n = run.len();
    if n < 2 || n > names.len() {
        return false;
    }
    (k.saturating_sub(n - 1)..=k)
        .filter(|&o| o + n <= names.len())
        .any(|o| {
            names[o..o + n]
                .iter()
                .zip(run)
                .all(|(a, b)| a.as_str() == *b)
        })
}

/// The byte ranges of `text` (a `.rs` file) that the list reads as a non-instance sense.
fn spans(text: &str) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let region = regions(b);
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !is_id(b[i]) {
            i += 1;
            continue;
        }
        let s = i;
        while i < b.len() && is_id(b[i]) {
            i += 1;
        }
        let e = i;
        let segs = segments(b, s, e);
        let names: Vec<String> = segs
            .iter()
            .map(|&(x, y)| String::from_utf8_lossy(&b[x..y]).to_ascii_lowercase())
            .collect();
        for (k, &(x, y)) in segs.iter().enumerate() {
            if !HOMOGRAPHS.iter().any(|h| h.word == names[k]) {
                continue;
            }
            if beside_plane(b, &names, k, s, e) {
                continue;
            }
            let at = region[x];
            let whole = segs.len() == 1;
            let read = HOMOGRAPHS
                .iter()
                .filter(|h| h.word == names[k])
                .any(|h| match h.sense {
                    Sense::Compound(run) => compound_covers(&names, k, run),
                    Sense::Binding(spelling) => {
                        at == Region::Code
                            && whole
                            && &b[s..e] == spelling.as_bytes()
                            && !module_path(b, s, e)
                    }
                    Sense::Prose => at == Region::Comment && whole && standalone_in_prose(b, s, e),
                });
            if read {
                out.push((x, y));
            }
        }
    }
    out
}

/// `masked` (the chain's text so far, same length as `original`) with every [`HOMOGRAPHS`] sense of
/// a `.rs` file masked; the senses are read off `original`. Any other file, or a text whose length
/// an earlier mask changed, is returned as it came: an unaligned reading is never masked.
pub(super) fn mask_homographs_in<'a>(rel: &str, original: &str, masked: &'a str) -> Cow<'a, str> {
    if !rel.ends_with(".rs") || original.len() != masked.len() {
        return Cow::Borrowed(masked);
    }
    let lower = original.to_ascii_lowercase();
    if !HOMOGRAPHS.iter().any(|h| lower.contains(h.word)) {
        return Cow::Borrowed(masked);
    }
    let found = spans(original);
    if found.is_empty() {
        return Cow::Borrowed(masked);
    }
    let mut out = masked.as_bytes().to_vec();
    for (x, y) in found {
        if out[x..y].iter().all(u8::is_ascii) {
            out[x..y].fill(b'x');
        }
    }
    match String::from_utf8(out) {
        Ok(s) => Cow::Owned(s),
        Err(_) => Cow::Borrowed(masked),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(src: &str) -> String {
        mask_homographs_in("crates/x/src/a.rs", src, src).into_owned()
    }

    #[test]
    fn every_row_has_a_reason_and_names_its_own_word() {
        for h in HOMOGRAPHS {
            assert!(h.why.len() > 20, "{} needs a justification", h.word);
            match h.sense {
                Sense::Compound(run) => assert!(run.len() >= 2 && run.contains(&h.word)),
                Sense::Binding(s) => assert_eq!(s.to_ascii_lowercase(), h.word),
                Sense::Prose => {}
            }
        }
    }

    #[test]
    fn the_kernels_own_senses_are_masked() {
        let src = "pub fn f(decision: RoutingDecision, streams: &[S]) -> bool {\n    \
                   // a streaming response is not buffered.\n    \
                   let streaming = streaming_content_types();\n    \
                   pool_decision_gates(Decision::Continue, PRODUCED_STREAMS)\n}\n";
        let out = masked(src);
        for w in ["decision", "Decision", "streams", "STREAMS", "streaming"] {
            assert!(!out.contains(w), "{w} survived in {out}");
        }
        assert_eq!(out.len(), src.len());
    }

    #[test]
    fn instance_positions_still_count() {
        for src in [
            "pub const KEY: &str = \"decision\";\n",
            "let p = Plane { instance: \"streams\".into() };\n",
            "pub use crate::plane::decision::serve;\n",
            "mod streaming;\n",
            "use crate::planes::{streams, llm};\n",
            "// the streaming plane answers here.\n",
            "use busbar_plane_streaming::Codec;\n",
            "#[cfg(feature = \"plane-decision\")]\n",
            "pub fn route_to_decision() {}\n",
            "let m = \"the trust decision could not be kept\";\n",
            "// `streaming` is the plane's id.\n",
        ] {
            assert_eq!(masked(src), src, "an instance position was masked: {src}");
        }
    }

    #[test]
    fn a_literal_and_a_comment_are_told_apart_across_lines() {
        let src = "let s = \"first line \\\n    streaming\";\nlet streaming = 1; // \"\n";
        let out = masked(src);
        assert!(
            out.contains("    streaming\""),
            "a continued literal is a literal: {out}"
        );
        assert!(out.contains("let xxxxxxxxx = 1"), "{out}");
    }

    #[test]
    fn a_non_rust_file_is_not_read() {
        let src = "streaming: true\ndecision: x\n";
        assert_eq!(
            mask_homographs_in("crates/x/fixture.yaml", src, src),
            Cow::Borrowed(src)
        );
    }
}
