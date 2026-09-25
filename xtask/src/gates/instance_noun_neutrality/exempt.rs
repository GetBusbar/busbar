//! THE FROZEN-LITERAL PRAGMA — the one reviewed way a noun hit that is frozen text leaves the census.
//!
//! The census counts a noun wherever code or a string literal spells it, and that is right: a
//! plane key in a `"…"` is the crate naming the plane as surely as an identifier is. One kind of
//! literal is not a coupling a drain may touch: FROZEN customer- or operator-visible text (a
//! diagnostics catalog entry, an error string, a wire string), which §9.5 forbids changing. It gets
//! a marker of the SAME SHAPE as plane-purity-strict's frozen-wire carve-out — per line, reasoned,
//! and checked rather than trusted:
//!
//! `// noun-neutrality: frozen-literal pinned-by=<path> <reason>`
//!
//! * **A reason is required.** A bare marker is not a reviewed exemption and is refused.
//! * **Literal only.** It exempts noun occurrences INSIDE a string literal that touches its line
//!   (the whole literal when it spans lines — the marker sits on the line that closes it), never an
//!   identifier: an identifier on a marked line is still counted, and a marker whose line names its
//!   noun only in code is refused outright. A trailing marker covers its own line; a marker alone on
//!   a comment line covers the code line directly below it (the shape rustfmt leaves).
//! * **Pinned, and the pin is read.** plane-purity's pin is a released-tag config fingerprint,
//!   which fits config keys only, so this marker CITES its pin instead: `<path>` is the drift test
//!   or the committed rendered document that holds the text (`docs/diagnostics.md`, which the
//!   registry's drift test regenerates and compares). The gate reads it and refuses the marker
//!   unless it contains the literal (as compiled, or as written). A marker cannot cite its own file
//!   — a literal trivially "mentions" itself.
//! * **Counted and ratcheted.** The live count is reported and must equal the ledger's
//!   `[pragma_ceiling] frozen_literal`, so it can only fall.
//!
//! A refused marker exempts nothing AND reds its row, so an unreviewed exemption can never ride in
//! wearing the shape of a reviewed one.

use std::collections::BTreeSet;

use crate::ctx::Ctx;
use crate::scan::{blank_code_marking, LexState};

/// The marker prefix. A file that does not contain it is never lexed a second time.
pub const MARKER: &str = "noun-neutrality:";
const KIND: &str = "frozen-literal";
const CITE: &str = "pinned-by=";
/// The ledger key the ceiling is recorded under, in the `[pragma_ceiling]` table.
pub const CEILING_KEY: &str = "frozen_literal";

/// One marker as it sits in a scanned source file, with every reason it is refused.
#[derive(Debug, Clone)]
pub struct Pragma {
    pub file: String,
    /// 1-based line the marker sits on.
    pub line: usize,
    pub cite: Option<String>,
    pub reason: String,
    /// Empty = honoured. Anything here reds the row and the marker exempts nothing.
    pub problems: Vec<String>,
    /// 0-based index of the code line whose literals it covers.
    target: Option<usize>,
    /// The literals on the target line that hold a noun occurrence the census would count.
    covered: BTreeSet<usize>,
}

impl Pragma {
    pub fn site(&self) -> String {
        format!("{}:{}", self.file, self.line)
    }
    pub fn honoured(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Where a matched occurrence sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Comment,
    Literal(usize),
    Code,
}

struct Literal {
    lines: BTreeSet<usize>,
    /// The literal's content as written, lines joined with `\n`.
    text: String,
}

/// One file, lexed ONCE with the crate's multi-line-aware blanker: per char, which literal (if any)
/// it is the content of, and where the line's `//` comment starts.
pub struct FileLex {
    raw: Vec<Vec<char>>,
    lower: Vec<Vec<char>>,
    blanked: Vec<Vec<char>>,
    comment_at: Vec<Option<usize>>,
    lit: Vec<Vec<Option<usize>>>,
    literals: Vec<Literal>,
}

/// Lex `text`. Every literal delimiter survives [`blank_code_marking`] as a `"` and every other
/// `"` is blanked (a char literal, a comment), so literal content is exactly what lies between an
/// opening and a closing `"` in the blanked text, carried across lines.
pub fn lex(text: &str) -> FileLex {
    let mut st = LexState::default();
    let mut open: Option<usize> = None;
    let mut fl = FileLex {
        raw: Vec::new(),
        lower: Vec::new(),
        blanked: Vec::new(),
        comment_at: Vec::new(),
        lit: Vec::new(),
        literals: Vec::new(),
    };
    for (idx, line) in text.lines().enumerate() {
        let (blanked, comment_at) = blank_code_marking(line, &mut st);
        let raw: Vec<char> = line.chars().collect();
        let blanked: Vec<char> = blanked.chars().collect();
        let mut ids = vec![None; raw.len()];
        if let Some(id) = open {
            fl.literals[id].text.push('\n');
            fl.literals[id].lines.insert(idx);
        }
        for (i, c) in blanked.iter().enumerate() {
            if *c == '"' {
                open = match open {
                    Some(_) => None,
                    None => {
                        fl.literals.push(Literal {
                            lines: BTreeSet::from([idx]),
                            text: String::new(),
                        });
                        Some(fl.literals.len() - 1)
                    }
                };
                continue;
            }
            if let (Some(id), Some(rc)) = (open, raw.get(i)) {
                ids[i] = Some(id);
                fl.literals[id].text.push(*rc);
            }
        }
        fl.lower
            .push(raw.iter().map(|c| c.to_ascii_lowercase()).collect());
        fl.raw.push(raw);
        fl.blanked.push(blanked);
        fl.comment_at.push(comment_at);
        fl.lit.push(ids);
    }
    fl
}

impl FileLex {
    pub fn lines(&self) -> usize {
        self.raw.len()
    }
    /// The raw line and its ASCII-lowercased twin, char-aligned, for the matchers.
    pub fn line(&self, idx: usize) -> (&[char], &[char]) {
        (&self.raw[idx], &self.lower[idx])
    }
    pub fn classify(&self, idx: usize, at: usize) -> Class {
        if self.comment_at[idx].is_some_and(|c| at >= c) {
            return Class::Comment;
        }
        if let Some(Some(id)) = self.lit[idx].get(at) {
            return Class::Literal(*id);
        }
        // Blanked but not literal content: a block comment.
        match (self.blanked[idx].get(at), self.raw[idx].get(at)) {
            (Some(' '), Some(r)) if *r != ' ' => Class::Comment,
            _ => Class::Code,
        }
    }
    fn has_code(&self, idx: usize) -> bool {
        self.blanked[idx].iter().any(|c| !c.is_whitespace())
    }
    fn comment(&self, idx: usize) -> Option<String> {
        self.comment_at[idx].map(|c| self.raw[idx][c..].iter().collect())
    }
}

/// `(citation, reason)` of a marker in a comment, or `None` when there is no marker. A marker with
/// a missing citation or reason IS returned — it is refused by name, never silently ignored.
fn parse_marker(comment: &str) -> Option<(Option<String>, String)> {
    let mut rest = comment;
    while let Some(i) = rest.find(MARKER) {
        let tail = rest[i + MARKER.len()..].trim_start_matches([' ', '\t']);
        if let Some(after) = tail.strip_prefix(KIND) {
            if after.is_empty() || after.starts_with([' ', '\t']) {
                let after = after.trim();
                return Some(match after.strip_prefix(CITE) {
                    Some(r) => {
                        let mut it = r.splitn(2, char::is_whitespace);
                        let cite = it.next().unwrap_or("").trim();
                        let reason = it.next().unwrap_or("").trim();
                        (
                            (!cite.is_empty()).then(|| cite.to_string()),
                            reason.to_string(),
                        )
                    }
                    None => (None, after.to_string()),
                });
            }
        }
        rest = &rest[i + 1..];
    }
    None
}

/// Every marker in the file, with its target line resolved. Validation happens in [`judge`].
pub fn collect(file: &str, fl: &FileLex) -> Vec<Pragma> {
    let mut out = Vec::new();
    for idx in 0..fl.lines() {
        let Some(comment) = fl.comment(idx) else {
            continue;
        };
        let Some((cite, reason)) = parse_marker(&comment) else {
            continue;
        };
        let mut problems = Vec::new();
        let target = if fl.has_code(idx) {
            Some(idx)
        } else if idx + 1 < fl.lines() && fl.has_code(idx + 1) {
            Some(idx + 1)
        } else {
            problems.push(
                "a marker alone on a comment line covers the code line directly below it, and \
                 there is none"
                    .to_string(),
            );
            None
        };
        if cite.is_none() {
            problems.push(format!(
                "cites nothing — `{CITE}<drift test or rendered document>` is required"
            ));
        }
        if reason.is_empty() {
            problems.push("states no reason — a bare marker is not a reviewed exemption".into());
        }
        out.push(Pragma {
            file: file.to_string(),
            line: idx + 1,
            cite,
            reason,
            problems,
            target,
            covered: BTreeSet::new(),
        });
    }
    out
}

/// Judge every marker in one file. `spans(idx)` yields the census's counted occurrences on line
/// `idx` (every noun this file may not name), as char spans on the raw line.
pub fn judge(
    cx: &Ctx,
    fl: &FileLex,
    pragmas: &mut [Pragma],
    spans: &dyn Fn(usize) -> Vec<(usize, usize)>,
) {
    for p in pragmas.iter_mut() {
        let Some(t) = p.target else {
            continue;
        };
        let on_line: BTreeSet<usize> = fl.lit[t].iter().flatten().copied().collect();
        let mut code_hits = 0usize;
        for (s, _) in spans(t) {
            match fl.classify(t, s) {
                Class::Literal(id) if on_line.contains(&id) => {
                    p.covered.insert(id);
                }
                Class::Code => code_hits += 1,
                _ => {}
            }
        }
        // Occurrences on the literal's OTHER lines (a multi-line literal closed on this one).
        for id in &on_line {
            for &l in &fl.literals[*id].lines {
                if l != t
                    && spans(l)
                        .iter()
                        .any(|(s, _)| fl.classify(l, *s) == Class::Literal(*id))
                {
                    p.covered.insert(*id);
                }
            }
        }
        if p.covered.is_empty() {
            p.problems.push(if code_hits > 0 {
                "names its noun in an IDENTIFIER (code), not a string literal — the marker never \
                 exempts code; rename it or record it for the cross-crate rename"
                    .to_string()
            } else {
                "covers no string literal that names a counted noun — it exempts nothing"
                    .to_string()
            });
            continue;
        }
        if let Some(cite) = p.cite.clone() {
            judge_pin(cx, fl, p, &cite);
        }
    }
}

/// The literal's text as the compiler reads it: line continuations folded, simple escapes decoded.
fn compiled(text: &str) -> String {
    let mut out = String::new();
    let mut it = text.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('\n') => {
                while it.peek().is_some_and(|c| c.is_whitespace()) {
                    it.next();
                }
            }
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some(o) => out.push(o),
            None => out.push('\\'),
        }
    }
    out
}

fn judge_pin(cx: &Ctx, fl: &FileLex, p: &mut Pragma, cite: &str) {
    if cite.starts_with('/') || cite.split('/').any(|seg| seg == "..") {
        p.problems
            .push(format!("{CITE}`{cite}` is not a repository-relative path"));
        return;
    }
    if cite == p.file {
        p.problems.push(format!(
            "{CITE}`{cite}` cites the literal's own file — a literal trivially mentions itself; \
             cite the drift test or the committed rendered document that pins it"
        ));
        return;
    }
    let pin = match cx.read(cite) {
        Ok(t) => t,
        Err(e) => {
            p.problems.push(format!(
                "{CITE}`{cite}` cannot be read ({e}) — nothing pins the literal"
            ));
            return;
        }
    };
    for id in &p.covered {
        let lit = &fl.literals[*id];
        let text = compiled(&lit.text);
        if !(pin.contains(&text) || pin.contains(&lit.text)) {
            let shown: String = text.chars().take(80).collect();
            p.problems.push(format!(
                "{CITE}`{cite}` does not contain the literal \"{shown}\" — it pins nothing, so the \
                 text is not frozen"
            ));
        }
    }
}

/// Literal ids honoured markers exempt, file-wide (a multi-line literal is exempt on every line).
pub fn exempt_literals(pragmas: &[Pragma]) -> BTreeSet<usize> {
    pragmas
        .iter()
        .filter(|p| p.honoured())
        .flat_map(|p| p.covered.iter().copied())
        .collect()
}

/// Whether a counted line touching an exempt literal is entirely exempt: every occurrence on it sits
/// inside an exempt literal (or a comment). One in code, or in an unmarked literal, keeps it counted.
pub fn line_exempt(
    fl: &FileLex,
    idx: usize,
    spans: &[(usize, usize)],
    ok: &BTreeSet<usize>,
) -> bool {
    if ok.is_empty() || !fl.lit[idx].iter().flatten().any(|id| ok.contains(id)) {
        return false;
    }
    // A comment occurrence is not counted here either: the census's per-line strip can read a
    // trailing comment as literal text on the line that closes a multi-line literal.
    spans.iter().all(|(s, _)| match fl.classify(idx, *s) {
        Class::Comment => true,
        Class::Literal(id) => ok.contains(&id),
        Class::Code => false,
    })
}

/// The ledger's recorded ceiling: absent = 0 (a real ceiling), `Err` = present but not a bare
/// non-negative integer, which the row refuses rather than compares.
pub fn ceiling(doc_text: Option<&str>) -> Result<usize, String> {
    let doc = doc_text.and_then(|t| crate::toml_doc::parse_str(t).ok());
    match doc
        .as_ref()
        .and_then(|d| d.table("pragma_ceiling"))
        .and_then(|t| t.get(CEILING_KEY))
    {
        None => Ok(0),
        Some(v) => v
            .as_int()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| format!("{v:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_marker_parses_its_citation_and_reason_and_a_bare_one_keeps_neither() {
        assert_eq!(
            parse_marker(" noun-neutrality: frozen-literal pinned-by=docs/x.md catalog text"),
            Some((Some("docs/x.md".into()), "catalog text".into()))
        );
        assert_eq!(
            parse_marker(" noun-neutrality: frozen-literal"),
            Some((None, String::new()))
        );
        assert_eq!(parse_marker(" noun-neutrality: frozen-literalX y"), None);
    }

    #[test]
    fn a_multi_line_literal_is_one_literal_and_compiles_its_continuations() {
        let fl = lex("let a = \"one \\\n     two\"; let b = 1;\n");
        assert_eq!(fl.literals.len(), 1);
        assert_eq!(compiled(&fl.literals[0].text), "one two");
        assert_eq!(fl.literals[0].lines, BTreeSet::from([0, 1]));
        assert_eq!(fl.classify(1, 5), Class::Literal(0));
        assert_eq!(fl.classify(1, 15), Class::Code);
    }
}
