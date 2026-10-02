//! THE ONE SIDE-CHANNEL SCANNER — `scripts/plane-purity-lint.sh`'s `scan()` awk program, rule for
//! rule and spelling for spelling.
//!
//! It emits one [`Hit`] per violation, in the shape the shell emitted as
//! `CATEGORY<TAB>file:line<TAB>trimmed-source`, so a hit list written by this scanner and one
//! written by the awk are the same artefact and `--parity` can diff them line for line.
//!
//! Two things it deliberately keeps from the shell, because both were bugs the shell had to be
//! taught out of:
//!
//! * **The spellings that are not `::` and not CamelCase.** `extern crate busbar_mcp;`,
//!   `use busbar_a2a as alias;`, `busbar_core :: internal`, `MCPCallRecord` / `OpenAIClient` /
//!   `LLMRouter`, and `include!("…/busbar-voice/…")` each bind exactly the side channel the
//!   original patterns were written for, spelled so the original patterns could not see them.
//! * **`include!` is decided ABOVE the pragma gate.** It used to fall through to the vocabulary
//!   rules, which the frozen-wire pragma exempts — so one trailing comment spliced a plane's source
//!   into a neutral crate under a clean report. PATH-INCLUDE and SYMBOL are structural and no
//!   config-freeze excuses either.
//!
//! No regex engine: `xtask` has one dependency and this is not the place to add a second. Every
//! pattern below is the awk pattern written out as a scan, with its awk source in the comment so
//! the two can be read against each other.

use crate::ctx::SourceFile;

use super::vocab::Vocab;

/// The six category names, in the fixed report order the shell prints and
/// `qa/plane-purity-strict.toml` keys its `[categories]` table by.
pub const CATEGORIES: [&str; 6] = [
    "PATH-INCLUDE",
    "SYMBOL",
    "TYPE",
    "KEY",
    "DIALECT",
    "BACKWARDS",
];

// THE INSTANCE WORDS ARE NOT HERE ANY MORE. `PLANE_ALTERNATION` (four hand-typed plane keys, one of
// them a dialect and two of the five planes missing), the six-name dialect list, and the CamelCase
// and acronym prefix lists built from both are all DERIVED now — see [`super::vocab`] — and handed
// to [`scan`] as a [`Vocab`]. A new plane, transport or dialect is in the scan the day its crate or
// its declaration is in the tree.

/// The named plane record types the TYPE rule bans outright.
const RECORD_TYPES: [&str; 4] = ["McpCallRecord", "McpDemotionRow", "TaskRow", "TaskEventRow"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Scan NEUTRAL sources for the side channels reaching AROUND the ABI.
    Forward,
    /// Scan PLANE sources for the backwards reach into `busbar_core::` implementation.
    Reverse,
}

/// Which scope a hit belongs to. `Production` is the scan `--check` runs; `Test` is what `--strict`
/// adds. One pass classifies every hit into exactly one of the two, so the two lists can never
/// double-count a hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Production,
    Test,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub category: &'static str,
    pub file: String,
    pub line: usize,
    pub code: String,
}

impl Hit {
    /// The shell's `emit`: `CATEGORY<TAB>file:line<TAB>trimmed-source`.
    pub fn tsv(&self) -> String {
        format!(
            "{}\t{}:{}\t{}",
            self.category, self.file, self.line, self.code
        )
    }

    pub fn site(&self) -> String {
        format!("{}:{}", self.file, self.line)
    }
}

/// Scan one file list, BOTH scopes in one pass: `(production, test)`. Callers pass the WALK's
/// output, so a missing root or a below-floor scan has already been refused before a single line is
/// read — the shell had to bolt both guards on in front of `find` and this crate gets them from
/// [`crate::ctx::WalkSpec`].
///
/// ONE PASS, NOT TWO. The two scopes used to be two full scans of the same files, each re-deciding
/// every line's scope in order to throw half of the hits away; every line is now read once and its
/// hits land in the list its scope names. The partition is the same one — a hit is test-scope
/// exactly when it was, production exactly when it was — at half the reads.
pub fn scan(files: &[SourceFile], mode: Mode, vocab: &Vocab) -> (Vec<Hit>, Vec<Hit>) {
    let mut prod = Vec::new();
    let mut test = Vec::new();
    for f in files {
        scan_file(&f.rel_str(), &f.text, mode, vocab, &mut prod, &mut test);
    }
    (prod, test)
}

fn scan_file(
    name: &str,
    text: &str,
    mode: Mode,
    vocab: &Vocab,
    prod: &mut Vec<Hit>,
    test: &mut Vec<Hit>,
) {
    // Per-FILE reset. The awk shares state across its file list and resets on `FNR == 1`; here the
    // state simply cannot outlive the file, which is the same rule made unrepresentable.
    let mut in_block = false;
    let mut test_depth: i32 = 0;
    let mut pend = false;
    let mut prev_frozen = false;
    let mut lex = crate::scan::LexState::default();

    let istestfile = name.contains("/tests/") || ends_with_tests_rs(name);

    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let code = strip(raw, &mut in_block);
        // `code` keeps literal contents because a plane key or dialect name spelled in a `"…"` is
        // still the crate naming it — that is what the categories below are counting. The
        // `#[cfg(test)] mod` DEPTH is a different question and reads the blanked copy, so a brace
        // inside a literal can no longer hold the test window open (which would silently drop
        // production hits) or shut it early (which would count test hits as production).
        let counted = crate::scan::blank_code(raw, &mut lex);
        let nopen = counted.matches('{').count() as i32;
        let nclose = counted.matches('}').count() as i32;

        // FROZEN-WIRE pragma, read on the RAW line so the marker lives in a comment. A BARE PRAGMA
        // IS NOT A PRAGMA: the contract is one pragma per excused line, each justifying itself in
        // the diff, so at least one word of reason is required for the marker to count. Computed
        // before any early continue, so `prev_frozen` stays in step across the scope skips.
        let curpragma = has_frozen_wire_pragma(raw);
        let frozen = curpragma || prev_frozen;
        // A trailing pragma (the line has code) does NOT bleed onto the next line; only a
        // pure-comment pragma line exempts the single code line that follows it, which is the
        // shape rustfmt produces when it relocates a comment that trailed an opening `{`.
        prev_frozen = curpragma && code.trim().is_empty();

        // `#[cfg(test)] mod { … }` tracking, so unit-test code is excluded from (b)/(c). READ OFF
        // THE BLANKED LINE, for the reason the depth above is: `code` keeps literal contents so the
        // vocabulary rules can search them, and a line whose STRING holds `#[cfg(test)] mod x {`
        // then opens a test window over production source — every hit after it silently reclassified
        // out of the `--check` pass and into the ratcheted one. The attribute and the `mod` keyword
        // hold no literal of their own, so blanking cannot hide a real gate.
        let is_cfgtest = counted.contains("#[cfg(") && {
            let counted_lc = format!(" {} ", counted.to_lowercase());
            word_ci(&counted_lc, "test")
        };
        let has_mod = has_bare_word_mod(&counted);
        let mut entered = false;
        // The attribute and its `mod` on ONE line, or the `mod` a prior `#[cfg(test)]` guarded —
        // the same entry either way, which is why the two arms are one condition. They are the two
        // spellings rustfmt produces for the same construct, not two rules.
        if (is_cfgtest || pend) && has_mod {
            test_depth = (nopen - nclose).max(0);
            entered = test_depth > 0;
            pend = false;
        } else if pend && counted.contains(|c: char| !c.is_whitespace()) && !is_cfgtest {
            // the attribute guarded a NON-mod item; do not block-skip the rest of the file
            pend = false;
        } else if test_depth > 0 {
            test_depth = (test_depth + nopen - nclose).max(0);
        }
        if is_cfgtest && !has_mod {
            pend = true;
        }
        let intest = istestfile || test_depth > 0 || entered;

        if code.trim().is_empty() {
            continue;
        }
        // The categories this line is guilty of, in rule order, and whether a test-scope
        // PATH-INCLUDE must ALSO land in the production list (see (a)).
        let mut found: Vec<&'static str> = Vec::new();
        let mut include_in_prod_too = false;
        let mut emit = |category: &'static str| found.push(category);

        if mode == Mode::Reverse {
            // No backwards reach: a plane crate must not name `busbar_core::` implementation items.
            // THE CRATE IS NAMED, NOT ONLY ITS PATHS — the two spellings that bind the crate with
            // no `::` on the line walked straight through the original rule, and either one
            // re-opens plane→core-internals wholesale.
            if code.contains("busbar_core")
                && (path_of(&code, "busbar_core")
                    || extern_crate_of(&code, "busbar_core")
                    || bound_as(&code, "busbar_core"))
            {
                emit("BACKWARDS");
            }
        } else {
            forward_rules(
                &code,
                frozen,
                vocab,
                &mut emit,
                &mut include_in_prod_too,
                intest,
            );
        }

        let trimmed = code.trim();
        let hit = |category: &'static str| Hit {
            category,
            file: name.to_string(),
            line: lineno,
            code: trimmed.to_string(),
        };
        if include_in_prod_too {
            prod.push(hit("PATH-INCLUDE"));
        }
        let out: &mut Vec<Hit> = if intest { test } else { prod };
        out.extend(found.into_iter().map(hit));
    }
}

/// The five FORWARD rules over one neutral line, in the order they are reported.
fn forward_rules(
    code: &str,
    frozen: bool,
    vocab: &Vocab,
    emit: &mut impl FnMut(&'static str),
    include_in_prod_too: &mut bool,
    intest: bool,
) {
    // (a) PATH-INCLUDE — unconditional, test scope included: an instant fail wherever it lives,
    //     and NEVER excusable by the pragma below, because a dual-compile is structural and no
    //     config-freeze can justify it. So a test-scope include lands in the PRODUCTION list
    //     too — `--check` fails on it — exactly as the two-pass scanner counted it.
    if (code.contains("#[") || code.contains("include"))
        && (path_attr_include(code, vocab) || macro_include(code, vocab))
    {
        emit("PATH-INCLUDE");
        *include_in_prod_too = intest;
    }

    // (b) SYMBOL — an instance-crate symbol path, an `extern crate`, or a `use … as` that
    //     renames the crate out of this scanner's sight. Also never excusable: a frozen config
    //     FIELD or TYPE never requires naming an instance crate.
    if code.contains("busbar_")
        && vocab.crate_idents.iter().any(|krate| {
            code.contains(krate.as_str())
                && (path_of(code, krate) || extern_crate_of(code, krate) || bound_as(code, krate))
        })
    {
        emit("SYMBOL");
    }

    // THE FROZEN-WIRE CARVE-OUT: exempt from the VOCABULARY rules ONLY, and only below the two
    // structural rules above.
    if frozen {
        return;
    }

    // (c3) TYPE — checked before the bare-key rule so `McpFoo` reads as TYPE, not KEY.
    if RECORD_TYPES.iter().any(|t| bare_word(code, t))
        || vocab
            .camel_prefixes
            .iter()
            .any(|p| prefix_then_upper(code, p))
        || vocab
            .screaming_prefixes
            .iter()
            .any(|p| prefix_then_upper(code, p))
    {
        emit("TYPE");
    }

    let lc = format!(" {} ", code.to_lowercase());
    // (c1) KEY — a concrete plane key as a bare token, or a transport by its compound name.
    //      Word-boundary, so it does NOT match inside `busbar_mcp` / `plane_mcp` /
    //      `MCP_RUNTIME_SLOT`: `_` is not a boundary.
    if vocab.key_words.iter().any(|k| word_ci(&lc, k))
        || vocab.literal_words.iter().any(|q| lc.contains(q.as_str()))
    {
        emit("KEY");
    }

    // (c2) DIALECT — a dialect the tree declares, as a token.
    if vocab.dialects.iter().any(|d| word_ci(&lc, d)) {
        emit("DIALECT");
    }
}

/// `FILENAME ~ /_tests?\.rs$/`
fn ends_with_tests_rs(name: &str) -> bool {
    name.ends_with("_test.rs") || name.ends_with("_tests.rs")
}

/// Comment and block-comment stripping, string literals respected so a `//` inside a `"…"` is not a
/// comment and a token inside a `"…"` IS kept. `in_block` persists across lines (block comments
/// span them); the in-string flag is per line, exactly as the awk resets it, which guards against a
/// raw-string or char-literal desync running away with the rest of the file.
pub fn strip(line: &str, in_block: &mut bool) -> String {
    // BYTE-WISE, and the same scan. Every delimiter this reads (`/`, `*`, `"`, `\\`) is ASCII, and
    // no byte of a multi-byte UTF-8 character equals an ASCII byte, so walking bytes finds exactly
    // the delimiters walking characters did. What is kept is a set of whole byte runs cut at those
    // ASCII delimiters, so it is still valid UTF-8. The per-character version built a `String` for
    // every two-character lookahead, on every character of every line.
    let b = line.as_bytes();
    let mut res: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if *in_block {
            if c == b'*' && next == Some(b'/') {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if in_str {
            res.push(c);
            if c == b'\\' {
                if let Some(n) = next {
                    res.push(n);
                }
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == b'/' && next == Some(b'*') {
            *in_block = true;
            i += 2;
            continue;
        }
        if c == b'/' && next == Some(b'/') {
            break;
        }
        if c == b'"' {
            in_str = true;
        }
        res.push(c);
        i += 1;
    }
    String::from_utf8(res).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// `$0 ~ /plane-purity:[[:space:]]*frozen-wire[[:space:]]+[^[:space:]]/` — the marker, then at
/// least one word of REASON. Without the reason it is an un-reviewable blanket exemption wearing
/// the shape of a reviewed one.
pub fn has_frozen_wire_pragma(raw: &str) -> bool {
    let mut rest = raw;
    while let Some(i) = rest.find("plane-purity:") {
        let tail = &rest[i + "plane-purity:".len()..];
        let tail = tail.trim_start_matches([' ', '\t']);
        if let Some(after) = tail.strip_prefix("frozen-wire") {
            let trimmed = after.trim_start_matches([' ', '\t']);
            // the marker must be FOLLOWED by whitespace and then a non-space character
            if after.len() != trimmed.len() && !trimmed.is_empty() {
                return true;
            }
        }
        rest = &rest[i + 1..];
    }
    false
}

/// `code ~ /(^|[^A-Za-z0-9_])mod([^A-Za-z0-9_])/` — note the awk requires a character AFTER `mod`,
/// so a line ending in a bare `mod` is not a mod line.
fn has_bare_word_mod(code: &str) -> bool {
    let b = code.as_bytes();
    code.match_indices("mod").any(|(i, _)| {
        (i == 0 || !is_ident_b(b[i - 1])) && b.get(i + 3).is_some_and(|c| !is_ident_b(*c))
    })
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// [`is_ident`] over one BYTE. Every needle this scanner matches is ASCII, so a match always starts
/// and ends on a character boundary, and a byte of a multi-byte character is never an identifier
/// byte — exactly as the multi-byte character it belongs to is never an identifier character. The
/// byte form is the character form, without a `Vec<char>` per needle per line.
fn is_ident_b(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The awk's `[^a-z0-9_]` identifier boundary, applied to the LOWERCASED, space-padded line.
fn is_ident_lc_b(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
}

/// `function word_ci(lc, needle) { return (lc ~ ("[^a-z0-9_]" needle "[^a-z0-9_]")) }` — a
/// whole-word, case-insensitive hit of a lowercase needle in the padded lowercased line. The awk
/// pattern needs a character on EACH side, which the padding supplies.
pub fn word_ci(lc: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let hay = lc.as_bytes();
    lc.match_indices(needle).any(|(i, _)| {
        let end = i + needle.len();
        i >= 1 && end < hay.len() && !is_ident_lc_b(hay[i - 1]) && !is_ident_lc_b(hay[end])
    })
}

/// `(^|[^A-Za-z0-9_])<word>([^A-Za-z0-9_]|$)` over the un-lowercased line.
fn bare_word(code: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let b = code.as_bytes();
    code.match_indices(word).any(|(i, _)| {
        let end = i + word.len();
        (i == 0 || !is_ident_b(b[i - 1])) && b.get(end).is_none_or(|c| !is_ident_b(*c))
    })
}

/// `(^|[^A-Za-z0-9_])<prefix>[A-Z][A-Za-z0-9_]*` — a prefix at an identifier boundary followed by
/// an UPPERCASE letter. The trailing `[A-Za-z0-9_]*` matches zero-width, so the uppercase letter is
/// the whole requirement, and that is what keeps `MCP_RUNTIME_SLOT` out.
fn prefix_then_upper(code: &str, prefix: &str) -> bool {
    if prefix.is_empty() {
        return false;
    }
    let b = code.as_bytes();
    code.match_indices(prefix).any(|(i, _)| {
        (i == 0 || !is_ident_b(b[i - 1]))
            && b.get(i + prefix.len()).is_some_and(u8::is_ascii_uppercase)
    })
}

/// `<krate>[[:space:]]*::` — unanchored, exactly as the awk wrote it. rustfmt will not produce
/// `busbar_core :: internal`, but rustc accepts it, so the separator tolerates whitespace.
fn path_of(code: &str, krate: &str) -> bool {
    let mut rest = code;
    while let Some(i) = rest.find(krate) {
        let tail = &rest[i + krate.len()..];
        if tail.trim_start_matches([' ', '\t']).starts_with("::") {
            return true;
        }
        rest = &rest[i + 1..];
    }
    false
}

/// `(^|[^A-Za-z0-9_])extern[[:space:]]+crate[[:space:]]+<krate>([^A-Za-z0-9_]|$)`
fn extern_crate_of(code: &str, krate: &str) -> bool {
    let b = code.as_bytes();
    code.match_indices("extern").any(|(i, _)| {
        if i > 0 && is_ident_b(b[i - 1]) {
            return false;
        }
        let Some(t) = strip_required_space(&code[i + "extern".len()..]) else {
            return false;
        };
        let Some(t) = t.strip_prefix("crate") else {
            return false;
        };
        let Some(t) = strip_required_space(t) else {
            return false;
        };
        let Some(after) = t.strip_prefix(krate) else {
            return false;
        };
        after.chars().next().is_none_or(|c| !is_ident(c))
    })
}

/// `[[:space:]]+` — at least one space or tab, or no match at all.
fn strip_required_space(s: &str) -> Option<&str> {
    let t = s.trim_start_matches([' ', '\t']);
    if t.len() == s.len() {
        None
    } else {
        Some(t)
    }
}

/// `(^|[^A-Za-z0-9_])<krate>[[:space:]]+as[[:space:]]` — the alias that renames the crate out of
/// every later line's sight.
fn bound_as(code: &str, krate: &str) -> bool {
    if krate.is_empty() {
        return false;
    }
    let b = code.as_bytes();
    code.match_indices(krate).any(|(i, _)| {
        if i > 0 && is_ident_b(b[i - 1]) {
            return false;
        }
        let tail = &code[i + krate.len()..];
        let t = tail.trim_start_matches([' ', '\t']);
        if t.len() == tail.len() {
            return false; // no whitespace after the crate name
        }
        t.strip_prefix("as")
            .is_some_and(|after| after.starts_with([' ', '\t']))
    })
}

/// The instance directory spellings a dual-compile has to name: `busbar-llm/`, `busbar-plane-mcp/`,
/// `busbar-transport-http/`, … — every one the tree derives, see [`super::vocab`].
fn names_plane_dir(s: &str, vocab: &Vocab) -> bool {
    vocab.dir_needles.iter().any(|d| s.contains(d.as_str()))
}

/// `#\[[[:space:]]*path[[:space:]]*=[[:space:]]*"[^"]*busbar-<instance>\/`
fn path_attr_include(code: &str, vocab: &Vocab) -> bool {
    let mut rest = code;
    while let Some(i) = rest.find("#[") {
        let t = rest[i + 2..].trim_start_matches([' ', '\t']);
        if let Some(t) = t.strip_prefix("path") {
            let t = t.trim_start_matches([' ', '\t']);
            if let Some(t) = t.strip_prefix('=') {
                let t = t.trim_start_matches([' ', '\t']);
                if let Some(t) = t.strip_prefix('"') {
                    let quoted = t.split('"').next().unwrap_or("");
                    if names_plane_dir(quoted, vocab) {
                        return true;
                    }
                }
            }
        }
        rest = &rest[i + 1..];
    }
    false
}

/// `include(_str|_bytes)?![[:space:]]*[({[][^)}\]]*"[^"]*busbar-<instance>\/` — the macro
/// dual-compile, the spelling that splices a plane's source in with no attribute at all.
fn macro_include(code: &str, vocab: &Vocab) -> bool {
    let mut rest = code;
    while let Some(i) = rest.find("include") {
        let mut t = &rest[i + "include".len()..];
        for suffix in ["_str", "_bytes"] {
            if let Some(s) = t.strip_prefix(suffix) {
                t = s;
                break;
            }
        }
        if let Some(t) = t.strip_prefix('!') {
            let t = t.trim_start_matches([' ', '\t']);
            if t.starts_with(['(', '{', '[']) {
                // every `"` reachable without crossing a closing delimiter opens a candidate literal
                let inner = &t[1..];
                for (off, c) in inner.char_indices() {
                    if c == ')' || c == '}' || c == ']' {
                        break;
                    }
                    if c == '"' {
                        let quoted = inner[off + 1..].split('"').next().unwrap_or("");
                        if names_plane_dir(quoted, vocab) {
                            return true;
                        }
                    }
                }
            }
        }
        rest = &rest[i + 1..];
    }
    false
}
