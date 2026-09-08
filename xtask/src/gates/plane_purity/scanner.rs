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

/// The plane keys as the scanner spells them in a crate/dir name (`busbar-<key>`) and in a crate
/// identifier (`busbar_<key>`). Kept as literals rather than derived from [`crate::planes`]
/// because these are the awk alternations' contents and drift between the two would be silent.
pub const PLANE_ALTERNATION: [&str; 4] = ["llm", "mcp", "a2a", "voice"];

/// The 1.6.0 PLANE-CRATE identifiers — `busbar_plane_<p>` — as the SYMBOL row spells them.
///
/// SEPARATE FROM [`PLANE_ALTERNATION`] AND DELIBERATELY SO. That list drives the vocabulary rows
/// (TYPE/KEY/DIALECT), which match a BARE TOKEN; this one drives the SYMBOL row, which matches a
/// crate binding (`::`, `extern crate`, `use … as`). The two sets are not the same set and merging
/// them would be wrong in both directions:
///
///   * `admin` is a plane in 1.6.0 (`crates/busbar-plane-admin`) but `admin` is ALSO 1.5.5 config
///     and auth grammar — `auth.admin_auth:`, the `/admin` route prefix, `admin-tokens`. Putting it
///     in [`PLANE_ALTERNATION`] would turn every one of those frozen operator-visible words into a
///     KEY violation, which is not a boundary breach, it is the product's vocabulary.
///   * conversely, a neutral crate binding `busbar_plane_admin::` IS a boundary breach and nothing
///     else. A crate edge is unambiguous where a word is not.
///
/// WHY THIS MATTERS FOR THE CONFIG LAYER. The SYMBOL row previously spelled only `busbar_<p>` (the
/// legacy plane crates). `busbar_plane_llm::X` contains no `busbar_llm`, so a neutral crate — the
/// 1.5.5 config document root above all — could name a 1.6.0 plane crate and the gate stayed green.
/// That is precisely the edge the config layer must never grow: a config parser must never name a
/// plane. It is named here, and [`crate::gates::plane_purity::ROW_PLANE_CRATE_CENSUS`] refuses the
/// day this literal and the `crates/busbar-plane-*` directories disagree.
pub const PLANE_CRATE_ALTERNATION: [&str; 5] = ["llm", "mcp", "a2a", "voice", "admin"];

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

/// The six dialect names the DIALECT rule bans as whole words.
pub const DIALECTS: [&str; 6] = [
    "openai",
    "anthropic",
    "gemini",
    "bedrock",
    "cohere",
    "responses",
];

/// The named plane record types the TYPE rule bans outright.
const RECORD_TYPES: [&str; 4] = ["McpCallRecord", "McpDemotionRow", "TaskRow", "TaskEventRow"];

/// The CamelCase plane/dialect prefixes: a prefix followed by an uppercase letter is a plane- or
/// dialect-named type.
const CAMEL_PREFIXES: [&str; 11] = [
    "Mcp",
    "A2a",
    "A2A",
    "Llm",
    "Voice",
    "Openai",
    "Anthropic",
    "Gemini",
    "Bedrock",
    "Cohere",
    "Responses",
];

/// The SCREAMING/acronym spellings. `MCPCallRecord`, `OpenAIClient` and `LLMRouter` carried no
/// prefix the CamelCase list knew, and the KEY rule could not save them either: `word_ci` needs the
/// token to end at an identifier boundary, and in `mcpcallrecord` it does not. The
/// SCREAMING_SNAKE carve-out survives — `MCP_RUNTIME_SLOT` is `MCP` followed by `_`, not by an
/// uppercase letter, so it still does not match.
const SCREAMING_PREFIXES: [&str; 10] = [
    "MCP",
    "LLM",
    "VOICE",
    "OpenAI",
    "OPENAI",
    "ANTHROPIC",
    "GEMINI",
    "BEDROCK",
    "COHERE",
    "RESPONSES",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Scan NEUTRAL sources for the side channels reaching AROUND the ABI.
    Forward,
    /// Scan PLANE sources for the backwards reach into `busbar_core::` implementation.
    Reverse,
}

/// Which scope this pass reports. `Production` is the scan `--check` runs and is byte-identical to
/// the scanner before `--strict` existed; `Test` FLIPS the same gate rather than dropping it, so a
/// production pass and a test pass never double-count one hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Production,
    Test,
}

impl Scope {
    fn is_test_pass(self) -> bool {
        self == Scope::Test
    }
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

/// Scan one file list. Callers pass the WALK's output, so a missing root or a below-floor scan has
/// already been refused before a single line is read — the shell had to bolt both guards on in
/// front of `find` and this crate gets them from [`crate::ctx::WalkSpec`].
pub fn scan(files: &[SourceFile], mode: Mode, scope: Scope) -> Vec<Hit> {
    let mut out = Vec::new();
    for f in files {
        scan_file(&f.rel_str(), &f.text, mode, scope, &mut out);
    }
    out
}

fn scan_file(name: &str, text: &str, mode: Mode, scope: Scope, out: &mut Vec<Hit>) {
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
        let padded = format!(" {code} ");
        let lc = padded.to_lowercase();
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
        let counted_lc = format!(" {} ", counted.to_lowercase());
        let is_cfgtest = counted.contains("#[cfg(") && word_ci(&counted_lc, "test");
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

        let mut emit = |category: &'static str| {
            out.push(Hit {
                category,
                file: name.to_string(),
                line: lineno,
                code: code.trim().to_string(),
            });
        };

        if mode == Mode::Reverse {
            // No backwards reach: a plane crate must not name `busbar_core::` implementation items.
            // THE CRATE IS NAMED, NOT ONLY ITS PATHS — the two spellings that bind the crate with
            // no `::` on the line walked straight through the original rule, and either one
            // re-opens plane→core-internals wholesale.
            let reach = path_of(&code, "busbar_core")
                || extern_crate_of(&code, "busbar_core")
                || bound_as(&code, "busbar_core");
            if reach && (intest == scope.is_test_pass()) {
                emit("BACKWARDS");
            }
            continue;
        }

        // (a) PATH-INCLUDE — unconditional, test scope included: an instant fail wherever it lives,
        //     and NEVER excusable by the pragma below, because a dual-compile is structural and no
        //     config-freeze can justify it. Under a test pass it is restricted to test-scope hits
        //     so the two passes never double-count.
        let pathinclude = path_attr_include(&code) || macro_include(&code);
        if pathinclude && (!scope.is_test_pass() || intest) {
            emit("PATH-INCLUDE");
        }

        // (b)/(c): which scope THIS pass reports.
        if intest != scope.is_test_pass() {
            continue;
        }

        // (b) SYMBOL — a plane-crate symbol path, an `extern crate`, or a `use … as` that renames
        //     the crate out of this scanner's sight. Also never excusable: a frozen config FIELD or
        //     TYPE never requires naming a plane crate.
        // BOTH GENERATIONS OF PLANE CRATE. `busbar_<p>` is the legacy plane crate; `busbar_plane_<p>`
        // is the 1.6.0 pure-kind one, and it is NOT a substring of the former, so the original
        // spelling let a neutral crate bind a 1.6.0 plane with the gate green. Note this stays a
        // CRATE-BINDING test (`::`, `extern crate`, `use … as`), so the `busbar_plane_*` METRIC
        // FAMILY names core legitimately emits (`busbar_plane_requests_total`) are not hits: no
        // metric family name is followed by `::`.
        if PLANE_ALTERNATION
            .iter()
            .map(|p| format!("busbar_{p}"))
            .chain(
                PLANE_CRATE_ALTERNATION
                    .iter()
                    .map(|p| format!("busbar_plane_{p}")),
            )
            .any(|krate| {
                path_of(&code, &krate) || extern_crate_of(&code, &krate) || bound_as(&code, &krate)
            })
        {
            emit("SYMBOL");
        }

        // THE FROZEN-WIRE CARVE-OUT: exempt from the VOCABULARY rules ONLY, and only below the two
        // structural rules above.
        if frozen {
            continue;
        }

        // (c3) TYPE — checked before the bare-key rule so `McpFoo` reads as TYPE, not KEY.
        if RECORD_TYPES.iter().any(|t| bare_word(&code, t))
            || CAMEL_PREFIXES.iter().any(|p| prefix_then_upper(&code, p))
            || SCREAMING_PREFIXES
                .iter()
                .any(|p| prefix_then_upper(&code, p))
        {
            emit("TYPE");
        }

        // (c1) KEY — a concrete plane key as a bare token. Word-boundary, so it does NOT match
        //      inside `busbar_mcp` / `plane_mcp` / `MCP_RUNTIME_SLOT`: `_` is not a boundary.
        if PLANE_ALTERNATION.iter().any(|k| word_ci(&lc, k)) {
            emit("KEY");
        }

        // (c2) DIALECT — one of the six dialect names as a token.
        if DIALECTS.iter().any(|d| word_ci(&lc, d)) {
            emit("DIALECT");
        }
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
    let chars: Vec<char> = line.chars().collect();
    let mut res = String::with_capacity(line.len());
    let mut i = 0;
    let mut in_str = false;
    while i < chars.len() {
        let c = chars[i];
        let two = |i: usize| -> String { chars[i..(i + 2).min(chars.len())].iter().collect() };
        if *in_block {
            if two(i) == "*/" {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if in_str {
            res.push(c);
            if c == '\\' {
                if let Some(n) = chars.get(i + 1) {
                    res.push(*n);
                }
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if two(i) == "/*" {
            *in_block = true;
            i += 2;
            continue;
        }
        if two(i) == "//" {
            break;
        }
        if c == '"' {
            in_str = true;
            res.push(c);
            i += 1;
            continue;
        }
        res.push(c);
        i += 1;
    }
    res
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
    let b: Vec<char> = code.chars().collect();
    for i in 0..b.len() {
        if b[i..].starts_with(&['m', 'o', 'd']) {
            let before_ok = i == 0 || !is_ident(b[i - 1]);
            let after = b.get(i + 3);
            if before_ok && after.is_some_and(|c| !is_ident(*c)) {
                return true;
            }
        }
    }
    false
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The awk's `[^a-z0-9_]` identifier boundary, applied to the LOWERCASED, space-padded line.
fn is_ident_lc(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
}

/// `function word_ci(lc, needle) { return (lc ~ ("[^a-z0-9_]" needle "[^a-z0-9_]")) }` — a
/// whole-word, case-insensitive hit of a lowercase needle in the padded lowercased line.
pub fn word_ci(lc: &str, needle: &str) -> bool {
    let hay: Vec<char> = lc.chars().collect();
    let nee: Vec<char> = needle.chars().collect();
    if nee.is_empty() || hay.len() < nee.len() + 2 {
        return false;
    }
    for i in 1..=(hay.len() - nee.len() - 1) {
        if hay[i..i + nee.len()] == nee[..]
            && !is_ident_lc(hay[i - 1])
            && !is_ident_lc(hay[i + nee.len()])
        {
            return true;
        }
    }
    false
}

/// `(^|[^A-Za-z0-9_])<word>([^A-Za-z0-9_]|$)` over the un-lowercased line.
fn bare_word(code: &str, word: &str) -> bool {
    let b: Vec<char> = code.chars().collect();
    let w: Vec<char> = word.chars().collect();
    if w.is_empty() || b.len() < w.len() {
        return false;
    }
    for i in 0..=(b.len() - w.len()) {
        if b[i..i + w.len()] == w[..]
            && (i == 0 || !is_ident(b[i - 1]))
            && b.get(i + w.len()).is_none_or(|c| !is_ident(*c))
        {
            return true;
        }
    }
    false
}

/// `(^|[^A-Za-z0-9_])<prefix>[A-Z][A-Za-z0-9_]*` — a prefix at an identifier boundary followed by
/// an UPPERCASE letter. The trailing `[A-Za-z0-9_]*` matches zero-width, so the uppercase letter is
/// the whole requirement, and that is what keeps `MCP_RUNTIME_SLOT` out.
fn prefix_then_upper(code: &str, prefix: &str) -> bool {
    let b: Vec<char> = code.chars().collect();
    let p: Vec<char> = prefix.chars().collect();
    if p.is_empty() || b.len() <= p.len() {
        return false;
    }
    for i in 0..=(b.len() - p.len() - 1) {
        if b[i..i + p.len()] == p[..]
            && (i == 0 || !is_ident(b[i - 1]))
            && b[i + p.len()].is_ascii_uppercase()
        {
            return true;
        }
    }
    false
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
    let b: Vec<char> = code.chars().collect();
    for i in 0..b.len() {
        if !b[i..].starts_with(&['e', 'x', 't', 'e', 'r', 'n']) {
            continue;
        }
        if i > 0 && is_ident(b[i - 1]) {
            continue;
        }
        let tail: String = b[i + "extern".len()..].iter().collect();
        let Some(t) = strip_required_space(&tail) else {
            continue;
        };
        let Some(t) = t.strip_prefix("crate") else {
            continue;
        };
        let Some(t) = strip_required_space(t) else {
            continue;
        };
        let Some(after) = t.strip_prefix(krate) else {
            continue;
        };
        if after.chars().next().is_none_or(|c| !is_ident(c)) {
            return true;
        }
    }
    false
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
    let b: Vec<char> = code.chars().collect();
    let k: Vec<char> = krate.chars().collect();
    if b.len() < k.len() {
        return false;
    }
    for i in 0..=(b.len() - k.len()) {
        if b[i..i + k.len()] != k[..] || (i > 0 && is_ident(b[i - 1])) {
            continue;
        }
        let tail: String = b[i + k.len()..].iter().collect();
        let t = tail.trim_start_matches([' ', '\t']);
        if t.len() == tail.len() {
            continue; // no whitespace after the crate name
        }
        if let Some(after) = t.strip_prefix("as") {
            if after.starts_with([' ', '\t']) {
                return true;
            }
        }
    }
    false
}

/// The plane directory spellings a dual-compile has to name: `busbar-llm/`, `busbar-mcp/`, …
fn names_plane_dir(s: &str) -> bool {
    PLANE_ALTERNATION
        .iter()
        .any(|p| s.contains(&format!("busbar-{p}/")))
}

/// `#\[[[:space:]]*path[[:space:]]*=[[:space:]]*"[^"]*busbar-(llm|mcp|a2a|voice)\/`
fn path_attr_include(code: &str) -> bool {
    let mut rest = code;
    while let Some(i) = rest.find("#[") {
        let t = rest[i + 2..].trim_start_matches([' ', '\t']);
        if let Some(t) = t.strip_prefix("path") {
            let t = t.trim_start_matches([' ', '\t']);
            if let Some(t) = t.strip_prefix('=') {
                let t = t.trim_start_matches([' ', '\t']);
                if let Some(t) = t.strip_prefix('"') {
                    let quoted = t.split('"').next().unwrap_or("");
                    if names_plane_dir(quoted) {
                        return true;
                    }
                }
            }
        }
        rest = &rest[i + 1..];
    }
    false
}

/// `include(_str|_bytes)?![[:space:]]*[({[][^)}\]]*"[^"]*busbar-(llm|mcp|a2a|voice)\/` — the macro
/// dual-compile, the spelling that splices a plane's source in with no attribute at all.
fn macro_include(code: &str) -> bool {
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
                        if names_plane_dir(quoted) {
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
