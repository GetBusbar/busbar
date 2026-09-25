// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT THE SHIPPED BINARY ACTUALLY CONTAINS — the one source classifier the composition root's
//! scanning gates share.
//!
//! A gate that answers a question about production code by reading a `.rs` file whole is not
//! answering that question. Every crate in this tree keeps its unit tests in the same file as the
//! code they exercise, inside `#[cfg(test)] mod tests { … }`, and that block is not in the shipped
//! binary. So a scan that reads the file whole is satisfied by a token that appears ONLY in a test
//! — including a token the test wrote precisely because it was mocking the production path that is
//! missing. The gate then reports the property holds while the property is absent, which is the
//! exact failure a gate exists to prevent.
//!
//! The construction gate already had the right answer, in Python: `scripts/construction-gate/
//! rules.py` carries a `scan_file` that strips comments (respecting string literals, so a `//`
//! inside a string is not a comment), blanks literal contents (so a brace inside a string does not
//! disturb structure matching), and tracks `#[cfg(test)] mod` depth so every line inside a test
//! module is flagged. This is that classifier, in Rust, with the same rules — so the two gates
//! agree about what "production" means rather than each having a private opinion.
//!
//! [`Line::intest`] is the whole point. Everything else here exists to compute it correctly.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// One classified source line.
#[derive(Debug, Clone)]
pub struct Line {
    /// 1-based line number in the file it came from.
    pub no: usize,
    /// The line with comments removed and string literals left intact.
    pub code: String,
    /// The same with string/char literal CONTENTS blanked, so braces and parens inside a literal
    /// do not disturb structure matching.
    pub blank: String,
    /// True when this line is test code: a `#[cfg(test)] mod` body, or a test file.
    pub intest: bool,
}

/// Strip `//`-to-EOL and `/* … */` (which may span lines via `in_block`) while leaving string
/// literals intact. Same rules as the construction gate's `strip_comments`.
fn strip_comments(line: &str, in_block: &mut bool) -> String {
    let b: Vec<char> = line.chars().collect();
    let mut out = String::new();
    let mut i = 0usize;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        let c2: String = b[i..(i + 2).min(b.len())].iter().collect();
        if *in_block {
            if c2 == "*/" {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if in_str {
            out.push(c);
            if c == '\\' {
                if let Some(n) = b.get(i + 1) {
                    out.push(*n);
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
        if c2 == "/*" {
            *in_block = true;
            i += 2;
            continue;
        }
        if c2 == "//" {
            break;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Replace string and char literal contents with spaces. Lifetimes (`'a`) are not char literals
/// and are left alone — the same carve-out `rules.py`'s `blank_literals` makes.
fn blank_literals(code: &str) -> String {
    let b: Vec<char> = code.chars().collect();
    let mut out = String::with_capacity(code.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == '"' {
            out.push('"');
            i += 1;
            while i < b.len() && b[i] != '"' {
                if b[i] == '\\' {
                    out.push(' ');
                    i += 1;
                }
                if i < b.len() {
                    out.push(' ');
                    i += 1;
                }
            }
            if i < b.len() {
                out.push('"');
                i += 1;
            }
            continue;
        }
        // `'x'` and `'\x'` are char literals; `'a` followed by anything else is a lifetime.
        if b[i] == '\'' {
            let esc = b.get(i + 1) == Some(&'\\');
            let close = if esc { i + 3 } else { i + 2 };
            if b.get(close) == Some(&'\'') {
                out.push('\'');
                out.push(' ');
                out.push('\'');
                i = close + 1;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// True when `code` carries a `#[cfg(...)]` whose predicate names `test` as a whole word.
fn is_cfg_test(code: &str) -> bool {
    if !code.contains("#[cfg(") {
        return false;
    }
    let padded = format!(" {} ", code.to_lowercase());
    let bytes: Vec<char> = padded.chars().collect();
    for i in 0..bytes.len().saturating_sub(5) {
        if bytes[i + 1..i + 5].iter().collect::<String>() == "test" {
            let before = bytes[i];
            let after = bytes[i + 5];
            let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
            if !word(before) && !word(after) {
                return true;
            }
        }
    }
    false
}

/// True when `code` uses `mod` as a whole word.
fn has_mod_word(code: &str) -> bool {
    let bytes: Vec<char> = format!(" {code} ").chars().collect();
    for i in 0..bytes.len().saturating_sub(4) {
        if bytes[i + 1..i + 4].iter().collect::<String>() == "mod" {
            let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
            if !word(bytes[i]) && !word(bytes[i + 4]) {
                return true;
            }
        }
    }
    false
}

/// Classify one source text. `is_test_file` marks the whole file as test code up front (an
/// integration test, a `_tests.rs`, a `test_support` module).
pub fn classify(src: &str, is_test_file: bool) -> Vec<Line> {
    let mut in_block = false;
    let mut testdepth: i64 = 0;
    let mut pend = false;
    let mut out = Vec::new();
    for (idx, raw) in src.lines().enumerate() {
        let code = strip_comments(raw, &mut in_block);
        let blank = blank_literals(&code);
        let nopen = blank.matches('{').count() as i64;
        let nclose = blank.matches('}').count() as i64;
        let cfgtest = is_cfg_test(&code);
        let modword = has_mod_word(&code);
        let mut entered = false;
        if cfgtest && modword {
            // `#[cfg(test)] mod tests {` on one line.
            testdepth = (nopen - nclose).max(0);
            entered = testdepth > 0;
            pend = false;
        } else if pend && modword {
            // `#[cfg(test)]` on its own line, `mod tests {` on the next.
            testdepth = (nopen - nclose).max(0);
            entered = testdepth > 0;
            pend = false;
        } else if pend && !code.trim().is_empty() && !cfgtest {
            // The `#[cfg(test)]` gated something that was not a module; it is not a test body.
            pend = false;
        } else if testdepth > 0 {
            testdepth = (testdepth + nopen - nclose).max(0);
        }
        if cfgtest && !modword {
            pend = true;
        }
        out.push(Line {
            no: idx + 1,
            code,
            blank,
            intest: is_test_file || testdepth > 0 || entered,
        });
    }
    out
}

/// The production lines of a file on disk: comments stripped, `#[cfg(test)]` module bodies gone.
/// A file that cannot be read yields nothing, which every caller treats as "reaches nothing" —
/// the safe direction for a gate.
pub fn production_lines(path: &Path) -> Vec<Line> {
    let Ok(src) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let is_test_file = is_test_path(path);
    classify(&src, is_test_file)
        .into_iter()
        .filter(|l| !l.intest)
        .collect()
}

/// The production TEXT of a file on disk, one line per line, comments and test modules removed.
pub fn production_text(path: &Path) -> String {
    production_lines(path)
        .iter()
        .map(|l| format!("{}\n", l.code))
        .collect()
}

/// Whether a path is a test file in its entirety, by the same fragments the plane gates use.
pub fn is_test_path(path: &Path) -> bool {
    let p = path.to_string_lossy().replace('\\', "/");
    p.ends_with("_tests.rs")
        || p.ends_with("/tests.rs")
        || p.contains("/test_support")
        || p.contains("/tests/")
}

/// Every `.rs` file under `dir` that is production source, skipping `target/` and `tests/` trees.
pub fn production_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name == "tests" {
                continue;
            }
            production_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") && !is_test_path(&path) {
            out.push(path);
        }
    }
}

/// THE BODY OF ONE ITEM, by brace matching over production lines.
///
/// Gates that ask "does this function reach that seam" must ask it of the FUNCTION, not of the file
/// the function happens to live in: a file-wide scan is satisfied by any other function in the same
/// file, which is how a step that reaches nothing passes a gate that says it reaches something.
///
/// Returns the production lines from the one whose `code` contains `signature` through the line
/// that closes its body, or `None` when no line carries the signature.
pub fn item_body<'a>(lines: &'a [Line], signature: &str) -> Option<Vec<&'a Line>> {
    let start = lines.iter().position(|l| l.code.contains(signature))?;
    let mut depth: i64 = 0;
    let mut seen_open = false;
    let mut body = Vec::new();
    for line in &lines[start..] {
        body.push(line);
        depth += line.blank.matches('{').count() as i64;
        if line.blank.contains('{') {
            seen_open = true;
        }
        depth -= line.blank.matches('}').count() as i64;
        if seen_open && depth <= 0 {
            return Some(body);
        }
    }
    // An unterminated body is a parse failure, not a pass: hand back what was found so the caller
    // scans it, rather than silently reporting the item absent.
    Some(body)
}

// ---------------------------------------------------------------------------
// WHAT COUNTS AS A TEST THAT WAS WATCHED — shared by every gate that accepts a named test as
// evidence (`capability_equality.rs`'s proven cells, `field_coverage.rs`'s carried fields).
//
// A named function is evidence only when it is (1) TEST CODE, (2) a TEST the harness runs, and
// (3) a body that ASSERTS something, directly or one hop into a same-file helper. A gate that
// checked only that `fn NAME(` appears somewhere accepts a production helper, a `fn` quoted in a
// doc comment and an empty body alike; one copy of the rule is what keeps two gates from holding
// two different bars.
// ---------------------------------------------------------------------------

/// What an assertion looks like. `expect`/`unwrap` are deliberately NOT here: they say a value was
/// the shape the test assumed, which is a precondition, not the thing under test.
pub const ASSERTION_TOKENS: &[&str] = &[
    "assert!",
    "assert_eq!",
    "assert_ne!",
    "assert_matches!",
    "debug_assert!",
    "debug_assert_eq!",
    "debug_assert_ne!",
    "expect_err(",
    "unwrap_err(",
];

/// Whether an attribute line marks the item below it as a test the harness runs. `#[test]`,
/// `#[tokio::test]`, `#[tokio::test(flavor = "…")]` and `#[rstest]` all satisfy it.
pub fn is_test_attribute(code: &str) -> bool {
    let t = code.trim();
    t.starts_with("#[") && (t.contains("test]") || t.contains("test("))
}

/// Whether a body — a slice of classified lines — asserts anything itself.
pub fn asserts_directly(body: &[&Line]) -> bool {
    body.iter()
        .any(|l| ASSERTION_TOKENS.iter().any(|tok| l.code.contains(tok)))
}

/// The bare identifiers a body CALLS, so one hop into a same-file helper can be followed. Crude on
/// purpose: this is used only to widen what counts as asserting, never to narrow it.
pub fn called_idents(body: &[&Line]) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for line in body {
        let chars: Vec<char> = line.code.chars().collect();
        let mut i = 0usize;
        while i < chars.len() {
            if chars[i] == '(' {
                let mut j = i;
                while j > 0 && (chars[j - 1].is_ascii_alphanumeric() || chars[j - 1] == '_') {
                    j -= 1;
                }
                if j < i && !chars[j].is_ascii_digit() {
                    out.insert(chars[j..i].iter().collect::<String>());
                }
            }
            i += 1;
        }
    }
    out
}

/// Whether the item whose signature is on line `at` carries a test attribute in the attribute block
/// directly above it.
pub fn has_test_attribute(lines: &[Line], at: usize) -> bool {
    let mut i = at;
    while i > 0 {
        i -= 1;
        let code = lines[i].code.trim();
        if code.is_empty() {
            continue;
        }
        if code.starts_with("#[") || code.starts_with("#!") {
            if is_test_attribute(code) {
                return true;
            }
            continue;
        }
        // Anything else is the previous item; the attribute block is over.
        return false;
    }
    false
}

/// Why a named function is not evidence, in the order the three checks run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotEvidence {
    /// No `fn NAME(` in the code (comments stripped) of any file searched.
    Absent,
    /// Only in production code: outside every `#[cfg(test)]` module and not in a test file.
    Production,
    /// Test code, but no test attribute: a helper the harness never runs.
    NotATest,
    /// A test whose body asserts nothing, directly or one hop down.
    AssertsNothing,
}

/// THE EVIDENCE CHECK over a set of classified files: `Ok` when at least one `fn NAME(` is a test
/// that asserts; otherwise the furthest any occurrence got, so the failure names the real gap.
pub fn test_fn_is_evidence(files: &[Vec<Line>], func: &str) -> Result<(), NotEvidence> {
    let sig = format!("fn {func}(");
    let mut best = NotEvidence::Absent;
    let rank = |n: NotEvidence| match n {
        NotEvidence::Absent => 0,
        NotEvidence::Production => 1,
        NotEvidence::NotATest => 2,
        NotEvidence::AssertsNothing => 3,
    };
    for lines in files {
        for (at, line) in lines.iter().enumerate() {
            // The name must be the whole identifier: `fn NAME(` inside `fn XNAME(` is not it.
            let Some(col) = line.code.find(&sig) else {
                continue;
            };
            if line.code[..col]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                continue;
            }
            let verdict = if !line.intest {
                NotEvidence::Production
            } else if !has_test_attribute(lines, at) {
                NotEvidence::NotATest
            } else if !body_asserts_at(lines, at, &sig) {
                NotEvidence::AssertsNothing
            } else {
                return Ok(());
            };
            if rank(verdict) > rank(best) {
                best = verdict;
            }
        }
    }
    Err(best)
}

/// Whether the occurrence of `signature` on line `at` asserts — directly, or through helpers in
/// the same file, followed to any depth. Read from `at` so the body is THIS occurrence's, not the
/// file's first. Any depth rather than one hop because a matrix test commonly delegates twice
/// (`roundtrip_x()` → `assert_request_roundtrip()` → `assert_divergences()`); the helpers must still
/// live in the same file, so a name that merely matches something elsewhere cannot vouch for it.
pub fn body_asserts_at(lines: &[Line], at: usize, signature: &str) -> bool {
    let Some(body) = item_body(&lines[at..], signature) else {
        return false;
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut queue = vec![body];
    while let Some(body) = queue.pop() {
        if asserts_directly(&body) {
            return true;
        }
        for callee in called_idents(&body) {
            if seen.insert(callee.clone()) {
                if let Some(helper) = item_body(lines, &format!("fn {callee}(")) {
                    queue.push(helper);
                }
            }
        }
    }
    false
}

// ── THE PLUGIN VOCABULARY IS DATA ─────────────────────────────────────────────────────────────────
// "A plugin tests itself; the kernel never tests or names a plugin." A scanning gate here still has
// to know WHICH plugin crates and plugin-owned files to read, so that knowledge lives as data: the
// linked-plugin table the composition root itself folds (`[package.metadata.busbar.linked]` /
// `linked-axes` in this crate's Cargo.toml), and, for the plugin-owned files a gate pins, a fixture
// beside the test (`tests/fixtures/*.txt`). The test source spells neither.

/// The lines of `crates/busbar/tests/fixtures/<name>`: trimmed; blank lines and lines starting with `#`
/// dropped (a `#` inside a line is data).
/// An absent or empty fixture is a failure, never an empty list (an empty list scans nothing and
/// passes).
pub fn fixture_lines(name: &str) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    let lines: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert!(!lines.is_empty(), "fixture {} is empty", path.display());
    lines
}

/// `[table]` rows `key = "value"` of this crate's Cargo.toml, in file order (the same shape
/// `src/linked_gen.rs` reads). An absent or empty table is a failure.
pub fn manifest_table(table: &str) -> Vec<(String, String)> {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("read crates/busbar/Cargo.toml");
    let header = format!("[{table}]");
    let mut in_table = false;
    let mut rows = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == header;
            continue;
        }
        if in_table {
            if let Some((k, v)) = code.split_once('=') {
                rows.push((
                    k.trim().trim_matches('"').to_string(),
                    v.trim().trim_matches('"').to_string(),
                ));
            }
        }
    }
    assert!(
        !rows.is_empty(),
        "Cargo.toml: `{header}` is missing or empty"
    );
    rows
}

/// Every LINKED crate whose linked row carries the `plane` axis — the planes this binary links, as
/// `(feature, crate directory under crates/)`, in manifest order.
pub fn linked_plane_crates() -> Vec<(String, String)> {
    let axes = manifest_table("package.metadata.busbar.linked-axes");
    manifest_table("package.metadata.busbar.linked")
        .into_iter()
        .filter(|(feature, _)| {
            axes.iter()
                .any(|(f, a)| f == feature && a.split_whitespace().any(|x| x == "plane"))
        })
        .collect()
}

/// The rows of `tests/fixtures/plane_doctrine.txt` whose first word is `kind`, each the remaining
/// whitespace-split words, leaked once (the doctrine is pinned for the process's life).
pub fn doctrine_rows(kind: &str) -> Vec<Vec<&'static str>> {
    static ROWS: std::sync::OnceLock<Vec<Vec<&'static str>>> = std::sync::OnceLock::new();
    ROWS.get_or_init(|| {
        fixture_lines("plane_doctrine.txt")
            .into_iter()
            .map(|l| {
                let l: &'static str = Box::leak(l.into_boxed_str());
                l.split_whitespace().collect()
            })
            .collect()
    })
    .iter()
    .filter(|r| r[0] == kind)
    .map(|r| r[1..].to_vec())
    .collect()
}

/// The cargo features this build enabled (build.rs publishes them as `BUSBAR_ENABLED_FEATURES`).
pub fn enabled_features() -> std::collections::BTreeSet<&'static str> {
    env!("BUSBAR_ENABLED_FEATURES").split_whitespace().collect()
}

/// THE ROOT LEGS THIS BUILD CARRIES: each doctrine `root-leg <leg> <feature>` row whose feature is
/// enabled. The mcp and a2a legs are the kernel-loop rider those planes are SERVED through, so the
/// feature that links the plane gates them, not a `root-*` feature of their own.
pub fn compiled_root_legs() -> std::collections::BTreeSet<&'static str> {
    let on = enabled_features();
    doctrine_rows("root-leg")
        .into_iter()
        .filter(|r| on.contains(r[1]))
        .map(|r| r[0])
        .collect()
}

/// [`linked_plane_crates`] whose entry module is the crate's OWN `linked` module (no
/// `[package.metadata.busbar.linked-entry]` row) — the planes whose code lives in their own crate,
/// not in a composition-root module.
pub fn linked_plane_crates_own_entry() -> Vec<(String, String)> {
    let entries = manifest_table("package.metadata.busbar.linked-entry");
    linked_plane_crates()
        .into_iter()
        .filter(|(_, krate)| !entries.iter().any(|(k, _)| k == krate))
        .collect()
}
