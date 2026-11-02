// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(dead_code)]

pub mod boot;
pub mod credentials;
pub mod lines;
pub mod otlp;
pub mod pinned_planes;
#[path = "../../../../crates/busbar/src/root/tests/test_plugins.rs"]
pub mod plugins;
pub mod root_install;
pub mod upstream;

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
            testdepth = (nopen - nclose).max(0);
            entered = testdepth > 0;
            pend = false;
        } else if pend && modword {
            testdepth = (nopen - nclose).max(0);
            entered = testdepth > 0;
            pend = false;
        } else if pend && !code.trim().is_empty() && !cfgtest {
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

pub fn production_text(path: &Path) -> String {
    production_lines(path)
        .iter()
        .map(|l| format!("{}\n", l.code))
        .collect()
}

pub fn is_test_path(path: &Path) -> bool {
    let p = path.to_string_lossy().replace('\\', "/");
    p.ends_with("_tests.rs")
        || p.ends_with("/tests.rs")
        || p.contains("/test_support")
        || p.contains("/tests/")
}

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

    Some(body)
}

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

pub fn is_test_attribute(code: &str) -> bool {
    let t = code.trim();
    t.starts_with("#[") && (t.contains("test]") || t.contains("test("))
}

pub fn asserts_directly(body: &[&Line]) -> bool {
    body.iter()
        .any(|l| ASSERTION_TOKENS.iter().any(|tok| l.code.contains(tok)))
}

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

pub fn operator_module() -> String {
    let row = manifest_table("package.metadata.busbar.operator-auth")
        .into_iter()
        .find(|(k, _)| k == "row")
        .map(|(_, v)| v)
        .expect("`[package.metadata.busbar.operator-auth]` states its `row`");
    manifest_table("package.metadata.busbar.linked-name")
        .into_iter()
        .find(|(k, _)| *k == row)
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("the operator row `{row}` has a `linked-name`"))
}

pub fn manifest_table(table: &str) -> Vec<(String, String)> {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("read dist/default/Cargo.toml");
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

pub fn enabled_features() -> std::collections::BTreeSet<&'static str> {
    env!("BUSBAR_ENABLED_FEATURES").split_whitespace().collect()
}

pub fn linked_plane_crates_own_entry() -> Vec<(String, String)> {
    let entries = manifest_table("package.metadata.busbar.linked-entry");
    linked_plane_crates()
        .into_iter()
        .filter(|(_, krate)| !entries.iter().any(|(k, _)| k == krate))
        .collect()
}
