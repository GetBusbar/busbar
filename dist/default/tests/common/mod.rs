// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub mod boot;
pub mod chat_spend;
pub mod credentials;
pub mod fresh_namespace;
pub mod lines;
pub mod migration_rows;
pub mod otlp;
pub mod pinned_planes;
#[path = "../../../../crates/busbar/src/root/tests/test_plugins.rs"]
pub mod plugins;
pub mod upstream;

use std::path::Path;

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
        if (cfgtest || pend) && modword {
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

fn is_test_path(path: &Path) -> bool {
    let p = path.to_string_lossy().replace('\\', "/");
    p.ends_with("_tests.rs")
        || p.ends_with("/tests.rs")
        || p.contains("/test_support")
        || p.contains("/tests/")
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
