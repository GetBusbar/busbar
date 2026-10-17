// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO TEST IN THIS CRATE PASSES BY SKIPPING ITS SUBJECT (status row 114). An instrument that cannot
//! produce a NO is not a check, and when an instrument must choose, it false-fails
//! (BUSBAR-1.6.0.md): a test whose subject is absent fails, it never returns early and reports `ok`.
//!
//! A scan over this crate's own test sources — every `.rs` under a `tests/` directory (in `src/`
//! or the crate's `tests/`) and every `src/` file named `*_tests.rs` or `tests.rs`, this file
//! excluded — fails, naming `file:line`, on:
//!
//! * (a) a `println!`/`eprintln!` whose literal starts `skip:` or `SKIP`;
//! * (b) a `CI` environment probe (`var_os("CI")` / `var("CI")`): the switch that made a guard fatal
//!   under CI and silent everywhere else;
//! * (c) an `if` or let-else guard on a subject probe (`auth_cdylib`, `write_auth_plugin`, an
//!   absolute `Path::new("/`, `var("HOME")`, `read_dir(&dir).is_ok()`) whose body is nothing but
//!   comments, prints and a bare `return;`.
//!
//! Comments are blanked before the scan, so prose that names these shapes is not a finding.

use std::path::{Path, PathBuf};

/// Files the scan must reach, so a walk that silently found nothing cannot pass.
const MUST_COVER: &[&str] = &[
    "src/auth/tests/plugin_chain_tests.rs",
    "src/plane_host/pipe_tests.rs",
];

/// The probes whose early-return guard is a skip (rule c).
const SUBJECTS: &[&str] = &[
    "auth_cdylib",
    "write_auth_plugin",
    "Path::new(\"/",
    "var(\"HOME\")",
    "read_dir(&dir).is_ok()",
];

const RULE_A: &str = "(a) a `skip:` print";
const RULE_B: &str = "(b) a CI probe";
const RULE_C: &str = "(c) an early-return guard on an absent subject";

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The crate's test sources, this file excluded.
fn test_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, under_tests: bool, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .map(|e| e.expect("a directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_owned();
            if path.is_dir() {
                walk(&path, under_tests || name == "tests", out);
            } else if name.ends_with(".rs")
                && (under_tests || name == "tests.rs" || name.ends_with("_tests.rs"))
            {
                out.push(path);
            }
        }
    }
    let root = crate_root();
    let mut out = Vec::new();
    walk(&root.join("src"), false, &mut out);
    walk(&root.join("tests"), true, &mut out);
    let me = root.join("tests").join("no_silent_skip.rs");
    out.retain(|p| *p != me);
    out
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// If a string, raw string or char literal starts at `i`, the index just past it.
fn literal_end(b: &[u8], i: usize) -> Option<usize> {
    match b[i] {
        b'"' => {
            let mut j = i + 1;
            while j < b.len() {
                match b[j] {
                    b'\\' => j += 2,
                    b'"' => return Some(j + 1),
                    _ => j += 1,
                }
            }
            Some(b.len())
        }
        b'r' if i == 0
            || !is_ident(b[i - 1])
            || (b[i - 1] == b'b' && (i < 2 || !is_ident(b[i - 2]))) =>
        {
            let mut j = i + 1;
            while b.get(j) == Some(&b'#') {
                j += 1;
            }
            if b.get(j) != Some(&b'"') {
                return None;
            }
            let hashes = j - i - 1;
            j += 1;
            while j < b.len() {
                if b[j] == b'"'
                    && b[j + 1..]
                        .iter()
                        .take(hashes)
                        .filter(|&&c| c == b'#')
                        .count()
                        == hashes
                {
                    return Some(j + 1 + hashes);
                }
                j += 1;
            }
            Some(b.len())
        }
        b'\'' => {
            if b.get(i + 1) == Some(&b'\\') {
                // Past the escaped character itself, so `'\''` ends at its own closing quote.
                let mut j = i + 3;
                while j < b.len() && b[j] != b'\'' {
                    j += 1;
                }
                return Some(j + 1);
            }
            let lead = *b.get(i + 1)?;
            let width = match lead {
                0x00..=0x7f => 1,
                0xc0..=0xdf => 2,
                0xe0..=0xef => 3,
                _ => 4,
            };
            (b.get(i + 1 + width) == Some(&b'\'')).then_some(i + 2 + width)
        }
        _ => None,
    }
}

/// `src` with every comment blanked to spaces; newlines and literals are kept, so offsets and line
/// numbers hold.
fn mask_comments(src: &str) -> Vec<u8> {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                out[i] = b' ';
                i += 1;
            }
        } else if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    out[i] = b' ';
                    out[i + 1] = b' ';
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    out[i] = b' ';
                    out[i + 1] = b' ';
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if b[i] != b'\n' {
                        out[i] = b' ';
                    }
                    i += 1;
                }
            }
        } else if let Some(end) = literal_end(b, i) {
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

fn find_all(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    hay.windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .collect()
}

fn skip_ws(m: &[u8], mut i: usize) -> usize {
    while i < m.len() && m[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// The index of the bracket closing the one at `open`, skipping literals.
fn matching(m: &[u8], open: usize) -> Option<usize> {
    let close = match m[open] {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        _ => return None,
    };
    let mut depth = 0usize;
    let mut i = open;
    while i < m.len() {
        if let Some(end) = literal_end(m, i) {
            i = end;
            continue;
        }
        if m[i] == m[open] {
            depth += 1;
        } else if m[i] == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// When the subject at `pos` is the condition of an `if` or the scrutinee of a let-else, the
/// guard's body (between its braces).
fn guard_body(m: &[u8], pos: usize) -> Option<std::ops::Range<usize>> {
    let start = m[..pos]
        .iter()
        .rposition(|&c| matches!(c, b';' | b'{' | b'}'))
        .map_or(0, |i| i + 1);
    let mut head = &m[skip_ws(m, start)..pos];
    if let Some(rest) = head.strip_prefix(b"else") {
        head = &rest[skip_ws(rest, 0)..];
    }
    let is_if = head.starts_with(b"if ") || head.starts_with(b"if!") || head.starts_with(b"if(");
    let is_let = head.starts_with(b"let ");
    if !is_if && !is_let {
        return None;
    }
    let mut i = pos;
    let open = loop {
        if i >= m.len() {
            return None;
        }
        if let Some(end) = literal_end(m, i) {
            i = end;
            continue;
        }
        match m[i] {
            b';' => return None,
            b'{' => break i,
            _ => i += 1,
        }
    };
    if is_let && !m[pos..open].trim_ascii_end().ends_with(b"else") {
        return None;
    }
    Some(open + 1..matching(m, open)?)
}

/// Whether a guard body is nothing but prints and a bare `return;` (comments are already blank).
fn is_bare_skip(m: &[u8], body: std::ops::Range<usize>) -> bool {
    const PRINTS: &[&[u8]] = &[b"eprintln!", b"println!", b"eprint!", b"print!"];
    let mut i = body.start;
    let mut returns = false;
    loop {
        i = skip_ws(m, i);
        if i >= body.end {
            return returns;
        }
        let rest = &m[i..body.end];
        if let Some(print) = PRINTS.iter().find(|p| rest.starts_with(p)) {
            let open = skip_ws(m, i + print.len());
            let Some(close) = (open < body.end).then(|| matching(m, open)).flatten() else {
                return false;
            };
            i = skip_ws(m, close + 1);
            if m.get(i) == Some(&b';') {
                i += 1;
            }
        } else if rest.starts_with(b"return") {
            let after = skip_ws(m, i + b"return".len());
            if after < body.end && m[after] != b';' {
                return false;
            }
            returns = true;
            i = after + 1;
        } else {
            return false;
        }
    }
}

/// Every finding in one source: its 1-based line and its rule.
fn scan(src: &str) -> Vec<(usize, &'static str)> {
    let m = mask_comments(src);
    let line_of = |pos: usize| m[..pos].iter().filter(|&&c| c == b'\n').count() + 1;
    let mut found = Vec::new();

    for pos in find_all(&m, b"println!") {
        let open = skip_ws(&m, pos + b"println!".len());
        if !matches!(m.get(open), Some(b'(' | b'[' | b'{')) {
            continue;
        }
        let lit = skip_ws(&m, open + 1);
        if m.get(lit) == Some(&b'"')
            && (m[lit + 1..].starts_with(b"skip:") || m[lit + 1..].starts_with(b"SKIP"))
        {
            found.push((line_of(pos), RULE_A));
        }
    }
    for probe in [&b"var_os(\"CI\")"[..], &b"var(\"CI\")"[..]] {
        for pos in find_all(&m, probe) {
            found.push((line_of(pos), RULE_B));
        }
    }
    for subject in SUBJECTS {
        for pos in find_all(&m, subject.as_bytes()) {
            if guard_body(&m, pos).is_some_and(|body| is_bare_skip(&m, body)) {
                found.push((line_of(pos), RULE_C));
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

#[test]
fn no_test_in_this_crate_passes_by_skipping_its_subject() {
    let root = crate_root();
    let sources = test_sources();
    for must in MUST_COVER {
        assert!(
            sources.iter().any(|p| p.ends_with(must)),
            "the scan must cover {must}; it walked {} files",
            sources.len()
        );
    }
    let mut findings = Vec::new();
    for path in &sources {
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let lines: Vec<&str> = src.lines().collect();
        let rel = path.strip_prefix(&root).unwrap_or(path).display();
        for (line, rule) in scan(&src) {
            let text = lines.get(line - 1).map_or("", |l| l.trim());
            findings.push(format!("{rel}:{line}: {rule}: {text}"));
        }
    }
    assert!(
        findings.is_empty(),
        "{} test-source site(s) pass by skipping an absent subject; each must be a hard failure \
         (status row 114):\n{}",
        findings.len(),
        findings.join("\n")
    );
}

/// The scan can say NO: every skip shape it names is found, and the hard-failure forms that
/// replace them are not.
#[test]
fn the_scan_finds_every_skip_shape_and_passes_the_hard_failures() {
    let skips: &[(&str, &str)] = &[
        ("eprintln!(\"skip: not built\");", RULE_A),
        ("println!(\n    \"SKIP the rest\"\n);", RULE_A),
        ("if std::env::var_os(\"CI\").is_some() { panic!(); }", RULE_B),
        ("let ci = std::env::var(\"CI\").is_ok();", RULE_B),
        (
            "let dir = d();\nlet Some(path) = auth_cdylib() else {\n    eprintln!(\"why\"); // note\n    return;\n};",
            RULE_C,
        ),
        (
            "if !write_auth_plugin(&dir, \"idp.tar.gz\", \"a\", \"b\") {\n    return;\n}",
            RULE_C,
        ),
        (
            "let Ok(home) = std::env::var(\"HOME\") else {\n    return; // no HOME\n};",
            RULE_C,
        ),
        (
            "if !std::path::Path::new(\"/bin/cat\").exists() {\n    return;\n}",
            RULE_C,
        ),
        (
            "if std::fs::read_dir(&dir).is_ok() {\n    eprintln!(\"bypassed\");\n    return;\n}",
            RULE_C,
        ),
    ];
    for (src, rule) in skips {
        assert!(
            scan(src).iter().any(|(_, r)| r == rule),
            "the scan must find {rule} in:\n{src}\n(found {:?})",
            scan(src)
        );
    }

    let clean: &[&str] = &[
        "assert!(std::path::Path::new(\"/bin/cat\").exists(), \"/bin/cat is required by this test\");",
        "let home = std::env::var(\"HOME\").expect(\"HOME must be set for this test\");",
        "let lib = std::fs::read(auth_cdylib()).unwrap();",
        "write_auth_plugin(&dir, \"idp.tar.gz\", \"a\", \"b\");",
        "assert!(std::fs::read_dir(&dir).is_err(), \"fails for every user\");",
        "if std::fs::read_dir(&dir).is_ok() {\n    panic!(\"readable\");\n}",
        "// eprintln!(\"skip: in prose\"); std::env::var_os(\"CI\")\n/* if !auth_cdylib() { return; } */",
        "fn write_auth_plugin(dir: &Path) {\n    return;\n}",
    ];
    for src in clean {
        assert!(
            scan(src).is_empty(),
            "the scan must pass:\n{src}\n(found {:?})",
            scan(src)
        );
    }
}
