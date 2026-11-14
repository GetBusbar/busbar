// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Lint `validate-drops-reason` (decision 124): a migrate host's validation answer says whether
//! the current plugin could not be obtained or refused the settings. A `.validate(` or
//! `.validate_migrated(` call whose result is consumed by `.is_err()` in the same expression
//! throws that reason away, so the operator gets a hint that fits neither case. This scan reads
//! every `.rs` file under this crate's `src/` and refuses such a call, including one that spans
//! several lines. A deliberate site opts out with
//! `// lint-allow(validate-drops-reason): <reason>` on the line above the call; a marker without
//! a reason is itself refused. The gate's self-test runs over `tests/fixtures/validate_drops_reason`
//! (`pass_*` must pass, `fail_*` must fail).

use std::path::{Path, PathBuf};

const RULE: &str = "validate-drops-reason";
const CALLS: [&str; 2] = [".validate(", ".validate_migrated("];
const DROPS: &str = ".is_err()";

fn marker() -> String {
    format!("// lint-allow({RULE}):")
}

/// The byte just after the `)` that closes the `(` at `open`, if balanced.
fn close_of(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0_usize;
    for (at, byte) in text.bytes().enumerate().skip(open) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(at + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// The line (1-based) holding byte `at`.
fn line_of(text: &str, at: usize) -> usize {
    text[..at].bytes().filter(|b| *b == b'\n').count() + 1
}

/// Whether the line above `line` (1-based) carries a marker with a reason.
fn allowed(lines: &[&str], line: usize) -> bool {
    line >= 2
        && lines[line - 2]
            .trim()
            .strip_prefix(&marker())
            .is_some_and(|reason| !reason.trim().is_empty())
}

/// Every refusal in `text`, as `line: what`.
fn refusals(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut found = Vec::new();
    for (number, line) in lines.iter().enumerate() {
        if let Some(reason) = line.trim().strip_prefix(&marker()) {
            if reason.trim().is_empty() {
                found.push(format!(
                    "{}: `{RULE}` allow marker without a reason",
                    number + 1
                ));
            }
        }
    }
    for call in CALLS {
        let mut from = 0;
        while let Some(found_at) = text[from..].find(call) {
            let at = from + found_at;
            from = at + call.len();
            let Some(end) = close_of(text, at + call.len() - 1) else {
                continue;
            };
            if !text[end..].trim_start().starts_with(DROPS) {
                continue;
            }
            let line = line_of(text, at);
            if !allowed(&lines, line) {
                found.push(format!(
                    "{line}: `{}` result consumed by `{DROPS}` drops the validation reason",
                    call.trim_end_matches('(')
                ));
            }
        }
    }
    found
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_migrate_host_validation_drops_its_reason() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    files(&root, &mut sources);
    assert!(!sources.is_empty(), "the crate's sources are scanned");
    let mut stray = Vec::new();
    for path in sources {
        let text = std::fs::read_to_string(&path).expect("UTF-8 source");
        for refusal in refusals(&text) {
            stray.push(format!("{}:{refusal}", path.display()));
        }
    }
    assert!(
        stray.is_empty(),
        "`{RULE}`: match on the validation answer instead of `{DROPS}`: {stray:#?}"
    );
}

#[test]
fn the_gate_passes_deliberate_sites_and_refuses_dropped_reasons() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/validate_drops_reason");
    let mut seen = (0, 0);
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("the gate fixtures")
        .map(|entry| entry.expect("fixture").path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let found = refusals(&std::fs::read_to_string(&path).expect("UTF-8 fixture"));
        if name.starts_with("pass_") {
            seen.0 += 1;
            assert!(found.is_empty(), "{name} must pass: {found:#?}");
        } else if name.starts_with("fail_") {
            seen.1 += 1;
            assert!(!found.is_empty(), "{name} must fail");
        }
    }
    assert!(seen.0 >= 3 && seen.1 >= 3, "fixtures present: {seen:?}");
}
