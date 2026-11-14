// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Lint `laneless-ledger-row` (UPG-H2): a budget-cell model row is built only by the sealed
//! constructor in `governance/mod.rs`, which refuses an unnamed lane with no count. The seal
//! field makes any other plain literal a compile error; this scan also refuses the struct-update
//! form, which the seal cannot stop inside `governance`.

use std::path::{Path, PathBuf};

/// The type name, assembled so this file holds no literal of the form it scans for.
const NAME: &str = concat!("Model", "Cell");
const SEAL_MODULE: &str = concat!("mod ", "model_cell_seal");

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The source with every `//` comment removed, line structure kept.
fn strip_line_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| line.find("//").map_or(line, |at| &line[..at]))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Byte range of the `mod model_cell_seal { .. }` body, if the file declares it.
fn seal_region(source: &str) -> Option<(usize, usize)> {
    let start = source.find(SEAL_MODULE)?;
    let open = start + source[start..].find('{')?;
    let mut depth = 0usize;
    for (offset, c) in source[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((open, open + offset));
                }
            }
            _ => {}
        }
    }
    None
}

#[test]
fn model_cell_literals_only_in_constructor() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    assert!(
        !files.is_empty(),
        "no kernel sources under {}",
        root.display()
    );

    let mut violations = Vec::new();
    let mut sealed_literals = 0usize;
    let mut seal_found = false;
    for file in &files {
        let raw = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        let source = strip_line_comments(&raw);
        let governance_root = file.ends_with("governance/mod.rs");
        let seal = governance_root.then(|| seal_region(&source)).flatten();
        seal_found |= seal.is_some();
        let mut from = 0;
        while let Some(found) = source[from..].find(NAME) {
            let at = from + found;
            from = at + NAME.len();
            if source[..at].chars().next_back().is_some_and(is_ident) {
                continue;
            }
            if !source[from..].trim_start().starts_with('{') {
                continue;
            }
            let line_start = source[..at].rfind('\n').map_or(0, |n| n + 1);
            let before = source[line_start..at].trim();
            if before.ends_with("struct")
                || before.ends_with("impl")
                || before.ends_with("impl super::")
            {
                continue;
            }
            if seal.is_some_and(|(open, close)| at > open && at < close) {
                sealed_literals += 1;
                continue;
            }
            let line = source[..at].matches('\n').count() + 1;
            let shown = file.strip_prefix(&root).unwrap_or(file);
            violations.push(format!("src/{}:{line}", shown.display()));
        }
    }
    assert!(
        violations.is_empty(),
        "laneless-ledger-row: build every {NAME} through {NAME}::new (governance/mod.rs, \
         {SEAL_MODULE}), never a literal or struct-update form; found {} literal(s):\n{}",
        violations.len(),
        violations.join("\n")
    );
    assert!(
        seal_found,
        "laneless-ledger-row: governance/mod.rs must declare `{SEAL_MODULE}` with the sealed {NAME}::new"
    );
    assert_eq!(
        sealed_literals, 1,
        "laneless-ledger-row: the seal module holds exactly the one constructor literal"
    );
}
