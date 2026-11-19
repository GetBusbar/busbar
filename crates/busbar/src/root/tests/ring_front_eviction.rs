// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Source-scan gate `ring-front-eviction`: no O(n) one-at-a-time front eviction
//! (`remove(0)`, or `drain(..1)` / `drain(..over)`) on a bounded ring under
//! `root/durability/`. Clippy cannot express this. A justified site carries the
//! marker comment `ring-front-eviction: allow(<reason>)` on the same or the
//! preceding line.

use std::path::Path;

const ALLOW: &str = "ring-front-eviction: allow(";

/// The needles, built at runtime so this file never matches itself.
fn needles() -> [String; 3] {
    [
        format!(".{}(0)", "remove"),
        format!(".{}(..1)", "drain"),
        format!(".{}(..over)", "drain"),
    ]
}

/// Every `file:line` in `source` that front-evicts without an allow marker.
fn findings(file: &str, source: &str) -> Vec<String> {
    let needles = needles();
    let mut out = Vec::new();
    let mut previous = "";
    for (n, line) in source.lines().enumerate() {
        let code = line.split("//").next().unwrap_or("");
        let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if needles
            .iter()
            .any(|needle| compact.contains(needle.as_str()))
            && !line.contains(ALLOW)
            && !previous.contains(ALLOW)
        {
            out.push(format!("{file}:{}: {}", n + 1, line.trim()));
        }
        previous = line;
    }
    out
}

fn scan(dir: &Path, out: &mut Vec<String>, files: &mut usize) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            scan(&path, out, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text = std::fs::read_to_string(&path).expect("read source");
            *files += 1;
            out.extend(findings(&path.display().to_string(), &text));
        }
    }
}

#[test]
fn ring_front_eviction_gate() {
    // The root crate's own sources, from either manifest that builds this target (crates/busbar or
    // dist/default): both sit two levels below the repository root.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/busbar/src/root/durability");
    let mut out = Vec::new();
    let mut files = 0;
    scan(&dir, &mut out, &mut files);
    assert!(files > 5, "the gate scanned {files} files: never vacuous");
    assert!(
        out.is_empty(),
        "ring-front-eviction: O(n) front eviction on a bounded ring; batch it \
         (see durability/ring.rs) or mark a justified site with `{ALLOW}<reason>)`:\n{}",
        out.join("\n")
    );
}

#[test]
fn ring_front_eviction_gate_fixture() {
    let [remove, drain_one, drain_over] = needles();
    let bad = format!(
        "fn a(v: &mut Vec<u8>) {{\n    v{remove};\n}}\nfn b(v: &mut Vec<u8>) {{\n    v{drain_one};\n    \
         v{drain_over};\n}}\n"
    );
    assert_eq!(findings("bad.rs", &bad).len(), 3, "both shapes are flagged");
    let spaced = format!("v . {} ( .. over );", "drain");
    assert_eq!(
        findings("spaced.rs", &spaced).len(),
        1,
        "spacing is ignored"
    );
    let allowed = format!(
        "// {ALLOW}fixture)\nv{remove};\nv{drain_one}; // {ALLOW}fixture)\n// v{drain_over};\n"
    );
    assert!(
        findings("allowed.rs", &allowed).is_empty(),
        "allow markers and comments are honoured"
    );
    let batched = format!("v.{}(..AUDIT_SLACK);\nv.{}(1);\n", "drain", "remove");
    assert!(findings("batched.rs", &batched).is_empty());
}
