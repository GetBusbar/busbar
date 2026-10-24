// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAW 11 (BUSBAR-1.6.0 lines 2127-2132; the relay-only ruling at 418-422): no crate carries a
//! resolved-completion seam. MOVED HERE, unchanged, from `plane_host_universal_purity.rs`, whose
//! universal-`EngineHost` purity scan is retired with its subject: it counted the in-root LINKED
//! planes (`plane` axis) calling each host method, and since the retired engine crate's deletion
//! (DEV-GREEN row 83) every plane is a door plane that holds no `EngineHost` and reaches busbar
//! only over the ABI (BUSBAR-1.6.0.md l.2179, Part 2 #2).

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root must exist")
}

/// Strip line/block comments from one source line, respecting string literals — the exact discipline of
/// `plane_transport_neutrality.rs::strip_comments`: a `//` inside a string is NOT a comment, a token
/// inside a string IS kept. `in_block` persists across lines; string state is per line.
fn strip_comments(line: &str, in_block: &mut bool) -> String {
    let b = line.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        let c2 = if i + 1 < b.len() {
            &b[i..i + 2]
        } else {
            &b[i..]
        };
        if *in_block {
            if c2 == b"*/" {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if in_str {
            out.push(c as char);
            if c == b'\\' {
                if i + 1 < b.len() {
                    out.push(b[i + 1] as char);
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
        if c2 == b"/*" {
            *in_block = true;
            i += 2;
            continue;
        }
        if c2 == b"//" {
            break; // line comment (// /// //!) to EOL
        }
        if c == b'"' {
            in_str = true;
            out.push('"');
            i += 1;
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    out
}

/// The whole source, comments stripped (block-aware). Used both for trait-body parsing and caller scan.
fn strip_source(src: &str) -> String {
    let mut in_block = false;
    let mut out = String::new();
    for line in src.lines() {
        out.push_str(&strip_comments(line, &mut in_block));
        out.push('\n');
    }
    out
}

/// Every non-test `.rs` under `dir`, recursively (excludes `*/tests/*`, `*_test(s).rs`) — the plane's
/// exported source, not its unit tests (mirrors the shell/`plane_transport_neutrality.rs` scope).
fn plane_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("tests") {
                continue;
            }
            plane_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.ends_with("_test.rs") || name.ends_with("_tests.rs") {
                continue;
            }
            out.push(path);
        }
    }
}

/// LAW 11 (BUSBAR-1.6.0 lines 2127-2132; the relay-only ruling at 418-422): busbar runs no
/// completion on a completion plane to answer an upstream's sampling ask, and routes no call to another
/// plane on the content's say-so. The kernel's resolved-completion seam (the arrival, its fn-pointer
/// type, the set-once install, the test hook and the resolver) and the completion plane's synthesizer that
/// filled it were that route; 1.5.5 carried none of it. This pins that no crate's non-test source
/// declares or names any of it again.
#[test]
fn no_crate_carries_a_resolved_completion_seam() {
    const SEAM: &[&str] = &[
        "completion_ingress",
        "COMPLETION_INGRESS",
        "CompletionArrival",
        "CompletionIngress",
        "synthesize_completion",
    ];
    let crates = repo_root().join("crates");
    let mut scanned = 0usize;
    let mut hits = Vec::new();
    for entry in std::fs::read_dir(&crates)
        .expect("the crates directory is readable")
        .flatten()
    {
        let mut files = Vec::new();
        plane_rs_files(&entry.path().join("src"), &mut files);
        for f in files {
            scanned += 1;
            let code = strip_source(&std::fs::read_to_string(&f).expect("source is readable"));
            for token in SEAM {
                if code.contains(token) {
                    hits.push(format!("  {}: {token}", f.display()));
                }
            }
        }
    }
    assert!(
        scanned > 100,
        "the scan read {scanned} files; a scan that reads nothing passes vacuously"
    );
    assert!(
        hits.is_empty(),
        "a resolved-completion seam is back (busbar would answer an upstream's ask on another \
         plane):\n{}",
        hits.join("\n")
    );
}
