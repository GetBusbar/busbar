// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MECHANICAL PREVENTION for the gauntlet-before-upgrade invariant: a bare `on_upgrade` binds the socket
//! BEFORE the open-pass gauntlet can reject it, so it must exist in EXACTLY ONE place — the neutral
//! acceptor `busbar-substrate/src/ingress/duplex_ws.rs`, where `accept`/`serve_gauntlet` own the
//! single audited call. Every plane's WS-accept fn receives a `WsArrival` and reaches the socket ONLY
//! through `serve_gauntlet`/`accept_gauntlet`; none may call `on_upgrade` itself. This test scans every
//! `.rs` in the workspace's `crates/` tree and fails RED if a `.on_upgrade(` CALL appears in any file
//! other than `duplex_ws.rs`. Doc/line comments that merely NAME `on_upgrade` are not calls and are
//! excluded, exactly as the neutrality lints strip comments before judging a token.

use std::path::Path;

/// The ONLY file allowed to contain an `on_upgrade(` call — the neutral WS acceptor. Matched by its
/// FULL relative path (not basename): the egress dialer shares the basename `duplex_ws.rs`, and a bare
/// `on_upgrade(` there must NOT be exempted, so only the ingress acceptor path is allowed.
const ALLOWED_PATH_SUFFIX: &str = "ingress/duplex_ws.rs";

fn crates_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR is crates/busbar-substrate; its parent is the crates/ tree.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/busbar-substrate has a parent (crates/)")
        .to_path_buf()
}

/// Collect every `.rs` file under `dir`, skipping any `target/` build dir.
fn rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("target") {
                continue;
            }
            rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Whether `line` contains a `.on_upgrade(` METHOD CALL that is not inside a line/doc comment. Matching
/// the method-call form (leading `.`) excludes a fn DEFINITION whose name merely ends in `_on_upgrade`
/// and a bare word in prose. A `//`-anchored comment (including `///` / `//!`) and a doc-continuation
/// `*` line are excluded — a comment naming the call is not the call.
fn has_uncommented_on_upgrade_call(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
        return false;
    }
    let code = match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    };
    code.contains(".on_upgrade(")
}

#[test]
fn on_upgrade_appears_in_no_file_except_the_neutral_acceptor() {
    let mut files = Vec::new();
    rs_files(&crates_root(), &mut files);
    assert!(
        !files.is_empty(),
        "the source scan found no .rs files — the crates/ root resolution is wrong"
    );

    let mut offenders: Vec<String> = Vec::new();
    let mut allowed_hits = 0usize;
    for path in &files {
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        let basename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // This lint's own source names `.on_upgrade(` in its detector + messages — skip it.
        if basename == "on_upgrade_confined.rs" {
            continue;
        }
        // Full-path (not basename) exemption: only the ingress acceptor, never the egress dialer that
        // shares the `duplex_ws.rs` basename.
        let rel = path.to_string_lossy().replace('\\', "/");
        for (lineno, line) in src.lines().enumerate() {
            if has_uncommented_on_upgrade_call(line) {
                if rel.ends_with(ALLOWED_PATH_SUFFIX) {
                    allowed_hits += 1;
                } else {
                    offenders.push(format!(
                        "{}:{}: {}",
                        path.display(),
                        lineno + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a bare `on_upgrade(` call escaped the neutral acceptor ({}): it must be reached ONLY through \
         serve_gauntlet/accept_gauntlet so the gauntlet runs before the socket binds:\n{}",
        ALLOWED_PATH_SUFFIX,
        offenders.join("\n")
    );
    assert!(
        allowed_hits >= 1,
        "expected the single audited `on_upgrade(` call in {ALLOWED_PATH_SUFFIX}; found none — the \
         acceptor moved and this gate is now scanning the wrong tree"
    );
}
