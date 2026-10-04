// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `CallerToken` has exactly ONE definition in the workspace: `busbar-contract/src/auth.rs`.
//!
//! The request-extension carrier of the caller's bearer token is an ABI shape, and every ABI shape
//! lives in `busbar-contract` (THE DESIGN §11.5). A second `struct CallerToken` (the retired
//! `busbar-kernel-identity/src/carrier.rs` one) would be a distinct type: an `Extension<CallerToken>`
//! inserted by one crate would silently never be found by an extractor naming the other. Every
//! other crate re-exports or imports the contract one (`busbar-kernel` re-exports it by identity).

use std::path::{Path, PathBuf};

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// True when `line` declares a type named exactly `CallerToken` (struct, enum, union or alias).
fn declares_caller_token(line: &str) -> bool {
    let code = line.split("//").next().unwrap_or("").trim_start();
    let code = code.strip_prefix("pub").map_or(code, |rest| {
        // `pub`, `pub(crate)`, `pub(super)`, ...
        let rest = rest.trim_start();
        if rest.starts_with('(') {
            rest.split_once(')')
                .map_or(rest, |(_, after)| after)
                .trim_start()
        } else {
            rest
        }
    });
    ["struct", "enum", "union", "type"].iter().any(|kw| {
        code.strip_prefix(kw)
            .filter(|rest| rest.starts_with(char::is_whitespace))
            .is_some_and(|rest| {
                let name = rest.trim_start();
                name.starts_with("CallerToken")
                    && !name["CallerToken".len()..]
                        .starts_with(|c: char| c.is_alphanumeric() || c == '_')
            })
    })
}

#[test]
fn caller_token_is_defined_exactly_once_in_busbar_contract_auth() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    rust_sources(&crates, &mut files);
    assert!(
        files.len() > 100,
        "the scan walked only {} files; the workspace layout moved under this test",
        files.len()
    );

    let mut defs = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a readable source file");
        for (i, line) in text.lines().enumerate() {
            if declares_caller_token(line) {
                let rel = file.strip_prefix(&crates).unwrap_or(file);
                defs.push(format!("{}:{}", rel.display(), i + 1));
            }
        }
    }

    assert_eq!(
        defs.len(),
        1,
        "`CallerToken` must have exactly one definition (busbar-contract/src/auth.rs); found: {defs:?}"
    );
    assert!(
        defs[0].replace('\\', "/").starts_with("busbar-contract/src/auth.rs:"),
        "the one `CallerToken` definition must live in busbar-contract/src/auth.rs; found: {defs:?}"
    );
}

#[test]
fn the_detector_sees_a_second_definition() {
    // The detector must fire on the shapes a duplicate would take, or the test above is blind.
    assert!(declares_caller_token(
        "pub struct CallerToken(pub Option<String>);"
    ));
    assert!(declares_caller_token(
        "    pub(crate) struct CallerToken { t: String }"
    ));
    assert!(declares_caller_token("struct CallerToken;"));
    assert!(declares_caller_token("pub type CallerToken = String;"));
    assert!(!declares_caller_token("pub struct CallerTokenView;"));
    assert!(!declares_caller_token(
        "pub use busbar_contract::auth::CallerToken;"
    ));
    assert!(!declares_caller_token("// pub struct CallerToken;"));
    assert!(!declares_caller_token(
        "impl std::fmt::Debug for CallerToken {"
    ));
}
