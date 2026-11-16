// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WORKSPACE LAW (decision 124, UPG-A12): the launch env vars 1.6 retired are spelled, as a quoted
//! string literal, in exactly one production file: `root/retired_env.rs`, whose
//! `RETIRED_LAUNCH_ENV` table drives the BUSBAR-3029
//! "set but ignored" notice. A retired name spelled anywhere else is a reader (or a dead copy) the
//! notice cannot see. Test code is exempt: files under a `tests/` directory, and the tail of a file
//! from its first column-0 `#[cfg(test)]`.

use std::path::{Path, PathBuf};

const RETIRED: [&str; 4] = [
    "BUSBAR_PROVIDERS",
    "BUSBAR_WORKER_THREADS",
    "BUSBAR_UPSTREAM_HTTP1_ONLY",
    "BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE",
];

const SINGLE_SOURCE: &str = "crates/busbar/src/root/retired_env.rs";

fn production_part(text: &str) -> &str {
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        if line.trim_end() == "#[cfg(test)]" {
            return &text[..at];
        }
        at += line.len();
    }
    text
}

/// The retired names `text`'s production part spells as an exact quoted literal.
fn quoted_retired_names(text: &str) -> Vec<&'static str> {
    let production = production_part(text);
    RETIRED
        .into_iter()
        .filter(|name| production.contains(&format!("\"{name}\"")))
        .collect()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name != "tests" && name != "target" && !name.starts_with('.') {
                rust_sources(&path, out);
            }
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

#[test]
fn retired_launch_env_names_are_spelled_only_in_the_retired_table() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_sources(&root.join("crates"), &mut files);
    assert!(
        files.iter().any(|f| f.ends_with(SINGLE_SOURCE)),
        "the walk must reach {SINGLE_SOURCE}"
    );
    let mut offenders = Vec::new();
    for file in &files {
        if file.ends_with(SINGLE_SOURCE) {
            continue;
        }
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for name in quoted_retired_names(&text) {
            let shown = file.strip_prefix(&root).unwrap_or(file);
            offenders.push(format!("{} spells \"{name}\"", shown.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "a retired launch env var may be named only in {SINGLE_SOURCE}'s RETIRED_LAUNCH_ENV, \
         so the BUSBAR-3029 notice reports every one:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_law_fires_on_a_planted_literal_and_exempts_only_test_code() {
    assert_eq!(
        quoted_retired_names("pub const X: &str = \"BUSBAR_PROVIDERS\";\n"),
        ["BUSBAR_PROVIDERS"]
    );
    assert_eq!(
        quoted_retired_names(
            "fn f() { env(\"BUSBAR_UPSTREAM_HTTP1_ONLY\"); }\n#[cfg(test)]\nmod t { \"BUSBAR_WORKER_THREADS\" }\n"
        ),
        ["BUSBAR_UPSTREAM_HTTP1_ONLY"]
    );
    assert!(quoted_retired_names("let s = \"BUSBAR_PROVIDERS_EXTRA\";\n").is_empty());
    assert!(quoted_retired_names("// BUSBAR_PROVIDERS is retired\n").is_empty());
}
