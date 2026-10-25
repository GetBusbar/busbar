// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`--validate` REFUSES AS THE PUBLISHED 1.5.5 BINARY DID** — every case of the golden captured
//! from it (`tests/v1.5.5-validate/`: `cases.txt` the configurations, `refusals.txt` what 1.5.5's
//! `--validate` printed for each, captured from the release binary by `capture.sh`, at ba24944479).
//!
//! Each case's `export:` block is validated by this build and its refusal's item lines (`  - …`) must
//! equal 1.5.5's, byte for byte and in order; a case 1.5.5 accepted must validate clean. The header
//! line is not compared: 1.6.0 prefixes it with a `BUSBAR-NNNN:` code (CHANGELOG, Improvements).
//!
//! A case naming an export module this build does not serve (its sink not linked) is not this
//! build's to answer, and is skipped — the refusal is the unknown-exporter one, pinned by
//! `export_unknown_module_lists_what_links.rs`. The default build serves every case.
//!
//! A SKIP IS DECIDED BY THE BINARY'S OWN LIST, NOT BY THE REFUSAL TEXT, AND ZERO JUDGED IS RED. Which
//! modules this build serves is read from its own unknown-exporter refusal (the list of the modules
//! it links); a case is skipped only when it names a module outside that list, every other case must
//! be judged, and a run that judged no case at all fails (Law 8: a check that compared nothing is
//! not a pass). The file compiles only where a linked row carries the export-door axis the golden's
//! module rides, so a build with no such sink has no test here rather than a vacuous one.

#![cfg(linked_axis_export_doors)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The golden directory, at the repository root beside the migration corpus.
fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/v1.5.5-validate")
}

/// `(case, 1.5.5's item lines)` in golden order.
fn cases() -> Vec<(String, Vec<String>)> {
    let text = std::fs::read_to_string(golden().join("refusals.txt")).expect("the golden");
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        match line.strip_prefix("=== ") {
            Some(case) => out.push((case.to_string(), Vec::new())),
            None => out
                .last_mut()
                .expect("an item line follows a case")
                .1
                .push(line.to_string()),
        }
    }
    out
}

/// The export modules this build serves, as its own `--validate` lists them when asked for a module
/// nothing serves.
fn linked_modules(dir: &Path) -> Vec<String> {
    let out = validate(dir, "  x: { module: nosuch }\\n");
    out.lines()
        .find_map(|l| l.split_once("export modules are ").map(|(_, list)| list))
        .map(|list| list.split(" | ").map(|m| m.trim().to_string()).collect())
        .unwrap_or_default()
}

/// Every module a golden case names (`module: <name>`).
fn modules_of(case: &str) -> Vec<String> {
    case.split("module: ")
        .skip(1)
        .map(|rest| {
            rest.split(|c: char| c == ',' || c == '}' || c.is_whitespace())
                .next()
                .unwrap_or("")
                .to_string()
        })
        .collect()
}

/// This build's `--validate` over the case: its whole output.
fn validate(dir: &Path, case: &str) -> String {
    // `\n` and `\"` are the golden's escapes (printf %b in capture.sh).
    let block = case.replace("\\n", "\n").replace("\\\"", "\"");
    std::fs::write(dir.join("providers.yaml"), "").unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        // The store 1.5.5 ran this case on, named (Q-STORE = (B)): the golden's lines are unchanged.
        format!(
            "listen: \"127.0.0.1:0\"\nstore: {{module: memory}}\nproviders: {{}}\nmodels: {{}}\nexport:\n{block}"
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--validate")
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .output()
        .expect("run busbar");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn validate_refuses_every_golden_case_as_1_5_5_did() {
    let dir = std::env::temp_dir().join(format!("busbar-golden-155-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cases = cases();
    assert!(
        cases.len() >= 10,
        "the golden holds its cases: {}",
        cases.len()
    );
    let linked = linked_modules(&dir);
    let mut answered = 0;
    for (case, want) in &cases {
        let named = modules_of(case);
        assert!(!named.is_empty(), "a golden case names no module: {case}");
        let out = validate(&dir, case);
        if named.iter().any(|m| !linked.contains(m)) {
            // Not this build's to answer, and the binary must say so the one way it does.
            assert!(
                out.contains("unknown exporter"),
                "{case}: names a module outside {linked:?} and was not refused as unknown:\n{out}"
            );
            continue;
        }
        answered += 1;
        let got: Vec<String> = out
            .lines()
            .filter(|l| l.starts_with("  - "))
            .map(str::to_string)
            .collect();
        assert_eq!(&got, want, "{case}:\n{out}");
        if want.is_empty() {
            assert!(out.contains("ok: config valid"), "{case}:\n{out}");
        } else {
            let header = out.lines().find(|l| l.starts_with("[error]")).unwrap_or("");
            assert!(header.ends_with(" config errors:"), "{case}:\n{out}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        answered > 0,
        "the golden judged NO case: this build serves {linked:?} and every one of the {} cases names \
         a module outside it. A comparison that compared nothing is not a pass.",
        cases.len()
    );
}
