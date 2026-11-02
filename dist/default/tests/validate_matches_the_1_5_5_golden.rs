// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(linked_axis_export_doors)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/v1.5.5-validate")
}

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

fn linked_modules(dir: &Path) -> Vec<String> {
    let out = validate(dir, "  x: { module: nosuch }\\n");
    out.lines()
        .find_map(|l| l.split_once("export modules are ").map(|(_, list)| list))
        .map(|list| list.split(" | ").map(|m| m.trim().to_string()).collect())
        .unwrap_or_default()
}

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

fn validate(dir: &Path, case: &str) -> String {
    let block = case.replace("\\n", "\n").replace("\\\"", "\"");
    std::fs::write(dir.join("providers.yaml"), "").unwrap();
    std::fs::write(
        dir.join("config.yaml"),

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
