// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE UNKNOWN-EXPORTER REFUSAL LISTS THE MODULES THIS BUILD SERVES.** Driven through the real
//! binary's `--validate`.
//!
//! A config naming an export module nothing serves is refused with the list of the modules that do
//! exist. That list is the export sinks this build LINKS, in the frozen order — the kernel serves
//! no module of its own since its last one became a linked sink (K9e-2). A build that does not link
//! a sink does not offer it: it would be naming, as available, the very module it refuses when asked
//! for it.
//!
//! Which modules the refusal offers is the binary's own answer, and each one it offers is asked of
//! `--validate` in turn: none of them is an unknown exporter. A build that serves every module
//! 1.5.5's refusal offered prints 1.5.5's line byte for byte: that line is DATA
//! in the oracle corpus (`testing/shadow-oracle/fixtures/law0/unknown-exporter-1.5.5.txt`, verbatim
//! from the 1.5.5 binary), so the source names no sink.

use std::path::{Path, PathBuf};
use std::process::Command;

/// 1.5.5's refusal for `module: nosuch`, byte for byte (DATA, verbatim from the 1.5.5 binary).
const REFUSAL_1_5_5: &str =
    include_str!("../../../testing/shadow-oracle/fixtures/law0/unknown-exporter-1.5.5.txt");

/// The refusal's head for `module: nosuch`; the modules it offers follow, ` | `-separated.
const REFUSAL_HEAD: &str =
    "export.x.module: unknown exporter 'nosuch'; the built-in export modules are ";

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-export-list-{tag}-{}-{}",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// `--validate` over a config whose only section is `export:` with `instance`: its whole output.
fn validate(dir: &Path, instance: &str) -> String {
    std::fs::write(dir.join("providers.yaml"), "").unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!("listen: \"127.0.0.1:0\"\nproviders: {{}}\nmodels: {{}}\nexport:\n{instance}"),
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
fn the_unknown_exporter_refusal_lists_exactly_the_modules_this_build_serves() {
    let dir = fixture_dir("list");
    let refusal = validate(&dir, "  x: { module: nosuch }\n");
    let line = refusal
        .lines()
        .map(|l| l.trim_start().trim_start_matches("- "))
        .find(|l| l.starts_with(REFUSAL_HEAD))
        .unwrap_or_else(|| panic!("no unknown-exporter refusal for 'nosuch':\n{refusal}"))
        .to_string();
    let tail = &line[REFUSAL_HEAD.len()..];
    let offered: Vec<&str> = if tail.is_empty() {
        Vec::new()
    } else {
        tail.split(" | ").collect()
    };
    assert!(
        offered.iter().all(|m| !m.is_empty() && !m.contains(' ')),
        "the refusal offers module names, ` | `-separated: {line}"
    );
    let mut seen = std::collections::BTreeSet::new();
    for module in &offered {
        assert!(seen.insert(*module), "`{module}` is offered twice: {line}");
        // Every module it offers is one this build serves: asked for alone, it is no unknown
        // exporter (its settings may be refused; its name is not).
        let out = validate(&dir, &format!("  x: {{ module: {module} }}\n"));
        assert!(
            !out.contains("invalid YAML"),
            "the probe config must parse:\n{out}"
        );
        assert!(
            !out.contains(&format!("unknown exporter '{module}'")),
            "the refusal offers `{module}`, which this build does not serve:\n{out}"
        );
    }
    // A build serving every module 1.5.5 offered prints 1.5.5's line, byte for byte; a build that
    // does not link one of them never offers it.
    let line_1_5_5 = REFUSAL_1_5_5.trim_end();
    let offered_1_5_5: Vec<&str> = line_1_5_5
        .strip_prefix(REFUSAL_HEAD)
        .expect("the 1.5.5 line is the same refusal")
        .split(" | ")
        .collect();
    let serves_all = offered_1_5_5.iter().all(|module| {
        !validate(&dir, &format!("  x: {{ module: {module} }}\n"))
            .contains(&format!("unknown exporter '{module}'"))
    });
    if serves_all {
        assert_eq!(
            line, line_1_5_5,
            "the refusal is 1.5.5's line, byte for byte"
        );
    } else {
        for module in &offered_1_5_5 {
            if offered.contains(module) {
                continue;
            }
            assert!(
                !line.contains(&format!(" {module} ")) && !line.ends_with(&format!(" {module}")),
                "this build does not serve '{module}' but offers it: {line}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
