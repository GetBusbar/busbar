// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE UNKNOWN-EXPORTER REFUSAL LISTS THE MODULES THIS BUILD SERVES.** Driven through the real
//! binary's `--validate`.
//!
//! A config naming an export module nothing serves is refused with the list of the modules that do
//! exist. That list is the kernel's own modules plus the export sinks this build LINKS, in the
//! frozen order. A default build links every sink, so its refusal is 1.5.5's line byte for byte, and
//! that line is pinned below. A build that does not link a sink does not offer it: it would be
//! naming, as available, the very module it refuses when asked for it.
//!
//! Which sinks the build links is the binary's own answer (each module alone, asked of
//! `--validate`), never a feature name.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The 1.5.5 refusal for `module: nosuch`, byte for byte, which every default build still prints.
const DEFAULT_REFUSAL: &str = "export.x.module: unknown exporter 'nosuch'; the built-in export \
                               modules are prometheus | request-log-webhook | request-log-file | otlp";

/// The first-party export sinks, in the frozen order, each with an instance line that configures it.
const SINKS: &[(&str, &str)] = &[
    (
        "prometheus",
        "  x: { module: prometheus, settings: { buffer_seconds: 60 } }\n",
    ),
    (
        "request-log-webhook",
        "  x: { module: request-log-webhook, settings: { url: \"https://siem.example/in\" } }\n",
    ),
    (
        "request-log-file",
        "  x: { module: request-log-file, settings: { path: '/tmp/busbar-requests.jsonl' } }\n",
    ),
];

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-export-list-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
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
    let linked: Vec<&str> = SINKS
        .iter()
        .filter(|(module, line)| {
            let out = validate(&dir, line);
            // A probe that never reached the export section proves nothing either way.
            assert!(
                !out.contains("invalid YAML"),
                "the probe config must parse:\n{out}"
            );
            !out.contains(&format!("unknown exporter '{module}'"))
        })
        .map(|(module, _)| *module)
        .collect();
    let refusal = validate(&dir, "  x: { module: nosuch }\n");
    let _ = std::fs::remove_dir_all(&dir);
    let line = refusal
        .lines()
        .map(|l| l.trim_start().trim_start_matches("- "))
        .find(|l| l.starts_with("export.x.module: unknown exporter 'nosuch'"))
        .unwrap_or_else(|| panic!("no unknown-exporter refusal for 'nosuch':\n{refusal}"));

    // What this build serves: the sinks it links, then the kernel's own `otlp`, in the frozen order.
    let mut served = linked.clone();
    served.push("otlp");
    assert_eq!(
        line,
        format!(
            "export.x.module: unknown exporter 'nosuch'; the built-in export modules are {}",
            served.join(" | ")
        ),
        "the refusal must offer exactly the modules this build serves (linked: {linked:?})"
    );
    // A build that does not link a sink never offers it.
    for (module, _) in SINKS.iter().filter(|(m, _)| !linked.contains(m)) {
        assert!(
            !line.contains(&format!(" {module} ")) && !line.ends_with(&format!(" {module}")),
            "this build does not link '{module}' but offers it: {line}"
        );
    }
    // The default build links every sink, and its refusal is 1.5.5's byte for byte.
    if linked.len() == SINKS.len() {
        assert_eq!(line, DEFAULT_REFUSAL);
    }
}
