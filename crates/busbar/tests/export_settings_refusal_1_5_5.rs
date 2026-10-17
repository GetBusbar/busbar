// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **AN EXPORT SINK'S SETTINGS REFUSAL IS RENDERED UNDER ITS INSTANCE, AS 1.5.5 PRINTED IT**
//! (WIRE-EXPORT, operator text parity). A sink on the export kind's memory ABI is handed its
//! `settings:` section alone, so it cannot name its instance: it answers `settings: <words>`, and
//! the HOST renders the line under the instance (`abi::mechanism::lifecycle::refusal_lines`) —
//! `export.<instance>.settings: …`, the shape 1.5.5 printed.
//!
//! Driven through the shipped binary's `--validate`, over every sink this build serves (the modules
//! its unknown-exporter refusal offers), each handed a settings key no sink declares. RED before the
//! host's rendering: the door sinks' lines read `settings: …`, with no instance. 1.5.5's own lines,
//! sink by sink, are DATA in the oracle corpus
//! (`testing/shadow-oracle/fixtures/law0/export-settings-refusals-1.5.5.json`, verbatim from the
//! 1.5.5 binary), each held byte for byte on every build that serves its sink; this source names no sink.

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::path::Path;
use std::process::Command;

/// A settings key no sink declares.
const PLANTED_KEY: &str = "planted_key_no_sink_declares";

/// The unknown-exporter refusal's head; the modules this build serves follow, ` | `-separated.
const REFUSAL_HEAD: &str =
    "export.x.module: unknown exporter 'nosuch'; the built-in export modules are ";

fn write_configs(dir: &Path, export: &str) {
    std::fs::write(
        dir.join("providers.yaml"),
        include_str!("fixtures/mock_provider.yaml"),
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "listen: \"127.0.0.1:{}\"\nadmin_listen: \"127.0.0.1:{}\"\nadmin_require_mtls: \
             false\nauth:\n  chain: []\nexport:\n{export}providers:\n  mock:\n    api_key: {{ \
             env: MOCK_KEY }}\nmodels:\n  test-model:\n    provider: mock\n",
            common::boot::free_port(),
            common::boot::free_port(),
        ),
    )
    .unwrap();
}

/// `--validate` over `export`: its exit status and what it printed.
fn validate(dir: &Path, export: &str) -> (bool, String) {
    write_configs(dir, export);
    let out = Command::new(common::boot::exe())
        .arg("--validate")
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .output()
        .expect("run busbar --validate");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

/// The modules this build serves, as its unknown-exporter refusal offers them.
fn served(dir: &Path) -> Vec<String> {
    let (_, text) = validate(dir, "  x: { module: nosuch }\n");
    let line = text
        .lines()
        .map(|l| l.trim_start().trim_start_matches("- "))
        .find(|l| l.starts_with(REFUSAL_HEAD))
        .unwrap_or_else(|| panic!("no unknown-exporter refusal for 'nosuch':\n{text}"));
    let tail = &line[REFUSAL_HEAD.len()..];
    if tail.is_empty() {
        return Vec::new();
    }
    tail.split(" | ").map(str::to_string).collect()
}

#[test]
fn a_sinks_settings_refusal_is_rendered_under_its_instance_as_1_5_5_printed_it() {
    let dir = common::plugins::scratch("export-settings-1-5-5");
    let mut refused = 0usize;
    for module in served(&dir) {
        let (ok, text) = validate(
            &dir,
            &format!("  x: {{ module: {module}, settings: {{ {PLANTED_KEY}: 1 }} }}\n"),
        );
        let lines: Vec<&str> = text
            .lines()
            .map(|l| l.trim_start_matches("  - "))
            .filter(|l| l.contains(PLANTED_KEY))
            .collect();
        if lines.is_empty() {
            continue;
        }
        assert!(
            !ok,
            "{module}: a refused settings key validated clean:\n{text}"
        );
        refused += 1;
        for line in lines {
            assert!(
                line.starts_with("export.x.settings: "),
                "{module}: the sink's refusal is not rendered under its instance: `{line}`\n{text}"
            );
        }
    }
    assert!(
        refused > 0,
        "no sink this build serves refused a key it does not declare, so the rendering went unproven"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// 1.5.5's settings refusals, sink by sink, as DATA (verbatim from the 1.5.5 binary).
const REFUSALS_1_5_5: &str = include_str!(
    "../../../testing/shadow-oracle/fixtures/law0/export-settings-refusals-1.5.5.json"
);

/// EVERY 1.5.5 SETTINGS REFUSAL READS AS 1.5.5 PRINTED IT on a build that serves its sink: the line
/// itself, or the sentence it opens (a whole sentence 1.5.5 printed unprefixed), and a refusal
/// 1.5.5 printed once is printed once.
#[test]
fn every_1_5_5_settings_refusal_reads_as_1_5_5_printed_it() {
    let doc: serde_json::Value = serde_json::from_str(REFUSALS_1_5_5).expect("the fixture is JSON");
    let dir = common::plugins::scratch("export-settings-1-5-5-lines");
    for case in doc["cases"].as_array().expect("cases") {
        let module = case["module"].as_str().expect("module");
        let export = case["export"].as_str().expect("export");
        let want = case["line"].as_str().expect("line");
        let prefix = case["match"].as_str() == Some("prefix");
        let once = case["once"].as_bool().unwrap_or(false);
        let (ok, text) = validate(&dir, export);
        if text.contains(&format!("unknown exporter '{module}'")) {
            // A build that does not serve this sink has no refusal of it to render.
            continue;
        }
        assert!(!ok, "{module}: the case validated clean:\n{text}");
        let printed = text
            .lines()
            .map(|l| l.trim_start_matches("  - "))
            .filter(|l| {
                if prefix {
                    l.starts_with(want)
                } else {
                    *l == want
                }
            })
            .count();
        if once {
            assert_eq!(printed, 1, "{module}: 1.5.5's line `{want}`, once:\n{text}");
        } else {
            assert!(
                printed > 0,
                "{module}: the refusal is not 1.5.5's line `{want}`:\n{text}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
