// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **AN EXPORT SINK'S SETTINGS REFUSAL READS AS 1.5.5 PRINTED IT** (WIRE-EXPORT, operator text
//! parity). A sink on the export kind's memory ABI is handed its `settings:` section alone, so it
//! cannot name its instance: it answers `settings: <words>`, and the HOST renders the line under
//! the instance (`abi::mechanism::lifecycle::refusal_lines`) — `export.<instance>.settings: …`,
//! byte for byte what 1.5.5 printed. A whole sentence (prometheus's zero-retention refusal) is the
//! sink's own and is printed unprefixed, as 1.5.5 printed it.
//!
//! Driven through the shipped binary's `--validate`, one sink of each kind this build links, each
//! with a bad `settings` key. RED before the host's rendering: the door sinks' lines read
//! `settings: …`, with no instance.

#![cfg(unix)]
#![cfg(linked_axis_body_ingress)]

mod common;

use std::path::Path;
use std::process::Command;

/// `(module, instance line, the 1.5.5 line)`: one bad settings key per sink kind.
const CASES: &[(&str, &str, &str)] = &[
    (
        "prometheus",
        "  metrics: { module: prometheus, settings: { buffer_seconds: 60, bogus: 1 } }\n",
        "export.metrics.settings: unknown field `bogus`, expected `buffer_seconds` or \
         `key_gauge_limit`",
    ),
    (
        "prometheus",
        "  metrics: { module: prometheus, settings: { key_gauge_limit: 7 } }\n",
        "export.metrics.settings: missing field `buffer_seconds`",
    ),
    (
        "otlp",
        "  trace: { module: otlp, settings: { url: \"http://127.0.0.1:4318/v1/traces\", bogus: 1 } }\n",
        "export.trace.settings: unknown field `bogus`, expected `url`",
    ),
    (
        "request-log-file",
        "  file: { module: request-log-file, settings: { path: 7 } }\n",
        "export.file.settings: invalid type: integer `7`, expected a string",
    ),
];

/// 1.5.5's zero-retention refusal: a whole sentence, unprefixed.
const ZERO_RETENTION: &str = "the `module: prometheus` export instance sets \
     settings.buffer_seconds: 0, which retains no observations";

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

#[test]
fn a_sinks_settings_refusal_is_rendered_under_its_instance_as_1_5_5_printed_it() {
    let dir = common::plugins::scratch("export-settings-1-5-5");
    for (module, line, want) in CASES {
        let (ok, text) = validate(&dir, line);
        if text.contains(&format!("unknown exporter '{module}'")) {
            // A build that does not link this sink has no refusal of it to render.
            continue;
        }
        assert!(!ok, "{module}: a bad settings key validated clean:\n{text}");
        assert!(
            text.lines().any(|l| l.trim_start_matches("  - ") == *want),
            "{module}: the refusal is not 1.5.5's line `{want}`:\n{text}"
        );
    }
    let (ok, text) = validate(
        &dir,
        "  metrics: { module: prometheus, settings: { buffer_seconds: 0 } }\n",
    );
    if !text.contains("unknown exporter 'prometheus'") {
        assert!(!ok, "{text}");
        assert!(
            text.lines()
                .any(|l| l.trim_start_matches("  - ").starts_with(ZERO_RETENTION)),
            "the zero-retention sentence is printed unprefixed:\n{text}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// 1.5.5's refusal of a second scrape-sink instance: the sink states the `one_instance` mark, so the
/// host asks its limits check while the configuration is resolved and prints its line verbatim —
/// once per extra instance, naming the first. (The kernel's own proof that a `one_instance` module's
/// words are rendered verbatim runs on its scrape double, busbar-kernel
/// `config/tests/tests.rs::export_named_map_allows_two_instances_of_one_module`; the 1.5.5 words are
/// the linked sink's, pinned here.)
const SECOND_SCRAPE_INSTANCE: &str = "export.two: a second `module: prometheus` instance (already \
     defined as 'one'). Prometheus serves the ONE well-known /metrics route, so a second instance \
     could only be silently ignored — keep a single instance.";

#[test]
fn a_second_scrape_sink_instance_is_refused_as_1_5_5_printed_it() {
    let dir = common::plugins::scratch("export-second-scrape-1-5-5");
    let (ok, text) = validate(
        &dir,
        "  one: { module: prometheus, settings: { buffer_seconds: 60 } }\n  two: { module: \
         prometheus, settings: { buffer_seconds: 60 } }\n",
    );
    if !text.contains("unknown exporter 'prometheus'") {
        assert!(
            !ok,
            "a second scrape-sink instance validated clean:\n{text}"
        );
        let printed = text
            .lines()
            .filter(|l| l.trim_start_matches("  - ") == SECOND_SCRAPE_INSTANCE)
            .count();
        assert_eq!(printed, 1, "the refusal is not 1.5.5's line, once:\n{text}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
