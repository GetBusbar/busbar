// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIG-BUILTIN: a 1.5.5 setup that used a module 1.6.0 no longer links in (the four exporters, the
//! webhook-signature auth module) is carried, never refused: the config is kept as written and the
//! report names the plugin to install.

use crate::scratch::{accept, facts, Scratch};
use crate::{plan, write, Inputs, Written};

const SOURCE: &str =
    include_str!("../../../../dist/default/tests/fixtures/upgrade_1_5_5/former_builtins.yaml");

#[test]
fn former_builtin_setup_is_carried_and_names_each_plugin_to_install() {
    let scratch = Scratch::new();
    let path = scratch.deployment(SOURCE);
    let facts = facts();
    let planned = plan(&Inputs::new(&path, &facts, &accept))
        .unwrap_or_else(|refusal| panic!("a former built-in is carried, not refused: {refusal}"));
    let report = planned.report().join("\n");
    assert_eq!(write(&planned, &accept), Ok(Written::Stamped));
    let written = std::fs::read_to_string(&path).unwrap();
    for (instance, module, plugin) in [
        ("metrics", "prometheus", "busbar-export-prometheus"),
        ("traces", "otlp", "busbar-export-otlp"),
        ("req-log", "request-log-webhook", "busbar-export-webhook"),
        ("req-file", "request-log-file", "busbar-export-file"),
        ("twilio", "webhook-signature", "busbar-auth-webhook-signature"),
    ] {
        assert!(
            written.contains(&format!("module: {module}")),
            "{module}: the entry is kept"
        );
        let line = report
            .lines()
            .find(|line| line.contains(plugin))
            .unwrap_or_else(|| panic!("{plugin} is named in the report:\n{report}"));
        assert!(
            line.contains(instance) && line.contains(module),
            "{line}: names the instance and the module"
        );
    }
    assert!(
        written.contains("signing_secret: { env: TWILIO_AUTH_TOKEN }")
            && written.contains("url: { env: REQ_LOG_URL }"),
        "secrets stay references"
    );
}

#[test]
fn former_builtin_report_never_carries_a_setting_value() {
    let scratch = Scratch::new();
    let path = scratch.deployment(SOURCE);
    let facts = facts();
    let planned = plan(&Inputs::new(&path, &facts, &accept)).unwrap();
    let report = planned.report().join("\n");
    for value in ["TWILIO_AUTH_TOKEN", "REQ_LOG_URL", "otel.example.com", "edge.example.com"] {
        assert!(!report.contains(value), "{value} leaked into the report");
    }
}
