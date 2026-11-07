// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::migration_table as declared_vocabulary;

pub fn retired_config_keys_1_5_3() -> Vec<(&'static str, String)> {
    let trace_home = format!(
        "an `export:` instance with `module: {}` and `settings.url`",
        declared_vocabulary::text("export_trace_module")
    );
    [


        ("observability", declared_vocabulary::text("observability_home").to_string()),

        ("admin_insecure", "admin_require_mtls (INVERTED: `admin_insecure: true` ⇒ `admin_require_mtls: false`)".to_string()),

        ("upstream_credentials", "pools.upstream_credentials (the all-pools default) + a per-pool `pools.<p>.upstream_credentials` override".to_string()),

        ("methods", "the matching `identity-providers:` definition (browser_login + settings are per-provider)".to_string()),

        (declared_vocabulary::text("observability_trace_key"), trace_home.clone()),
        (declared_vocabulary::text("observability_trace_key_1_4"), trace_home),
    ]
    .into_iter()
    .filter(|(old, _)| !old.is_empty())
    .collect()
}

pub fn retired_observability_keys() -> Vec<(&'static str, String)> {
    let log = declared_vocabulary::text("observability_log_type_key");
    let mut out: Vec<(&'static str, String)> = declared_vocabulary::pairs("observability_log_keys")
        .into_iter()
        .map(|(old, leaf)| (old, format!("export.{log}.settings.{leaf}")))
        .collect();
    out.push((
        "metrics",
        format!(
            "export.{}.settings (buffer_seconds / key_gauge_limit)",
            declared_vocabulary::text("metrics_type_key")
        ),
    ));
    out
}

pub const RENAMED_HOOK_STAGES: &[(&str, &str)] = &[
    ("route", "candidate"),
    ("attempt", "routing"),
    ("completion", "response"),
];
