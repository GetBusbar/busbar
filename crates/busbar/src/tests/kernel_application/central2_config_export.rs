// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use busbar_kernel::config::*;

#[test]
fn test_limits_set_value_overrides_default() {
    crate::dist_root_install::install();
    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  acme:
    api_key: { env: ACME_KEY }
models:
  widget:
    provider: acme
    max_concurrent: 10
limits:
  upstream_request_timeout_secs: 42
  max_inbound_concurrent: 256
  request_body_max_bytes: 1048576
  pool_idle_timeout_secs: 77
export:
  metrics:
    module: prometheus
    settings:
      buffer_seconds: 30
      key_gauge_limit: 9
advanced:
  rate_sweep_interval: 64
  usage_flush_interval_ms: 5
health:
  default_probe_interval_secs: 7
routing:
  default_policy_timeout_ms: 99
"#;
    let deploy: DeployCfg = serde_yaml::from_str(yaml).expect("limits override must parse");
    let l = LimitsResolved::from_sections(
        &deploy.limits,
        &deploy.advanced,
        &busbar_kernel::config::resolve_export(&deploy.export, &mut Vec::new()),
        &deploy.health,
        &deploy.routing,
    );
    assert_eq!(l.upstream_request_timeout_secs, 42);
    assert_eq!(l.max_inbound_concurrent, 256);
    assert_eq!(l.request_body_max_bytes, 1_048_576);
    assert_eq!(l.pool_idle_timeout_secs, 77);
    assert_eq!(l.key_gauge_limit, 9);
    assert_eq!(l.rate_sweep_interval, 64);
    assert_eq!(l.usage_flush_interval_ms, 5);
    assert_eq!(l.default_probe_interval_secs, 7);
    assert_eq!(l.default_policy_timeout_ms, 99);

    assert_eq!(l.pool_max_idle_per_host, DEFAULT_POOL_MAX_IDLE_PER_HOST);
    assert_eq!(l.default_probe_timeout_secs, DEFAULT_PROBE_TIMEOUT_SECS);
    assert_eq!(l.hard_down_cooldown_secs, DEFAULT_HARD_DOWN_COOLDOWN_SECS);
}

#[test]
fn export_named_map_allows_two_instances_of_one_module() {
    crate::dist_root_install::install();
    let defs: busbar_kernel::config::ExportDefs = serde_yaml::from_str(
        "req-log:  { module: request-log-webhook, settings: { url: \"https://logs.example.com/a\" } }\n\
         req-siem: { module: request-log-webhook, settings: { url: \"https://siem.internal/b\", delivery_timeout_secs: 9 } }\n",
    )
    .expect("two instances of one module parse");
    let mut errors = Vec::new();
    let export = busbar_kernel::config::resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(export.plugins.len(), 2);
    assert_eq!(export.plugins[0].name, "req-log");
    assert_eq!(export.plugins[1].name, "req-siem");

    assert_eq!(
        export.plugins[0].def.settings.get("delivery_timeout_secs"),
        None
    );
    assert_eq!(
        export.plugins[1].def.settings["delivery_timeout_secs"],
        serde_json::json!(9)
    );

    let defs: busbar_kernel::config::ExportDefs = serde_yaml::from_str(
        "one: { module: prometheus, settings: { buffer_seconds: 60 } }\n\
         two: { module: prometheus, settings: { buffer_seconds: 60 } }\n",
    )
    .expect("parses");
    let mut errors = Vec::new();
    let export = busbar_kernel::config::resolve_export(&defs, &mut errors);
    assert_eq!(
        errors,
        busbar_export_prometheus::check_limits(&["one".to_string(), "two".to_string()]),
        "the module's own words, verbatim"
    );
    assert_eq!(
        export.plugins.len(),
        1,
        "the extra instance is not resolved"
    );

    let defs: busbar_kernel::config::ExportDefs =
        serde_yaml::from_str("x: { module: nope }\n").expect("parses");
    let mut errors = Vec::new();
    let _ = busbar_kernel::config::resolve_export(&defs, &mut errors);
    assert!(
        errors.iter().any(|e| e.starts_with(
            "export.x.module: unknown exporter 'nope'; the built-in export modules are "
        )),
        "an unknown export module must name the modules this build serves; got {errors:?}"
    );
}
