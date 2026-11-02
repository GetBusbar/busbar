// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::migrate::*;

#[path = "../../../../busbar-kernel/src/config/legacy_markers.rs"]
mod legacy_markers;
use legacy_markers::{detect_legacy_markers, legacy_config_error};

const LEGACY_14X: &str = r#"
listen: "0.0.0.0:8080"
auth:
  chain: ["test-idp-double"]
  group_map:
    growth-eng:
      allowed_pools: [fast]
      group: growth
    platform:
      allowed_pools: []
      admin_scope: full
    capped:
      rpm_limit: 60
      tpm_limit: 100000
      max_budget_cents: 5000
      budget_period: monthly
governance:
  enabled: true
  store: acme-durable
  db_path: "acme://host/db"
  admin_token: "${BUSBAR_ADMIN_TOKEN}"
  price_per_request_cents: 2
  rate_sweep_interval: 128
  usage_flush_interval_ms: 50
  rate_card:
    widget: { input_utok: 3.0, output_utok: 15.0 }
  budget_groups:
    acme: { max_budget_cents: 1000000, budget_period: monthly }
    growth: { max_budget_cents: 200000, budget_period: daily, parent: acme }
providers:
  vendor-a:
    api_key_env: VENDOR_A_KEY
models:
  widget: { provider: vendor-a }
pools:
  fast:
    members:
      - { target: widget, weight: 1, cost_per_mtok: 4 }
    hooks: [cheapest, pii-screen]
    breaker:
      base_cooldown_secs: 15
      trip: { mode: error_rate, window_s: 30, n: 3 }
    failover: { deadline_secs: 120, cap: 3 }
hooks:
  pii-screen:
    kind: gate
    socket: /run/pii.sock
    timeout_ms: 2
    on_error: reject
  audit-tap:
    kind: tap
    webhook: "https://sidecar.internal/audit"
    global: true
observability:
  otlp_endpoint: "http://otel:4318/v1/traces"
"#;

#[test]
fn legacy_markers_detected_and_named() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let doc: serde_yaml::Value = serde_yaml::from_str(LEGACY_14X).unwrap();
    let markers = detect_legacy_markers(&doc);
    let joined = markers.join("\n");
    for expect in [
        "`governance:`",
        "`auth.group_map:`",
        "top-level `hooks:`",
        "api_key_env",
        "target:",
    ] {
        assert!(
            joined.contains(expect),
            "marker '{expect}' missing from: {joined}"
        );
    }
    let err = legacy_config_error(&markers);
    assert!(
        err.contains("busbar --migrate-config"),
        "the refusal must point at the migrator: {err}"
    );
    assert!(
        err.contains("1.x"),
        "the refusal must name the version family: {err}"
    );

    let clean = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/clean-config-1.5.0.yaml"),
    )
    .expect("the canonical example exists");
    let doc: serde_yaml::Value = serde_yaml::from_str(&clean).unwrap();
    assert!(
        detect_legacy_markers(&doc).is_empty(),
        "the canonical 1.5.0 example must not trip the 1.x detector"
    );
}

#[test]
fn auth_mode_marker_detected() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let doc: serde_yaml::Value =
        serde_yaml::from_str("auth:\n  mode: token\nproviders: {}\nmodels: {}\n").unwrap();
    let markers = detect_legacy_markers(&doc);
    assert!(
        markers.iter().any(|m| m.contains("`auth.mode:`")),
        "{markers:?}"
    );
}

#[test]
fn migrate_14x_round_trips_into_deploy_cfg() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let out = migrate_config(LEGACY_14X).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("output is valid YAML");
    let root = doc.as_mapping().unwrap();
    let get = |path: &[&str]| -> serde_yaml::Value {
        let mut cur = serde_yaml::Value::Mapping(root.clone());
        for k in path {
            cur = cur
                .as_mapping()
                .and_then(|m| m.get(serde_yaml::Value::from(*k)).cloned())
                .unwrap_or_else(|| panic!("path {path:?} missing at '{k}'"));
        }
        cur
    };

    assert!(root.get(serde_yaml::Value::from("governance")).is_none());
    assert_eq!(get(&["store", "module"]).as_str(), Some("acme-durable"));
    assert_eq!(
        get(&["store", "settings", "url"]).as_str(),
        Some("acme://host/db")
    );
    assert_eq!(get(&["per_request_fee"]).as_u64(), Some(2));
    assert_eq!(
        get(&["advanced", "rate_sweep_interval"]).as_u64(),
        Some(128)
    );
    assert_eq!(
        get(&["rate_card", "widget", "input_utok"]).as_f64(),
        Some(3.0)
    );

    let growth_limits = get(&["groups", "growth", "limits"]);
    let growth_limit = &growth_limits.as_sequence().unwrap()[0];
    assert_eq!(
        growth_limit
            .as_mapping()
            .unwrap()
            .get(serde_yaml::Value::from("per"))
            .and_then(|v| v.as_str()),
        Some("day")
    );
    assert_eq!(get(&["groups", "growth", "parent"]).as_str(), Some("acme"));

    let op = busbar_kernel::config::operator_provider();
    let admin_auth = get(&["auth", "admin_auth"]);
    assert_eq!(
        admin_auth.as_sequence().unwrap()[0].as_str(),
        Some(op),
        "a 1.5.3 admin chain is a list of bare PROVIDER NAMES"
    );

    let token_env = get(&["identity-providers", op, "token", "env"])
        .as_str()
        .map(str::to_string);
    assert_eq!(token_env.as_deref(), Some("BUSBAR_ADMIN_TOKEN"));

    assert_eq!(
        get(&[
            "auth",
            "role_bindings",
            "test-idp-double",
            "growth-eng",
            "group"
        ])
        .as_str(),
        Some("growth")
    );

    assert_eq!(
        get(&[
            "auth",
            "role_bindings",
            "test-idp-double",
            "capped",
            "group"
        ])
        .as_str(),
        Some("migrated-capped")
    );
    let ml = get(&["groups", "migrated-capped", "limits"]);
    let limits = ml.as_sequence().unwrap();
    assert_eq!(limits.len(), 3, "rpm + tpm + budget -> three limits");

    assert_eq!(
        get(&["providers", "vendor-a", "api_key", "env"]).as_str(),
        Some("VENDOR_A_KEY")
    );

    let members = get(&["pools", "fast", "members"]);
    let member = members.as_sequence().unwrap()[0]
        .as_mapping()
        .expect("the member is still a rich object");
    assert_eq!(
        member
            .get(serde_yaml::Value::from("model"))
            .and_then(|v| v.as_str()),
        Some("widget"),
        "`target:` was renamed to `model:` in place"
    );
    for retired in ["target", "cost_per_mtok"] {
        assert!(
            !member.contains_key(serde_yaml::Value::from(retired)),
            "the retired member key `{retired}` is gone"
        );
    }
    assert_eq!(
        get(&["pools", "fast", "breaker", "trip", "window_secs"]).as_u64(),
        Some(30)
    );
    assert_eq!(
        get(&["pools", "fast", "breaker", "trip", "consecutive_n"]).as_u64(),
        Some(3)
    );
    assert_eq!(
        get(&["pools", "fast", "failover", "timeout_secs"]).as_u64(),
        Some(120)
    );
    assert_eq!(
        get(&["pools", "fast", "failover", "max_hops"]).as_u64(),
        Some(3)
    );

    assert_eq!(
        get(&["hooks", "pii-screen", "module"]).as_str(),
        Some("socket"),
        "the socket transport became module: socket"
    );
    assert_eq!(
        get(&["hooks", "pii-screen", "settings", "path"]).as_str(),
        Some("/run/pii.sock")
    );
    assert_eq!(
        get(&["hooks", "audit-tap", "module"]).as_str(),
        Some("webhook"),
        "the webhook transport became module: webhook"
    );
    let pool_hooks = get(&["pools", "fast", "hooks"]);
    let pool_hooks = pool_hooks.as_sequence().unwrap();
    assert_eq!(
        pool_hooks[0].as_str(),
        Some("cheapest"),
        "strategies stay bare"
    );
    assert_eq!(
        pool_hooks[1].as_str(),
        Some("pii-screen"),
        "a registry reference is now a BARE hook name, not an inline instance"
    );
    let all_pools = get(&["pools", "hooks"]);
    assert_eq!(
        all_pools
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>(),
        ["audit-tap"],
        "the global: true tap became the reserved pools.hooks all-pools attach"
    );

    assert_eq!(get(&["export", "traces", "module"]).as_str(), Some("otlp"));
    assert_eq!(
        get(&["export", "traces", "settings", "url"]).as_str(),
        Some("http://otel:4318/v1/traces")
    );

    assert_eq!(
        out.warnings
            .iter()
            .filter(|w| w.contains("allowed_pools: []") && w.contains("platform"))
            .count(),
        1,
        "warnings: {:?}",
        out.warnings
    );

    assert!(out.yaml.contains("# WARNING(migrate):"));

    assert!(detect_legacy_markers(&doc).is_empty());
    let deploy: Result<busbar_kernel::config::DeployCfg, _> =
        busbar_kernel::config::deploy_from_yaml_str(&out.yaml);
    assert!(
        deploy.is_ok(),
        "migrated config must boot-parse: {:?}",
        deploy.err().map(|e| e.to_string())
    );
}

fn migrate_to_value(raw: &str) -> (MigrateOutput, serde_yaml::Value) {
    let out = migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("output is valid YAML");
    (out, doc)
}

fn dig<'a>(doc: &'a serde_yaml::Value, path: &[&str]) -> Option<&'a serde_yaml::Value> {
    let mut cur = doc;
    for k in path {
        cur = cur.as_mapping()?.get(serde_yaml::Value::from(*k))?;
    }
    Some(cur)
}

#[test]
fn detect_real_14x_top_level_and_on_exhausted_markers() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
auth:
  chain: [tokens]
  modules: { test-idp-double: { max_admin_scope: full } }
group_map: { r1: { allowed_pools: [fast] } }
admin_auth: [admin-tokens]
providers: {}
models: {}
pools:
  primary:
    members: [ { target: a } ]
    on_exhausted: { action: "fallback_pool:overflow" }
"#;
    let doc: serde_yaml::Value = serde_yaml::from_str(raw).unwrap();
    let joined = detect_legacy_markers(&doc).join("\n");
    for expect in [
        "top-level `group_map:`",
        "top-level `admin_auth:`",
        "`auth.modules:`",
        "`auth.chain: [tokens]`",
        "on_exhausted.action",
    ] {
        assert!(
            joined.contains(expect),
            "marker '{expect}' missing from:\n{joined}"
        );
    }
}

#[test]
fn migrate_realistic_14x_governance_preserves_the_real_db_path() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
governance:
  enabled: true
  db_path: /var/lib/busbar/governance.db
  admin_token: "${BUSBAR_ADMIN_TOKEN}"
providers: {}
models: {}
pools: {}
"#;
    let out = migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("output is valid YAML");
    let root = doc.as_mapping().unwrap();
    let get = |path: &[&str]| -> serde_yaml::Value {
        let mut cur = serde_yaml::Value::Mapping(root.clone());
        for k in path {
            cur = cur
                .as_mapping()
                .and_then(|m| m.get(serde_yaml::Value::from(*k)).cloned())
                .unwrap_or_else(|| panic!("path {path:?} missing at '{k}'"));
        }
        cur
    };
    assert_eq!(
        get(&["store", "module"]).as_str(),
        Some(
            serde_yaml::from_str::<serde_yaml::Value>(include_str!(
                "../../../../busbar-kernel/src/tests/fixtures/frozen_customer_text.yaml"
            ))
            .expect("the frozen customer text")["legacy_backend_1_4"]
                .as_str()
                .expect("the frozen string")
                .to_string()
                .as_str()
        ),
        "1.4.x's only durable backend -- migration must select it, not default to memory"
    );
    assert_eq!(
        get(&["store", "settings", "db_path"]).as_str(),
        Some("/var/lib/busbar/governance.db"),
        "the operator's REAL existing database path must survive migration, not get silently dropped"
    );
}

#[test]
fn migrate_14x_governance_with_no_explicit_db_path_uses_the_14x_default() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
governance:
  enabled: true
providers: {}
models: {}
pools: {}
"#;
    let out = migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("output is valid YAML");
    let root = doc.as_mapping().unwrap();
    let store = root
        .get(serde_yaml::Value::from("store"))
        .and_then(|v| v.as_mapping().cloned())
        .expect("store: section must be present even when db_path was implicit");
    assert_eq!(
        store
            .get(serde_yaml::Value::from("module"))
            .and_then(|v| v.as_str()),
        Some(
            serde_yaml::from_str::<serde_yaml::Value>(include_str!(
                "../../../../busbar-kernel/src/tests/fixtures/frozen_customer_text.yaml"
            ))
            .expect("the frozen customer text")["legacy_backend_1_4"]
                .as_str()
                .expect("the frozen string")
                .to_string()
                .as_str()
        )
    );
    assert_eq!(
        store
            .get(serde_yaml::Value::from("settings"))
            .and_then(|v| v.as_mapping())
            .and_then(|m| m.get(serde_yaml::Value::from("db_path")))
            .and_then(|v| v.as_str()),
        Some("busbar-governance.db"),
        "must reproduce 1.4.x's real implicit default path, not a 1.5.0-side default"
    );
}

#[test]
fn detect_retired_observability_export_keys_loud_fail() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
observability:
  request_log_webhook_url: "https://logs.example.com/busbar"
  max_inflight_webhook_deliveries: 32
metrics:
  buffer_seconds: 60
providers: {}
models: {}
pools: {}
"#;
    let doc: serde_yaml::Value = serde_yaml::from_str(raw).unwrap();
    let markers = detect_legacy_markers(&doc);
    let joined = markers.join("\n");
    assert!(
        joined.contains("request_log_webhook_url"),
        "the retired webhook key must loud-fail with a named marker; got: {joined}"
    );
    assert!(
        joined.contains("metrics"),
        "the retired top-level metrics block must loud-fail; got: {joined}"
    );

    assert!(
        joined.contains("export.request-log-webhook") && joined.contains("export.prometheus"),
        "markers must name the new export home; got: {joined}"
    );
}

#[test]
fn migrate_1_5_x_inline_hooks_converge_and_are_idempotent() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
providers: {}
models: {}
pools:
  fast:
    members: [ { model: a } ]
    hooks:
      - cheapest
      - { module: busbar-phi, settings: { url: "https://s/pii" }, kind: gate, on_error: reject }
global_hooks:
  - { module: busbar-audit, settings: { url: "https://s/audit" }, kind: tap, at: completion }
"#;
    let out1 = migrate_config(raw).expect("migrates");

    let doc: serde_yaml::Value = serde_yaml::from_str(&out1.yaml).expect("valid YAML");
    assert!(
        detect_legacy_markers(&doc).is_empty(),
        "no residual 1.x marker"
    );
    let deploy: busbar_kernel::config::DeployCfg =
        busbar_kernel::config::deploy_from_yaml_str(&out1.yaml)
            .expect("migrated config boot-parses");

    assert!(
        !deploy.hooks.is_empty(),
        "named hooks: definition map present"
    );
    let fast = &deploy.pools.pools["fast"];
    assert_eq!(fast.policy, busbar_kernel::config::PoolPolicy::Cheapest);
    assert_eq!(
        fast.gates.len(),
        1,
        "the inline pool hook became one bare reference"
    );
    assert!(
        deploy.hooks.contains_key(&fast.gates[0]),
        "the pool's bare reference resolves to a named definition"
    );
    assert_eq!(
        deploy.pools.all_pool_hooks.len(),
        1,
        "the inline global instance became the reserved pools.hooks all-pools attach"
    );
    assert!(
        deploy.hooks.contains_key(&deploy.pools.all_pool_hooks[0]),
        "the all-pools reference resolves to a named definition"
    );

    let audit = &deploy.hooks[&deploy.pools.all_pool_hooks[0]];
    assert_eq!(
        audit.phase,
        vec![busbar_kernel::config::HookStage::Response]
    );

    let out2 = migrate_config(&out1.yaml).expect("re-migrates");
    let v1: serde_yaml::Value = serde_yaml::from_str(&out1.yaml).unwrap();
    let v2: serde_yaml::Value = serde_yaml::from_str(&out2.yaml).unwrap();
    assert_eq!(
        v1, v2,
        "the migration must be idempotent on the config tree"
    );
}

fn assert_loud_fail_with_breadcrumb(raw: &str, needle: &str) {
    let doc: serde_yaml::Value = serde_yaml::from_str(raw).expect("valid YAML");
    let markers = detect_legacy_markers(&doc);
    assert!(
        markers.iter().any(|m| m.contains(needle)),
        "the retired key '{needle}' must trip the boot detector; got {markers:?}"
    );
    let err = legacy_config_error(&markers);
    assert!(
        err.contains("busbar --migrate-config"),
        "the refusal must point at the migrator: {err}"
    );
}

fn migrate_golden(
    raw: &str,
) -> (
    busbar_kernel::config::migrate::MigrateOutput,
    serde_yaml::Value,
) {
    let (out, doc) = migrate_to_value(raw);
    let yaml = serde_yaml::to_string(&doc).expect("serializable");
    let _: busbar_kernel::config::DeployCfg = busbar_kernel::config::deploy_from_yaml_str(&yaml)
        .expect("the migrated config must boot-parse as 1.5.3");
    let (_out2, doc2) = migrate_to_value(&yaml);
    assert_eq!(
        doc, doc2,
        "the migration must be a FIXED POINT: re-running it changes nothing"
    );
    (out, doc)
}

#[test]
fn golden_migrate_admin_insecure_inverts_to_admin_require_mtls() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "admin_insecure: true\nproviders: {}\nmodels: {}\npools: {}\n";
    assert_loud_fail_with_breadcrumb(raw, "admin_insecure");

    let (out, doc) = migrate_golden(raw);
    assert!(
        dig(&doc, &["admin_insecure"]).is_none(),
        "the retired key must not survive migration"
    );
    assert_eq!(
        dig(&doc, &["admin_require_mtls"]).and_then(|v| v.as_bool()),
        Some(false),
        "an explicit 1.5.2 waiver must survive as the 1.5.3 waiver, INVERTED"
    );
    assert!(
        out.changes.iter().any(|c| c.contains("admin_require_mtls")),
        "the change ledger names the inversion; got {:?}",
        out.changes
    );

    let (_, doc) = migrate_golden("admin_insecure: false\nproviders: {}\nmodels: {}\npools: {}\n");
    assert_eq!(
        dig(&doc, &["admin_require_mtls"]).and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[test]
fn golden_migrate_auth_upstream_credentials_moves_to_pools() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "auth:\n  chain: [keys]\n  upstream_credentials: passthrough\n\
               providers: {}\nmodels: {}\npools: {}\n";
    assert_loud_fail_with_breadcrumb(raw, "auth.upstream_credentials");

    let (out, doc) = migrate_golden(raw);
    assert!(
        dig(&doc, &["auth", "upstream_credentials"]).is_none(),
        "the retired key must not survive under auth:"
    );
    assert_eq!(
        dig(&doc, &["pools", "upstream_credentials"]).and_then(|v| v.as_str()),
        Some("passthrough"),
        "the mode lands on the reserved `pools:` section key, VALUE PRESERVED"
    );
    assert!(
        out.changes
            .iter()
            .any(|c| c.contains("pools.upstream_credentials")),
        "the change ledger names the move; got {:?}",
        out.changes
    );
}

#[test]
fn golden_migrate_observability_block_folds_into_an_otlp_export_instance() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "observability:\n  otlp_url: \"http://otel:4318/v1/traces\"\n\
               providers: {}\nmodels: {}\npools: {}\n";
    assert_loud_fail_with_breadcrumb(raw, "observability");

    let (out, doc) = migrate_golden(raw);
    assert!(
        dig(&doc, &["observability"]).is_none(),
        "the whole block is DELETED in 1.5.3"
    );
    assert_eq!(
        dig(&doc, &["export", "traces", "module"]).and_then(|v| v.as_str()),
        Some("otlp")
    );
    assert_eq!(
        dig(&doc, &["export", "traces", "settings", "url"]).and_then(|v| v.as_str()),
        Some("http://otel:4318/v1/traces"),
        "the trace sink is PRESERVED, not lost with the block"
    );
    assert!(
        out.changes.iter().any(|c| c.contains("otlp")),
        "the change ledger names the fold; got {:?}",
        out.changes
    );

    let (_, doc) = migrate_golden(
        "observability:\n  otlp_endpoint: \"http://otel:4318/v1/traces\"\n\
         providers: {}\nmodels: {}\npools: {}\n",
    );
    assert_eq!(
        dig(&doc, &["export", "traces", "settings", "url"]).and_then(|v| v.as_str()),
        Some("http://otel:4318/v1/traces")
    );
}

#[test]
fn golden_migrate_type_keyed_export_becomes_a_named_map() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "export:\n\
               \x20 prometheus: { settings: { buffer_seconds: 60 } }\n\
               \x20 request-log-webhook: { settings: { url: \"https://logs.example.com/a\" } }\n\
               \x20 generic-webhook: { settings: { url: \"https://siem.internal/b\", auth_header: { name: Authorization, value: \"Bearer x\" } } }\n\
               providers: {}\nmodels: {}\npools: {}\n";
    assert_loud_fail_with_breadcrumb(raw, "TYPE-KEYED");

    let (_out, doc) = migrate_golden(raw);
    assert_eq!(
        dig(&doc, &["export", "metrics", "module"]).and_then(|v| v.as_str()),
        Some("prometheus")
    );
    assert_eq!(
        dig(&doc, &["export", "req-log", "module"]).and_then(|v| v.as_str()),
        Some("request-log-webhook")
    );

    assert_eq!(
        dig(&doc, &["export", "req-log-audit", "module"]).and_then(|v| v.as_str()),
        Some("request-log-webhook")
    );
    assert_eq!(
        dig(
            &doc,
            &["export", "req-log-audit", "settings", "auth_header", "name"]
        )
        .and_then(|v| v.as_str()),
        Some("Authorization")
    );

    let deploy: busbar_kernel::config::DeployCfg =
        busbar_kernel::config::deploy_from_yaml_str(&serde_yaml::to_string(&doc).unwrap())
            .expect("boot-parses");
    let mut errs = Vec::new();
    let export = busbar_kernel::config::resolve_export(&built_ins(&deploy.export), &mut errs);
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(webhooks(&deploy.export), 2);
    assert!(export.recorder.is_some());
}

#[test]
fn golden_migrate_inline_chain_entries_dedupe_into_identity_providers() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();

    let op = busbar_kernel::config::operator_provider();
    let raw = format!(
        "auth:\n\
         \x20 chain:\n\
         \x20   - keys\n\
         \x20   - test-idp-double: {{ settings: {{ issuer: \"https://idp.example/\" }} }}\n\
         \x20 admin_auth:\n\
         \x20   - {op}: {{ token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
         \x20   - test-idp-double: {{ max_admin_scope: full }}\n\
         \x20 methods:\n\
         \x20   test-idp-double:\n\
         \x20     audience: busbar\n\
         \x20     browser_login: {{ client_id: busbar-web }}\n\
         providers: {{}}\nmodels: {{}}\npools: {{}}\n"
    );
    let raw = raw.as_str();
    assert_loud_fail_with_breadcrumb(raw, "INLINE module entries");
    assert_loud_fail_with_breadcrumb(raw, "auth.methods");

    let (out, doc) = migrate_golden(raw);

    assert_eq!(
        dig(&doc, &["auth", "chain"])
            .and_then(|v| v.as_sequence().cloned())
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect::<Vec<_>>(),
        ["keys", "test-idp-double"]
    );
    assert_eq!(
        dig(&doc, &["auth", "admin_auth"])
            .and_then(|v| v.as_sequence().cloned())
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect::<Vec<_>>(),
        [op, "test-idp-double"]
    );
    assert!(
        dig(&doc, &["auth", "methods"]).is_none(),
        "the parallel methods map is gone"
    );

    let defs = dig(&doc, &["identity-providers"])
        .and_then(|v| v.as_mapping().cloned())
        .expect("identity-providers map");
    assert_eq!(
        defs.len(),
        2,
        "one definition per MODULE (test-idp-double + the operator credential), not one per REFERENCE: {defs:?}"
    );
    assert_eq!(
        dig(&doc, &["identity-providers", "test-idp-double", "module"]).and_then(|v| v.as_str()),
        Some("test-idp-double")
    );
    assert_eq!(
        dig(
            &doc,
            &["identity-providers", "test-idp-double", "max_admin_scope"]
        )
        .and_then(|v| v.as_str()),
        Some("full"),
        "the ceiling written on the ADMIN chain entry lands on the one definition"
    );
    assert_eq!(
        dig(
            &doc,
            &[
                "identity-providers",
                "test-idp-double",
                "settings",
                "issuer"
            ]
        )
        .and_then(|v| v.as_str()),
        Some("https://idp.example/"),
        "the settings written on the DATA chain entry land on the same definition"
    );
    assert_eq!(
        dig(
            &doc,
            &[
                "identity-providers",
                "test-idp-double",
                "settings",
                "audience"
            ]
        )
        .and_then(|v| v.as_str()),
        Some("busbar"),
        "the settings written on the METHODS entry merge in too"
    );
    assert_eq!(
        dig(
            &doc,
            &[
                "identity-providers",
                "test-idp-double",
                "browser_login",
                "client_id"
            ]
        )
        .and_then(|v| v.as_str()),
        Some("busbar-web"),
        "browser_login is PER-PROVIDER in 1.5.3"
    );

    assert_eq!(
        dig(&doc, &["identity-providers", op, "token", "env"]).and_then(|v| v.as_str()),
        Some("BUSBAR_ADMIN_TOKEN")
    );
    assert!(
        out.changes.iter().any(|c| c.contains("identity-providers")),
        "the change ledger names the lift; got {:?}",
        out.changes
    );

    let deploy: busbar_kernel::config::DeployCfg =
        busbar_kernel::config::deploy_from_yaml_str(&serde_yaml::to_string(&doc).unwrap())
            .expect("boot-parses");
    let mut errs = Vec::new();
    let auth = busbar_kernel::config::resolve_auth(
        deploy.auth.as_ref().expect("auth"),
        &deploy.identity_providers,
        &mut errs,
    );
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(auth.chain[1], auth.admin_auth[1]);
}

#[test]
fn golden_migrate_bare_tap_pins_the_legacy_request_only_phase() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "global_hooks:\n  - { module: busbar-audit-hook, kind: tap }\n\
               providers: {}\nmodels: {}\npools: {}\n";
    let (_, doc) = migrate_golden(raw);

    let hooks = dig(&doc, &["hooks"])
        .and_then(|v| v.as_mapping().cloned())
        .expect("the migrated doc carries a named `hooks:` definition map");
    let (_, def) = hooks
        .iter()
        .next()
        .expect("the inline global tap became exactly one named definition");

    let phase = def
        .as_mapping()
        .and_then(|m| m.get(serde_yaml::Value::from("phase")).cloned())
        .and_then(|v| v.as_sequence().cloned())
        .expect("a migrated bare TAP must carry an EXPLICIT `phase:` (not the widened default)");
    assert_eq!(
        phase,
        vec![serde_yaml::Value::from("request")],
        "a legacy tap with no `at:` fired at REQUEST only; migration must preserve exactly that, \
         not silently widen it to the four core stages"
    );

    let raw_gate = "global_hooks:\n  - { module: busbar-phi, kind: gate }\n\
                    providers: {}\nmodels: {}\npools: {}\n";
    let (_, doc_gate) = migrate_golden(raw_gate);
    let gates = dig(&doc_gate, &["hooks"])
        .and_then(|v| v.as_mapping().cloned())
        .expect("named hooks map");
    let (_, gdef) = gates.iter().next().expect("one definition");
    assert!(
        gdef.as_mapping()
            .and_then(|m| m.get(serde_yaml::Value::from("phase")))
            .is_none(),
        "a gate carries no `at:` default, so migration must not invent a `phase:` for it"
    );
}

/// 1.5.3 — the redis→valkey rename. The first-party Valkey store plugin was renamed
/// wholesale: repo, crate, artifact, manifest NAME (`busbar-store-valkey-plugin`) and the config
/// ALIAS (`valkey`). Nothing resolves `redis` any more — the loader matches a `store.module:` against
/// the installed manifests' `name`/`alias`, and neither spelling exists on the renamed artifact — so
/// an un-migrated `store.module: redis` is not a "wrong backend", it is a boot that cannot find its
/// store at all.
///
/// Both halves of the contract are asserted here:
///   (a) `detect_legacy_markers` LOUD-FAILS boot/`--validate` with a marker naming the old spelling,
///       the new one, and the `--migrate-config` breadcrumb — instead of the generic
///       "does not match any plugin" the loader would otherwise produce.
///   (b) `--migrate-config` mechanically rewrites the value, records a `changes` entry, and is
///       idempotent (a config already saying `valkey` is untouched and un-flagged).
///
/// Before `migrate_store_module` existed the migrated document still said
/// `redis` and `detect_legacy_markers` returned nothing for it.
#[test]
fn migrate_store_module_retired_1_5_3_spellings_to_the_renamed_alias() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let renamed = serde_yaml::from_str::<serde_yaml::Value>(include_str!(
        "../../../../busbar-kernel/src/tests/fixtures/frozen_customer_text.yaml"
    ))
    .expect("the frozen customer text")["renamed_module_1_5_3"]
        .as_str()
        .expect("the frozen string")
        .to_string();
    let retired = serde_yaml::from_str::<serde_yaml::Value>(include_str!(
        "../../../../busbar-kernel/src/tests/fixtures/frozen_customer_text.yaml"
    ))
    .expect("the frozen customer text")["retired_modules_1_5_3"]
        .clone();
    let retired: Vec<&str> = retired
        .as_sequence()
        .unwrap()
        .iter()
        .flat_map(|v| v.as_str())
        .collect();
    assert_eq!(retired.len(), 3, "the three retired 1.5.x spellings");
    for old in retired {
        let raw = format!(
            "store:\n  module: {old}\n  settings: {{ url: \"kv://127.0.0.1:6379/0\" }}\n\
             providers: {{}}\nmodels: {{}}\npools: {{}}\n"
        );

        let doc: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
        let joined = detect_legacy_markers(&doc).join("\n");
        assert!(
            joined.contains(old) && joined.contains(renamed.as_str()),
            "`store.module: {old}` must loud-fail with a marker naming the old AND new spelling; \
             got: {joined}"
        );

        let (out, doc) = migrate_to_value(&raw);
        assert_eq!(
            dig(&doc, &["store", "module"]).and_then(|v| v.as_str()),
            Some(renamed.as_str()),
            "`store.module: {old}` must be rewritten to the new alias; migrated:\n{}",
            out.yaml
        );

        assert_eq!(
            dig(&doc, &["store", "settings", "url"]).and_then(|v| v.as_str()),
            Some("kv://127.0.0.1:6379/0"),
            "the operator's connection URL must survive verbatim; migrated:\n{}",
            out.yaml
        );
        assert!(
            out.changes.iter().any(|c| c.contains("store.module")),
            "the rewrite must be RECORDED in the change ledger; got {:?}",
            out.changes
        );

        assert!(
            detect_legacy_markers(&doc).is_empty(),
            "the migrated document still trips the 1.x detector: {:?}",
            detect_legacy_markers(&doc)
        );
    }

    let already =
        format!("store:\n  module: {renamed}\nproviders: {{}}\nmodels: {{}}\npools: {{}}\n");
    let (out, doc) = migrate_to_value(&already);
    assert_eq!(
        dig(&doc, &["store", "module"]).and_then(|v| v.as_str()),
        Some(renamed.as_str())
    );
    assert!(
        !out.changes.iter().any(|c| c.contains("store.module")),
        "a config already on the new alias must produce no store.module change; got {:?}",
        out.changes
    );

    let other = "store:\n  module: acme-durable\nproviders: {}\nmodels: {}\npools: {}\n";
    let (_, doc) = migrate_to_value(other);
    assert_eq!(
        dig(&doc, &["store", "module"]).and_then(|v| v.as_str()),
        Some("acme-durable")
    );
}

fn webhooks(defs: &busbar_kernel::config::ExportDefs) -> usize {
    defs.values()
        .filter(|d| d.module.trim() == "request-log-webhook")
        .count()
}

fn built_ins(defs: &busbar_kernel::config::ExportDefs) -> busbar_kernel::config::ExportDefs {
    defs.iter()
        .filter(|(_, d)| d.module.trim() != "request-log-webhook")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[test]
fn golden_migrate_terraform_acceptance_admin_insecure_inline_admin_auth() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"admin_listen: "0.0.0.0:8081"
admin_insecure: true
models:
  test-model:
    provider: anthropic
    max_concurrent: 1
    max_requests: -1
providers:
  anthropic:
    api_key: { env: "ANTHROPIC_API_KEY" }
auth:
  chain: [keys]
  admin_auth:
    - admin-tokens: { token: { env: "BUSBAR_ADMIN_TOKEN" } }
"#;
    assert_loud_fail_with_breadcrumb(raw, "admin_insecure");

    let (out, doc) = migrate_golden(raw);
    assert_eq!(
        dig(&doc, &["admin_require_mtls"]).and_then(|v| v.as_bool()),
        Some(false),
        "the admin waiver survives, inverted; changes {:?}",
        out.changes
    );
    assert_eq!(
        dig(&doc, &["auth", "admin_auth"])
            .and_then(|v| v.as_sequence())
            .map(|s| s.len()),
        Some(1),
        "the admin chain keeps its one entry: {doc:?}"
    );
    assert!(
        dig(&doc, &["identity-providers", "admin-tokens", "token"]).is_some(),
        "the operator credential is lifted into identity-providers: {doc:?}"
    );
}
