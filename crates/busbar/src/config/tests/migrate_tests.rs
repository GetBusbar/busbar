// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the 1.4.x -> 1.5.0 config migrator + the loud fail-closed 1.x detector (P9).

use super::*;

/// A representative 1.4.x config exercising every deterministic transform at once.
const LEGACY_14X: &str = r#"
listen: "0.0.0.0:8080"
auth:
  chain: ["oidc"]
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
  store: postgres
  db_path: "postgres://host/db"
  admin_token: "${BUSBAR_ADMIN_TOKEN}"
  price_per_request_cents: 2
  rate_sweep_interval: 128
  usage_flush_interval_ms: 50
  rate_card:
    claude: { input_utok: 3.0, output_utok: 15.0 }
  budget_groups:
    acme: { max_budget_cents: 1000000, budget_period: monthly }
    growth: { max_budget_cents: 200000, budget_period: daily, parent: acme }
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
models:
  claude: { provider: anthropic }
pools:
  fast:
    members:
      - { target: claude, weight: 1, cost_per_mtok: 4 }
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

/// Every 1.x structural marker is DETECTED and NAMED; a clean 1.5.0 document yields none.
#[test]
fn legacy_markers_detected_and_named() {
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

    // A clean 1.5.0 shape (the canonical example) has NO markers.
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

/// `auth.mode:` alone (the oldest marker) trips the detector too.
#[test]
fn auth_mode_marker_detected() {
    let doc: serde_yaml::Value =
        serde_yaml::from_str("auth:\n  mode: token\nproviders: {}\nmodels: {}\n").unwrap();
    let markers = detect_legacy_markers(&doc);
    assert!(
        markers.iter().any(|m| m.contains("`auth.mode:`")),
        "{markers:?}"
    );
}

/// The migrated output covers every deterministic transform, parses as YAML, and its VALUE TREE
/// deserializes into the 1.5.0 `DeployCfg` (boot-parses) - the round-trip that makes the
/// migration path real.
#[test]
fn migrate_14x_round_trips_into_deploy_cfg() {
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

    // governance dissolved.
    assert!(root.get(serde_yaml::Value::from("governance")).is_none());
    assert_eq!(get(&["store", "module"]).as_str(), Some("postgres"));
    assert_eq!(
        get(&["store", "settings", "url"]).as_str(),
        Some("postgres://host/db")
    );
    assert_eq!(get(&["per_request_fee"]).as_u64(), Some(2));
    assert_eq!(
        get(&["advanced", "rate_sweep_interval"]).as_u64(),
        Some(128)
    );
    assert_eq!(
        get(&["rate_card", "claude", "input_utok"]).as_f64(),
        Some(3.0)
    );
    // budget_groups -> groups with C8 window nouns (daily -> day, monthly -> month).
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
    // admin_token ${VAR} -> admin-tokens secret ref.
    let admin_auth = get(&["auth", "admin_auth"]);
    assert_eq!(
        admin_auth.as_sequence().unwrap()[0].as_str(),
        Some("admin-tokens"),
        "a 1.5.3 admin chain is a list of bare PROVIDER NAMES"
    );
    // The operator credential rode along onto the `identity-providers:` DEFINITION (audit §2).
    let token_env = get(&["identity-providers", "admin-tokens", "token", "env"])
        .as_str()
        .map(str::to_string);
    assert_eq!(token_env.as_deref(), Some("BUSBAR_ADMIN_TOKEN"));
    // group_map -> role_bindings nested under the ONE external chain module.
    assert_eq!(
        get(&["auth", "role_bindings", "oidc", "growth-eng", "group"]).as_str(),
        Some("growth")
    );
    // Inline caps became a generated group bound to the role.
    assert_eq!(
        get(&["auth", "role_bindings", "oidc", "capped", "group"]).as_str(),
        Some("migrated-capped")
    );
    let ml = get(&["groups", "migrated-capped", "limits"]);
    let limits = ml.as_sequence().unwrap();
    assert_eq!(limits.len(), 3, "rpm + tpm + budget -> three limits");
    // api_key_env -> secret ref.
    assert_eq!(
        get(&["providers", "anthropic", "api_key", "env"]).as_str(),
        Some("ANTHROPIC_KEY")
    );
    // target -> model; cost off members; alias renames.
    let members = get(&["pools", "fast", "members"]);
    let member = members.as_sequence().unwrap()[0].as_mapping().unwrap();
    assert_eq!(
        member
            .get(serde_yaml::Value::from("model"))
            .and_then(|v| v.as_str()),
        Some("claude")
    );
    assert!(member.get(serde_yaml::Value::from("target")).is_none());
    assert!(member
        .get(serde_yaml::Value::from("cost_per_mtok"))
        .is_none());
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
    // 1.5.3 named hooks: the 1.x registry became the top-level `hooks:` DEFINITION map (module:
    // derived from the socket/webhook transport); the pool keeps its BARE reference; the
    // `global: true` tap moved to the reserved `pools.hooks:` all-pools attach.
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
    // otlp_endpoint -> otlp_url -> the `module: otlp` export instance (1.5.3 deletes the
    // `observability:` block; `export:` is the single telemetry-egress surface).
    assert_eq!(get(&["export", "traces", "module"]).as_str(), Some("otlp"));
    assert_eq!(
        get(&["export", "traces", "settings", "url"]).as_str(),
        Some("http://otel:4318/v1/traces")
    );

    // The LOUD [] warning fired for the platform role's semantic flip, exactly once.
    assert_eq!(
        out.warnings
            .iter()
            .filter(|w| w.contains("allowed_pools: []") && w.contains("platform"))
            .count(),
        1,
        "warnings: {:?}",
        out.warnings
    );
    // The output document itself carries the warning as a comment.
    assert!(out.yaml.contains("# WARNING(migrate):"));

    // ROUND-TRIP: the migrated document deserializes into the 1.5.0 DeployCfg (boot-parses) and
    // trips NO legacy marker.
    assert!(detect_legacy_markers(&doc).is_empty());
    let deploy: Result<crate::config::DeployCfg, _> = serde_yaml::from_str(&out.yaml);
    assert!(
        deploy.is_ok(),
        "migrated config must boot-parse: {:?}",
        deploy.err().map(|e| e.to_string())
    );
}

/// Small helper: migrate `raw` and return the parsed output document (panics if migrate fails).
fn migrate_to_value(raw: &str) -> (MigrateOutput, serde_yaml::Value) {
    let out = migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("output is valid YAML");
    (out, doc)
}

/// Path-getter over a parsed migrated document.
fn dig<'a>(doc: &'a serde_yaml::Value, path: &[&str]) -> Option<&'a serde_yaml::Value> {
    let mut cur = doc;
    for k in path {
        cur = cur.as_mapping()?.get(serde_yaml::Value::from(*k))?;
    }
    Some(cur)
}

/// THE user-reported seed bug (and every 1.4.x `on_exhausted` spelling): a pool's
/// `on_exhausted: { action: … }` is rewritten to the 1.5.0 shape (bare `reject` / `least_bad`, or
/// `{ fallback_pool: <pool> }`). Before the fix the `action:` wrapper passed straight through and
/// `deny_unknown_fields` rejected it at `--validate` with "unknown field `action`" - a migrate that
/// reported changes but emitted an unbootable config. The migrated document must BOOT-PARSE.
#[test]
fn migrate_on_exhausted_all_arms_round_trip() {
    let raw = r#"
providers: {}
models: {}
pools:
  primary:
    members: [ { target: a } ]
    on_exhausted: { action: "fallback_pool:overflow" }   # the exact user case
  overflow:
    members: [ { target: b } ]
    on_exhausted: { action: least_bad }
  strict:
    members: [ { target: c } ]
    on_exhausted: { action: reject }
  legacy503:
    members: [ { target: d } ]
    on_exhausted: { action: status_503 }
  nameless:
    members: [ { target: e } ]
    on_exhausted: { action: "fallback_pool:" }            # no pool named -> TODO, safe reject
  bogus:
    members: [ { target: f } ]
    on_exhausted: { action: explode }                     # unknown -> TODO, safe reject
"#;
    let (out, doc) = migrate_to_value(raw);

    // fallback_pool:<name> -> { fallback_pool: <name> }.
    assert_eq!(
        dig(&doc, &["pools", "primary", "on_exhausted", "fallback_pool"]).and_then(|v| v.as_str()),
        Some("overflow"),
        "fallback_pool:<name> must become the structured 1.5.0 form"
    );
    // bare keywords stay bare.
    assert_eq!(
        dig(&doc, &["pools", "overflow", "on_exhausted"]).and_then(|v| v.as_str()),
        Some("least_bad")
    );
    assert_eq!(
        dig(&doc, &["pools", "strict", "on_exhausted"]).and_then(|v| v.as_str()),
        Some("reject")
    );
    // status_503 (a 1.4.x alias) -> bare `reject`.
    assert_eq!(
        dig(&doc, &["pools", "legacy503", "on_exhausted"]).and_then(|v| v.as_str()),
        Some("reject")
    );
    // the `action:` wrapper is GONE everywhere.
    for pool in [
        "primary",
        "overflow",
        "strict",
        "legacy503",
        "nameless",
        "bogus",
    ] {
        assert!(
            dig(&doc, &["pools", pool, "on_exhausted", "action"]).is_none(),
            "pool {pool} still carries the 1.4.x on_exhausted.action wrapper"
        );
    }
    // the two undecidable arms are FLAGGED, never silently wrong.
    assert!(
        out.todos.iter().any(|t| t.contains("nameless")),
        "an empty fallback_pool must raise a TODO: {:?}",
        out.todos
    );
    assert!(
        out.todos.iter().any(|t| t.contains("bogus")),
        "an unknown action must raise a TODO: {:?}",
        out.todos
    );
    // THE round-trip: the migrated config boot-parses (the user's failure is gone).
    assert!(
        serde_yaml::from_str::<crate::config::DeployCfg>(&out.yaml).is_ok(),
        "on_exhausted-bearing config must boot-parse: {:?}",
        serde_yaml::from_str::<crate::config::DeployCfg>(&out.yaml).err()
    );
}

/// The REAL shipped 1.4.x (`v1.4.1`) `DeployCfg` put `group_map:` / `admin_auth:` at the TOP LEVEL
/// (not under `auth:`), used `auth.chain: [tokens]` with `auth.client_tokens`, and could carry
/// per-module `auth.modules:` caps. Before the fix the migrator only knew the NESTED `auth.group_map`
/// shape, so a real config passed group_map / admin_auth / modules / `tokens` straight through to a
/// `deny_unknown_fields` rejection. Everything must now migrate into the 1.5.0 auth shape and
/// boot-parse.
#[test]
fn migrate_real_14x_top_level_auth_surfaces() {
    let raw = r#"
auth:
  chain: [tokens, oidc]
  upstream_credentials: own
  client_tokens: [ "${BUSBAR_CLIENT_TOKEN}" ]
  modules:
    oidc:
      allowed_groups: [growth]
      max_admin_scope: full
admin_auth: [admin-tokens]
group_map:
  growth-eng:
    allowed_pools: [fast]
    rpm_limit: 120
providers: {}
models: {}
pools: {}
"#;
    let (out, doc) = migrate_to_value(raw);

    // chain: tokens -> keys (deduped), oidc carries its folded max_admin_scope.
    let chain = dig(&doc, &["auth", "chain"])
        .unwrap()
        .as_sequence()
        .unwrap();
    assert_eq!(chain[0].as_str(), Some("keys"), "tokens -> keys");
    assert_eq!(
        chain[1].as_str(),
        Some("oidc"),
        "a 1.5.3 chain is a list of bare PROVIDER NAMES"
    );
    assert_eq!(
        dig(&doc, &["identity-providers", "oidc", "max_admin_scope"]).and_then(|v| v.as_str()),
        Some("full"),
        "auth.modules.oidc.max_admin_scope must fold onto the identity-providers DEFINITION"
    );
    // top-level group_map -> auth.role_bindings nested under the ONE external module (oidc).
    assert_eq!(
        dig(
            &doc,
            &[
                "auth",
                "role_bindings",
                "oidc",
                "growth-eng",
                "allowed_pools"
            ]
        )
        .and_then(|v| v.as_sequence())
        .map(|s| s.len()),
        Some(1),
        "top-level group_map must migrate to auth.role_bindings.<module>"
    );
    // top-level admin_auth -> auth.admin_auth (nested).
    assert!(
        dig(&doc, &["auth", "admin_auth"])
            .and_then(|v| v.as_sequence())
            .is_some(),
        "top-level admin_auth must move under auth"
    );
    // nothing auth-shaped survives at the ROOT (all would be deny_unknown_fields rejections).
    for k in ["group_map", "admin_auth", "modules"] {
        assert!(
            doc.as_mapping()
                .unwrap()
                .get(serde_yaml::Value::from(k))
                .is_none(),
            "top-level `{k}` must be gone after migration"
        );
    }
    // allowed_groups has no 1.5.0 home -> an explicit TODO, never a silent drop.
    assert!(
        out.todos.iter().any(|t| t.contains("allowed_groups")),
        "dropping auth.modules.*.allowed_groups must raise a TODO: {:?}",
        out.todos
    );
    // boot-parses.
    assert!(
        serde_yaml::from_str::<crate::config::DeployCfg>(&out.yaml).is_ok(),
        "real top-level 1.4.x auth surfaces must migrate to a bootable config: {:?}",
        serde_yaml::from_str::<crate::config::DeployCfg>(&out.yaml).err()
    );
}

/// The 1.4.x TOP-LEVEL `global_hooks: [<name>]` (a list of REGISTRY names) → the reserved
/// `pools.hooks:` all-pools attach (1.5.3). A registry name becomes a NAMED DEFINITION under
/// `hooks:` and a BARE reference in `pools.hooks:`; a hook that is BOTH named in global_hooks AND
/// flagged `global: true` must appear exactly ONCE in the all-pools list (no duplicate).
#[test]
fn migrate_global_hooks_names_resolve_and_dedup() {
    let raw = r#"
providers: {}
models: {}
pools: {}
hooks:
  audit-tap:
    kind: tap
    webhook: "https://sidecar.internal/audit"
    global: true
global_hooks: [audit-tap]
"#;
    let (out, doc) = migrate_to_value(raw);
    // No top-level global_hooks survives.
    assert!(
        dig(&doc, &["global_hooks"]).is_none(),
        "the removed top-level global_hooks: must not survive"
    );
    let all = dig(&doc, &["pools", "hooks"]).unwrap();
    let all = all.as_sequence().unwrap();
    assert_eq!(
        all.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>(),
        ["audit-tap"],
        "the doubly-named global hook is a single BARE all-pools reference: {all:?}"
    );
    // The name resolves to a named DEFINITION whose module: came from the webhook transport.
    assert_eq!(
        dig(&doc, &["hooks", "audit-tap", "module"]).and_then(|v| v.as_str()),
        Some("webhook"),
        "the registry name became a named hook definition"
    );
    assert!(
        serde_yaml::from_str::<crate::config::DeployCfg>(&out.yaml).is_ok(),
        "global_hooks must migrate to a bootable config: {:?}",
        serde_yaml::from_str::<crate::config::DeployCfg>(&out.yaml).err()
    );
}

/// The detector must NAME every real 1.4.x marker so boot/`--validate` refuse the old format loudly
/// (P9): the top-level group_map / admin_auth, per-module `auth.modules`, an `auth.chain: [tokens]`,
/// and a pool `on_exhausted.action`.
#[test]
fn detect_real_14x_top_level_and_on_exhausted_markers() {
    let raw = r#"
auth:
  chain: [tokens]
  modules: { oidc: { max_admin_scope: full } }
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

/// `price_per_1k_tokens_cents` synthesizes a flagged rate_card entry per model (N cents/1k =
/// 10N micro-units/token on every tier).
#[test]
fn migrate_price_per_1k_synthesizes_rate_card() {
    let raw = r#"
governance:
  price_per_1k_tokens_cents: 5
providers: {}
models:
  m1: { provider: p }
  m2: { provider: p }
pools: {}
"#;
    let out = migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).unwrap();
    let card = doc
        .as_mapping()
        .unwrap()
        .get(serde_yaml::Value::from("rate_card"))
        .and_then(|v| v.as_mapping())
        .expect("rate_card synthesized");
    for m in ["m1", "m2"] {
        let entry = card
            .get(serde_yaml::Value::from(m))
            .and_then(|v| v.as_mapping())
            .unwrap();
        assert_eq!(
            entry
                .get(serde_yaml::Value::from("input_utok"))
                .and_then(|v| v.as_f64()),
            Some(50.0),
            "5 cents/1k = 50 micro-units/token"
        );
    }
    assert!(
        out.todos.iter().any(|t| t.contains("rate_card")),
        "the uniform synthesis is flagged for review"
    );
}

/// REGRESSION: a pool `policy:` migrates to `hooks: [<strategy>, ...]` even when the config has
/// NO top-level `hooks:` registry block (the block-processing pass returns early in that case).
#[test]
fn migrate_pool_policy_without_hooks_block() {
    let raw = r#"
providers: {}
models: {}
pools:
  fast:
    members: [ { target: claude, weight: 1 } ]
    policy: cheapest
"#;
    let out = migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).unwrap();
    let hooks = doc
        .as_mapping()
        .and_then(|m| m.get(serde_yaml::Value::from("pools")))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("fast")))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("hooks")))
        .and_then(|v| v.as_sequence())
        .expect("policy became a hooks list");
    assert_eq!(hooks[0].as_str(), Some("cheapest"));
    // The migrated document boot-parses (no leftover `policy:` unknown-field).
    assert!(
        serde_yaml::from_str::<crate::config::DeployCfg>(&out.yaml).is_ok(),
        "policy-only pool must migrate to a bootable config"
    );
}

/// `auth.mode` mapping: passthrough -> upstream_credentials; token -> keys chain + a re-mint TODO.
#[test]
fn migrate_auth_mode_arms() {
    let out = migrate_config("auth:\n  mode: passthrough\nproviders: {}\nmodels: {}\npools: {}\n")
        .unwrap();
    assert!(out.yaml.contains("upstream_credentials: passthrough"));

    let out =
        migrate_config("auth:\n  mode: token\nproviders: {}\nmodels: {}\npools: {}\n").unwrap();
    assert!(out.yaml.contains("- keys"));
    assert!(
        out.todos.iter().any(|t| t.contains("signed key")),
        "static-token removal must surface the key re-mint TODO: {:?}",
        out.todos
    );
}

/// A group_map with an AMBIGUOUS module home (no external chain module) gets the placeholder +
/// TODO, never a silent guess.
#[test]
fn migrate_group_map_without_module_flags_placeholder() {
    let raw = r#"
auth:
  group_map:
    r1: { allowed_pools: [fast] }
providers: {}
models: {}
pools: {}
"#;
    let out = migrate_config(raw).unwrap();
    assert!(out.yaml.contains("<module>"));
    assert!(out
        .todos
        .iter()
        .any(|t| t.contains("replace the '<module>' placeholder")));
}

/// REGRESSION: a top-level `group_map:` alongside a NON-MAPPING `auth:` (e.g. `auth: null`) must
/// NOT silently vanish. Before the fix, `migrate_auth` took `group_map` off `root` up front, then
/// hit `let Value::Mapping(auth) = ... else { return; }` when `auth:` was present but not a
/// mapping - the early `return` dropped the already-extracted `group_map` with no warning/TODO,
/// violating this module's own "never silently drop, pass through or TODO" contract.
#[test]
fn migrate_group_map_survives_a_non_mapping_auth() {
    let raw = r#"
auth: null
group_map:
  growth-eng:
    allowed_pools: [fast]
providers: {}
models: {}
pools: {}
"#;
    let out = migrate_config(raw).unwrap();
    // The data must survive SOMEWHERE in the migrated document - either restored at the top level,
    // or (if a future fix manages to migrate it) folded into auth.role_bindings. Either way it must
    // not disappear, and there must be a loud TODO/warning naming the problem.
    assert!(
        out.yaml.contains("group_map") || out.yaml.contains("role_bindings"),
        "group_map data must not silently vanish from the migrated document:\n{}",
        out.yaml
    );
    assert!(
        out.todos.iter().any(|t| t.contains("group_map"))
            || out.warnings.iter().any(|w| w.contains("group_map")),
        "a non-mapping `auth:` losing group_map must surface a loud TODO/warning, got \
         todos={:?} warnings={:?}",
        out.todos,
        out.warnings
    );
}

/// REGRESSION (the mirror image of `migrate_group_map_survives_a_non_mapping_auth`): `group_map:`
/// ITSELF being a non-mapping (`group_map: [foo]`) while `auth:` IS a mapping must NOT silently
/// vanish either. Before the fix, `migrate_auth`'s `if let Value::Mapping(gm) = gm { .. }` treated
/// anything else as a silent no-op: `bindings` stayed empty but execution fell straight through to
/// unconditionally emit an EMPTY `auth.role_bindings.<module>: {}` plus a MISLEADING "auth.group_map
/// -> auth.role_bindings" changelog entry, as if the data had actually migrated - the group_map
/// content itself was gone with no warning/TODO at all.
#[test]
fn migrate_non_mapping_group_map_survives_a_mapping_auth() {
    let raw = r#"
auth:
  chain: [oidc]
group_map: [foo]
providers: {}
models: {}
pools: {}
"#;
    let out = migrate_config(raw).unwrap();
    assert!(
        out.yaml.contains("group_map"),
        "a non-mapping group_map must not silently vanish from the migrated document:\n{}",
        out.yaml
    );
    assert!(
        out.todos.iter().any(|t| t.contains("group_map"))
            || out.warnings.iter().any(|w| w.contains("group_map")),
        "a non-mapping `group_map:` disappearing must surface a loud TODO/warning, got \
         todos={:?} warnings={:?}",
        out.todos,
        out.warnings
    );
    // The misleading "migrated" changelog entry must not appear when nothing actually migrated.
    assert!(
        !out.changes
            .iter()
            .any(|c| c.contains("group_map -> auth.role_bindings")),
        "must not claim a group_map -> role_bindings migration happened when it did not: {:?}",
        out.changes
    );
}

/// REGRESSION: a REALISTIC 1.4.x `governance:` block -- no `store:` key, because 1.4.x's
/// `GovernanceCfg` never had one (its only durable backend was SQLite at `db_path`). Before the
/// fix, gating the store migration on that nonexistent key silently dropped `db_path` and emitted
/// NO `store:` section at all, which defaults to the ephemeral in-memory store on boot -- orphaning
/// every real key/budget/audit row in the operator's actual database. The migrated document must
/// carry the real `db_path` forward as `store: { module: sqlite, settings: { db_path } }`.
#[test]
fn migrate_realistic_14x_governance_preserves_the_real_sqlite_db_path() {
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
        Some("sqlite"),
        "1.4.x's only durable backend was SQLite -- migration must select it, not default to memory"
    );
    assert_eq!(
        get(&["store", "settings", "db_path"]).as_str(),
        Some("/var/lib/busbar/governance.db"),
        "the operator's REAL existing database path must survive migration, not get silently dropped"
    );
}

/// REGRESSION, the omitted-`db_path` case: a 1.4.x config that never set `db_path` explicitly relied
/// on 1.4.x's real default (`busbar-governance.db`). Migration must reproduce THAT default, not
/// silently select the 1.5.0-side in-memory default, or the operator's real (implicitly-named)
/// database becomes unreachable after migration too.
#[test]
fn migrate_14x_governance_with_no_explicit_db_path_uses_the_14x_default() {
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
        Some("sqlite")
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

/// 1.5.2 SCOPE COLLAPSE migration: a config still naming the retired delegated `mint` /
/// `hooks-register` admin scopes — in a `group_map` `admin_scope` (→ `role_bindings`) and in an
/// `auth.modules` `max_admin_scope` (→ the chain entry) — is rewritten to `full`, with a loud
/// per-site WARNING so the operator can tighten it back to `read-only`.
#[test]
fn migrate_dropped_scopes_map_to_full_with_warning() {
    let raw = r#"
auth:
  chain: ["oidc"]
  modules:
    oidc:
      max_admin_scope: hooks-register
  group_map:
    minter:
      admin_scope: mint
providers:
  anthropic: { api_key_env: KEY }
models:
  claude: { provider: anthropic }
pools:
  fast:
    members:
      - { target: claude, weight: 1 }
"#;
    let out = migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("output is valid YAML");
    let auth = doc
        .as_mapping()
        .unwrap()
        .get(serde_yaml::Value::from("auth"))
        .and_then(|v| v.as_mapping())
        .expect("auth mapping");

    // (a) role_bindings.oidc.minter.admin_scope: mint -> full.
    let bound_scope = auth
        .get(serde_yaml::Value::from("role_bindings"))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("oidc")))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("minter")))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("admin_scope")))
        .and_then(|v| v.as_str());
    assert_eq!(
        bound_scope,
        Some("full"),
        "the retired `mint` admin_scope must be rewritten to `full`; got {bound_scope:?}"
    );

    // (b) the oidc provider's max_admin_scope: hooks-register -> full. 1.5.3: the cap lives on the
    // `identity-providers:` DEFINITION (audit §2), which the chain now references by bare name — so
    // the scope rewrite and the definition lift compose in ONE migrator run.
    let oidc_cap =
        dig(&doc, &["identity-providers", "oidc", "max_admin_scope"]).and_then(|v| v.as_str());
    assert_eq!(
        oidc_cap,
        Some("full"),
        "the retired `hooks-register` max_admin_scope must be rewritten to `full`; got {oidc_cap:?}"
    );
    let chain = auth
        .get(serde_yaml::Value::from("chain"))
        .and_then(|v| v.as_sequence())
        .expect("chain sequence");
    assert!(
        chain.iter().any(|e| e.as_str() == Some("oidc")),
        "the chain references the provider by BARE NAME: {chain:?}"
    );

    // Loud, per-site warnings naming both rewrites.
    assert!(
        out.warnings.iter().any(|w| w.contains("mint -> full")),
        "a warning must name the mint -> full rewrite; got {:?}",
        out.warnings
    );
    assert!(
        out.warnings
            .iter()
            .any(|w| w.contains("hooks-register -> full")),
        "a warning must name the hooks-register -> full rewrite; got {:?}",
        out.warnings
    );
}

/// task #139: `observability.emit_server_timing` -> `advanced.response_headers.server_timing`. The
/// key is REMOVED from `observability` (else `deny_unknown_fields` rejects the migrated document —
/// see `test_migrated_configs_boot_parse`-style coverage) and reappears nested under the new
/// `advanced.response_headers` block, alongside any advanced fields that were already present.
#[test]
fn migrate_emit_server_timing_moves_to_advanced_response_headers() {
    let raw = r#"
providers: {}
models: {}
advanced:
  rate_sweep_interval: 64
observability:
  emit_server_timing: true
  otlp_endpoint: "http://otel:4318/v1/traces"
"#;
    let (out, doc) = migrate_to_value(raw);

    // The old key is GONE (a raw pass-through would `deny_unknown_fields`-reject at boot instead of
    // silently keeping stale semantics). 1.5.3 deletes the whole enclosing block, so assert that.
    assert!(
        dig(&doc, &["observability"]).is_none(),
        "the whole observability block must not survive migration: {doc:?}"
    );
    // The new key carries the SAME value, in its new home.
    assert_eq!(
        dig(&doc, &["advanced", "response_headers", "server_timing"]).and_then(|v| v.as_bool()),
        Some(true)
    );
    // A pre-existing sibling `advanced:` field (rate_sweep_interval) is preserved, not clobbered by
    // the cross-section splice.
    assert_eq!(
        dig(&doc, &["advanced", "rate_sweep_interval"]).and_then(|v| v.as_u64()),
        Some(64)
    );
    // The sibling otlp_endpoint rename still fires in the same run and then FOLDS into the `otlp`
    // export instance (the migrations chain rather than colliding).
    assert_eq!(
        dig(&doc, &["export", "traces", "settings", "url"]).and_then(|v| v.as_str()),
        Some("http://otel:4318/v1/traces")
    );
    assert!(
        out.changes
            .iter()
            .any(|c| c.contains("emit_server_timing -> advanced.response_headers.server_timing")),
        "a change entry must name the rename; got {:?}",
        out.changes
    );

    // The migrated document must boot-parse cleanly (deny_unknown_fields would catch a stray key).
    let deploy: Result<crate::config::DeployCfg, _> = serde_yaml::from_str(&out.yaml);
    assert!(
        deploy.is_ok(),
        "migrated config must boot-parse: {:?}",
        deploy.err().map(|e| e.to_string())
    );
}

/// 1.5.3 HARD tap-stage rename: an old inline hook instance carrying `at:` (`route`/`attempt`/
/// `completion`) lifts to a NAMED DEFINITION whose `phase:` list uses the new vocabulary
/// (`candidate`/`routing`/`response`). The pool keeps BARE references; the result must BOOT-PARSE
/// (the old `at:` strings would otherwise fail as unknown `HookStage` variants).
#[test]
fn migrate_hook_stage_at_values_are_renamed() {
    let raw = r#"
providers: {}
models: {}
pools:
  primary:
    members: [ { model: a } ]
    hooks:
      - { module: webhook, settings: { url: "https://s/route" }, kind: tap, at: route }
      - { module: webhook, settings: { url: "https://s/attempt" }, kind: tap, at: attempt }
global_hooks:
  - { module: webhook, settings: { url: "https://s/done" }, kind: tap, at: completion }
"#;
    let (out, doc) = migrate_to_value(raw);

    // Every hook is now a named DEFINITION; the `at:` renamed onto its `phase:` list. Locate each by
    // its distinguishing settings.url (auto-generated names are not asserted directly).
    let defs = dig(&doc, &["hooks"]).unwrap();
    let defs = defs.as_mapping().unwrap();
    let phase_for = |url_suffix: &str| -> Option<String> {
        defs.iter().find_map(|(_, d)| {
            let d = d.as_mapping()?;
            let url = d
                .get(serde_yaml::Value::from("settings"))?
                .as_mapping()?
                .get(serde_yaml::Value::from("url"))?
                .as_str()?;
            if !url.ends_with(url_suffix) {
                return None;
            }
            let phase = d.get(serde_yaml::Value::from("phase"))?.as_sequence()?;
            phase.first()?.as_str().map(str::to_string)
        })
    };
    assert_eq!(
        phase_for("/route").as_deref(),
        Some("candidate"),
        "`at: route` must migrate to `phase: [candidate]`"
    );
    assert_eq!(
        phase_for("/attempt").as_deref(),
        Some("routing"),
        "`at: attempt` must migrate to `phase: [routing]`"
    );
    assert_eq!(
        phase_for("/done").as_deref(),
        Some("response"),
        "`at: completion` must migrate to `phase: [response]`"
    );

    // The pool keeps BARE references, and the global instance became a reserved all-pools attach.
    let pool_hooks = dig(&doc, &["pools", "primary", "hooks"])
        .unwrap()
        .as_sequence()
        .unwrap();
    assert!(
        pool_hooks.iter().all(|v| v.as_str().is_some()),
        "pool hooks are bare names now: {pool_hooks:?}"
    );
    assert!(
        dig(&doc, &["pools", "hooks"])
            .and_then(|v| v.as_sequence().cloned())
            .is_some_and(|s| !s.is_empty()),
        "the global instance became a reserved pools.hooks attach"
    );

    // Boot-parse proves the rename closed the loud-fail (old `at:` strings would 400 as variants).
    let deploy: Result<crate::config::DeployCfg, _> = serde_yaml::from_str(&out.yaml);
    assert!(
        deploy.is_ok(),
        "migrated config must boot-parse: {:?}",
        deploy.err().map(|e| e.to_string())
    );
}

/// A config that never set `emit_server_timing` (or had no `observability:` block at all) migrates
/// with NO `advanced.response_headers` block synthesized — the migrator must not manufacture config
/// the operator never wrote.
#[test]
fn migrate_emit_server_timing_absent_is_a_no_op() {
    let raw = "providers: {}\nmodels: {}\n";
    let (out, doc) = migrate_to_value(raw);
    assert!(
        dig(&doc, &["advanced"]).is_none(),
        "no advanced: block should be synthesized: {doc:?}"
    );
    assert!(
        !out.changes.iter().any(|c| c.contains("response_headers")),
        "no change entry expected when the old key was absent; got {:?}",
        out.changes
    );
}

/// 1.5.3 observability→export lift-out: an un-migrated config carrying `observability.request_log_webhook_url`
/// or a top-level `metrics:` block LOUD-FAILS at boot/`--validate` — `detect_legacy_markers` names
/// each retired key with the migrate breadcrumb.
///
/// RED-BEFORE-GREEN: before this unit these keys parsed silently (they were live `ObservabilityCfg` /
/// `MetricsCfg` fields), so `detect_legacy_markers` returned NO marker for them — this assertion fails
/// on the pre-retirement tree.
#[test]
fn detect_retired_observability_export_keys_loud_fail() {
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
    // Each marker names its new home under the export exporters so the operator knows where it went.
    assert!(
        joined.contains("export.request-log-webhook") && joined.contains("export.prometheus"),
        "markers must name the new export home; got: {joined}"
    );
}

/// `--migrate-config` mechanically REWRITES the retired observability keys into the new `export:`
/// surface (built-in exporters, so a full rewrite — not a printed TODO). The webhook URL + limits land
/// under `export.request-log-webhook.settings`, the metrics block under `export.prometheus.settings`,
/// and the old keys are gone from `observability:` / the top level. Idempotent.
///
/// RED-BEFORE-GREEN: `migrate_observability_export` did not exist before this unit, so the migrated
/// document had no `export:` block — these `dig` lookups return `None` on the pre-migration tree.
#[test]
fn migrate_observability_export_rewrites_old_to_new() {
    let raw = r#"
observability:
  otlp_url: "https://otel.example.com/v1/traces"
  request_log_webhook_url: "https://logs.example.com/busbar"
  max_inflight_webhook_deliveries: 32
  webhook_delivery_timeout_secs: 5
metrics:
  buffer_seconds: 90
  key_gauge_limit: 1500
providers: {}
models: {}
pools: {}
"#;
    let (out, doc) = migrate_to_value(raw);

    // request-log-webhook exporter — 1.5.3: a NAMED instance (`req-log`) whose `module:` says which
    // built-in backs it, not a type key.
    assert_eq!(
        dig(&doc, &["export", "req-log", "module"]).and_then(|v| v.as_str()),
        Some("request-log-webhook"),
    );
    assert_eq!(
        dig(&doc, &["export", "req-log", "settings", "url"]).and_then(|v| v.as_str()),
        Some("https://logs.example.com/busbar"),
    );
    assert_eq!(
        dig(
            &doc,
            &["export", "req-log", "settings", "max_inflight_deliveries"]
        )
        .and_then(|v| v.as_u64()),
        Some(32),
    );
    assert_eq!(
        dig(
            &doc,
            &["export", "req-log", "settings", "delivery_timeout_secs"]
        )
        .and_then(|v| v.as_u64()),
        Some(5),
    );
    // prometheus exporter — likewise a NAMED instance (`metrics`).
    assert_eq!(
        dig(&doc, &["export", "metrics", "module"]).and_then(|v| v.as_str()),
        Some("prometheus"),
    );
    assert_eq!(
        dig(&doc, &["export", "metrics", "settings", "buffer_seconds"]).and_then(|v| v.as_u64()),
        Some(90),
    );
    assert_eq!(
        dig(&doc, &["export", "metrics", "settings", "key_gauge_limit"]).and_then(|v| v.as_u64()),
        Some(1500),
    );
    // 1.5.3 §3: `otlp_url` folds into an `otlp` export instance and the `observability:` BLOCK IS
    // DELETED outright — `export:` is the single telemetry-egress surface.
    assert_eq!(
        dig(&doc, &["export", "traces", "module"]).and_then(|v| v.as_str()),
        Some("otlp"),
    );
    assert_eq!(
        dig(&doc, &["export", "traces", "settings", "url"]).and_then(|v| v.as_str()),
        Some("https://otel.example.com/v1/traces"),
    );
    assert!(
        dig(&doc, &["observability"]).is_none(),
        "the whole observability block must be gone after migration"
    );
    assert!(
        dig(&doc, &["metrics"]).is_none(),
        "the retired top-level metrics block must be removed"
    );
    assert!(
        out.changes
            .iter()
            .any(|c| c.contains("request-log-webhook"))
            && out.changes.iter().any(|c| c.contains("prometheus"))
            && out.changes.iter().any(|c| c.contains("otlp")),
        "the change ledger names all three rewrites; got {:?}",
        out.changes
    );

    // The migrated document BOOT-PARSES as a 1.5.3 config, and resolves to the typed export block —
    // a golden that would catch a rewrite that produces a shape the parser rejects.
    let migrated_yaml = serde_yaml::to_string(&doc).unwrap();
    let deploy: crate::config::DeployCfg =
        serde_yaml::from_str(&migrated_yaml).expect("the migrated config must boot-parse");
    let mut errs = Vec::new();
    let export = crate::config::resolve_export(&deploy.export, &mut errs);
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(export.request_log_webhooks.len(), 1);
    assert!(export.prometheus.is_some() && export.otlp.is_some());

    // IDEMPOTENT: re-migrating the already-new document moves nothing more, and the TREE is stable.
    let (out2, doc2) = migrate_to_value(&migrated_yaml);
    assert!(
        !out2
            .changes
            .iter()
            .any(|c| c.contains("request-log-webhook")
                || c.contains("prometheus")
                || c.contains("otlp")),
        "a second migrate is a no-op for the export rewrite; got {:?}",
        out2.changes
    );
    assert_eq!(doc, doc2, "the migration is a fixed point after one run");
}

/// GOLDEN (a): a 1.5.0/1.5.2 config with an INLINE `global_hooks:` instance AND an inline pool-hook
/// instance converges to the 1.5.3 shape — a top-level `hooks:` DEFINITION map, the reserved
/// `pools.hooks:` all-pools attach, and BARE per-pool references — boot-parses, and re-running the
/// migrator over the output is a NO-OP on the config tree (idempotent / golden-stable).
#[test]
fn migrate_1_5_x_inline_hooks_converge_and_are_idempotent() {
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
    // Boot-parses into the 1.5.3 DeployCfg and trips no legacy marker.
    let doc: serde_yaml::Value = serde_yaml::from_str(&out1.yaml).expect("valid YAML");
    assert!(
        detect_legacy_markers(&doc).is_empty(),
        "no residual 1.x marker"
    );
    let deploy: crate::config::DeployCfg =
        serde_yaml::from_str(&out1.yaml).expect("migrated config boot-parses");

    // The named-definition map holds both lifted hooks; the pool keeps its strategy + a BARE ref; the
    // global instance became the reserved all-pools attach.
    assert!(
        !deploy.hooks.is_empty(),
        "named hooks: definition map present"
    );
    let fast = &deploy.pools.pools["fast"];
    assert_eq!(fast.policy, crate::config::PoolPolicy::Cheapest);
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
    // The lifted def's `at: completion` renamed onto `phase: [response]`.
    let audit = &deploy.hooks[&deploy.pools.all_pool_hooks[0]];
    assert_eq!(audit.phase, vec![crate::config::HookStage::Response]);

    // IDEMPOTENT: re-migrating the output leaves the config tree byte-for-byte identical (the header
    // comment block carries run-specific todos, so compare the parsed VALUE, not the raw text).
    let out2 = migrate_config(&out1.yaml).expect("re-migrates");
    let v1: serde_yaml::Value = serde_yaml::from_str(&out1.yaml).unwrap();
    let v2: serde_yaml::Value = serde_yaml::from_str(&out2.yaml).unwrap();
    assert_eq!(
        v1, v2,
        "the migration must be idempotent on the config tree"
    );
}

// ── 1.5.3 GRAMMAR-LOCK migration GOLDENS (audit §2/§3/§4/§5) ─────────────────────────────────────
//
// One golden per retired key. Each asserts the same four things, because those four together are
// what "a migration path" means for a break-once release:
//   1. the retired key LOUD-FAILS the boot detector with the `--migrate-config` breadcrumb (an
//      operator can never silently boot a config whose semantics moved);
//   2. `--migrate-config` mechanically rewrites it into the 1.5.3 home (nothing is merely a TODO —
//      every one of these is deterministic, so leaving it to a human would be a lost setting);
//   3. the migrated document BOOT-PARSES and resolves (a rewrite that produces an unparseable shape
//      is worse than no rewrite);
//   4. re-running the migrator is a FIXED POINT — the tree is byte-identical (shape-convergent).

/// Assert the boot detector names `needle` and points at the migrator, for a config the operator
/// might really still have. Shared by the goldens below so each one states only what is specific.
fn assert_loud_fail_with_breadcrumb(raw: &str, needle: &str) {
    let doc: serde_yaml::Value = serde_yaml::from_str(raw).expect("valid YAML");
    let markers = detect_legacy_markers(&doc);
    assert!(
        markers.iter().any(|m| m.contains(needle)),
        "the retired key '{needle}' must trip the boot detector; got {markers:?}"
    );
    let err = crate::config::migrate::legacy_config_error(&markers);
    assert!(
        err.contains("busbar --migrate-config"),
        "the refusal must point at the migrator: {err}"
    );
}

/// Migrate `raw`, assert the result BOOT-PARSES, and assert a second run is a fixed point.
/// Returns the migrated document for the golden's own shape assertions.
fn migrate_golden(raw: &str) -> (crate::config::migrate::MigrateOutput, serde_yaml::Value) {
    let (out, doc) = migrate_to_value(raw);
    let yaml = serde_yaml::to_string(&doc).expect("serializable");
    let _: crate::config::DeployCfg =
        serde_yaml::from_str(&yaml).expect("the migrated config must boot-parse as 1.5.3");
    let (_out2, doc2) = migrate_to_value(&yaml);
    assert_eq!(
        doc, doc2,
        "the migration must be a FIXED POINT: re-running it changes nothing"
    );
    (out, doc)
}

/// GOLDEN §5 — `admin_insecure: true` -> `admin_require_mtls: false` (the flag INVERTED so the safe
/// posture is the default).
///
/// RED-BEFORE-GREEN: `admin_require_mtls` did not exist before this unit, and `admin_insecure` was a
/// live field that parsed clean — so neither the loud-fail nor the rewrite existed.
#[test]
fn golden_migrate_admin_insecure_inverts_to_admin_require_mtls() {
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

    // The other polarity: an explicit `false` (guard ON) becomes `true` (guard ON) — the BEHAVIOR is
    // preserved across the inversion, which is the only thing an operator cares about.
    let (_, doc) = migrate_golden("admin_insecure: false\nproviders: {}\nmodels: {}\npools: {}\n");
    assert_eq!(
        dig(&doc, &["admin_require_mtls"]).and_then(|v| v.as_bool()),
        Some(true)
    );
}

/// GOLDEN §4 — `auth.upstream_credentials:` -> the reserved `pools.upstream_credentials:` all-pools
/// default (whose credential reaches the upstream is a ROUTING property, not an inbound-auth one).
///
/// RED-BEFORE-GREEN: `pools.upstream_credentials` did not exist before this unit and
/// `auth.upstream_credentials` was a live field, so there was nothing to detect and nowhere to move.
#[test]
fn golden_migrate_auth_upstream_credentials_moves_to_pools() {
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

/// GOLDEN §3 — the `observability:` BLOCK is DELETED and its last field folds into a `module: otlp`
/// `export:` instance, so `export:` is the single telemetry-egress surface.
///
/// RED-BEFORE-GREEN: there was no `otlp` export module before this unit, so `otlp_url` had nowhere
/// to go and the block could not be deleted without losing the trace sink.
#[test]
fn golden_migrate_observability_block_folds_into_an_otlp_export_instance() {
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

    // The 1.4.x spelling chains through the `otlp_endpoint -> otlp_url` rename in the SAME run.
    let (_, doc) = migrate_golden(
        "observability:\n  otlp_endpoint: \"http://otel:4318/v1/traces\"\n\
         providers: {}\nmodels: {}\npools: {}\n",
    );
    assert_eq!(
        dig(&doc, &["export", "traces", "settings", "url"]).and_then(|v| v.as_str()),
        Some("http://otel:4318/v1/traces")
    );
}

/// GOLDEN §3 — the TYPE-KEYED `export:` block becomes the NAMED map (`<name>: { module, settings }`),
/// which is what makes two instances of one module expressible at all.
///
/// RED-BEFORE-GREEN: the type-keyed shape was the live grammar before this unit, so there was
/// nothing to detect and no named map to converge on.
#[test]
fn golden_migrate_type_keyed_export_becomes_a_named_map() {
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
    // The retired `generic-webhook` exporter FOLDS into `request-log-webhook`: its only extra was
    // `auth_header:` (now a setting there) and its other reason to exist — a SECOND target — is
    // exactly what the named map provides. So the migrated config has TWO webhook instances.
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

    // And the migrated document really resolves to two independent webhook sinks.
    let deploy: crate::config::DeployCfg =
        serde_yaml::from_str(&serde_yaml::to_string(&doc).unwrap()).expect("boot-parses");
    let mut errs = Vec::new();
    let export = crate::config::resolve_export(&deploy.export, &mut errs);
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(export.request_log_webhooks.len(), 2);
    assert!(export.prometheus.is_some());
}

/// GOLDEN §2 + A7 — inline `auth.chain:`/`auth.admin_auth:` entries and the `auth.methods:` block all
/// lift into ONE `identity-providers:` definition per module, referenced by bare name.
///
/// This is THE point of audit §2, and the assertion that proves it is the DEDUPE: `oidc` appears in
/// BOTH chains and in `methods:` in the source, and there is exactly ONE definition afterwards,
/// carrying the union of what the three sites contributed. Under the retired grammar the operator
/// wrote those settings three times and nothing stopped the copies from drifting.
///
/// RED-BEFORE-GREEN: `identity-providers:` did not exist before this unit, so there was no map to
/// converge onto and the inline form was the live grammar.
#[test]
fn golden_migrate_inline_chain_entries_dedupe_into_identity_providers() {
    let raw = "auth:\n\
               \x20 chain:\n\
               \x20   - keys\n\
               \x20   - oidc: { settings: { issuer: \"https://idp.example/\" } }\n\
               \x20 admin_auth:\n\
               \x20   - admin-tokens: { token: { env: BUSBAR_ADMIN_TOKEN } }\n\
               \x20   - oidc: { max_admin_scope: full }\n\
               \x20 methods:\n\
               \x20   oidc:\n\
               \x20     audience: busbar\n\
               \x20     browser_login: { client_id: busbar-web }\n\
               providers: {}\nmodels: {}\npools: {}\n";
    assert_loud_fail_with_breadcrumb(raw, "INLINE module entries");
    assert_loud_fail_with_breadcrumb(raw, "auth.methods");

    let (out, doc) = migrate_golden(raw);

    // Both chains are now lists of BARE NAMES.
    assert_eq!(
        dig(&doc, &["auth", "chain"])
            .and_then(|v| v.as_sequence().cloned())
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect::<Vec<_>>(),
        ["keys", "oidc"]
    );
    assert_eq!(
        dig(&doc, &["auth", "admin_auth"])
            .and_then(|v| v.as_sequence().cloned())
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect::<Vec<_>>(),
        ["admin-tokens", "oidc"]
    );
    assert!(
        dig(&doc, &["auth", "methods"]).is_none(),
        "the parallel methods map is gone (A7)"
    );

    // THE DEDUPE: exactly ONE `oidc` definition, carrying the union of all three source sites.
    let defs = dig(&doc, &["identity-providers"])
        .and_then(|v| v.as_mapping().cloned())
        .expect("identity-providers map");
    assert_eq!(
        defs.len(),
        2,
        "one definition per MODULE (oidc + admin-tokens), not one per REFERENCE: {defs:?}"
    );
    assert_eq!(
        dig(&doc, &["identity-providers", "oidc", "module"]).and_then(|v| v.as_str()),
        Some("oidc")
    );
    assert_eq!(
        dig(&doc, &["identity-providers", "oidc", "max_admin_scope"]).and_then(|v| v.as_str()),
        Some("full"),
        "the ceiling written on the ADMIN chain entry lands on the one definition"
    );
    assert_eq!(
        dig(&doc, &["identity-providers", "oidc", "settings", "issuer"]).and_then(|v| v.as_str()),
        Some("https://idp.example/"),
        "the settings written on the DATA chain entry land on the same definition"
    );
    assert_eq!(
        dig(
            &doc,
            &["identity-providers", "oidc", "settings", "audience"]
        )
        .and_then(|v| v.as_str()),
        Some("busbar"),
        "the settings written on the METHODS entry merge in too (A7)"
    );
    assert_eq!(
        dig(
            &doc,
            &["identity-providers", "oidc", "browser_login", "client_id"]
        )
        .and_then(|v| v.as_str()),
        Some("busbar-web"),
        "browser_login is PER-PROVIDER in 1.5.3 (A7)"
    );
    // The operator credential rides onto the admin-tokens definition, not the chain entry.
    assert_eq!(
        dig(
            &doc,
            &["identity-providers", "admin-tokens", "token", "env"]
        )
        .and_then(|v| v.as_str()),
        Some("BUSBAR_ADMIN_TOKEN")
    );
    assert!(
        out.changes.iter().any(|c| c.contains("identity-providers")),
        "the change ledger names the lift; got {:?}",
        out.changes
    );

    // And the migrated config RESOLVES: both chains point at the SAME definition, so their entries
    // are identical by construction — the drift the retired grammar allowed is now impossible.
    let deploy: crate::config::DeployCfg =
        serde_yaml::from_str(&serde_yaml::to_string(&doc).unwrap()).expect("boot-parses");
    let mut errs = Vec::new();
    let auth = crate::config::resolve_auth(
        deploy.auth.as_ref().expect("auth"),
        &deploy.identity_providers,
        &mut errs,
    );
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(auth.chain[1], auth.admin_auth[1]);
}

/// GOLDEN — a legacy TAP with no `at:` must migrate to an EXPLICIT `phase: [request]`.
///
/// Under the frozen 1.5.3 rule an omitted `phase:` means ALL FOUR core stages, but a 1.5.0/1.5.2 tap
/// with no `at:` fired at the REQUEST stage ONLY (`resolve_tap_hooks_admits_only_request_stage_taps`).
/// Migrating it without pinning the stage would silently take that tap from one firing per request to
/// four — a behavior change smuggled in by a config migration. A migration must be
/// semantics-preserving, so the old default is written out explicitly.
///
/// RED-BEFORE-GREEN: `hook_entry_to_def` only emitted `phase:` when `at:` was PRESENT, so a bare tap
/// migrated with no `phase:` at all and silently widened to four stages.
#[test]
fn golden_migrate_bare_tap_pins_the_legacy_request_only_phase() {
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

    // A GATE has no stage default to preserve, so it is left alone (omitted `phase:` is correct).
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

/// AUDIT HIGH-2 — A MIGRATION MUST NEVER SILENTLY DROP OPERATOR CONFIG. `root.remove()` takes the
/// `auth:` key whatever its shape, so a MALFORMED block (`auth: null`, `auth: []`, a scalar — real
/// hand-edited shapes) hit the `let … else` and returned, leaving the migrated document with NO
/// `auth:` key and NO ledger entry at all. The block must survive VERBATIM and be named in the todos.
///
/// RED-BEFORE-GREEN: on the pre-fix tree the migrated document has no `auth:` key for any of these
/// three shapes and `out.todos` never mentions `auth:`.
#[test]
fn migrate_never_drops_a_malformed_auth_block() {
    for (shape, raw_auth) in [
        ("null", "auth:\n"),
        ("sequence", "auth: []\n"),
        ("scalar", "auth: tokens\n"),
    ] {
        let raw = format!("{raw_auth}providers: {{}}\nmodels: {{}}\npools: {{}}\n");
        let (out, doc) = migrate_to_value(&raw);
        let kept = dig(&doc, &["auth"]).unwrap_or_else(|| {
            panic!(
                "a malformed `auth:` ({shape}) was DROPPED by the migration:\n{}",
                out.yaml
            )
        });
        let original: serde_yaml::Value = serde_yaml::from_str(raw_auth).unwrap();
        assert_eq!(
            Some(kept),
            original
                .as_mapping()
                .and_then(|m| m.get(serde_yaml::Value::from("auth"))),
            "a malformed `auth:` ({shape}) must be carried through EXACTLY as written"
        );
        assert!(
            out.todos.iter().any(|t| t.starts_with("auth:")),
            "a malformed `auth:` ({shape}) must be NAMED in the todos, never silently passed \
             through; got {:?}",
            out.todos
        );
    }
}

/// The same rule for the OTHER map this pass takes: a malformed `identity-providers:` is put back
/// verbatim (together with the `auth:` block already removed by then) and flagged, rather than being
/// replaced by synthesized definitions.
///
/// RED-BEFORE-GREEN: pre-fix, `identity-providers: 7` vanished from the output entirely (the `match`
/// fell through to `Mapping::new()`), taking the operator's line with it.
#[test]
fn migrate_never_drops_a_malformed_identity_providers_block() {
    let raw = "auth:\n  chain: [{ oidc: { settings: { issuer: https://a.example.com } } }]\n\
               identity-providers: 7\nproviders: {}\nmodels: {}\npools: {}\n";
    let (out, doc) = migrate_to_value(raw);
    assert_eq!(
        dig(&doc, &["identity-providers"]).and_then(|v| v.as_u64()),
        Some(7),
        "a malformed `identity-providers:` must be carried through EXACTLY as written:\n{}",
        out.yaml
    );
    assert!(
        dig(&doc, &["auth", "chain"]).is_some(),
        "the `auth:` block this pass removed first must be restored on the early return:\n{}",
        out.yaml
    );
    assert!(
        out.todos
            .iter()
            .any(|t| t.starts_with("identity-providers:")),
        "the untouched malformed block must be named in the todos; got {:?}",
        out.todos
    );
}

/// AUDIT MED-1 — the `observability:`/`metrics:` blocks ARE deleted in 1.5.3 (retired sections), so a
/// malformed one legitimately disappears; what must not happen is it disappearing with NO record. The
/// deletion is recorded in `changes` so an operator diffing the ledger sees it.
///
/// RED-BEFORE-GREEN: pre-fix, `observability: null` / `metrics: null` were removed by `root.remove()`
/// and the `let … else` returned — `out.changes` mentions neither.
#[test]
fn migrate_records_the_deletion_of_a_malformed_retired_block() {
    let raw = "observability:\nmetrics: []\nproviders: {}\nmodels: {}\npools: {}\n";
    let (out, doc) = migrate_to_value(raw);
    assert!(
        dig(&doc, &["observability"]).is_none() && dig(&doc, &["metrics"]).is_none(),
        "both blocks are RETIRED in 1.5.3 and must still be deleted:\n{}",
        out.yaml
    );
    assert!(
        out.changes
            .iter()
            .any(|c| c.starts_with("observability: block removed")),
        "the observability deletion must be RECORDED in the ledger; got {:?}",
        out.changes
    );
    assert!(
        out.changes
            .iter()
            .any(|c| c.starts_with("metrics: block removed")),
        "the metrics deletion must be RECORDED in the ledger; got {:?}",
        out.changes
    );
}

/// AUDIT HIGH-3 — THE DEDUPE MUST NOT EAT A PLANE'S SETTINGS. One module configured on BOTH auth
/// planes with DIFFERENT settings (the data chain against one OIDC issuer, the admin chain against
/// another) was deduped into ONE definition carrying only the FIRST plane's settings — so the
/// migrated config authenticated admins against the wrong issuer. Two definitions is the honest
/// outcome: `<module>-admin` carries the admin plane's settings and `auth.admin_auth` references it.
///
/// RED-BEFORE-GREEN: pre-fix the migrated doc has ONE `oidc` definition whose `settings.issuer` is
/// `data.example.com`, `auth.admin_auth` is `[oidc]`, and `admin.example.com` appears nowhere.
#[test]
fn migrate_identity_providers_splits_a_per_plane_settings_conflict() {
    let raw = "auth:\n  \
                 chain: [{ oidc: { settings: { issuer: https://data.example.com } } }]\n  \
                 admin_auth: [{ oidc: { max_admin_scope: full, settings: { issuer: https://admin.example.com } } }]\n\
               providers: {}\nmodels: {}\npools: {}\n";
    let (out, doc) = migrate_to_value(raw);

    assert_eq!(
        dig(&doc, &["identity-providers", "oidc", "settings", "issuer"]).and_then(|v| v.as_str()),
        Some("https://data.example.com"),
        "the first plane keeps the module-named definition:\n{}",
        out.yaml
    );
    assert_eq!(
        dig(
            &doc,
            &["identity-providers", "oidc-admin", "settings", "issuer"]
        )
        .and_then(|v| v.as_str()),
        Some("https://admin.example.com"),
        "the CONFLICTING second plane must get its OWN definition — its settings must not be \
         dropped:\n{}",
        out.yaml
    );
    assert_eq!(
        dig(&doc, &["identity-providers", "oidc-admin", "module"]).and_then(|v| v.as_str()),
        Some("oidc"),
        "the split definition still names the same backing module"
    );
    assert_eq!(
        dig(&doc, &["auth", "admin_auth"]).and_then(|v| v.as_sequence()),
        Some(&vec![serde_yaml::Value::from("oidc-admin")]),
        "the admin plane must REFERENCE the split definition:\n{}",
        out.yaml
    );
    assert_eq!(
        dig(&doc, &["auth", "chain"]).and_then(|v| v.as_sequence()),
        Some(&vec![serde_yaml::Value::from("oidc")]),
        "the data plane keeps referencing the original definition"
    );
    assert!(
        out.todos.iter().any(|t| t.contains("oidc-admin")),
        "a split must be explained in the todos; got {:?}",
        out.todos
    );

    // AND THE DEDUPE STILL WINS when there is nothing to lose: identical settings on both planes
    // (and a plane that states none) still fold into exactly ONE definition.
    let same = "auth:\n  \
                  chain: [{ oidc: { settings: { issuer: https://one.example.com } } }]\n  \
                  admin_auth: [{ oidc: { settings: { issuer: https://one.example.com } } }, { tokens: {} }]\n\
                providers: {}\nmodels: {}\npools: {}\n";
    let (_, doc) = migrate_to_value(same);
    let defs = dig(&doc, &["identity-providers"])
        .and_then(|v| v.as_mapping())
        .expect("definitions");
    assert!(
        defs.contains_key(serde_yaml::Value::from("oidc"))
            && !defs.contains_key(serde_yaml::Value::from("oidc-admin")),
        "identical per-plane settings must still DEDUPE to one definition: {defs:?}"
    );
    assert_eq!(
        dig(&doc, &["auth", "admin_auth"]).and_then(|v| v.as_sequence()),
        Some(&vec![
            serde_yaml::Value::from("oidc"),
            serde_yaml::Value::from("tokens")
        ]),
        "both planes reference the ONE deduped definition"
    );
}

/// B2: a 1.4.x `budget_period` the migrator cannot express EXACTLY must never collapse silently
/// onto the ALL-TIME window.
///
/// `weekly` and `hourly` are both real 1.4.x periods (the tree's own admin tests name `weekly`), and
/// the old `_ => "total"` catch-all mapped BOTH to `per: total` — `WINDOW_TOTAL => 0`, the window
/// that NEVER ROLLS. That silently turned a recurring cap into a LIFETIME cap: once the group spends
/// it, it is blocked forever, with nothing in `changes`/`todos` to say so. The goldens only ever
/// exercised `monthly`/`daily`, which is why they stayed green.
///
/// So: `hourly` now maps EXACTLY (`hour`), `weekly` lands on the longest ROLLING window with a loud
/// TODO naming both the period and the window, and NOTHING recurring reaches `total`.
#[test]
fn unmappable_budget_period_never_silently_becomes_the_all_time_window() {
    let raw = "\
governance:
  enabled: true
  budget_groups:
    weekly-team: { max_budget_cents: 700000, budget_period: weekly }
    hourly-team: { max_budget_cents: 1000, budget_period: hourly }
    burst-team: { max_budget_cents: 500, budget_period: fortnightly }
    forever-team: { max_budget_cents: 900, budget_period: total }
providers: {}
models: {}
pools: {}
";
    let (out, doc) = migrate_to_value(raw);
    let per = |group: &str| -> String {
        dig(&doc, &["groups", group, "limits"])
            .and_then(|v| v.as_sequence())
            .and_then(|s| s.first())
            .and_then(|l| l.as_mapping())
            .and_then(|m| m.get(serde_yaml::Value::from("per")))
            .and_then(|v| v.as_str())
            .unwrap_or("<missing>")
            .to_string()
    };

    // `hourly` has an EXACT 1.5.3 window; it must land there and stay silent.
    assert_eq!(per("hourly-team"), "hour", "hourly -> the `hour` window");

    // `weekly` has NO 1.5.3 window. Whatever it maps to, it must still ROLL.
    let weekly = per("weekly-team");
    assert_ne!(
        weekly, "total",
        "a recurring weekly cap must NEVER become the all-time window (it never rolls, so the cap \
         becomes a lifetime cap)"
    );
    assert!(
        out.todos
            .iter()
            .any(|t| t.contains("weekly") && t.contains(&weekly)),
        "an approximated window must be LOUD — a todo naming the period AND the window it was \
         mapped to; got {:?}",
        out.todos
    );

    // An unrecognized word gets the same treatment, never a silent all-time collapse.
    let burst = per("burst-team");
    assert_ne!(
        burst, "total",
        "an unrecognized period must not become total"
    );
    assert!(
        out.todos
            .iter()
            .any(|t| t.contains("fortnightly") && t.contains(&burst)),
        "an unrecognized period must be named in the todos; got {:?}",
        out.todos
    );

    // …while an EXPLICIT all-time cap still maps to `total`, silently: that one really is all-time.
    assert_eq!(per("forever-team"), "total");
    assert!(
        !out.todos.iter().any(|t| t.contains("forever-team")),
        "an exact mapping must not push a todo; got {:?}",
        out.todos
    );
}

/// LOW-2 (round 4): an APPROXIMATED window may never loosen the operator's cap.
///
/// `weekly -> month` errs TIGHTER (a week's allowance has to last a month) — fail-closed, fine.
/// `yearly -> month` errs LOOSER, and the migrator carried the AMOUNT over unchanged: the operator's
/// `max_budget_cents: 1200000, budget_period: yearly` came out as `{ budget: 1200000, per: month }`
/// — TWELVE TIMES the annual cap they wrote, in force from the first boot for anyone who does not
/// act on the TODO. A migration is allowed to approximate; it is not allowed to hand out budget
/// nobody authorised.
///
/// The choice made: RESCALE proportionally (a year is 12 months), preserving spend per unit time,
/// rounding DOWN with a floor of 1 so the error can only ever go the fail-closed way and the output
/// still satisfies `validate_groups`' `amount > 0`. The TODO says both numbers out loud.
#[test]
fn a_yearly_budget_period_is_rescaled_never_loosened_onto_the_month_window() {
    let raw = "\
governance:
  enabled: true
  budget_groups:
    annual-team: { max_budget_cents: 1200000, budget_period: yearly }
    annual-alias: { max_budget_cents: 1200000, budget_period: annually }
    tiny-annual: { max_budget_cents: 6, budget_period: year }
    weekly-team: { max_budget_cents: 700000, budget_period: weekly }
providers: {}
models: {}
pools: {}
";
    let (out, doc) = migrate_to_value(raw);
    let limit = |group: &str| -> serde_yaml::Mapping {
        dig(&doc, &["groups", group, "limits"])
            .and_then(|v| v.as_sequence())
            .and_then(|s| s.first())
            .and_then(|l| l.as_mapping())
            .cloned()
            .unwrap_or_default()
    };
    let field = |group: &str, key: &str| -> serde_yaml::Value {
        limit(group)
            .get(serde_yaml::Value::from(key))
            .cloned()
            .unwrap_or(serde_yaml::Value::Null)
    };

    // GOLDEN: the whole migrated limit, both members, for every yearly spelling.
    for group in ["annual-team", "annual-alias"] {
        assert_eq!(
            field(group, "per"),
            serde_yaml::Value::from("month"),
            "{group}: yearly lands on the longest rolling window"
        );
        assert_eq!(
            field(group, "budget"),
            serde_yaml::Value::from(100000u64),
            "{group}: 1_200_000/year must become 100_000/month, NOT 1_200_000/month — carrying \
             the amount over unchanged is a 12x cap increase the operator never wrote"
        );
    }

    // Rounding is DOWN (never up: up is the loosening direction) with a floor of 1, so the emitted
    // config still satisfies `validate_groups`' `amount > 0`.
    assert_eq!(
        field("tiny-annual", "budget"),
        serde_yaml::Value::from(1u64),
        "6/year floors to 1/month — tighter than exact, and never the `budget: 0` that would make \
         the migrated config refuse to boot"
    );

    // A SHORTER period already errs tighter, so its amount is untouched.
    assert_eq!(
        field("weekly-team", "per"),
        serde_yaml::Value::from("month")
    );
    assert_eq!(
        field("weekly-team", "budget"),
        serde_yaml::Value::from(700000u64),
        "weekly -> month is already fail-CLOSED; rescaling it would loosen the cap"
    );

    // LOUD: the todo names the period, the window, and the rescale.
    let todo = out
        .todos
        .iter()
        .find(|t| t.contains("groups.annual-team"))
        .unwrap_or_else(|| panic!("no todo for the approximated annual cap: {:?}", out.todos));
    assert!(
        todo.contains("yearly") && todo.contains("month") && todo.contains("DIVIDED BY 12"),
        "the todo must name the period, the window AND the rescale it applied; got {todo:?}"
    );
}

/// B1: the migrator NEVER takes a key off the document and then discards the value because it was
/// not the shape the migration expected.
///
/// Three sites did exactly that, with no `changes`, no `todos` and no warning: the top-level
/// `hooks:` map, the top-level `global_hooks:` list, and the PER-POOL `hooks:` list. The reported
/// failure is the third: an operator writes the scalar form `pools: { frontier: { hooks: baa-gate }
/// }`, hits a loud 1.5.3 parse error, runs `busbar --migrate-config` — and the key is dropped on the
/// floor. `busbar --validate` then PASSES, because an ABSENT `hooks:` is the legal default, so the
/// pool ships with its rejecting compliance gate silently gone.
///
/// The contract asserted here (and enforced structurally by `Taken`): every malformed-shape key is
/// still IN the migrated document, EXACTLY as written, and is named in `todos`.
#[test]
fn a_wrong_shaped_key_is_never_taken_and_discarded() {
    let raw = "\
hooks: some-hook-name
global_hooks: audit-tap
providers: {}
models: {}
pools:
  frontier:
    hooks: baa-gate
    members: []
";
    let (out, doc) = migrate_to_value(raw);

    // THE reported case: the pool's compliance gate survives the migration.
    assert_eq!(
        dig(&doc, &["pools", "frontier", "hooks"]).and_then(|v| v.as_str()),
        Some("baa-gate"),
        "a scalar `pools.frontier.hooks:` must be left EXACTLY as written, never dropped — an \
         absent `hooks:` is a legal default, so --validate would then PASS with the gate gone. \
         Migrated document:\n{}",
        out.yaml
    );
    // …and the other two take-then-discard sites.
    assert_eq!(
        dig(&doc, &["hooks"]).and_then(|v| v.as_str()),
        Some("some-hook-name"),
        "a non-mapping top-level `hooks:` must survive; got:\n{}",
        out.yaml
    );
    assert_eq!(
        dig(&doc, &["global_hooks"]).and_then(|v| v.as_str()),
        Some("audit-tap"),
        "a non-sequence `global_hooks:` must survive; got:\n{}",
        out.yaml
    );

    // Surviving silently is not enough — the operator has to be TOLD, per key.
    for key in ["pools.frontier.hooks", "hooks", "global_hooks"] {
        assert!(
            out.todos.iter().any(|t| t.starts_with(&format!("{key}:"))),
            "`{key}` was preserved but not reported; every malformed-shape key must push a todo. \
             todos: {:?}",
            out.todos
        );
    }
}

/// 1.5.3 §C — the redis→valkey rename. The first-party Valkey store plugin was renamed
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
/// RED-BEFORE-GREEN: before `migrate_store_module` existed the migrated document still said
/// `redis` and `detect_legacy_markers` returned nothing for it.
#[test]
fn migrate_store_module_redis_to_valkey() {
    for old in ["redis", "busbar-store-redis", "busbar-store-redis-plugin"] {
        let raw = format!(
            "store:\n  module: {old}\n  settings: {{ url: \"redis://127.0.0.1:6379/0\" }}\n\
             providers: {{}}\nmodels: {{}}\npools: {{}}\n"
        );

        // (a) the loud fail-closed detector.
        let doc: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
        let joined = detect_legacy_markers(&doc).join("\n");
        assert!(
            joined.contains(old) && joined.contains("valkey"),
            "`store.module: {old}` must loud-fail with a marker naming the old AND new spelling; \
             got: {joined}"
        );

        // (b) the mechanical rewrite.
        let (out, doc) = migrate_to_value(&raw);
        assert_eq!(
            dig(&doc, &["store", "module"]).and_then(|v| v.as_str()),
            Some("valkey"),
            "`store.module: {old}` must be rewritten to the new alias; migrated:\n{}",
            out.yaml
        );
        // The settings bag rides along untouched — the URL SCHEME is the upstream driver's, not a
        // busbar-owned name, so the migrator must not touch it.
        assert_eq!(
            dig(&doc, &["store", "settings", "url"]).and_then(|v| v.as_str()),
            Some("redis://127.0.0.1:6379/0"),
            "the operator's connection URL must survive verbatim; migrated:\n{}",
            out.yaml
        );
        assert!(
            out.changes.iter().any(|c| c.contains("store.module")),
            "the rewrite must be RECORDED in the change ledger; got {:?}",
            out.changes
        );

        // The migrated document must not itself trip the detector (the operator ran the migrator;
        // running it again must not keep telling them to run it).
        assert!(
            detect_legacy_markers(&doc).is_empty(),
            "the migrated document still trips the 1.x detector: {:?}",
            detect_legacy_markers(&doc)
        );
    }

    // IDEMPOTENT: a config already on the new alias is untouched and un-flagged.
    let already = "store:\n  module: valkey\nproviders: {}\nmodels: {}\npools: {}\n";
    let (out, doc) = migrate_to_value(already);
    assert_eq!(
        dig(&doc, &["store", "module"]).and_then(|v| v.as_str()),
        Some("valkey")
    );
    assert!(
        !out.changes.iter().any(|c| c.contains("store.module")),
        "a config already on the new alias must produce no store.module change; got {:?}",
        out.changes
    );
    // …and an UNRELATED store module is not touched either.
    let other = "store:\n  module: postgres\nproviders: {}\nmodels: {}\npools: {}\n";
    let (_, doc) = migrate_to_value(other);
    assert_eq!(
        dig(&doc, &["store", "module"]).and_then(|v| v.as_str()),
        Some("postgres")
    );
}

/// B1 (see `a_wrong_shaped_key_is_never_taken_and_discarded`) for the 1.5.3 store rename: a `store:`
/// block written in a shape the rename cannot read is LEFT EXACTLY AS WRITTEN, in place, and named
/// in `todos` — never lifted out of the document and dropped. An absent `store:` is the legal
/// `memory` default, so a silent drop here would turn a durable deployment ephemeral and still pass
/// `--validate`: precisely the failure mode `Taken` exists to make structurally impossible.
#[test]
fn a_wrong_shaped_store_block_is_never_taken_and_discarded() {
    let raw = "store: redis\nproviders: {}\nmodels: {}\npools: {}\n";
    let (out, doc) = migrate_to_value(raw);
    assert_eq!(
        dig(&doc, &["store"]).and_then(|v| v.as_str()),
        Some("redis"),
        "a scalar `store:` must be left EXACTLY as written, never dropped; migrated:\n{}",
        out.yaml
    );
    assert!(
        out.todos.iter().any(|t| t.starts_with("store:")),
        "the malformed `store:` was preserved but not reported; todos: {:?}",
        out.todos
    );
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 1.5.3 — the EXPORT PROJECTION GRAMMAR migration (`streams:` made explicit).
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// Today's `export:` shape carries no `streams:`, so the projection it grants is IMPLIED by the
/// module. The migrator makes it EXPLICIT, in the order the operator wrote the instances, and says
/// so in the ledger — the grammar is taught by the migrated document rather than by a doc page.
///
/// GOLDEN, not a sed: the migrated document must boot-parse and resolve to the SAME projection the
/// pre-migration document meant.
#[test]
fn migrate_export_adds_the_explicit_streams_projection() {
    let raw = "\
export:
  metrics:
    module: prometheus
    settings:
      buffer_seconds: 60
  req-log:
    module: request-log-webhook
    settings:
      url: https://sink.example.com/l
  tail:
    module: request-log-file
    settings:
      path: /var/log/busbar.jsonl
  traces:
    module: otlp
    settings:
      url: http://localhost:4318/v1/traces
";
    let (out, doc) = migrate_to_value(raw);
    for (name, stream) in [
        ("metrics", "metrics"),
        ("req-log", "logs"),
        ("tail", "logs"),
        ("traces", "traces"),
    ] {
        let got = dig(&doc, &["export", name, "streams"])
            .unwrap_or_else(|| panic!("export.{name}.streams was not written"));
        assert_eq!(
            got,
            &serde_yaml::from_str::<serde_yaml::Value>(&format!("[{stream}]")).unwrap(),
            "export.{name}.streams"
        );
        assert!(
            out.changes
                .iter()
                .any(|c| c.contains(&format!("export.{name}")) && c.contains("streams")),
            "the ledger must name export.{name}'s new projection; got {:?}",
            out.changes
        );
    }
    // Instance ORDER is preserved (delivery order is deterministic and operator-visible).
    let names: Vec<String> = dig(&doc, &["export"])
        .unwrap()
        .as_mapping()
        .unwrap()
        .keys()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["metrics", "req-log", "tail", "traces"]);

    // GOLDEN: the migrated `export:` block PARSES under the 1.5.3 grammar and resolves — with NO
    // validation errors — to the projection the pre-migration document already meant. A rewrite that
    // wrote a projection the validator rejects would fail right here.
    let migrated_yaml = serde_yaml::to_string(&doc).unwrap();
    let defs: crate::config::ExportDefs =
        serde_yaml::from_value(dig(&doc, &["export"]).unwrap().clone())
            .expect("the migrated export block must parse");
    let mut errs = Vec::new();
    let export = crate::config::resolve_export(&defs, &mut errs);
    assert!(errs.is_empty(), "{errs:?}");
    assert!(export.request_log_webhooks[0]
        .projection
        .wants_stream(busbar_plugin_loader::ExportStream::Logs));

    // IDEMPOTENT: a second run writes nothing more.
    let (out2, doc2) = migrate_to_value(&migrated_yaml);
    assert!(
        !out2.changes.iter().any(|c| c.contains("streams")),
        "re-migrating must be a no-op; got {:?}",
        out2.changes
    );
    assert_eq!(
        doc2, doc,
        "the migrated tree must be stable under re-migration"
    );
}

/// A MALFORMED instance is LEFT EXACTLY AS WRITTEN with a TODO naming it — the `Taken<T>` discipline
/// (`take_mapping` is take-on-match). Silently dropping or "fixing" an operator's export instance is
/// the bug class that machinery exists to kill.
#[test]
fn migrate_export_leaves_a_malformed_instance_alone_with_a_todo() {
    let raw = "export:\n  broken: null\n  ok:\n    module: request-log-file\n    settings:\n      path: /tmp/x.jsonl\n";
    let (out, doc) = migrate_to_value(raw);
    assert!(
        dig(&doc, &["export", "broken"]).is_some_and(|v| v.is_null()),
        "the malformed instance must survive EXACTLY as written"
    );
    assert!(
        out.todos.iter().any(|t| t.contains("export.broken")),
        "a malformed instance must be flagged; got {:?}",
        out.todos
    );
    // Its healthy sibling is still migrated.
    assert!(dig(&doc, &["export", "ok", "streams"]).is_some());
}

/// An instance whose `module:` this build does not know cannot have its projection inferred. The
/// migrator must NOT guess — it flags it and leaves the instance alone.
#[test]
fn migrate_export_flags_an_unknown_module_rather_than_guessing() {
    let raw = "export:\n  siem:\n    module: some-third-party-sink\n    settings: {}\n";
    let (out, doc) = migrate_to_value(raw);
    assert!(dig(&doc, &["export", "siem", "streams"]).is_none());
    assert!(
        out.todos
            .iter()
            .any(|t| t.contains("export.siem") && t.contains("streams")),
        "an unknown module must be flagged, not guessed; got {:?}",
        out.todos
    );
}

/// `audit` was REMOVED as a stream. A hand-written `streams: [audit]` is NOT silently rewritten (a
/// projection is a security-relevant declaration — the operator decides what replaces it); it is
/// left as written with a TODO that names the replacement shape.
#[test]
fn migrate_export_flags_the_retired_audit_stream() {
    let raw = "export:\n  soc2:\n    module: request-log-webhook\n    streams: [logs, audit]\n    settings:\n      url: https://siem.example.com/l\n";
    let (out, doc) = migrate_to_value(raw);
    let streams = dig(&doc, &["export", "soc2", "streams"]).unwrap();
    assert_eq!(
        streams,
        &serde_yaml::from_str::<serde_yaml::Value>("[logs, audit]").unwrap(),
        "the operator's declaration must be left EXACTLY as written"
    );
    assert!(
        out.todos
            .iter()
            .any(|t| t.contains("export.soc2") && t.contains("audit")),
        "the retired `audit` stream must be flagged; got {:?}",
        out.todos
    );
}
