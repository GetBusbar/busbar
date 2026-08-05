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
    let entry = &admin_auth.as_sequence().unwrap()[0];
    let token_env = entry
        .as_mapping()
        .unwrap()
        .get(serde_yaml::Value::from("admin-tokens"))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("token")))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("env")))
        .and_then(|v| v.as_str());
    assert_eq!(token_env, Some("BUSBAR_ADMIN_TOKEN"));
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
    // hooks block dissolved: the pool ref inlined, the global tap moved to global_hooks.
    assert!(root.get(serde_yaml::Value::from("hooks")).is_none());
    let pool_hooks = get(&["pools", "fast", "hooks"]);
    let pool_hooks = pool_hooks.as_sequence().unwrap();
    assert_eq!(
        pool_hooks[0].as_str(),
        Some("cheapest"),
        "strategies stay bare"
    );
    let inlined = pool_hooks[1].as_mapping().unwrap();
    assert_eq!(
        inlined
            .get(serde_yaml::Value::from("module"))
            .and_then(|v| v.as_str()),
        Some("socket")
    );
    assert_eq!(
        inlined
            .get(serde_yaml::Value::from("settings"))
            .and_then(|v| v.as_mapping())
            .and_then(|m| m.get(serde_yaml::Value::from("path")))
            .and_then(|v| v.as_str()),
        Some("/run/pii.sock")
    );
    let ghooks = get(&["global_hooks"]);
    let g0 = ghooks.as_sequence().unwrap()[0].as_mapping().unwrap();
    assert_eq!(
        g0.get(serde_yaml::Value::from("module"))
            .and_then(|v| v.as_str()),
        Some("webhook")
    );
    // otlp_endpoint -> otlp_url.
    assert_eq!(
        get(&["observability", "otlp_url"]).as_str(),
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
        dig(&chain[1], &["oidc", "max_admin_scope"]).and_then(|v| v.as_str()),
        Some("full"),
        "auth.modules.oidc.max_admin_scope must fold onto the chain entry"
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

/// The 1.4.x TOP-LEVEL `global_hooks: [<name>]` was a list of REGISTRY names; 1.5.0 wants inline
/// refs. A registry name must resolve to its inline ref, and a hook that is BOTH named in
/// global_hooks AND flagged `global: true` must appear exactly ONCE (no duplicate, no leftover bare
/// name that `--validate` would reject).
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
    let gh = dig(&doc, &["global_hooks"]).unwrap().as_sequence().unwrap();
    assert_eq!(
        gh.len(),
        1,
        "the doubly-named global hook must not duplicate: {gh:?}"
    );
    assert_eq!(
        dig(&gh[0], &["module"]).and_then(|v| v.as_str()),
        Some("webhook"),
        "the registry name must resolve to its inline module ref"
    );
    // no leftover BARE string (a non-strategy bare name is not a valid 1.5.0 global-hook ref).
    assert!(
        gh[0].as_str().is_none(),
        "a bare registry name must not survive"
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

    // (b) the oidc chain entry's max_admin_scope: hooks-register -> full.
    let chain = auth
        .get(serde_yaml::Value::from("chain"))
        .and_then(|v| v.as_sequence())
        .expect("chain sequence");
    let oidc_cap = chain.iter().find_map(|e| {
        let m = e.as_mapping()?;
        let body = m.get(serde_yaml::Value::from("oidc"))?.as_mapping()?;
        body.get(serde_yaml::Value::from("max_admin_scope"))?
            .as_str()
    });
    assert_eq!(
        oidc_cap,
        Some("full"),
        "the retired `hooks-register` max_admin_scope must be rewritten to `full`; got {oidc_cap:?}"
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

    // The old key is GONE from `observability` (a raw pass-through would `deny_unknown_fields`-reject
    // at boot instead of silently keeping stale semantics).
    assert!(
        dig(&doc, &["observability", "emit_server_timing"]).is_none(),
        "the old key must not survive migration: {doc:?}"
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
    // The sibling otlp_endpoint rename still fires in the same run (the two migrations don't collide).
    assert_eq!(
        dig(&doc, &["observability", "otlp_url"]).and_then(|v| v.as_str()),
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

/// 1.5.3 HARD tap-stage rename: `--migrate-config` rewrites the old `at:` wire strings
/// (`route`/`attempt`/`completion`) to the new phase vocabulary (`candidate`/`routing`/`response`)
/// in place — in the top-level `global_hooks:` list AND in each `pools.<name>.hooks:` list — and the
/// result must BOOT-PARSE (the old strings would otherwise fail as unknown `HookStage` variants).
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

    // Pool hook `at:` strings are rewritten to the new phase names, in order.
    let pool_hooks = dig(&doc, &["pools", "primary", "hooks"])
        .unwrap()
        .as_sequence()
        .unwrap();
    assert_eq!(
        dig(&pool_hooks[0], &["at"]).and_then(|v| v.as_str()),
        Some("candidate"),
        "`at: route` must migrate to `at: candidate`"
    );
    assert_eq!(
        dig(&pool_hooks[1], &["at"]).and_then(|v| v.as_str()),
        Some("routing"),
        "`at: attempt` must migrate to `at: routing`"
    );
    // The global-hook `at:` string is rewritten too.
    let gh = dig(&doc, &["global_hooks"]).unwrap().as_sequence().unwrap();
    assert_eq!(
        dig(&gh[0], &["at"]).and_then(|v| v.as_str()),
        Some("response"),
        "`at: completion` must migrate to `at: response`"
    );
    // Each rewrite is named in the change ledger.
    assert!(
        out.changes
            .iter()
            .any(|c| c.contains("hook stage `at: completion` -> `at: response`")),
        "a change entry must name the completion->response rewrite; got {:?}",
        out.changes
    );
    // The migrated document must boot-parse: the old strings would fail as unknown HookStage
    // variants, so a clean parse proves the rewrite closed the loud-fail.
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

    // request-log-webhook exporter.
    assert_eq!(
        dig(&doc, &["export", "request-log-webhook", "settings", "url"]).and_then(|v| v.as_str()),
        Some("https://logs.example.com/busbar"),
    );
    assert_eq!(
        dig(
            &doc,
            &[
                "export",
                "request-log-webhook",
                "settings",
                "max_inflight_deliveries"
            ]
        )
        .and_then(|v| v.as_u64()),
        Some(32),
    );
    assert_eq!(
        dig(
            &doc,
            &[
                "export",
                "request-log-webhook",
                "settings",
                "delivery_timeout_secs"
            ]
        )
        .and_then(|v| v.as_u64()),
        Some(5),
    );
    // prometheus exporter.
    assert_eq!(
        dig(
            &doc,
            &["export", "prometheus", "settings", "buffer_seconds"]
        )
        .and_then(|v| v.as_u64()),
        Some(90),
    );
    assert_eq!(
        dig(
            &doc,
            &["export", "prometheus", "settings", "key_gauge_limit"]
        )
        .and_then(|v| v.as_u64()),
        Some(1500),
    );
    // otlp_url stays on observability (tracing is still core); the retired keys are gone.
    assert_eq!(
        dig(&doc, &["observability", "otlp_url"]).and_then(|v| v.as_str()),
        Some("https://otel.example.com/v1/traces"),
    );
    assert!(
        dig(&doc, &["observability", "request_log_webhook_url"]).is_none(),
        "the retired webhook key must be removed from observability"
    );
    assert!(
        dig(&doc, &["metrics"]).is_none(),
        "the retired top-level metrics block must be removed"
    );
    assert!(
        out.changes
            .iter()
            .any(|c| c.contains("request-log-webhook"))
            && out.changes.iter().any(|c| c.contains("export.prometheus")),
        "the change ledger names both rewrites; got {:?}",
        out.changes
    );

    // Idempotent: re-migrating the already-new document moves nothing more.
    let migrated_yaml = serde_yaml::to_string(&doc).unwrap();
    let (out2, _doc2) = migrate_to_value(&migrated_yaml);
    assert!(
        !out2
            .changes
            .iter()
            .any(|c| c.contains("request-log-webhook") || c.contains("export.prometheus")),
        "a second migrate is a no-op for the export rewrite; got {:?}",
        out2.changes
    );
}
