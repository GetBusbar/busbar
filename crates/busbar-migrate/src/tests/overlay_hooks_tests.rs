// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIGRATE-ON-BOOT r42 §9 C1 reds (n), (n1), (n2), (n3) and (n4)(4): the drop-in overlay, folded
//! as v1.5.5's `apply_root_to_deploy` + `apply_pre_resolve_sections` + `resolve` + `merge_into`
//! made it effective.
//!
//! The expected documents are the 1.5.5 effective configs read off v1.5.5's merge code
//! (`config/overlay.rs` `merge_into`, `RootSettings::apply_to_deploy`, `config/patch.rs`) for each
//! pair, compared as trees; the bytes the fold does not touch are compared byte for byte.

use busbar_contract::yaml::{self, Value, ValueExt};

use crate::overlay::DEFAULT_OVERLAY_FILENAME;
use crate::scratch::Scratch;
use crate::{backup_path, patch, plan, write, Inputs, Plan, Refusal, Written};

fn accept(_: &str) -> Result<(), String> {
    Ok(())
}

/// Plan `base` with `overlay` at the default path.
fn fold(scratch: &Scratch, base: &str, overlay: &str) -> Result<Plan, Refusal> {
    let path = scratch.config(base);
    scratch.file(DEFAULT_OVERLAY_FILENAME, overlay);
    plan(&Inputs::new(&path, &accept))
}

fn tree(text: &str) -> Value {
    patch::document(text).expect("a YAML mapping")
}

fn assert_tree(written: &str, expected: &str) {
    assert!(
        yaml::same_tree(&tree(written), &tree(expected)),
        "written:\n{written}\nexpected:\n{expected}"
    );
}

fn at<'v>(value: &'v Value, path: &[&str]) -> Option<&'v Value> {
    path.iter().try_fold(value, |value, key| value.get(*key))
}

fn names(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(ValueExt::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

const BASE_NO_STORE: &str = "\
# 1.5.5 deployment
listen: 0.0.0.0:8080
auth:
  chain: [idp1]
models:
  sonnet:
    provider: anthropic
groups:
  base_group: {}
  doomed_group: {}
hooks:
  base_hook:
    module: audit-tap
    kind: tap
  shadowed:
    module: old-gate
    kind: gate
pools:
  hooks: [base_hook]
  main:
    members:
      - model: sonnet
    hooks: [cheapest, base_hook, shadowed]
";

const SQLITE: &str = "\
store:
  module: sqlite
  settings:
    path: /var/lib/busbar/busbar.db
";

/// Every `OverlayDoc` field: two hooks (one shadowing a base hook, written by an older build with
/// `plugin`), `global_hooks: [api_hook, base_hook]` over base `pools.hooks: [base_hook]`, a hook
/// tombstone that also names a base global hook, a group and a group tombstone, a root `limits`
/// override, an OIDC identity provider and a webhook exporter, and a rollback pin.
const OVERLAY_N: &str = r#"{
  "version": 1,
  "hooks": {
    "api_hook": {"kind": "gate", "module": "ratelimit", "timeout_ms": 5, "on_error": "reject",
      "prompt": "no", "user": "ro", "priority": 3, "at": null, "on_empty": null,
      "settings": {"rps": 10}, "signals": [], "global": true, "default": false, "groups": [],
      "phase": []},
    "shadowed": {"kind": "gate", "plugin": "new-gate", "timeout_ms": 1, "on_error": "api_hook",
      "prompt": "no", "user": "no", "priority": 0, "at": "response", "on_empty": "weighted",
      "settings": {}, "signals": [], "global": false, "default": false, "groups": ["eng"],
      "phase": []}
  },
  "global_hooks": ["api_hook", "base_hook"],
  "deleted": ["base_hook"],
  "groups": {"eng": {"enabled": true}},
  "deleted_groups": ["doomed_group"],
  "root": {"limits": {"max_inbound_concurrent": 512}},
  "named_maps": {
    "identity-providers": {"idp1": {"module": "oidc", "settings": {"issuer": "https://idp.example"}}},
    "export": {"exp1": {"module": "webhook", "settings": {"url": "https://hooks.example/in"}}}
  },
  "plugin_versions": {"busbar-auth-oidc": "1.0.3"}
}"#;

/// v1.5.5's effective config for `BASE_NO_STORE` ⊕ `OVERLAY_N`, as config.yaml.
const EFFECTIVE_N: &str = "\
config_version: 1
listen: 0.0.0.0:8080
auth:
  chain: [idp1]
models:
  sonnet:
    provider: anthropic
groups:
  base_group: {}
  eng:
    enabled: true
hooks:
  shadowed:
    module: new-gate
    groups: [eng]
    phase: [response]
    kind: gate
    timeout_ms: 1
    on_error: {hook: api_hook}
    on_empty: weighted
    prompt: 'no'
    user: 'no'
    priority: 0
  api_hook:
    module: ratelimit
    settings:
      rps: 10
    kind: gate
    timeout_ms: 5
    on_error: reject
    prompt: 'no'
    user: ro
    priority: 3
pools:
  hooks: [api_hook]
  main:
    members:
      - model: sonnet
    hooks: [cheapest, shadowed]
limits:
  max_inbound_concurrent: 512
identity-providers:
  idp1:
    module: oidc
    settings:
      issuer: https://idp.example
export:
  exp1:
    module: webhook
    settings:
      url: https://hooks.example/in
";

/// (n) the drop-in overlay over (i) a config with no `store:` block and (ii) a sqlite store: the
/// rewritten config.yaml is 1.5.5's effective config; every line the fold did not change is the
/// operator's byte for byte; `config.yaml.1.5.5` and `<o>.1.5.5` are the originals; the pin is
/// reported and warned, never written.
#[test]
fn a_drop_in_overlay_folds_to_1_5_5s_effective_config() {
    for store in ["", SQLITE] {
        let scratch = Scratch::new();
        let base = format!("{BASE_NO_STORE}{store}");
        let plan = fold(&scratch, &base, OVERLAY_N).unwrap();
        assert_tree(plan.planned(), &format!("{EFFECTIVE_N}{store}"));
        for kept in [
            "# 1.5.5 deployment\n",
            "auth:\n  chain: [idp1]\nmodels:\n  sonnet:\n    provider: anthropic\n",
            "  main:\n    members:\n      - model: sonnet\n",
            "  base_group: {}\n",
            store,
        ] {
            assert!(
                plan.planned().contains(kept),
                "{kept:?} in\n{}",
                plan.planned()
            );
        }
        let pin = plan
            .report()
            .iter()
            .find(|line| line.contains("plugin_versions.busbar-auth-oidc: 1.0.3"));
        assert!(pin.is_some(), "{:?}", plan.report());
        assert!(plan.warnings().iter().any(|line| Some(line) == pin));
        assert!(!plan.planned().contains("busbar-auth-oidc"));
        let path = scratch.dir().join("config.yaml");
        assert_eq!(write(&plan, &accept), Ok(Written::Stamped));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), plan.planned());
        assert_eq!(std::fs::read_to_string(backup_path(&path)).unwrap(), base);
        assert_eq!(
            std::fs::read_to_string(scratch.dir().join("busbar-overlay.json.1.5.5")).unwrap(),
            OVERLAY_N
        );
    }
}

/// (n1)(1) the overlay's global list is unioned after base `pools.hooks`, base order first, no
/// duplicate; a `global: true` hook not yet listed joins last.
#[test]
fn the_global_attachment_is_base_first_without_duplicates() {
    let scratch = Scratch::new();
    let base = "hooks:\n  a: {module: x, kind: tap}\n  b: {module: x, kind: tap}\npools:\n  hooks: [a, b]\n";
    let overlay = r#"{"hooks": {"c": {"kind": "tap", "module": "x"}, "d": {"kind": "tap", "module": "x", "global": true}},
        "global_hooks": ["c", "a"]}"#;
    let plan = fold(&scratch, base, overlay).unwrap();
    let planned = tree(plan.planned());
    assert_eq!(
        names(at(&planned, &["pools", "hooks"])),
        ["a", "b", "c", "d"]
    );
}

/// (n1)(2) a tombstone of a base global hook removes the hook, its name from `pools.hooks` and from
/// every pool's own list.
#[test]
fn a_tombstone_of_a_base_global_hook_removes_it_everywhere() {
    let scratch = Scratch::new();
    let base = "hooks:\n  h: {module: x, kind: gate}\n  k: {module: x, kind: tap}\npools:\n  hooks: [h, k]\n  p:\n    hooks: [fastest, h]\n";
    let plan = fold(&scratch, base, r#"{"deleted": ["h"]}"#).unwrap();
    let planned = tree(plan.planned());
    assert!(at(&planned, &["hooks", "h"]).is_none());
    assert!(at(&planned, &["hooks", "k"]).is_some());
    assert_eq!(names(at(&planned, &["pools", "hooks"])), ["k"]);
    assert_eq!(names(at(&planned, &["pools", "p", "hooks"])), ["fastest"]);
}

/// (n1)(3) an overlay hook shadowing a base hook replaces it in place (the overlay wins, at the
/// base entry's position); `at` becomes `phase`, a non-empty `phase` wins over `at`, and with
/// neither no `phase` is written; `on_error` is bare for a terminal and `{hook: …}` otherwise.
#[test]
fn an_overlay_hook_replaces_a_base_hook_in_place() {
    let scratch = Scratch::new();
    let base = "hooks:\n  first:\n    module: old\n    kind: tap\n  second:\n    module: keep\n    kind: tap\n";
    let overlay = r#"{"hooks": {
        "first": {"kind": "tap", "plugin": "new", "at": "routing"},
        "both": {"kind": "tap", "module": "x", "at": "request", "phase": ["response", "candidate"], "on_error": "first"},
        "neither": {"kind": "gate", "module": "x", "on_error": "second"}}}"#;
    let plan = fold(&scratch, base, overlay).unwrap();
    let planned = tree(plan.planned());
    let hooks = planned.get("hooks").and_then(ValueExt::as_mapping).unwrap();
    assert_eq!(hooks[0].0.as_str(), Some("first"), "kept at its position");
    let first = at(&planned, &["hooks", "first"]).unwrap();
    assert_eq!(first.get("module").and_then(ValueExt::as_str), Some("new"));
    assert_eq!(names(first.get("phase")), ["routing"]);
    assert_eq!(
        first.get("on_error").and_then(ValueExt::as_str),
        Some("nothing")
    );
    assert_eq!(first.get("timeout_ms").and_then(ValueExt::as_u64), Some(1));
    let both = at(&planned, &["hooks", "both"]).unwrap();
    assert_eq!(names(both.get("phase")), ["response", "candidate"]);
    assert_eq!(
        both.get("on_error").and_then(ValueExt::as_str),
        Some("first")
    );
    let neither = at(&planned, &["hooks", "neither"]).unwrap();
    assert!(neither.get("phase").is_none());
    assert_eq!(
        at(neither, &["on_error", "hook"]).and_then(ValueExt::as_str),
        Some("second")
    );
    assert!(plan
        .planned()
        .contains("  second:\n    module: keep\n    kind: tap\n"));
}

/// (n2) an overlay group, a tombstone of a base group, and a group added then tombstoned in the
/// same overlay each give 1.5.5's effective set; no `groups:` is added when none remains.
#[test]
fn overlay_groups_and_tombstones_give_1_5_5s_set() {
    let scratch = Scratch::new();
    let base = "groups:\n  base: {}\n  gone: {}\n";
    let overlay = r#"{"groups": {"new": {"enabled": false}, "fleeting": {}}, "deleted_groups": ["gone", "fleeting"]}"#;
    let plan = fold(&scratch, base, overlay).unwrap();
    assert_tree(
        plan.planned(),
        "config_version: 1\ngroups:\n  base: {}\n  new:\n    enabled: false\n",
    );
    let scratch = Scratch::new();
    let plan = fold(
        &scratch,
        "listen: x\n",
        r#"{"groups": {"g": {}}, "deleted_groups": ["g"]}"#,
    )
    .unwrap();
    assert_tree(plan.planned(), "config_version: 1\nlisten: x\n");
}

/// (n3) `identity-providers` and `export` entries are added by name; a section 1.5.5 never read is
/// dropped with a report line; a name config.yaml already defines refuses CONFIG; the plugin pins
/// are report lines and WARNs, never config.
#[test]
fn named_maps_fold_and_plugin_pins_are_only_reported() {
    let scratch = Scratch::new();
    let overlay = r#"{"named_maps": {"export": {"exp1": {"module": "webhook"}}, "tools": {"t": {}}},
        "plugin_versions": {"store-sqlite": "1.0.2"}}"#;
    let plan = fold(&scratch, "export:\n  base: {module: file}\n", overlay).unwrap();
    let planned = tree(plan.planned());
    assert!(at(&planned, &["export", "exp1"]).is_some());
    assert!(at(&planned, &["export", "base"]).is_some());
    assert!(planned.get("tools").is_none());
    assert!(plan
        .report()
        .iter()
        .any(|line| line.contains("`named_maps.tools` is dropped")));
    assert!(plan
        .warnings()
        .iter()
        .any(|line| line.contains("plugin_versions.store-sqlite: 1.0.2")));
    assert!(!plan.planned().contains("store-sqlite"));

    let scratch = Scratch::new();
    let refused = fold(
        &scratch,
        "export:\n  exp1: {module: file}\n",
        r#"{"named_maps": {"export": {"exp1": {"module": "webhook"}}}}"#,
    )
    .unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert!(refused.to_string().contains("`export.exp1`"), "{refused}");
}

/// `default: true` refuses where it was the base ordering of a pool in 1.5.5 (a non-rewriting gate,
/// and a pool whose `hooks:` names no strategy), naming the hook and the pools; otherwise it is
/// dropped with one report line.
#[test]
fn a_default_hook_refuses_only_where_it_ordered_a_pool() {
    let overlay = r#"{"hooks": {"order": {"kind": "gate", "module": "x", "default": true}}}"#;
    let scratch = Scratch::new();
    let refused = fold(&scratch, "pools:\n  p:\n    hooks: [order]\n", overlay).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    let shown = refused.to_string();
    assert!(
        shown.contains("`order`") && shown.contains("pools p"),
        "{shown}"
    );
    assert_eq!(scratch.names(), ["busbar-overlay.json", "config.yaml"]);

    let scratch = Scratch::new();
    let plan = fold(&scratch, "pools:\n  p:\n    hooks: [usage]\n", overlay).unwrap();
    assert!(plan
        .report()
        .iter()
        .any(|line| line.contains("`default: true` is dropped")));
    let rewriting =
        r#"{"hooks": {"order": {"kind": "gate", "module": "x", "prompt": "rw", "default": true}}}"#;
    let scratch = Scratch::new();
    assert!(fold(&scratch, "pools:\n  p:\n    members: []\n", rewriting).is_ok());
}

/// A hook 1.5.5's `HookCfg` could not read refuses CONFIG naming it (never skipped).
#[test]
fn a_hook_1_5_5_could_not_read_is_refused() {
    for (hook, text) in [
        (
            r#"{"kind": "tap", "module": "x", "bogus": 1}"#,
            "unknown field `bogus`",
        ),
        (
            r#"{"kind": "tap", "module": "x", "plugin": "y"}"#,
            "duplicate field `module`",
        ),
        (r#"{"module": "x"}"#, "missing field `kind`"),
        (r#"{"kind": "tap", "module": "x", "at": "nowhere"}"#, "`at`"),
        (
            r#"{"kind": "tap", "module": "x", "priority": 70000}"#,
            "`priority`",
        ),
    ] {
        let scratch = Scratch::new();
        let refused = fold(
            &scratch,
            "listen: x\n",
            &format!(r#"{{"hooks": {{"h": {hook}}}}}"#),
        )
        .unwrap_err();
        assert_eq!(refused.word(), "CONFIG", "{hook}");
        let shown = refused.to_string();
        assert!(
            shown.contains("`hooks.h`") && shown.contains(text),
            "{shown}"
        );
    }
}

/// (n4)(4) what the fold never emits: none of the overlay's own keys `global_hooks`, `global`,
/// `default`, `at` or `plugin` reaches config.yaml.
#[test]
fn the_fold_never_emits_the_overlays_own_hook_keys() {
    let scratch = Scratch::new();
    let plan = fold(&scratch, BASE_NO_STORE, OVERLAY_N).unwrap();
    let planned = tree(plan.planned());
    assert!(planned.get("global_hooks").is_none());
    for (_, hook) in planned.get("hooks").and_then(ValueExt::as_mapping).unwrap() {
        for key in ["global", "default", "at", "plugin"] {
            assert!(hook.get(key).is_none(), "{key} in {hook:?}");
        }
    }
}
