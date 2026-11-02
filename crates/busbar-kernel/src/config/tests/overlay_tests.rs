// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/config/overlay.rs`.

use super::*;

fn gate() -> HookCfg {
    serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": "test-hook", "prompt": "rw", "global": true
    }))
    .unwrap()
}

use crate::test_support::TestOverlayStore;
/// A minimal RESOLVED config to merge overlays into (providers/models empty; registry empty).
fn minimal_cfg() -> RootCfg {
    let deploy: super::super::DeployCfg =
        serde_json::from_value(serde_json::json!({"providers": {}, "models": {}})).unwrap();
    super::super::resolve(&deploy, &HashMap::new()).expect("minimal config resolves")
}

/// merge_into adds overlay hooks to the resolved registry + unions global names; an overlay
/// hook with a base hook's name wins.
#[test]
fn merge_into_deploy() {
    let mut cfg = minimal_cfg();
    let mut base = gate();
    base.plugin = "base-module".to_string();
    cfg.hooks.insert("base_hook".to_string(), base);
    let doc = from_state(
        &HashMap::from([
            ("base_hook".to_string(), gate()), // same name as a base hook → overlay wins
            ("api_hook".to_string(), gate()),
        ]),
        &["api_hook".to_string(), "base_hook".to_string()],
    );
    cfg.global_hooks.push("base_hook".to_string());
    merge_into(&mut cfg, doc);
    assert!(cfg.hooks.contains_key("api_hook"));
    assert!(cfg.hooks.contains_key("base_hook"));
    assert_eq!(cfg.hooks["base_hook"].plugin, "test-hook", "overlay wins");
    // global_hooks unioned, no duplicate of base_hook.
    assert_eq!(
        cfg.global_hooks
            .iter()
            .filter(|g| *g == "base_hook")
            .count(),
        1,
        "global union does not duplicate"
    );
    assert!(cfg.global_hooks.iter().any(|g| g == "api_hook"));
}

/// TOMBSTONE: a hook the API deleted (recorded in `deleted`) is removed from the effective config at
/// boot even if it was defined in base config.yaml — so an API deletion survives a restart.
#[test]
fn merge_into_applies_tombstones() {
    let mut cfg = minimal_cfg();
    cfg.hooks.insert("base_hook".to_string(), gate());
    cfg.global_hooks.push("base_hook".to_string());
    let doc = OverlayDoc {
        hooks: HashMap::new(),
        global_hooks: Vec::new(),
        deleted: vec!["base_hook".to_string()],
        ..Default::default()
    };
    merge_into(&mut cfg, doc);
    assert!(
        !cfg.hooks.contains_key("base_hook"),
        "a tombstoned base hook is removed from the effective config"
    );
    assert!(!cfg.global_hooks.iter().any(|g| g == "base_hook"));
}

/// REGRESSION: `persist` must NOT overwrite a present-but-unreadable/corrupt overlay — that would
/// drop accumulated deletion tombstones and silently resurrect a deleted hook on restart.
fn group_with_budget() -> GroupCfg {
    serde_json::from_value(serde_json::json!({
        "limits": [ { "budget": 1000, "per": "month" } ]
    }))
    .unwrap()
}

/// merge_into inserts overlay groups (an overlay group with a base group's name wins) and applies
/// group tombstones LAST — an API-deleted group stays gone even if base config.yaml defined it.
#[test]
fn merge_into_groups_and_group_tombstones() {
    let mut cfg = minimal_cfg();
    cfg.groups.insert("team".to_string(), group_with_budget());
    cfg.groups.insert("doomed".to_string(), group_with_budget());
    let doc = OverlayDoc {
        groups: BTreeMap::from([("user:alice".to_string(), group_with_budget())]),
        deleted_groups: vec!["doomed".to_string()],
        ..Default::default()
    };
    merge_into(&mut cfg, doc);
    assert!(cfg.groups.contains_key("user:alice"), "overlay group added");
    assert!(cfg.groups.contains_key("team"), "base group untouched");
    assert!(
        !cfg.groups.contains_key("doomed"),
        "tombstoned group removed even though base defined it"
    );
}

/// REGRESSION: a HOOK write must PRESERVE the groups section + its tombstones — the read-modify-write
/// loads the whole doc and mutates only the hook section. Guards against "persist rebuilds the doc
/// inline and silently drops groups".
/// `OverlaySection::parse` is the ONE valid-name gate: `groups`/`hooks` round-trip, everything
/// else is `None` (the reset endpoint 400s on it).
#[test]
fn overlay_section_parse_round_trips_and_rejects() {
    assert_eq!(
        OverlaySection::parse("groups"),
        Some(OverlaySection::Groups)
    );
    assert_eq!(OverlaySection::parse("hooks"), Some(OverlaySection::Hooks));
    assert_eq!(OverlaySection::parse("root"), Some(OverlaySection::Root));
    assert_eq!(OverlaySection::Groups.as_str(), "groups");
    assert_eq!(OverlaySection::Hooks.as_str(), "hooks");
    assert_eq!(OverlaySection::Root.as_str(), "root");
    for bad in ["", "Groups", "hook", "auth", "plugins", "groups/", "Root"] {
        assert!(
            OverlaySection::parse(bad).is_none(),
            "`{bad}` is not a section"
        );
    }
}

/// `clear_section(Groups)` wipes the groups entries + tombstones and leaves the hooks section
/// (and its tombstones) untouched — the per-section reset invariant.
#[test]
fn clear_section_wipes_one_section_only() {
    let mut doc = OverlayDoc {
        hooks: HashMap::from([("h".to_string(), gate())]),
        global_hooks: vec!["h".to_string()],
        deleted: vec!["gonehook".to_string()],
        groups: BTreeMap::from([("user:alice".to_string(), group_with_budget())]),
        deleted_groups: vec!["gonegroup".to_string()],
        ..Default::default()
    };
    doc.clear_section(OverlaySection::Groups);
    assert!(doc.groups.is_empty(), "groups entries cleared");
    assert!(doc.deleted_groups.is_empty(), "group tombstones cleared");
    assert!(doc.hooks.contains_key("h"), "hooks section preserved");
    assert_eq!(
        doc.global_hooks,
        vec!["h".to_string()],
        "global wiring preserved"
    );
    assert_eq!(
        doc.deleted,
        vec!["gonehook".to_string()],
        "hook tombstones preserved"
    );
    // And the symmetric case.
    doc.clear_section(OverlaySection::Hooks);
    assert!(doc.hooks.is_empty() && doc.global_hooks.is_empty() && doc.deleted.is_empty());
}

/// `section_is_empty` is true only when a section carries neither entries nor tombstones — the
/// idempotent-no-op predicate the reset handler short-circuits on.
#[test]
fn section_is_empty_tracks_entries_and_tombstones() {
    let empty = OverlayDoc::default();
    assert!(empty.section_is_empty(OverlaySection::Groups));
    assert!(empty.section_is_empty(OverlaySection::Hooks));
    // A lone tombstone (no live entry) still counts as non-empty (a base deletion to revert).
    let tombstoned = OverlayDoc {
        deleted_groups: vec!["x".to_string()],
        deleted: vec!["y".to_string()],
        ..Default::default()
    };
    assert!(!tombstoned.section_is_empty(OverlaySection::Groups));
    assert!(!tombstoned.section_is_empty(OverlaySection::Hooks));
}
/// A minimal base `DeployCfg` (all uncovered sections at their defaults) to apply root overrides
/// onto. Uses the real YAML parse path so the defaults match production exactly.
fn minimal_deploy() -> DeployCfg {
    serde_yaml::from_str("providers: {}\nmodels: {}\n").expect("minimal deploy parses")
}

/// A `RootSettings` naming a couple of overrides, parsed from JSON exactly as the API body would.
fn sample_root() -> RootSettings {
    serde_json::from_value(serde_json::json!({
        "listen": "0.0.0.0:9000",
        "per_request_fee": 7,
        "rate_card": { "m0": { "input_utok": 1.5, "output_utok": 2.0 } },
        "limits": { "max_inbound_concurrent": 512 }
    }))
    .expect("root settings parse")
}

/// `apply_to_deploy` overwrites ONLY the named fields; unset fields keep base values.
#[test]
fn root_apply_overwrites_only_named_fields() {
    let mut deploy = minimal_deploy();
    let base_admin_listen = deploy.admin_listen.clone();
    // NON-DEFAULT base values, or this test cannot see the defect it guards: with an
    // all-defaults base a whole-section clobber is indistinguishable from a per-field merge,
    // which is why it passed for as long as the bug existed.
    deploy.limits.upstream_request_timeout_secs = 30;
    deploy.limits.request_body_max_bytes = 1_048_576;
    sample_root().apply_to_deploy(&mut deploy);
    assert_eq!(
        deploy.limits.upstream_request_timeout_secs, 30,
        "a limits field the overlay never names keeps the operator's value"
    );
    assert_eq!(
        deploy.limits.request_body_max_bytes, 1_048_576,
        "including a deliberately tightened body cap"
    );
    assert_eq!(deploy.listen, "0.0.0.0:9000", "listen overridden");
    assert_eq!(deploy.per_request_fee, 7, "fee overridden");
    assert_eq!(
        deploy.limits.max_inbound_concurrent, 512,
        "a limits field overridden"
    );
    assert!(
        deploy
            .rate_card
            .as_ref()
            .is_some_and(|rc| rc.contains_key("m0")),
        "rate_card overridden"
    );
    assert_eq!(
        deploy.admin_listen, base_admin_listen,
        "an unset field keeps its base value"
    );
}

/// `is_empty` / `section_is_empty(Root)` track whether any override is set.
#[test]
fn root_is_empty_tracks_overrides() {
    assert!(RootSettings::default().is_empty());
    assert!(OverlayDoc::default().section_is_empty(OverlaySection::Root));
    let doc = OverlayDoc {
        root: Some(sample_root()),
        ..Default::default()
    };
    assert!(!doc.section_is_empty(OverlaySection::Root));
    // A root override does not make hooks/groups non-empty (independent sections).
    assert!(doc.section_is_empty(OverlaySection::Hooks));
    assert!(doc.section_is_empty(OverlaySection::Groups));
}
/// `clear_section(Root)` wipes only the root override; the hooks/groups sections survive. And the
/// on-disk `clear_section` refuses a corrupt overlay (fail-closed, like the sibling sections).
#[test]
fn clear_root_section_only() {
    let mut doc = OverlayDoc {
        hooks: HashMap::from([("h".to_string(), gate())]),
        root: Some(sample_root()),
        ..Default::default()
    };
    doc.clear_section(OverlaySection::Root);
    assert!(doc.root.is_none(), "root cleared");
    assert!(doc.hooks.contains_key("h"), "hooks preserved");
}

/// `apply_root_to_deploy` is a no-op when the overlay has no root override, and applies it when
/// present — the pre-resolve boot-merge half.
#[test]
fn apply_root_to_deploy_noop_and_active() {
    let mut deploy = minimal_deploy();
    apply_root_to_deploy(&mut deploy, &OverlayDoc::default());
    assert_eq!(
        deploy.per_request_fee, 0,
        "no root override → base unchanged"
    );
    let doc = OverlayDoc {
        root: Some(sample_root()),
        ..Default::default()
    };
    apply_root_to_deploy(&mut deploy, &doc);
    assert_eq!(deploy.per_request_fee, 7, "root override applied");
}

/// An unknown key in a root-settings body is a loud reject (`deny_unknown_fields`), never a silent
/// no-op — the same fail-closed posture as the DeployCfg surface.
#[test]
fn root_settings_rejects_unknown_field() {
    let r: Result<RootSettings, _> =
        serde_json::from_value(serde_json::json!({ "lissten": "0.0.0.0:9000" }));
    assert!(r.is_err(), "a typo'd root field is rejected");
}

/// PLUGIN VERSION PINS (1.5.0 rollback-friendly versioning): a `plugin_versions` pin lowers BOTH
/// the per-name `min_versions` floor (third-party path) AND a PER-NAME `first_party_floors` entry
/// (first-party path) when applied to a base `DeployCfg`. Each pin scopes its first-party
/// override to its own name — there is no single global floor lowered for every first-party plugin.
#[test]
fn plugin_versions_pins_lower_the_floors() {
    let mut deploy = minimal_deploy();
    // Base has a higher floor and no first-party floor override (the automatic default).
    deploy
        .plugins
        .min_versions
        .insert("acme-store-x".to_string(), "2.0.0".to_string());
    assert!(deploy.plugins.first_party_floors.is_empty());

    let doc = OverlayDoc {
        plugin_versions: BTreeMap::from([
            ("acme-store-x".to_string(), "1.4.0".to_string()),
            (
                "busbar-store-first-party-plugin".to_string(),
                "1.5.0".to_string(),
            ),
        ]),
        ..Default::default()
    };
    apply_plugin_versions_to_deploy(&mut deploy, &doc);

    assert_eq!(
        deploy
            .plugins
            .min_versions
            .get("acme-store-x")
            .map(String::as_str),
        Some("1.4.0"),
        "the third-party floor is LOWERED to the pinned version"
    );
    // PER-NAME first-party floor overrides: each pinned name gets exactly its pinned version;
    // there is no global floor, so an unpinned first-party plugin is unaffected.
    assert_eq!(
        deploy
            .plugins
            .first_party_floors
            .get("acme-store-x")
            .map(String::as_str),
        Some("1.4.0"),
    );
    assert_eq!(
        deploy
            .plugins
            .first_party_floors
            .get("busbar-store-first-party-plugin")
            .map(String::as_str),
        Some("1.5.0"),
    );
}

/// No pins ⇒ no per-name floor overrides (the automatic posture is untouched): `apply_root_to_deploy`
/// (which also applies pins) leaves `first_party_floors` EMPTY when the overlay carries no pins, so
/// every first-party plugin keeps the binary's own version as its floor.
#[test]
fn no_pins_leaves_first_party_floor_none() {
    let mut deploy = minimal_deploy();
    apply_root_to_deploy(&mut deploy, &OverlayDoc::default());
    assert!(
        deploy.plugins.first_party_floors.is_empty(),
        "with no pins the automatic first-party floor stands"
    );
}
/// `clear_section(PluginVersions)` wipes only the pins; the other sections survive — the durable
/// half of `DELETE /api/v1/admin/overlay/plugin_versions` (lift every rollback pin).
#[test]
fn clear_plugin_versions_section_only() {
    let mut doc = OverlayDoc {
        hooks: HashMap::from([("h".to_string(), gate())]),
        plugin_versions: BTreeMap::from([("p".to_string(), "1.0.0".to_string())]),
        ..Default::default()
    };
    doc.clear_section(OverlaySection::PluginVersions);
    assert!(doc.plugin_versions.is_empty(), "pins cleared");
    assert!(doc.hooks.contains_key("h"), "hooks preserved");
}

/// The `plugin_versions` path segment parses to the section and round-trips its label.
#[test]
fn plugin_versions_section_parses() {
    assert_eq!(
        OverlaySection::parse("plugin_versions"),
        Some(OverlaySection::PluginVersions)
    );
    assert_eq!(OverlaySection::PluginVersions.as_str(), "plugin_versions");
}

#[test]
fn store_round_trip_preserves_every_sibling_and_resets_only_requested_section() {
    let fixture = TestOverlayStore::new();
    let backend = fixture.backend();
    persist(
        Some(&backend),
        &HashMap::from([("h".into(), gate())]),
        &["h".into()],
        None,
        None,
        &HashSet::new(),
    )
    .unwrap();
    persist_groups(
        Some(&backend),
        &BTreeMap::from([("g".into(), group_with_budget())]),
        None,
        None,
        &HashSet::new(),
    )
    .unwrap();
    persist_root(Some(&backend), &sample_root()).unwrap();
    try_persist_plugin_versions(
        Some(&backend),
        &BTreeMap::from([("p".into(), "1.0.0".into())]),
    )
    .unwrap();
    let section = crate::config::named_map::NamedMapSection::Export;
    persist_named_map(
        Some(&backend),
        section,
        "named",
        Some(&serde_json::json!({"module":"test"})),
    )
    .unwrap();
    let doc = backend.read_required().unwrap().unwrap();
    assert!(doc.hooks.contains_key("h"));
    assert!(doc.groups.contains_key("g"));
    assert!(doc.root.is_some());
    assert_eq!(doc.plugin_versions["p"], "1.0.0");
    assert!(doc.named_maps["export"].contains_key("named"));
    clear_section(Some(&backend), OverlaySection::Hooks).unwrap();
    let doc = backend.read_required().unwrap().unwrap();
    assert!(doc.hooks.is_empty());
    assert!(doc.groups.contains_key("g"));
    assert!(doc.root.is_some());
    assert_eq!(doc.plugin_versions["p"], "1.0.0");
    assert!(doc.named_maps["export"].contains_key("named"));
}

#[test]
fn hook_and_group_tombstones_reconcile_readds_and_prune_nonbase_names() {
    let fixture = TestOverlayStore::new();
    let backend = fixture.backend();
    write(
        &backend,
        &OverlayDoc {
            deleted: vec!["base".into(), "readd".into(), "inert".into()],
            deleted_groups: vec!["base".into(), "readd".into(), "inert".into()],
            ..Default::default()
        },
    )
    .unwrap();
    let names = HashSet::from(["base".into(), "readd".into()]);
    persist(
        Some(&backend),
        &HashMap::from([("readd".into(), gate())]),
        &[],
        None,
        None,
        &names,
    )
    .unwrap();
    persist_groups(
        Some(&backend),
        &BTreeMap::from([("readd".into(), group_with_budget())]),
        None,
        None,
        &names,
    )
    .unwrap();
    let doc = backend.read_required().unwrap().unwrap();
    assert_eq!(doc.deleted, vec!["base"]);
    assert_eq!(doc.deleted_groups, vec!["base"]);
}

#[test]
fn corrupt_overlay_refuses_reads_and_all_mutations_without_clobbering() {
    let fixture = TestOverlayStore::new();
    fixture.seed_bytes(b"invalid JSON");
    let backend = fixture.backend();
    assert!(backend.read_required().is_err());
    assert!(persist_root(Some(&backend), &sample_root()).is_err());
    assert!(persist_groups(
        Some(&backend),
        &BTreeMap::new(),
        None,
        None,
        &HashSet::new()
    )
    .is_err());
    assert!(clear_section(Some(&backend), OverlaySection::Root).is_err());
    assert_eq!(fixture.read_bytes().unwrap(), b"invalid JSON");
}

#[test]
fn refused_write_never_exposes_uncommitted_generation_and_replays_original_before_new_edit() {
    let fixture = TestOverlayStore::new();
    let backend = fixture.backend();
    persist_root(Some(&backend), &sample_root()).unwrap();
    let before = fixture.read_bytes();
    fixture.fail_writes(true);
    assert!(persist_root(Some(&backend), &RootSettings::default()).is_err());
    assert_eq!(fixture.read_bytes(), before);
    fixture.fail_writes(false);
    // The previous immutable candidate is resolved, but this different edit is refused.
    assert!(persist_root(Some(&backend), &sample_root()).is_err());
    assert!(backend.read_required().unwrap().unwrap().root.is_none());
    assert!(persist_root(Some(&backend), &sample_root()).is_err());
    let (backend, _) = backend.reopen_for_reload().unwrap();
    persist_root(Some(&backend), &sample_root()).unwrap();
}

#[test]
fn unknown_commit_replays_exact_candidate_and_never_applies_the_new_request() {
    let fixture = TestOverlayStore::new();
    let backend = fixture.backend();
    fixture.lose_next_commit_reply();
    assert!(persist_root(Some(&backend), &sample_root()).is_err());
    assert!(persist_root(Some(&backend), &RootSettings::default()).is_err());
    let candidates = fixture.candidates();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0], candidates[1]);
    assert!(backend.read_required().unwrap().unwrap().root.is_some());
}

#[test]
fn overlays_larger_than_record_bound_round_trip_without_a_content_cap() {
    let fixture = TestOverlayStore::new();
    let backend = fixture.backend();
    let payload = "x".repeat(busbar_contract::MAX_RECORD_BYTES * 2 + 17);
    let mut doc = OverlayDoc::default();
    doc.named_maps.insert(
        "export".into(),
        BTreeMap::from([(
            "huge".into(),
            serde_json::json!({"module":"test", "settings":{"payload":payload}}),
        )]),
    );
    write(&backend, &doc).unwrap();
    assert_eq!(
        serde_json::to_value(backend.read_required().unwrap().unwrap()).unwrap(),
        serde_json::to_value(doc).unwrap()
    );
}

#[test]
fn required_store_read_failure_is_not_mistaken_for_absence() {
    let fixture = TestOverlayStore::new();
    let backend = fixture.backend();
    assert!(backend.read_required().unwrap().is_none());
    fixture.fail_reads(true);
    assert!(backend.read_required().is_err());
    assert!(persist_root(Some(&backend), &sample_root()).is_err());
}

#[test]
fn legacy_hook_spelling_is_migrated_from_store_bytes() {
    let fixture = TestOverlayStore::new();
    fixture
        .seed_bytes(br#"{"hooks":{"legacy":{"kind":"gate","plugin":"test-hook","at":"request"}}}"#);
    let doc = fixture.backend().read_required().unwrap().unwrap();
    assert_eq!(doc.hooks["legacy"].plugin, "test-hook");
}
