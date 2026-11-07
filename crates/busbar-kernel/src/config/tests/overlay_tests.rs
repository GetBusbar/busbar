// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::overlay_store::tests::{fixture, LOSE, REFUSE};
use std::sync::atomic::Ordering;

fn gate() -> HookCfg {
    serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": "test-hook", "prompt": "rw", "global": true
    }))
    .unwrap()
}

fn minimal_cfg() -> RootCfg {
    let deploy: super::super::DeployCfg =
        serde_json::from_value(serde_json::json!({"providers": {}, "models": {}})).unwrap();
    super::super::resolve(&deploy, &HashMap::new()).expect("minimal config resolves")
}

#[test]
fn merge_into_deploy() {
    let mut cfg = minimal_cfg();
    let mut base = gate();
    base.plugin = "base-module".to_string();
    cfg.hooks.insert("base_hook".to_string(), base);
    let doc = from_state(
        &HashMap::from([
            ("base_hook".to_string(), gate()),
            ("api_hook".to_string(), gate()),
        ]),
        &["api_hook".to_string(), "base_hook".to_string()],
    );
    cfg.global_hooks.push("base_hook".to_string());
    merge_into(&mut cfg, doc);
    assert!(cfg.hooks.contains_key("api_hook"));
    assert!(cfg.hooks.contains_key("base_hook"));
    assert_eq!(cfg.hooks["base_hook"].plugin, "test-hook", "overlay wins");

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

fn group_with_budget() -> GroupCfg {
    serde_json::from_value(serde_json::json!({
        "limits": [ { "budget": 1000, "per": "month" } ]
    }))
    .unwrap()
}

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

    doc.clear_section(OverlaySection::Hooks);
    assert!(doc.hooks.is_empty() && doc.global_hooks.is_empty() && doc.deleted.is_empty());
}

#[test]
fn section_is_empty_tracks_entries_and_tombstones() {
    let empty = OverlayDoc::default();
    assert!(empty.section_is_empty(OverlaySection::Groups));
    assert!(empty.section_is_empty(OverlaySection::Hooks));

    let tombstoned = OverlayDoc {
        deleted_groups: vec!["x".to_string()],
        deleted: vec!["y".to_string()],
        ..Default::default()
    };
    assert!(!tombstoned.section_is_empty(OverlaySection::Groups));
    assert!(!tombstoned.section_is_empty(OverlaySection::Hooks));
}

fn minimal_deploy() -> DeployCfg {
    serde_yaml::from_str("providers: {}\nmodels: {}\n").expect("minimal deploy parses")
}

fn sample_root() -> RootSettings {
    serde_json::from_value(serde_json::json!({
        "listen": "0.0.0.0:9000",
        "per_request_fee": 7,
        "rate_card": { "m0": { "input_utok": 1.5, "output_utok": 2.0 } },
        "limits": { "max_inbound_concurrent": 512 }
    }))
    .expect("root settings parse")
}

#[test]
fn root_apply_overwrites_only_named_fields() {
    let mut deploy = minimal_deploy();
    let base_admin_listen = deploy.admin_listen.clone();

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

#[test]
fn root_is_empty_tracks_overrides() {
    assert!(RootSettings::default().is_empty());
    assert!(OverlayDoc::default().section_is_empty(OverlaySection::Root));
    let doc = OverlayDoc {
        root: Some(sample_root()),
        ..Default::default()
    };
    assert!(!doc.section_is_empty(OverlaySection::Root));

    assert!(doc.section_is_empty(OverlaySection::Hooks));
    assert!(doc.section_is_empty(OverlaySection::Groups));
}

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

#[test]
fn root_settings_rejects_unknown_field() {
    let r: Result<RootSettings, _> =
        serde_json::from_value(serde_json::json!({ "lissten": "0.0.0.0:9000" }));
    assert!(r.is_err(), "a typo'd root field is rejected");
}

#[test]
fn plugin_versions_pins_lower_the_floors() {
    let mut deploy = minimal_deploy();

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

#[test]
fn no_pins_leaves_first_party_floor_none() {
    let mut deploy = minimal_deploy();
    apply_root_to_deploy(&mut deploy, &OverlayDoc::default());
    assert!(
        deploy.plugins.first_party_floors.is_empty(),
        "with no pins the automatic first-party floor stands"
    );
}

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

#[test]
fn plugin_versions_section_parses() {
    assert_eq!(
        OverlaySection::parse("plugin_versions"),
        Some(OverlaySection::PluginVersions)
    );
    assert_eq!(OverlaySection::PluginVersions.as_str(), "plugin_versions");
}

#[tokio::test]
async fn store_round_trip_preserves_every_sibling_and_resets_only_requested_section() {
    let backend = OverlayStore::from_core(crate::real_store::core().await).unwrap();
    persist_async(
        Some(&backend),
        &HashMap::from([("h".into(), gate())]),
        &["h".into()],
        None,
        None,
        &HashSet::new(),
    )
    .await
    .unwrap();
    persist_groups_async(
        Some(&backend),
        &BTreeMap::from([("g".into(), group_with_budget())]),
        None,
        None,
        &HashSet::new(),
    )
    .await
    .unwrap();
    persist_root_async(Some(&backend), &sample_root())
        .await
        .unwrap();
    try_persist_plugin_versions_async(
        Some(&backend),
        &BTreeMap::from([("p".into(), "1.0.0".into())]),
    )
    .await
    .unwrap();
    let section = crate::config::named_map::NamedMapSection::Export;
    persist_named_map_async(
        Some(&backend),
        section,
        "named",
        Some(&serde_json::json!({"module":"test"})),
    )
    .await
    .unwrap();
    let doc = backend.read_required_async().await.unwrap().unwrap();
    assert!(doc.hooks.contains_key("h"));
    assert!(doc.groups.contains_key("g"));
    assert!(doc.root.is_some());
    assert_eq!(doc.plugin_versions["p"], "1.0.0");
    assert!(doc.named_maps["export"].contains_key("named"));
    clear_section_async(Some(&backend), OverlaySection::Hooks)
        .await
        .unwrap();
    let doc = backend.read_required_async().await.unwrap().unwrap();
    assert!(doc.hooks.is_empty());
    assert!(doc.groups.contains_key("g"));
    assert!(doc.root.is_some());
    assert_eq!(doc.plugin_versions["p"], "1.0.0");
    assert!(doc.named_maps["export"].contains_key("named"));
}

#[tokio::test]
async fn hook_and_group_tombstones_reconcile_readds_and_prune_nonbase_names() {
    let backend = OverlayStore::from_core(crate::real_store::core().await).unwrap();
    write_async(
        &backend,
        &OverlayDoc {
            deleted: vec!["base".into(), "readd".into(), "inert".into()],
            deleted_groups: vec!["base".into(), "readd".into(), "inert".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let names = HashSet::from(["base".into(), "readd".into()]);
    persist_async(
        Some(&backend),
        &HashMap::from([("readd".into(), gate())]),
        &[],
        None,
        None,
        &names,
    )
    .await
    .unwrap();
    persist_groups_async(
        Some(&backend),
        &BTreeMap::from([("readd".into(), group_with_budget())]),
        None,
        None,
        &names,
    )
    .await
    .unwrap();
    let doc = backend.read_required_async().await.unwrap().unwrap();
    assert_eq!(doc.deleted, vec!["base"]);
    assert_eq!(doc.deleted_groups, vec!["base"]);
}

#[tokio::test]
async fn refused_write_never_exposes_uncommitted_generation_and_replays_original_before_new_edit() {
    let (calls, _, backend) = fixture().await;
    persist_root_async(Some(&backend), &sample_root())
        .await
        .unwrap();
    let before = backend.read_bytes_async().await.unwrap();
    calls.publication.store(REFUSE, Ordering::SeqCst);
    assert!(persist_root_async(Some(&backend), &RootSettings::default())
        .await
        .is_err());
    assert_eq!(backend.read_bytes_async().await.unwrap(), before);
    calls.publication.store(0, Ordering::SeqCst);
    assert!(persist_root_async(Some(&backend), &sample_root())
        .await
        .is_err());
    assert!(backend
        .read_required_async()
        .await
        .unwrap()
        .unwrap()
        .root
        .is_none());
    assert!(persist_root_async(Some(&backend), &sample_root())
        .await
        .is_err());
    let (backend, _) = backend.reopen_for_reload_async().await.unwrap();
    persist_root_async(Some(&backend), &sample_root())
        .await
        .unwrap();
}

#[tokio::test]
async fn unknown_commit_replays_exact_candidate_and_never_applies_the_new_request() {
    let (calls, _, backend) = fixture().await;
    calls.publication.store(LOSE, Ordering::SeqCst);
    assert!(persist_root_async(Some(&backend), &sample_root())
        .await
        .is_err());
    assert!(persist_root_async(Some(&backend), &RootSettings::default())
        .await
        .is_err());
    let candidates = calls.sent.lock().unwrap().clone();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0], candidates[1]);
    assert!(backend
        .read_required_async()
        .await
        .unwrap()
        .unwrap()
        .root
        .is_some());
}

#[tokio::test]
async fn overlays_larger_than_record_bound_round_trip_without_a_content_cap() {
    let backend = OverlayStore::from_core(crate::real_store::core().await).unwrap();
    let payload = "x".repeat(busbar_contract::MAX_RECORD_BYTES * 2 + 17);
    let mut doc = OverlayDoc::default();
    doc.named_maps.insert(
        "export".into(),
        BTreeMap::from([(
            "huge".into(),
            serde_json::json!({"module":"test", "settings":{"payload":payload}}),
        )]),
    );
    write_async(&backend, &doc).await.unwrap();
    assert_eq!(
        serde_json::to_value(backend.read_required_async().await.unwrap().unwrap()).unwrap(),
        serde_json::to_value(OverlayDoc {
            version: OVERLAY_VERSION,
            ..doc
        })
        .unwrap()
    );
}

#[tokio::test]
async fn required_store_read_failure_is_not_mistaken_for_absence() {
    let (calls, _, backend) = fixture().await;
    assert!(backend.read_required_async().await.unwrap().is_none());
    calls.fail_reads.store(true, Ordering::SeqCst);
    assert!(backend.read_required_async().await.is_err());
    assert!(persist_root_async(Some(&backend), &sample_root())
        .await
        .is_err());
}
