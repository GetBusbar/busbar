// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn gate() -> HookCfg {
    serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": "test-hook", "prompt": "rw", "global": true
    }))
    .unwrap()
}

use crate::test_support::TestOverlayStore;

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

#[test]
fn store_round_trip_preserves_every_sibling_and_resets_only_requested_section() {
    let backend = OverlayStore::new(crate::real_store::store()).unwrap();
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
    let backend = OverlayStore::new(crate::real_store::store()).unwrap();
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
fn refused_write_never_exposes_uncommitted_generation_and_replays_original_before_new_edit() {
    let fixture = TestOverlayStore::new();
    let backend = fixture.backend();
    persist_root(Some(&backend), &sample_root()).unwrap();
    let before = fixture.read_bytes();
    fixture.fail_writes(true);
    assert!(persist_root(Some(&backend), &RootSettings::default()).is_err());
    assert_eq!(fixture.read_bytes(), before);
    fixture.fail_writes(false);

    assert!(persist_root(Some(&backend), &sample_root()).is_err());
    assert!(backend.read_required().unwrap().unwrap().root.is_none());
    assert!(persist_root(Some(&backend), &sample_root()).is_err());
    let (backend, _) = backend.reopen_for_reload().unwrap();
    persist_root(Some(&backend), &sample_root()).unwrap();
}

#[test]
fn unknown_commit_replays_exact_candidate_and_never_applies_the_new_request() {
    use busbar_contract::abi::sdk::store::conditional::{Decision, Request};
    use busbar_contract::abi::store::OpId;
    use busbar_contract::kinds::RecordBytes;
    use busbar_contract::records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta};
    use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    struct LostCommitReply {
        inner: Arc<busbar_plugin_loader::store_v3::LoadedStore>,
        lose_reply: AtomicBool,
        candidates: Mutex<Vec<Request>>,
    }
    impl StoreCalls for LostCommitReply {
        fn supports_record_transaction(&self) -> bool {
            self.inner.supports_record_transaction()
        }
        fn record_transaction<'a>(&'a self, request: &'a Request) -> StoreCall<'a, Decision> {
            Box::pin(async move {
                self.candidates.lock().unwrap().push(request.clone());
                let decision = self.inner.record_transaction(request).await?;
                if self.lose_reply.swap(false, Ordering::SeqCst) {
                    Err(StoreFailure::Failed("planted lost commit reply".into()))
                } else {
                    Ok(decision)
                }
            })
        }
        fn add_usage_batch<'a>(
            &'a self,
            op: OpId,
            cells: &'a [(&'a str, u64, UsageDelta)],
        ) -> StoreCall<'a, ()> {
            self.inner.add_usage_batch(op, cells)
        }
        fn add_metering_batch<'a>(
            &'a self,
            op: OpId,
            deltas: &'a [MeteringDelta],
        ) -> StoreCall<'a, ()> {
            self.inner.add_metering_batch(op, deltas)
        }
        fn record_put<'a>(
            &'a self,
            schema: &'a str,
            key: &'a [u8],
            value: &'a RecordBytes,
        ) -> StoreCall<'a, ()> {
            self.inner.record_put(schema, key, value)
        }
        fn record_get<'a>(
            &'a self,
            schema: &'a str,
            key: &'a [u8],
        ) -> StoreCall<'a, Option<RecordBytes>> {
            self.inner.record_get(schema, key)
        }
        fn record_scan<'a>(
            &'a self,
            schema: &'a str,
            prefix: &'a [u8],
            limit: u32,
        ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
            self.inner.record_scan(schema, prefix, limit)
        }
        fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
            self.inner.upsert_plane_record(record)
        }
        fn get_plane_record<'a>(
            &'a self,
            kind: &'a str,
            id: &'a str,
        ) -> StoreCall<'a, Option<Vec<u8>>> {
            self.inner.get_plane_record(kind, id)
        }
        fn append_plane_record<'a>(
            &'a self,
            op: OpId,
            record: PlaneRecordRef<'a>,
        ) -> StoreCall<'a, ()> {
            self.inner.append_plane_record(op, record)
        }
        fn list_plane_records<'a>(
            &'a self,
            kind: &'a str,
            selector: &'a PlaneSelector<'a>,
        ) -> StoreCall<'a, Vec<Vec<u8>>> {
            self.inner.list_plane_records(kind, selector)
        }
        fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
            self.inner.delete_plane_record(kind, id)
        }
        fn redeem_plane_token<'a>(
            &'a self,
            kind: &'a str,
            token: &'a str,
            expires_at: u64,
            now: u64,
        ) -> StoreCall<'a, bool> {
            self.inner.redeem_plane_token(kind, token, expires_at, now)
        }
        fn plane_token_live<'a>(
            &'a self,
            kind: &'a str,
            token: &'a str,
            expires_at: u64,
            now: u64,
        ) -> StoreCall<'a, bool> {
            self.inner.plane_token_live(kind, token, expires_at, now)
        }
    }
    let calls = Arc::new(LostCommitReply {
        inner: crate::real_store::store(),
        lose_reply: AtomicBool::new(true),
        candidates: Mutex::new(Vec::new()),
    });
    let backend = OverlayStore::new(calls.clone()).unwrap();
    assert!(persist_root(Some(&backend), &sample_root()).is_err());
    assert!(persist_root(Some(&backend), &RootSettings::default()).is_err());
    let candidates = calls.candidates.lock().unwrap().clone();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0], candidates[1]);
    assert!(backend.read_required().unwrap().unwrap().root.is_some());
}

#[test]
fn overlays_larger_than_record_bound_round_trip_without_a_content_cap() {
    let backend = OverlayStore::new(crate::real_store::store()).unwrap();
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
    use busbar_contract::abi::sdk::store::conditional::{Decision, Request};
    use busbar_contract::abi::store::OpId;
    use busbar_contract::kinds::RecordBytes;
    use busbar_contract::records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta};
    use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct FailReads {
        inner: Arc<busbar_plugin_loader::store_v3::LoadedStore>,
        fail: AtomicBool,
    }
    impl StoreCalls for FailReads {
        fn supports_record_transaction(&self) -> bool {
            self.inner.supports_record_transaction()
        }
        fn record_transaction<'a>(&'a self, request: &'a Request) -> StoreCall<'a, Decision> {
            self.inner.record_transaction(request)
        }
        fn record_get<'a>(
            &'a self,
            schema: &'a str,
            key: &'a [u8],
        ) -> StoreCall<'a, Option<RecordBytes>> {
            if self.fail.load(Ordering::SeqCst) {
                Box::pin(std::future::ready(Err(StoreFailure::Failed(
                    "planted read failure".into(),
                ))))
            } else {
                self.inner.record_get(schema, key)
            }
        }
        fn add_usage_batch<'a>(
            &'a self,
            op: OpId,
            cells: &'a [(&'a str, u64, UsageDelta)],
        ) -> StoreCall<'a, ()> {
            self.inner.add_usage_batch(op, cells)
        }
        fn add_metering_batch<'a>(
            &'a self,
            op: OpId,
            deltas: &'a [MeteringDelta],
        ) -> StoreCall<'a, ()> {
            self.inner.add_metering_batch(op, deltas)
        }
        fn record_put<'a>(
            &'a self,
            schema: &'a str,
            key: &'a [u8],
            value: &'a RecordBytes,
        ) -> StoreCall<'a, ()> {
            self.inner.record_put(schema, key, value)
        }
        fn record_scan<'a>(
            &'a self,
            schema: &'a str,
            prefix: &'a [u8],
            limit: u32,
        ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
            self.inner.record_scan(schema, prefix, limit)
        }
        fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
            self.inner.upsert_plane_record(record)
        }
        fn get_plane_record<'a>(
            &'a self,
            kind: &'a str,
            id: &'a str,
        ) -> StoreCall<'a, Option<Vec<u8>>> {
            self.inner.get_plane_record(kind, id)
        }
        fn append_plane_record<'a>(
            &'a self,
            op: OpId,
            record: PlaneRecordRef<'a>,
        ) -> StoreCall<'a, ()> {
            self.inner.append_plane_record(op, record)
        }
        fn list_plane_records<'a>(
            &'a self,
            kind: &'a str,
            selector: &'a PlaneSelector<'a>,
        ) -> StoreCall<'a, Vec<Vec<u8>>> {
            self.inner.list_plane_records(kind, selector)
        }
        fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
            self.inner.delete_plane_record(kind, id)
        }
        fn redeem_plane_token<'a>(
            &'a self,
            kind: &'a str,
            token: &'a str,
            expires_at: u64,
            now: u64,
        ) -> StoreCall<'a, bool> {
            self.inner.redeem_plane_token(kind, token, expires_at, now)
        }
        fn plane_token_live<'a>(
            &'a self,
            kind: &'a str,
            token: &'a str,
            expires_at: u64,
            now: u64,
        ) -> StoreCall<'a, bool> {
            self.inner.plane_token_live(kind, token, expires_at, now)
        }
    }
    let calls = Arc::new(FailReads {
        inner: crate::real_store::store(),
        fail: AtomicBool::new(false),
    });
    let backend = OverlayStore::new(calls.clone()).unwrap();
    assert!(backend.read_required().unwrap().is_none());
    calls.fail.store(true, Ordering::SeqCst);
    assert!(backend.read_required().is_err());
    assert!(persist_root(Some(&backend), &sample_root()).is_err());
}
