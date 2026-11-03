// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use crate::test_common as common;
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta};
use busbar_contract::store_calls::StoreCall;

// Passive observation of the actual opened Store. Every method forwards its exact arguments
// and returned future unchanged. Only pointer-free counts of overlay write/transaction attempts
// are retained; this neither implements Store behavior nor intercepts acknowledgements.
struct ObservedStoreCalls {
    calls: Arc<dyn busbar_contract::store_calls::StoreCalls>,
    record_writes: std::sync::atomic::AtomicUsize,
    transactions: std::sync::atomic::AtomicUsize,
}

impl busbar_contract::store_calls::StoreCalls for ObservedStoreCalls {
    fn supports_usage_correction(&self) -> bool {
        self.calls.supports_usage_correction()
    }

    fn apply_usage_correction<'a>(
        &'a self,
        request: &'a busbar_contract::records::correction::Request,
    ) -> StoreCall<'a, busbar_contract::records::correction::Decision> {
        self.calls.apply_usage_correction(request)
    }

    fn supports_record_transaction(&self) -> bool {
        self.calls.supports_record_transaction()
    }

    fn record_transaction<'a>(
        &'a self,
        request: &'a busbar_contract::abi::sdk::store::conditional::Request,
    ) -> StoreCall<'a, busbar_contract::abi::sdk::store::conditional::Decision> {
        self.transactions
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.calls.record_transaction(request)
    }

    fn add_usage_batch<'a>(
        &'a self,
        op: OpId,
        cells: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        self.calls.add_usage_batch(op, cells)
    }

    fn add_metering_batch<'a>(
        &'a self,
        op: OpId,
        deltas: &'a [MeteringDelta],
    ) -> StoreCall<'a, ()> {
        self.calls.add_metering_batch(op, deltas)
    }

    fn record_put<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
        value: &'a RecordBytes,
    ) -> StoreCall<'a, ()> {
        self.record_writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.calls.record_put(schema, key, value)
    }

    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        self.calls.record_get(schema, key)
    }

    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        self.calls.record_scan(schema, prefix, limit)
    }

    fn put_key<'a>(&'a self, key: &'a busbar_contract::records::VirtualKey) -> StoreCall<'a, ()> {
        self.calls.put_key(key)
    }

    fn get_key<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreCall<'a, Option<busbar_contract::records::VirtualKey>> {
        self.calls.get_key(id)
    }

    fn list_keys(&self) -> StoreCall<'_, Vec<busbar_contract::records::VirtualKey>> {
        self.calls.list_keys()
    }

    fn delete_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, ()> {
        self.calls.delete_key(id)
    }

    fn put_key_with_credential<'a>(
        &'a self,
        key: &'a busbar_contract::records::VirtualKey,
        secret: &'a busbar_contract::records::CredentialSecret,
    ) -> StoreCall<'a, ()> {
        self.calls.put_key_with_credential(key, secret)
    }

    fn list_credentials<'a>(
        &'a self,
        key_id: &'a str,
    ) -> StoreCall<'a, Vec<busbar_contract::records::CredentialMeta>> {
        self.calls.list_credentials(key_id)
    }

    fn revoke_credential<'a>(&'a self, id: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        self.calls.revoke_credential(id, reason)
    }

    fn list_credentials_since(
        &self,
        since: u64,
    ) -> StoreCall<'_, Vec<busbar_contract::records::CredentialSecret>> {
        self.calls.list_credentials_since(since)
    }

    fn add_denylist<'a>(&'a self, sub: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        self.calls.add_denylist(sub, reason)
    }

    fn list_denylist(&self) -> StoreCall<'_, Vec<String>> {
        self.calls.list_denylist()
    }

    fn list_metering(
        &self,
        bucket: u64,
    ) -> StoreCall<'_, Vec<busbar_contract::records::MeteringRow>> {
        self.calls.list_metering(bucket)
    }

    fn list_audit(&self) -> StoreCall<'_, Vec<busbar_contract::records::AuditRecord>> {
        self.calls.list_audit()
    }

    fn list_audit_tail(
        &self,
        limit: u64,
    ) -> StoreCall<'_, Vec<busbar_contract::records::AuditRecord>> {
        self.calls.list_audit_tail(limit)
    }

    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        self.calls.upsert_plane_record(record)
    }

    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> StoreCall<'a, Option<Vec<u8>>> {
        self.calls.get_plane_record(kind, id)
    }

    fn append_plane_record<'a>(
        &'a self,
        op: OpId,
        record: PlaneRecordRef<'a>,
    ) -> StoreCall<'a, ()> {
        self.calls.append_plane_record(op, record)
    }

    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        self.calls.list_plane_records(kind, selector)
    }

    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
        self.calls.delete_plane_record(kind, id)
    }

    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.calls.redeem_plane_token(kind, token, expires_at, now)
    }

    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.calls.plane_token_live(kind, token, expires_at, now)
    }

    fn list_plane_record_parents<'a>(&'a self, kind: &'a str) -> StoreCall<'a, Vec<String>> {
        self.calls.list_plane_record_parents(kind)
    }

    fn purge_plane_records_before<'a>(&'a self, kind: &'a str, before: u64) -> StoreCall<'a, u64> {
        self.calls.purge_plane_records_before(kind, before)
    }

    fn purge_usage_before(&self, before: u64) -> StoreCall<'_, u64> {
        self.calls.purge_usage_before(before)
    }
}

#[tokio::test]
async fn exchange_provisions_user_leaf_from_child_default_and_key_is_usable() {
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("auth-self-group-provision");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "corp", true);
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            "corp": { "module": oidc_module, "settings": common::credentials::settings("api://auth-self-groups") }
        },
        "auth": {
            "chain": ["corp"], "admin_auth": [], "signing_key": { "file": signing },
            "key_ttl": "1h",
            "role_bindings": { "corp": { "eng": { "group": "team" } } }
        },
        "groups": { "team": { "child_default": { "limits": [{ "budget": 500, "per": "month" }] } } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store bootstraps its config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional config records");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay.clone()),
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let gov = app
        .governance
        .as_ref()
        .expect("the actual Store supplies governance")
        .clone();
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
    // Principal DATA enters the real public post-identity mint API. This case exercises actual
    // group transactions and Store persistence, not authentication of an external credential.
    let mut principal = busbar_kernel::auth::Principal::from_id("sam");
    principal.roles = vec!["eng".to_string()];
    let before = handle.load();
    let first = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        busbar_kernel::auth::login::issue_self_key(
            &before,
            &handle,
            "corp",
            principal.clone(),
            false,
        ),
    )
    .await
    .expect("the actual first mint completes within ten seconds");
    let (group, secret) = match first {
        busbar_kernel::auth::login::SelfKeyIssue::Issued { group, secret, .. } => (group, secret),
        _ => panic!("the actual first exchange issues a key"),
    };
    assert_eq!(group, "user:sam");
    let current = handle.load();
    let registry = &current.groups_registry;
    let leaf = registry
        .get("user:sam")
        .expect("the actual transaction published the user leaf");
    assert_eq!(
        leaf.parent.as_deref(),
        Some("team"),
        "leaf parented under the team"
    );
    assert_eq!(
        leaf.limits,
        registry["team"].child_default.as_ref().unwrap().limits,
        "leaf limits stamped from the team's child_default"
    );
    assert!(
        !leaf.limits.is_empty(),
        "child_default limits actually copied onto the leaf"
    );
    assert!(current.cost.group_named("user:sam").is_some());
    let key = gov
        .verify_token(
            secret.expose(&busbar_kernel::seal::lend()),
            busbar_kernel::store::now(),
            None,
        )
        .expect("the minted real key verifies");
    let binding = gov
        .lookup_by_sub(&key.id)
        .expect("the actual Store holds the minted binding");
    assert!(
        gov.try_admit(
            &current.cost,
            &binding,
            "unused-pool",
            busbar_kernel::store::now()
        )
        .is_ok(),
        "the actual key is admitted through its published enforcement chain (not MissingGroup)"
    );
    let persisted = overlay
        .read_required()
        .expect("read the actual Store overlay")
        .expect("group provisioning persisted a real overlay generation");
    assert_eq!(persisted.groups.get("user:sam"), Some(leaf));
    let second = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        busbar_kernel::auth::login::issue_self_key(&current, &handle, "corp", principal, false),
    )
    .await
    .expect("the actual second mint completes within ten seconds");
    let second_secret = match second {
        busbar_kernel::auth::login::SelfKeyIssue::Issued { secret, .. } => secret,
        _ => panic!("the actual second exchange reuses the key"),
    };
    let second_key = gov
        .verify_token(
            second_secret.expose(&busbar_kernel::seal::lend()),
            busbar_kernel::store::now(),
            None,
        )
        .expect("the reissued real key verifies");
    assert_eq!(second_key.id, key.id, "same deterministic key row");
    assert_eq!(
        handle.load().groups_registry.len(),
        2,
        "team + exactly one user leaf (no duplicate)"
    );
    let self_rows = gov
        .all_keys()
        .unwrap()
        .into_iter()
        .filter(|key| {
            key.enabled && key.deleted_at.is_none() && key.group.as_deref() == Some("user:sam")
        })
        .count();
    assert_eq!(self_rows, 1, "exactly one key binding");
}

#[tokio::test]
async fn existing_self_leaf_refuses_a_changed_team_before_issue_or_refresh() {
    for refresh in [false, true] {
        crate::dist_root_install::install();
        let library_path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
                .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
        );
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual store statement reads")
            .expect("the actual store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual store statement is valid")
            .name;
        let mut manifest = plugins::manifest(
            "store",
            &module,
            busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let directory = plugins::scratch("auth-self-group-refuse-rehome");
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual store archive");
        let settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
        assert!(
            settings.is_object(),
            "the actual store settings are an object"
        );
        let oidc_path = common::plugins::token_verifier_cdylib_path()
            .expect("the freshly built actual OIDC product is required");
        let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
            .expect("the actual OIDC statement reads")
            .expect("the actual OIDC product exports its statement");
        let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
            .expect("the actual OIDC statement is valid")
            .name;
        common::credentials::install_auth_plugin(&directory, &oidc_module, "corp", true);
        let signing = directory.join("signing-key");
        std::fs::write(&signing, hex::encode([9u8; 32]))
            .expect("write the actual configured signing key");
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {},
            "models": {},
            "identity-providers": {
                "corp": { "module": oidc_module, "settings": common::credentials::settings("api://auth-self-groups") }
            },
            "auth": {
                "chain": ["corp"], "admin_auth": [], "signing_key": { "file": signing },
                "key_ttl": "1h",
                "role_bindings": { "corp": { "eng": { "group": "team-b" } } }
            },
            "groups": {
                "team-a": { "child_default": { "limits": [{ "budget": 500, "per": "month" }] } },
                "team-b": {},
                "user:sam": { "parent": "team-a", "limits": [{ "budget": 37, "per": "month" }] }
            },
            "store": { "module": module, "settings": settings },
            "advanced": { "allow_destinations": ["127.0.0.1"] },
        }))
        .expect("the product deployment parses");
        let config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the product deployment resolves");
        let plugin_config = busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
            .expect("the actual Store bootstraps its config authority");
        let overlay = busbar_kernel::config::overlay::OverlayStore::new(
            anchor
                .calls
                .as_ref()
                .cloned()
                .expect("the actual Store exposes typed calls"),
        )
        .expect("the actual Store supports conditional config records");
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            config,
            plugin_config,
            Some(overlay.clone()),
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(anchor),
            true,
        )
        .expect("the actual product builds the session deployment");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, &module).expect(
            "the actual Store binds rate-card history and usage recovery before activation",
        );
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        let app = Arc::new(app);
        let gov = app
            .governance
            .as_ref()
            .expect("the real Store supplies governance")
            .clone();
        let handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
        let before = handle.load();
        let overlay_before = overlay
            .read_bytes()
            .expect("read the actual overlay before refusal");
        // Existing valid credential DATA is minted through the actual governance API. The group
        // is already present under team-a, matching the original setup's successful issue.
        let old = if refresh {
            let now = busbar_kernel::store::now();
            Some(
                gov.issue_self("sam", "corp", None, now.saturating_add(3600), now)
                    .expect("the original team credential can be issued")
                    .1,
            )
        } else {
            None
        };
        let mut principal = busbar_kernel::auth::Principal::from_id("sam");
        principal.roles = vec!["eng".to_string()];
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            busbar_kernel::auth::login::issue_self_key(
                &before, &handle, "corp", principal, refresh,
            ),
        )
        .await
        .expect("the actual re-home refusal completes within ten seconds");
        assert!(matches!(
            result,
            busbar_kernel::auth::login::SelfKeyIssue::Failed
        ));
        assert!(
            Arc::ptr_eq(&before, &handle.load()),
            "refusal must not swap the group tree"
        );
        assert_eq!(
            overlay
                .read_bytes()
                .expect("read the actual overlay after refusal"),
            overlay_before,
            "refusal must not persist a changed group"
        );
        if let Some(old) = old {
            assert!(
                gov.verify_token(&old, busbar_kernel::store::now(), None)
                    .is_some(),
                "refused refresh must not invalidate the existing token"
            );
        } else {
            assert!(
                gov.all_keys()
                    .unwrap()
                    .into_iter()
                    .filter(|key| key.enabled
                        && key.deleted_at.is_none()
                        && key.group.as_deref() == Some("user:sam"))
                    .count()
                    == 0,
                "refused issue must not mint a binding"
            );
        }
    }
}

#[tokio::test]
async fn existing_self_leaf_with_matching_team_reuses_the_snapshot_without_persistence() {
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("auth-self-group-reuse");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "corp", true);
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            "corp": { "module": oidc_module, "settings": common::credentials::settings("api://auth-self-groups") }
        },
        "auth": {
            "chain": ["corp"], "admin_auth": [], "signing_key": { "file": signing },
            "key_ttl": "1h",
            "role_bindings": { "corp": { "eng": { "group": "team-a" } } }
        },
        "groups": {
            "team-a": { "child_default": { "limits": [{ "budget": 500, "per": "month" }] } },
            "team-b": {},
            "user:sam": { "parent": "team-a", "limits": [{ "budget": 37, "per": "month" }] }
        },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store bootstraps its config authority");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let gov = app
        .governance
        .as_ref()
        .expect("the actual Store supplies governance")
        .clone();
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
    let before = handle.load();
    assert!(
        before.overlay_path.is_none(),
        "precondition: no writable overlay is supplied"
    );
    let mut principal = busbar_kernel::auth::Principal::from_id("sam");
    principal.roles = vec!["eng".to_string()];
    for refresh in [false, false, true] {
        let issued = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            busbar_kernel::auth::login::issue_self_key(
                &before,
                &handle,
                "corp",
                principal.clone(),
                refresh,
            ),
        )
        .await
        .expect("the actual reuse completes within ten seconds");
        let (group, secret) = match issued {
            busbar_kernel::auth::login::SelfKeyIssue::Issued { group, secret, .. } => {
                (group, secret)
            }
            _ => panic!("an existing matching leaf needs no writable overlay"),
        };
        assert_eq!(group, "user:sam");
        assert!(
            Arc::ptr_eq(&before, &handle.load()),
            "re-login must preserve the snapshot and customized limits"
        );
        assert!(gov
            .verify_token(
                secret.expose(&busbar_kernel::seal::lend()),
                busbar_kernel::store::now(),
                None
            )
            .is_some());
    }
    assert_eq!(
        gov.all_keys()
            .unwrap()
            .into_iter()
            .filter(|key| key.enabled
                && key.deleted_at.is_none()
                && key.group.as_deref() == Some("user:sam"))
            .count(),
        1
    );
}

#[tokio::test]
async fn proof_self_mint_disabled_refuses_self_serve() {
    for self_mint in [Some(true), Some(false), None] {
        crate::dist_root_install::install();
        let library_path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
                .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
        );
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual store statement reads")
            .expect("the actual store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual store statement is valid")
            .name;
        let mut manifest = plugins::manifest(
            "store",
            &module,
            busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let directory = plugins::scratch("auth-self-mint-policy");
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual store archive");
        let settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
        assert!(
            settings.is_object(),
            "the actual store settings are an object"
        );
        let oidc_path = common::plugins::token_verifier_cdylib_path()
            .expect("the freshly built actual OIDC product is required");
        let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
            .expect("the actual OIDC statement reads")
            .expect("the actual OIDC product exports its statement");
        let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
            .expect("the actual OIDC statement is valid")
            .name;
        common::credentials::install_auth_plugin(&directory, &oidc_module, "corp", true);
        let signing = directory.join("signing-key");
        std::fs::write(&signing, hex::encode([9u8; 32]))
            .expect("write the actual configured signing key");
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {},
            "models": {},
            "identity-providers": {
                "corp": { "module": oidc_module, "settings": common::credentials::settings("api://auth-self-groups") }
            },
            "auth": {
                "chain": ["corp"], "admin_auth": [], "signing_key": { "file": signing },
                "key_ttl": "1h", "policy": { "self_mint": self_mint },
                "role_bindings": { "corp": { "eng": { "group": "team" } } }
            },
            "groups": { "team": { "child_default": { "limits": [{ "budget": 500, "per": "month" }] } } },
            "store": { "module": module, "settings": settings },
            "advanced": { "allow_destinations": ["127.0.0.1"] },
        }))
        .expect("the product deployment parses");
        let config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the product deployment resolves");
        let plugin_config = busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let mut anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
            .expect("the actual Store bootstraps its config authority");
        let observed = Arc::new(ObservedStoreCalls {
            calls: anchor
                .calls
                .as_ref()
                .cloned()
                .expect("the actual Store exposes typed calls"),
            record_writes: std::sync::atomic::AtomicUsize::new(0),
            transactions: std::sync::atomic::AtomicUsize::new(0),
        });
        anchor.calls = Some(observed.clone());
        let overlay = busbar_kernel::config::overlay::OverlayStore::new(
            anchor
                .calls
                .as_ref()
                .cloned()
                .expect("the actual Store exposes typed calls"),
        )
        .expect("the actual Store supports conditional config records");
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            config,
            plugin_config,
            Some(overlay.clone()),
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(anchor),
            true,
        )
        .expect("the actual product builds the session deployment");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, &module).expect(
            "the actual Store binds rate-card history and usage recovery before activation",
        );
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        let app = Arc::new(app);
        let gov = app
            .governance
            .as_ref()
            .expect("the actual Store supplies governance")
            .clone();
        let overlay_before = overlay
            .read_bytes()
            .expect("the actual overlay reads before exchange");
        let writes_before = observed
            .record_writes
            .load(std::sync::atomic::Ordering::SeqCst);
        let transactions_before = observed
            .transactions
            .load(std::sync::atomic::Ordering::SeqCst);
        let token = common::credentials::token_for("subject", &["eng"], "api://auth-self-groups");
        let router = busbar_kernel::build_router(app);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/auth/token")
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tower::ServiceExt::oneshot(router, request),
        )
        .await
        .expect("the real OIDC exchange completes within ten seconds")
        .unwrap();
        let status = response.status();
        let body = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            axum::body::to_bytes(response.into_body(), 64 * 1024),
        )
        .await
        .expect("the actual exchange body completes within ten seconds")
        .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if self_mint == Some(false) {
            assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
            assert!(body.get("api_key").is_none(), "no credential is issued");
            assert!(
                gov.all_keys().unwrap().is_empty(),
                "the refused exchange must not write any key to its attached store"
            );
            assert_eq!(
                overlay.read_bytes().unwrap(),
                overlay_before,
                "no overlay publication"
            );
            assert_eq!(
                observed
                    .record_writes
                    .load(std::sync::atomic::Ordering::SeqCst),
                writes_before,
                "no overlay record staging was attempted"
            );
            assert_eq!(
                observed
                    .transactions
                    .load(std::sync::atomic::Ordering::SeqCst),
                transactions_before,
                "no overlay conditional candidate was submitted"
            );
        } else {
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            let token = body["api_key"].as_str().expect("issued token");
            let key = gov
                .verify_token(token, busbar_kernel::store::now(), None)
                .expect("the exchange returns a usable signed key");
            assert_eq!(body["key_id"].as_str(), Some(key.id.as_str()));
            assert_eq!(key.group.as_deref(), Some("user:oidc:subject"));
            assert_eq!(
                gov.all_keys()
                    .unwrap()
                    .into_iter()
                    .filter(|key| key.enabled
                        && key.deleted_at.is_none()
                        && key.group.as_deref() == Some("user:oidc:subject"))
                    .count(),
                1
            );
            assert_eq!(gov.all_keys().unwrap().len(), 1);
            assert!(
                observed
                    .record_writes
                    .load(std::sync::atomic::Ordering::SeqCst)
                    > writes_before,
                "positive control: the actual allowed exchange stages its group record"
            );
            assert!(
                observed
                    .transactions
                    .load(std::sync::atomic::Ordering::SeqCst)
                    > transactions_before,
                "positive control: the actual allowed exchange submits its conditional candidate"
            );
        }
    }
}

#[tokio::test]
async fn self_mint_mode_policy_gates_exchange_login_and_refresh_before_mutation() {
    let user = busbar_kernel::governance::SELF_KEY_BINDING_MODE;
    let app = busbar_kernel::governance::SELF_KEY_BINDING_MODE_APP;
    for route in ["exchange", "login", "refresh"] {
        for (block, role, allowed) in [
            (None, None, true),
            (Some(vec![user]), None, true),
            (Some(vec![app]), None, false),
            (Some(vec![]), None, false),
            (None, Some(vec![app]), false),
        ] {
            let mut policy = serde_json::Map::new();
            if let Some(block) = block {
                policy.insert("binding_modes".into(), serde_json::json!(block));
            }
            if let Some(role) = role {
                policy.insert(
                    "mint_ceilings".into(),
                    serde_json::json!({ "eng": { "binding_modes": role } }),
                );
            }
            crate::dist_root_install::install();
            let library_path = std::path::PathBuf::from(
                std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
                    .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
            );
            let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
                .expect("the actual store statement reads")
                .expect("the actual store exports its statement");
            let module = busbar_contract::abi::mechanism::rendering::read(&statement)
                .expect("the actual store statement is valid")
                .name;
            let mut manifest = plugins::manifest(
                "store",
                &module,
                busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
            );
            manifest.statement = Some(hex::encode(statement));
            let library = std::fs::read(library_path).expect("the actual store library reads");
            let directory = plugins::scratch("auth-self-mint-mode-policy");
            let archive =
                plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
            std::fs::write(directory.join("store.tar.gz"), archive)
                .expect("stage the actual store archive");
            let settings: serde_json::Value = serde_json::from_str(
                &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS")
                    .unwrap_or_else(|_| "{}".into()),
            )
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
            assert!(
                settings.is_object(),
                "the actual store settings are an object"
            );
            let oidc_path = common::plugins::token_verifier_cdylib_path()
                .expect("the freshly built actual OIDC product is required");
            let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
                .expect("the actual OIDC statement reads")
                .expect("the actual OIDC product exports its statement");
            let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
                .expect("the actual OIDC statement is valid")
                .name;
            common::credentials::install_auth_plugin(&directory, &oidc_module, "corp", true);
            let signing = directory.join("signing-key");
            std::fs::write(&signing, hex::encode([9u8; 32]))
                .expect("write the actual configured signing key");
            let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
                "providers": {},
                "models": {},
                "identity-providers": {
                    "corp": { "module": oidc_module, "settings": common::credentials::settings("api://auth-self-groups") }
                },
                "auth": {
                    "chain": ["corp"], "admin_auth": [], "signing_key": { "file": signing },
                    "key_ttl": "1h", "policy": policy,
                    "role_bindings": { "corp": { "eng": { "group": "team" } } }
                },
                "groups": { "team": { "child_default": { "limits": [{ "budget": 500, "per": "month" }] } } },
                "store": { "module": module, "settings": settings },
                "advanced": { "allow_destinations": ["127.0.0.1"] },
            }))
            .expect("the product deployment parses");
            let config = busbar_kernel::config::resolve(&deploy, &Default::default())
                .expect("the product deployment resolves");
            let plugin_config = busbar_kernel::config::PluginsCfg {
                enabled: true,
                dir: directory.to_string_lossy().into_owned(),
                ..Default::default()
            };
            let mut anchor =
                busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
                    .expect("the actual Store bootstraps its config authority");
            let observed = Arc::new(ObservedStoreCalls {
                calls: anchor
                    .calls
                    .as_ref()
                    .cloned()
                    .expect("the actual Store exposes typed calls"),
                record_writes: std::sync::atomic::AtomicUsize::new(0),
                transactions: std::sync::atomic::AtomicUsize::new(0),
            });
            anchor.calls = Some(observed.clone());
            let overlay = busbar_kernel::config::overlay::OverlayStore::new(
                anchor
                    .calls
                    .as_ref()
                    .cloned()
                    .expect("the actual Store exposes typed calls"),
            )
            .expect("the actual Store supports conditional config records");
            let rules = Arc::new(crate::root::door_steps::Rules::default())
                as Arc<dyn busbar_kernel::appbuild::RootRules>;
            let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
                config,
                plugin_config,
                Some(overlay.clone()),
                Default::default(),
                Default::default(),
                (None, None),
                None,
                &rules,
                Some(anchor),
                true,
            )
            .expect("the actual product builds the session deployment");
            limits.stage_boot();
            let _book = crate::root::boot::book(&app, &module).expect(
                "the actual Store binds rate-card history and usage recovery before activation",
            );
            limits.keep().expect("the product limits commit");
            if let Some(rotate) = rotate {
                rotate();
            }
            let app = Arc::new(app);
            let gov = app
                .governance
                .as_ref()
                .expect("the actual Store supplies governance")
                .clone();
            let (router, handle) =
                busbar_kernel::router::build_router_with_limits(app, 64 * 1024, 1, false);
            let before = handle.load();
            let overlay_before = overlay
                .read_bytes()
                .expect("the actual overlay reads before admission");
            let writes_before = observed
                .record_writes
                .load(std::sync::atomic::Ordering::SeqCst);
            let transactions_before = observed
                .transactions
                .load(std::sync::atomic::Ordering::SeqCst);
            let token = if route == "exchange" {
                let anonymous = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    tower::ServiceExt::oneshot(
                        router.clone(),
                        axum::http::Request::builder()
                            .method("POST")
                            .uri("/auth/token")
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    ),
                )
                .await
                .expect("the actual anonymous exchange is bounded")
                .unwrap();
                assert_eq!(anonymous.status(), axum::http::StatusCode::UNAUTHORIZED);
                assert!(Arc::ptr_eq(&before, &handle.load()));
                assert!(gov.all_keys().unwrap().is_empty());
                assert_eq!(overlay.read_bytes().unwrap(), overlay_before);
                assert_eq!(
                    observed
                        .record_writes
                        .load(std::sync::atomic::Ordering::SeqCst),
                    writes_before
                );
                assert_eq!(
                    observed
                        .transactions
                        .load(std::sync::atomic::Ordering::SeqCst),
                    transactions_before
                );
                let credential =
                    common::credentials::token_for("subject", &["eng"], "api://auth-self-groups");
                let response = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    tower::ServiceExt::oneshot(
                        router,
                        axum::http::Request::builder()
                            .method("POST")
                            .uri("/auth/token")
                            .header("authorization", format!("Bearer {credential}"))
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    ),
                )
                .await
                .expect("the actual OIDC exchange is bounded")
                .unwrap();
                let status = response.status();
                let body = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    axum::body::to_bytes(response.into_body(), 64 * 1024),
                )
                .await
                .expect("the actual exchange body is bounded")
                .unwrap();
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                if allowed {
                    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
                    Some(body["api_key"].as_str().expect("issued token").to_string())
                } else {
                    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
                    assert_eq!(
                        body["error"],
                        "the key this identity would mint is over the mint ceiling (auth.policy)"
                    );
                    assert!(body.get("api_key").is_none());
                    None
                }
            } else {
                // The public login/refresh mint API takes verified principal DATA. The exchange arm
                // above separately supplies that same subject and role through actual OIDC verification.
                let mut principal = busbar_kernel::auth::Principal::from_id("oidc:subject");
                principal.roles = vec!["eng".to_string()];
                match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    busbar_kernel::auth::login::issue_self_key(
                        &before,
                        &handle,
                        "corp",
                        principal,
                        route == "refresh",
                    ),
                )
                .await
                .expect("the actual post-identity mint is bounded")
                {
                    busbar_kernel::auth::login::SelfKeyIssue::Issued { secret, .. } => {
                        assert!(allowed);
                        Some(secret.expose(&busbar_kernel::seal::lend()).clone())
                    }
                    busbar_kernel::auth::login::SelfKeyIssue::OverCeiling => {
                        assert!(!allowed);
                        None
                    }
                    _ => panic!("unexpected actual post-identity mint result"),
                }
            };
            if let Some(token) = token {
                let key = gov
                    .verify_token(&token, busbar_kernel::store::now(), None)
                    .unwrap();
                assert_eq!(key.binding_mode.as_deref(), Some(user));
                assert_eq!(key.group.as_deref(), Some("user:oidc:subject"));
                assert_eq!(gov.all_keys().unwrap().len(), 1);
                assert!(handle
                    .load()
                    .groups_registry
                    .contains_key("user:oidc:subject"));
                let persisted = overlay
                    .read_required()
                    .expect("the real Store overlay reads")
                    .expect("the allowed mint persisted an actual overlay generation");
                assert_eq!(
                    persisted.groups["user:oidc:subject"].parent.as_deref(),
                    Some("team")
                );
            } else {
                assert!(gov.all_keys().unwrap().is_empty(), "no binding was written");
                assert!(
                    Arc::ptr_eq(&before, &handle.load()),
                    "no group snapshot swap"
                );
                assert!(!before.groups_registry.contains_key("user:oidc:subject"));
                assert_eq!(
                    overlay.read_bytes().unwrap(),
                    overlay_before,
                    "no group overlay was persisted"
                );
                assert_eq!(
                    observed
                        .record_writes
                        .load(std::sync::atomic::Ordering::SeqCst),
                    writes_before,
                    "no Store overlay staging was attempted"
                );
                assert_eq!(
                    observed
                        .transactions
                        .load(std::sync::atomic::Ordering::SeqCst),
                    transactions_before,
                    "no Store conditional candidate was submitted"
                );
            }
        }
    }
}
