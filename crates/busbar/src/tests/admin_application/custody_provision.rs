// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::http::StatusCode;
use busbar_contract::records::*;
use busbar_core_admin::admin_state::AppAdmin as _;
use busbar_kernel::audit_ring;
use std::sync::Arc;

use crate::root::test_plugins as plugins;
use crate::test_common as common;

struct RefusesKeyWrites(Arc<dyn busbar_contract::records::RecordStore>);

impl busbar_contract::records::RecordStore for RefusesKeyWrites {
    fn put_key(&self, _key: &VirtualKey) -> RecordStoreResult<()> {
        Err(RecordStoreError("key write unavailable".into()))
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.0.get_key(id)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.0.list_keys()
    }
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.0.delete_key(id)
    }
    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        self.0.list_keys_since(since)
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
        self.0.get_usage(bucket_id, window_start)
    }
    fn apply_usage_correction(
        &self,
        request: &correction::Request,
    ) -> RecordStoreResult<correction::Decision> {
        self.0.apply_usage_correction(request)
    }
    fn supports_usage_correction(&self) -> bool {
        self.0.supports_usage_correction()
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        self.0.put_usage(bucket_id, window_start, ledger)
    }
    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        self.0.add_usage(bucket_id, window_start, delta)
    }
    fn add_usage_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> RecordStoreResult<()> {
        self.0.add_usage_batch_deduped(op, cells)
    }
    fn supports_usage_batch_deduped(&self) -> bool {
        self.0.supports_usage_batch_deduped()
    }
    fn supports_metering_batch_deduped(&self) -> bool {
        self.0.supports_metering_batch_deduped()
    }
    fn add_metering_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        deltas: &[MeteringDelta],
    ) -> RecordStoreResult<()> {
        self.0.add_metering_batch_deduped(op, deltas)
    }
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.0.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.0.list_metering(bucket)
    }
    fn put_credential(&self, secret: &CredentialSecret) -> RecordStoreResult<()> {
        self.0.put_credential(secret)
    }
    fn rewrap_credential(
        &self,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> RecordStoreResult<bool> {
        self.0.rewrap_credential(expected, replacement)
    }
    fn put_key_with_credential(
        &self,
        _key: &VirtualKey,
        _secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        Err(RecordStoreError("key write unavailable".into()))
    }
    fn list_credentials(&self, key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        self.0.list_credentials(key_id)
    }
    fn revoke_credential(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        self.0.revoke_credential(id, reason)
    }
    fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        self.0.list_credentials_since(since)
    }
    fn append_audit(&self, entry: &AuditRecord) -> RecordStoreResult<()> {
        self.0.append_audit(entry)
    }
    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        self.0.list_audit()
    }
    fn add_denylist(&self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        self.0.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        self.0.list_denylist()
    }
    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        self.0.list_audit_tail(limit)
    }
    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.0.upsert_plane_record(record)
    }
    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        self.0.get_plane_record(kind, id)
    }
    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.0.append_plane_record(record)
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        self.0.list_plane_records(kind, selector)
    }
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        self.0.list_plane_record_parents(kind)
    }
    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        self.0.purge_plane_records_before(kind, before)
    }
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        self.0.purge_plane_records(kind, before, retention)
    }
    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        self.0.delete_plane_record(kind, id)
    }
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        self.0.redeem_plane_token(kind, token, expires_at, now)
    }
    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        self.0.plane_token_live(kind, token, expires_at, now)
    }
}

const PROVISION_FAIL_GROUP: &str = "user:alice-mint-fail";

const PROVISION_FAIL_RESOURCE: &str = "group:user:alice-mint-fail";

const PROVISION_FAIL_VERSION_SUMMARY: &str = "group.provision group:user:alice-mint-fail";

#[tokio::test]
async fn mint_failure_after_the_provision_commit_still_records_the_committed_group() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("provision-mint-fault");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let signing_key = directory.join("signing.key");
    std::fs::write(&signing_key, [7u8; 32]).expect("write the configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [], "signing_key": { "file": signing_key } },
        "groups": { "team": {} },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let opened = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual signed Store opens through the normal bootstrap");
    let refusing = busbar_contract::store_calls::OpenedStore {
        records: Arc::new(RefusesKeyWrites(opened.records)),
        calls: None,
    };
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(refusing),
        false,
    )
    .expect("the actual product builds the provision deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let (_data, admin, handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port");
    let address = listener.local_addr().expect("an address");
    let serving = tokio::spawn(async move { axum::serve(listener, admin).await });
    let client = reqwest::Client::new();
    let versions_before = handle
        .load()
        .versions()
        .list(0, busbar_core_admin::v1::contract::LIST_LIMIT_MAX)
        .len();

    let status = client
        .post(format!("http://{address}/api/v1/admin/keys"))
        .json(&serde_json::json!({"name":"k", "group":PROVISION_FAIL_GROUP,"parent":"team"}))
        .send()
        .await
        .expect("the actual admin surface answers")
        .status();
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the mint half fails, so the request fails"
    );

    let live = handle.load();
    assert!(
        live.groups_registry.contains_key(PROVISION_FAIL_GROUP),
        "the auto-provisioned leaf is committed and live"
    );
    assert!(
        live.cost.group_named(PROVISION_FAIL_GROUP).is_some(),
        "and it is in the enforcement model, so a retry can bind to it"
    );

    assert!(
        busbar_kernel::audit::auditlog::AUDIT_LOG
            .list_filtered(
                0,
                audit_ring::MAX_AUDIT_ENTRIES,
                Some("group.provision"),
                Some(PROVISION_FAIL_RESOURCE)
            )
            .iter()
            .any(|e| e.outcome == audit_ring::OUTCOME_APPLIED),
        "the committed provision is in the audit trail"
    );
    let versions = live
        .versions()
        .list(0, busbar_core_admin::v1::contract::LIST_LIMIT_MAX);
    assert!(
        versions.len() > versions_before,
        "the committed provision is in the version log"
    );
    let entry = versions
        .iter()
        .find(|v| v.summary.contains(PROVISION_FAIL_VERSION_SUMMARY))
        .expect("the version entry names the provisioned group");

    assert_eq!(
        entry.version, live.config_version,
        "the version entry is attributed to the snapshot that was actually committed"
    );

    let audit_rows_before = busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(
            0,
            audit_ring::MAX_AUDIT_ENTRIES,
            Some("group.provision"),
            Some(PROVISION_FAIL_RESOURCE),
        )
        .len();
    let status = client
        .post(format!("http://{address}/api/v1/admin/keys"))
        .json(&serde_json::json!({"name":"k", "group":PROVISION_FAIL_GROUP,"parent":"team"}))
        .send()
        .await
        .expect("the actual admin surface answers")
        .status();
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        busbar_kernel::audit::auditlog::AUDIT_LOG
            .list_filtered(
                0,
                audit_ring::MAX_AUDIT_ENTRIES,
                Some("group.provision"),
                Some(PROVISION_FAIL_RESOURCE)
            )
            .len(),
        audit_rows_before,
        "a retry against the now-existing group does not re-provision"
    );
    serving.abort();
}

#[tokio::test]
async fn auto_provision_stops_at_the_group_ceiling() {
    use std::time::{Duration, Instant};
    const CHILD: &str = "BUSBAR_ADMIN_GROUP_CEILING_CHILD";
    const WITNESS: &str = "actual OIDC group ceiling assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }

    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("admin-group-ceiling");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            "test-scope-module": { "module": oidc_module, "max_admin_scope": "full", "settings": common::credentials::settings("api://admin-group-ceiling") }
        },
        "auth": {
            "chain": [], "admin_auth": ["test-scope-module"], "signing_key": { "file": signing },
            "key_ttl": "1h",
            "role_bindings": { "test-scope-module": { "minters": { "admin_scope": "full" } } }
        },
        "groups": { "team": {} },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let mut config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    config.limits.max_auto_provisioned_groups = 2;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
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
        .expect("the actual Store binds the node book before rates commit");
    limits
        .keep()
        .expect("the product limits commit after the book opens");
    if let Some(rotate) = rotate {
        rotate();
    }

    // The original literal test:ceiling-audit actor is now the genuine OIDC subject
    // oidc:test:ceiling-audit; provider, role and exact audit predicates stay explicit.
    const ACTOR: &str = "oidc:test:ceiling-audit";
    static ACCEPTED: std::sync::OnceLock<
        std::sync::Mutex<Option<tokio::sync::oneshot::Sender<audit_ring::AuditEntry>>>,
    > = std::sync::OnceLock::new();
    fn accepted(entry: &audit_ring::AuditEntry) {
        if entry.action == "key.create" && entry.resource == "key:-" && entry.principal == ACTOR {
            if let Some(sender) = ACCEPTED.get().and_then(|slot| slot.lock().unwrap().take()) {
                let _ = sender.send(entry.clone());
            }
        }
    }
    let token = common::credentials::token_for(
        "test:ceiling-audit",
        &["minters"],
        "api://admin-group-ceiling",
    );
    let (router, handle) =
        busbar_kernel::build_router_with_limits(Arc::new(app), 1 << 20, 0, false);
    let request = |name: &str, group: &str| {
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/admin/keys")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({
                    "name":name,"group":group,"parent":"team",
                })
                .to_string(),
            ))
            .unwrap()
    };
    let first = tokio::time::timeout(
        Duration::from_secs(10),
        tower::ServiceExt::oneshot(router.clone(), request("k1", "user:alice")),
    )
    .await
    .expect("the actual first mint is bounded")
    .unwrap();
    assert_eq!(
        first.status(),
        StatusCode::CREATED,
        "the first self-mint provisions its leaf"
    );
    tokio::time::timeout(
        Duration::from_secs(10),
        axum::body::to_bytes(first.into_body(), 64 * 1024),
    )
    .await
    .expect("the actual mint body is bounded")
    .unwrap();
    let (send, receive) = tokio::sync::oneshot::channel();
    ACCEPTED
        .set(std::sync::Mutex::new(Some(send)))
        .expect("the isolated observer installs once");
    busbar_kernel::audit::auditlog::install_accepted_entry_test_hook(accepted);
    let second = tokio::time::timeout(
        Duration::from_secs(10),
        tower::ServiceExt::oneshot(router.clone(), request("k2", "user:bob")),
    )
    .await
    .expect("the actual ceiling mint is bounded")
    .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::CONFLICT,
        "the ceiling refuses the next auto-provision"
    );
    assert!(
        !handle.load().groups_registry.contains_key("user:bob"),
        "and nothing was provisioned"
    );
    tokio::time::timeout(
        Duration::from_secs(10),
        axum::body::to_bytes(second.into_body(), 64 * 1024),
    )
    .await
    .expect("the actual refusal body is bounded")
    .unwrap();
    let recorded = tokio::time::timeout(Duration::from_secs(5), receive)
        .await
        .expect("the ceiling refusal audit must be published")
        .expect("the actual accepted audit callback remains registered");
    assert_eq!(
        recorded.outcome,
        audit_ring::OUTCOME_REJECTED,
        "the ceiling refusal must write its own `key.create`/rejected audit row"
    );
    let third = tokio::time::timeout(
        Duration::from_secs(10),
        tower::ServiceExt::oneshot(router, request("k3", "user:alice")),
    )
    .await
    .expect("the actual repeat mint is bounded")
    .unwrap();
    assert_eq!(
        third.status(),
        StatusCode::CREATED,
        "a mint that provisions nothing is unaffected by the ceiling"
    );
    tokio::time::timeout(
        Duration::from_secs(10),
        axum::body::to_bytes(third.into_body(), 64 * 1024),
    )
    .await
    .expect("the actual repeat body is bounded")
    .unwrap();
    println!("{WITNESS}");
}
