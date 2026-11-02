// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::http::StatusCode;
use busbar_contract::records::*;
use busbar_core_admin::admin_state::AppAdmin as _;
use busbar_kernel::audit_ring;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

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
    let directory = plugins::scratch("provision-mint-fault");
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
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
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
