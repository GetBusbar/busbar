// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::http::StatusCode;
use busbar_core_admin::admin_state::AppAdmin as _;
use busbar_kernel::audit_ring;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

struct RefusesKeyWrites(Arc<dyn busbar_contract::records::RecordStore>);

impl busbar_contract::records::RecordStore for RefusesKeyWrites {
    fn put_key(
        &self,
        _key: &busbar_contract::records::VirtualKey,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        Err(busbar_contract::records::RecordStoreError(
            "key write unavailable".into(),
        ))
    }
    fn put_key_with_credential(
        &self,
        _key: &busbar_contract::records::VirtualKey,
        _secret: &busbar_contract::records::CredentialSecret,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        Err(busbar_contract::records::RecordStoreError(
            "key write unavailable".into(),
        ))
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_contract::records::RecordStoreResult<Option<busbar_contract::records::VirtualKey>>
    {
        self.0.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::VirtualKey>>
    {
        self.0.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_contract::records::RecordStoreResult<()> {
        self.0.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_contract::records::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.0.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.0.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_contract::records::MeteringDelta,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.0.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::MeteringRow>>
    {
        self.0.list_metering(bucket)
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
