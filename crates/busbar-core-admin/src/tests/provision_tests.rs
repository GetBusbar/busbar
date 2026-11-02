use crate::admin_state::AppAdmin as _;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use serde_json::json;

use busbar_kernel::audit_ring;
use busbar_kernel::governance::GovState;
use busbar_kernel::state::AppHandle;
use busbar_kernel_testkit::test_support::store_double::MemoryStore;

struct RefusesKeyWrites(MemoryStore);

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

fn gov(store: Arc<dyn busbar_kernel::governance::RecordStore>) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            store,
            None,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[7u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .expect("gov"),
    )
}

fn tree(names: &[&str]) -> std::collections::BTreeMap<String, busbar_kernel::config::GroupCfg> {
    names
        .iter()
        .map(|n| (n.to_string(), busbar_kernel::config::GroupCfg::default()))
        .collect()
}

async fn mint_with_parent(
    handle: &Arc<AppHandle>,
    name: &str,
    group: &str,
    parent: &str,
) -> StatusCode {
    mint_as(
        handle,
        busbar_kernel::auth::AuthPrincipal(None),
        name,
        group,
        parent,
    )
    .await
}

async fn mint_as(
    handle: &Arc<AppHandle>,
    principal: busbar_kernel::auth::AuthPrincipal,
    name: &str,
    group: &str,
    parent: &str,
) -> StatusCode {
    crate::keys::create_key(
        State(handle.clone()),
        axum::Extension(principal),
        HeaderMap::new(),
        axum::Extension(std::sync::Arc::new(crate::keys::KeyReplayCache::new())),
        axum::body::Bytes::from(
            json!({ "name": name, "group": group, "parent": parent }).to_string(),
        ),
    )
    .await
    .status()
}

const PROVISION_FAIL_GROUP: &str = "user:alice-mint-fail";

const PROVISION_FAIL_RESOURCE: &str = "group:user:alice-mint-fail";

const PROVISION_FAIL_VERSION_SUMMARY: &str = "group.provision group:user:alice-mint-fail";

#[tokio::test]
async fn mint_failure_after_the_provision_commit_still_records_the_committed_group() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let app = crate::new_test_app()
        .governance(gov(Arc::new(RefusesKeyWrites(MemoryStore::new()))))
        .groups_tree(tree(&["team"]))
        .build();
    let handle = Arc::new(AppHandle::new(app));
    let versions_before = handle
        .load()
        .versions()
        .list(0, crate::v1::contract::LIST_LIMIT_MAX)
        .len();

    let status = mint_with_parent(&handle, "k", PROVISION_FAIL_GROUP, "team").await;
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
    let versions = live.versions().list(0, crate::v1::contract::LIST_LIMIT_MAX);
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
    let status = mint_with_parent(&handle, "k", PROVISION_FAIL_GROUP, "team").await;
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
}

const CEILING_ACTOR: &str = "test:ceiling-audit";

#[tokio::test]
async fn auto_provision_stops_at_the_group_ceiling() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let mut app = crate::new_test_app()
        .governance(gov(Arc::new(MemoryStore::new())))
        .groups_tree(tree(&["team"]))
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");

        inner.max_auto_provisioned_groups = 2;
    }
    let handle = Arc::new(AppHandle::new(app));

    assert_eq!(
        mint_with_parent(&handle, "k1", "user:alice", "team").await,
        StatusCode::CREATED,
        "the first self-mint provisions its leaf"
    );

    let ceiling_actor = busbar_kernel::auth::AuthPrincipal(Some(
        busbar_contract::auth::Principal::from_id(CEILING_ACTOR),
    ));
    let audit = busbar_kernel_testkit::test_support::accepted_audit::observe_accepted_admin_entry(
        "key.create",
        crate::keys::KEY_RESOURCE_NONE,
        CEILING_ACTOR,
    );
    let status = mint_as(&handle, ceiling_actor, "k2", "user:bob", "team").await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the ceiling refuses the next auto-provision"
    );
    assert!(
        !handle.load().groups_registry.contains_key("user:bob"),
        "and nothing was provisioned"
    );
    let recorded = tokio::time::timeout(std::time::Duration::from_secs(5), audit.accepted())
        .await
        .expect("the ceiling refusal audit must be published")
        .expect("the accepted audit observer remains registered");
    assert_eq!(
        recorded.outcome,
        audit_ring::OUTCOME_REJECTED,
        "the ceiling refusal must write its own `key.create`/rejected audit row"
    );

    assert_eq!(
        mint_with_parent(&handle, "k3", "user:alice", "team").await,
        StatusCode::CREATED,
        "a mint that provisions nothing is unaffected by the ceiling"
    );
}
