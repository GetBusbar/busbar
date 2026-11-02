use crate::admin_state::AppAdmin as _;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use serde_json::json;

use busbar_kernel::audit_ring;
use busbar_kernel::governance::GovState;
use busbar_kernel::state::AppHandle;
use busbar_kernel_testkit::test_support::store_double::MemoryStore;

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
