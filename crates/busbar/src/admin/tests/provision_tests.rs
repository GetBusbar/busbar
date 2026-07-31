//! THE POST-COMMIT FAILURE BRANCH of `POST /keys` with auto-provisioning.
//!
//! `Outcome::commit_then` runs a config PERSIST-and-SWAP and then a store write, under one guard.
//! The two halves cannot be atomic with each other: once the swap has happened it is visible to
//! every in-flight request and un-persisting is itself fallible. So the honest semantics are not
//! "compensate" but "the provision is committed, and it is RECORDED at commit time" — which is what
//! these tests pin, on the branch where the config half commits and the store half then fails.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use serde_json::json;

use crate::governance::{GovState, MemoryStore};
use crate::state::AppHandle;
use crate::test_support::TestApp;

/// A store whose KEY WRITES always fail — the mint half of `commit_then` cannot succeed, while the
/// config half (which never touches the store) commits normally. Everything else delegates.
struct RefusesKeyWrites(MemoryStore);

impl busbar_api::Store for RefusesKeyWrites {
    fn put_key(&self, _key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
        Err(busbar_api::StoreError("key write unavailable".into()))
    }
    fn put_key_with_credential(
        &self,
        _key: &busbar_api::VirtualKey,
        _secret: &busbar_api::CredentialSecret,
    ) -> busbar_api::StoreResult<()> {
        Err(busbar_api::StoreError("key write unavailable".into()))
    }
    fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
        self.0.get_key(id)
    }
    fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
        self.0.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
        self.0.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
        self.0.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_api::UsageLedger,
    ) -> busbar_api::StoreResult<()> {
        self.0.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(&self, delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
        self.0.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
        self.0.list_metering(bucket)
    }
}

fn gov(store: Arc<dyn crate::governance::Store>) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            store,
            None,
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &[7u8; 32],
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .expect("gov"),
    )
}

fn tree(names: &[&str]) -> std::collections::BTreeMap<String, crate::config::GroupCfg> {
    names
        .iter()
        .map(|n| (n.to_string(), crate::config::GroupCfg::default()))
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
        crate::auth::AuthPrincipal(None),
        name,
        group,
        parent,
    )
    .await
}

/// `mint_with_parent`, but naming the CALLER. Audit rows carry `actor_id()`, so a test that asserts
/// on the process-global audit log can filter to rows only IT could have written — the same reason
/// each test provisions its own group name.
async fn mint_as(
    handle: &Arc<AppHandle>,
    principal: crate::auth::AuthPrincipal,
    name: &str,
    group: &str,
    parent: &str,
) -> StatusCode {
    crate::admin::create_key(
        State(handle.clone()),
        axum::Extension(principal),
        axum::Extension(crate::auth::AdminScope(
            crate::admin::v1::contract::Grants::of(crate::admin::v1::contract::Scope::Full),
        )),
        HeaderMap::new(),
        axum::body::Bytes::from(
            json!({ "name": name, "group": group, "parent": parent }).to_string(),
        ),
    )
    .await
    .status()
}

/// The group THIS test provisions. Unique to it on purpose: the audit log is process-global and the
/// assertions below filter it by `(action, resource)`, so any other test provisioning the same name
/// lands a row inside this test's filter. Three of them used to share `user:alice`, and one foreign
/// row is enough to break the count-equality assertion on the retry (observed 1→2).
const PROVISION_FAIL_GROUP: &str = "user:alice-mint-fail";
/// The audit `resource` for [`PROVISION_FAIL_GROUP`] — `record_by` writes `group:<name>`.
const PROVISION_FAIL_RESOURCE: &str = "group:user:alice-mint-fail";
/// The version-log summary fragment naming that provision.
const PROVISION_FAIL_VERSION_SUMMARY: &str = "group.provision group:user:alice-mint-fail";

/// A mint that fails AFTER the auto-provision has committed leaves the group live — and says so.
/// The group.provision audit row and the version-log entry are written at COMMIT time, so the
/// committed config change is never invisible, and the retry is idempotent (the group now exists).
#[tokio::test]
async fn mint_failure_after_the_provision_commit_still_records_the_committed_group() {
    crate::metrics::init();
    let app = TestApp::new()
        .governance(gov(Arc::new(RefusesKeyWrites(MemoryStore::new()))))
        .groups_tree(tree(&["team"]))
        .build();
    let handle = Arc::new(AppHandle::new(app));
    let versions_before = handle
        .load()
        .versions
        .list(0, crate::admin::v1::contract::LIST_LIMIT_MAX)
        .len();

    let status = mint_with_parent(&handle, "k", PROVISION_FAIL_GROUP, "team").await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the mint half fails, so the request fails"
    );

    // THE COMMITTED HALF IS LIVE: the leaf was persisted and swapped before the mint ran.
    let live = handle.load();
    assert!(
        live.groups_registry.contains_key(PROVISION_FAIL_GROUP),
        "the auto-provisioned leaf is committed and live"
    );
    assert!(
        live.cost.group_named(PROVISION_FAIL_GROUP).is_some(),
        "and it is in the enforcement model, so a retry can bind to it"
    );

    // AND IT IS RECORDED — at COMMIT time, so a mint that fails afterwards cannot erase the fact
    // that the config changed.
    assert!(
        crate::admin::audit::AUDIT
            .list_filtered(
                0,
                crate::admin::audit::MAX_AUDIT_ENTRIES,
                Some("group.provision"),
                Some(PROVISION_FAIL_RESOURCE)
            )
            .iter()
            .any(|e| e.outcome == crate::admin::audit::OUTCOME_APPLIED),
        "the committed provision is in the audit trail"
    );
    let versions = live
        .versions
        .list(0, crate::admin::v1::contract::LIST_LIMIT_MAX);
    assert!(
        versions.len() > versions_before,
        "the committed provision is in the version log"
    );
    let entry = versions
        .iter()
        .find(|v| v.summary.contains(PROVISION_FAIL_VERSION_SUMMARY))
        .expect("the version entry names the provisioned group");
    // The recorded version is the COMMITTED snapshot's own, read inside the transaction — not
    // whatever a post-lock-release `handle.load()` happened to observe.
    assert_eq!(
        entry.version, live.config_version,
        "the version entry is attributed to the snapshot that was actually committed"
    );

    // THE RETRY IS IDEMPOTENT: the group exists now, so a second attempt takes the no-provision
    // path (it still fails on the store, but it does not re-provision or double-record).
    //
    // Scoped by resource (PROVISION_FAIL_RESOURCE), which removes cross-test contamination, but
    // NOT by seq — `AUDIT` is a 1000-entry ring (`MAX_AUDIT_ENTRIES`), and a large enough
    // concurrent admin-mutation burst between the two reads below could evict this test's own rows
    // before the second read. Latent: nothing in this suite currently drives that many concurrent
    // audit writes. Accepted rather than bracketed by seq, which would narrow the window but not
    // defeat eviction.
    let audit_rows_before = crate::admin::audit::AUDIT
        .list_filtered(
            0,
            crate::admin::audit::MAX_AUDIT_ENTRIES,
            Some("group.provision"),
            Some(PROVISION_FAIL_RESOURCE),
        )
        .len();
    let status = mint_with_parent(&handle, "k", PROVISION_FAIL_GROUP, "team").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        crate::admin::audit::AUDIT
            .list_filtered(
                0,
                crate::admin::audit::MAX_AUDIT_ENTRIES,
                Some("group.provision"),
                Some(PROVISION_FAIL_RESOURCE)
            )
            .len(),
        audit_rows_before,
        "a retry against the now-existing group does not re-provision"
    );
}

/// The principal this test mints as, so its audit rows are distinguishable from every other
/// refused mint in the binary (they all share the `key:-` resource).
const CEILING_ACTOR: &str = "test:ceiling-audit";

/// `key.create`/rejected rows written by [`CEILING_ACTOR`] — this test's refusals and no others.
fn ceiling_refusal_rows() -> usize {
    crate::admin::audit::AUDIT
        .list_filtered(
            0,
            crate::admin::audit::MAX_AUDIT_ENTRIES,
            Some("key.create"),
            Some(crate::admin::KEY_RESOURCE_NONE),
        )
        .iter()
        .filter(|e| {
            e.outcome == crate::admin::audit::OUTCOME_REJECTED && e.principal == CEILING_ACTOR
        })
        .count()
}

/// #20: auto-provision-on-mint had NO ceiling on the NUMBER of groups, so a `mint`-scope credential
/// could grow the limit tree without bound — every leaf is a new enforcement bucket, version-log
/// entry and persisted overlay row. `limits.max_auto_provisioned_groups` caps it; explicitly
/// configured groups and mints that bind to an EXISTING group are unaffected.
#[tokio::test]
async fn auto_provision_stops_at_the_group_ceiling() {
    crate::metrics::init();
    let mut app = TestApp::new()
        .governance(gov(Arc::new(MemoryStore::new())))
        .groups_tree(tree(&["team"]))
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        // Ceiling of 2: the base `team` group plus exactly ONE auto-provisioned leaf.
        inner.max_auto_provisioned_groups = 2;
    }
    let handle = Arc::new(AppHandle::new(app));

    assert_eq!(
        mint_with_parent(&handle, "k1", "user:alice", "team").await,
        StatusCode::CREATED,
        "the first self-mint provisions its leaf"
    );
    // A refused mint records `key.create`/rejected against `key:-` — a resource EVERY refused mint
    // in the binary shares, so this filters to rows written by THIS test's principal. Without that
    // a concurrent test's refusal satisfies the assertion and it passes with the fix reverted.
    let ceiling_actor =
        crate::auth::AuthPrincipal(Some(busbar_api::Principal::from_id(CEILING_ACTOR)));
    let rejected_before = ceiling_refusal_rows();
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
    let rejected_after = ceiling_refusal_rows();
    assert!(
        rejected_after > rejected_before,
        "the ceiling refusal must write a `key.create`/rejected audit row \
         (before={rejected_before}, after={rejected_after})"
    );

    // Binding to an EXISTING group still works at the ceiling — only auto-provisioning is gated.
    assert_eq!(
        mint_with_parent(&handle, "k3", "user:alice", "team").await,
        StatusCode::CREATED,
        "a mint that provisions nothing is unaffected by the ceiling"
    );
}
