// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTHORIZATION SERVER OVER THE DEPLOYMENT'S STORE: the library's own storage-conformance
//! harness against [`SharedStorage`], two nodes over one store serving one server, and the signing
//! key minted once per deployment.
//!
//! The store here is a double of the store's plane-record verbs and its single-use claims, over
//! maps the test holds: every clone is the same store, so two planes built over two clones are two
//! nodes on one deployment. It files records exactly as the linked in-tree store does: a record is
//! kept at `(kind, parent or else id, seq)`, `get_plane_record` reads `(kind, id, 0)`, a list by
//! parent reads the records whose parent it names, and a delete takes every sequence of an identity.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::sdk::store::{Cap, Cell, Grant};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta,
};
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};
use oauth_as::store::Storage as _;

use crate::config::OauthAsCfg;
use crate::plane::{seam_build, AsPlane};
use crate::shared::{Shared, SharedStorage, LABEL, MINT_CLAIM_SECS};

/// `(kind, parent or else id, seq)` to `(parent, body)`, as the linked in-tree store keys them.
type Records = BTreeMap<(String, String, u64), (Option<String>, Vec<u8>)>;

/// The double. Cheap to clone; every clone is the same store.
#[derive(Clone, Default)]
struct OneStore {
    records: Arc<Mutex<Records>>,
    claims: Arc<Mutex<BTreeMap<(String, String), u64>>>,
}

impl OneStore {
    fn calls(&self) -> Arc<dyn StoreCalls> {
        Arc::new(self.clone())
    }

    /// Redeem `(kind, token)` as another node would.
    fn redeem(&self, kind: &str, token: &str, expires_at: u64, now: u64) -> bool {
        let mut claims = self.claims.lock().unwrap_or_else(|p| p.into_inner());
        claims.retain(|_, lapses| *lapses > now);
        claims
            .insert((kind.to_string(), token.to_string()), expires_at)
            .is_none()
    }

    fn put(&self, kind: &str, id: &str, body: &[u8]) {
        self.records
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((kind.to_string(), id.to_string(), 0), (None, body.to_vec()));
    }
}

fn not_this<'a, T: Send + 'a>() -> StoreCall<'a, T> {
    Box::pin(async {
        Err(StoreFailure::Failed(
            "not a slot this server uses".to_string(),
        ))
    })
}

impl StoreCalls for OneStore {
    fn reserve<'a>(&'a self, _: OpId, _: u64, _: &'a [Cell<'a>]) -> StoreCall<'a, Vec<Grant>> {
        not_this()
    }
    fn slice_release<'a>(
        &'a self,
        _: OpId,
        _: u64,
        _: &'a [(u64, u64)],
    ) -> StoreCall<'a, Vec<u64>> {
        not_this()
    }
    fn add_usage_batch<'a>(
        &'a self,
        _: OpId,
        _: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        not_this()
    }
    fn add_metering_batch<'a>(&'a self, _: OpId, _: &'a [MeteringDelta]) -> StoreCall<'a, ()> {
        not_this()
    }
    fn append_audit_batch<'a>(&'a self, _: OpId, _: &'a [AuditRecord]) -> StoreCall<'a, ()> {
        not_this()
    }
    fn window_caps<'a>(&'a self, _: OpId, _: &'a [Cap<'a>]) -> StoreCall<'a, ()> {
        not_this()
    }
    fn append_batch<'a>(
        &'a self,
        _: OpId,
        _: &'a str,
        _: &'a [RecordBytes],
    ) -> StoreCall<'a, Head> {
        not_this()
    }
    fn heads(&self) -> StoreCall<'_, Vec<(String, Head)>> {
        not_this()
    }
    fn session_put<'a>(&'a self, _: u64, _: &'a str, _: &'a str) -> StoreCall<'a, ()> {
        not_this()
    }
    fn session_remove(&self, _: u64) -> StoreCall<'_, ()> {
        not_this()
    }
    fn sessions_for<'a>(&'a self, _: &'a str) -> StoreCall<'a, Vec<(u64, String)>> {
        not_this()
    }
    fn record_put<'a>(&'a self, _: &'a str, _: &'a [u8], _: &'a RecordBytes) -> StoreCall<'a, ()> {
        not_this()
    }
    fn record_get<'a>(&'a self, _: &'a str, _: &'a [u8]) -> StoreCall<'a, Option<RecordBytes>> {
        not_this()
    }
    fn record_scan<'a>(
        &'a self,
        _: &'a str,
        _: &'a [u8],
        _: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        not_this()
    }
    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        // Filed as the linked in-tree store files it: under the parent when there is one, at its
        // sequence position.
        let identity = record.parent.unwrap_or(record.id).to_string();
        self.records
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                (record.kind.to_string(), identity, record.seq),
                (record.parent.map(str::to_string), record.body.to_vec()),
            );
        Box::pin(async { Ok(()) })
    }
    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> StoreCall<'a, Option<Vec<u8>>> {
        let got = self
            .records
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(kind.to_string(), id.to_string(), 0))
            .map(|(_, body)| body.clone());
        Box::pin(async move { Ok(got) })
    }
    fn append_plane_record<'a>(&'a self, _: OpId, _: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        not_this()
    }
    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        let rows: Vec<Vec<u8>> = self
            .records
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|((k, _, _), (parent, _))| {
                k == kind
                    && match selector {
                        PlaneSelector::All => true,
                        PlaneSelector::Parent(p) => parent.as_deref() == Some(p.as_ref()),
                    }
            })
            .map(|(_, (_, body))| body.clone())
            .collect();
        Box::pin(async move { Ok(rows) })
    }
    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
        self.records
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|(k, i, _), _| !(k == kind && i == id));
        Box::pin(async { Ok(()) })
    }
    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        let first = self.redeem(kind, token, expires_at, now);
        Box::pin(async move { Ok(first) })
    }
    fn plane_token_live<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: u64,
        _: u64,
    ) -> StoreCall<'a, bool> {
        not_this()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn block(signing_key: bool) -> serde_yaml::Value {
    serde_yaml::to_value(OauthAsCfg {
        issuer: "https://gw.example.com".to_string(),
        signing_key: signing_key.then(|| busbar_contract::SecretRef::env("BUSBAR_TEST_AS_KEY")),
        key_id: None,
        default_grant: Vec::new(),
        access_token_ttl_secs: None,
        refresh_token_ttl_secs: None,
        fapi2: false,
        clients: Vec::new(),
    })
    .expect("the block serializes")
}

/// One node's generation over `store` (`None`: no store configured), after `prior`.
fn node(
    store: Option<&OneStore>,
    prior: Option<&Arc<dyn std::any::Any + Send + Sync>>,
    secrets: Vec<(String, String)>,
) -> Arc<dyn std::any::Any + Send + Sync> {
    seam_build::<crate::NoConnections>(
        &block(!secrets.is_empty()),
        secrets,
        Vec::new(),
        prior,
        store.map(OneStore::calls),
    )
    .expect("builds")
}

fn plane(g: &Arc<dyn std::any::Any + Send + Sync>) -> Arc<AsPlane> {
    Arc::clone(g)
        .downcast::<AsPlane>()
        .expect("this crate's server")
}

fn jwks(p: &AsPlane) -> String {
    serde_json::to_string(&p.server().jwks()).expect("the key set serializes")
}

fn client(id: &str) -> oauth_as::client::Client {
    oauth_as::client::Client {
        client_id: oauth_as::client::ClientId::new(id),
        auth: oauth_as::client::ClientAuth::Public,
        grant_types: vec![oauth_as::grant::GrantType::AuthorizationCode],
        redirect_uris: vec!["https://app.example.com/cb".to_string()],
        allowed_scopes: oauth_as::scope::ScopeSet::default(),
        default_scopes: oauth_as::scope::ScopeSet::default(),
        name: Some(id.to_string()),
        registration: None,
    }
}

/// THE LIBRARY'S OWN CONTRACT, raced on real threads: atomic `take_*`, the four compare-and-swaps,
/// the revocation barriers and cascades, the replay ledger and the sweep, every check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_store_backed_server_holds_the_storage_contract() {
    let violations = oauth_as::storage_conformance::StorageConformance::new(|| async {
        SharedStorage::new(Arc::new(Shared::new(OneStore::default().calls())))
    })
    .with_spawn(|task| {
        tokio::spawn(task);
    })
    .run()
    .await;
    assert!(violations.is_empty(), "{violations:#?}");
}

/// RED before the store-backed records: each node held its own `MemoryStorage`, so a client one node
/// registered was unknown to the other, and a replayed proof was fresh on the second node.
#[tokio::test]
async fn two_nodes_on_one_store_are_one_authorization_server() {
    let store = OneStore::default();
    let (a, b) = (
        node(Some(&store), None, Vec::new()),
        node(Some(&store), None, Vec::new()),
    );
    let (a, b) = (plane(&a), plane(&b));

    a.server()
        .store()
        .put_client(client("agent-1"))
        .await
        .expect("node A registers");
    assert!(
        b.server()
            .store()
            .get_client(&oauth_as::client::ClientId::new("agent-1"))
            .await
            .expect("node B reads")
            .is_some(),
        "a client node A registered is unknown on node B"
    );

    let until = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
    assert!(a
        .server()
        .store()
        .claim_replay_id("jti-1", until)
        .await
        .expect("claims"));
    assert!(
        !b.server()
            .store()
            .claim_replay_id("jti-1", until)
            .await
            .expect("claims"),
        "a proof node A accepted is fresh again on node B"
    );

    // The consent screen: a session opened on A, an answer staked on B, spent once across both.
    a.open_session("busbar-operator", "session-1".to_string())
        .await;
    b.stake("session-1", "key-1".to_string(), true).await;
    assert!(
        a.is_staked("session-1", "key-1").await,
        "the answer is staked on both nodes"
    );
    let shared = Shared::new(store.calls());
    assert_eq!(
        shared.spend("session-1", "key-1").await.expect("spends"),
        Some(true)
    );
    assert_eq!(
        shared.spend("session-1", "key-1").await.expect("spends"),
        None,
        "one staked answer was spent twice"
    );
}

/// RED before: with no `signing_key`, each node generated its own key, so a token node A signed
/// failed verification on node B.
#[tokio::test]
async fn two_nodes_on_one_store_sign_with_one_minted_key() {
    let store = OneStore::default();
    let (a, b) = (
        node(Some(&store), None, Vec::new()),
        node(Some(&store), None, Vec::new()),
    );
    let (a, b) = (plane(&a), plane(&b));
    let minted = a
        .unconfigured_key()
        .expect("node A signs with a minted key");
    assert_eq!(
        b.unconfigured_key().as_ref(),
        Some(&minted),
        "node B minted a second key"
    );
    assert_eq!(jwks(&a), jwks(&b), "the two nodes publish different keys");
}

/// The key does not roll: a reload and a restart over the same store sign with the key a token was
/// signed under before them, so a verifier never refuses a valid unexpired token across either.
#[tokio::test]
async fn a_reload_and_a_restart_keep_the_minted_key() {
    let store = OneStore::default();
    let first = node(Some(&store), None, Vec::new());
    let reloaded = node(Some(&store), Some(&first), Vec::new());
    let restarted = node(Some(&store), None, Vec::new());
    let before = jwks(&plane(&first));
    assert_eq!(
        jwks(&plane(&reloaded)),
        before,
        "a reload published a different key"
    );
    assert_eq!(
        jwks(&plane(&restarted)),
        before,
        "a restart published a different key"
    );
}

/// A configured `signing_key` always wins over the minted one.
#[tokio::test]
async fn a_configured_signing_key_overrides_the_minted_one() {
    use base64::Engine as _;
    let store = OneStore::default();
    let minted = plane(&node(Some(&store), None, Vec::new()));
    let der = crate::signer::RingEs256Key::generate_pkcs8().expect("a key");
    let configured = plane(&node(
        Some(&store),
        None,
        vec![(
            crate::config::SIGNING_KEY_PATH.to_string(),
            base64::engine::general_purpose::STANDARD.encode(&der),
        )],
    ));
    assert_eq!(
        configured.unconfigured_key(),
        None,
        "the configured server minted a key"
    );
    assert_ne!(
        jwks(&configured),
        jwks(&minted),
        "the configured server publishes the minted key instead of its own"
    );
}

/// A build that LOSES the store's minting claim never signs with a key it minted itself: it takes
/// the winner's, or refuses.
#[tokio::test]
async fn a_minting_claim_loser_never_signs_with_its_own_key() {
    let store = OneStore::default();
    let now = now_secs();
    assert!(store.redeem(
        &format!("{LABEL}mint"),
        "signing",
        now + MINT_CLAIM_SECS,
        now
    ));
    let minted = AtomicBool::new(false);
    let shared = Shared::new(store.calls());
    let refused = shared
        .signing_key(|| {
            minted.store(true, Ordering::SeqCst);
            Ok(vec![1, 2, 3])
        })
        .await;
    assert!(refused.is_err(), "a loser with no winner's key must refuse");
    assert!(!minted.load(Ordering::SeqCst), "a claim loser minted a key");

    // The winner keeps its key while the loser waits: the loser signs with the winner's.
    use base64::Engine as _;
    let winner = store.clone();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        winner.put(
            &format!("{LABEL}key"),
            "signing",
            base64::engine::general_purpose::STANDARD
                .encode([9u8, 9, 9])
                .as_bytes(),
        );
    });
    let taken = shared
        .signing_key(|| {
            minted.store(true, Ordering::SeqCst);
            Ok(vec![1, 2, 3])
        })
        .await
        .expect("the winner's key");
    writer.join().expect("the winner wrote");
    assert_eq!(
        taken,
        vec![9, 9, 9],
        "the loser did not take the winner's key"
    );
    assert!(!minted.load(Ordering::SeqCst), "a claim loser minted a key");
}

/// With no store configured the server keeps its records in this process, as it always did.
#[tokio::test]
async fn without_a_store_the_records_stay_in_process() {
    let a = plane(&node(None, None, Vec::new()));
    let b = plane(&node(None, None, Vec::new()));
    a.server()
        .store()
        .put_client(client("agent-1"))
        .await
        .expect("registers");
    assert!(b
        .server()
        .store()
        .get_client(&oauth_as::client::ClientId::new("agent-1"))
        .await
        .expect("reads")
        .is_none());
}
