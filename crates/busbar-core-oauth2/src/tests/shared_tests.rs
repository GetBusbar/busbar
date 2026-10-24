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
use crate::shared::{Shared, SharedStorage, LABEL, MINT_CLAIM_SECS, VERSION_CLAIM_SECS};

/// `(kind, parent or else id, seq)` to `(parent, body)`, as the linked in-tree store keys them.
type Records = BTreeMap<(String, String, u64), (Option<String>, Vec<u8>)>;

/// One answer the double holds back: the slot (`get` or `redeem`), the record kind it is for, and
/// how long the answer takes after the store has decided it.
type Stall = (&'static str, String, std::time::Duration);

/// The double. Cheap to clone; every clone is the same store.
#[derive(Clone, Default)]
struct OneStore {
    records: Arc<Mutex<Records>>,
    /// Each claim lapses on the runtime's clock, `expires_at - now` after it was redeemed, so a test
    /// on a paused clock moves every claim's lapse with it.
    claims: Arc<Mutex<BTreeMap<(String, String), tokio::time::Instant>>>,
    stalls: Arc<Mutex<Vec<Stall>>>,
}

impl OneStore {
    fn calls(&self) -> Arc<dyn StoreCalls> {
        Arc::new(self.clone())
    }

    /// Redeem `(kind, token)` as another node would.
    fn redeem(&self, kind: &str, token: &str, expires_at: u64, now: u64) -> bool {
        let at = tokio::time::Instant::now();
        let lapses = at + std::time::Duration::from_secs(expires_at.saturating_sub(now));
        let mut claims = self.claims.lock().unwrap_or_else(|p| p.into_inner());
        claims.retain(|_, l| *l > at);
        claims
            .insert((kind.to_string(), token.to_string()), lapses)
            .is_none()
    }

    /// Hold back the next answer of `slot` for the kind `name` of the server's records by `by`: the
    /// store decides the call at once and answers it `by` later, as a stalled node or a slow store
    /// would.
    fn stall(&self, slot: &'static str, name: &str, by: std::time::Duration) {
        self.stalls.lock().unwrap_or_else(|p| p.into_inner()).push((
            slot,
            format!("{LABEL}{name}"),
            by,
        ));
    }

    fn stalled(&self, slot: &str, kind: &str) -> Option<std::time::Duration> {
        let mut stalls = self.stalls.lock().unwrap_or_else(|p| p.into_inner());
        let i = stalls
            .iter()
            .position(|(s, k, _)| *s == slot && k == kind)?;
        Some(stalls.remove(i).2)
    }

    /// Every record of the server's kinds the store still holds.
    fn rows(&self) -> Vec<(String, String, u64)> {
        self.records
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .filter(|(k, _, _)| k.starts_with(LABEL))
            .cloned()
            .collect()
    }

    /// Age every record that says when it was written (an `at` member) by `secs`, as if it had
    /// been written that much earlier.
    fn age(&self, secs: u64) {
        let mut records = self.records.lock().unwrap_or_else(|p| p.into_inner());
        for (_, body) in records.values_mut() {
            let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(body) else {
                continue;
            };
            let Some(at) = v.get("at").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            v["at"] = serde_json::json!(at.saturating_sub(secs));
            *body = serde_json::to_vec(&v).expect("a JSON body serializes");
        }
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
        let stall = self.stalled("get", kind);
        Box::pin(async move {
            if let Some(by) = stall {
                tokio::time::sleep(by).await;
            }
            Ok(got)
        })
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
        let stall = self.stalled("redeem", kind);
        Box::pin(async move {
            if let Some(by) = stall {
                tokio::time::sleep(by).await;
            }
            Ok(first)
        })
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

/// RED (audit core-oauth2 r4#1): a writer whose version claim lapsed before it wrote must not write.
/// Node A takes a code and stalls inside its version claim past the claim's lapse; node B then wins
/// the lapsed version and takes the same code. Before the fix A wrote anyway and both nodes held
/// the code: one authorization code redeemed twice.
#[tokio::test(start_paused = true)]
async fn a_take_whose_version_claim_lapsed_never_lands() {
    let store = OneStore::default();
    let node_b = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    node_b
        .put_client(client("agent-1"))
        .await
        .expect("registers");
    node_b
        .put_authorization_code(oauth_as::authorization::AuthorizationCodeRecord::new(
            "code-1",
            oauth_as::client::ClientId::new("agent-1"),
            "https://app.example.com/cb",
            oauth_as::scope::ScopeSet::default(),
            "busbar-operator",
            "challenge",
            std::time::SystemTime::now() + std::time::Duration::from_secs(600),
        ))
        .await
        .expect("issues");

    let stall = std::time::Duration::from_secs(VERSION_CLAIM_SECS + 10);
    store.stall("redeem", "bucket.v", stall);
    let node_a = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    let a = tokio::spawn(async move { node_a.take_authorization_code("code-1").await });
    tokio::time::sleep(std::time::Duration::from_secs(VERSION_CLAIM_SECS + 1)).await;
    let b = node_b.take_authorization_code("code-1").await;
    let a = a.await.expect("node A ran");
    let taken = [&a, &b].iter().filter(|t| matches!(t, Ok(Some(_)))).count();
    assert_eq!(
        taken, 1,
        "one authorization code was taken {taken} times (node A: {a:?}, node B: {b:?})"
    );
}

/// RED (audit core-oauth2 r4#1, the key): a minting winner whose claim lapsed before it wrote must
/// not keep a key. Node A wins the minting claim and stalls reading the store past the claim's
/// lapse; node C wins the lapsed claim and keeps its key. Before the fix A then minted and kept a
/// second key over C's, so the two nodes signed with different keys.
#[tokio::test(start_paused = true)]
async fn a_minting_winner_whose_claim_lapsed_keeps_no_second_key() {
    let store = OneStore::default();
    // A's first read is answered at once (nothing kept); its read after the won claim stalls.
    let a_store = store.clone();
    let a = tokio::spawn(async move {
        let shared = Shared::new(a_store.calls());
        a_store.stall("get", "key", std::time::Duration::ZERO);
        a_store.stall(
            "get",
            "key",
            std::time::Duration::from_secs(MINT_CLAIM_SECS + 10),
        );
        shared.signing_key(|| Ok(vec![1, 1, 1])).await
    });
    tokio::time::sleep(std::time::Duration::from_secs(MINT_CLAIM_SECS + 1)).await;
    let c = Shared::new(store.calls())
        .signing_key(|| Ok(vec![3, 3, 3]))
        .await;
    let a = a.await.expect("node A ran");
    let kept = Shared::new(store.calls())
        .signing_key(|| Ok(vec![9, 9, 9]))
        .await;
    for (node, key) in [("A", &a), ("C", &c)] {
        if let Ok(key) = key {
            assert_eq!(
                Ok(key),
                kept.as_ref(),
                "node {node} signs with a key the store does not keep (A: {a:?}, C: {c:?}, kept: \
                 {kept:?})"
            );
        }
    }
}

/// RED (audit core-oauth2 r4#2): the sweep reclaims what has lapsed. A client registers, takes a
/// code, holds a token family that is revoked, opens a consent session and stakes an answer on it,
/// claims a replay id, and is deleted; once every record, barrier and session has lapsed, a sweep
/// leaves none of the server's rows behind. Before the fix index rows, sessions, stakes, the
/// family barrier and the client's bucket were kept forever.
#[tokio::test]
async fn a_sweep_past_every_expiry_leaves_no_record_behind() {
    use oauth_as::store::RevocationWindow;
    let store = OneStore::default();
    let shared = Arc::new(Shared::new(store.calls()));
    let s = SharedStorage::new(Arc::clone(&shared));
    let now = std::time::SystemTime::now();
    let hour = std::time::Duration::from_secs(3600);
    let id = oauth_as::client::ClientId::new("agent-1");
    let subject = Some("busbar-operator".to_string());

    s.put_client(client("agent-1")).await.expect("registers");
    s.put_authorization_code(oauth_as::authorization::AuthorizationCodeRecord::new(
        "code-1",
        id.clone(),
        "https://app.example.com/cb",
        oauth_as::scope::ScopeSet::default(),
        "busbar-operator",
        "challenge",
        now + std::time::Duration::from_secs(60),
    ))
    .await
    .expect("issues a code");
    assert!(s
        .take_authorization_code("code-1")
        .await
        .expect("takes")
        .is_some());
    let mut access = oauth_as::token::IssuedToken::new(
        "at-1",
        id.clone(),
        subject.clone(),
        oauth_as::scope::ScopeSet::default(),
        now,
        now + hour,
    );
    access.family_id = Some("fam-1".to_string());
    let _ = s.put_token(access).await.expect("issues a token");
    let mut refresh = oauth_as::token::RefreshTokenRecord::new(
        "rt-1",
        id.clone(),
        subject.clone(),
        oauth_as::scope::ScopeSet::default(),
        "fam-1",
    );
    refresh.expires_at = Some(now + 2 * hour);
    let _ = s
        .put_refresh_token(refresh)
        .await
        .expect("issues a refresh token");
    s.revoke_token_family(
        "fam-1",
        RevocationWindow {
            recorded_at: now,
            until: now + 2 * hour,
        },
    )
    .await
    .expect("revokes the family");
    shared
        .open_session(
            "session-1",
            "busbar-operator",
            std::time::Duration::from_secs(600),
        )
        .await
        .expect("opens a session");
    shared
        .stake(
            "session-1",
            "key-1",
            true,
            std::time::Duration::from_secs(600),
        )
        .await
        .expect("stakes");
    assert!(s
        .claim_replay_id("jti-1", now + std::time::Duration::from_secs(60))
        .await
        .expect("claims"));
    assert!(s
        .delete_client(
            &id,
            RevocationWindow {
                recorded_at: now,
                until: now + 2 * hour,
            },
        )
        .await
        .expect("deletes"));

    // Three hours on: every record, barrier, session and answer above has lapsed.
    store.age(3 * 3600);
    let later = now + 3 * hour;
    s.sweep_expired(later).await.expect("sweeps");
    s.sweep_expired(later).await.expect("sweeps again");
    let left = store.rows();
    assert!(left.is_empty(), "rows the sweep never reclaims: {left:#?}");
}

/// How many held-back point reads of the server's `bucket` records are still unspent.
fn bucket_reads_left(store: &OneStore) -> usize {
    let bucket = format!("{LABEL}bucket");
    store
        .stalls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .filter(|(slot, kind, _)| *slot == "get" && *kind == bucket)
        .count()
}

/// RED: the sweep judges each client's records on the body its listing already read, and reads a
/// client's records again only when it has something to reclaim. Ten clients that hold nothing
/// lapsed cost no point read; one whose code has lapsed is still read and swept. Before the fix
/// the sweep read every client's records a second time, every minute, on every node.
#[tokio::test]
async fn the_sweep_reads_again_only_the_records_it_changes() {
    let store = OneStore::default();
    let s = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    for i in 0..10 {
        s.put_client(client(&format!("idle-{i}")))
            .await
            .expect("registers");
    }
    s.put_client(client("lapsing")).await.expect("registers");
    s.put_authorization_code(code("code-1", "lapsing"))
        .await
        .expect("issues a code");
    // Every point read of a bucket from here spends one of these, so what is left counts them.
    for _ in 0..32 {
        store.stall("get", "bucket", std::time::Duration::ZERO);
    }
    let later = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
    let removed = s.sweep_expired(later).await.expect("sweeps");
    assert_eq!(removed, 1, "the lapsed code is reclaimed");
    assert_eq!(
        32 - bucket_reads_left(&store),
        1,
        "only the client with something lapsed is read again"
    );
    assert!(
        s.take_authorization_code("code-1")
            .await
            .expect("takes")
            .is_none(),
        "the lapsed code is gone"
    );
}

fn code(code: &str, client_id: &str) -> oauth_as::authorization::AuthorizationCodeRecord {
    oauth_as::authorization::AuthorizationCodeRecord::new(
        code,
        oauth_as::client::ClientId::new(client_id),
        "https://app.example.com/cb",
        oauth_as::scope::ScopeSet::default(),
        "busbar-operator",
        "challenge",
        std::time::SystemTime::now() + std::time::Duration::from_secs(600),
    )
}

/// RED (row 159): a cell the sweep retired never blocks the cell made again under its id. The sweep
/// retires an emptied bucket at version 2 under the claim on version 3, which stands for two
/// minutes; a client whose records come back inside them climbs to version 3 again. Before the fix
/// that write lost the retirement's claim on every attempt and answered a storage error (a login
/// failing at the token endpoint); now the made-again cell's claims name an epoch of their own.
#[tokio::test(start_paused = true)]
async fn a_retired_cell_never_blocks_its_own_recreation() {
    let store = OneStore::default();
    let s = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    s.put_authorization_code(code("code-1", "agent-1"))
        .await
        .expect("version 1");
    assert!(s
        .take_authorization_code("code-1")
        .await
        .expect("version 2")
        .is_some());
    // Long enough ago that every claim on versions 1 and 2 has lapsed, and the sweep retires the
    // emptied bucket, under the claim on version 3.
    tokio::time::advance(std::time::Duration::from_secs(VERSION_CLAIM_SECS + 60)).await;
    store.age(3600);
    s.sweep_expired(std::time::SystemTime::now())
        .await
        .expect("sweeps");
    let bucket = format!("{LABEL}bucket");
    assert!(
        store.rows().iter().all(|(k, _, _)| *k != bucket),
        "the emptied bucket was retired"
    );

    s.put_authorization_code(code("code-2", "agent-1"))
        .await
        .expect("version 1 again");
    assert!(s
        .take_authorization_code("code-2")
        .await
        .expect("version 2 again")
        .is_some());
    s.put_authorization_code(code("code-3", "agent-1"))
        .await
        .expect(
            "version 3 of the made-again bucket is written while the retirement's claim stands",
        );
    assert!(
        s.take_authorization_code("code-3")
            .await
            .expect("version 4")
            .is_some(),
        "the code written at version 3 is held"
    );
}

/// RED (row 159): with the store, a second answer to one request on one session is spent, once, as
/// the in-process table spends it. Before the fix the spend claim named only the session and the
/// request, so it stood from the first answer's spend and a second answer could never be spent:
/// `/authorize` sent the operator back to the consent screen for the session's life.
#[tokio::test]
async fn a_second_answer_on_one_session_is_spent_once() {
    let store = OneStore::default();
    let shared = Shared::new(store.calls());
    let ttl = std::time::Duration::from_secs(600);
    shared
        .open_session("session-1", "busbar-operator", ttl)
        .await
        .expect("opens");
    shared
        .stake("session-1", "key-1", true, ttl)
        .await
        .expect("stakes");
    assert_eq!(
        shared.spend("session-1", "key-1").await.expect("spends"),
        Some(true)
    );
    shared
        .stake("session-1", "key-1", false, ttl)
        .await
        .expect("stakes again");
    assert_eq!(
        shared.spend("session-1", "key-1").await.expect("spends"),
        Some(false),
        "the second answer was never spent"
    );
    assert_eq!(
        shared.spend("session-1", "key-1").await.expect("spends"),
        None,
        "one answer was spent twice"
    );
}

/// RED (row 159): in the deployment's store, a self-registered client whose bucket has held nothing
/// for the idle period is reclaimed by the sweep, bucket and all. Before the fix a bucket holding a
/// client never held nothing, so it was kept for good.
#[tokio::test]
async fn an_idle_self_registered_client_leaves_the_store() {
    use oauth_as::client::ClientId;
    let store = OneStore::default();
    let p = plane(&node(Some(&store), None, Vec::new()));
    let info = p
        .server()
        .register_dynamic_client(
            &oauth_as::registration::ClientMetadata {
                redirect_uris: vec!["http://127.0.0.1:3000/callback".to_string()],
                token_endpoint_auth_method: Some("none".to_string()),
                grant_types: None,
                response_types: Some(vec!["code".to_string()]),
                client_name: Some("an agent".to_string()),
                scope: None,
                software_statement: None,
            },
            None,
        )
        .await
        .expect("registers");
    let id = ClientId::new(info.client_id);
    // A client stored with no registration (none of the server's own paths store one) is kept.
    p.server()
        .store()
        .put_client(client("agent-1"))
        .await
        .expect("stores");
    store.age(crate::policy::REGISTERED_CLIENT_IDLE.as_secs() + 60);
    p.server()
        .store()
        .sweep_expired(std::time::SystemTime::now())
        .await
        .expect("sweeps");
    assert!(
        p.server()
            .store()
            .get_client(&id)
            .await
            .expect("reads")
            .is_none(),
        "an idle self-registered client was kept"
    );
    assert!(
        p.server()
            .store()
            .get_client(&ClientId::new("agent-1"))
            .await
            .expect("reads")
            .is_some(),
        "a client nobody registered was reclaimed"
    );
    let bucket = format!("{LABEL}bucket");
    assert_eq!(
        store.rows().iter().filter(|(k, _, _)| *k == bucket).count(),
        1,
        "the reclaimed client's bucket is still kept"
    );
}
