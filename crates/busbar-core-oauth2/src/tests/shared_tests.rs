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
use std::sync::{Arc, Mutex};

use busbar_contract::abi::sdk::store::conditional::{Decision, Expected, Mutation, Request};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta};
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};
use oauth_as::store::Storage as _;

use crate::config::OauthAsCfg;
use crate::plane::{seam_build, AsPlane};
use crate::shared::{Shared, SharedStorage, LABEL, VERSION_CLAIM_SECS};

/// `(kind, parent or else id, seq)` to `(parent, body)`, as the linked in-tree store keys them.
type Records = BTreeMap<(String, String, u64), (Option<String>, Vec<u8>)>;

/// One answer the double holds back: the slot (`get` or `redeem`), the record kind it is for, and
/// how long the answer takes after the store has decided it.
type Stall = (&'static str, String, std::time::Duration);

/// The double. Cheap to clone; every clone is the same store.
#[derive(Clone, Default)]
struct OneStore {
    records: Arc<Mutex<Records>>,
    /// Claims derive their remaining seconds from store wall time, never caller time; a timer
    /// includes the deadline second. The paused runtime advances those timers, so a test
    /// on a paused clock moves every claim's lapse with it.
    claims: Arc<Mutex<BTreeMap<(String, String), tokio::time::Instant>>>,
    stalls: Arc<Mutex<Vec<Stall>>>,
    atomic: Arc<Mutex<AtomicRecords>>,
    decisions: Arc<Mutex<Vec<DecisionDelay>>>,
}

pub(super) fn test_store_calls() -> Arc<dyn StoreCalls> {
    OneStore::default().calls()
}

type AtomicRows = BTreeMap<(String, Vec<u8>), Vec<u8>>;

#[derive(Default)]
struct AtomicRecords {
    rows: AtomicRows,
    receipts: BTreeMap<[u8; 16], Request>,
    calls: Vec<Request>,
}

/// Backend work is owned by its task, independently of the client awaiting the answer.
struct DecisionDelay {
    schema: String,
    before: Option<Arc<tokio::sync::Notify>>,
    accepted: Arc<tokio::sync::Notify>,
    decided: Arc<tokio::sync::Notify>,
    lose_answer: bool,
}

impl OneStore {
    fn delay_decision(
        &self,
        name: &str,
        lose_answer: bool,
    ) -> (
        Arc<tokio::sync::Notify>,
        Arc<tokio::sync::Notify>,
        Arc<tokio::sync::Notify>,
    ) {
        let release = Arc::new(tokio::sync::Notify::new());
        let accepted = Arc::new(tokio::sync::Notify::new());
        let decided = Arc::new(tokio::sync::Notify::new());
        self.decisions.lock().unwrap().push(DecisionDelay {
            schema: format!("{LABEL}{name}.atomic.v1"),
            before: Some(release.clone()),
            accepted: accepted.clone(),
            decided: decided.clone(),
            lose_answer,
        });
        (release, accepted, decided)
    }

    fn decide(&self, request: &Request) -> Result<Decision, StoreFailure> {
        request
            .validate()
            .map_err(|e| StoreFailure::Refused(e.into()))?;
        let mut state = self.atomic.lock().unwrap();
        state.calls.push(request.clone());
        if let Some(applied) = state.receipts.get(&request.op_id.0) {
            return if applied == request {
                Ok(Decision::Applied)
            } else {
                Err(StoreFailure::Conflict)
            };
        }
        if request.predicates.iter().any(|p| {
            let value = state.rows.get(&(p.schema.clone(), p.key.clone()));
            match &p.expected {
                Expected::Absent => value.is_some(),
                Expected::Bytes(bytes) => value != Some(bytes),
            }
        }) {
            return Ok(Decision::ConditionConflict);
        }
        apply_mutations(&mut state.rows, &request.mutations);
        state.receipts.insert(request.op_id.0, request.clone());
        Ok(Decision::Applied)
    }

    fn calls(&self) -> Arc<dyn StoreCalls> {
        Arc::new(self.clone())
    }

    /// Redeem `(kind, token)` as another node would.
    fn redeem(&self, kind: &str, token: &str, expires_at: u64, _now: u64) -> bool {
        let mut claims = self.claims.lock().unwrap_or_else(|p| p.into_inner());
        let store_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if expires_at < store_now {
            return false;
        }
        let at = tokio::time::Instant::now();
        let remaining = expires_at.saturating_sub(store_now).saturating_add(1);
        let lapses = at + std::time::Duration::from_secs(remaining);
        claims.retain(|_, deadline| *deadline > at);
        match claims.entry((kind.to_string(), token.to_string())) {
            std::collections::btree_map::Entry::Occupied(_) => false,
            std::collections::btree_map::Entry::Vacant(row) => {
                row.insert(lapses);
                true
            }
        }
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
        self.visible()
            .keys()
            .filter(|(k, _, _)| k.starts_with(LABEL))
            .cloned()
            .collect()
    }

    /// Logical live rows: raw authority suppresses legacy rows, including after retirement.
    /// Physical tombstones remain observable through `atomic.rows` for fencing assertions.
    fn visible(&self) -> Records {
        let mut rows = self.records.lock().unwrap().clone();
        for ((schema, key), value) in &logical_rows(&self.atomic.lock().unwrap().rows) {
            let Some(kind) = schema.strip_suffix(".atomic.v1") else {
                continue;
            };
            let id = String::from_utf8(key.clone()).expect("OAuth digest/id");
            rows.retain(|(k, i, _), _| k != kind || i != &id);
            if let Some(body) = crate::shared::authority_body(value).expect("valid authority") {
                rows.insert((kind.to_string(), id, 0), (None, body.to_vec()));
            }
        }
        rows
    }

    /// Age every record that says when it was written (an `at` member, at any depth) by `secs`,
    /// as if it had been written that much earlier.
    fn age(&self, secs: u64) {
        fn older(v: &mut serde_json::Value, secs: u64) {
            match v {
                serde_json::Value::Object(map) => {
                    for (k, member) in map.iter_mut() {
                        match member.as_u64() {
                            Some(at) if k == "at" => {
                                *member = serde_json::json!(at.saturating_sub(secs))
                            }
                            _ => older(member, secs),
                        }
                    }
                }
                serde_json::Value::Array(items) => items.iter_mut().for_each(|i| older(i, secs)),
                _ => {}
            }
        }
        let mut records = self.records.lock().unwrap_or_else(|p| p.into_inner());
        for (_, body) in records.values_mut() {
            let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(body) else {
                continue;
            };
            older(&mut v, secs);
            *body = serde_json::to_vec(&v).expect("a JSON body serializes");
        }
        drop(records);
        self.rewrite_atomic(|_, value| older(value, secs));
    }

    fn age_indexes(&self, secs: u64) {
        let prefix = format!("{LABEL}ix.");
        self.rewrite_atomic(|schema, value| {
            if schema.starts_with(&prefix) {
                if let Some(at) = value.get("at").and_then(|at| at.as_u64()) {
                    value["at"] = serde_json::json!(at.saturating_sub(secs));
                }
            }
        });
    }

    /// The fixture's wall-clock adjustment changes logical cells, including their physical
    /// descriptors/chunks. It does not relax the double's real per-record validation.
    fn rewrite_atomic(&self, mut change: impl FnMut(&str, &mut serde_json::Value)) {
        let mut state = self.atomic.lock().unwrap();
        for ((schema, key), body) in logical_rows(&state.rows) {
            let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&body) else {
                continue;
            };
            let original = value.clone();
            change(&schema, &mut value);
            if value == original {
                continue;
            }
            let candidate = Shared::candidate(
                &schema,
                std::str::from_utf8(&key).expect("OAuth root id"),
                Some(body),
                serde_json::to_vec(&value).unwrap(),
            );
            let physical = crate::shared::records::physical(candidate, &[]).unwrap();
            physical.validate().unwrap();
            apply_mutations(&mut state.rows, &physical.mutations);
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
    fn supports_record_transaction(&self) -> bool {
        true
    }

    fn record_transaction<'a>(&'a self, request: &'a Request) -> StoreCall<'a, Decision> {
        let delayed = {
            let mut delays = self.decisions.lock().unwrap();
            delays
                .iter()
                .position(|d| request.predicates.iter().any(|p| p.schema == d.schema))
                .map(|i| delays.remove(i))
        };
        if let Some(delay) = delayed {
            let store = self.clone();
            let request = request.clone();
            let (answer, receiver) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                delay.accepted.notify_one();
                if let Some(release) = delay.before {
                    release.notified().await;
                }
                let decision = store.decide(&request);
                delay.decided.notify_one();
                let result = if delay.lose_answer {
                    Err(StoreFailure::Fault("lost committed answer".into()))
                } else {
                    decision
                };
                let _ = answer.send(result);
            });
            return Box::pin(async move { receiver.await.expect("backend task answers") });
        }
        let result = self.decide(request);
        Box::pin(async move { result })
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
    fn record_put<'a>(&'a self, _: &'a str, _: &'a [u8], _: &'a RecordBytes) -> StoreCall<'a, ()> {
        not_this()
    }
    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        let got = self
            .atomic
            .lock()
            .unwrap()
            .rows
            .get(&(schema.into(), key.to_vec()))
            .cloned()
            .map(|b| RecordBytes::new(b).expect("bounded test row"));
        let name = schema.strip_suffix(".atomic.v1").unwrap_or(schema);
        let stall = self.stalled("get", name);
        Box::pin(async move {
            if let Some(by) = stall {
                tokio::time::sleep(by).await;
            }
            Ok(got)
        })
    }
    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        let rows = self
            .atomic
            .lock()
            .unwrap()
            .rows
            .iter()
            .filter(|((s, k), _)| s == schema && k.starts_with(prefix))
            .take(limit as usize)
            .map(|((_, k), v)| {
                (
                    k.clone(),
                    RecordBytes::new(v.clone()).expect("bounded test row"),
                )
            })
            .collect();
        Box::pin(async move { Ok(rows) })
    }
    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        let delayed = {
            let mut delays = self.decisions.lock().unwrap();
            delays
                .iter()
                .position(|d| d.schema == format!("{}.atomic.v1", record.kind))
                .map(|i| delays.remove(i))
        };
        if let Some(delay) = delayed {
            let store = self.clone();
            let kind = record.kind.to_string();
            let id = record.id.to_string();
            let body = record.body.to_vec();
            let (answer, receiver) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                delay.accepted.notify_one();
                if let Some(release) = delay.before {
                    release.notified().await;
                }
                store.put(&kind, &id, &body);
                delay.decided.notify_one();
                let _ = answer.send(Ok(()));
            });
            return Box::pin(async move { receiver.await.expect("backend task answers") });
        }
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

/// Store capability refusal applies even when a configured signing key bypasses minting.
#[tokio::test]
async fn a_store_without_conditional_transactions_fails_closed() {
    struct Unsupported;
    impl StoreCalls for Unsupported {
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
        fn record_put<'a>(
            &'a self,
            _: &'a str,
            _: &'a [u8],
            _: &'a RecordBytes,
        ) -> StoreCall<'a, ()> {
            panic!("must not emulate")
        }
        fn record_get<'a>(&'a self, _: &'a str, _: &'a [u8]) -> StoreCall<'a, Option<RecordBytes>> {
            panic!("must refuse before reads")
        }
        fn record_scan<'a>(
            &'a self,
            _: &'a str,
            _: &'a [u8],
            _: u32,
        ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
            panic!("must refuse before scans")
        }
        fn upsert_plane_record<'a>(&'a self, _: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
            panic!("must refuse before plane writes")
        }
        fn get_plane_record<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
        ) -> StoreCall<'a, Option<Vec<u8>>> {
            panic!("must refuse before plane reads")
        }
        fn append_plane_record<'a>(&'a self, _: OpId, _: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
            panic!("must refuse before plane appends")
        }
        fn list_plane_records<'a>(
            &'a self,
            _: &'a str,
            _: &'a PlaneSelector<'a>,
        ) -> StoreCall<'a, Vec<Vec<u8>>> {
            panic!("must refuse before plane scans")
        }
        fn delete_plane_record<'a>(&'a self, _: &'a str, _: &'a str) -> StoreCall<'a, ()> {
            panic!("must refuse before plane deletes")
        }
        fn redeem_plane_token<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: u64,
            _: u64,
        ) -> StoreCall<'a, bool> {
            panic!("must refuse before token redemption")
        }
        fn plane_token_live<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: u64,
            _: u64,
        ) -> StoreCall<'a, bool> {
            panic!("must refuse before token liveness reads")
        }
    }
    let calls: Arc<dyn StoreCalls> = Arc::new(Unsupported);
    assert!(Shared::require_atomic(calls.as_ref()).is_err());
    let shared = Arc::new(Shared::new(calls));
    let storage = SharedStorage::new(shared.clone());
    assert!(storage.put_client(client("unsupported")).await.is_err());
    assert!(storage
        .get_client(&oauth_as::client::ClientId::new("unsupported"))
        .await
        .is_err());
    assert!(shared
        .open_session("unsupported", "alice", std::time::Duration::from_secs(60))
        .await
        .is_err());
    assert!(shared
        .signing_key(|| panic!("must refuse before mint"))
        .await
        .is_err());
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

/// Backend decisions can arrive after the old lease window; an unexpired refresh token is taken
/// once. Authorization-code lifetime is too short to witness a 120-second delayed spend.
#[tokio::test(start_paused = true)]
async fn a_late_refresh_take_conflicts_after_another_node_took_it() {
    let store = OneStore::default();
    let node_b = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    node_b
        .put_client(client("atomic-client"))
        .await
        .expect("registers");
    assert_eq!(
        node_b
            .put_refresh_token(refresh("take-refresh"))
            .await
            .expect("issues"),
        oauth_as::store::WriteOutcome::Applied
    );

    let (release, accepted, decided) = store.delay_decision("bucket", false);
    let node_a = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    let a = tokio::spawn(async move { node_a.take_refresh_token("take-refresh").await });
    accepted.notified().await;
    tokio::time::advance(std::time::Duration::from_secs(VERSION_CLAIM_SECS + 1)).await;
    let b = node_b.take_refresh_token("take-refresh").await;
    release.notify_one();
    decided.notified().await;
    let a = a.await.expect("node A ran");
    let taken = [&a, &b].iter().filter(|t| matches!(t, Ok(Some(_)))).count();
    assert_eq!(
        taken, 1,
        "one refresh token was taken {taken} times (node A: {a:?}, node B: {b:?})"
    );
}

/// A stale absent read cannot replace a key another node kept in the meantime.
#[tokio::test(start_paused = true)]
async fn a_key_minter_with_a_stale_read_uses_the_committed_key() {
    let store = OneStore::default();
    // The raw read is absent; the following legacy-fallback read stalls.
    let a_store = store.clone();
    let a = tokio::spawn(async move {
        let shared = Shared::new(a_store.calls());
        a_store.stall("get", "key", std::time::Duration::ZERO);
        a_store.stall(
            "get",
            "key",
            std::time::Duration::from_secs(VERSION_CLAIM_SECS + 10),
        );
        shared.signing_key(|| Ok(vec![1, 1, 1])).await
    });
    tokio::time::sleep(std::time::Duration::from_secs(VERSION_CLAIM_SECS + 1)).await;
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
/// leaves none of the server's live payloads behind. Raw authority retains credential-free unique
/// retirement markers, which prevent legacy resurrection and ABA. Before the fix index rows, sessions, stakes, the
/// family barrier and the client's bucket were kept forever.
#[tokio::test]
async fn a_sweep_past_every_expiry_leaves_no_live_payload_behind() {
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
    assert!(
        store
            .atomic
            .lock()
            .unwrap()
            .rows
            .values()
            .all(|body| crate::shared::authority_body(body).unwrap().is_none()),
        "only credential-free retirement markers may remain physically stored"
    );
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

/// A cell the sweep retired never blocks the cell made again under its id. The sweep
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

/// With the store, a second answer to one request on one session is spent, once, as
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

/// In the deployment's store, a self-registered client whose bucket has held nothing
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

/// The keys of every row of the server's record kind `name` the store still holds.
fn rows_of(store: &OneStore, name: &str) -> Vec<String> {
    let k = format!("{LABEL}{name}");
    store
        .rows()
        .into_iter()
        .filter(|(kind, _, _)| *kind == k)
        .map(|(_, id, _)| id)
        .collect()
}

/// Whether any row of the server's record kind `name` names `word` in its body.
fn names(store: &OneStore, name: &str, word: &str) -> bool {
    let k = format!("{LABEL}{name}");
    store
        .visible()
        .iter()
        .filter(|((kind, _, _), _)| *kind == k)
        .any(|(_, (_, body))| body.windows(word.len()).any(|w| w == word.as_bytes()))
}

/// A subject's index entry for a client is reclaimed once that client
/// no longer holds a consent of the subject, and only then; once no client holds one, nothing of
/// the subject's index is left. Two clients hold `alice`'s consent; one is withdrawn, then the
/// other. Before the fix every subject index row was kept forever.
#[tokio::test]
async fn a_sweep_reclaims_a_subject_index_its_clients_no_longer_hold() {
    use oauth_as::store::RevocationWindow;
    let store = OneStore::default();
    let shared = Arc::new(Shared::new(store.calls()));
    let s = SharedStorage::new(Arc::clone(&shared));
    let now = std::time::SystemTime::now();
    let window = RevocationWindow {
        recorded_at: now,
        until: now + std::time::Duration::from_secs(60),
    };
    let consent = |id: &str, client: &str| oauth_as::consent::ConsentRecord {
        consent_id: id.into(),
        client_id: oauth_as::client::ClientId::new(client),
        subject: "alice".into(),
        scope: oauth_as::scope::ScopeSet::default(),
        resource: Vec::new(),
        granted_at: now,
        authentication: None,
    };
    for (id, client_id) in [("c-1", "agent-1"), ("c-2", "agent-2")] {
        s.put_client(client(client_id)).await.expect("registers");
        s.put_consent(consent(id, client_id))
            .await
            .expect("records the consent");
    }
    assert!(names(&store, "ix.subj", "agent-1") && names(&store, "ix.subj", "agent-2"));
    s.revoke_consent("c-1", window).await.expect("withdraws");

    store.age(crate::shared::INDEX_GRACE_SECS + 1);
    s.sweep_expired(now).await.expect("sweeps");
    let held = s.consents_for_subject("alice").await.expect("lists");
    assert_eq!(held.len(), 1, "the kept consent is still found");
    assert_eq!(held[0].client_id.as_str(), "agent-2");
    assert!(
        !names(&store, "ix.subj", "agent-1"),
        "the withdrawn client's subject entry is reclaimed"
    );
    assert!(
        names(&store, "ix.subj", "agent-2"),
        "the holder's subject entry is kept"
    );

    s.revoke_consent("c-2", window).await.expect("withdraws");
    store.age(crate::shared::INDEX_GRACE_SECS + crate::shared::RETIRE_AFTER_SECS + 1);
    let later = now + std::time::Duration::from_secs(3600);
    s.sweep_expired(later).await.expect("sweeps");
    s.sweep_expired(later).await.expect("sweeps again");
    assert_eq!(
        rows_of(&store, "ix.subj"),
        Vec::<String>::new(),
        "no client holds alice's consent: nothing of her index is left"
    );
    assert!(s
        .consents_for_subject("alice")
        .await
        .expect("lists")
        .is_empty());
}

/// RED (audit core-oauth2, the sweep-abort note): one index row whose client's records cannot be
/// read is said and skipped; it never ends the pass. A credential index row whose client's bucket
/// does not decode comes first; a lapsed row of a later index must still be reclaimed. Before the
/// fix the `?` on that read ended the whole index sweep.
#[tokio::test]
async fn one_unreadable_client_never_ends_the_index_sweep() {
    let store = OneStore::default();
    let shared = Arc::new(Shared::new(store.calls()));
    let s = SharedStorage::new(Arc::clone(&shared));
    store.put(
        &format!("{LABEL}bucket"),
        &crate::shared::digest("unreadable"),
        b"not a bucket",
    );
    shared
        .index("tok", "at-unreadable", "unreadable")
        .await
        .expect("indexes");
    shared
        .index("rt", "rt-gone", "agent-1")
        .await
        .expect("indexes");
    store.age(crate::shared::INDEX_GRACE_SECS + 1);
    s.sweep_expired(std::time::SystemTime::now())
        .await
        .expect("sweeps");
    assert_eq!(
        rows_of(&store, "ix.rt"),
        Vec::<String>::new(),
        "a later index is swept past the unreadable client"
    );
    assert_eq!(
        rows_of(&store, "ix.tok").len(),
        1,
        "the row it could not judge is kept"
    );
}

#[tokio::test]
async fn a_replay_claim_does_not_extend_an_expired_absolute_deadline() {
    let store = OneStore::default();
    let storage = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    let expired = std::time::SystemTime::UNIX_EPOCH;
    assert!(!storage
        .claim_replay_id("expired-absolute-deadline", expired)
        .await
        .expect("claim"));
}

fn refresh(value: &str) -> oauth_as::token::RefreshTokenRecord {
    let mut record = oauth_as::token::RefreshTokenRecord::new(
        value,
        oauth_as::client::ClientId::new("atomic-client"),
        Some("alice".into()),
        oauth_as::scope::ScopeSet::default(),
        "atomic-family",
    );
    record.expires_at =
        Some(std::time::SystemTime::now() + std::time::Duration::from_secs(30 * 24 * 3600));
    record
}

/// The backend decides after the client future was dropped, past the old claim's lifetime.
/// This uses an unexpired refresh token: authorization-code lifetimes cannot witness this race.
#[tokio::test(start_paused = true)]
async fn a_late_cancelled_write_cannot_undo_client_revocation() {
    let store = OneStore::default();
    let a = Arc::new(SharedStorage::new(Arc::new(Shared::new(store.calls()))));
    let b = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    a.put_client(client("atomic-client"))
        .await
        .expect("registers");
    let (release, accepted, decided) = store.delay_decision("bucket", false);
    let writer = {
        let a = a.clone();
        tokio::spawn(async move { a.put_refresh_token(refresh("late-refresh")).await })
    };
    accepted.notified().await;
    writer.abort();
    assert!(writer.await.expect_err("client cancelled").is_cancelled());
    drop(a); // A restart loses the volatile pending table; the backend comparison still fences it.
    tokio::time::advance(std::time::Duration::from_secs(VERSION_CLAIM_SECS + 60)).await;
    let now = std::time::SystemTime::now();
    b.delete_client(
        &oauth_as::client::ClientId::new("atomic-client"),
        oauth_as::store::RevocationWindow {
            recorded_at: now,
            until: now + std::time::Duration::from_secs(3600),
        },
    )
    .await
    .expect("revokes while old backend work is pending");
    release.notify_one();
    decided.notified().await;
    assert!(
        b.get_refresh_token("late-refresh")
            .await
            .expect("reads")
            .is_none(),
        "late backend write resurrected a revoked refresh token"
    );
    assert!(b
        .get_client(&oauth_as::client::ClientId::new("atomic-client"))
        .await
        .expect("reads client")
        .is_none());
}

#[tokio::test]
async fn a_lost_answer_replays_the_exact_candidate_and_applied_receipt() {
    let store = OneStore::default();
    let shared = Arc::new(Shared::new(store.calls()));
    let storage = Arc::new(SharedStorage::new(shared));
    storage
        .put_client(client("atomic-client"))
        .await
        .expect("registers");
    let (release, accepted, decided) = store.delay_decision("bucket", true);
    let writer = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.put_refresh_token(refresh("replay-refresh")).await })
    };
    accepted.notified().await;
    release.notify_one();
    decided.notified().await;
    assert!(
        writer.await.expect("writer answered").is_err(),
        "lost answer remains unknown"
    );
    let candidate = store
        .atomic
        .lock()
        .unwrap()
        .calls
        .last()
        .expect("submitted candidate")
        .clone();
    let other = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    let now = std::time::SystemTime::now();
    other
        .delete_client(
            &oauth_as::client::ClientId::new("atomic-client"),
            oauth_as::store::RevocationWindow {
                recorded_at: now,
                until: now + std::time::Duration::from_secs(3600),
            },
        )
        .await
        .unwrap();
    assert!(storage
        .get_refresh_token("replay-refresh")
        .await
        .expect("replays receipt before checking now-false predicates, then reads newer revocation")
        .is_none());
    let state = store.atomic.lock().unwrap();
    let replays: Vec<_> = state
        .calls
        .iter()
        .filter(|r| r.op_id == candidate.op_id)
        .collect();
    assert!(
        replays.len() >= 2,
        "the lost answer was inferred from rows instead of replayed"
    );
    assert!(
        replays.iter().all(|r| **r == candidate),
        "replay changed its operation id or exact candidate body"
    );
}

#[tokio::test]
async fn a_first_key_mint_race_keeps_one_key_after_a_late_decision() {
    let store = OneStore::default();
    let (release, accepted, decided) = store.delay_decision("key", false);
    let first = {
        let calls = store.calls();
        tokio::spawn(async move { Shared::new(calls).signing_key(|| Ok(vec![1, 1, 1])).await })
    };
    accepted.notified().await;
    let winner = Shared::new(store.calls())
        .signing_key(|| Ok(vec![2, 2, 2]))
        .await
        .expect("second node commits");
    release.notify_one();
    decided.notified().await;
    assert_eq!(
        first
            .await
            .expect("first node answers")
            .expect("uses winner"),
        winner
    );
    assert_eq!(
        Shared::new(store.calls())
            .signing_key(|| Ok(vec![3, 3, 3]))
            .await
            .expect("restart reads"),
        winner
    );
}

#[tokio::test]
async fn legacy_cells_and_keys_migrate_without_late_legacy_overwrites() {
    use base64::Engine as _;
    let store = OneStore::default();
    let id = crate::shared::digest("atomic-client");
    let mut bucket = crate::shared::Bucket {
        id: "atomic-client".into(),
        client: Some(client("atomic-client")),
        ..Default::default()
    };
    bucket
        .refresh
        .insert("legacy-refresh".into(), refresh("legacy-refresh"));
    let legacy = serde_json::to_vec(&crate::shared::Cell {
        v: 4,
        b: bucket,
        at: now_secs(),
        id: id.clone(),
        e: "legacy-epoch".into(),
    })
    .unwrap();
    store.put(&format!("{LABEL}bucket"), &id, &legacy);
    let shared = Arc::new(Shared::new(store.calls()));
    shared
        .index("rt", "legacy-refresh", "atomic-client")
        .await
        .unwrap();
    let storage = SharedStorage::new(shared);
    assert!(
        storage
            .get_refresh_token("legacy-refresh")
            .await
            .unwrap()
            .is_some(),
        "live legacy refresh token was lost"
    );
    let now = std::time::SystemTime::now();
    storage
        .delete_client(
            &oauth_as::client::ClientId::new("atomic-client"),
            oauth_as::store::RevocationWindow {
                recorded_at: now,
                until: now + std::time::Duration::from_secs(3600),
            },
        )
        .await
        .unwrap();
    store.put(&format!("{LABEL}bucket"), &id, &legacy);
    let restarted = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    assert!(
        restarted
            .get_refresh_token("legacy-refresh")
            .await
            .unwrap()
            .is_none(),
        "legacy writer overrode the authoritative revocation"
    );
    store.age(7200);
    restarted
        .sweep_expired(now + std::time::Duration::from_secs(7200))
        .await
        .unwrap();
    store.put(&format!("{LABEL}bucket"), &id, &legacy);
    assert!(
        SharedStorage::new(Arc::new(Shared::new(store.calls())))
            .get_refresh_token("legacy-refresh")
            .await
            .unwrap()
            .is_none(),
        "retirement fell back to stale legacy authority"
    );
    store.put(
        &format!("{LABEL}key"),
        "signing",
        base64::engine::general_purpose::STANDARD
            .encode([7u8, 7, 7])
            .as_bytes(),
    );
    assert_eq!(
        Shared::new(store.calls())
            .signing_key(|| panic!("must preserve legacy key"))
            .await
            .unwrap(),
        vec![7, 7, 7]
    );
    store.put(
        &format!("{LABEL}key"),
        "signing",
        base64::engine::general_purpose::STANDARD
            .encode([8u8, 8, 8])
            .as_bytes(),
    );
    assert_eq!(
        Shared::new(store.calls())
            .signing_key(|| panic!("must preserve authority"))
            .await
            .unwrap(),
        vec![7, 7, 7]
    );
}

#[tokio::test]
async fn a_cancelled_client_keeps_its_exact_candidate_for_replay() {
    let store = OneStore::default();
    let shared = Arc::new(Shared::new(store.calls()));
    let storage = Arc::new(SharedStorage::new(shared.clone()));
    storage.put_client(client("atomic-client")).await.unwrap();
    let (release, accepted, decided) = store.delay_decision("bucket", false);
    let mut writer = {
        let storage = storage.clone();
        tokio::spawn(async move {
            storage
                .put_refresh_token(refresh("cancelled-refresh"))
                .await
        })
    };
    tokio::select! {
        _ = accepted.notified() => {},
        result = &mut writer => panic!("write returned before the delayed backend accepted it: {result:?}"),
    }
    writer.abort();
    assert!(writer.await.unwrap_err().is_cancelled());
    let candidate = shared
        .pending
        .lock()
        .unwrap()
        .last()
        .expect("future drop retains candidate")
        .as_ref()
        .clone();
    assert!(
        storage
            .get_refresh_token("cancelled-refresh")
            .await
            .unwrap()
            .is_some(),
        "next access replays the retained candidate"
    );
    release.notify_one();
    decided.notified().await;
    let state = store.atomic.lock().unwrap();
    let submissions: Vec<_> = state
        .calls
        .iter()
        .filter(|r| r.op_id == candidate.op_id)
        .collect();
    assert_eq!(
        submissions.len(),
        2,
        "replay and late original backend decision share one receipt"
    );
    assert!(submissions.iter().all(|r| **r == candidate));
}

#[tokio::test]
async fn a_late_cancelled_write_cannot_bypass_the_family_barrier() {
    let store = OneStore::default();
    let a = Arc::new(SharedStorage::new(Arc::new(Shared::new(store.calls()))));
    let b = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    a.put_client(client("atomic-client")).await.unwrap();
    let (release, accepted, decided) = store.delay_decision("bucket", false);
    let writer = {
        let a = a.clone();
        tokio::spawn(async move { a.put_refresh_token(refresh("family-refresh")).await })
    };
    accepted.notified().await;
    writer.abort();
    assert!(writer.await.unwrap_err().is_cancelled());
    drop(a);
    let now = std::time::SystemTime::now();
    assert_eq!(
        b.revoke_token_family(
            "atomic-family",
            oauth_as::store::RevocationWindow {
                recorded_at: now,
                until: now + std::time::Duration::from_secs(3600)
            }
        )
        .await
        .unwrap(),
        0
    );
    release.notify_one();
    decided.notified().await;
    assert!(
        b.get_refresh_token("family-refresh")
            .await
            .unwrap()
            .is_none(),
        "family revocation completed before the old backend candidate"
    );
}

#[tokio::test]
async fn a_late_bucket_commit_restores_indexes_reclaimed_while_it_was_pending() {
    late_bucket_commit_restores_indexes("atomic-client").await;
}

#[tokio::test]
async fn a_late_bucket_commit_restores_chunked_indexes_for_a_long_client_id() {
    late_bucket_commit_restores_indexes(&format!("https://client.example/{}", "c".repeat(900)))
        .await;
}

async fn late_bucket_commit_restores_indexes(client_id: &str) {
    let store = OneStore::default();
    let a = Arc::new(SharedStorage::new(Arc::new(Shared::new(store.calls()))));
    let b = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    a.put_client(client(client_id)).await.unwrap();
    let (release, accepted, decided) = store.delay_decision("bucket", false);
    let mut grant = refresh("indexed-refresh");
    grant.client_id = oauth_as::client::ClientId::new(client_id);
    let mut writer = {
        let a = a.clone();
        tokio::spawn(async move { a.put_refresh_token(grant).await })
    };
    tokio::select! {
        _ = accepted.notified() => {},
        result = &mut writer => panic!("write returned before the delayed backend accepted it: {result:?}"),
    }
    writer.abort();
    assert!(writer.await.unwrap_err().is_cancelled());
    drop(a);
    store.age_indexes(crate::shared::INDEX_GRACE_SECS + 1);
    b.sweep_expired(std::time::SystemTime::now()).await.unwrap();
    assert!(
        rows_of(&store, "ix.rt").is_empty(),
        "uncommitted credential's old prewritten index was reclaimed"
    );
    release.notify_one();
    decided.notified().await;
    assert!(
        b.get_refresh_token("indexed-refresh")
            .await
            .unwrap()
            .is_some(),
        "late accepted bucket commit must also restore reachability"
    );
}

#[tokio::test]
async fn retirement_has_no_aba_across_recreation() {
    let store = OneStore::default();
    let a = Arc::new(SharedStorage::new(Arc::new(Shared::new(store.calls()))));
    let b = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    assert_eq!(
        b.put_refresh_token(refresh("initial-refresh"))
            .await
            .unwrap(),
        oauth_as::store::WriteOutcome::Applied
    );
    b.take_refresh_token("initial-refresh").await.unwrap();
    store.age(3600);
    b.sweep_expired(std::time::SystemTime::now()).await.unwrap();
    let schema = format!("{LABEL}bucket.atomic.v1");
    let key = crate::shared::digest("atomic-client").into_bytes();
    let first_retirement =
        store.atomic.lock().unwrap().rows[&(schema.clone(), key.clone())].clone();
    assert!(crate::shared::authority_body(&first_retirement)
        .unwrap()
        .is_none());
    let (release, accepted, decided) = store.delay_decision("bucket", false);
    let writer = {
        let a = a.clone();
        tokio::spawn(async move { a.put_refresh_token(refresh("stale-refresh")).await })
    };
    accepted.notified().await;
    writer.abort();
    assert!(writer.await.unwrap_err().is_cancelled());
    drop(a);
    assert_eq!(
        b.put_refresh_token(refresh("new-refresh")).await.unwrap(),
        oauth_as::store::WriteOutcome::Applied
    );
    b.take_refresh_token("new-refresh").await.unwrap();
    store.age(3600);
    b.sweep_expired(std::time::SystemTime::now()).await.unwrap();
    let second_retirement = store.atomic.lock().unwrap().rows[&(schema, key)].clone();
    assert_ne!(
        first_retirement, second_retirement,
        "each retirement must have a distinct comparison value"
    );
    release.notify_one();
    decided.notified().await;
    assert!(
        b.get_refresh_token("stale-refresh")
            .await
            .unwrap()
            .is_none(),
        "a candidate from an older retirement cycle must conflict"
    );
}

#[tokio::test]
async fn a_legacy_revocation_barrier_survives_its_first_import() {
    let store = OneStore::default();
    let now = std::time::SystemTime::now();
    let id = crate::shared::digest("atomic-client");
    let bucket = crate::shared::Bucket {
        id: "atomic-client".into(),
        client_barrier: Some(crate::shared::Times {
            recorded_at: now,
            until: now + std::time::Duration::from_secs(3600),
        }),
        ..Default::default()
    };
    let cell = crate::shared::Cell {
        v: 9,
        b: bucket,
        at: now_secs(),
        id: id.clone(),
        e: "legacy-revoked".into(),
    };
    store.put(
        &format!("{LABEL}bucket"),
        &id,
        &serde_json::to_vec(&cell).unwrap(),
    );
    let storage = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    assert!(matches!(
        storage
            .put_refresh_token(refresh("revoked-before-import"))
            .await
            .unwrap(),
        oauth_as::store::WriteOutcome::RefusedRevoked
    ));
    assert!(storage
        .get_refresh_token("revoked-before-import")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_cancelled_family_revocation_commits_its_barrier_and_cascade_together() {
    let store = OneStore::default();
    let a = Arc::new(SharedStorage::new(Arc::new(Shared::new(store.calls()))));
    let b = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    assert_eq!(
        a.put_refresh_token(refresh("existing-family-refresh"))
            .await
            .unwrap(),
        oauth_as::store::WriteOutcome::Applied
    );
    let (release, accepted, decided) = store.delay_decision("family", false);
    let revoker = {
        let a = a.clone();
        tokio::spawn(async move {
            let now = std::time::SystemTime::now();
            a.revoke_token_family(
                "atomic-family",
                oauth_as::store::RevocationWindow {
                    recorded_at: now,
                    until: now + std::time::Duration::from_secs(3600),
                },
            )
            .await
        })
    };
    accepted.notified().await;
    revoker.abort();
    assert!(revoker.await.unwrap_err().is_cancelled());
    drop(a);
    release.notify_one();
    decided.notified().await;
    assert!(
        b.get_refresh_token("existing-family-refresh")
            .await
            .unwrap()
            .is_none(),
        "backend decision cannot persist a barrier without its existing-token cascade"
    );
    assert!(matches!(
        b.put_refresh_token(refresh("new-family-refresh"))
            .await
            .unwrap(),
        oauth_as::store::WriteOutcome::RefusedRevoked
    ));
}

fn device(device_code: &str, user_code: &str) -> oauth_as::device::DeviceGrant {
    let now = std::time::SystemTime::now();
    oauth_as::device::DeviceGrant {
        device_code: device_code.into(),
        user_code: user_code.into(),
        client_id: oauth_as::client::ClientId::new("atomic-client"),
        scope: oauth_as::scope::ScopeSet::default(),
        state: oauth_as::device::DeviceGrantState::Pending,
        created_at: now,
        expires_at: now + std::time::Duration::from_secs(600),
        interval: std::time::Duration::from_secs(5),
        last_poll_at: None,
    }
}

#[tokio::test]
async fn a_cancelled_device_take_releases_its_user_code_in_the_backend_decision() {
    let store = OneStore::default();
    let a = Arc::new(SharedStorage::new(Arc::new(Shared::new(store.calls()))));
    let b = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    a.put_device_grant(device("old-device", "ABCD-EFGH"))
        .await
        .unwrap();
    let (release, accepted, decided) = store.delay_decision("bucket", false);
    let taker = {
        let a = a.clone();
        tokio::spawn(async move { a.take_device_grant("old-device").await })
    };
    accepted.notified().await;
    taker.abort();
    assert!(taker.await.unwrap_err().is_cancelled());
    drop(a);
    release.notify_one();
    decided.notified().await;
    assert!(b.get_device_grant("old-device").await.unwrap().is_none());
    b.put_device_grant(device("new-device", "ABCD-EFGH"))
        .await
        .unwrap();
    assert_eq!(
        b.find_device_grant_by_user_code("ABCDEFGH")
            .await
            .unwrap()
            .unwrap()
            .device_code,
        "new-device"
    );
}

#[tokio::test]
async fn replacing_a_device_user_code_releases_only_the_previous_code() {
    let store = OneStore::default();
    let s = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    s.put_device_grant(device("first-device", "ABCD-EFGH"))
        .await
        .unwrap();
    let mut updated = device("first-device", "JKLM-NPQR");
    updated.state = oauth_as::device::DeviceGrantState::Approved {
        subject: "operator".into(),
    };
    assert!(s
        .compare_and_swap_device_grant(&oauth_as::device::DeviceGrantState::Pending, updated)
        .await
        .unwrap());
    assert!(s
        .find_device_grant_by_user_code("ABCDEFGH")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        s.find_device_grant_by_user_code("JKLMNPQR")
            .await
            .unwrap()
            .unwrap()
            .device_code,
        "first-device"
    );
    s.put_device_grant(device("second-device", "ABCD-EFGH"))
        .await
        .unwrap();
    s.take_device_grant("first-device").await.unwrap();
    assert_eq!(
        s.find_device_grant_by_user_code("ABCDEFGH")
            .await
            .unwrap()
            .unwrap()
            .device_code,
        "second-device"
    );
}

#[tokio::test]
async fn a_delayed_subject_sweep_cannot_detach_a_new_consent() {
    let store = OneStore::default();
    let a = Arc::new(Shared::new(store.calls()));
    let b = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    a.index_subject("alice", "atomic-client").await.unwrap();
    let id = crate::shared::digest("alice");
    let (_, _, _, index) = a
        .read_cell::<crate::shared::SubjectIndex>(crate::shared::SUBJECT_INDEX, &id)
        .await
        .unwrap();
    let (release, accepted, decided) = store.delay_decision("ix.subj", false);
    let sweep = {
        let a = a.clone();
        tokio::spawn(async move { a.sweep_subject(&id, &index.clients).await })
    };
    accepted.notified().await;
    b.put_consent(oauth_as::consent::ConsentRecord {
        consent_id: "new-consent".into(),
        client_id: oauth_as::client::ClientId::new("atomic-client"),
        subject: "alice".into(),
        scope: oauth_as::scope::ScopeSet::default(),
        resource: Vec::new(),
        granted_at: std::time::SystemTime::now(),
        authentication: None,
    })
    .await
    .unwrap();
    release.notify_one();
    decided.notified().await;
    sweep.await.unwrap().unwrap();
    assert_eq!(b.consents_for_subject("alice").await.unwrap().len(), 1);
}

/// Inspect physical roots as logical rows; chunk schemas never become visible OAuth records.
fn logical_rows(
    rows: &BTreeMap<(String, Vec<u8>), Vec<u8>>,
) -> BTreeMap<(String, Vec<u8>), Vec<u8>> {
    rows.iter()
        .filter(|((schema, _), _)| schema.ends_with(".atomic.v1"))
        .map(|((schema, key), root)| {
            let value = match crate::shared::records::Descriptor::decode(root).unwrap() {
                None => root.clone(),
                Some(descriptor) => {
                    let mut bytes = Vec::new();
                    for part in 0..descriptor.parts() {
                        bytes.extend_from_slice(
                            &rows[&(
                                crate::shared::records::parts_schema(schema),
                                descriptor.key(key, part),
                            )],
                        );
                    }
                    assert!(
                        descriptor.check(&bytes),
                        "fixture observes complete atomic chunks"
                    );
                    bytes
                }
            };
            ((schema.clone(), key.clone()), value)
        })
        .collect()
}

fn apply_mutations(rows: &mut AtomicRows, mutations: &[Mutation]) {
    for mutation in mutations {
        match mutation {
            Mutation::Put { schema, key, value } => {
                rows.insert((schema.clone(), key.clone()), value.clone());
            }
            Mutation::Delete { schema, key } => {
                rows.remove(&(schema.clone(), key.clone()));
            }
            Mutation::DeleteRange {
                schema,
                prefix,
                exact_key_length,
            } => {
                rows.retain(|(s, k), _| {
                    s != schema || k.len() as u64 != *exact_key_length || !k.starts_with(prefix)
                });
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_chunk_reader_retries_when_its_old_generation_was_reclaimed() {
    let store = OneStore::default();
    let a = Arc::new(SharedStorage::new(Arc::new(Shared::new(store.calls()))));
    let b = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    assert_eq!(
        a.put_refresh_token(refresh("first-chunked-refresh"))
            .await
            .unwrap(),
        oauth_as::store::WriteOutcome::Applied
    );
    store.stall("get", "bucket", std::time::Duration::from_secs(1));
    let reader = {
        let a = a.clone();
        tokio::spawn(async move { a.get_refresh_token("first-chunked-refresh").await })
    };
    tokio::task::yield_now().await;
    assert!(
        store.stalls.lock().unwrap().is_empty(),
        "reader captured the old root"
    );
    assert_eq!(
        b.put_refresh_token(refresh("second-chunked-refresh"))
            .await
            .unwrap(),
        oauth_as::store::WriteOutcome::Applied
    );
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    assert!(
        reader.await.unwrap().unwrap().is_some(),
        "reclaimed old chunks must trigger a fresh root read"
    );
    assert!(store
        .atomic
        .lock()
        .unwrap()
        .rows
        .values()
        .all(|b| b.len() <= busbar_contract::bounded::MAX_RECORD_BYTES));
}

#[tokio::test]
async fn a_missing_chunk_under_an_unchanged_root_fails_closed() {
    let store = OneStore::default();
    let storage = SharedStorage::new(Arc::new(Shared::new(store.calls())));
    assert_eq!(
        storage
            .put_refresh_token(refresh("corrupt-chunked-refresh"))
            .await
            .unwrap(),
        oauth_as::store::WriteOutcome::Applied
    );
    let schema = crate::shared::atomic_schema("bucket");
    {
        let mut state = store.atomic.lock().unwrap();
        let key = crate::shared::digest("atomic-client").into_bytes();
        let descriptor =
            crate::shared::records::Descriptor::decode(&state.rows[&(schema.clone(), key.clone())])
                .unwrap()
                .expect("large bucket uses bounded chunks");
        state
            .rows
            .remove(&(
                crate::shared::records::parts_schema(&schema),
                descriptor.key(&key, 0),
            ))
            .unwrap();
    }
    let error = storage
        .get_refresh_token("corrupt-chunked-refresh")
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("incomplete or corrupt chunked record"));
}

#[tokio::test]
async fn replacing_a_blind_large_index_reclaims_its_exact_old_generation() {
    let store = OneStore::default();
    let shared = Shared::new(store.calls());
    shared
        .index("rt", "large-index", &"c".repeat(600))
        .await
        .unwrap();
    let schema = crate::shared::atomic_schema("ix.rt");
    assert!(store
        .atomic
        .lock()
        .unwrap()
        .rows
        .keys()
        .any(|(s, _)| s == &crate::shared::records::parts_schema(&schema)));
    // A concurrent blind publication can leave an unobserved generation. Inline replacement
    // retires every generation, not just the one a preparatory read happened to observe.
    let mut orphan_key = crate::shared::digest("large-index").into_bytes();
    orphan_key.push(0);
    orphan_key.extend_from_slice(&[9; 32]);
    orphan_key.extend_from_slice(&0u64.to_le_bytes());
    store.atomic.lock().unwrap().rows.insert(
        (crate::shared::records::parts_schema(&schema), orphan_key),
        b"unobserved old generation".to_vec(),
    );
    let mut blind = Shared::candidate(&schema, "unrelated-guard", None, b"guard".to_vec());
    Arc::make_mut(&mut blind).mutations = vec![Mutation::Put {
        schema: schema.clone(),
        key: crate::shared::digest("large-index").into_bytes(),
        value: serde_json::to_vec(&crate::shared::IndexRow {
            client: "small-client".into(),
            key: crate::shared::digest("large-index"),
            at: crate::shared::now_secs(),
        })
        .unwrap(),
    }];
    assert!(
        !blind
            .predicates
            .iter()
            .any(|p| p.key == crate::shared::digest("large-index").as_bytes()),
        "caller supplied no index-root comparison"
    );
    assert_eq!(shared.submit(blind).await.unwrap(), Decision::Applied);
    assert_eq!(
        shared
            .client_of("rt", "large-index")
            .await
            .unwrap()
            .as_deref(),
        Some("small-client")
    );
    let state = store.atomic.lock().unwrap();
    assert!(!state
        .rows
        .keys()
        .any(|(s, _)| s == &crate::shared::records::parts_schema(&schema)));
    let last = state.calls.last().unwrap();
    assert!(
        last.predicates
            .iter()
            .all(|p| p.key != crate::shared::digest("large-index").as_bytes()),
        "blind index replacement preserves its original logical predicates"
    );
}
