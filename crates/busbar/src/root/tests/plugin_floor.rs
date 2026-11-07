// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::persistence::{Address, ExpectedValue, Mutation, PreparedCandidate};
use busbar_contract::plugin_rows::{NeedLevel, PluginRows, Row, Skipped, Trust};
use busbar_contract::Secret;
use busbar_kernel::persistence::boot_identity::INSTANCE;
use busbar_kernel::persistence::facade::CoreStore;
use busbar_kernel::persistence::scoped::{migration_address, Outcome, ScopedStore};

use super::{hold, PluginFloor, PLUGIN_FLOOR_SCHEMA, RELEASE_KEYS_FLOOR_SCHEMA};
use crate::root::store_double::NativeFaults;

struct Fixture {
    faults: Arc<NativeFaults>,
    core: Arc<CoreStore>,
    owner: PluginFloor,
    records: ScopedStore,
}
impl Fixture {
    async fn new() -> Self {
        let faults = NativeFaults::open().await;
        let core = crate::root::real_store::core_over(faults.clone()).await;
        let owner = PluginFloor::new(core.clone()).unwrap();
        let records = ScopedStore::host_private(
            core.clone(),
            INSTANCE,
            [PLUGIN_FLOOR_SCHEMA.into(), RELEASE_KEYS_FLOOR_SCHEMA.into()],
        )
        .unwrap();
        faults.clear_observations();
        Self {
            faults,
            core,
            owner,
            records,
        }
    }
    async fn seed(&self, schema: &str, host: &str, name: &str, bytes: &[u8]) {
        assert!(matches!(
            self.records
                .put(schema, &floor_key(host, name), Secret::new(bytes.to_vec()))
                .await
                .unwrap(),
            Outcome::Applied
        ));
        self.faults.clear_observations();
    }
    async fn kept(&self, host: &str, name: &str) -> Option<Secret<Vec<u8>>> {
        self.records
            .get(PLUGIN_FLOOR_SCHEMA, &floor_key(host, name))
            .await
            .unwrap()
    }
}
// Fixture keys use the documented length framing; all reads and writes pass
// through the canonical scoped CoreStore facade and the actual native Store.
fn floor_key(host: &str, name: &str) -> Vec<u8> {
    [host, name]
        .into_iter()
        .flat_map(|part| {
            [
                (part.len() as u32).to_be_bytes().as_slice(),
                part.as_bytes(),
            ]
            .concat()
        })
        .collect()
}
fn address(schema: &str, host: &str, name: &str) -> Address {
    migration_address(true, INSTANCE, schema, &floor_key(host, name)).unwrap()
}
fn puts(candidate: &PreparedCandidate, at: &Address, bytes: &[u8]) -> bool {
    candidate.candidate().mutations.iter().any(|m| {
        matches!(m,
        Mutation::Put { address, value } if address == at && value == &Secret::new(bytes.to_vec()))
    })
}
fn exact_predicate(candidate: &PreparedCandidate, at: &Address, bytes: &[u8]) {
    assert!(candidate.candidate().predicates.iter().any(|p| p.address == *at
        && matches!(&p.expected, ExpectedValue::Exact(value) if value == &Secret::new(bytes.to_vec()))));
}

#[tokio::test]
async fn release_keys_floor_survives_restart_and_a_plugin_rollback_pin_cannot_lower_it() {
    let f = Fixture::new().await;
    assert_eq!(f.owner.release_keys_floor("node-a").await.unwrap(), 0);
    f.owner
        .enforce_release_keys("node-a", &[7], true)
        .await
        .unwrap();
    let restarted = PluginFloor::new(f.core.clone()).unwrap();
    assert_eq!(restarted.release_keys_floor("node-a").await.unwrap(), 7);
    let row = first_party("busbar-hook-pinned", "1.0.0");
    let pin = BTreeMap::from([(row.name.clone(), row.version.clone())]);
    let refusal = super::check_candidate(&restarted, "node-a", &row, Some(6), &pin)
        .await
        .expect_err("an exact plugin rollback pin cannot lower the keys-document floor");
    assert!(refusal.contains("keys-rollback") && refusal.contains("below 7"));
    super::check_candidate(&restarted, "node-a", &row, Some(7), &pin)
        .await
        .unwrap();
    assert_eq!(restarted.release_keys_floor("node-a").await.unwrap(), 7);
    restarted
        .enforce_release_keys("node-b", &[6], true)
        .await
        .unwrap();
    assert_eq!(restarted.release_keys_floor("node-b").await.unwrap(), 6);
}

#[tokio::test]
async fn release_keys_dry_run_never_creates_or_raises_a_floor() {
    let f = Fixture::new().await;
    f.owner
        .enforce_release_keys("node-a", &[3], false)
        .await
        .unwrap();
    assert_eq!(f.owner.release_keys_floor("node-a").await.unwrap(), 0);
    assert!(f.faults.requests.lock().unwrap().is_empty());
    f.owner
        .enforce_release_keys("node-a", &[3], true)
        .await
        .unwrap();
    f.faults.clear_observations();
    f.owner
        .enforce_release_keys("node-a", &[4], false)
        .await
        .unwrap();
    assert!(f
        .owner
        .enforce_release_keys("node-a", &[2], false)
        .await
        .is_err());
    assert_eq!(f.owner.release_keys_floor("node-a").await.unwrap(), 3);
    assert!(
        f.faults.requests.lock().unwrap().is_empty(),
        "read-only checks do not cross COMMIT"
    );
}

#[tokio::test]
async fn a_malformed_release_keys_floor_is_never_absence_or_echoed() {
    let f = Fixture::new().await;
    f.seed(
        RELEASE_KEYS_FLOOR_SCHEMA,
        "node-a",
        "busbar-release-keys",
        b"private-corrupt-floor",
    )
    .await;
    for refusal in [
        f.owner.release_keys_floor("node-a").await.unwrap_err(),
        f.owner
            .enforce_release_keys("node-a", &[10], true)
            .await
            .unwrap_err(),
    ] {
        assert!(refusal.contains("malformed"));
        assert!(!refusal.contains("private-corrupt"));
    }
    assert!(
        f.faults.requests.lock().unwrap().is_empty(),
        "refusal never overwrites a corrupt security record"
    );
    assert_eq!(
        f.records
            .get(
                RELEASE_KEYS_FLOOR_SCHEMA,
                &floor_key("node-a", "busbar-release-keys")
            )
            .await
            .unwrap(),
        Some(Secret::new(b"private-corrupt-floor".to_vec()))
    );
}

#[tokio::test]
async fn a_present_malformed_floor_is_never_treated_as_absence_or_echoed() {
    for corrupt in [
        b"private-invalid-version".as_slice(),
        b"private-invalid-utf8\xff".as_slice(),
    ] {
        let f = Fixture::new().await;
        f.seed(PLUGIN_FLOOR_SCHEMA, "node-a", "busbar-hook-x", corrupt)
            .await;
        let refused = hold(
            &f.owner,
            "node-a",
            &Scanned(vec![first_party("busbar-hook-x", "1.2.0")]),
            &BTreeMap::new(),
        )
        .await
        .unwrap_err();
        assert!(refused.contains("malformed"));
        assert!(!refused.contains("private-invalid"));
        assert_eq!(
            f.kept("node-a", "busbar-hook-x").await,
            Some(Secret::new(corrupt.to_vec()))
        );
        assert!(f.faults.requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn a_read_only_floor_check_refuses_downgrades_without_raising_or_creating_marks() {
    let f = Fixture::new().await;
    let name = "busbar-hook-check";
    f.seed(PLUGIN_FLOOR_SCHEMA, "node-a", name, b"2.0.0").await;
    let lower = Scanned(vec![first_party(name, "1.0.0")]);
    assert!(super::check(&f.owner, "node-a", &lower, &BTreeMap::new())
        .await
        .unwrap_err()
        .contains("below 2.0.0"));
    let newer = Scanned(vec![first_party(name, "3.0.0")]);
    super::check(&f.owner, "node-a", &newer, &BTreeMap::new())
        .await
        .unwrap();
    assert_eq!(
        f.kept("node-a", name).await,
        Some(Secret::new(b"2.0.0".to_vec()))
    );
    let fresh = Scanned(vec![first_party("busbar-hook-first-install", "1.0.0")]);
    super::check(&f.owner, "node-a", &fresh, &BTreeMap::new())
        .await
        .unwrap();
    assert!(f
        .kept("node-a", "busbar-hook-first-install")
        .await
        .is_none());
    assert!(f.faults.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_read_only_floor_check_keeps_rollback_authority_scoped_to_its_exact_plugin() {
    let f = Fixture::new().await;
    for name in ["busbar-hook-pinned", "busbar-hook-other"] {
        f.seed(PLUGIN_FLOOR_SCHEMA, "node-a", name, b"2.0.0").await;
    }
    let pins = BTreeMap::from([("busbar-hook-pinned".into(), "1.0.0".into())]);
    super::check(
        &f.owner,
        "node-a",
        &Scanned(vec![first_party("busbar-hook-pinned", "1.0.0")]),
        &pins,
    )
    .await
    .unwrap();
    assert!(super::check(
        &f.owner,
        "node-a",
        &Scanned(vec![first_party("busbar-hook-other", "1.0.0")]),
        &pins
    )
    .await
    .is_err());
    assert!(f.faults.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_old_first_party_release_is_refused_after_a_restart_on_the_same_store() {
    let f = Fixture::new().await;
    let none = BTreeMap::new();
    hold(
        &f.owner,
        "node-a",
        &Scanned(vec![first_party("busbar-hook-x", "1.2.0")]),
        &none,
    )
    .await
    .unwrap();
    let restarted = PluginFloor::new(f.core.clone()).unwrap();
    let older = Scanned(vec![first_party("busbar-hook-x", "1.1.0")]);
    let refused = hold(&restarted, "node-a", &older, &none).await.unwrap_err();
    assert!(
        refused.contains("below 1.2.0")
            && refused.contains("POST /api/v1/admin/plugins/rollback")
            && refused.contains(r#"{"file": "busbar-hook-x-1.1.0.tar.gz"}"#)
    );
    assert!(!refused.contains("first_party_floors"));
    let pinned = BTreeMap::from([("busbar-hook-x".into(), "1.1.0".into())]);
    hold(&restarted, "node-a", &older, &pinned).await.unwrap();
    assert_eq!(
        f.kept("node-a", "busbar-hook-x").await,
        Some(Secret::new(b"1.2.0".to_vec()))
    );
    hold(&restarted, "node-b", &older, &none).await.unwrap();
    hold(
        &restarted,
        "node-a",
        &Scanned(vec![first_party("busbar-hook-x", "1.3.0")]),
        &none,
    )
    .await
    .unwrap();
    assert_eq!(
        f.kept("node-a", "busbar-hook-x").await,
        Some(Secret::new(b"1.3.0".to_vec()))
    );
}

#[tokio::test]
async fn a_delayed_keys_document_cannot_lower_a_concurrent_newer_floor() {
    let f = Fixture::new().await;
    let host = "concurrent-keys-floor";
    f.owner
        .enforce_release_keys(host, &[1], true)
        .await
        .unwrap();
    let at = address(RELEASE_KEYS_FLOOR_SCHEMA, host, "busbar-release-keys");
    let (send, arrived) = tokio::sync::oneshot::channel();
    let send = Arc::new(Mutex::new(Some(send)));
    let release = Arc::new(tokio::sync::Notify::new());
    let gate = release.clone();
    let first = Arc::new(AtomicBool::new(true));
    *f.faults.on_commit.lock().unwrap() = Some(Arc::new(move |candidate| {
        let send = send.clone();
        let gate = gate.clone();
        let first = first.clone();
        let at = at.clone();
        Box::pin(async move {
            if puts(&candidate, &at, &2u64.to_be_bytes()) && first.swap(false, Ordering::AcqRel) {
                send.lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(candidate)
                    .unwrap();
                gate.notified().await;
            }
            Ok(())
        })
    }));
    let old_owner = PluginFloor::new(f.core.clone()).unwrap();
    let old = tokio::spawn(async move { old_owner.enforce_release_keys(host, &[2], true).await });
    let candidate = tokio::time::timeout(WAIT, arrived).await.unwrap().unwrap();
    exact_predicate(
        &candidate,
        &address(RELEASE_KEYS_FLOOR_SCHEMA, host, "busbar-release-keys"),
        &1u64.to_be_bytes(),
    );
    f.owner
        .enforce_release_keys(host, &[3], true)
        .await
        .unwrap();
    release.notify_one();
    assert!(tokio::time::timeout(WAIT, old)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err()
        .contains("below 3"));
    assert_eq!(f.owner.release_keys_floor(host).await.unwrap(), 3);
}

#[tokio::test]
async fn a_release_keys_floor_with_a_lost_ack_replays_one_immutable_transaction() {
    let f = Fixture::new().await;
    let weak = Arc::downgrade(&f.faults);
    *f.faults.on_commit.lock().unwrap() = Some(Arc::new(move |_| {
        let faults = weak.upgrade().unwrap();
        Box::pin(async move {
            // First COMMIT applies and loses its reply; the exact replay succeeds.
            if faults.requests.lock().unwrap().len() == 2 {
                faults.lose_acks.store(false, Ordering::Release);
            }
            Ok(())
        })
    }));
    f.faults.lose_acks.store(true, Ordering::Release);
    f.owner
        .enforce_release_keys("lost-keys-floor", &[9], true)
        .await
        .unwrap();
    {
        let crossed = f.faults.requests.lock().unwrap();
        assert_eq!(crossed.len(), 2);
        assert_eq!(crossed[0].candidate().id, crossed[1].candidate().id);
        assert_eq!(crossed[0].fingerprint(), crossed[1].fingerprint());
    }
    assert_eq!(
        f.owner.release_keys_floor("lost-keys-floor").await.unwrap(),
        9
    );
}

#[tokio::test]
async fn a_delayed_older_floor_candidate_cannot_lower_a_concurrent_newer_floor() {
    let f = Fixture::new().await;
    let host = "concurrent-floor";
    let name = "busbar-hook-floor-race";
    hold(
        &f.owner,
        host,
        &Scanned(vec![first_party(name, "1.1.0")]),
        &BTreeMap::new(),
    )
    .await
    .unwrap();
    let at = address(PLUGIN_FLOOR_SCHEMA, host, name);
    let (send, arrived) = tokio::sync::oneshot::channel();
    let send = Arc::new(Mutex::new(Some(send)));
    let release = Arc::new(tokio::sync::Notify::new());
    let gate = release.clone();
    let first = Arc::new(AtomicBool::new(true));
    *f.faults.on_commit.lock().unwrap() = Some(Arc::new(move |candidate| {
        let send = send.clone();
        let gate = gate.clone();
        let first = first.clone();
        let at = at.clone();
        Box::pin(async move {
            if puts(&candidate, &at, b"1.2.0") && first.swap(false, Ordering::AcqRel) {
                send.lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(candidate)
                    .unwrap();
                gate.notified().await;
            }
            Ok(())
        })
    }));
    let old_owner = PluginFloor::new(f.core.clone()).unwrap();
    let old = tokio::spawn(async move {
        hold(
            &old_owner,
            host,
            &Scanned(vec![first_party(name, "1.2.0")]),
            &BTreeMap::new(),
        )
        .await
    });
    let candidate = tokio::time::timeout(WAIT, arrived).await.unwrap().unwrap();
    exact_predicate(
        &candidate,
        &address(PLUGIN_FLOOR_SCHEMA, host, name),
        b"1.1.0",
    );
    hold(
        &f.owner,
        host,
        &Scanned(vec![first_party(name, "1.3.0")]),
        &BTreeMap::new(),
    )
    .await
    .unwrap();
    release.notify_one();
    assert!(tokio::time::timeout(WAIT, old)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err()
        .contains("below 1.3.0"));
    assert_eq!(
        f.kept(host, name).await,
        Some(Secret::new(b"1.3.0".to_vec()))
    );
    assert!(hold(
        &PluginFloor::new(f.core.clone()).unwrap(),
        host,
        &Scanned(vec![first_party(name, "1.2.0")]),
        &BTreeMap::new()
    )
    .await
    .is_err());
}

#[tokio::test]
async fn a_floor_with_a_lost_ack_replays_the_exact_candidate_after_another_upgrade() {
    let f = Fixture::new().await;
    let host = "unknown-floor";
    let name = "busbar-hook-unknown-floor";
    hold(
        &f.owner,
        host,
        &Scanned(vec![first_party(name, "1.1.0")]),
        &BTreeMap::new(),
    )
    .await
    .unwrap();
    f.faults.clear_observations();
    let at = address(PLUGIN_FLOOR_SCHEMA, host, name);
    let (send, mut arrived) = tokio::sync::mpsc::unbounded_channel();
    let attempts = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    let gate = release.clone();
    *f.faults.on_commit.lock().unwrap() = Some(Arc::new(move |candidate| {
        let send = send.clone();
        let attempts = attempts.clone();
        let gate = gate.clone();
        let at = at.clone();
        Box::pin(async move {
            if puts(&candidate, &at, b"1.2.0") {
                send.send(candidate).unwrap();
                if attempts.fetch_add(1, Ordering::AcqRel) == 1 {
                    gate.notified().await;
                }
            }
            Ok(())
        })
    }));
    f.faults.lose_acks.store(true, Ordering::Release);
    let old_owner = PluginFloor::new(f.core.clone()).unwrap();
    let old = tokio::spawn(async move {
        hold(
            &old_owner,
            host,
            &Scanned(vec![first_party(name, "1.2.0")]),
            &BTreeMap::new(),
        )
        .await
    });
    let first = tokio::time::timeout(WAIT, arrived.recv())
        .await
        .unwrap()
        .unwrap();
    let replay = tokio::time::timeout(WAIT, arrived.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.candidate().id, replay.candidate().id);
    assert_eq!(first.fingerprint(), replay.fingerprint());
    exact_predicate(&first, &address(PLUGIN_FLOOR_SCHEMA, host, name), b"1.1.0");
    assert_eq!(
        f.kept(host, name).await,
        Some(Secret::new(b"1.2.0".to_vec()))
    );
    f.faults.lose_acks.store(false, Ordering::Release);
    hold(
        &f.owner,
        host,
        &Scanned(vec![first_party(name, "1.3.0")]),
        &BTreeMap::new(),
    )
    .await
    .unwrap();
    release.notify_one();
    tokio::time::timeout(WAIT, old)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        f.kept(host, name).await,
        Some(Secret::new(b"1.3.0".to_vec()))
    );
    assert!(
        arrived.try_recv().is_err(),
        "the old effect is not replanned a third time"
    );
}

const WAIT: std::time::Duration = std::time::Duration::from_secs(5);
/// The rows a scan admitted: dropped-in first-party plugins at the versions named.
#[derive(Debug)]
struct Scanned(Vec<Row>);

fn first_party(name: &str, version: &str) -> Row {
    Row {
        file: format!("{name}-{version}.tar.gz"),
        key: name.to_string(),
        name: name.to_string(),
        alias: name.to_string(),
        kind: "hook".to_string(),
        version: version.to_string(),
        abi_version: 1,
        trust: Trust::Trusted {
            publisher: "busbar".to_string(),
            first_party: true,
        },
        ephemeral: false,
        in_process: false,
        linked: false,
        needs_prompt: NeedLevel::No,
        needs_user: NeedLevel::No,
        settings_schema: None,
    }
}

impl PluginRows for Scanned {
    fn resolve(&self, name_or_alias: &str) -> Option<Row> {
        self.0.iter().find(|r| r.name == name_or_alias).cloned()
    }
    fn unresolved_reason(&self, _: &str) -> Option<Skipped> {
        None
    }
    fn loadable(&self) -> Vec<Row> {
        self.0.clone()
    }
    fn linked(&self) -> Vec<Row> {
        Vec::new()
    }
    fn skipped(&self) -> Vec<Skipped> {
        Vec::new()
    }
    fn store_door(
        &self,
        name: &str,
    ) -> Result<busbar_contract::persistence::axis::StoreDoor, String> {
        Err(format!("no store `{name}`"))
    }
    fn secret_refusal(&self, name: &str) -> String {
        format!("no secret `{name}`")
    }
    fn kind_refusal(&self, kind: &str, _: &str, name: &str) -> String {
        format!("no {kind} `{name}`")
    }
    fn secret_slots(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}
