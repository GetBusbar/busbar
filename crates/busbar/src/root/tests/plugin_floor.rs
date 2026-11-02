// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::plugin_rows::{NeedLevel, PluginRows, Row, Skipped, Trust};

use super::hold;

#[test]
fn release_keys_floor_survives_restart_and_a_plugin_rollback_pin_cannot_lower_it() {
    let store = crate::root::store_double::RecordSlots::new();
    let calls = store.calls();
    assert_eq!(
        super::release_keys_floor(calls.as_ref(), "node-a").unwrap(),
        0
    );
    super::enforce_release_keys(calls.as_ref(), "node-a", &[7], true).unwrap();

    let calls = store.calls();
    assert_eq!(
        super::release_keys_floor(calls.as_ref(), "node-a").unwrap(),
        7
    );
    let row = first_party("busbar-hook-pinned", "1.0.0");
    let pin = BTreeMap::from([(row.name.clone(), row.version.clone())]);
    let refusal = super::check_candidate(calls.as_ref(), "node-a", &row, Some(6), &pin)
        .expect_err("an exact plugin rollback pin cannot lower the keys-document floor");
    assert!(refusal.contains("keys-rollback") && refusal.contains("below 7"));
    super::check_candidate(calls.as_ref(), "node-a", &row, Some(7), &pin).unwrap();
    assert_eq!(
        super::release_keys_floor(calls.as_ref(), "node-a").unwrap(),
        7
    );
    super::enforce_release_keys(calls.as_ref(), "node-b", &[6], true).unwrap();
    assert_eq!(
        super::release_keys_floor(calls.as_ref(), "node-b").unwrap(),
        6
    );
}

#[test]
fn release_keys_dry_run_never_creates_or_raises_a_floor() {
    let store = crate::root::store_double::RecordSlots::new();
    let calls = store.calls();
    super::enforce_release_keys(calls.as_ref(), "node-a", &[3], false).unwrap();
    assert_eq!(
        super::release_keys_floor(calls.as_ref(), "node-a").unwrap(),
        0
    );
    super::enforce_release_keys(calls.as_ref(), "node-a", &[3], true).unwrap();
    store.on_transaction(|_| panic!("a read-only keys floor check must not write"));
    super::enforce_release_keys(calls.as_ref(), "node-a", &[4], false).unwrap();
    assert!(super::enforce_release_keys(calls.as_ref(), "node-a", &[2], false).is_err());
    assert_eq!(
        super::release_keys_floor(calls.as_ref(), "node-a").unwrap(),
        3
    );
}

#[test]
fn a_malformed_release_keys_floor_is_never_absence_or_echoed() {
    let store = crate::root::store_double::RecordSlots::new();
    let key = super::release_keys_key("node-a");
    store.put_row(
        super::RELEASE_KEYS_FLOOR_SCHEMA,
        &key,
        b"private-corrupt-floor",
    );
    for refusal in [
        super::release_keys_floor(store.calls().as_ref(), "node-a").unwrap_err(),
        super::enforce_release_keys(store.calls().as_ref(), "node-a", &[10], true).unwrap_err(),
    ] {
        assert!(refusal.contains("malformed"));
        assert!(!refusal.contains("private-corrupt"));
    }
    assert_eq!(
        store.puts(),
        0,
        "refusal never overwrites a corrupt security record"
    );
}

#[test]
fn a_delayed_keys_document_cannot_lower_a_concurrent_newer_floor() {
    use busbar_contract::abi::sdk::store::conditional::{Expected, Mutation};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    const HOST: &str = "concurrent-keys-floor";
    let store = crate::root::store_double::RecordSlots::new();
    super::enforce_release_keys(store.calls().as_ref(), HOST, &[1], true).unwrap();
    let (arrived, crossing) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let release = ReleaseTransaction(Some(release));
    let released = Mutex::new(released);
    let first = AtomicBool::new(true);
    store.on_transaction(move |request| {
        let older = request.mutations.iter().any(|mutation| {
            matches!(mutation,
            Mutation::Put { schema, key, value } if schema == super::RELEASE_KEYS_FLOOR_SCHEMA
                && key == &super::release_keys_key(HOST) && value.as_slice() == 2u64.to_be_bytes())
        });
        if older && first.swap(false, Ordering::AcqRel) {
            arrived.send(request.clone()).unwrap();
            released.lock().unwrap().recv_timeout(WAIT).unwrap();
        }
        None
    });
    let old_store = store.clone();
    let old = std::thread::spawn(move || {
        super::enforce_release_keys(old_store.calls().as_ref(), HOST, &[2], true)
    });
    let candidate = crossing.recv_timeout(WAIT).expect("the older CAS is held");
    assert_eq!(
        candidate.predicates[0].expected,
        Expected::Bytes(1u64.to_be_bytes().to_vec())
    );
    super::enforce_release_keys(store.calls().as_ref(), HOST, &[3], true).unwrap();
    release.release();
    assert!(old.join().unwrap().unwrap_err().contains("below 3"));
    assert_eq!(
        super::release_keys_floor(store.calls().as_ref(), HOST).unwrap(),
        3
    );
}

#[test]
fn a_release_keys_floor_with_a_lost_ack_replays_one_immutable_transaction() {
    use std::sync::Mutex;
    let store = crate::root::store_double::RecordSlots::new();
    let crossed = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&crossed);
    store.on_transaction(move |request| {
        seen.lock().unwrap().push(request.clone());
        None
    });
    store.lose_acks(true);
    super::enforce_release_keys(store.calls().as_ref(), "lost-keys-floor", &[9], true).unwrap();
    let crossed = crossed.lock().unwrap();
    assert_eq!(crossed.len(), 2);
    assert_eq!(
        crossed[0], crossed[1],
        "the original operation id and complete candidate are replayed"
    );
    assert_eq!(store.puts(), 1);
    assert_eq!(
        super::release_keys_floor(store.calls().as_ref(), "lost-keys-floor").unwrap(),
        9
    );
}

#[test]
fn a_present_malformed_floor_is_never_treated_as_absence_or_echoed() {
    for corrupt in [
        b"private-invalid-version".as_slice(),
        b"private-invalid-utf8\xff".as_slice(),
    ] {
        let store = crate::root::store_double::RecordSlots::new();
        let key = super::floor_key("node-a", "busbar-hook-x");
        store.put_row(super::PLUGIN_FLOOR_SCHEMA, &key, corrupt);
        let refused = hold(
            store.calls().as_ref(),
            "node-a",
            &Scanned(vec![first_party("busbar-hook-x", "1.2.0")]),
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(refused.contains("malformed"));
        assert!(!refused.contains("private-invalid"));
        assert_eq!(
            super::wait_for(store.calls().record_get(super::PLUGIN_FLOOR_SCHEMA, &key))
                .unwrap()
                .unwrap()
                .as_slice(),
            corrupt
        );
    }
}

#[test]
fn a_read_only_floor_check_refuses_downgrades_without_raising_or_creating_marks() {
    let store = crate::root::store_double::RecordSlots::new();
    let name = "busbar-hook-check";
    let key = super::floor_key("node-a", name);
    store.put_row(super::PLUGIN_FLOOR_SCHEMA, &key, b"2.0.0");
    store.on_transaction(|_| panic!("a dry-run floor check must never write"));
    let lower = Scanned(vec![first_party(name, "1.0.0")]);
    assert!(
        super::check(store.calls().as_ref(), "node-a", &lower, &BTreeMap::new())
            .unwrap_err()
            .contains("below 2.0.0")
    );
    let newer = Scanned(vec![first_party(name, "3.0.0")]);
    super::check(store.calls().as_ref(), "node-a", &newer, &BTreeMap::new()).unwrap();
    assert_eq!(kept_floor(&store, "node-a", name), b"2.0.0");
    let fresh = Scanned(vec![first_party("busbar-hook-first-install", "1.0.0")]);
    super::check(store.calls().as_ref(), "node-a", &fresh, &BTreeMap::new()).unwrap();
    assert!(super::wait_for(store.calls().record_get(
        super::PLUGIN_FLOOR_SCHEMA,
        &super::floor_key("node-a", "busbar-hook-first-install"),
    ))
    .unwrap()
    .is_none());
}

#[test]
fn a_read_only_floor_check_keeps_rollback_authority_scoped_to_its_exact_plugin() {
    let store = crate::root::store_double::RecordSlots::new();
    for name in ["busbar-hook-pinned", "busbar-hook-other"] {
        store.put_row(
            super::PLUGIN_FLOOR_SCHEMA,
            &super::floor_key("node-a", name),
            b"2.0.0",
        );
    }
    let pins = BTreeMap::from([("busbar-hook-pinned".into(), "1.0.0".into())]);
    let pinned = Scanned(vec![first_party("busbar-hook-pinned", "1.0.0")]);
    super::check(store.calls().as_ref(), "node-a", &pinned, &pins).unwrap();
    let other = Scanned(vec![first_party("busbar-hook-other", "1.0.0")]);
    assert!(super::check(store.calls().as_ref(), "node-a", &other, &pins).is_err());
}

const WAIT: std::time::Duration = std::time::Duration::from_secs(5);

struct ReleaseTransaction(Option<std::sync::mpsc::Sender<()>>);

impl ReleaseTransaction {
    fn release(mut self) {
        if let Some(send) = self.0.take() {
            let _ = send.send(());
        }
    }
}

impl Drop for ReleaseTransaction {
    fn drop(&mut self) {
        if let Some(send) = self.0.take() {
            let _ = send.send(());
        }
    }
}

fn kept_floor(store: &crate::root::store_double::RecordSlots, host: &str, name: &str) -> Vec<u8> {
    super::wait_for(
        store
            .calls()
            .record_get(super::PLUGIN_FLOOR_SCHEMA, &super::floor_key(host, name)),
    )
    .unwrap()
    .expect("the floor is stored")
    .as_slice()
    .to_vec()
}

fn floor_candidate(
    request: &busbar_contract::abi::sdk::store::conditional::Request,
    host: &str,
    name: &str,
    version: &str,
) -> bool {
    use busbar_contract::abi::sdk::store::conditional::Mutation;
    request.mutations.iter().any(|mutation| matches!(mutation,
        Mutation::Put { schema, key, value } if schema == super::PLUGIN_FLOOR_SCHEMA
            && key.as_slice() == super::floor_key(host, name).as_slice() && value.as_slice() == version.as_bytes()))
}

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
    fn store_door(&self, name: &str) -> Result<busbar_contract::store_calls::StoreDoor, String> {
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

#[test]
fn an_old_first_party_release_is_refused_after_a_restart_on_the_same_store() {
    let store = crate::root::store_double::RecordSlots::new();
    let none = BTreeMap::new();
    hold(
        store.calls().as_ref(),
        "node-a",
        &Scanned(vec![first_party("busbar-hook-x", "1.2.0")]),
        &none,
    )
    .expect("a first load sets the floor");

    let older = Scanned(vec![first_party("busbar-hook-x", "1.1.0")]);
    let refused = hold(store.calls().as_ref(), "node-a", &older, &none)
        .expect_err("an old release does not load in the newer one's place");
    assert!(
        refused.contains("below 1.2.0")
            && refused.contains("POST /api/v1/admin/plugins/rollback")
            && refused.contains(r#"{"file": "busbar-hook-x-1.1.0.tar.gz"}"#),
        "the refusal names the floor and the audited rollback that admits it: {refused}"
    );

    assert!(
        !refused.contains("first_party_floors"),
        "the refusal points at a key config.yaml refuses: {refused}"
    );

    let pinned: BTreeMap<String, String> =
        [("busbar-hook-x".to_string(), "1.1.0".to_string())].into();
    hold(store.calls().as_ref(), "node-a", &older, &pinned).expect("the pin rolls it back");
    hold(store.calls().as_ref(), "node-b", &older, &none)
        .expect("another host keeps its own floor");
    hold(
        store.calls().as_ref(),
        "node-a",
        &Scanned(vec![first_party("busbar-hook-x", "1.3.0")]),
        &none,
    )
    .expect("a newer release loads and raises the floor");
}

#[test]
fn a_delayed_older_floor_candidate_cannot_lower_a_concurrent_newer_floor() {
    use busbar_contract::abi::sdk::store::conditional::Expected;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    const HOST: &str = "concurrent-floor";
    const NAME: &str = "busbar-hook-floor-race";
    let store = crate::root::store_double::RecordSlots::new();
    hold(
        store.calls().as_ref(),
        HOST,
        &Scanned(vec![first_party(NAME, "1.1.0")]),
        &BTreeMap::new(),
    )
    .unwrap();
    let (arrived, crossing) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let release = ReleaseTransaction(Some(release));
    let released = Mutex::new(released);
    let first = AtomicBool::new(true);
    store.on_transaction(move |request| {
        if floor_candidate(request, HOST, NAME, "1.2.0") && first.swap(false, Ordering::AcqRel) {
            arrived.send(request.clone()).unwrap();
            released
                .lock()
                .unwrap()
                .recv_timeout(WAIT)
                .expect("the test releases the older candidate");
        }
        None
    });
    let old_store = store.clone();
    let (settled, outcome) = std::sync::mpsc::channel();
    let old = std::thread::spawn(move || {
        let result = hold(
            old_store.calls().as_ref(),
            HOST,
            &Scanned(vec![first_party(NAME, "1.2.0")]),
            &BTreeMap::new(),
        );
        let _ = settled.send(result);
    });
    let candidate = crossing
        .recv_timeout(WAIT)
        .expect("the real older CAS is delayed");
    assert_eq!(candidate.predicates.len(), 1);
    assert_eq!(
        candidate.predicates[0].expected,
        Expected::Bytes(b"1.1.0".to_vec())
    );
    hold(
        store.calls().as_ref(),
        HOST,
        &Scanned(vec![first_party(NAME, "1.3.0")]),
        &BTreeMap::new(),
    )
    .expect("the newer candidate commits while the older one is in flight");
    assert_eq!(kept_floor(&store, HOST, NAME), b"1.3.0");
    release.release();
    let refused = outcome
        .recv_timeout(WAIT)
        .expect("the stale comparison completes")
        .expect_err("a stale 1.2.0 candidate cannot lower 1.3.0");
    old.join().unwrap();
    assert!(
        refused.contains("below 1.3.0"),
        "the real downgrade refusal: {refused}"
    );
    assert_eq!(kept_floor(&store, HOST, NAME), b"1.3.0");
    assert!(
        hold(
            store.calls().as_ref(),
            HOST,
            &Scanned(vec![first_party(NAME, "1.2.0")]),
            &BTreeMap::new()
        )
        .is_err(),
        "a later unpinned restart still enforces the concurrent high-water mark"
    );
}

#[test]
fn a_floor_with_a_lost_ack_replays_the_exact_candidate_after_another_upgrade() {
    use busbar_contract::abi::sdk::store::conditional::Expected;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    const HOST: &str = "unknown-floor";
    const NAME: &str = "busbar-hook-unknown-floor";
    let store = crate::root::store_double::RecordSlots::new();
    hold(
        store.calls().as_ref(),
        HOST,
        &Scanned(vec![first_party(NAME, "1.1.0")]),
        &BTreeMap::new(),
    )
    .unwrap();
    let writes_before = store.puts();
    let (arrived, crossings) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let release = ReleaseTransaction(Some(release));
    let released = Mutex::new(released);
    let attempts = AtomicUsize::new(0);
    store.on_transaction(move |request| {
        if floor_candidate(request, HOST, NAME, "1.2.0") {
            arrived.send(request.clone()).unwrap();
            if attempts.fetch_add(1, Ordering::AcqRel) == 1 {
                released
                    .lock()
                    .unwrap()
                    .recv_timeout(WAIT)
                    .expect("the test releases the exact replay");
            }
        }
        None
    });
    store.lose_acks(true);
    let old_store = store.clone();
    let (settled, outcome) = std::sync::mpsc::channel();
    let old = std::thread::spawn(move || {
        let result = hold(
            old_store.calls().as_ref(),
            HOST,
            &Scanned(vec![first_party(NAME, "1.2.0")]),
            &BTreeMap::new(),
        );
        let _ = settled.send(result);
    });
    let first = crossings
        .recv_timeout(WAIT)
        .expect("the original transaction crosses");
    let replay = crossings
        .recv_timeout(WAIT)
        .expect("unknown commit causes a receipt replay");
    assert_eq!(
        first, replay,
        "operation id, predicates and full mutation bytes are immutable"
    );
    assert_eq!(
        first.predicates[0].expected,
        Expected::Bytes(b"1.1.0".to_vec())
    );
    assert_eq!(
        kept_floor(&store, HOST, NAME),
        b"1.2.0",
        "the first transaction committed before losing its ack"
    );
    store.lose_acks(false);
    hold(
        store.calls().as_ref(),
        HOST,
        &Scanned(vec![first_party(NAME, "1.3.0")]),
        &BTreeMap::new(),
    )
    .expect("another boot advances the floor before the old receipt is replayed");
    release.release();
    outcome
        .recv_timeout(WAIT)
        .expect("the receipt replay completes")
        .expect("the Store returns the original Applied receipt despite the newer row");
    old.join().unwrap();
    assert_eq!(kept_floor(&store, HOST, NAME), b"1.3.0");
    assert_eq!(
        store.puts() - writes_before,
        2,
        "only the two distinct upgrades wrote rows"
    );
    assert!(
        matches!(
            crossings.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ),
        "the original effect was not replanned or submitted a third time"
    );
}
