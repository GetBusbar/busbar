// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
// Actual KernelServices controls relocated from the deleted conformance Host simulator.
use busbar_contract::abi::host::service::MAX_RANDOM_FILL;
use busbar_contract::abi::mechanism::{call::Outcome, KindCode};
use busbar_contract::abi::plane::{RecordChain, CHAIN_LENGTH_PREFIXED};
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::services::{chain_key, Caller, HostServices, Later, Ran, RecordsList, Stored};
use busbar_kernel::host_records::StoreRows;
use busbar_kernel::host_services::{InstanceFacts, KernelServices as Host, Offload};
use std::sync::{mpsc, Arc};
use std::time::Duration;
const NOT_ADMITTED: &str = "the instance is not admitted";
const NOT_A_KIND: &str = "not a record kind the instance declared";
const NO_TTL: &str = "a claim states its time to live";
const CHAIN_READ_WHOLE: &str = "a chained record kind is read whole, through records.list";
struct Inline;
impl Offload for Inline {
    fn run(&self, f: Box<dyn FnOnce() + Send>) {
        f();
    }
}
#[path = "../src/tests/real_store.rs"]
mod real_store;
mod door {
    pub use busbar_kernel::door::op_id;
}
fn admitted() -> Host {
    admitted_over(real_store::store())
}
fn admitted_over(store: Arc<busbar_plugin_loader::store_v3::LoadedStore>) -> Host {
    let h = Host::new()
        .with_records(Arc::new(StoreRows(store)))
        .with_pool(Arc::new(Inline));
    h.admit(
        "plane",
        InstanceFacts {
            record_kinds: vec![RecordSchemaId::new("tasks"), RecordSchemaId::new("journal")],
            record_chains: vec![RecordChain {
                kind: 1,
                framing: CHAIN_LENGTH_PREFIXED,
                flags: 0,
                _reserved: 0,
            }],
            ..InstanceFacts::default()
        },
    )
    .expect("actual host admits the declared instance");
    h
}
fn keep(h: &Host, kind: u32, key: &[u8], value: &[u8]) {
    let (tx, rx) = mpsc::channel();
    h.record_write(
        &caller("plane"),
        if kind == 0 { "tasks" } else { "journal" },
        key,
        RecordBytes::new(value.to_vec()).unwrap(),
        Box::new(move |r| {
            tx.send(r).unwrap();
        }),
    )
    .expect("write admitted");
    assert!(
        h.drain(Duration::from_secs(5)),
        "actual host drains the write"
    );
    rx.recv_timeout(Duration::from_secs(5))
        .unwrap()
        .expect("actual store accepts the write");
}
fn caller(instance: &str) -> Caller {
    Caller {
        instance: Arc::from(instance),
        plugin: Arc::from("plane"),
        kind: KindCode::Plane,
    }
}

fn later() -> (Later, mpsc::Receiver<Stored>) {
    let (tx, rx) = mpsc::channel();
    (
        Box::new(move |s| {
            let _ = tx.send(s);
        }),
        rx,
    )
}

fn answer(r: Ran, rx: &mpsc::Receiver<Stored>) -> Stored {
    match r {
        Ran::Now(s) => s,
        Ran::Later => rx
            .recv_timeout(Duration::from_secs(10))
            .expect("a pended service answers"),
    }
}

#[test]
fn random_fill_draws_fresh_bytes_and_refuses_outside_its_cap() {
    let h = Host::new();
    let first = h.random_fill(16);
    let second = h.random_fill(16);
    assert_eq!((first.outcome, first.bytes.len()), (Outcome::Ready, 16));
    assert_eq!((second.outcome, second.bytes.len()), (Outcome::Ready, 16));
    assert_ne!(first.bytes, second.bytes);
    assert_eq!(
        h.random_fill(MAX_RANDOM_FILL).bytes.len() as u64,
        MAX_RANDOM_FILL
    );
    for len in [0, MAX_RANDOM_FILL + 1] {
        let s = h.random_fill(len);
        assert_eq!(
            (s.outcome, s.error),
            (
                Outcome::Refused,
                "a fill asks for 1 to MAX_RANDOM_FILL bytes"
            )
        );
    }
}
#[test]
fn records_refuse_an_instance_the_host_never_admitted() {
    let h = admitted();
    let c = caller("never-admitted");
    let (l, rx) = later();
    let s = answer(h.records_get(&c, "tasks", b"k", l), &rx);
    assert_eq!(
        (s.outcome, s.error),
        (Outcome::Refused, NOT_ADMITTED),
        "get: {s:?}"
    );
    let (l, rx) = later();
    let list = RecordsList {
        kind: "tasks".into(),
        prefix: Vec::new(),
        after: None,
        limit: 0,
    };
    let s = answer(h.records_list(&c, list, l), &rx);
    assert_eq!(
        (s.outcome, s.error),
        (Outcome::Refused, NOT_ADMITTED),
        "list: {s:?}"
    );
    let (l, rx) = later();
    let s = answer(h.records_claim(&c, "tasks", b"k", 1000, l), &rx);
    assert_eq!(
        (s.outcome, s.error),
        (Outcome::Refused, NOT_ADMITTED),
        "claim: {s:?}"
    );
}

fn get(h: &Host, c: &Caller, kind: &str, key: &str) -> Stored {
    let (l, rx) = later();
    answer(h.records_get(c, kind, key.as_bytes(), l), &rx)
}

fn list(h: &Host, kind: &str, prefix: &str, after: Option<&str>, limit: u32) -> Stored {
    let (l, rx) = later();
    let ask = RecordsList {
        kind: kind.into(),
        prefix: prefix.as_bytes().to_vec(),
        after: after.map(|a| a.as_bytes().to_vec()),
        limit,
    };
    answer(h.records_list(&caller("plane"), ask, l), &rx)
}

fn claim(h: &Host, kind: &str, key: &str, ttl_ms: u64) -> Stored {
    let (l, rx) = later();
    answer(
        h.records_claim(&caller("plane"), kind, key.as_bytes(), ttl_ms, l),
        &rx,
    )
}

fn rows(s: &Stored) -> Vec<(String, String)> {
    let at = |sp: busbar_contract::abi::mechanism::call::Span| {
        if sp.offset == busbar_contract::abi::mechanism::check::SPAN_ABSENT {
            return String::new();
        }
        let (from, len) = (sp.offset as usize, sp.len as usize);
        String::from_utf8_lossy(&s.bytes[from..from + len]).into_owned()
    };
    s.spans
        .iter()
        .map(|sp| (at(sp.key), at(sp.value)))
        .collect()
}

fn row(k: &[u8], v: &str) -> (String, String) {
    (String::from_utf8_lossy(k).into_owned(), v.to_string())
}

#[test]
fn records_read_the_instances_own_writes_and_claim_once() {
    use busbar_contract::abi::host::service::{ABSENT, CLAIM_TAKEN, CLAIM_WON, FOUND};
    let h = admitted();
    let c = caller("plane");
    assert_eq!(get(&h, &c, "tasks", "t/1").value, ABSENT);
    let s = get(&h, &c, "secrets", "t/1");
    assert_eq!(
        (s.outcome, s.error),
        (Outcome::Refused, NOT_A_KIND),
        "{s:?}"
    );
    let s = get(&h, &caller("another"), "tasks", "t/1");
    assert_eq!(
        (s.outcome, s.error),
        (Outcome::Refused, NOT_ADMITTED),
        "{s:?}"
    );

    keep(&h, 0, b"t/2", b"two");
    keep(&h, 0, b"t/1", b"one");
    keep(&h, 0, b"u/1", b"else");
    let s = get(&h, &c, "tasks", "t/1");
    assert_eq!((s.outcome, s.value), (Outcome::Ready, FOUND), "{s:?}");
    assert_eq!(s.bytes, b"one");
    assert_eq!(rows(&s), [(String::new(), "one".to_string())]);
    assert_eq!(
        rows(&list(&h, "tasks", "t/", None, 0)),
        [row(b"t/1", "one"), row(b"t/2", "two")]
    );
    assert_eq!(
        rows(&list(&h, "tasks", "t/", Some("t/1"), 0)),
        [row(b"t/2", "two")]
    );
    assert_eq!(rows(&list(&h, "tasks", "", None, 1)), [row(b"t/1", "one")]);

    keep(&h, 0, b"t/1", b"");
    assert_eq!(get(&h, &c, "tasks", "t/1").value, ABSENT);
    assert_eq!(
        rows(&list(&h, "tasks", "t/", None, 0)),
        [row(b"t/2", "two")]
    );

    assert_eq!(claim(&h, "tasks", "approval", 1000).value, CLAIM_WON);
    assert_eq!(claim(&h, "tasks", "approval", 1000).value, CLAIM_TAKEN);
    assert_eq!(claim(&h, "tasks", "another", 1000).value, CLAIM_WON);
    let s = claim(&h, "tasks", "never", 0);
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NO_TTL), "{s:?}");
    let s = claim(&h, "secrets", "k", 1000);
    assert_eq!(
        (s.outcome, s.error),
        (Outcome::Refused, NOT_A_KIND),
        "{s:?}"
    );
}

#[test]
fn a_chained_kinds_writes_are_appended_to_their_chain_and_read_whole() {
    let store = real_store::store();
    let h = admitted_over(store.clone());
    keep(&h, 1, b"task-a", b"first");
    keep(&h, 1, b"task-b", b"other");
    keep(&h, 1, b"task-a", b"second");

    busbar_kernel::host_records::RecordRows::record_put(
        &StoreRows(store),
        RecordSchemaId::new("journal"),
        &busbar_kernel::host_records::record_key("plane", &chain_key(b"task-c", 1)),
        &RecordBytes::new(b"stray".to_vec()).unwrap(),
    )
    .expect("the unrelated raw row is written in the actual Store");
    let s = get(&h, &caller("plane"), "journal", "task-a");
    assert_eq!(
        (s.outcome, s.error),
        (Outcome::Refused, CHAIN_READ_WHOLE),
        "{s:?}"
    );
    assert_eq!(
        rows(&list(&h, "journal", "", None, 0)),
        [
            row(&chain_key(b"task-a", 1), "first"),
            row(&chain_key(b"task-a", 2), "second"),
            row(&chain_key(b"task-b", 1), "other"),
        ]
    );

    keep(&h, 1, b"task-a", b"");
    assert_eq!(
        rows(&list(&h, "journal", "", None, 0)),
        [row(&chain_key(b"task-b", 1), "other")]
    );
    keep(&h, 1, b"task-a", b"again");
    assert_eq!(
        rows(&list(&h, "journal", "task-a", None, 0)),
        [row(&chain_key(b"task-a", 1), "again")]
    );
}

// The removed simulator accepted any offered digest from a fixed tuple. Actual
// approvals are digest-bound; the production owner is deliberately exercised here.
fn trust_host() -> Host {
    let h = Host::new();
    h.admit(
        "plane",
        InstanceFacts {
            trust: vec![(
                "fs".into(),
                busbar_kernel::trust::section::TrustEntry {
                    pin: None,
                    policy: busbar_kernel::trust::reverify::Policy {
                        ttl_ms: 0,
                        recovery_backoff_ms: 0,
                    },
                    approved: std::collections::BTreeMap::from([("read".into(), "one".into())]),
                },
            )],
            ..InstanceFacts::default()
        },
    )
    .expect("actual host admits explicit digest-bound item approval");
    h
}
#[test]
fn configured_item_approval_is_bound_to_its_actual_digest() {
    use busbar_contract::abi::host::service::{
        DISTRUST_CHANGED, DISTRUST_NONE, DISTRUST_UNKNOWN_ITEM,
    };
    let h = trust_host();
    let c = caller("plane");
    assert_eq!(
        h.trust_serves(&c, "fs", Some("read"), Some("one")).value,
        DISTRUST_NONE
    );
    assert_eq!(
        h.trust_serves(&c, "fs", Some("read"), Some("two")).value,
        DISTRUST_CHANGED
    );
    assert_eq!(
        h.trust_serves(&c, "fs", Some("unknown"), None).value,
        DISTRUST_UNKNOWN_ITEM
    );
    assert_eq!(
        h.trust_sight_item(&c, "fs", "read", "one").outcome,
        Outcome::Ready
    );
    assert_eq!(
        h.trust_serves(&c, "fs", Some("read"), Some("one")).value,
        DISTRUST_NONE
    );
}
#[test]
fn item_sightings_refuse_wrong_owners_and_invalid_evidence_without_changing_approval() {
    use busbar_contract::abi::host::service::DISTRUST_NONE;
    let h = trust_host();
    let c = caller("plane");
    assert_eq!(
        h.trust_sight_item(&c, "fs", "read", "one").outcome,
        Outcome::Ready
    );
    assert_eq!(
        h.trust_serves(&c, "fs", Some("read"), None).value,
        DISTRUST_NONE
    );
    for who in [caller("never-admitted"), caller("another-instance")] {
        let s = h.trust_sight_item(&who, "fs", "read", "");
        assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_ADMITTED));
    }
    for evidence in ["", " \t\n", "before\0after"] {
        assert_eq!(
            h.trust_sight_item(&c, "fs", "read", evidence).outcome,
            Outcome::Refused
        );
    }
    assert_eq!(
        h.trust_sight_item(&c, "unknown", "read", "one").outcome,
        Outcome::Refused
    );
    assert_eq!(
        h.trust_serves(&c, "fs", Some("read"), None).value,
        DISTRUST_NONE
    );
    assert_eq!(
        h.trust_sight_item(&c, "unknown", "read", "").error,
        busbar_kernel::host_services::NOT_A_COUNTERPARTY
    );
}

#[test]
fn trust_serves_item_less_answers_the_counterpartys_own_verdict() {
    use busbar_contract::abi::host::service::{
        DISTRUST_NONE, DISTRUST_NOT_APPROVED, DISTRUST_UNKNOWN, DISTRUST_UNKNOWN_ITEM,
    };
    use busbar_kernel::trust::{
        book::Ruling,
        reverify::Policy,
        section::{DeclaredPin, TrustEntry},
    };
    let entry = || TrustEntry {
        pin: Some(DeclaredPin {
            mechanism: "fingerprint".into(),
            root: false,
            peer_key: false,
            key: None,
            fingerprint: Some("one".into()),
        }),
        policy: Policy {
            ttl_ms: 0,
            recovery_backoff_ms: 0,
        },
        approved: std::collections::BTreeMap::from([("tool".into(), "one".into())]),
    };
    let h = Host::new();
    h.admit(
        "plane",
        InstanceFacts {
            trust: vec![("agent".into(), entry()), ("pending".into(), entry())],
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    h.trust_rule("plane/agent", Ruling::Approve)
        .expect("actual authority approves declared fingerprint");
    h.trust_rule("plane/agent/tool", Ruling::Revoke)
        .expect("actual authority revokes declared item");
    let c = caller("plane");
    let verdict = |cp: &str, item: Option<&str>| h.trust_serves(&c, cp, item, None).value;
    assert_eq!(verdict("agent", None), DISTRUST_NONE);
    assert_eq!(verdict("agent", Some("tool")), DISTRUST_NOT_APPROVED);
    assert_eq!(verdict("agent", Some("other")), DISTRUST_UNKNOWN_ITEM);
    assert_eq!(verdict("pending", None), DISTRUST_NOT_APPROVED);
    assert_eq!(verdict("stranger", None), DISTRUST_UNKNOWN);
}

#[test]
fn sightings_never_rewrite_the_actual_configured_item_approval() {
    use busbar_contract::abi::host::service::{DISTRUST_NONE, DISTRUST_NOT_APPROVED};
    let h = trust_host();
    let c = caller("plane");
    for evidence in ["one", "one", "two"] {
        assert_eq!(
            h.trust_sight_item(&c, "fs", "read", evidence).outcome,
            Outcome::Ready
        );
        assert_eq!(
            h.trust_sight_item(&c, "fs", "draft", evidence).outcome,
            Outcome::Ready
        );
        let rows = h.trust_rows();
        let read = rows
            .iter()
            .find(|r| r.counterparty == "fs" && r.item.as_deref() == Some("read"))
            .expect("actual observed item row");
        assert_eq!(
            read.approved.as_deref(),
            Some("one"),
            "a sighting carries no authority to rewrite configured approval"
        );
        assert_eq!(read.seen.as_deref(), Some(evidence));
        assert_eq!(
            h.trust_serves(&c, "fs", Some("draft"), Some(evidence))
                .value,
            DISTRUST_NOT_APPROVED,
            "observing a new item never grants it"
        );
    }
    assert_ne!(
        h.trust_serves(&c, "fs", Some("read"), Some("two")).value,
        DISTRUST_NONE,
        "changed evidence does not become its own approval"
    );
}

#[test]
fn counterparty_sightings_refuse_invalid_evidence_without_mutating_seen() {
    let h = trust_host();
    let c = caller("plane");
    let sight = |who: &Caller, cp: &str, evidence: &str| {
        let (l, rx) = later();
        answer(h.trust_sight(who, cp, evidence, l), &rx)
    };
    assert_eq!(sight(&c, "fs", "one").outcome, Outcome::Ready);
    for evidence in ["", " \t\n", "before\0after"] {
        assert_eq!(sight(&c, "fs", evidence).outcome, Outcome::Refused);
        let rows = h.trust_rows();
        let row = rows
            .iter()
            .find(|r| r.counterparty == "fs" && r.item.is_none())
            .unwrap();
        assert_eq!(
            row.seen.as_deref(),
            Some("one"),
            "invalid evidence changes no retained observation"
        );
    }
    let unadmitted = sight(&caller("unadmitted"), "fs", "");
    assert_eq!(
        (unadmitted.outcome, unadmitted.error),
        (Outcome::Refused, NOT_ADMITTED)
    );
    assert_eq!(
        sight(&c, "unknown", "").error,
        busbar_kernel::host_services::NOT_A_COUNTERPARTY
    );
    assert_eq!(
        sight(&c, "fs", "interior space").outcome,
        Outcome::Ready,
        "only blank and NUL are invalid; no extra digest grammar"
    );
}
