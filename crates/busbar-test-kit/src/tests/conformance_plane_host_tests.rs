// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE SCRIPT'S HOST SERVES WHAT THE KERNEL SERVES (`conformance/plane_host.rs`; THE DESIGN
//! §2: "Each kind has ONE conformance suite that runs the shipped compiled-in build and the
//! dropped-in build through the same table"; §11.12, the host services). A plane that judges a
//! destination (`dest.judge`), draws random bytes (`random.fill`), reads and claims its own records
//! (`records.get` / `records.list` / `records.claim`) or asks whether a counterparty serves with no
//! item named (`trust.serves`) is answered here as the kernel answers it, with the kernel's
//! refusals, so the published suite can run its door at all. RED: each service refused UNSERVED, and
//! an item-less trust row not read.

use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::host::conn::connector::{
    EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::host::service::{
    DEST_ALLOWED, DEST_EXPLAIN, DEST_INTERNAL, DEST_METADATA, DEST_NO_HOST, DEST_OBFUSCATED,
    DEST_PLAINTEXT, DEST_REFUSE_PRIVATE, DEST_RESOLVE, DEST_SCHEME, DEST_UNRESOLVABLE,
    DISTRUST_NONE, DISTRUST_NOT_APPROVED, DISTRUST_UNKNOWN, DISTRUST_UNKNOWN_ITEM, MAX_RANDOM_FILL,
};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::{RecordChain, CHAIN_LENGTH_PREFIXED};
use busbar_contract::net::METADATA_HOSTS;
use busbar_contract::plane_calls::InstanceDecl;
use busbar_contract::services::{chain_key, Caller, HostServices, Later, Ran, RecordsList, Stored};
use serde_json::{json, Value};

use super::host::Host;

/// The kernel's words for a fill of no bytes or above the cap.
const FILL_OUT_OF_RANGE: &str = "a fill asks for 1 to MAX_RANDOM_FILL bytes";
/// The kernel's words for a caller it never admitted.
const NOT_ADMITTED: &str = "the instance is not admitted";
/// The kernel's words for a record kind the caller did not declare.
const NOT_A_KIND: &str = "not a record kind the instance declared";
/// The kernel's words for `records.get` on a chained kind.
const CHAIN_READ_WHOLE: &str = "a chained record kind is read whole, through records.list";
/// The kernel's words for a claim with no time to live.
const NO_TTL: &str = "a claim states its time to live";
/// The kernel's words for a may-pend judgement asked outside a ticketed op.
const UNTICKETED: &str = "a service that may pend is callable only inside a ticketed op";

fn host(v: &Value) -> Host {
    Host::of(v).expect("a stated host")
}

fn caller(instance: &str) -> Caller {
    Caller {
        instance: Arc::from(instance),
        plugin: Arc::from("plane"),
        kind: KindCode::Plane,
    }
}

/// A completion and where its answer arrives.
fn later() -> (Later, mpsc::Receiver<Stored>) {
    let (tx, rx) = mpsc::channel();
    (
        Box::new(move |s| {
            let _ = tx.send(s);
        }),
        rx,
    )
}

/// The answer `r` gives, at once or through its completion.
fn answer(r: Ran, rx: &mpsc::Receiver<Stored>) -> Stored {
    match r {
        Ran::Now(s) => s,
        Ran::Later => rx
            .recv_timeout(Duration::from_secs(10))
            .expect("a pended service answers"),
    }
}

/// `dest.judge` of `dest` under `class` and `flags`, with no ticket.
fn judged(h: &Host, dest: &str, class: u32, flags: u32) -> Stored {
    match h.dest_judge(dest, class, flags, None) {
        Ran::Now(s) => s,
        Ran::Later => panic!("`{dest}`: a ticket-less judgement pended"),
    }
}

/// The span keys of `s`, as text.
fn keys(s: &Stored) -> Vec<String> {
    s.spans
        .iter()
        .map(|sp| {
            let (at, len) = (sp.key.offset as usize, sp.key.len as usize);
            String::from_utf8_lossy(&s.bytes[at..at + len]).into_owned()
        })
        .collect()
}

#[test]
fn random_fill_draws_fresh_bytes_the_same_on_both_legs_and_refuses_outside_its_cap() {
    let (linked, dropped) = (host(&json!({})), host(&json!({})));
    let first = linked.random_fill(16);
    assert_eq!(first.outcome, Outcome::Ready, "{first:?}");
    assert_eq!(first.bytes.len(), 16, "a fill writes the bytes it asks for");
    let second = linked.random_fill(16);
    assert_eq!(second.outcome, Outcome::Ready, "{second:?}");
    assert_ne!(first.bytes, second.bytes, "every fill draws fresh bytes");
    // The two legs draw one stream, so what a plane mints from it folds the same on both.
    assert_eq!(dropped.random_fill(16).bytes, first.bytes);
    assert_eq!(dropped.random_fill(16).bytes, second.bytes);
    let whole = linked.random_fill(MAX_RANDOM_FILL);
    assert_eq!(whole.bytes.len() as u64, MAX_RANDOM_FILL, "{whole:?}");
    for len in [0, MAX_RANDOM_FILL + 1] {
        let s = linked.random_fill(len);
        assert_eq!(
            (s.outcome, s.error),
            (Outcome::Refused, FILL_OUT_OF_RANGE),
            "a fill of {len} bytes"
        );
    }
}

#[test]
fn dest_judge_answers_the_owner_default_guard_without_resolving() {
    let h = host(&json!({}));
    let metadata = format!("https://{}/", METADATA_HOSTS[0]);
    let open = EGRESS_OPEN_WEB;
    let infra = EGRESS_OPERATOR_INFRASTRUCTURE;
    let strict = DEST_REFUSE_PRIVATE | DEST_EXPLAIN;
    for (dest, class, flags, verdict) in [
        ("https://vendor.example/agent", open, strict, DEST_ALLOWED),
        (
            "https://vendor.example/agent",
            infra,
            DEST_EXPLAIN,
            DEST_ALLOWED,
        ),
        ("HTTPS://vendor.example/", open, 0, DEST_ALLOWED),
        ("vendor.example:8443", open, 0, DEST_ALLOWED),
        ("http://vendor.example/", open, 0, DEST_PLAINTEXT),
        ("http://vendor.example/", infra, 0, DEST_ALLOWED),
        ("ftp://vendor.example/", open, 0, DEST_SCHEME),
        ("https://user@vendor.example/", open, 0, DEST_NO_HOST),
        ("", open, 0, DEST_NO_HOST),
        (
            "https://vendor.example/",
            EGRESS_LOOPBACK_ALLOWED + 1,
            0,
            DEST_NO_HOST,
        ),
        (metadata.as_str(), infra, 0, DEST_METADATA),
        ("https://169.254.169.254/latest", infra, 0, DEST_METADATA),
        ("https://10.0.0.7/", open, 0, DEST_INTERNAL),
        ("https://10.0.0.7/", infra, 0, DEST_ALLOWED),
        (
            "https://10.0.0.7/",
            infra,
            DEST_REFUSE_PRIVATE,
            DEST_INTERNAL,
        ),
        (
            "https://127.0.0.1/",
            EGRESS_LOOPBACK_ALLOWED,
            0,
            DEST_ALLOWED,
        ),
        (
            "http://127.0.0.1/",
            EGRESS_LOOPBACK_ALLOWED,
            0,
            DEST_ALLOWED,
        ),
        (
            "http://1.1.1.1/",
            EGRESS_LOOPBACK_ALLOWED,
            0,
            DEST_PLAINTEXT,
        ),
        (
            "https://10.0.0.7/",
            EGRESS_LOOPBACK_ALLOWED,
            0,
            DEST_INTERNAL,
        ),
        ("https://localhost/", open, 0, DEST_INTERNAL),
        ("https://localhost/", infra, 0, DEST_ALLOWED),
        ("https://0x7f000001/", open, 0, DEST_OBFUSCATED),
    ] {
        let s = judged(&h, dest, class, flags);
        assert_eq!(
            (s.outcome, s.value),
            (Outcome::Ready, verdict),
            "`{dest}` under class {class}, flags {flags}: {s:?}"
        );
        // Not asked to resolve, nothing is written.
        assert!(s.bytes.is_empty() && s.spans.is_empty(), "`{dest}`: {s:?}");
    }
}

#[test]
fn dest_judge_resolves_through_the_stated_answers_and_writes_what_it_judged() {
    let h = host(&json!({ "resolve": {
        "vendor.example": ["93.184.215.14", "1.1.1.1"],
        "inner.example": ["10.1.2.3"],
        "empty.example": [] } }));
    // A literal is its own answer: judged at once, written.
    let (l, rx) = later();
    let s = answer(
        h.dest_judge("https://1.1.1.1/", EGRESS_OPEN_WEB, DEST_RESOLVE, Some(l)),
        &rx,
    );
    assert_eq!(
        (s.outcome, s.value),
        (Outcome::Ready, DEST_ALLOWED),
        "{s:?}"
    );
    assert_eq!(keys(&s), ["1.1.1.1"]);
    // A judgement asked to resolve may pend: never asked outside a ticketed op, a literal's
    // included, as the kernel refuses it.
    for dest in ["https://vendor.example/", "https://1.1.1.1/"] {
        let s = judged(&h, dest, EGRESS_OPEN_WEB, DEST_RESOLVE);
        assert_eq!(
            (s.outcome, s.error),
            (Outcome::Refused, UNTICKETED),
            "`{dest}`: {s:?}"
        );
    }
    // A refusal the name decides answers at once, ticket or none.
    let s = judged(&h, "https://localhost/", EGRESS_OPEN_WEB, DEST_RESOLVE);
    assert_eq!(
        (s.outcome, s.value),
        (Outcome::Ready, DEST_INTERNAL),
        "{s:?}"
    );
    for (dest, flags, verdict, written) in [
        (
            "https://vendor.example/",
            DEST_RESOLVE,
            DEST_ALLOWED,
            vec!["93.184.215.14", "1.1.1.1"],
        ),
        (
            "https://inner.example/",
            DEST_RESOLVE | DEST_EXPLAIN,
            DEST_INTERNAL,
            vec!["10.1.2.3"],
        ),
        (
            "https://inner.example/",
            DEST_RESOLVE,
            DEST_INTERNAL,
            vec![],
        ),
        (
            "https://empty.example/",
            DEST_RESOLVE,
            busbar_contract::abi::host::service::DEST_NO_ADDRESSES,
            vec![],
        ),
        (
            "https://unknown.example/",
            DEST_RESOLVE,
            DEST_UNRESOLVABLE,
            vec![],
        ),
    ] {
        let (l, rx) = later();
        let s = answer(h.dest_judge(dest, EGRESS_OPEN_WEB, flags, Some(l)), &rx);
        assert_eq!(
            (s.outcome, s.value),
            (Outcome::Ready, verdict),
            "`{dest}`: {s:?}"
        );
        assert_eq!(keys(&s), written, "`{dest}`: {s:?}");
    }
}

#[test]
fn records_refuse_an_instance_the_host_never_admitted() {
    let h = host(&json!({}));
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

#[test]
fn trust_serves_item_less_answers_the_counterpartys_own_verdict() {
    let h = host(&json!({ "trusted": [
        ["agent", null, "none"],
        ["agent", "tool", "not_approved"],
        ["pending", null, "not_approved"] ] }));
    let c = caller("plane");
    let verdict = |cp: &str, item: Option<&str>| h.trust_serves(&c, cp, item, None).value;
    assert_eq!(verdict("agent", None), DISTRUST_NONE);
    assert_eq!(verdict("agent", Some("tool")), DISTRUST_NOT_APPROVED);
    assert_eq!(verdict("agent", Some("other")), DISTRUST_UNKNOWN_ITEM);
    assert_eq!(verdict("pending", None), DISTRUST_NOT_APPROVED);
    // A counterparty no row names is one the instance does not declare.
    assert_eq!(verdict("stranger", None), DISTRUST_UNKNOWN);
}

/// A host that admitted the instance `plane`, declaring `tasks` and the chained `journal`.
fn admitted() -> Host {
    let h = host(&json!({}));
    h.admit(&InstanceDecl {
        label: Arc::from("plane"),
        record_kinds: vec!["tasks", "journal"],
        record_chains: vec![RecordChain {
            kind: 1,
            framing: CHAIN_LENGTH_PREFIXED,
            flags: 0,
            _reserved: 0,
        }],
        ..InstanceDecl::default()
    });
    h
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

/// The rows of a list answer, as text.
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
    // What the instance's answers wrote, it reads back.
    h.keep(0, b"t/2", b"two");
    h.keep(0, b"t/1", b"one");
    h.keep(0, b"u/1", b"else");
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
    // An empty value is a tombstone.
    h.keep(0, b"t/1", b"");
    assert_eq!(get(&h, &c, "tasks", "t/1").value, ABSENT);
    assert_eq!(
        rows(&list(&h, "tasks", "t/", None, 0)),
        [row(b"t/2", "two")]
    );
    // A claim is won once.
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
    let h = admitted();
    h.keep(1, b"task-a", b"first");
    h.keep(1, b"task-b", b"other");
    h.keep(1, b"task-a", b"second");
    // A key that is no scope is never kept.
    h.keep(1, &chain_key(b"task-c", 1), b"stray");
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
    // An empty write drops the chain; its next append starts again at 1.
    h.keep(1, b"task-a", b"");
    assert_eq!(
        rows(&list(&h, "journal", "", None, 0)),
        [row(&chain_key(b"task-b", 1), "other")]
    );
    h.keep(1, b"task-a", b"again");
    assert_eq!(
        rows(&list(&h, "journal", "task-a", None, 0)),
        [row(&chain_key(b"task-a", 1), "again")]
    );
}
