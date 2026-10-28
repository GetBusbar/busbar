// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The list rule and the unserved defaults (`services.rs`).

use super::*;

fn kv(k: &str, v: &str) -> (Vec<u8>, Vec<u8>) {
    (k.as_bytes().to_vec(), v.as_bytes().to_vec())
}

#[test]
fn the_list_lays_queued_writes_over_the_store_then_applies_after_and_limit() {
    let stored = vec![kv("a", "s"), kv("b", "s"), kv("c", "s")];
    let queued = vec![kv("c", "q"), kv("d", "q")];
    assert_eq!(
        merge_list(stored.clone(), queued.clone(), None, 10),
        vec![kv("a", "s"), kv("b", "s"), kv("c", "q"), kv("d", "q")]
    );
    assert_eq!(
        merge_list(stored.clone(), queued.clone(), Some(b"b"), 10),
        vec![kv("c", "q"), kv("d", "q")]
    );
    assert_eq!(merge_list(stored, queued, None, 1), vec![kv("a", "s")]);
}

#[test]
fn a_tombstone_is_absent_and_a_queued_one_hides_the_stored_row_before_the_limit() {
    let stored = vec![kv("a", "s"), kv("b", ""), kv("c", "s")];
    let queued = vec![kv("a", "")];
    assert_eq!(merge_list(stored, queued, None, 1), vec![kv("c", "s")]);
}

/// A chained record's listed key is its scope, `/` and twenty digits; the parts read back from it,
/// and a key that is no record's (a bare scope, a short or non-digit tail) names none.
#[test]
fn a_chain_key_is_its_scope_and_its_sequence_and_reads_back() {
    let key = chain_key(b"a11ce/t1", 7);
    assert_eq!(key, b"a11ce/t1/00000000000000000007".to_vec());
    assert_eq!(chain_key_parts(&key), Some((&b"a11ce/t1"[..], 7)));
    assert_eq!(
        chain_key_parts(&chain_key(b"s", u64::MAX)),
        Some((&b"s"[..], u64::MAX))
    );
    for none in [
        &b"a11ce/t1"[..],
        b"/00000000000000000007",
        b"t1/0000000000000000007",
        b"t1-00000000000000000007",
        b"t1/0000000000000000000x",
        b"t1/99999999999999999999",
    ] {
        assert_eq!(
            chain_key_parts(none),
            None,
            "{}",
            String::from_utf8_lossy(none)
        );
    }
    assert!(
        chain_key(b"t1", 9) < chain_key(b"t1", 10),
        "key order is sequence order"
    );
}

// ── the unserved defaults ────────────────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicUsize, Ordering};

fn caller() -> Caller {
    Caller {
        instance: Arc::from("the-instance"),
        plugin: Arc::from("the-plugin"),
        kind: KindCode::Store,
    }
}

/// A [`Later`] that counts its calls: an unserved service answers at once and never calls it.
fn later(calls: &Arc<AtomicUsize>) -> Later {
    let calls = Arc::clone(calls);
    Box::new(move |_| {
        calls.fetch_add(1, Ordering::SeqCst);
    })
}

/// A finished answer; a pend is a finding.
fn now(name: &str, ran: Ran) -> Stored {
    match ran {
        Ran::Now(stored) => stored,
        Ran::Later => panic!("{name}: an unserved service answers at once, it never pends"),
    }
}

/// One row per [`HostServices`] method: its name as the trait spells it, and a call of it through
/// the trait object. `now` is the clock, which has no refusal; its row answers the zero reading as
/// READY `0` and is checked on its own below.
type Row = (
    &'static str,
    fn(&dyn HostServices, &Arc<AtomicUsize>) -> Stored,
);

const ROWS: &[Row] = &[
    ("now", |s, _| {
        assert_eq!(
            s.now(),
            Reading {
                wall_ns: 0,
                mono_ns: 0
            }
        );
        Stored::refused(UNSERVED)
    }),
    ("dest_judge", |s, l| {
        now("dest_judge", s.dest_judge("x", 0, 0, Some(later(l))))
    }),
    ("records_get", |s, l| {
        now(
            "records_get",
            s.records_get(&caller(), "k", b"key", later(l)),
        )
    }),
    ("records_list", |s, l| {
        let list = RecordsList {
            kind: "k".to_string(),
            prefix: Vec::new(),
            after: None,
            limit: 0,
        };
        now("records_list", s.records_list(&caller(), list, later(l)))
    }),
    ("records_claim", |s, l| {
        now(
            "records_claim",
            s.records_claim(&caller(), "k", b"key", 1, later(l)),
        )
    }),
    ("sign", |s, _| s.sign(&caller(), b"data")),
    ("trust_sight", |s, l| {
        now(
            "trust_sight",
            s.trust_sight(&caller(), "peer", "hash", later(l)),
        )
    }),
    ("trust_unreached", |s, _| {
        s.trust_unreached(&caller(), "peer")
    }),
    ("trust_sight_item", |s, _| {
        s.trust_sight_item(&caller(), "peer", "item", "digest")
    }),
    ("trust_decide", |s, _| {
        let key = TrustKeyRef {
            counterparty: "peer",
            item: Some("item"),
        };
        s.trust_decide(&caller(), key, Some("digest"), true)
    }),
    ("trust_state", |s, _| s.trust_state(&caller(), "peer")),
    ("trust_serves", |s, _| {
        s.trust_serves(&caller(), "peer", Some("item"), None)
    }),
    ("trust_due", |s, _| s.trust_due(&caller())),
    ("trust_verify", |s, _| {
        s.trust_verify(&caller(), "peer", b"payload", b"[]")
    }),
    ("entitlement_check", |s, _| {
        s.entitlement_check(&caller(), Some(1), "model:m")
    }),
    ("session_emit", |s, _| {
        s.session_emit(&caller(), 1, b"bytes")
    }),
    ("random_fill", |s, _| s.random_fill(16)),
    ("records_secret", |s, l| {
        now("records_secret", s.records_secret("k", "id", later(l)))
    }),
    ("unit_nest", |s, l| {
        let ask = NestAsk {
            verb: "v".to_string(),
            target: "t".to_string(),
            body: Vec::new(),
        };
        now("unit_nest", s.unit_nest(&caller(), Some(1), ask, later(l)))
    }),
    ("work_open", |s, l| {
        now(
            "work_open",
            s.work_open(&caller(), Some(1), "k", b"rec", later(l)),
        )
    }),
    ("work_find", |s, l| {
        now(
            "work_find",
            s.work_find(&caller(), Some(1), b"ref", later(l)),
        )
    }),
    ("work_settle", |s, l| {
        now(
            "work_settle",
            s.work_settle(&caller(), None, 5, b"rec", later(l)),
        )
    }),
    ("work_resume", |s, l| {
        now(
            "work_resume",
            s.work_resume(&caller(), Some(1), 5, later(l)),
        )
    }),
    ("disk_append", |s, l| {
        let dest = DiskDest {
            key: "sink".to_string(),
            path: "/nowhere".to_string(),
            rotate_at: None,
            rotate: DiskRotate::Truncate,
        };
        now(
            "disk_append",
            s.disk_append(&dest, b"line".to_vec(), later(l)),
        )
    }),
    ("verify_lookup", |s, l| {
        now(
            "verify_lookup",
            s.verify_lookup(&caller(), b"key", later(l)),
        )
    }),
    ("verify_store", |s, _| {
        s.verify_store(&caller(), b"key", b"entry", 0)
    }),
    ("content_scan", |s, l| {
        now(
            "content_scan",
            s.content_scan(&caller(), Some(1), b"text", later(l)),
        )
    }),
    ("hook_call", |s, l| {
        let ask = HookAsk {
            stage: 0,
            from: 0,
            system: None,
            messages: Vec::new(),
        };
        now("hook_call", s.hook_call(&caller(), Some(1), ask, later(l)))
    }),
    ("snapshot_read", |s, _| {
        match s.snapshot_read(&caller(), 0) {
            Snapshot::Refused(why) => Stored::refused(why),
            other => panic!("snapshot_read: an unserved snapshot is refused, not {other:?}"),
        }
    }),
];

/// A host that overrides nothing.
struct Bare;

impl HostServices for Bare {}

/// THE REFUSAL: on a host that overrides nothing, every service answers REFUSED `UNSERVED` at
/// once, and the clock the zero reading. RED: a service whose default serves, pends, or refuses in
/// other words than an unserved host's.
#[test]
fn every_service_of_a_bare_host_answers_as_unserved() {
    let calls = Arc::new(AtomicUsize::new(0));
    let host: Arc<dyn HostServices> = Arc::new(Bare);
    for (name, call) in ROWS {
        assert_eq!(
            call(host.as_ref(), &calls),
            Stored::refused(UNSERVED),
            "{name}"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no later is ever called");
}

/// A host serving the clock and `dest.judge`, and counting its judgements.
#[derive(Default)]
struct Judging {
    judged: AtomicUsize,
}

impl HostServices for Judging {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 7,
            mono_ns: 9,
        }
    }

    fn dest_judge(&self, _: &str, _: u32, _: u32, later: Option<Later>) -> Ran {
        self.judged.fetch_add(1, Ordering::SeqCst);
        match later {
            Some(later) => {
                later(Stored::ready(3));
                Ran::Later
            }
            None => Ran::Now(Stored::ready(3)),
        }
    }
}

/// THE OVERRIDE: an overridden service answers the host's own answer, through the trait object,
/// and every other service still answers as unserved.
#[test]
fn an_override_answers_and_the_rest_still_refuse() {
    let judging = Arc::new(Judging::default());
    let host: Arc<dyn HostServices> = judging.clone();
    assert_eq!(
        host.now(),
        Reading {
            wall_ns: 7,
            mono_ns: 9
        }
    );
    assert_eq!(
        now("dest_judge", host.dest_judge("x", 0, 0, None)),
        Stored::ready(3)
    );
    let calls = Arc::new(AtomicUsize::new(0));
    assert!(matches!(
        host.dest_judge("x", 0, 0, Some(later(&calls))),
        Ran::Later
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the override handed its later on"
    );
    assert_eq!(judging.judged.load(Ordering::SeqCst), 2);
    for (name, call) in ROWS
        .iter()
        .filter(|(n, _)| !["now", "dest_judge"].contains(n))
    {
        assert_eq!(
            call(host.as_ref(), &calls),
            Stored::refused(UNSERVED),
            "{name}"
        );
    }
}
