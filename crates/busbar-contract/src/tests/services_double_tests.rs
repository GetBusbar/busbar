// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared host-services double (`services_double.rs`): every service the trait declares
//! answers as an unserved host's on a double that overrides nothing, and an override answers in
//! its place while the rest still refuse.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::super::{
    Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, Reading, RecordsList, Snapshot,
    Stored, TrustKeyRef, UNSERVED,
};
use super::{ServicesDouble, Unserved};
use crate::abi::mechanism::KindCode;

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
        now("work_settle", s.work_settle(&caller(), 5, b"rec", later(l)))
    }),
    ("work_resume", |s, l| {
        now(
            "work_resume",
            s.work_resume(&caller(), Some(1), 5, later(l)),
        )
    }),
    ("disk_append", |s, l| {
        let dest = DiskDest {
            key: "file".to_string(),
            path: "/nowhere".to_string(),
            rotate_at: None,
            keep: 0,
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

/// The method names the `HostServices` trait declares, read off its own source: every `fn <name>(`
/// between `pub trait HostServices` and the trait's closing brace.
fn trait_methods() -> Vec<String> {
    let src = include_str!("../services.rs");
    let body = src
        .split_once("pub trait HostServices")
        .expect("services.rs declares HostServices")
        .1;
    let body = &body[..body.find("\n}\n").expect("the trait closes")];
    body.lines()
        .filter_map(|l| l.trim().strip_prefix("fn "))
        .map(|l| l.split(['(', '<']).next().unwrap_or_default().to_string())
        .collect()
}

/// THE COVERAGE: the rows are exactly the trait's methods. RED: a service the trait gains without
/// a row here (its refusing default unproven), or a row for a service it dropped.
#[test]
fn the_rows_are_every_service_the_trait_declares() {
    let mut declared = trait_methods();
    assert!(
        declared.len() > 20,
        "the trait read is broken: {declared:?}"
    );
    declared.sort();
    let mut rows: Vec<String> = ROWS.iter().map(|(n, _)| (*n).to_string()).collect();
    rows.sort();
    assert_eq!(
        rows, declared,
        "every HostServices method has a row here, and a refusing default in ServicesDouble"
    );
}

/// THE REFUSAL: on the double that overrides nothing, every service answers REFUSED `UNSERVED`
/// at once, and the clock the zero reading. RED: a service whose default serves, pends, or
/// refuses in other words than an unserved host's.
#[test]
fn every_service_of_the_bare_double_answers_as_unserved() {
    let calls = Arc::new(AtomicUsize::new(0));
    let double: Arc<dyn HostServices> = Arc::new(Unserved);
    for (name, call) in ROWS {
        assert_eq!(
            call(double.as_ref(), &calls),
            Stored::refused(UNSERVED),
            "{name}"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no later is ever called");
}

/// A double serving the clock and `dest.judge`, and counting its judgements.
#[derive(Default)]
struct Judging {
    judged: AtomicUsize,
}

impl ServicesDouble for Judging {
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

/// THE OVERRIDE: an overridden service answers the double's own answer, through the trait object,
/// and every other service still answers as unserved.
#[test]
fn an_override_answers_and_the_rest_still_refuse() {
    let double = Arc::new(Judging::default());
    let host: Arc<dyn HostServices> = double.clone();
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
    assert_eq!(double.judged.load(Ordering::SeqCst), 2);
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
