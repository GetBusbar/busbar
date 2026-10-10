// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `unit.nest` as the kernel serves it: a child of the unit the crossing serves, handed to the
//! root's seam under the parent's principal and one more depth; the depth cap and the node's
//! permit bound; the whole reply laid out as the ABI states it; a reply the root drops answers
//! FAILED and gives its permit back.

use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::check::SPAN_ABSENT;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::records::VirtualKey;
use busbar_contract::services::{Caller, HostServices, Later, NestAsk, Ran, Stored};

use super::*;
use crate::host_units::UnitRecord;

/// A root seam that records every nest and answers by script: `held` keeps the reply for the test,
/// otherwise it answers at once with status 200, one field and the body echoed.
#[derive(Default)]
struct Seam {
    seen: Mutex<Vec<Nest>>,
    held: Mutex<Vec<NestDone>>,
    hold: bool,
    drop_reply: bool,
}

impl NestRoute for Seam {
    fn nest(&self, nest: Nest, done: NestDone) {
        let body = nest.ask.body.clone();
        self.seen.lock().unwrap().push(nest);
        if self.drop_reply {
            return;
        }
        if self.hold {
            self.held.lock().unwrap().push(done);
            return;
        }
        done(NestReply::Answered {
            status: 200,
            fields: vec![(b"x-child".to_vec(), b"yes".to_vec())],
            body,
        });
    }
}

fn caller() -> Caller {
    Caller {
        instance: Arc::from("inst"),
        plugin: Arc::from("the-plugin"),
        kind: KindCode::Plane,
    }
}

fn services(seam: Arc<Seam>) -> KernelServices {
    let s = KernelServices::new();
    s.admit("inst", InstanceFacts::default()).unwrap();
    assert!(s.attach_nest(seam));
    s
}

fn ask(body: &[u8]) -> NestAsk {
    NestAsk {
        verb: "POST".into(),
        target: "/child".into(),
        body: body.to_vec(),
    }
}

fn run(f: impl FnOnce(Later) -> Ran) -> Option<Stored> {
    let slot: Arc<Mutex<Option<Stored>>> = Arc::default();
    let mine = Arc::clone(&slot);
    match f(Box::new(move |s| *mine.lock().unwrap() = Some(s))) {
        Ran::Now(s) => Some(s),
        Ran::Later => slot.lock().unwrap().take(),
    }
}

fn alice() -> Arc<VirtualKey> {
    Arc::new(VirtualKey {
        id: "alice".into(),
        ..VirtualKey::default()
    })
}

#[test]
fn a_nested_unit_runs_under_its_parents_principal_one_level_deeper() {
    let seam = Arc::new(Seam::default());
    let s = services(Arc::clone(&seam));
    s.units().admitted(
        7,
        UnitRecord {
            principal: Some(alice()),
            depth: 1,
        },
    );
    let got = run(|l| s.unit_nest(&caller(), Some(7), ask(b"hello"), l)).expect("answered");
    let seen = seam.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!((seen[0].parent, seen[0].depth), (7, 2));
    assert_eq!(
        seen[0].principal.as_ref().map(|k| k.id.as_str()),
        Some("alice")
    );
    assert_eq!(seen[0].ask, ask(b"hello"));
    // The whole reply: the status, the body in span 0, each field after it.
    assert_eq!((got.outcome, got.value), (Outcome::Ready, 200));
    let at = |o: u32, n: u32| got.bytes[o as usize..(o + n) as usize].to_vec();
    assert_eq!(got.spans[0].key.offset, SPAN_ABSENT);
    assert_eq!(
        at(got.spans[0].value.offset, got.spans[0].value.len),
        b"hello"
    );
    let f = got.spans[1];
    assert_eq!(at(f.key.offset, f.key.len), b"x-child");
    assert_eq!(at(f.value.offset, f.value.len), b"yes");
    assert_eq!(
        s.nested().available(),
        NEST_CONCURRENCY,
        "the permit went back"
    );
}

#[test]
fn a_nest_with_no_unit_in_flight_or_past_the_cap_is_refused_before_the_root_sees_it() {
    let seam = Arc::new(Seam::default());
    let s = services(Arc::clone(&seam));
    let refused = |r: Option<Stored>, why: &str| {
        let r = r.expect("answered");
        assert_eq!((r.outcome, r.error), (Outcome::Refused, why));
    };
    refused(
        run(|l| s.unit_nest(&caller(), None, ask(b""), l)),
        NEST_NO_UNIT,
    );
    refused(
        run(|l| s.unit_nest(&caller(), Some(9), ask(b""), l)),
        NEST_NO_UNIT,
    );
    s.units().admitted(
        9,
        UnitRecord {
            principal: None,
            depth: NEST_DEPTH_MAX,
        },
    );
    refused(
        run(|l| s.unit_nest(&caller(), Some(9), ask(b""), l)),
        NEST_TOO_DEEP,
    );
    // An instance never admitted.
    let stranger = Caller {
        instance: Arc::from("stranger"),
        ..caller()
    };
    refused(
        run(|l| s.unit_nest(&stranger, Some(9), ask(b""), l)),
        NOT_ADMITTED,
    );
    assert!(seam.seen.lock().unwrap().is_empty());
    // The deepest child the cap admits runs.
    s.units().admitted(
        10,
        UnitRecord {
            principal: None,
            depth: NEST_DEPTH_MAX - 1,
        },
    );
    let ok = run(|l| s.unit_nest(&caller(), Some(10), ask(b""), l)).expect("answered");
    assert_eq!(ok.outcome, Outcome::Ready);
    assert_eq!(seam.seen.lock().unwrap()[0].depth, NEST_DEPTH_MAX);
}

#[test]
fn services_with_no_seam_refuse_a_nest() {
    let s = KernelServices::new();
    s.admit("inst", InstanceFacts::default()).unwrap();
    s.units().admitted(1, UnitRecord::default());
    let r = run(|l| s.unit_nest(&caller(), Some(1), ask(b""), l)).expect("answered");
    assert_eq!((r.outcome, r.error), (Outcome::Refused, NO_NEST_ROUTE));
}

#[test]
fn a_nest_pends_until_the_child_answers_and_holds_its_permit_meanwhile() {
    let seam = Arc::new(Seam {
        hold: true,
        ..Seam::default()
    });
    let s = services(Arc::clone(&seam));
    s.units().admitted(1, UnitRecord::default());
    let slot: Arc<Mutex<Option<Stored>>> = Arc::default();
    let mine = Arc::clone(&slot);
    let ran = s.unit_nest(
        &caller(),
        Some(1),
        ask(b"x"),
        Box::new(move |st| *mine.lock().unwrap() = Some(st)),
    );
    assert!(matches!(ran, Ran::Later));
    assert!(slot.lock().unwrap().is_none(), "pending");
    assert_eq!(s.nested().available(), NEST_CONCURRENCY - 1);
    let done = seam.held.lock().unwrap().pop().unwrap();
    done(NestReply::Unserved("nothing serves that claim"));
    let got = slot.lock().unwrap().take().expect("answered");
    assert_eq!(
        (got.outcome, got.error),
        (Outcome::Refused, "nothing serves that claim")
    );
    assert_eq!(s.nested().available(), NEST_CONCURRENCY);
}

#[test]
fn a_reply_the_root_drops_answers_failed_and_gives_its_permit_back() {
    let seam = Arc::new(Seam {
        drop_reply: true,
        ..Seam::default()
    });
    let s = services(seam);
    s.units().admitted(1, UnitRecord::default());
    let got = run(|l| s.unit_nest(&caller(), Some(1), ask(b""), l)).expect("answered");
    assert_eq!((got.outcome, got.error), (Outcome::Failed, NEST_DROPPED));
    assert_eq!(s.nested().available(), NEST_CONCURRENCY);
}
