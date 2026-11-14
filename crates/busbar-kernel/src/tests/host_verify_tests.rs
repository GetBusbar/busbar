// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};

use busbar_contract::abi::host::service::{VERIFY_FOLLOW, VERIFY_HIT, VERIFY_LEAD};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::services::{Later, Ran, Stored};

use super::*;
use crate::host_services::tests::verdict_now as now;

fn kept() -> (Later, Arc<Mutex<Option<Stored>>>) {
    let got = Arc::new(Mutex::new(None));
    let g = Arc::clone(&got);
    (Box::new(move |s| *g.lock().unwrap() = Some(s)), got)
}

fn label(s: &str) -> Arc<str> {
    Arc::from(s)
}

#[test]
fn the_first_caller_leads_the_rest_follow_and_the_store_answers_them() {
    let book = VerifyBook::default();
    let a = label("a");
    let lead = now(book.lookup(&a, b"k", 0, kept().0));
    assert_eq!((lead.outcome, lead.value), (Outcome::Ready, VERIFY_LEAD));

    let (l1, f1) = kept();
    let (l2, f2) = kept();
    assert!(matches!(book.lookup(&a, b"k", 1, l1), Ran::Later));
    assert!(matches!(book.lookup(&a, b"k", 2, l2), Ran::Later));
    assert!(
        f1.lock().unwrap().is_none(),
        "a follower waits for the store"
    );

    let stored = book.store(&a, b"k", b"verdict", 0, 3);
    assert_eq!((stored.outcome, stored.value), (Outcome::Ready, 0));
    for f in [f1, f2] {
        let s = f.lock().unwrap().take().expect("answered by the store");
        assert_eq!(
            (s.value, s.bytes.as_slice()),
            (VERIFY_FOLLOW, &b"verdict"[..])
        );
        assert_eq!(s.spans[0].value.len, 7);
    }

    let hit = now(book.lookup(&a, b"k", 4, kept().0));
    assert_eq!(
        (hit.value, hit.bytes.as_slice()),
        (VERIFY_HIT, &b"verdict"[..])
    );
}

#[test]
fn an_entry_stands_for_its_ttl_or_the_default_then_is_led_again() {
    let book = VerifyBook::default();
    let a = label("a");
    let _ = book.store(&a, b"k", b"v", 10, 0);
    assert_eq!(now(book.lookup(&a, b"k", 9, kept().0)).value, VERIFY_HIT);
    assert_eq!(now(book.lookup(&a, b"k", 10, kept().0)).value, VERIFY_LEAD);
    let _ = book.store(&a, b"d", b"v", 0, 0);
    assert_eq!(
        now(book.lookup(&a, b"d", DEFAULT_TTL_MS - 1, kept().0)).value,
        VERIFY_HIT
    );
}

#[test]
fn a_lapsed_lead_passes_to_the_first_follower() {
    let book = VerifyBook::default();
    let a = label("a");
    let _ = now(book.lookup(&a, b"k", 0, kept().0));
    let (l1, f1) = kept();
    let (l2, f2) = kept();
    assert!(matches!(book.lookup(&a, b"k", 1, l1), Ran::Later));
    assert!(matches!(book.lookup(&a, b"k", 1, l2), Ran::Later));
    assert_eq!(book.expire(LEAD_MS - 1), 0, "the lead still stands");
    assert_eq!(book.expire(LEAD_MS), 1);
    assert_eq!(
        f1.lock().unwrap().take().map(|s| s.value),
        Some(VERIFY_LEAD)
    );
    assert!(f2.lock().unwrap().is_none(), "the second keeps following");
    let _ = book.store(&a, b"k", b"v", 0, LEAD_MS + 1);
    assert_eq!(
        f2.lock().unwrap().take().map(|s| s.value),
        Some(VERIFY_FOLLOW)
    );

    let _ = now(book.lookup(&a, b"j", 0, kept().0));
    assert_eq!(
        now(book.lookup(&a, b"j", LEAD_MS, kept().0)).value,
        VERIFY_LEAD
    );
}

#[test]
fn two_instances_never_share_a_key() {
    let book = VerifyBook::default();
    let _ = book.store(&label("a"), b"k", b"a's", 0, 0);
    assert_eq!(
        now(book.lookup(&label("b"), b"k", 1, kept().0)).value,
        VERIFY_LEAD
    );
    assert_eq!(
        now(book.lookup(&label("a"), b"k", 1, kept().0)).value,
        VERIFY_HIT
    );
}

#[test]
fn every_bound_refuses() {
    let book = VerifyBook::default();
    let a = label("a");
    let long = vec![0u8; MAX_ENTRY + 1];
    let s = book.store(&a, b"k", &long, 0, 0);
    assert_eq!((s.outcome, s.error), (Outcome::Refused, ENTRY_TOO_LONG));

    for n in 0..MAX_FOLLOWERS {
        if n == 0 {
            let _ = now(book.lookup(&a, b"f", 0, kept().0));
        }
        assert!(matches!(book.lookup(&a, b"f", 1, kept().0), Ran::Later));
    }
    let s = now(book.lookup(&a, b"f", 1, kept().0));
    assert_eq!((s.outcome, s.error), (Outcome::Refused, TOO_MANY_FOLLOWERS));

    let b = label("b");
    for n in 0..MAX_KEYS {
        let _ = now(book.lookup(&b, &n.to_le_bytes(), 0, kept().0));
    }
    let s = now(book.lookup(&b, b"one more", 0, kept().0));
    assert_eq!((s.outcome, s.error), (Outcome::Refused, CACHE_FULL));

    let c = label("c");
    for n in 0..MAX_KEYS {
        let _ = book.store(&c, &n.to_le_bytes(), b"v", 1, 0);
    }
    assert_eq!(
        now(book.lookup(&c, b"one more", 5, kept().0)).value,
        VERIFY_LEAD
    );
    assert!(book.keys("c") <= MAX_KEYS);
}

fn visits(book: &VerifyBook, instance: &str) -> u64 {
    book.lock().get(instance).map_or(0, Keys::visits)
}

/// C5: a new key's admission visits no slot it does not answer about, at any fill.
#[test]
fn verify_room_visits_flat() {
    let cost = |n: usize| {
        let book = VerifyBook::default();
        let a = label("a");
        for i in 0..n {
            let _ = book.store(&a, &i.to_le_bytes(), b"v", 1_000, 0);
        }
        let before = visits(&book, "a");
        let _ = now(book.lookup(&a, b"new", 1, kept().0));
        visits(&book, "a") - before
    };
    assert_eq!(cost(10), cost(MAX_KEYS - 1));
    assert!(cost(MAX_KEYS) <= (expiry::POP_PER_OP + 2) as u64);
}

/// C5: a slot with a lead and followers is pinned: no pop, slice or at-cap insert drops it, and
/// every follower is answered by the store.
#[test]
fn verify_pinned_never_popped() {
    let book = VerifyBook::default();
    let a = label("a");
    let _ = book.store(&a, b"k", b"old", 1, 0);
    assert_eq!(now(book.lookup(&a, b"k", 5, kept().0)).value, VERIFY_LEAD);
    let mut waiting = Vec::new();
    for _ in 0..MAX_FOLLOWERS {
        let (later, got) = kept();
        assert!(matches!(book.lookup(&a, b"k", 6, later), Ran::Later));
        waiting.push(got);
    }
    for i in 0..MAX_KEYS - 1 {
        let _ = book.store(&a, &i.to_le_bytes(), b"v", 5, 6);
    }
    assert_eq!(book.expire(100), 0, "the lead stands");
    for i in 0..MAX_KEYS {
        let _ = now(book.lookup(&a, &(i + MAX_KEYS).to_le_bytes(), 200, kept().0));
    }
    let _ = book.store(&a, b"k", b"new", 0, 300);
    for got in waiting {
        let s = got
            .lock()
            .unwrap()
            .take()
            .expect("every follower is answered");
        assert_eq!((s.value, s.bytes), (VERIFY_FOLLOW, b"new".to_vec()));
    }
}

/// C5: lapses go through the pinned list: one with followers hands off and stays pinned, one
/// with none and no entry is removed.
#[test]
fn verify_lapse_through_pinned_retain() {
    let book = VerifyBook::default();
    let a = label("a");
    let _ = now(book.lookup(&a, b"bare", 0, kept().0));
    // A stale entry is popped before a lead is made, so this lead holds no entry either.
    let _ = book.store(&a, b"stale", b"v", 10, 0);
    let _ = now(book.lookup(&a, b"stale", 10, kept().0));
    let _ = now(book.lookup(&a, b"led", 0, kept().0));
    let (later, got) = kept();
    assert!(matches!(book.lookup(&a, b"led", 1, later), Ran::Later));
    assert_eq!(book.expire(LEAD_MS + 10), 1, "the follower takes the lead");
    assert_eq!(got.lock().unwrap().take().unwrap().value, VERIFY_LEAD);
    assert_eq!(
        book.keys("a"),
        1,
        "the lapsed leads with no follower are removed; the handed one stays"
    );
    assert!(matches!(
        book.lookup(&a, b"led", LEAD_MS + 11, kept().0),
        Ran::Later
    ));
}

/// C5 (7c): a full cache past its deadlines is idle after one `verify_tick`.
#[test]
fn verify_drains_to_idle_in_one_pass() {
    let book = VerifyBook::default();
    let a = label("a");
    for i in 0..MAX_KEYS {
        let _ = book.store(&a, &i.to_le_bytes(), b"v", 1_000, 0);
    }
    assert_eq!(book.keys("a"), MAX_KEYS);
    let _ = book.expire(1_000);
    assert_eq!(book.keys("a"), 0);
}
