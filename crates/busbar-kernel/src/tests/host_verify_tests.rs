// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host-side verify cache: hit, lead and follow; a lead that lapses passes to a follower; every
//! bound refuses; two instances never share a key.

use std::sync::{Arc, Mutex};

use busbar_contract::abi::host::service::{VERIFY_FOLLOW, VERIFY_HIT, VERIFY_LEAD};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::services::{Later, Ran, Stored};

use super::*;

/// A [`Later`] that keeps what it is answered.
fn kept() -> (Later, Arc<Mutex<Option<Stored>>>) {
    let got = Arc::new(Mutex::new(None));
    let g = Arc::clone(&got);
    (Box::new(move |s| *g.lock().unwrap() = Some(s)), got)
}

fn now(r: Ran) -> Stored {
    match r {
        Ran::Now(s) => s,
        Ran::Later => panic!("pended"),
    }
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

/// RED: a leader that never stores does not wedge its followers: the tick hands the lead to the
/// first one, and a lookup after the lapse leads.
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

    // A lapsed lead with nobody waiting is taken over by the next lookup.
    let _ = now(book.lookup(&a, b"j", 0, kept().0));
    assert_eq!(
        now(book.lookup(&a, b"j", LEAD_MS, kept().0)).value,
        VERIFY_LEAD
    );
}

/// RED: two instances never share an entry or a lead.
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

/// RED, one arm per bound: an entry too long, a full cache, a full lead.
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

    // Every key led (in use): a new key is refused, never evicting a lead.
    let b = label("b");
    for n in 0..MAX_KEYS {
        let _ = now(book.lookup(&b, &n.to_le_bytes(), 0, kept().0));
    }
    let s = now(book.lookup(&b, b"one more", 0, kept().0));
    assert_eq!((s.outcome, s.error), (Outcome::Refused, CACHE_FULL));
    // An idle key with a stale entry makes room.
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
