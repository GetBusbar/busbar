// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kept blocks: what they hold, in what order, and that a slot's storage comes back.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::off_path::{book, text, window, window_from};
use super::{set_bytes, set_text, Kept, Slots, Text, TextList, Window};
use crate::json;

#[derive(Debug, Default, PartialEq)]
struct Rec {
    id: u64,
    name: String,
    bytes: Vec<u8>,
}

impl Kept for Rec {
    fn clear(&mut self) {
        self.id = 0;
        self.name.clear();
        self.bytes.clear();
    }
}

fn filled(id: u64, name: &str) -> Rec {
    let mut r = Rec {
        id,
        ..Rec::default()
    };
    set_text(&mut r.name, name);
    r
}

fn ids(w: &Window<Rec>) -> Vec<u64> {
    w.iter().map(|r| r.id).collect()
}

#[test]
fn text_orders_and_hashes_as_str() {
    let keys = ["pool-b", "pool-a", "", "pool-ab", "Z"];
    let mut by_text: BTreeMap<Text, u8> = BTreeMap::new();
    let mut by_string: BTreeMap<String, u8> = BTreeMap::new();
    for (n, k) in keys.iter().enumerate() {
        let n = n as u8;
        // Both variants, alternating: the variant must not matter.
        let t = if n.is_multiple_of(2) {
            text(k)
        } else {
            Text::Shared(Arc::from(*k))
        };
        by_text.insert(t, n);
        by_string.insert((*k).into(), n);
    }
    let a: Vec<(&str, u8)> = by_text.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    let b: Vec<(&str, u8)> = by_string.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    assert_eq!(a, b);
    assert_eq!(
        json::to_string(&by_text).unwrap(),
        json::to_string(&by_string).unwrap()
    );
}

#[test]
fn text_variants_are_one_value() {
    let fixed = Text::fixed("lane/");
    let shared = text("lane/");
    assert_eq!(fixed, shared);
    assert_eq!(shared.cmp(&fixed), std::cmp::Ordering::Equal);
    assert_eq!(fixed, "lane/");
    assert_eq!(fixed, *"lane/");
    assert_eq!(fixed, String::from("lane/"));
    // A map keyed by Text is found by a &str, as one keyed by String is.
    let mut m: std::collections::HashMap<Text, u8> = std::collections::HashMap::new();
    m.insert(shared, 7);
    assert_eq!(m.get("lane/"), Some(&7));
    assert_eq!(fixed.to_string(), "lane/");
    assert!(Text::EMPTY.is_empty());
    assert_eq!(Text::default(), Text::EMPTY);
    assert_eq!(&*fixed, "lane/");
    assert_eq!(Text::from(Arc::<str>::from("x")).as_str(), "x");
}

#[test]
fn text_serialises_as_a_string_and_reads_back() {
    let t = text("a \"quoted\" name");
    assert_eq!(
        json::to_string(&t).unwrap(),
        json::to_string("a \"quoted\" name").unwrap()
    );
    let back: Text = json::parse_str(&json::to_string(&t).unwrap()).unwrap();
    assert_eq!(back, t);
    assert!(json::parse_str::<Text>("1").is_err());
}

#[test]
fn text_list_push_get_iter_clear() {
    let mut l = TextList::default();
    assert!(l.is_empty());
    l.push("content");
    l.push("");
    l.push("identity");
    assert_eq!(l.len(), 3);
    assert_eq!(l.get(0), Some("content"));
    assert_eq!(l.get(1), Some(""));
    assert_eq!(l.get(2), Some("identity"));
    assert_eq!(l.get(3), None);
    assert_eq!(l.iter().len(), 3);
    assert_eq!(
        (&l).into_iter().collect::<Vec<_>>(),
        ["content", "", "identity"]
    );
    let it = l.iter();
    assert_eq!(it.clone().count(), it.count());
    l.clear();
    assert!(l.is_empty());
    assert_eq!(l.get(0), None);
    l.push("again");
    assert_eq!(l.iter().collect::<Vec<_>>(), ["again"]);
    assert_eq!(l.clone(), l);
}

#[test]
fn set_text_and_set_bytes_replace() {
    let mut s = String::from("old value");
    set_text(&mut s, "new");
    assert_eq!(s, "new");
    let mut b = vec![1, 2, 3];
    set_bytes(&mut b, &[9]);
    assert_eq!(b, [9]);
}

#[test]
fn slots_reuse_their_records() {
    let mut s: Slots<Rec> = Slots::default();
    assert!(s.is_empty());
    {
        let r = s.push();
        r.id = 1;
        set_text(&mut r.name, "first, a long enough name to hold capacity");
    }
    s.push().id = 2;
    assert_eq!(s.len(), 2);
    assert_eq!(
        s.as_slice().iter().map(|r| r.id).collect::<Vec<_>>(),
        [1, 2]
    );
    let cap = s.as_slice()[0].name.capacity();
    s.clear();
    assert!(s.is_empty());
    assert!(s.as_slice().is_empty());
    // The first record comes back emptied, with its buffer.
    let r = s.push();
    assert_eq!(r.id, 0);
    assert!(r.name.is_empty());
    assert_eq!(r.name.capacity(), cap);
    s.as_mut_slice()[0].id = 5;
    assert_eq!(s.as_slice()[0].id, 5);
}

#[test]
fn window_below_at_and_past_capacity() {
    let mut w: Window<Rec> = window(3);
    assert_eq!((w.len(), w.capacity()), (0, 3));
    assert!(w.is_empty() && w.back().is_none());
    for id in 1..=3 {
        let mut r = filled(id, "n");
        assert!(!w.admit(&mut r), "room for {id}");
        assert_eq!(r, Rec::default(), "the record comes back emptied");
    }
    assert_eq!(ids(&w), [1, 2, 3]);
    assert_eq!(w.back().map(|r| r.id), Some(3));
    let mut r = filled(4, "newest, with a name long enough to own a buffer");
    assert!(w.admit(&mut r), "the oldest left");
    assert_eq!(ids(&w), [2, 3, 4]);
    // What came back holds the storage of the record that left (record 1: name "n").
    assert_eq!(r.id, 0);
    assert!(r.name.is_empty());
    assert!(r.name.capacity() >= 1);
    assert!(w.admit(&mut filled(5, "")));
    assert!(w.admit(&mut filled(6, "")));
    assert!(w.admit(&mut filled(7, "")));
    assert_eq!(ids(&w), [5, 6, 7]);
    w.back_mut().unwrap().id = 70;
    assert_eq!(ids(&w), [5, 6, 70]);
    assert_eq!(w.len(), 3);
    let it = w.iter();
    assert_eq!(it.clone().count(), 3);
}

#[test]
fn window_hands_back_the_evicted_storage() {
    let mut w: Window<Rec> = window(1);
    let mut first = filled(1, "a name long enough to own a heap buffer of its own");
    let cap = first.name.capacity();
    assert!(!w.admit(&mut first));
    let mut second = Rec::default();
    set_text(&mut second.name, "x");
    assert!(w.admit(&mut second));
    // `second` now owns what record 1 owned.
    assert_eq!(second.name.capacity(), cap);
    assert!(second.name.is_empty());
}

#[test]
fn window_of_no_capacity_holds_nothing() {
    let mut w: Window<Rec> = window(0);
    let mut r = filled(1, "n");
    assert!(!w.admit(&mut r));
    assert_eq!(r, Rec::default());
    assert!(w.is_empty());
    assert_eq!(w.capacity(), 0);
    assert!(w.back().is_none() && w.back_mut().is_none());
    assert_eq!(w.iter().count(), 0);
}

#[test]
fn window_from_keeps_the_newest() {
    let run: Vec<Rec> = (1..=5).map(|i| filled(i, "r")).collect();
    let w = window_from(3, run);
    assert_eq!(ids(&w), [3, 4, 5]);
    assert_eq!(w.capacity(), 3);
    let short = window_from(4, vec![filled(1, "a"), filled(2, "b")]);
    assert_eq!(ids(&short), [1, 2]);
    assert_eq!(short.capacity(), 4);
    let mut short = short;
    for i in 3..=5 {
        short.admit(&mut filled(i, ""));
    }
    assert_eq!(ids(&short), [2, 3, 4, 5]);
}

#[test]
fn book_open_close_full_and_reopen() {
    let mut b = book::<u64, Rec>(2);
    assert_eq!((b.len(), b.capacity()), (0, 2));
    assert!(b.is_empty());
    {
        let r = b.open(10).unwrap();
        r.id = 10;
        set_text(&mut r.name, "ten");
    }
    b.open(20).unwrap().id = 20;
    assert!(b.open(10).is_none(), "an open key is refused");
    assert!(b.open(30).is_none(), "a full book is refused");
    assert_eq!(b.len(), 2);
    assert_eq!(b.get(10).map(|r| r.name.as_str()), Some("ten"));
    b.get_mut(20).unwrap().id = 21;
    assert_eq!(b.get(20).map(|r| r.id), Some(21));
    assert!(b.close(10));
    assert!(!b.close(10), "closing twice");
    assert!(b.get(10).is_none());
    // The freed slot is reused, emptied.
    let r = b.open(30).unwrap();
    assert_eq!(*r, Rec::default());
    assert_eq!(b.len(), 2);
    assert!(b.close(30) && b.close(20));
    assert!(b.is_empty());
}
