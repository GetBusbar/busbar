// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KEPT BLOCKS ALLOCATE NOTHING after warm-up (GROUP-records K0): counted with the SDK's
//! `Watch` allocator, on this thread, while armed.

use busbar_contract::abi::sdk::test_support::watch::Watch;
use busbar_contract::kept::off_path::{book, text, window};
use busbar_contract::kept::{set_bytes, set_text, Kept, Slots, Text, TextList};

#[global_allocator]
static A: Watch = Watch::new();

#[derive(Debug, Default)]
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

fn fill(r: &mut Rec, id: u64) {
    r.id = id;
    set_text(&mut r.name, "a record name of ordinary length");
    set_bytes(&mut r.bytes, &[7; 48]);
}

#[test]
fn window_admit_allocates_nothing() {
    let mut w = window::<Rec>(4);
    let mut staged = Rec::default();
    // Warm: every slot and the staging record have grown to the size they will need.
    for id in 0..12 {
        fill(&mut staged, id);
        w.admit(&mut staged);
    }
    let here = A.armed_here(b"", || {
        for id in 100..140 {
            fill(&mut staged, id);
            w.admit(&mut staged);
        }
    });
    assert_eq!(here.allocs, 0);
    assert_eq!(w.len(), 4);
}

#[test]
fn text_list_refill_allocates_nothing() {
    let mut l = TextList::default();
    for _ in 0..3 {
        l.clear();
        l.push("content");
        l.push("identity");
    }
    let here = A.armed_here(b"", || {
        l.clear();
        l.push("content");
        l.push("identity");
        assert_eq!(l.iter().count(), 2);
    });
    assert_eq!(here.allocs, 0);
}

#[test]
fn slots_refill_allocates_nothing() {
    let mut s: Slots<Rec> = Slots::default();
    for _ in 0..3 {
        s.clear();
        for id in 0..3 {
            fill(s.push(), id);
        }
    }
    let here = A.armed_here(b"", || {
        s.clear();
        for id in 0..3 {
            fill(s.push(), id);
        }
    });
    assert_eq!(here.allocs, 0);
}

#[test]
fn book_open_and_close_allocate_nothing() {
    let mut b = book::<u64, Rec>(4);
    for round in 0..3 {
        for key in 0..4 {
            fill(b.open(key + round * 10).unwrap(), key);
        }
        for key in 0..4 {
            assert!(b.close(key + round * 10));
        }
    }
    let here = A.armed_here(b"", || {
        for key in 100..104 {
            fill(b.open(key).unwrap(), key);
        }
        assert!(b.open(200).is_none());
        for key in 100..104 {
            assert!(b.close(key));
        }
    });
    assert_eq!(here.allocs, 0);
}

#[test]
fn cloning_a_text_allocates_nothing() {
    let shared = text("pool-a");
    let fixed = Text::fixed("lane/");
    let here = A.armed_here(b"", || {
        let a = shared.clone();
        let b = fixed.clone();
        assert_eq!(a.len() + b.len(), 11);
    });
    assert_eq!(here.allocs, 0);
}
