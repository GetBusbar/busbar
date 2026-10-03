// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE CONFORMANCE SUITE, CROSSING HALF (TODO ABI-b4 store; M6/contract): the answers the
//! sibling `conformance_tests` compare say the two builds AGREE; they cannot say the doors were
//! USED. A door that answered from a cache, or crossed twice, or not at all, would still agree.
//!
//! This runs one fixed op sequence (caps, reserve, a replayed reserve, release, a coalesced usage
//! batch and its replay, an append, a record put and get, and bridge reads and writes) against the
//! compiled-in door and the dropped-in door, and counts the crossings the instance made around
//! EACH op. Two things are asserted, EXACTLY (never "above zero"):
//!
//! * every op, a replay (the `op_id` dedupe, H4) and a refused conflict included, is exactly ONE
//!   crossing (a bridge read of a record is two: the read and its lease's release), on both builds: the dedupe is the store's to answer, so the host crosses to ask;
//! * the answers, op by op, are equal across the two builds.
//!
//! The proof runs under the RELEASE profile too (`cargo nextest run --release`): the counts are a
//! property of the table, and they must not move with optimisation.
//!
//! RED ARM, KEPT: [`a_comparator_that_only_wants_more_than_zero_passes_a_door_that_crosses_twice`]
//! shows the exact comparison refuses a doubled and a skipped crossing the loose one waves through.

use busbar_contract::abi::sdk::store::{Cap, Cell, Dimension};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::RecordStore;
use busbar_contract::store_calls::StoreCalls;

use super::conformance_tests::{block, cell_key, compiled_in, delta, dropped_in, key, line, op};
use crate::store_v3::LoadedStore;

fn crossed(s: &LoadedStore) -> u64 {
    s.plugin()
        .inner
        .crossings
        .load(std::sync::atomic::Ordering::SeqCst)
}

/// One step: its label, its answer as a transcript line, and the crossings it made.
type Step = (&'static str, String, u64);

fn run(s: &LoadedStore) -> Vec<Step> {
    let mut t: Vec<Step> = Vec::new();
    // Record one op: the crossings made while `answer` ran.
    macro_rules! step {
        ($label:expr, $answer:expr) => {{
            let before = crossed(s);
            let a = $answer;
            t.push(($label, a, crossed(s) - before));
        }};
        ($label:expr, $text:expr, $value:expr) => {{
            let before = crossed(s);
            let v = $value;
            t.push(($label, line($text, v.clone()), crossed(s) - before));
            v
        }};
    }
    let b: &dyn RecordStore = s;
    let caps = [
        Cap {
            key: cell_key("g", Dimension::Requests),
            cap: 3,
            config_gen: 1,
        },
        Cap {
            key: cell_key("g", Dimension::Class("input")),
            cap: 10,
            config_gen: 1,
        },
    ];
    let conflict = [Cap {
        key: cell_key("g", Dimension::Requests),
        cap: 4,
        config_gen: 1,
    }];
    let draw = [
        Cell {
            key: cell_key("g", Dimension::Requests),
            amount: 2,
        },
        Cell {
            key: cell_key("g", Dimension::Class("input")),
            amount: 9,
        },
    ];
    let cells = [("k", 60, delta(1, 5)), ("k", 60, delta(1, 5))];
    let r = |v: &[u8]| RecordBytes::new(v.to_vec()).expect("record");
    step!("caps", line("caps", block(s.window_caps(op(1), &caps))));
    step!(
        "caps op reused",
        line("caps op reused", block(s.window_caps(op(1), &conflict)))
    );
    let g = step!("reserve", "reserve", block(s.reserve(op(2), 0, &draw)));
    step!(
        "reserve replay",
        line("reserve replay", block(s.reserve(op(2), 0, &draw)))
    );
    step!(
        "reserve over",
        line("reserve over", block(s.reserve(op(3), 0, &draw)))
    );
    let items: Vec<(u64, u64)> = g
        .map(|g| g.iter().map(|x| (x.slice_id, 1)).collect())
        .unwrap_or_default();
    step!(
        "release",
        line("release", block(s.slice_release(op(4), 0, &items)))
    );
    step!(
        "release replay",
        line("release replay", block(s.slice_release(op(4), 0, &items)))
    );
    step!(
        "usage batch",
        line("usage batch", block(s.add_usage_batch(op(5), &cells)))
    );
    step!(
        "usage batch replay",
        line(
            "usage batch replay",
            block(s.add_usage_batch(op(5), &cells))
        )
    );
    step!(
        "append batch",
        line(
            "append batch",
            block(s.append_batch(op(6), "journal", &[r(b"1"), r(b"2")]))
        )
    );
    step!(
        "record put",
        line("record put", block(s.record_put("sch", b"a/1", &r(b"one"))))
    );
    step!(
        "record get",
        line(
            "record get",
            block(StoreCalls::record_get(s, "sch", b"a/1"))
        )
    );
    step!("bridge put_key", line("put", b.put_key(&key("a", None))));
    step!(
        "bridge get_key",
        line("get", b.get_key("a").map(|k| k.map(|k| k.id)))
    );
    step!("bridge get_usage", line("usage", b.get_usage("k", 60)));
    t
}

/// The crossings the sequence makes, pinned: one per op, replays and refusals included.
const EXPECTED: [(&str, u64); 15] = [
    ("caps", 1),
    ("caps op reused", 1),
    ("reserve", 1),
    ("reserve replay", 1),
    ("reserve over", 1),
    ("release", 1),
    ("release replay", 1),
    ("usage batch", 1),
    ("usage batch replay", 1),
    ("append batch", 1),
    ("record put", 1),
    ("record get", 1),
    ("bridge put_key", 1),
    // A bridge READ of a record is a LEASED answer: the read, then the release of the lease.
    ("bridge get_key", 2),
    ("bridge get_usage", 2),
];

/// `Err` names the first step whose crossing count is not the pinned one, exactly.
fn exact(counts: &[(&str, u64)], pinned: &[(&str, u64)]) -> Result<(), String> {
    if counts.len() != pinned.len() {
        return Err(format!("{} steps, pinned {}", counts.len(), pinned.len()));
    }
    for (c, p) in counts.iter().zip(pinned) {
        if c != p {
            return Err(format!("{}: {} crossings, pinned {}", c.0, c.1, p.1));
        }
    }
    Ok(())
}

fn counts(t: &[Step]) -> Vec<(&'static str, u64)> {
    t.iter().map(|s| (s.0, s.2)).collect()
}

#[test]
fn every_op_of_the_sequence_is_exactly_one_crossing_on_the_compiled_in_door() {
    let t = run(&compiled_in());
    if let Err(e) = exact(&counts(&t), &EXPECTED) {
        panic!("{e}");
    }
}

#[test]
fn the_dropped_in_door_makes_the_same_crossings_and_answers_the_same() {
    let Some(dropped) = dropped_in() else {
        eprintln!("skip: the store's cdylib is not built in this scoped run");
        return;
    };
    let (linked, dropped) = (run(&compiled_in()), run(&dropped));
    if let Err(e) = exact(&counts(&dropped), &EXPECTED) {
        panic!("dropped in: {e}");
    }
    for (l, d) in linked.iter().zip(&dropped) {
        assert_eq!(l, d, "the two doors diverge at '{}'", l.0);
    }
    assert_eq!(linked.len(), dropped.len());
}

#[test]
fn a_replay_is_answered_as_the_original_through_a_crossing() {
    // The dedupe (H4) is the store's: the replayed reserve and release answer what the first did,
    // and the usage batch's replay applies nothing (the ledger counts it once).
    let s = compiled_in();
    let t = run(&s);
    let at = |l: &str| {
        t.iter()
            .find(|x| x.0 == l)
            .map(|x| x.1.split_once(" = ").map(|y| y.1.to_string()))
    };
    assert_eq!(at("reserve replay"), at("reserve"));
    assert_eq!(at("release replay"), at("release"));
    assert!(t
        .iter()
        .find(|x| x.0 == "caps op reused")
        .is_some_and(|x| x.1.contains("STORE_OPID_CONFLICT")));
    assert!(
        t.iter()
            .find(|x| x.0 == "bridge get_usage")
            .is_some_and(|x| x.1.contains("requests: 2")),
        "one batch of two cells applied once, its replay not at all"
    );
}

/// THE RED ARM, KEPT. A loose comparator ("some crossing happened") passes a door that crosses
/// twice per op and one that skips the crossing on a replay; the exact one refuses both.
#[test]
fn a_comparator_that_only_wants_more_than_zero_passes_a_door_that_crosses_twice() {
    let doubled: Vec<(&str, u64)> = EXPECTED.iter().map(|(l, n)| (*l, n * 2)).collect();
    let mut skipped: Vec<(&str, u64)> = EXPECTED.to_vec();
    skipped[3].1 = 0;
    for bad in [&doubled, &skipped] {
        assert!(
            bad.iter().take(3).all(|(_, n)| *n > 0),
            "the loose check waves it through"
        );
        assert!(exact(bad, &EXPECTED).is_err(), "the exact check refuses it");
    }
    assert!(exact(&EXPECTED, &EXPECTED).is_ok());
}
