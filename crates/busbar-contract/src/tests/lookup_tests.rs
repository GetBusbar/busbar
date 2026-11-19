// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Every method of the four lookups against a plain `Vec` model, for 10,000 random operations with
//! a fixed seed, and the edges each one names.

use super::*;

/// A fixed-seed generator (xorshift64*), so a failure replays exactly.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const OPERATIONS: usize = 10_000;

// ---------------------------------------------------------------- Bits

fn bits_model<const W: usize>(set: &Bits<W>) -> Vec<usize> {
    (0..Bits::<W>::CAPACITY + 8)
        .filter(|id| set.contains(*id))
        .collect()
}

fn bits_of<const W: usize>(ids: &[usize]) -> Bits<W> {
    let mut set = Bits::new();
    for id in ids {
        set.insert(*id);
    }
    set
}

#[test]
fn bits_edges_one_word() {
    let mut set = Bits::<1>::new();
    assert_eq!(Bits::<1>::CAPACITY, 64);
    assert!(set.is_empty());
    assert!(set.insert(0));
    assert!(set.insert(63));
    assert!(!set.insert(63), "already in");
    assert!(!set.insert(64), "out of range");
    assert!(!set.insert(255), "out of range");
    assert!(!set.insert(usize::MAX), "out of range");
    assert_eq!(set.len(), 2);
    assert!(set.contains(0) && set.contains(63));
    assert!(!set.contains(64) && !set.contains(255) && !set.contains(usize::MAX));
    assert_eq!(set.next_from(0), Some(0));
    assert_eq!(set.next_from(1), Some(63));
    assert_eq!(set.next_from(64), None);
    assert_eq!(set.next_from(usize::MAX), None);
    assert!(!set.remove(64));
    assert!(set.remove(63));
    assert!(!set.remove(63), "not in any more");
    assert_eq!(set.len(), 1);
    assert_eq!(Bits::<1>::all_below(64).map(|s| s.len()), Some(64));
    assert_eq!(Bits::<1>::all_below(65), None);
    assert_eq!(Bits::<1>::all_below(0), Some(Bits::new()));
    assert_eq!(Bits::<1>::default(), Bits::new());
}

#[test]
fn bits_edges_four_words() {
    let mut set = Bits::<4>::new();
    assert_eq!(Bits::<4>::CAPACITY, 256);
    for id in [0, 63, 64, 255] {
        assert!(set.insert(id), "{id}");
        assert!(set.contains(id), "{id}");
    }
    assert!(!set.insert(256), "out of range");
    assert!(!set.contains(256));
    assert_eq!(set.len(), 4);
    assert_eq!(set.next_from(0), Some(0));
    assert_eq!(set.next_from(1), Some(63));
    assert_eq!(set.next_from(64), Some(64));
    assert_eq!(set.next_from(65), Some(255));
    assert_eq!(set.next_from(255), Some(255));
    assert_eq!(set.next_from(256), None);
    let all = Bits::<4>::all_below(256).expect("256 fits");
    assert_eq!(all.len(), 256);
    assert!(all.contains(255) && !all.contains(256));
    let some = Bits::<4>::all_below(65).expect("65 fits");
    assert_eq!(some.len(), 65);
    assert!(some.contains(64) && !some.contains(65));
    assert_eq!(Bits::<4>::all_below(257), None);
    let mut kept = all;
    kept.keep_only(&set);
    assert_eq!(kept, set);
    let mut dropped = all;
    dropped.drop_all(&set);
    assert_eq!(dropped.len(), 252);
    assert!(!dropped.contains(64) && dropped.contains(65));
}

fn bits_random<const W: usize>(seed: u64) {
    let mut rng = Rng::new(seed);
    let cap = Bits::<W>::CAPACITY;
    let mut set = Bits::<W>::new();
    let mut model: Vec<usize> = Vec::new();
    for _ in 0..OPERATIONS {
        // Ids run a little past the capacity, so the out-of-range answers are exercised too.
        let id = rng.below(cap + 8);
        match rng.below(8) {
            0 | 1 => {
                let fresh = id < cap && !model.contains(&id);
                assert_eq!(set.insert(id), fresh, "insert {id}");
                if fresh {
                    model.push(id);
                }
            }
            2 => {
                let held = model.iter().position(|m| *m == id);
                assert_eq!(set.remove(id), held.is_some(), "remove {id}");
                if let Some(at) = held {
                    model.swap_remove(at);
                }
            }
            3 => assert_eq!(set.contains(id), model.contains(&id), "contains {id}"),
            4 => {
                let want = model.iter().copied().filter(|m| *m >= id).min();
                assert_eq!(set.next_from(id), want, "next_from {id}");
            }
            5 => {
                let other: Vec<usize> = (0..rng.below(cap)).map(|_| rng.below(cap)).collect();
                let mut want = model.clone();
                want.retain(|m| other.contains(m));
                set.keep_only(&bits_of(&other));
                model = want;
            }
            6 => {
                let other: Vec<usize> = (0..rng.below(cap / 4 + 1))
                    .map(|_| rng.below(cap))
                    .collect();
                model.retain(|m| !other.contains(m));
                set.drop_all(&bits_of(&other));
            }
            _ => {
                let n = rng.below(cap + 2);
                match Bits::<W>::all_below(n) {
                    Some(all) if rng.below(4) == 0 => {
                        set = all;
                        model = (0..n).collect();
                    }
                    Some(all) => assert_eq!(bits_model(&all), (0..n).collect::<Vec<_>>()),
                    None => assert!(n > cap),
                }
            }
        }
        assert_eq!(set.len() as usize, model.len());
        assert_eq!(set.is_empty(), model.is_empty());
    }
    model.sort();
    assert_eq!(bits_model(&set), model);
}

#[test]
fn bits_one_word_matches_a_vec_model() {
    bits_random::<1>(0x0B17_5001);
}

#[test]
fn bits_four_words_match_a_vec_model() {
    bits_random::<4>(0x0B17_5004);
}

// ---------------------------------------------------------------- Indexed

#[test]
fn indexed_matches_a_vec_model() {
    let mut rng = Rng::new(0x1DE7_ED00);
    let mut indexed = Indexed::<u32, u64>::new();
    let mut model: Vec<(u32, u64)> = Vec::new();
    for _ in 0..OPERATIONS {
        let key = rng.below(64) as u32;
        match rng.below(5) {
            0 | 1 => {
                let fresh = rng.next();
                let row = indexed.row(key, || fresh);
                match model.iter_mut().find(|(k, _)| *k == key) {
                    Some((_, v)) => {
                        assert_eq!(*row, *v, "row {key} keeps its value");
                        *row = row.wrapping_add(1);
                        *v = v.wrapping_add(1);
                    }
                    None => {
                        assert_eq!(*row, fresh, "row {key} made");
                        model.push((key, fresh));
                    }
                }
            }
            2 => {
                let want = model.iter().find(|(k, _)| *k == key).map(|(_, v)| v);
                assert_eq!(indexed.get(&key), want, "get {key}");
            }
            3 => {
                let want = model.iter_mut().find(|(k, _)| *k == key).map(|(_, v)| v);
                match (indexed.get_mut(&key), want) {
                    (Some(got), Some(want)) => {
                        assert_eq!(*got, *want);
                        *got ^= 7;
                        *want ^= 7;
                    }
                    (None, None) => {}
                    (got, want) => panic!("get_mut {key}: {got:?} against {want:?}"),
                }
            }
            _ => {
                let rebuilt = Indexed::from_rows(indexed.rows().to_vec());
                assert_eq!(rebuilt, indexed);
                assert_eq!(rebuilt.get(&key), indexed.get(&key));
            }
        }
        assert_eq!(indexed.rows(), model.as_slice());
        assert_eq!(indexed.len(), model.len());
        assert_eq!(indexed.is_empty(), model.is_empty());
    }
}

#[test]
fn indexed_from_rows_finds_the_first_row_of_a_key() {
    let rows = vec![(1u8, "a"), (2, "b"), (1, "c")];
    let indexed = Indexed::from_rows(rows.clone());
    assert_eq!(indexed.get(&1), Some(&"a"));
    assert_eq!(indexed.get(&2), Some(&"b"));
    assert_eq!(indexed.get(&3), None);
    assert_eq!(indexed.rows(), rows.as_slice(), "rows are kept as read");
}

#[test]
fn indexed_borrows_its_key_for_lookup() {
    let mut indexed = Indexed::<String, u32>::new();
    *indexed.row("one".into(), || 0) += 1;
    *indexed.row("two".into(), || 5) += 1;
    *indexed.row("one".into(), || 9) += 1;
    assert_eq!(indexed.get("one"), Some(&2));
    assert_eq!(indexed.get("two"), Some(&6));
    assert_eq!(indexed.get("three"), None);
    assert_eq!(indexed.rows()[0].0, "one", "first-insert order");
    assert_eq!(Indexed::<String, u32>::default(), Indexed::new());
}

// ---------------------------------------------------------------- ByGroup

/// The model: rows in insert order (a re-insert moves the row to the end).
struct GroupModel(Vec<(u32, u8, u64)>);

impl GroupModel {
    fn remove(&mut self, key: u32) -> Option<u64> {
        let at = self.0.iter().position(|(k, _, _)| *k == key)?;
        Some(self.0.remove(at).2)
    }

    fn take(&mut self, group: u8) -> Vec<(u32, u64)> {
        let mut out: Vec<(u32, u64)> = self
            .0
            .iter()
            .filter(|(_, g, _)| *g == group)
            .map(|(k, _, v)| (*k, *v))
            .collect();
        out.reverse();
        self.0.retain(|(_, g, _)| *g != group);
        out
    }
}

fn taken(table: &mut ByGroup<u32, u8, u64>, group: u8) -> Vec<(u32, u64)> {
    let mut out = Vec::new();
    table.take_group(&group, |key, value| out.push((key, value)));
    out
}

#[test]
fn by_group_matches_a_vec_model() {
    let mut rng = Rng::new(0xB7_6800);
    let mut table = ByGroup::<u32, u8, u64>::new();
    let mut model = GroupModel(Vec::new());
    for _ in 0..OPERATIONS {
        let key = rng.below(200) as u32;
        let group = rng.below(12) as u8;
        match rng.below(9) {
            0..=2 => {
                let value = rng.next();
                let old = model.remove(key);
                model.0.push((key, group, value));
                assert_eq!(table.insert(key, group, value), old, "insert {key}");
            }
            3 | 4 => assert_eq!(table.remove(&key), model.remove(key), "remove {key}"),
            5 => {
                let want = model.0.iter().find(|(k, _, _)| *k == key).map(|r| &r.2);
                assert_eq!(table.get(&key), want, "get {key}");
                assert_eq!(table.contains_key(&key), want.is_some());
            }
            6 => {
                let want = model.0.iter_mut().find(|(k, _, _)| *k == key);
                match (table.get_mut(&key), want) {
                    (Some(got), Some(want)) => {
                        *got ^= 3;
                        want.2 ^= 3;
                    }
                    (None, None) => {}
                    (got, want) => panic!("get_mut {key}: {got:?} against {want:?}"),
                }
            }
            7 => {
                let want = model.take(group);
                assert_eq!(taken(&mut table, group), want, "take_group {group}");
            }
            _ => {
                let want = !model.0.iter().any(|(_, g, _)| *g == group);
                assert_eq!(table.group_is_empty(&group), want, "group_is_empty {group}");
            }
        }
        assert_eq!(table.len(), model.0.len());
        assert_eq!(table.is_empty(), model.0.is_empty());
    }
    for group in 0..12 {
        assert_eq!(taken(&mut table, group), model.take(group));
    }
    assert!(table.is_empty());
}

/// A group of `n` rows (keys `base .. base + n`, newest last), beside one row of another group.
fn group_of(n: u32, base: u32) -> ByGroup<u32, u8, u64> {
    let mut table = ByGroup::new();
    table.insert(9_999, 2, 0);
    for key in base..base + n {
        assert_eq!(table.insert(key, 1, u64::from(key)), None);
    }
    table
}

fn expect_group(table: &mut ByGroup<u32, u8, u64>, want_newest_first: &[u32]) {
    let want: Vec<(u32, u64)> = want_newest_first
        .iter()
        .map(|k| (*k, u64::from(*k)))
        .collect();
    assert_eq!(taken(table, 1), want);
    assert!(table.group_is_empty(&1));
    assert_eq!(table.get(&9_999), Some(&0), "the other group is untouched");
    assert_eq!(table.len(), 1);
}

#[test]
fn by_group_of_one_row() {
    let mut table = group_of(1, 0);
    assert!(!table.group_is_empty(&1));
    assert_eq!(table.remove(&0), Some(0));
    assert!(table.group_is_empty(&1));
    expect_group(&mut table, &[]);
    let mut table = group_of(1, 0);
    expect_group(&mut table, &[0]);
}

#[test]
fn by_group_of_two_rows() {
    // Remove the head (the newest), then the tail, each leaving the other.
    let mut table = group_of(2, 0);
    assert_eq!(table.remove(&1), Some(1));
    expect_group(&mut table, &[0]);
    let mut table = group_of(2, 0);
    assert_eq!(table.remove(&0), Some(0));
    expect_group(&mut table, &[1]);
}

#[test]
fn by_group_of_a_hundred_rows() {
    let all: Vec<u32> = (0..100).rev().collect();
    let mut table = group_of(100, 0);
    expect_group(&mut table, &all);

    // The head, the tail and a middle row out; the chain stays whole either side.
    let mut table = group_of(100, 0);
    assert_eq!(table.remove(&99), Some(99), "head");
    assert_eq!(table.remove(&0), Some(0), "tail");
    assert_eq!(table.remove(&50), Some(50), "middle");
    assert_eq!(table.remove(&50), None, "already out");
    let left: Vec<u32> = all
        .iter()
        .copied()
        .filter(|k| ![99, 0, 50].contains(k))
        .collect();
    expect_group(&mut table, &left);

    // A row re-inserted moves to the head of its (new) group.
    let mut table = group_of(100, 0);
    assert_eq!(table.insert(50, 1, 50), Some(50));
    let mut moved = vec![50];
    moved.extend(all.iter().copied().filter(|k| *k != 50));
    expect_group(&mut table, &moved);
    let mut table = group_of(100, 0);
    assert_eq!(table.insert(50, 3, 50), Some(50));
    assert_eq!(taken(&mut table, 3), vec![(50, 50)]);
    let rest: Vec<u32> = all.iter().copied().filter(|k| *k != 50).collect();
    expect_group(&mut table, &rest);
}

// ---------------------------------------------------------------- Slots

#[test]
fn slots_reuse_an_entry_and_refuse_the_stale_handle() {
    let mut slots = Slots::new();
    let first = slots.insert("a");
    let second = slots.insert("b");
    assert_eq!(slots.len(), 2);
    assert_eq!(slots.remove(first), Some("a"));
    assert_eq!(slots.remove(first), None, "already taken");
    assert_eq!(slots.get(first), None);
    let third = slots.insert("c");
    assert_eq!(third.index, first.index, "the free entry is reused");
    assert_ne!(third, first, "under a new generation");
    assert_eq!(slots.get(first), None, "the stale handle names nothing");
    assert_eq!(slots.remove(first), None, "the stale handle takes nothing");
    assert_eq!(slots.get(third), Some(&"c"));
    assert_eq!(slots.get(second), Some(&"b"));
    if let Some(value) = slots.get_mut(second) {
        *value = "B";
    }
    assert_eq!(slots.remove(second), Some("B"));
    assert_eq!(slots.len(), 1);
    assert!(!slots.is_empty());
    assert_eq!(slots.remove(third), Some("c"));
    assert!(slots.is_empty());
    assert!(Slots::<u8>::default().is_empty());
}

#[test]
fn slots_match_a_vec_model() {
    let mut rng = Rng::new(0x5107_5000);
    let mut slots = Slots::<u64>::new();
    // Every handle ever made, with the value it should still name (`None` once taken).
    let mut model: Vec<(Slot, Option<u64>)> = Vec::new();
    for _ in 0..OPERATIONS {
        match rng.below(5) {
            0 | 1 => {
                let value = rng.next();
                let slot = slots.insert(value);
                assert!(
                    model.iter().all(|(s, v)| *s != slot || v.is_none()),
                    "a live handle is never handed out twice"
                );
                model.push((slot, Some(value)));
            }
            2 if !model.is_empty() => {
                let at = rng.below(model.len());
                let (slot, want) = model[at];
                assert_eq!(slots.remove(slot), want, "remove");
                model[at].1 = None;
            }
            3 if !model.is_empty() => {
                let (slot, want) = model[rng.below(model.len())];
                assert_eq!(slots.get(slot).copied(), want, "get");
            }
            4 if !model.is_empty() => {
                let at = rng.below(model.len());
                let (slot, want) = model[at];
                match (slots.get_mut(slot), want) {
                    (Some(got), Some(want)) => {
                        assert_eq!(*got, want);
                        *got ^= 1;
                        model[at].1 = Some(want ^ 1);
                    }
                    (None, None) => {}
                    (got, want) => panic!("get_mut: {got:?} against {want:?}"),
                }
            }
            _ => {}
        }
        let live = model.iter().filter(|(_, v)| v.is_some()).count();
        assert_eq!(slots.len(), live);
        assert_eq!(slots.is_empty(), live == 0);
    }
}

/// The newest row is found without the map, and the answers are the same as the map's.
#[test]
fn indexed_finds_the_newest_row_first_and_every_other_row_by_the_map() {
    let mut rows = Indexed::<u64, u64>::new();
    for key in 1..=5 {
        *rows.row(key, || 0) += key;
    }
    // The newest row (5), an older row (2) and a key never inserted.
    *rows.row(5, || 0) += 10;
    assert_eq!(rows.get(&5), Some(&15));
    *rows.get_mut(&5).unwrap() += 1;
    *rows.get_mut(&2).unwrap() += 100;
    assert_eq!(rows.get(&2), Some(&102));
    assert_eq!(rows.get(&5), Some(&16));
    assert_eq!(rows.get(&9), None);
    assert_eq!(rows.len(), 5);
    assert_eq!(
        rows.rows().iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5]
    );
}

/// A key given twice to `from_rows` is found at its FIRST row, as before, even when the newest row
/// carries the same key.
#[test]
fn indexed_from_rows_with_a_repeated_key_still_finds_the_first_row() {
    let mut rows = Indexed::from_rows(vec![(1_u64, 10_u64), (2, 20), (1, 30)]);
    assert_eq!(rows.get(&1), Some(&10));
    *rows.get_mut(&1).unwrap() += 1;
    assert_eq!(rows.rows(), &[(1, 11), (2, 20), (1, 30)]);
    assert_eq!(*rows.row(1, || 0), 11);
}

/// `BitSet` against a plain `Vec<bool>` model, at widths either side of every word edge.
fn bitset_model(set: &BitSet, width: usize) -> Vec<bool> {
    (0..width).map(|at| set.contains(at)).collect()
}

fn bitset_random(width: usize, seed: u64) {
    let mut rng = Rng::new(seed);
    let mut set = BitSet::new();
    set.reset_empty(width);
    let mut model = vec![false; width];
    let mut other = BitSet::new();
    for _ in 0..OPERATIONS {
        let at = rng.below(width + 8);
        match rng.below(10) {
            0..=2 => {
                let fresh = at < width && !model[at];
                assert_eq!(set.insert(at), fresh, "width {width}: insert {at}");
                if fresh {
                    model[at] = true;
                }
            }
            3 | 4 => {
                let held = at < width && model[at];
                assert_eq!(set.remove(at), held, "width {width}: remove {at}");
                if held {
                    model[at] = false;
                }
            }
            5 => {
                let want = (at..width).find(|p| model[*p]);
                assert_eq!(set.next_from(at), want, "width {width}: next_from {at}");
            }
            6 => {
                // Keep only a random other set (its width may be narrower or wider).
                let other_width = rng.below(width + 70);
                other.reset_empty(other_width);
                let mut other_model = vec![false; other_width];
                for (p, held) in other_model.iter_mut().enumerate() {
                    if rng.below(2) == 0 {
                        other.insert(p);
                        *held = true;
                    }
                }
                set.keep_only(&other);
                for (p, held) in model.iter_mut().enumerate() {
                    *held &= other_model.get(p).copied().unwrap_or(false);
                }
            }
            7 => {
                other.reset_empty(width);
                let mut other_model = vec![false; width];
                for (p, held) in other_model.iter_mut().enumerate() {
                    if rng.below(3) == 0 {
                        other.insert(p);
                        *held = true;
                    }
                }
                set.drop_all(&other);
                for (p, held) in model.iter_mut().enumerate() {
                    *held &= !other_model[p];
                }
            }
            8 => {
                let mut copy = BitSet::new();
                copy.copy_from(&set);
                assert_eq!(copy, set, "width {width}: copy");
            }
            _ => {
                if rng.below(2) == 0 {
                    set.reset_full(width);
                    model.iter_mut().for_each(|held| *held = true);
                } else {
                    set.reset_empty(width);
                    model.iter_mut().for_each(|held| *held = false);
                }
            }
        }
        assert_eq!(bitset_model(&set, width), model, "width {width}");
        assert_eq!(set.len(), model.iter().filter(|held| **held).count());
        assert_eq!(set.is_empty(), !model.iter().any(|held| *held));
        assert_eq!(set.width(), width);
    }
}

#[test]
fn bitset_matches_a_model_at_every_word_edge() {
    for (seed, width) in [0, 1, 63, 64, 65, 127, 128, 129, 200, 1_000]
        .into_iter()
        .enumerate()
    {
        bitset_random(width, 0x9E37 + seed as u64);
    }
}

#[test]
fn bitset_equal_sets_are_equal_whatever_their_history() {
    // Bits at or above the width stay zero, so a full set reset narrower equals a fresh full one.
    let mut grown = BitSet::new();
    grown.reset_full(200);
    grown.reset_full(70);
    let mut fresh = BitSet::new();
    fresh.reset_full(70);
    assert_eq!(grown, fresh);
    assert_eq!(grown.len(), 70);
    assert!(!grown.contains(70) && grown.contains(69));
}

/// Up to 64 positions there is no block; above, one block is made once and reused across resets.
#[test]
fn bitset_holds_no_block_up_to_64_and_reuses_one_above() {
    let mut set = BitSet::new();
    set.reset_full(64);
    assert_eq!(set.rest.capacity(), 0, "64 positions need no heap block");
    set.reset_full(1_000);
    let block = set.rest.capacity();
    assert!(block >= 15);
    let at = set.rest.as_ptr();
    set.reset_empty(10);
    set.reset_full(1_000);
    set.copy_from(&BitSet::default());
    set.reset_full(1_000);
    assert_eq!(set.rest.capacity(), block, "one block, kept across resets");
    assert_eq!(set.rest.as_ptr(), at, "the same block");
}
