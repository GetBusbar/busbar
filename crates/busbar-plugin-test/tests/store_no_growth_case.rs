// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared Store v4 no-growth case (8.10) decides "storage does not grow with commits" by the
//! slot-row bound at every full slot cycle, over a commit count every store's CI can run against a
//! real database. Two in-memory doubles pin it: a slot-row store passes it, and a store that keeps
//! one row per commit and compacts only now and then is refused even when a compaction happens to
//! land on the last commit.

use std::sync::Mutex;

use busbar_contract::persistence::conformance::{self as cases, Subject};
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, CommitKey, DatasetId, Decision, Durability, Page,
    PersistenceBackend, PreparedCandidate, Read, ReadResult, Scan,
};
use busbar_contract::Secret;

/// What a double holds for its one writer: its slot rows, in commit order.
#[derive(Default)]
struct Rows {
    rows: Vec<(u32, u64)>,
    commits: usize,
    jumped: bool,
    before: Vec<usize>,
    after: Vec<usize>,
}

/// An in-memory store. `compact_every: None` keeps one row per slot, as the slot-row commit rule
/// requires; `Some(n)` keeps a row per commit and folds them to one per slot every `n` commits.
struct Double {
    compact_every: Option<usize>,
    rows: Mutex<Rows>,
}

impl Double {
    fn new(compact_every: Option<usize>) -> Self {
        Self {
            compact_every,
            rows: Mutex::new(Rows {
                before: vec![0; 64],
                after: vec![0; 64],
                ..Rows::default()
            }),
        }
    }
}

fn info() -> BackendInfo {
    BackendInfo {
        dataset: DatasetId([7; 16]),
        atomic_domain: [8; 16],
        clock_authority: [9; 16],
        physical_version: 1,
        durability: Durability::Ephemeral,
    }
}

impl PersistenceBackend for Double {
    fn info(&self) -> BackendInfo {
        info()
    }
    fn read(&self, _: std::sync::Arc<Read>) -> Call<'_, ReadResult> {
        unreachable!("the no-growth case only commits")
    }
    fn scan(&self, _: std::sync::Arc<Scan>) -> Call<'_, Page> {
        unreachable!("the no-growth case only commits")
    }
    fn commit(&self, _: PreparedCandidate, key: CommitKey) -> Call<'_, Decision> {
        Box::pin(async move {
            if !key.is_self_fenced() {
                let (slot, seq) = key.wire();
                let mut held = self.rows.lock().unwrap();
                let held = &mut *held;
                held.commits += 1;
                let side = if held.jumped {
                    &mut held.after
                } else {
                    &mut held.before
                };
                side[slot as usize] += 1;
                match self.compact_every {
                    None => {
                        held.rows.retain(|(s, _)| *s != slot);
                        held.rows.push((slot, seq));
                    }
                    Some(every) => {
                        held.rows.push((slot, seq));
                        if held.commits.is_multiple_of(every) {
                            let mut last: Vec<(u32, u64)> = Vec::new();
                            for &(s, q) in held.rows.iter().rev() {
                                if !last.iter().any(|(l, _)| *l == s) {
                                    last.push((s, q));
                                }
                            }
                            held.rows = last;
                        }
                    }
                }
            }
            Ok(Decision::Applied(Secret::new(Vec::new())))
        })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        unreachable!("the no-growth case reads no clock")
    }
}

impl Subject for Double {
    fn backend(&self) -> &dyn PersistenceBackend {
        self
    }
    fn slot_rows(&self, _: [u8; 16]) -> usize {
        self.rows.lock().unwrap().rows.len()
    }
    fn jump_clock(&self, _: u64) -> bool {
        self.rows.lock().unwrap().jumped = true;
        true
    }
}

fn run<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

/// A slot-row store passes the shared case, and the shared count cycles every one of the 64 slots
/// many times on each side of the clock jump: the bound is decided over full cycles, not by a raw
/// count.
#[test]
fn a_slot_row_store_passes_over_many_full_cycles_each_side_of_the_jump() {
    let store = Double::new(None);
    assert!(run(cases::no_growth(&store, cases::NO_GROWTH_COMMITS, 64)));
    let held = store.rows.lock().unwrap();
    assert_eq!(held.commits, cases::NO_GROWTH_COMMITS);
    assert_eq!(held.rows.len(), 64);
    for side in [&held.before, &held.after] {
        assert!(
            side.iter().all(|n| *n >= 16),
            "a slot cycled too few times on one side of the jump: {side:?}"
        );
    }
}

/// A store that keeps a row per commit and compacts only every 1,000 commits holds far more rows
/// than its peak for most of the run. The case refuses it at the first cycle that shows it, even
/// though such a store's compaction can land on the last commit and leave exactly the peak behind.
#[test]
#[should_panic(expected = "slot rows for a peak of 64")]
fn a_store_that_only_compacts_now_and_then_is_refused_mid_run() {
    let store = Double::new(Some(1_000));
    run(cases::no_growth(&store, cases::NO_GROWTH_COMMITS, 64));
}
