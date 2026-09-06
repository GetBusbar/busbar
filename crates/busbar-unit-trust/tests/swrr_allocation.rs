// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the weighted floor is allowed to allocate.
//!
//! This lives outside the unit rather than beside its other tests because measuring allocation
//! needs a global allocator, and the unit itself forbids unsafe code. The test binary is a crate of
//! its own, so the counting allocator here is confined to this file and never rides into the unit.

use busbar_unit_trust::lane::Unavailable;
use busbar_unit_trust::{select_weighted, BreakerView, LaneCandidate, LaneTable, SwrrState};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// An allocator that counts allocations while a test asks it to.
struct CountingAllocator;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Count the allocations one closure performs.
fn allocations_during(f: impl FnOnce()) -> usize {
    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    f();
    COUNTING.store(false, Ordering::Relaxed);
    ALLOCATIONS.load(Ordering::Relaxed)
}

/// A lane table and breaker that record nothing, so what is counted is the selection itself rather
/// than a fixture keeping a log.
struct SilentLanes;

impl LaneTable for SilentLanes {
    fn lane_admissible(&self, _lane: usize) -> bool {
        true
    }
}

impl BreakerView for SilentLanes {
    fn ready(&self, _pool: &str, _lane: usize, _now: u64) -> bool {
        true
    }
    fn try_admit(&self, _pool: &str, _lane: usize, _now: u64) -> Result<(), Unavailable> {
        Ok(())
    }
}

fn cands(pairs: &[(usize, u32)]) -> Vec<LaneCandidate> {
    pairs
        .iter()
        .map(|(idx, weight)| LaneCandidate {
            idx: *idx,
            weight: *weight,
        })
        .collect()
}

/// Selection is on the hot path of every request, so it must not allocate per candidate. The
/// credits are keyed pool first and lane second precisely so a selection finds the pool's credits
/// once and then reads each lane's credit without building a key: a flat map keyed by the pair
/// needs a freshly owned copy of the pool name for every candidate on every single selection.
///
/// The first selection for a pool is allowed its own allocations (the pool's name and its credit
/// map); every selection after that, over a pool already known, allocates nothing at all.
#[test]
fn a_warm_pools_selection_allocates_nothing() {
    let lanes = SilentLanes;
    let mut swrr = SwrrState::new();
    let c = cands(&[
        (0, 5),
        (1, 3),
        (2, 1),
        (3, 1),
        (4, 2),
        (5, 7),
        (6, 1),
        (7, 4),
    ]);
    // Warm the pool: after this the pool name and every lane's credit are already in the map.
    for _ in 0..16 {
        let _ = select_weighted(&mut swrr, "p", &c, &lanes, &lanes, 1000);
    }
    let allocations = allocations_during(|| {
        let picked = select_weighted(&mut swrr, "p", &c, &lanes, &lanes, 1000);
        assert!(picked.is_some());
    });
    assert_eq!(
        allocations, 0,
        "a selection over a pool already in the credit map must allocate nothing"
    );
}
