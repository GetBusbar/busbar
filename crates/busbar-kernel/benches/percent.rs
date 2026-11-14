// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PERCENT-DECODE HOT-PATH GATE (DEPENDENCY-LADDER §0, row C6): the baseline the
//! percent-encoding swap is measured against, recorded on the hand decoder first.
//!
//! `busbar_kernel::observability::percent_decode` runs per request: every captured path segment of
//! an arrival span goes through it. The bench times it over the corpus below; the swap commit is
//! red if any input's median or p99 is slower than this baseline by more than CI's run-to-run
//! noise (the larger of 2% and three times the baseline spread).
//!
//! The allocation witness pins today's count per call as the ceiling: one buffer of the input's
//! length, plus one copy of the input when the decoded bytes are not UTF-8. A counting
//! `#[global_allocator]` is armed only around the measured calls; `BUSBAR_ALLOC_INJECT` allocates
//! inside the armed window to prove the assertion can go red.
//!
//! ```text
//! cargo bench -p busbar-kernel --bench percent
//! ```

use busbar_kernel::observability::percent_decode;
use criterion::{criterion_group, criterion_main, Criterion};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct CountingAlloc;

static ARMED: AtomicBool = AtomicBool::new(false);
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to `System`, the process's real allocator; the only added behaviour
// is a relaxed counter bump when the armed flag is set, which allocates nothing itself.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// (name, input, allocations per call today).
const CORPUS: &[(&str, &str, usize)] = &[
    ("plain_segment", "gpt-4o-mini-2024-07-18", 1),
    (
        "escaped_slash",
        "projects%2Facme%2Fmodels%2Fgemini-1.5-pro",
        1,
    ),
    ("utf8_escape", "caf%C3%A9-%E2%82%AC-model", 1),
    ("short_escape", "100%25-and-100%", 1),
    ("invalid_utf8", "bad%FF%FEsegment", 2),
    (
        "long_escaped",
        "a%20long%20segment%20with%20many%20escapes%20and%20some%20plain%20text%20between%20them",
        1,
    ),
];

fn assert_allocations_per_call_at_most_today() {
    let inject = std::env::var_os("BUSBAR_ALLOC_INJECT").is_some();
    for &(name, input, ceiling) in CORPUS {
        let mut sink = 0usize;
        ALLOC_COUNT.store(0, Ordering::Relaxed);
        ARMED.store(true, Ordering::Relaxed);
        for _ in 0..1_000u32 {
            sink = sink.wrapping_add(black_box(percent_decode(black_box(input))).len());
            if inject {
                let v: Vec<u8> = Vec::with_capacity(16);
                sink = sink.wrapping_add(black_box(v).capacity());
            }
        }
        ARMED.store(false, Ordering::Relaxed);
        black_box(sink);
        let allocations = ALLOC_COUNT.load(Ordering::Relaxed);
        assert!(
            allocations <= ceiling * 1_000,
            "PERCENT ALLOC ({name}): 1000 decodes performed {allocations} allocation(s); \
             today's ceiling is {ceiling} per call"
        );
    }
}

fn percent(c: &mut Criterion) {
    let mut group = c.benchmark_group("percent_decode");
    for &(name, input, _) in CORPUS {
        group.bench_function(name, |b| b.iter(|| percent_decode(black_box(input))));
    }
    group.finish();
    assert_allocations_per_call_at_most_today();
}

criterion_group!(percent_benches, percent);
criterion_main!(percent_benches);
