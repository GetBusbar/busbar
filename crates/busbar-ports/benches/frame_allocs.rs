// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-FRAME (allocations): the runs of `frame.rs`, with every allocation counted process-wide
//! (`stats_alloc` over the system allocator) from after every thread's 100,000 warm-up cycles to
//! after its 1,000,000 counted cycles, partners included; printed per cycle of one measured
//! thread. The counter is shared by every thread, so the times of this binary are not the record:
//! `frame.rs` is.

use stats_alloc::StatsAlloc;
use std::alloc::System;

#[path = "b_frame/shapes.rs"]
mod shapes;

#[global_allocator]
static GLOBAL: StatsAlloc<System> = StatsAlloc::new(System);

fn allocations() -> usize {
    let s = GLOBAL.stats();
    s.allocations + s.reallocations
}

fn main() {
    println!(
        "B-FRAME (allocations)  {:<6} {:>10} {:>10} {:>10}",
        "shape", "1 thread", "8 threads", "8 pairs"
    );
    for (name, runs) in shapes::table() {
        println!(
            "B-FRAME (allocations)  {name:<6} {:>10.2} {:>10.2} {:>10.2}",
            runs[0].1, runs[1].1, runs[2].1
        );
    }
    println!("(allocations per cycle once warm)");
}
