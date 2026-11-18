// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-FRAME: three shapes of one request hand-off, side by side (the owner's allocation ruling of
//! 18 Nov 2026; GROUP-handoffs). The hand-off data is four 256-byte buffers, the shape of a hook
//! call's stage.
//!
//! - copy: today's shape at the hook call (`port_hooks/call.rs`, `prepare`): the request builds
//!   its own value, then copies it (`to_vec` per buffer) into a fresh value for the consumer.
//! - fresh: one fresh value, written in place once, shared (`Arc`) with the consumer and
//!   released by the last holder. No copy.
//! - pool: step 1's `FramePool` (one pool, one lock): take, write in place, share; the last
//!   holder clears the frame and returns it to the pool.
//!
//! Each shape runs three ways: one thread (made, handed over on the thread, dropped); 8 threads
//! at once, each on its own (one shared pool for `pool`); and 8 pairs of long-lived threads (the
//! first makes and hands over, drops its own and waits; the partner reads and drops last).
//! Per-cycle time is each measured thread's own elapsed time over its cycles, averaged over the
//! threads, with the plain system allocator: nothing counts allocations here, so the threads do
//! not meet on a counter. The allocations of the same runs are counted by `frame_allocs.rs`.

#[path = "b_frame/shapes.rs"]
mod shapes;

/// Not counted in this binary.
fn allocations() -> usize {
    0
}

fn main() {
    println!(
        "B-FRAME (time)  {:<6} {:>12} {:>12} {:>12}",
        "shape", "1 thread", "8 threads", "8 pairs"
    );
    for (name, runs) in shapes::table() {
        println!(
            "B-FRAME (time)  {name:<6} {:>9.1} ns {:>9.1} ns {:>9.1} ns",
            runs[0].0, runs[1].0, runs[2].0
        );
    }
    println!("(ns per cycle per measured thread)");
}
