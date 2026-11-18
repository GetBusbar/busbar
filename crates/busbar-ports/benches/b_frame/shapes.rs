// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hand-off shapes B-FRAME measures; shared by `frame.rs` (timed, plain system allocator) and
//! `frame_allocs.rs` (allocations counted). See `frame.rs` for what each shape is.

use busbar_ports::frame::{Frame, FramePool, Reset};
use std::hint::black_box;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::sync::{Arc, Barrier};
use std::time::Instant;

pub const WARM: usize = 100_000;
pub const CYCLES: usize = 1_000_000;
const THREADS: usize = 8;
const LINE: [u8; 256] = [0x5a; 256];

/// Four 256-byte buffers: the shape of a request's hand-off data.
#[derive(Default)]
struct Four {
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
    d: Vec<u8>,
}

impl Reset for Four {
    fn reset(&mut self) {
        self.a.clear();
        self.b.clear();
        self.c.clear();
        self.d.clear();
    }
}

impl Four {
    fn write(&mut self) {
        self.a.extend_from_slice(&LINE);
        self.b.extend_from_slice(&LINE);
        self.c.extend_from_slice(&LINE);
        self.d.extend_from_slice(&LINE);
    }

    fn len(&self) -> usize {
        self.a.len() + self.b.len() + self.c.len() + self.d.len()
    }

    /// The copy the hand-off makes today.
    fn copied(&self) -> Self {
        Four {
            a: self.a.to_vec(),
            b: self.b.to_vec(),
            c: self.c.to_vec(),
            d: self.d.to_vec(),
        }
    }
}

/// What a holder holds, in each shape.
enum Handed {
    Copy(Box<Four>),
    Fresh(Arc<Four>),
    Pool(Frame<Four>),
}

impl Handed {
    fn len(&self) -> usize {
        match self {
            Handed::Copy(v) => v.len(),
            Handed::Fresh(v) => v.len(),
            Handed::Pool(v) => v.len(),
        }
    }
}

#[derive(Clone, Copy)]
enum Shape {
    Copy,
    Fresh,
    Pool,
}

/// One hand-off in `shape`: what the request keeps, and what it hands over.
fn hand_off(shape: Shape, pool: &Arc<FramePool<Four>>) -> (Handed, Handed) {
    match shape {
        Shape::Copy => {
            let mut own = Four::default();
            own.write();
            let handed = Handed::Copy(Box::new(own.copied()));
            (Handed::Copy(Box::new(own)), handed)
        }
        Shape::Fresh => {
            let mut own = Four::default();
            own.write();
            let own = Arc::new(own);
            let handed = Handed::Fresh(Arc::clone(&own));
            (Handed::Fresh(own), handed)
        }
        Shape::Pool => {
            let mut frame = pool.take();
            if let Some(four) = frame.fill() {
                four.write();
            }
            let handed = Handed::Pool(frame.share());
            (Handed::Pool(frame), handed)
        }
    }
}

/// The window every measured thread of a run shares: all warm up, the count starts, all run, the
/// count ends.
struct Window {
    gate: Barrier,
    before: AtomicUsize,
    after: AtomicUsize,
}

impl Window {
    fn new(threads: usize) -> Self {
        Window {
            gate: Barrier::new(threads),
            before: AtomicUsize::new(0),
            after: AtomicUsize::new(0),
        }
    }

    fn measure(&self, mut cycle: impl FnMut()) -> f64 {
        for _ in 0..WARM {
            cycle();
        }
        if self.gate.wait().is_leader() {
            self.before.store(crate::allocations(), Ordering::SeqCst);
        }
        self.gate.wait();
        let start = Instant::now();
        for _ in 0..CYCLES {
            cycle();
        }
        let ns = start.elapsed().as_nanos() as f64 / CYCLES as f64;
        if self.gate.wait().is_leader() {
            self.after.store(crate::allocations(), Ordering::SeqCst);
        }
        self.gate.wait();
        ns
    }

    /// (ns per cycle averaged over the threads, allocations per cycle per measured thread)
    fn result(&self, ns: &[f64]) -> (f64, f64) {
        let allocs = self.after.load(Ordering::SeqCst) - self.before.load(Ordering::SeqCst);
        (
            ns.iter().sum::<f64>() / ns.len() as f64,
            allocs as f64 / (CYCLES * ns.len()) as f64,
        )
    }
}

/// `n` threads at once, each making, handing over on its own thread and dropping.
fn local(shape: Shape, n: usize, pool: &Arc<FramePool<Four>>) -> (f64, f64) {
    let window = Window::new(n);
    let ns: Vec<f64> = std::thread::scope(|s| {
        let joins: Vec<_> = (0..n)
            .map(|_| {
                s.spawn(|| {
                    window.measure(|| {
                        let (own, handed) = hand_off(shape, pool);
                        black_box(handed.len());
                        drop(handed);
                        drop(own);
                    })
                })
            })
            .collect();
        joins.into_iter().map(|j| j.join().unwrap()).collect()
    });
    window.result(&ns)
}

/// The hand-off between the two threads of a pair, made before the loop. Both sides spin, so the
/// time is the hand-off's own and not a thread's wake-up.
struct Pass {
    item: Mutex<Option<Handed>>,
    /// `EMPTY`, `FULL` (an item waits), `DONE` (the partner let it go), `STOP`.
    state: AtomicU8,
}

const EMPTY: u8 = 0;
const FULL: u8 = 1;
const DONE: u8 = 2;
const STOP: u8 = 3;

impl Pass {
    fn wait_for(&self, want: u8) -> u8 {
        loop {
            let now = self.state.load(Ordering::Acquire);
            if now == want || now == STOP {
                return now;
            }
            std::hint::spin_loop();
        }
    }
}

/// 8 pairs of long-lived threads: the first makes and hands over, drops its own and waits; the
/// partner reads and drops last.
fn pairs(shape: Shape, pool: &Arc<FramePool<Four>>) -> (f64, f64) {
    let window = Window::new(THREADS);
    let passes: Vec<Pass> = (0..THREADS)
        .map(|_| Pass {
            item: Mutex::new(None),
            state: AtomicU8::new(EMPTY),
        })
        .collect();
    let ns: Vec<f64> = std::thread::scope(|s| {
        let joins: Vec<_> = passes
            .iter()
            .map(|pass| {
                s.spawn(move || {
                    while pass.wait_for(FULL) == FULL {
                        let handed = pass.item.lock().unwrap().take();
                        black_box(handed.as_ref().map(Handed::len));
                        drop(handed);
                        pass.state.store(DONE, Ordering::Release);
                    }
                });
                let window = &window;
                s.spawn(move || {
                    let ns = window.measure(|| {
                        let (own, handed) = hand_off(shape, pool);
                        *pass.item.lock().unwrap() = Some(handed);
                        // The partner is handed the value only once this holder let go: it
                        // drops last.
                        drop(own);
                        pass.state.store(FULL, Ordering::Release);
                        pass.wait_for(DONE);
                        pass.state.store(EMPTY, Ordering::Release);
                    });
                    pass.state.store(STOP, Ordering::Release);
                    ns
                })
            })
            .collect();
        joins.into_iter().map(|j| j.join().unwrap()).collect()
    });
    window.result(&ns)
}

/// Every shape on 1 thread, 8 threads and 8 pairs: (name, [(ns, allocations per cycle); 3]).
pub fn table() -> Vec<(&'static str, [(f64, f64); 3])> {
    let pool = FramePool::<Four>::build(64);
    [
        ("copy", Shape::Copy),
        ("fresh", Shape::Fresh),
        ("pool", Shape::Pool),
    ]
    .into_iter()
    .map(|(name, shape)| {
        (
            name,
            [
                local(shape, 1, &pool),
                local(shape, THREADS, &pool),
                pairs(shape, &pool),
            ],
        )
    })
    .collect()
}
