// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-FRAMING-OPEN: accepting one framing on a test door and dropping it, as a connection's open and
//! close pay for it.
//!
//! The door answers every crossing at once (no wire, no pieces), so the time is the host side of
//! the open: the framing's buffers, the crossing of `begin` and the close on drop. Same allocator
//! as the shipped binary (jemalloc).
//!
//! It prints the median and p99 nanoseconds per open on one thread, then on `B_FRAMING_THREADS`
//! threads (default 8), and the resident memory (VmRSS, Linux) before and after
//! `B_FRAMING_HELD` (default 1,000) framings are held open at once. `B_FRAMING_OPENS` sets the
//! opens per thread (default 20,000).

use std::sync::{Arc, Barrier};
use std::time::Instant;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{ROLE_FRAMER, SIDE_ACCEPT};
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, Established, FramerDoor, Framing};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// A framer entry that answers every crossing at once.
struct Instant_ {
    facts: DoorFacts,
}

impl Instant_ {
    fn new() -> Self {
        Self {
            facts: DoorFacts {
                dials: false,
                name: "bench".to_owned(),
                claims: vec!["bench"],
                role: ROLE_FRAMER,
                composes_over: Vec::new(),
                ported: false,
                status_rows: Vec::new(),
                status_namespaces: vec![None],
                handoff_status: vec![None],
                duplex: Vec::new(),
                datagram: false,
            },
        }
    }
}

impl FramerDoor for Instant_ {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn accepts(&self) -> bool {
        true
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        if let Call::Begin(_, out) = call {
            out.framing = 1;
        }
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }
}

/// One open and close.
fn open(door: &Arc<dyn FramerDoor>, established: &Established) {
    let opened = Framing::begin(Arc::clone(door), SIDE_ACCEPT, "bench://x", established);
    std::hint::black_box(opened.is_ok());
}

/// Nanoseconds per open, sorted, for `opens` opens on this thread.
fn run(door: &Arc<dyn FramerDoor>, opens: usize) -> Vec<u64> {
    let established = Established::default();
    for _ in 0..opens / 20 {
        open(door, &established);
    }
    let mut times = Vec::with_capacity(opens);
    for _ in 0..opens {
        let at = Instant::now();
        open(door, &established);
        times.push(u64::try_from(at.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    times.sort_unstable();
    times
}

fn report(label: &str, mut all: Vec<u64>) {
    all.sort_unstable();
    let at = |q: usize| all[(all.len() * q / 100).min(all.len() - 1)];
    println!(
        "B-FRAMING-OPEN {label}: median {} ns, p99 {} ns per open ({} opens)",
        at(50),
        at(99),
        all.len()
    );
}

/// The process's resident memory in KiB, where the platform says (Linux).
fn rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let door: Arc<dyn FramerDoor> = Arc::new(Instant_::new());
    let opens = env("B_FRAMING_OPENS", 20_000);
    report("1 thread", run(&door, opens));

    let threads = env("B_FRAMING_THREADS", 8);
    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let (door, barrier) = (Arc::clone(&door), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                run(&door, opens)
            })
        })
        .collect();
    let all: Vec<u64> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap_or_default())
        .collect();
    report(&format!("{threads} threads"), all);

    let held = env("B_FRAMING_HELD", 1_000);
    let before = rss_kib();
    let established = Established::default();
    let open: Vec<_> = (0..held)
        .filter_map(|_| {
            Framing::begin(Arc::clone(&door), SIDE_ACCEPT, "bench://x", &established).ok()
        })
        .collect();
    let after = rss_kib();
    println!(
        "B-FRAMING-OPEN resident: {} KiB before, {} KiB after {} framings held ({} opened)",
        before.unwrap_or(0),
        after.unwrap_or(0),
        held,
        open.len()
    );
}
