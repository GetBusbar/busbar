// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WALK-NEXT (GROUP-time section 6, step 3): one `Walk::start` and one `next` over a four-member
//! pool, one million rounds, the median nanoseconds per round over 21 samples. Every port is a
//! fixed fake (all admitted, all free), so the figure is the walk's own work and its clock reads.

use std::hint::black_box;
use std::time::Instant;

use busbar_contract::caps::{KernelSeal, Pass, Route};
use busbar_contract::clock::HostClock;
use busbar_kernel_egress::ports::{
    Admit, BoxFut, Breaker, Capacity, Classified, DestinationId, Outcome, Permit, PermitHandle,
    Telemetry, Unavailable, UpstreamStatus,
};
use busbar_kernel_egress::{Member, Pool, Step, Walk, WalkPorts};

const ROUNDS: u32 = 1_000_000;
const SAMPLES: usize = 21;

struct Open;
impl Breaker for Open {
    fn try_admit(&self, _: &str, _: DestinationId, _: u64) -> Result<Admit, Unavailable> {
        Ok(Admit { probe_epoch: None })
    }
    fn unavailable(
        &self,
        _: &str,
        _: DestinationId,
        _: u64,
        _: &Pass<Route>,
    ) -> Option<Unavailable> {
        None
    }
    fn ready(&self, _: &str, _: DestinationId, _: u64, _: &Pass<Route>) -> bool {
        true
    }
    fn admissible(&self, _: DestinationId) -> bool {
        true
    }
    fn cooldown_remaining(&self, _: &str, _: DestinationId, _: u64, _: &Pass<Route>) -> u64 {
        0
    }
    fn classify(&self, _: DestinationId, _: UpstreamStatus) -> Classified {
        unreachable!("the walk never classifies")
    }
    fn observe(&self, _: &str, _: DestinationId, _: Outcome, _: u64, _: &Pass<Route>) -> bool {
        false
    }
    fn suppressing(&self, _: DestinationId, _: u64) -> bool {
        false
    }
    fn probed(&self, _: DestinationId, _: Outcome, _: u64, _: &Pass<Route>) {}
    fn release_probe(&self, _: &str, _: DestinationId, _: u64, _: u64) {}
    fn spend_budget(&self, _: DestinationId) -> bool {
        true
    }
    fn refund_budget(&self, _: DestinationId) {}
}

#[derive(Debug)]
struct Slot(DestinationId);
impl PermitHandle for Slot {
    fn destination(&self) -> DestinationId {
        self.0
    }
}

struct Free;
impl Capacity for Free {
    fn try_acquire(&self, d: DestinationId) -> Option<Permit> {
        Some(Permit::new(Box::new(Slot(d))))
    }
    fn acquire_any<'a>(
        &'a self,
        _: &'a [DestinationId],
    ) -> BoxFut<'a, Option<(DestinationId, Permit)>> {
        Box::pin(async { None })
    }
}

struct Quiet;
impl Telemetry for Quiet {
    fn upstream_attempt(&self, _: &str, _: DestinationId) {}
    fn upstream_failure(&self, _: &str, _: DestinationId, _: &'static str) {}
    fn failover(&self, _: &str, _: &'static str) {}
    fn breaker_trip(&self, _: &str, _: DestinationId) {}
    fn queued(&self, _: &str, _: i64, _: i64) {}
}

/// The host clock with a sleep that never waits: the walk under test never parks.
fn no_sleep(_: Instant) -> busbar_contract::clock::Sleep {
    Box::pin(async {})
}

fn main() {
    let members = (0..4)
        .map(|i| Member::new(DestinationId::new(i), format!("m{i}"), 1))
        .collect();
    let mut pools = foldhash::HashMap::default();
    let name = busbar_contract::kept::Text::fixed("p");
    pools.insert(name.clone(), Pool::new("p", members));
    let clock = HostClock::system(no_sleep);
    let ports = WalkPorts {
        breaker: &Open,
        capacity: &Free,
        clock: &clock,
        telemetry: &Quiet,
        pools: &pools,
    };
    let token = Pass::<Route>::mint(&KernelSeal::acquire_for_kernel());
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        for _ in 0..ROUNDS / SAMPLES as u32 {
            let at = clock.now();
            let mut walk = Walk::start(&ports, &name, at);
            let step = walk.next(&ports, None, &token, at);
            assert!(matches!(step, Step::Take(_)));
            black_box(step);
        }
        let per = started.elapsed().as_nanos() as f64 / f64::from(ROUNDS / SAMPLES as u32);
        samples.push(per);
    }
    samples.sort_by(f64::total_cmp);
    println!(
        "WALK-NEXT: Walk::start + next over a four-member pool: median {:.1} ns/round ({} rounds)",
        samples[SAMPLES / 2],
        ROUNDS
    );
}
