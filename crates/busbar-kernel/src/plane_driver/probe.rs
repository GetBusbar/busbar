// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HEALTH PROBE UNIT (`BUSBAR-1.6.0.md` Part 3, "Nested units, work continuations and probes
//! are units of their own"; §B item 14, K7): a kernel-originated unit pinned to one member. The
//! driver calls `arrive` with the probe claim, pushes the ATTEMPT piece alone, and sends the probe
//! request the plane emits through the member's far end, whose status table classifies the answer
//! as it classifies organic traffic. The unit is a tick: zero-billed, no lease (§1's exempt
//! origins), and it passes no kernel step.
//!
//! [`PlaneProbes`] binds the probe service's schedule ([`crate::probe`]) to one plane instance's
//! driver and egress: the composition root builds one for a plane whose tail states
//! `TAIL_PROBES`, and for no other.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::plane::{CLAIM_PROBE, TAIL_PROBES};
use busbar_contract::caps::{OriginKind, Pass, Route};
use busbar_contract::ids::UnitKey;
use busbar_contract::DestinationId;

use super::route::{self, CallerEnd, FarEnd, Pumping};
use super::{Arrival, Egress, HeadFields, PlaneDriver};
use crate::door::UnitKeyMint;
use crate::probe::ProbeTarget;
use crate::registry::Generation;
use crate::teller::{Kernel, UnitCtx};

/// A probe has no caller: what the plane answers it goes nowhere.
struct NoCaller;

impl CallerEnd for NoCaller {
    fn head(&self, _status: u32, _fields: HeadFields) {}

    async fn write(&self, _bytes: &[u8]) -> bool {
        true
    }
}

impl PlaneDriver {
    /// ONE HEALTH PROBE through `far`, a far end pinned to the probed member
    /// ([`Egress::probe`]), as unit `key`, bounded by `timeout`. A plane that refuses the probe
    /// arrival, or emits no request, sends nothing and nothing is recorded.
    pub async fn probe<F: FarEnd>(
        &self,
        kernel: &Kernel,
        key: UnitKey,
        far: &F,
        timeout: Duration,
    ) {
        let ctx = UnitCtx {
            key,
            origin: OriginKind::Tick,
            session: None,
            generation: Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        };
        let deadline_ns = self
            .calls
            .now_ns()
            .saturating_add(u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX));
        let arrival = Arrival {
            claim: CLAIM_PROBE,
            method: Vec::new(),
            target: Vec::new(),
            fields: Vec::new(),
            body: Arc::from(&[][..]),
        };
        let units = self.unit(&(), far, &NoCaller, arrival, deadline_ns);
        let Some(decoded) = units.arrive(key.get()) else {
            return;
        };
        let Some(ticket) = self.calls.mint() else {
            return;
        };
        let token = Pass::<Route>::mint(kernel.seal());
        let body = units.arrival.body.clone();
        let mut run = Pumping::new(self, &token, &units.state, &ctx, ticket, deadline_ns, body);
        run.lend_unit(CLAIM_PROBE, decoded.dialect, &[], 0);
        if let route::End::Cancel(_, None) = units.attempts(&mut run, None).await {
            // The deadline or a reload between crossings: the driver's own ticketless cancel.
            let _ = self.cancel_now(ticket);
        }
        run.finish();
    }
}

/// THE PROBE SERVICE'S TARGET for one plane instance: its driver, its egress, and the members the
/// schedule indexes, in the schedule's order.
pub struct PlaneProbes {
    driver: Arc<PlaneDriver>,
    egress: Arc<Egress>,
    kernel: Arc<Kernel>,
    keys: Arc<UnitKeyMint>,
    members: Vec<DestinationId>,
}

impl PlaneProbes {
    /// The target for a plane whose tail flags are `tail_flags`; `None` unless the plane states
    /// [`TAIL_PROBES`]: a plane that does not answer probes is never sent one.
    #[must_use]
    pub fn new(
        tail_flags: u32,
        driver: Arc<PlaneDriver>,
        egress: Arc<Egress>,
        kernel: Arc<Kernel>,
        keys: Arc<UnitKeyMint>,
        members: Vec<DestinationId>,
    ) -> Option<Self> {
        (tail_flags & TAIL_PROBES != 0).then_some(PlaneProbes {
            driver,
            egress,
            kernel,
            keys,
            members,
        })
    }
}

impl ProbeTarget for PlaneProbes {
    fn suppressing(&self, member: usize) -> bool {
        self.members.get(member).is_some_and(|d| {
            self.egress
                .breaker
                .suppressing(*d, self.egress.clock.now_secs())
        })
    }

    async fn probe(&self, member: usize, timeout: Duration) {
        let Some(far) = self
            .members
            .get(member)
            .and_then(|d| self.egress.probe(*d, timeout))
        else {
            return;
        };
        self.driver
            .probe(&self.kernel, self.keys.mint(), &far, timeout)
            .await;
    }
}
