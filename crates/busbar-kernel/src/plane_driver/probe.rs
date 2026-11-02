// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

struct NoCaller;

impl CallerEnd for NoCaller {
    fn head(&self, _status: u32, _fields: HeadFields) {}

    async fn write(&self, _bytes: &[u8]) -> bool {
        true
    }
}

impl PlaneDriver {
    pub async fn probe<F: FarEnd>(
        &self,
        kernel: &Kernel,
        key: UnitKey,
        far: &F,
        timeout: Duration,
    ) {
        let ctx = UnitCtx {
            call: kernel.next_call(),
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
            body: bytes::Bytes::new(),
        };

        self.sweep();
        let units = self.unit(&(), far, &NoCaller, arrival, deadline_ns);
        let Some(decoded) = units.arrive(key.get()) else {
            return;
        };

        if units.declined_status().is_some() {
            return;
        }
        let Some(ticket) = self.calls.mint() else {
            return;
        };
        let token = Pass::<Route>::mint_bound(kernel.seal(), ctx.call);
        let body = units.arrival.body.clone();
        let mut run = Pumping::new(self, &token, &units.state, &ctx, ticket, deadline_ns, body);
        run.lend_unit(CLAIM_PROBE, decoded.dialect, &[], 0);
        if let route::End::Cancel(_, None) = units.attempts(&mut run, None).await {
            let _ = run.cancel_now().await;
        }
        run.finish();
    }
}

pub struct PlaneProbes {
    driver: Arc<PlaneDriver>,
    egress: Arc<Egress>,
    kernel: Arc<Kernel>,
    keys: Arc<UnitKeyMint>,
    members: Vec<DestinationId>,
}

impl PlaneProbes {
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
        self.members
            .get(member)
            .is_some_and(|d| (self.egress.breaker)().suppressing(*d, self.egress.clock.now_secs()))
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
