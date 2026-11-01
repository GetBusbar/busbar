// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::plane::conditional::{
    Capability, ConditionalResult, Observation, ObservationResult, Request,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Exchange {
    Commit(Request),
    Observe(Observation),
}
impl Exchange {
    fn capability(&self) -> Capability {
        match self {
            Self::Commit(r) => r.capability,
            Self::Observe(r) => r.capability,
        }
    }
    fn correlation(&self) -> u64 {
        match self {
            Self::Commit(r) => r.candidate.correlation,
            Self::Observe(r) => r.correlation,
        }
    }
}
#[derive(Debug)]
pub(super) struct Kept {
    request: Exchange,
    unit: Option<u64>,
    receipt: Option<Arc<[u8]>>,
    lent: bool,
    cancelled: bool,
    applied: bool,
    advance: bool,
}
impl ServiceStore {
    pub(crate) fn conditional_negotiated(&self, caller: usize, ticket: Ticket) -> bool {
        self.lock(ticket)
            .get(&ticket)
            .is_some_and(|h| h.conditional_units.contains_key(&caller))
    }
    pub(crate) fn conditional_input(
        &self,
        caller: usize,
        ticket: Ticket,
        unit: Option<u64>,
    ) -> Result<(Capability, Option<Arc<[u8]>>), ()> {
        if ticket.is_none() {
            return Err(());
        }
        let mut map = self.lock(ticket);
        let held = map.entry(ticket).or_insert_with(|| Held {
            epoch: self.epochs.fetch_add(1, Ordering::Relaxed) + 1,
            entries: HashMap::new(),
            inspections: HashMap::new(),
            conditionals: HashMap::new(),
            conditional_units: HashMap::new(),
        });
        if held
            .conditional_units
            .get(&caller)
            .is_some_and(|u| *u != Ok(unit))
        {
            return Err(());
        }
        held.conditional_units.insert(caller, Ok(unit));
        let receipt = match held.conditionals.get_mut(&caller) {
            Some(k) if !k.cancelled => {
                if k.unit != unit {
                    return Err(());
                }
                if k.receipt.is_some() {
                    k.lent = true;
                }
                k.receipt.clone()
            }
            _ => None,
        };
        // The held marker remains until terminal output/cancel, including the gap between an
        // observation receipt and the fresh GET which consumes it. TICK cannot reset this epoch.
        Ok((
            Capability {
                ticket,
                epoch: held.epoch,
            },
            receipt,
        ))
    }
    fn exchange_begin(
        &self,
        caller: usize,
        unit: Option<u64>,
        request: Exchange,
    ) -> Result<bool, ()> {
        let c = request.capability();
        let id = request.correlation();
        if c.ticket.is_none() || c.epoch == 0 || id == 0 {
            return Err(());
        }
        let replaced = {
            let mut map = self.lock(c.ticket);
            let h = map
                .get_mut(&c.ticket)
                .filter(|h| h.epoch == c.epoch)
                .ok_or(())?;
            if h.conditional_units.get(&caller) != Some(&Ok(unit)) {
                return Err(());
            }
            if let Some(k) = h.conditionals.get(&caller) {
                if k.request.correlation() == id {
                    return if !k.cancelled && k.unit == unit && k.request == request {
                        Ok(false)
                    } else {
                        Err(())
                    };
                }
                if k.cancelled || !k.lent || !k.advance || id < k.request.correlation() {
                    return Err(());
                }
            }
            h.conditionals.insert(
                caller,
                Kept {
                    request,
                    unit,
                    receipt: None,
                    lent: false,
                    cancelled: false,
                    applied: false,
                    advance: false,
                },
            )
        };
        drop(replaced);
        self.held.conditional(c.ticket, caller, true);
        Ok(true)
    }
    pub(crate) fn conditional_begin(
        &self,
        caller: usize,
        unit: Option<u64>,
        request: &Request,
    ) -> Result<bool, ()> {
        self.exchange_begin(caller, unit, Exchange::Commit(request.clone()))
    }
    pub(crate) fn observation_begin(
        &self,
        caller: usize,
        unit: Option<u64>,
        request: &Observation,
    ) -> Result<bool, ()> {
        self.exchange_begin(caller, unit, Exchange::Observe(request.clone()))
    }
    fn exchange_complete(
        &self,
        caller: usize,
        unit: Option<u64>,
        request: Exchange,
        receipt: Arc<[u8]>,
        applied: bool,
        advance: bool,
    ) -> bool {
        let c = request.capability();
        let mut map = self.lock(c.ticket);
        let Some(k) = map
            .get_mut(&c.ticket)
            .filter(|h| h.epoch == c.epoch)
            .and_then(|h| h.conditionals.get_mut(&caller))
        else {
            return false;
        };
        if k.cancelled || k.unit != unit || k.request != request || k.receipt.is_some() {
            return false;
        }
        k.applied = applied;
        k.advance = advance;
        k.receipt = Some(receipt);
        true
    }
    pub(crate) fn conditional_complete(
        &self,
        caller: usize,
        unit: Option<u64>,
        request: &Request,
        result: &ConditionalResult,
        receipt: Arc<[u8]>,
    ) -> bool {
        if result.correlation != request.candidate.correlation {
            return false;
        }
        self.exchange_complete(
            caller,
            unit,
            Exchange::Commit(request.clone()),
            receipt,
            matches!(
                result.decision,
                Ok(busbar_contract::abi::sdk::store::conditional::Decision::Applied)
            ),
            result.decision.is_ok(),
        )
    }
    pub(crate) fn observation_complete(
        &self,
        caller: usize,
        unit: Option<u64>,
        request: &Observation,
        result: &ObservationResult,
        receipt: Arc<[u8]>,
    ) -> bool {
        if result.correlation != request.correlation {
            return false;
        }
        self.exchange_complete(
            caller,
            unit,
            Exchange::Observe(request.clone()),
            receipt,
            false,
            result.result.is_ok(),
        )
    }
    pub(crate) fn conditional_output_allowed(
        &self,
        caller: usize,
        ticket: Ticket,
        unit: Option<u64>,
    ) -> bool {
        let map = self.lock(ticket);
        match map.get(&ticket).and_then(|h| h.conditionals.get(&caller)) {
            None => true,
            Some(k) => !k.cancelled && k.unit == unit && k.lent && k.applied,
        }
    }
    pub(crate) fn conditional_finished(&self, caller: usize, ticket: Ticket) {
        self.held.conditional(ticket, caller, false);
    }
    pub(crate) fn conditional_cancel(&self, caller: usize, ticket: Ticket) {
        let receipt = {
            let mut map = self.lock(ticket);
            map.get_mut(&ticket).and_then(|h| {
                h.conditional_units.insert(caller, Err(()));
                h.conditionals.get_mut(&caller).and_then(|k| {
                    k.cancelled = true;
                    k.receipt.take()
                })
            })
        };
        drop(receipt);
        self.held.conditional(ticket, caller, false);
    }
}
