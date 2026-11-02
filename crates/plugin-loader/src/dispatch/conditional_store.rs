// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::plane::conditional::{
    Capability, ConditionalResult, Observation, ObservationResult, Request,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Exchange {
    Commit(zeroize::Zeroizing<Request>),
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
    finished: bool,
    settlement_lent: bool,
    owner: Option<&'static super::super::ticket::InstanceWake>,
}
impl Kept {
    pub(super) fn completed_owner(&self) -> Option<&'static super::super::ticket::InstanceWake> {
        self.receipt.as_ref().and(self.owner)
    }
    pub(super) fn retire(&mut self) -> bool {
        if !self.finished && matches!(self.request, Exchange::Commit(_)) {
            self.cancelled = true;
            true
        } else {
            false
        }
    }
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
            retirement: HashMap::new(),
        });
        if held
            .conditional_units
            .get(&caller)
            .is_some_and(|u| *u != Ok(unit))
        {
            return Err(());
        }
        held.conditional_units.insert(caller, Ok(unit));
        let receipt = match held.conditionals.get_mut(&(caller, held.epoch)) {
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
        owner: Option<&'static super::super::ticket::InstanceWake>,
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
            if let Some(k) = h.conditionals.get(&(caller, h.epoch)) {
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
                (caller, c.epoch),
                Kept {
                    request,
                    unit,
                    receipt: None,
                    lent: false,
                    cancelled: false,
                    applied: false,
                    advance: false,
                    finished: false,
                    settlement_lent: false,
                    owner,
                },
            )
        };
        drop(replaced);
        self.held.conditional(c.ticket, caller, true);
        Ok(true)
    }
    pub(crate) fn conditional_begin(
        &self,
        owner: &'static super::super::ticket::InstanceWake,
        unit: Option<u64>,
        request: &Request,
    ) -> Result<bool, ()> {
        self.exchange_begin(
            std::ptr::from_ref(owner) as usize,
            unit,
            Exchange::Commit(zeroize::Zeroizing::new(request.clone())),
            Some(owner),
        )
    }
    pub(crate) fn observation_begin(
        &self,
        caller: usize,
        unit: Option<u64>,
        request: &Observation,
    ) -> Result<bool, ()> {
        self.exchange_begin(caller, unit, Exchange::Observe(request.clone()), None)
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
            .and_then(|h| h.conditionals.get_mut(&(caller, c.epoch)))
        else {
            return false;
        };
        if (k.cancelled && !matches!(k.request, Exchange::Commit(_)))
            || k.finished
            || k.unit != unit
            || k.request != request
            || k.receipt.is_some()
        {
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
            Exchange::Commit(zeroize::Zeroizing::new(request.clone())),
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
        if map
            .get(&ticket)
            .is_some_and(|h| h.conditional_units.get(&caller) == Some(&Err(())))
        {
            return false;
        }
        match map
            .get(&ticket)
            .and_then(|h| h.conditionals.get(&(caller, h.epoch)))
        {
            None => true,
            Some(k) => !k.cancelled && k.unit == unit && k.lent && k.applied,
        }
    }
    pub(crate) fn conditional_finished(&self, caller: usize, ticket: Ticket) {
        {
            let mut map = self.lock(ticket);
            if let Some(h) = map.get_mut(&ticket) {
                if let Some(k) = h.conditionals.get_mut(&(caller, h.epoch)) {
                    if !k.cancelled {
                        k.finished = true;
                    }
                }
            }
        }
        self.held.conditional(ticket, caller, false);
    }
    pub(crate) fn conditional_cancel(&self, caller: usize, ticket: Ticket) {
        let receipt = {
            let mut map = self.lock(ticket);
            map.get_mut(&ticket).and_then(|h| {
                // Ordinary legacy service state does not opt an instance into this protocol.
                if !h.conditional_units.contains_key(&caller) {
                    return None;
                }
                h.conditional_units.insert(caller, Err(()));
                h.conditionals.get_mut(&(caller, h.epoch)).and_then(|k| {
                    k.cancelled = true;
                    if matches!(k.request, Exchange::Commit(_)) && !k.finished {
                        None
                    } else {
                        k.finished = true;
                        k.receipt.take()
                    }
                })
            })
        };
        drop(receipt);
        self.held.conditional(ticket, caller, false);
        self.wake_settlement_ready(caller);
    }

    pub(crate) fn conditional_retired(&self, caller: usize, request: &Request) -> bool {
        self.lock(request.capability.ticket)
            .get(&request.capability.ticket)
            .and_then(|h| h.conditionals.get(&(caller, request.capability.epoch)))
            .is_some_and(|k| {
                k.cancelled && matches!(&k.request, Exchange::Commit(held) if &**held == request)
            })
    }

    /// One immutable outcome for this same instance; never a capability or a new submission.
    pub(crate) fn settlement_input(
        &self,
        caller: usize,
    ) -> Option<(zeroize::Zeroizing<Request>, Arc<[u8]>)> {
        // The InstanceWake driver-selection lock serializes lending. Keep a lent receipt sticky
        // until ACK, then select the oldest existing epoch so new arrivals cannot starve it.
        for previously_lent in [true, false] {
            let mut oldest: Option<(Ticket, u64)> = None;
            for shard in &self.shards {
                let map = shard.lock().unwrap_or_else(|e| e.into_inner());
                for (ticket, h) in map.iter() {
                    for ((owner, epoch), k) in &h.conditionals {
                        if *owner == caller
                            && k.cancelled
                            && !k.finished
                            && k.settlement_lent == previously_lent
                            && k.receipt.is_some()
                            && matches!(k.request, Exchange::Commit(_))
                            && oldest.is_none_or(|(_, prior)| *epoch < prior)
                        {
                            oldest = Some((*ticket, *epoch));
                        }
                    }
                }
            }
            if let Some((ticket, epoch)) = oldest {
                let mut map = self.lock(ticket);
                if let Some(k) = map
                    .get_mut(&ticket)
                    .and_then(|h| h.conditionals.get_mut(&(caller, epoch)))
                {
                    if k.cancelled && !k.finished && k.settlement_lent == previously_lent {
                        if let (Exchange::Commit(request), Some(receipt)) = (&k.request, &k.receipt)
                        {
                            k.settlement_lent = true;
                            return Some((request.clone(), Arc::clone(receipt)));
                        }
                    }
                }
            }
        }
        None
    }

    pub(crate) fn conditional_current_retired(&self, caller: usize, ticket: Ticket) -> bool {
        self.lock(ticket)
            .get(&ticket)
            .is_some_and(|h| h.conditional_units.get(&caller) == Some(&Err(())))
    }

    pub(crate) fn wake_settlement_ready(&self, caller: usize) {
        let owner = self.shards.iter().find_map(|shard| {
            shard
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .find_map(|h| {
                    h.conditionals.iter().find_map(|((id, _), k)| {
                        (*id == caller && k.cancelled && !k.finished && k.receipt.is_some())
                            .then_some(k.owner)
                            .flatten()
                    })
                })
        });
        if let Some(owner) = owner {
            super::super::conditional::wake_driver(owner);
        }
    }

    /// Remove only the exact original commit after its receipt has been lent and acknowledged.
    pub(crate) fn settlement_ack(
        &self,
        caller: usize,
        ack: &busbar_contract::abi::sdk::plane::conditional::SettlementAck,
        consume: bool,
    ) -> Result<bool, ()> {
        // Hash the retained snapshot outside the shard lock. Its encoder and snapshot both
        // carry wiping owners, and retiring either owner must not happen under a host lock.
        let request = {
            let map = self.lock(ack.capability.ticket);
            let Some(h) = map.get(&ack.capability.ticket) else {
                return Ok(false);
            };
            let Some(k) = h.conditionals.get(&(caller, ack.capability.epoch)) else {
                return if h
                    .conditionals
                    .keys()
                    .any(|(owner, epoch)| *owner != caller && *epoch == ack.capability.epoch)
                {
                    Err(())
                } else {
                    Ok(false)
                };
            };
            let Exchange::Commit(request) = &k.request else {
                return Err(());
            };
            request.clone()
        };
        if !ack.matches(&request).map_err(|_| ())? {
            return Err(());
        }
        let removed = {
            let mut map = self.lock(ack.capability.ticket);
            let Some(h) = map.get_mut(&ack.capability.ticket) else {
                return Ok(false);
            };
            let key = (caller, ack.capability.epoch);
            let Some(k) = h.conditionals.get(&key) else {
                // An acknowledgement for another instance cannot consume its entry. An already
                // consumed acknowledgement is harmless, including an output retry.
                if h.conditionals
                    .keys()
                    .any(|(owner, epoch)| *owner != caller && *epoch == ack.capability.epoch)
                {
                    return Err(());
                }
                return Ok(false);
            };
            let Exchange::Commit(current) = &k.request else {
                return Err(());
            };
            if !k.cancelled
                || k.finished
                || !k.settlement_lent
                || k.receipt.is_none()
                || **current != *request
            {
                return Err(());
            }
            if !consume {
                return Ok(false);
            }
            let kept = h.conditionals.remove(&key);
            let empty_owner = if h.empty() {
                map.remove(&ack.capability.ticket)
            } else {
                None
            };
            (kept, empty_owner)
        };
        let consumed = removed.0.is_some();
        drop(removed);
        Ok(consumed)
    }

    /// Instance teardown ends plugin-side local obligations, never an in-flight store request.
    pub(crate) fn conditional_teardown(&self, caller: usize) {
        for shard in &self.shards {
            let removed = {
                let mut map = shard.lock().unwrap_or_else(|e| e.into_inner());
                let mut removed = Vec::new();
                for h in map.values_mut() {
                    h.conditional_units.remove(&caller);
                    let keys: Vec<_> = h
                        .conditionals
                        .keys()
                        .filter(|(owner, _)| *owner == caller)
                        .copied()
                        .collect();
                    for key in keys {
                        if let Some(kept) = h.conditionals.remove(&key) {
                            removed.push(kept);
                        }
                    }
                }
                let empty: Vec<_> = map
                    .iter()
                    .filter(|(_, h)| h.empty())
                    .map(|(ticket, _)| *ticket)
                    .collect();
                let owners: Vec<_> = empty
                    .into_iter()
                    .filter_map(|ticket| map.remove(&ticket))
                    .collect();
                (removed, owners)
            };
            drop(removed);
        }
    }

    #[cfg(test)]
    pub(crate) fn conditional_ticket_kept(&self, ticket: Ticket) -> bool {
        self.lock(ticket).contains_key(&ticket)
    }
}
