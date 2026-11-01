// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Inspection receipts in the service store's existing ticket/result epoch. No completion handle
//! can alias these records. A caller has one current query; increasing IDs replace consumed ones.

use super::*;
use busbar_contract::abi::mechanism::inspection::InspectionRequest;

#[derive(Debug)]
pub(super) struct Kept {
    request: InspectionRequest,
    unit: Option<u64>,
    receipt: Option<Arc<[u8]>>,
    lent: bool,
    cancelled: bool,
}

impl ServiceStore {
    pub(crate) fn inspection_active(&self, caller: usize, ticket: Ticket) -> bool {
        self.lock(ticket)
            .get(&ticket)
            .and_then(|h| h.inspections.get(&caller))
            .is_some_and(|kept| !kept.cancelled)
    }
    /// The epoch and immutable receipt lent to this crossing. Unit binding is host-derived.
    pub(crate) fn inspection_input(
        &self,
        caller: usize,
        ticket: Ticket,
        unit: Option<u64>,
    ) -> Result<(u64, Option<Arc<[u8]>>), ()> {
        if ticket.is_none() {
            return Ok((0, None));
        }
        let answer = {
            let mut map = self.lock(ticket);
            let held = map.entry(ticket).or_insert_with(|| Held {
                epoch: self.epochs.fetch_add(1, Ordering::Relaxed) + 1,
                entries: HashMap::new(),
                inspections: HashMap::new(),
                conditionals: HashMap::new(),
                conditional_units: HashMap::new(),
                retirement: HashMap::new(),
            });
            let receipt = match held.inspections.get_mut(&caller) {
                Some(kept) if !kept.cancelled => {
                    if kept.unit != unit {
                        return Err(());
                    }
                    if kept.receipt.is_some() {
                        kept.lent = true;
                    }
                    kept.receipt.clone()
                }
                _ => None,
            };
            (held.epoch, receipt)
        };
        if answer.1.is_some() {
            self.held.inspection(ticket, caller, false);
        }
        Ok(answer)
    }

    /// Reserve a copied request before reading the provider. `false` is an exact replay, which
    /// neither reads the provider again nor wakes the ticket again.
    pub(crate) fn inspection_begin(
        &self,
        caller: usize,
        unit: Option<u64>,
        request: &InspectionRequest,
    ) -> Result<bool, ()> {
        if request.id == 0 || request.ticket.is_none() || request.epoch == 0 {
            return Err(());
        }
        let replaced = {
            let mut map = self.lock(request.ticket);
            let held = map
                .get_mut(&request.ticket)
                .filter(|h| h.epoch == request.epoch)
                .ok_or(())?;
            if let Some(kept) = held.inspections.get(&caller) {
                if kept.request.id == request.id {
                    return if !kept.cancelled && kept.request == *request && kept.unit == unit {
                        Ok(false)
                    } else {
                        Err(())
                    };
                }
                if request.id < kept.request.id || (!kept.lent && !kept.cancelled) {
                    return Err(());
                }
            }
            held.inspections.insert(
                caller,
                Kept {
                    request: request.clone(),
                    unit,
                    receipt: None,
                    lent: false,
                    cancelled: false,
                },
            )
        };
        drop(replaced);
        self.held.inspection(request.ticket, caller, true);
        Ok(true)
    }

    /// Commit once, only if the original request still owns this epoch. Provider code ran with
    /// no store lock held. A cancel, new operation or recycled ticket discards late completion.
    pub(crate) fn inspection_complete(
        &self,
        caller: usize,
        unit: Option<u64>,
        request: &InspectionRequest,
        receipt: Arc<[u8]>,
    ) -> bool {
        let mut map = self.lock(request.ticket);
        let Some(kept) = map
            .get_mut(&request.ticket)
            .filter(|h| h.epoch == request.epoch)
            .and_then(|h| h.inspections.get_mut(&caller))
        else {
            return false;
        };
        if kept.cancelled || kept.unit != unit || kept.request != *request || kept.receipt.is_some()
        {
            return false;
        }
        kept.receipt = Some(receipt);
        true
    }

    /// Cancel this caller's inspection without disturbing other held driver service exchanges.
    /// Keep its ID tombstone until the epoch ends, so its request cannot start again.
    pub(crate) fn inspection_cancel(&self, caller: usize, ticket: Ticket) {
        let receipt = {
            let mut map = self.lock(ticket);
            map.get_mut(&ticket)
                .and_then(|h| h.inspections.get_mut(&caller))
                .and_then(|kept| {
                    kept.cancelled = true;
                    kept.receipt.take()
                })
        };
        drop(receipt);
        self.held.inspection(ticket, caller, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::abi::mechanism::inspection::InspectionQuery;

    fn request(
        store: &ServiceStore,
        caller: usize,
        ticket: Ticket,
        unit: Option<u64>,
    ) -> InspectionRequest {
        let (epoch, _) = store.inspection_input(caller, ticket, unit).unwrap();
        InspectionRequest {
            ticket,
            epoch,
            id: 1,
            query: InspectionQuery::CarrierSessions { sessions: vec![7] },
        }
    }

    #[test]
    fn receipts_cannot_alias_service_handles_rebind_units_queries_or_instances() {
        let store = ServiceStore::default();
        let ticket = Ticket {
            slot: 3,
            generation: 9,
        };
        store.held.track(ticket);
        store.keep(ticket, 1); // the ordinary completion handle's sequence is also 1.
        let a = request(&store, 11, ticket, Some(5));
        assert_eq!(store.inspection_begin(11, Some(5), &a), Ok(true));
        assert_eq!(store.held.held(ticket), 1);
        let mut changed = a.clone();
        changed.query = InspectionQuery::CarrierSessions { sessions: vec![8] };
        assert_eq!(store.inspection_begin(11, Some(5), &changed), Err(()));
        assert_eq!(store.inspection_begin(11, Some(6), &a), Err(()));
        let other = request(&store, 12, ticket, Some(6));
        assert_eq!(store.inspection_begin(12, Some(6), &other), Ok(true));
        assert_eq!(store.inspection_input(11, ticket, Some(6)), Err(()));
        assert!(store.inspection_complete(11, Some(5), &a, Arc::from(&b"original"[..])));
        assert!(!store.inspection_complete(11, Some(5), &a, Arc::from(&b"duplicate"[..])));
        assert_eq!(store.inspection_begin(11, Some(5), &a), Ok(false));
        assert!(store
            .inspection_input(12, ticket, Some(6))
            .unwrap()
            .1
            .is_none());
        assert_eq!(
            &*store
                .inspection_input(11, ticket, Some(5))
                .unwrap()
                .1
                .unwrap(),
            b"original"
        );
        assert_eq!(
            store.held.held(ticket),
            1,
            "the other instance's query is still held"
        );
        assert_eq!(
            store.held(),
            1,
            "the ordinary service answer remains distinct"
        );
        let mut next = a.clone();
        next.id = 2;
        assert_eq!(store.inspection_begin(11, Some(5), &next), Ok(true));
        assert_eq!(store.inspection_begin(11, Some(5), &a), Err(()));
    }

    #[test]
    fn cancellation_new_epoch_and_ticket_recycle_discard_late_receipts() {
        let store = ServiceStore::default();
        let ticket = Ticket {
            slot: 3,
            generation: 9,
        };
        let original = request(&store, 11, ticket, None);
        assert_eq!(store.inspection_begin(11, None, &original), Ok(true));
        store.inspection_cancel(11, ticket);
        assert!(!store.inspection_complete(11, None, &original, Arc::from(&b"late"[..])));
        assert_eq!(store.inspection_begin(11, None, &original), Err(()));
        assert!(store
            .inspection_input(11, ticket, None)
            .unwrap()
            .1
            .is_none());
        store.forget(ticket);
        let next = request(&store, 11, ticket, None);
        assert_ne!(original.epoch, next.epoch);
        assert_eq!(store.inspection_begin(11, None, &original), Err(()));
        assert_eq!(store.inspection_begin(11, None, &next), Ok(true));
        assert!(!store.inspection_complete(11, None, &original, Arc::from(&b"late"[..])));
        store.forget(ticket);
        let recycled = Ticket {
            generation: 10,
            ..ticket
        };
        let recycled_query = request(&store, 11, recycled, None);
        assert_eq!(store.inspection_begin(11, None, &recycled_query), Ok(true));
        assert!(!store.inspection_complete(11, None, &next, Arc::from(&b"late"[..])));
        assert!(store
            .inspection_input(11, recycled, None)
            .unwrap()
            .1
            .is_none());
    }
}
