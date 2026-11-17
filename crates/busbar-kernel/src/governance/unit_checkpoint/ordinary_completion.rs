// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Original ordinary checkpoint completion. Selected final-reader readiness is separate.

use super::{error, GovState, RecordStoreResult, RecoveryEvent, UnitCheckpoint};
use busbar_contract::storage::{StorageCredit, StorageSource};
use std::alloc::Layout;
use std::sync::{Arc, Mutex};

struct Accepted {
    book: Arc<()>,
    id: [u8; 16],
    unit: u64,
    revision: u64,
}

struct Applied {
    revision: u64,
    events: Vec<RecoveryEvent>,
}

struct State {
    accepted: Option<Accepted>,
    applied: Option<Applied>,
    event_credit: Option<StorageCredit>,
}

pub(super) struct OrdinarySignal {
    state: Mutex<State>,
    changed: tokio::sync::Notify,
    source: StorageSource,
    // Keep all retained backing charged through the last checkpoint/caller loan.
    _credit: StorageCredit,
}

/// Funded before the original native admission; only money may consume its reservation.
pub(crate) struct OrdinaryTerminalReservation {
    pub(super) signal: Arc<OrdinarySignal>,
}

impl OrdinaryTerminalReservation {
    pub(crate) fn reserve(source: &StorageSource) -> RecordStoreResult<Self> {
        let credit = source
            .try_reserve(Layout::new::<OrdinarySignal>().size())
            .map_err(|_| error("ordinary terminal completion capacity unavailable"))?;
        Ok(Self {
            signal: Arc::new(OrdinarySignal {
                state: Mutex::new(State {
                    accepted: None,
                    applied: None,
                    event_credit: None,
                }),
                changed: tokio::sync::Notify::new(),
                source: source.clone(),
                _credit: credit,
            }),
        })
    }
}

/// Move-only observation of the actual checkpoint's successful P/T/V/R completion.
/// It is not fee-debt Applied and cannot authorize selected delivery.
pub struct OrdinaryTerminalCompletion {
    signal: Arc<OrdinarySignal>,
}

impl OrdinaryTerminalCompletion {
    pub fn is_confirmed(&self, gov: &GovState) -> RecordStoreResult<bool> {
        let state = self
            .signal
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let accepted = state
            .accepted
            .as_ref()
            .ok_or_else(|| error("ordinary terminal not accepted"))?;
        if !Arc::ptr_eq(&accepted.book, &gov.unit_checkpoints.identity) {
            return Err(error(
                "ordinary terminal belongs to a different checkpoint book",
            ));
        }
        Ok(state.applied.is_some())
    }

    pub async fn wait(&self, gov: &GovState) -> RecordStoreResult<()> {
        loop {
            let changed = self.signal.changed.notified();
            if self.is_confirmed(gov)? {
                return Ok(());
            }
            changed.await;
        }
    }
}

impl OrdinarySignal {
    pub(super) fn accept(
        &self,
        gov: &GovState,
        snapshot: &UnitCheckpoint,
    ) -> RecordStoreResult<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.accepted.is_some() || !snapshot.ended || snapshot.partitions.is_some() {
            return Err(error(
                "ordinary terminal reservation already used or wrong mode",
            ));
        }
        state.accepted = Some(Accepted {
            book: gov.unit_checkpoints.identity.clone(),
            id: snapshot.id,
            unit: snapshot.unit,
            revision: snapshot.revision,
        });
        Ok(())
    }

    pub(super) fn fund_events(&self, events: &Vec<RecoveryEvent>) -> RecordStoreResult<()> {
        let bytes = events.iter().try_fold(
            Layout::array::<RecoveryEvent>(events.capacity())
                .map_err(|_| error("ordinary terminal event layout overflow"))?
                .size(),
            |sum, event| {
                sum.checked_add(event.payload.capacity())
                    .ok_or_else(|| error("ordinary terminal payload extent overflow"))
            },
        )?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state
            .event_credit
            .as_ref()
            .is_some_and(|credit| credit.len() >= bytes)
        {
            return Ok(());
        }
        let credit = self
            .source
            .try_reserve(bytes)
            .map_err(|_| error("ordinary terminal events remain unfunded"))?;
        state.event_credit = Some(credit);
        Ok(())
    }

    /// Only the successful original R branch calls this, after exact pending/source checks.
    pub(super) fn confirm(&self, snapshot: &mut UnitCheckpoint) -> RecordStoreResult<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let accepted = state
            .accepted
            .as_ref()
            .ok_or_else(|| error("ordinary terminal source absent"))?;
        if accepted.id != snapshot.id
            || accepted.unit != snapshot.unit
            || accepted.revision > snapshot.revision
            || snapshot.partitions.is_some()
            || !snapshot.ended
            || state.applied.is_some()
        {
            return Err(error("ordinary terminal acknowledgement source changed"));
        }
        let events = snapshot
            .terminal
            .as_ref()
            .ok_or_else(|| error("ordinary terminal operations not selected"))?;
        let bytes = events.iter().try_fold(
            Layout::array::<RecoveryEvent>(events.capacity())
                .map_err(|_| error("ordinary terminal layout overflow"))?
                .size(),
            |sum, event| {
                sum.checked_add(event.payload.capacity())
                    .ok_or_else(|| error("ordinary terminal extent overflow"))
            },
        )?;
        if state
            .event_credit
            .as_ref()
            .is_none_or(|credit| credit.len() < bytes)
        {
            return Err(error("ordinary terminal receipt backing not funded"));
        }
        state.applied = Some(Applied {
            revision: snapshot.revision,
            events: snapshot.terminal.take().expect("validated original events"),
        });
        drop(state);
        self.changed.notify_one();
        Ok(())
    }
}

impl GovState {
    pub(crate) fn finish_ordinary_checkpoint(
        &self,
        mut snapshot: UnitCheckpoint,
        reservation: &OrdinaryTerminalReservation,
    ) -> RecordStoreResult<OrdinaryTerminalCompletion> {
        if !self.unit_checkpoints_enabled() || snapshot.partitions.is_some() {
            return Err(error(
                "ordinary terminal requires original durable checkpoint custody",
            ));
        }
        let mut pending = self.unit_checkpoints.pending.lock();
        let previous = pending.get(&snapshot.id);
        if previous
            .is_some_and(|entry| entry.snapshot().ended || entry.snapshot().unit != snapshot.unit)
        {
            return Err(error("ordinary terminal already owned or source differs"));
        }
        snapshot.ended = true;
        snapshot.revision = match previous {
            Some(entry) => entry
                .snapshot()
                .revision
                .checked_add(1)
                .ok_or_else(|| error("ordinary terminal revision exhausted"))?,
            None => 0,
        };
        if snapshot.audit.is_none() {
            snapshot.audit = previous.and_then(|entry| entry.snapshot().audit.clone());
        }
        snapshot.validate()?;
        let persisted = previous.and_then(super::Pending::persisted);
        reservation.signal.accept(self, &snapshot)?;
        let entry = match self.apply_unit_checkpoint_live(&snapshot) {
            Ok(()) => super::Pending::terminal(snapshot, persisted),
            Err(_) => super::Pending::recovered(snapshot, persisted),
        }
        .with_ordinary_signal(reservation.signal.clone());
        pending.insert(entry.snapshot().id, entry);
        Ok(OrdinaryTerminalCompletion {
            signal: reservation.signal.clone(),
        })
    }
}
