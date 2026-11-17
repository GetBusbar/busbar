// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owned selected preparation and the exact connector handoff. No descriptive request mints these owners.

use std::sync::Arc;

use super::super::port_admission::Pending;
use super::super::port_session::PreparedExchange;
use super::super::port_upstream::{Candidate, SendFailed, UpOpen};
use super::super::{NativeAttempt, NativeCommitError, NativeRequestMoney, PreparedRateAttempt};
use crate::governance::selected_resource::{RateRefusalKind, RateRejected, RateReservation};
use crate::state::{SelectedCommitRejected, SelectedRateRejected};

/// Opaque ownership passed to an opted-in sender. There is no borrowed-send fallback.
pub struct OwnedPreparation {
    pub(super) prepared: PreparedExchange,
    pub(super) data: Option<Arc<crate::auth::native_data::NativeDataPending>>,
}

impl OwnedPreparation {
    pub(crate) fn new(
        prepared: PreparedExchange,
        data: Option<Arc<crate::auth::native_data::NativeDataPending>>,
    ) -> Self {
        Self { prepared, data }
    }
}

/// The committed guard is returned even if the connector or its first response failed.
pub struct SelectedOpen<'a> {
    pub(crate) opened: Result<UpOpen<'a>, SendFailed>,
    pub(crate) attempt: NativeAttempt,
}

/// Only the actual eligible walk can construct this linear handoff owner.
pub struct SelectedHandoff {
    pending: Arc<Pending>,
    reservation: Option<RateReservation>,
    committed: Option<NativeAttempt>,
    target: Candidate,
}

impl SelectedHandoff {
    pub(super) fn new(
        pending: Arc<Pending>,
        prepared: PreparedRateAttempt,
    ) -> Result<Self, SendFailed> {
        let target = prepared.selection().target().clone();
        let money = pending
            .admitted()
            .and_then(|unit| unit.selected.as_ref())
            .ok_or(SendFailed)?;
        let Some(rates) = pending.current_rates() else {
            let _ = money.no_send(prepared);
            return Err(SendFailed);
        };
        let reservation = match rates.reserve(prepared) {
            Ok(reservation) => reservation,
            Err(SelectedRateRejected::Policy { prepared, .. }) => {
                let _ = money.no_send(prepared);
                return Err(SendFailed);
            }
            Err(SelectedRateRejected::Rate(rejected)) => {
                let _ = money.no_send(rejected.prepared);
                return Err(SendFailed);
            }
        };
        Ok(Self {
            pending,
            reservation: Some(reservation),
            committed: None,
            target,
        })
    }

    pub(super) fn exchange(&self) -> Option<&super::super::port_session::UpExchange> {
        self.reservation
            .as_ref()
            .map(|held| held.prepared().exchange())
    }

    pub(crate) fn accepts_request(&self, request: &super::super::route::OutboundRequest) -> bool {
        self.exchange()
            .and_then(|exchange| {
                super::request_of(
                    &self.target.qualified_member,
                    &self.target.pool,
                    request.attempt_no,
                    exchange,
                )
            })
            .as_ref()
            == Some(request)
    }

    pub(crate) fn accepts(&self, pool: &str, member: &str, unit: busbar_contract::UnitKey) -> bool {
        self.target.pool.as_ref() == pool
            && self.target.qualified_member.as_ref() == member
            && self.pending.admitted().is_some_and(|admitted| {
                admitted.request.unit() == unit && admitted.request.is_live()
            })
    }

    /// Called after auth and local validation, immediately before connector open.
    pub(crate) fn commit(&mut self) -> bool {
        let pending = Arc::clone(&self.pending);
        let Some(money) = pending.admitted().and_then(|unit| unit.selected.as_ref()) else {
            return false;
        };
        let Some(rates) = pending.current_rates() else {
            return false;
        };
        loop {
            let Some(reservation) = self.reservation.take() else {
                return false;
            };
            if !money.request().is_live()
                || reservation.prepared().data().is_some_and(|data| {
                    !data.is_live()
                        || data
                            .execution()
                            .is_none_or(|proof| proof.binding().check_executing().is_err())
                })
            {
                let _ = money.no_send(reservation.cancel());
                return false;
            }
            match rates.commit(money, reservation) {
                Ok(attempt) => {
                    self.committed = Some(attempt);
                    return true;
                }
                Err(SelectedCommitRejected::Policy { prepared, .. }) => {
                    let _ = money.no_send(prepared);
                    return false;
                }
                Err(SelectedCommitRejected::Rate(rejected))
                | Err(SelectedCommitRejected::Money(NativeCommitError::Rate(rejected))) => {
                    if !self.retry_expired(money, rejected) {
                        return false;
                    }
                }
                Err(SelectedCommitRejected::Money(NativeCommitError::Before {
                    reservation,
                    ..
                })) => {
                    let _ = money.no_send(reservation.cancel());
                    return false;
                }
            }
        }
    }

    fn retry_expired(&mut self, money: &NativeRequestMoney, rejected: RateRejected) -> bool {
        if rejected.reason.kind != RateRefusalKind::ExpiredReservation || !money.request().is_live()
        {
            let _ = money.no_send(rejected.prepared);
            return false;
        }
        let Some(rates) = self.pending.current_rates() else {
            let _ = money.no_send(rejected.prepared);
            return false;
        };
        match rates.reserve(rejected.prepared) {
            Ok(reservation) => {
                self.reservation = Some(reservation);
                true
            }
            Err(SelectedRateRejected::Policy { prepared, .. }) => {
                let _ = money.no_send(prepared);
                false
            }
            Err(SelectedRateRejected::Rate(rejected)) => {
                let _ = money.no_send(rejected.prepared);
                false
            }
        }
    }

    pub(super) fn take_committed(&mut self) -> Option<NativeAttempt> {
        self.committed.take()
    }
}

impl Drop for SelectedHandoff {
    fn drop(&mut self) {
        if let Some(reservation) = self.reservation.take() {
            if let Some(money) = self
                .pending
                .admitted()
                .and_then(|unit| unit.selected.as_ref())
            {
                let _ = money.no_send(reservation.cancel());
            }
        }
    }
}
