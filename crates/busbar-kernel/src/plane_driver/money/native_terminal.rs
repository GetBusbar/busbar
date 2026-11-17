// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One terminal result carrier from the actual selected Open to its retained response owner.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::{
    locked,
    native_attempt::{NativeAttemptError, NativeRequestMoney},
    NativeAdmissionError, PlaneMoney,
};
use crate::governance::unit_checkpoint::{
    SelectedTerminalCompletion, SelectedTransfer, UnitCheckpoint,
};
use crate::governance::GovState;
use crate::plane_driver::request_admission::AdmittedRequest;
use busbar_contract::records::{RecordStoreError, RecordStoreResult};

pub(super) enum NativeTerminal {
    Ready(Arc<UnitCheckpoint>),
    Pending {
        accepted: Arc<UnitCheckpoint>,
        gov: Arc<GovState>,
        completion: Option<SelectedTerminalCompletion>,
    },
}

impl NativeTerminal {
    async fn wait(&mut self) -> RecordStoreResult<Arc<UnitCheckpoint>> {
        match self {
            Self::Ready(snapshot) => Ok(snapshot.clone()),
            Self::Pending {
                accepted,
                gov,
                completion,
            } => {
                if completion.is_none() {
                    *completion = Some(gov.selected_terminal_completion(accepted)?);
                }
                completion
                    .as_mut()
                    .expect("completion installed")
                    .wait(gov)
                    .await
            }
        }
    }
}

pub(super) struct TerminalSlot {
    id: [u8; 16],
    claimed: AtomicBool,
    published: AtomicBool,
    value: Mutex<Option<Result<NativeTerminal, String>>>,
    changed: tokio::sync::Notify,
}

impl TerminalSlot {
    pub(super) fn new(snapshot: &UnitCheckpoint) -> Arc<Self> {
        Arc::new(Self {
            id: snapshot.id,
            claimed: AtomicBool::new(false),
            published: AtomicBool::new(false),
            value: Mutex::new(None),
            changed: tokio::sync::Notify::new(),
        })
    }
    pub(super) fn publish(&self, terminal: Result<NativeTerminal, String>) {
        if self
            .published
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            *locked(&self.value) = Some(terminal);
            self.changed.notify_one();
        }
    }
}

/// One response-owned reader for the actual selected admission. Dropping/replacing a reader
/// retains its result and the book's fee/final-vector custody; no numeric-unit lookup mints it.
pub struct SelectedTerminalReceipt {
    slot: Arc<TerminalSlot>,
    terminal: Option<Result<NativeTerminal, String>>,
}

impl SelectedTerminalReceipt {
    pub async fn wait(&mut self) -> RecordStoreResult<Arc<UnitCheckpoint>> {
        while self.terminal.is_none() {
            let changed = self.slot.changed.notified();
            self.terminal = locked(&self.slot.value).take();
            if self.terminal.is_none() {
                changed.await;
            }
        }
        match self.terminal.as_mut().expect("terminal transferred") {
            Ok(terminal) => terminal.wait().await,
            Err(error) => Err(RecordStoreError(error.clone())),
        }
    }
}

impl Drop for SelectedTerminalReceipt {
    fn drop(&mut self) {
        if let Some(terminal) = self.terminal.take() {
            *locked(&self.slot.value) = Some(terminal);
        }
        self.slot.claimed.store(false, Ordering::Release);
    }
}

impl NativeRequestMoney {
    pub(crate) fn work_ended(
        &self,
        ending: crate::plane_driver::usage::Ending,
    ) -> Result<(), NativeAttemptError> {
        use crate::plane_driver::usage::Ending;
        let mut all = self.money.shard(self.request.unit());
        let open = all
            .get_mut(&self.request.unit())
            .ok_or(NativeAttemptError::Unavailable)?;
        self.check_open_identity(open)?;
        let native = open
            .native
            .as_mut()
            .ok_or(NativeAttemptError::Unavailable)?;
        match native.work {
            Some(Ending::End) => Ok(()),
            Some(previous) if previous == ending => Ok(()),
            Some(_) => Err(NativeAttemptError::Binding),
            None => {
                native.work = Some(ending);
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn work_ending(
        &self,
    ) -> Result<Option<crate::plane_driver::usage::Ending>, NativeAttemptError> {
        let all = self.money.shard(self.request.unit());
        let open = all
            .get(&self.request.unit())
            .ok_or(NativeAttemptError::Unavailable)?;
        self.check_open_identity(open)?;
        Ok(open
            .native
            .as_ref()
            .ok_or(NativeAttemptError::Unavailable)?
            .work)
    }

    pub fn terminal_receipt(&self) -> Result<SelectedTerminalReceipt, NativeAdmissionError> {
        self.terminal
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| NativeAdmissionError::Occupied)?;
        Ok(SelectedTerminalReceipt {
            slot: self.terminal.clone(),
            terminal: None,
        })
    }
}

impl PlaneMoney {
    /// The callback guard proves no Task effect or connector attempt has started. Transfer its
    /// empty failed terminal before consuming the original fee participant outside money locks.
    pub(super) fn abort_selected_startup(
        &self,
        request: &AdmittedRequest,
        slot: &Arc<TerminalSlot>,
    ) -> Result<(), NativeAttemptError> {
        use crate::governance::unit_checkpoint::partitions::Disposition;
        let (mut removed, terminal) = {
            let mut all = self.shard(request.unit());
            let open = all
                .get_mut(&request.unit())
                .ok_or(NativeAttemptError::Unavailable)?;
            if !request.matches_money_identity(
                &self.book,
                &open.identity,
                open.grant.as_ref().ok_or(NativeAttemptError::Unavailable)?,
            ) || !request.matches_governance(&self.gov)
            {
                return Err(NativeAttemptError::Binding);
            }
            let native = open
                .native
                .as_ref()
                .ok_or(NativeAttemptError::Unavailable)?;
            if native.work.is_some()
                || !Arc::ptr_eq(&native.terminal, slot)
                || native.checkpoint().id != slot.id
            {
                return Err(NativeAttemptError::Binding);
            }
            let mut snapshot = native.checkpoint().as_ref().clone();
            let expected = native.accepted_revision();
            let parts = snapshot
                .partitions
                .as_mut()
                .ok_or(NativeAttemptError::Binding)?;
            if parts.disposition != Disposition::Running
                || !parts.attempts.is_empty()
                || parts.session.is_some()
                || parts.far_end_answered
                || parts.caller_bytes_committed
                || parts.final_target.is_some()
                || open.last.iter().any(|count| count.amount != 0)
            {
                return Err(NativeAttemptError::Binding);
            }
            parts.disposition = Disposition::Failed;
            let (fee, completion) = open.fee.selected_fee();
            parts.fee = fee;
            snapshot.ended = true;
            snapshot.metered = false;
            let terminal = match self.gov.finish_selected_checkpoint_with_fee(
                snapshot,
                Some(expected),
                completion,
            ) {
                SelectedTransfer::Applied(snapshot) => NativeTerminal::Ready(snapshot),
                SelectedTransfer::RetainedPending(accepted) => NativeTerminal::Pending {
                    accepted,
                    gov: self.gov.clone(),
                    completion: None,
                },
                SelectedTransfer::RejectedNotOwned { error, .. } => {
                    return Err(NativeAttemptError::Custody(error))
                }
            };
            (
                all.remove(&request.unit())
                    .expect("checked exact open under shard"),
                terminal,
            )
        };
        self.gov.release_request(&removed.money.charge);
        removed.fee.refundable = true;
        drop(removed); // Resolves the actual fee account; observer cannot retain participation.
        slot.publish(Ok(terminal));
        Ok(())
    }
}
