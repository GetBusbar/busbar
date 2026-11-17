// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One leased reader per retained terminal entry. The existing flush tick signals changes;
//! cancellation releases only the waiter, never the book's factual custody or reader gate.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::{error, partitions, GovState, RecordStoreResult, UnitCheckpoint};

#[derive(Default)]
pub(super) struct TerminalSignal {
    pub(super) changed: tokio::sync::Notify,
    pub(super) claimed: AtomicBool,
}

impl TerminalSignal {
    pub(super) fn notify(&self) {
        // A retained permit covers resolution before the single reader starts waiting.
        self.changed.notify_one();
    }
}

/// A single final-reader lease minted from accepted terminal custody. Retains the exact final
/// Arc after delivery so the existing audit confirmation can retry without rereading live money.
pub struct SelectedTerminalCompletion {
    id: [u8; 16],
    book: Arc<()>,
    signal: Arc<TerminalSignal>,
    ready: Option<Arc<UnitCheckpoint>>,
}

impl Drop for SelectedTerminalCompletion {
    fn drop(&mut self) {
        self.signal.claimed.store(false, Ordering::Release);
    }
}

impl SelectedTerminalCompletion {
    /// Wait for the exact resolved revision. A cancelled future or an error retains book
    /// custody; this handle can be retried. Dropping it permits a replacement reader lease.
    pub async fn wait(&mut self, gov: &GovState) -> RecordStoreResult<Arc<UnitCheckpoint>> {
        if !Arc::ptr_eq(&self.book, &gov.unit_checkpoints.identity) {
            return Err(error(
                "selected terminal completion belongs to a different book",
            ));
        }
        if let Some(ready) = &self.ready {
            return Ok(ready.clone());
        }
        let signal = self.signal.clone();
        loop {
            // Register before reading readiness. notify_one retains a permit even if this
            // future has not yet been polled, so resolution between read and await is covered.
            let changed = signal.changed.notified();
            {
                let mut pending = gov.unit_checkpoints.pending.lock();
                let entry = pending.edit(&self.id).ok_or_else(|| {
                    error("selected terminal completion no longer has retained custody")
                })?;
                if !entry.awaiting_terminal_reader()
                    || !entry.matches_terminal_signal(Some(&signal))
                {
                    return Err(error(
                        "selected terminal completion lease no longer owns its reader",
                    ));
                }
            }
            if let Some(ready) = gov.take_selected_terminal_snapshot_for(self.id, Some(&signal))? {
                self.ready = Some(ready.clone());
                return Ok(ready);
            }
            changed.await;
        }
    }
}

impl GovState {
    /// Attach one waiter to an already accepted terminal revision. A fee/vector successor is
    /// allowed; changed source or identity facts cannot mint a reader from another snapshot.
    pub fn selected_terminal_completion(
        &self,
        accepted: &Arc<UnitCheckpoint>,
    ) -> RecordStoreResult<SelectedTerminalCompletion> {
        let mut pending = self.unit_checkpoints.pending.lock();
        let mut entry = pending.edit(&accepted.id).ok_or_else(|| {
            error("selected terminal completion requires retained accepted custody")
        })?;
        let current = entry.snapshot();
        if !accepted.ended
            || accepted.partitions.is_none()
            || !current.ended
            || !entry.awaiting_terminal_reader()
            || accepted.revision > current.revision
        {
            return Err(error(
                "selected terminal completion is not an accepted terminal revision",
            ));
        }
        if current != accepted.as_ref() {
            partitions::validate_successor(accepted, current)?;
        }
        let signal = entry.terminal_signal();
        signal
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| error("selected terminal completion already has a reader"))?;
        Ok(SelectedTerminalCompletion {
            id: accepted.id,
            book: self.unit_checkpoints.identity.clone(),
            signal,
            ready: None,
        })
    }
}
