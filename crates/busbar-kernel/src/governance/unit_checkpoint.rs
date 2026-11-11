// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Running unit custody. Reports replace a hot snapshot; only the existing usage flush tick
//! writes it. A terminal snapshot owns exact raw operation identities until their durable ACKs.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use busbar_contract::Count;
use busbar_kernel_ledger::cost::{EntryId, RawRateEra};
use serde::{Deserialize, Serialize};

use super::recovery::{RecoveryEvent, RecoveryState};
use super::{GovState, RecordStoreError, RecordStoreResult};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitTarget {
    pub bucket: String,
    pub window: u64,
    pub group: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitCheckpoint {
    pub id: [u8; 16],
    pub revision: u64,
    pub unit: u64,
    pub principal: String,
    pub group: String,
    pub arrived: u64,
    pub lane: String,
    pub provider: Option<String>,
    pub era_at: u64,
    pub era_entry: Option<[u8; 12]>,
    pub units: BTreeMap<String, Count>,
    pub targets: Vec<UnitTarget>,
    pub metered: bool,
    pub ended: bool,
    pub terminal: Option<Vec<RecoveryEvent>>,
    pub audit: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement: Option<crate::host_measurement::MeasurementEvidence>,
}

impl UnitCheckpoint {
    pub fn validate(&self) -> RecordStoreResult<()> {
        if let Some(evidence) = &self.measurement {
            evidence
                .validate(self)
                .map_err(|_| error("invalid host measurement origin"))?;
        }
        if self.principal.is_empty()
            || self
                .units
                .iter()
                .any(|(class, count)| class.is_empty() || count.is_negative())
        {
            return Err(error("invalid running money principal or quantity"));
        }
        let mut targets = std::collections::BTreeSet::new();
        if self.targets.iter().any(|target| {
            target.bucket.is_empty() || !targets.insert((&target.bucket, target.window))
        }) {
            return Err(error("duplicate or empty running money target"));
        }
        if let Some(events) = &self.terminal {
            if !self.ended {
                return Err(error("running checkpoint contains terminal operations"));
            }
            let mut operations = std::collections::BTreeSet::new();
            for event in events {
                event.follows(None).map_err(error)?;
                if !operations.insert(event.operation_id) {
                    return Err(error("duplicate unit terminal operation"));
                }
            }
        }
        Ok(())
    }

    pub fn era(&self) -> RawRateEra {
        RawRateEra {
            effective_from: self.era_at,
            entry_id: self.era_entry.map(EntryId),
        }
    }
}

/// The root implements this with kernel-owned named Store slots and journal evidence.
#[async_trait::async_trait]
pub trait UnitCheckpointSink: Send + Sync {
    async fn persist(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()>;
    async fn remove(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()>;
    async fn replay(&self) -> RecordStoreResult<Vec<UnitCheckpoint>>;
    async fn recover_audit(&self, _snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct UnitCheckpointBook {
    sink: OnceLock<Arc<dyn UnitCheckpointSink>>,
    pending: Mutex<BTreeMap<[u8; 16], Pending>>,
    flushing: tokio::sync::Mutex<()>,
}

struct Pending {
    snapshot: UnitCheckpoint,
    persisted: Option<u64>,
    recovered: bool,
}

fn error(message: impl ToString) -> RecordStoreError {
    RecordStoreError(message.to_string())
}

impl GovState {
    /// Bind after usage recovery is attached and before admitting any units. A recovered running
    /// unit ends at its last confirmed report, without reconstructing an admission or a fee.
    pub async fn attach_unit_checkpoint_sink(
        &self,
        sink: Arc<dyn UnitCheckpointSink>,
    ) -> RecordStoreResult<()> {
        if !self.recovery_enabled() {
            return Err(error("running unit custody requires usage recovery"));
        }
        let recovered = sink.replay().await?;
        for snapshot in &recovered {
            snapshot.validate()?;
            sink.recover_audit(snapshot).await?;
        }
        self.unit_checkpoints
            .sink
            .set(sink)
            .map_err(|_| error("unit checkpoint sink already attached"))?;
        {
            let mut pending = self
                .unit_checkpoints
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            for mut snapshot in recovered {
                let persisted = Some(snapshot.revision);
                if !snapshot.ended {
                    snapshot.ended = true;
                    snapshot.revision = snapshot
                        .revision
                        .checked_add(1)
                        .ok_or_else(|| error("unit checkpoint revision exhausted"))?;
                }
                if pending
                    .insert(
                        snapshot.id,
                        Pending {
                            snapshot,
                            persisted,
                            recovered: true,
                        },
                    )
                    .is_some()
                {
                    return Err(error("duplicate running unit checkpoint"));
                }
            }
        }
        if let Err(failed) = self.flush_unit_checkpoints().await {
            let pending = self
                .unit_checkpoints
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let owned = pending.values().all(|entry| {
                entry.persisted == Some(entry.snapshot.revision)
                    && entry.snapshot.terminal.as_ref().is_some_and(|events| {
                        events
                            .iter()
                            .all(|event| self.recovery_event(event.operation_id).is_some())
                    })
            });
            if !owned {
                return Err(failed);
            }
            tracing::warn!(error = %failed, "recovered unit targets remain admission-blocked while durable usage custody awaits resolution");
        }
        Ok(())
    }

    pub(super) fn unresolved_unit_target(&self, bucket: &str, window: u64) -> bool {
        self.unit_checkpoints
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .any(|entry| {
                entry.recovered
                    && entry
                        .snapshot
                        .targets
                        .iter()
                        .any(|target| target.bucket == bucket && target.window == window)
            })
    }

    /// Synchronous shutdown barrier: reports and an active native flush retain
    /// custody even when no RPC is currently being polled.
    pub(super) fn has_unsettled_unit_checkpoints(&self) -> bool {
        !self
            .unit_checkpoints
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty()
            || self.unit_checkpoints.flushing.try_lock().is_err()
    }

    pub(crate) fn unit_checkpoint_pending(&self, id: &[u8; 16]) -> bool {
        self.unit_checkpoints
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(id)
    }

    pub fn unit_checkpoints_enabled(&self) -> bool {
        self.unit_checkpoints.sink.get().is_some()
    }

    /// No Store call occurs on a report, including a streamed piece.
    pub fn stage_unit_checkpoint(&self, mut snapshot: UnitCheckpoint) {
        if !self.unit_checkpoints_enabled() {
            return;
        }
        let mut pending = self
            .unit_checkpoints
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match pending.get_mut(&snapshot.id) {
            Some(previous) if !previous.snapshot.ended => {
                // Exhaustion fails closed by keeping the last checkpoint; never wrap its identity.
                let Some(next) = previous.snapshot.revision.checked_add(1) else {
                    return;
                };
                snapshot.revision = next;
                previous.snapshot = snapshot;
            }
            Some(_) => {}
            None => {
                pending.insert(
                    snapshot.id,
                    Pending {
                        snapshot,
                        persisted: None,
                        recovered: false,
                    },
                );
            }
        }
    }

    /// Returns true when durable unit custody owns this bill. The caller must then bypass the
    /// ordinary write-behind bill, whose independently generated operation IDs would duplicate it.
    pub fn finish_unit_checkpoint(&self, mut snapshot: UnitCheckpoint) -> bool {
        if !self.unit_checkpoints_enabled() {
            return false;
        }
        snapshot.ended = true;
        let mut pending = self
            .unit_checkpoints
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if pending.get(&snapshot.id).is_some_and(|p| p.snapshot.ended) {
            return true;
        }
        snapshot.revision = pending
            .get(&snapshot.id)
            .map_or(0, |p| p.snapshot.revision.saturating_add(1));
        if snapshot.audit.is_none() {
            snapshot.audit = pending
                .get(&snapshot.id)
                .and_then(|p| p.snapshot.audit.clone());
        }
        let mut recovered = false;
        if let Err(failed) = self.apply_unit_checkpoint_live(&snapshot) {
            recovered = true;
            tracing::error!(unit = snapshot.unit, error = %failed,
                "terminal unit hot accounting failed; exact durable custody retained");
        }
        let persisted = pending.get(&snapshot.id).and_then(|p| p.persisted);
        pending.insert(
            snapshot.id,
            Pending {
                snapshot,
                persisted,
                recovered,
            },
        );
        true
    }

    /// Called by the existing usage flusher, including its final shutdown pass.
    pub async fn flush_unit_checkpoints(&self) -> RecordStoreResult<()> {
        let Some(sink) = self.unit_checkpoints.sink.get() else {
            return Ok(());
        };
        let _flush = self.unit_checkpoints.flushing.lock().await;
        let ids: Vec<_> = self
            .unit_checkpoints
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .copied()
            .collect();
        let mut first_error = None;
        for id in ids {
            if let Err(failed) = self.flush_unit_checkpoint(sink.as_ref(), id).await {
                tracing::warn!(checkpoint = %hex::encode(id), error = %failed,
                    "running money checkpoint remains unresolved and will retry");
                first_error.get_or_insert(failed);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn flush_unit_checkpoint(
        &self,
        sink: &dyn UnitCheckpointSink,
        id: [u8; 16],
    ) -> RecordStoreResult<()> {
        let (snapshot, persisted, recovered) = {
            let mut pending = self
                .unit_checkpoints
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let Some(entry) = pending.get_mut(&id) else {
                return Ok(());
            };
            entry.snapshot.validate()?;
            if entry.snapshot.ended && entry.snapshot.terminal.is_none() {
                entry.snapshot.terminal = Some(self.unit_terminal_events(&entry.snapshot)?);
                entry.snapshot.revision = entry
                    .snapshot
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| error("unit checkpoint revision exhausted"))?;
            }
            (entry.snapshot.clone(), entry.persisted, entry.recovered)
        };
        if persisted != Some(snapshot.revision) {
            sink.persist(&snapshot).await?;
            if let Some(entry) = self
                .unit_checkpoints
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get_mut(&id)
            {
                entry.persisted = Some(snapshot.revision);
            }
        }
        let Some(events) = &snapshot.terminal else {
            return Ok(());
        };
        for initial in events {
            self.restore_unit_terminal_receipt(initial).await?;
            if self.recovery_event(initial.operation_id).is_none() {
                self.keep_recovery_event(initial).await?;
            } else if self.recovery_initial_event(initial.operation_id).as_ref() != Some(initial) {
                return Err(error(
                    "terminal unit operation identity differs from recovery custody",
                ));
            }
        }
        // Select every exact terminal operation before driving any. One ambiguous operation must
        // not strand its siblings without durable custody or hide the operator recovery surface.
        let mut first_error = None;
        for initial in events {
            if let Err(failed) = self.drive_raw_recovery(initial.operation_id).await {
                first_error.get_or_insert(failed);
            }
            if !self
                .recovery_event(initial.operation_id)
                .is_some_and(|e| e.state == RecoveryState::Settled)
            {
                first_error.get_or_insert_with(|| {
                    error("terminal unit awaits durable recovery acknowledgement")
                });
            }
        }
        if let Some(failed) = first_error {
            return Err(failed);
        }
        if recovered {
            self.refresh_recovered_unit_targets(&snapshot).await?;
        }
        sink.remove(&snapshot).await?;
        self.unit_checkpoints
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&id);
        for event in events {
            self.forget_confirmed_recovery(event.operation_id);
        }
        Ok(())
    }
}
