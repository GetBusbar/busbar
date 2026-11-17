// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admission-bound response plans and exact native confirmation before terminal-byte release.
//! Owner approval: release !578 at e29f0e45, 2026-11-17T04:22:01.967Z. The general signer probe
//! remains in force; only the fixed ResponseIntent purpose is reachable here.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::persistence::Durability;
pub(crate) use busbar_contract::response_delivery::{FinalResponseIntent, ResponseDisposition};
use busbar_contract::response_delivery::{ResponseKey, ResponseStop};
use busbar_core_connector::response_delivery::{
    DeliveryCancel, DeliveryInput, DeliveryWatch, ReleasePublisher, ResponseHandles,
};
use busbar_kernel::persistence::journal::runtime::{Carried, RuntimeJournal, StagedRun};
use busbar_kernel_audit::response_intent::{
    is_response_intent, verify_response_intent, PreparedResponseIntent, ResponseIntentStamp,
};
use busbar_kernel_audit::AuditKeySet;
use busbar_kernel_wal::journal::{Entry, RecordClass};
use tokio::time::Instant;

use super::signer::{ResponseIntent, SignerHandle};

/// Validate matching historical records already read by boot under the verified persisted key.
/// This performs no journal scan and can never construct a live response or permit.
pub(crate) fn verify_history(
    book: &super::Durability,
    keys: &AuditKeySet,
) -> Result<(), FinalIntentError> {
    for record in &book.boot_records {
        if !is_response_intent(&record.body) {
            continue;
        }
        if record.class != RecordClass::Checkpoint {
            return Err(FinalIntentError::Integrity);
        }
        let header = ResponseIntentStamp {
            lease_epoch: record.lease_epoch,
            policy_epoch: record.policy_epoch,
            wall: record.wall,
            mono: record.mono,
        };
        verify_response_intent(&record.body, record.node, header, keys)
            .map_err(|_| FinalIntentError::Integrity)?;
    }
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// A content-free refusal to prepare, confirm or publish this response's final intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinalIntentError {
    Integrity,
    Capacity,
    Signer,
    Journal,
    Cancelled,
    Deadline,
}

impl From<ResponseStop> for FinalIntentError {
    fn from(reason: ResponseStop) -> Self {
        match reason {
            ResponseStop::Deadline => Self::Deadline,
            ResponseStop::Capacity => Self::Capacity,
            ResponseStop::Integrity => Self::Integrity,
            _ => Self::Cancelled,
        }
    }
}

impl std::fmt::Display for FinalIntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Integrity => "response intent identity or publication differs",
            Self::Capacity => "response intent admission capacity exhausted",
            Self::Signer => "response intent signature unavailable",
            Self::Journal => "response intent native confirmation unavailable",
            Self::Cancelled => "response intent cancelled",
            Self::Deadline => "response intent deadline expired",
        })
    }
}

impl std::error::Error for FinalIntentError {}

/// One root service for this actual journal incarnation, with one typed signer capability.
pub(crate) struct ResponseIntentService {
    journal: Arc<RuntimeJournal>,
    incarnation: u64,
    keys: AuditKeySet,
    signer: SignerHandle<ResponseIntent>,
    connection_generation: AtomicU64,
}

impl ResponseIntentService {
    pub(crate) fn journal(&self) -> &Arc<RuntimeJournal> {
        &self.journal
    }

    pub(crate) fn incarnation(&self) -> u64 {
        self.incarnation
    }

    /// Construct once from the actual bound book and authenticated retained verification keys.
    pub(crate) fn new(
        journal: Arc<RuntimeJournal>,
        incarnation: u64,
        keys: AuditKeySet,
        signer: SignerHandle<ResponseIntent>,
    ) -> Result<Arc<Self>, FinalIntentError> {
        let id = signer.key_id().map_err(|_| FinalIntentError::Signer)?;
        if keys.get(id).is_none() {
            return Err(FinalIntentError::Integrity);
        }
        Ok(Arc::new(Self {
            journal,
            incarnation,
            keys,
            signer,
            connection_generation: AtomicU64::new(0),
        }))
    }

    /// Allocate an actual root connection identity, never a process-global substitute incarnation.
    pub(crate) fn connection(self: &Arc<Self>) -> Result<ResponseConnection, FinalIntentError> {
        let previous = self
            .connection_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| FinalIntentError::Capacity)?;
        Ok(ResponseConnection {
            service: Arc::clone(self),
            generation: previous + 1,
            stream: AtomicU64::new(0),
        })
    }
}

/// A non-Clone root connection scope retained by its actual native connection owner.
pub(crate) struct ResponseConnection {
    service: Arc<ResponseIntentService>,
    generation: u64,
    stream: AtomicU64,
}

impl ResponseConnection {
    /// Bind a fresh host stream to its original actual unit, or explicitly admitted no-unit case.
    pub(crate) fn key(
        &self,
        stream: u64,
        unit: Option<busbar_contract::ids::UnitKey>,
    ) -> Result<ResponseKey, FinalIntentError> {
        if stream == 0 || unit.is_some_and(|unit| unit.get() == 0) {
            return Err(FinalIntentError::Integrity);
        }
        self.stream
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |previous| {
                (stream > previous).then_some(stream)
            })
            .map_err(|_| FinalIntentError::Integrity)?;
        Ok(ResponseKey {
            node: self.service.journal.node(),
            incarnation: self.service.incarnation,
            unit,
            connection_generation: self.generation,
            stream,
        })
    }

    /// Adopt the original acknowledged native handles before exposing output to this response.
    pub(crate) fn admit(
        &self,
        key: ResponseKey,
        handles: ResponseHandles,
        deadline: Instant,
    ) -> Result<(ResponsePlan, Arc<ResponseFinalizer>), FinalIntentError> {
        if key.node != self.service.journal.node()
            || key.incarnation != self.service.incarnation
            || key.connection_generation != self.generation
            || key.stream == 0
            || key.stream > self.stream.load(Ordering::Acquire)
            || handles.watch.key() != key
        {
            handles.cancel.cancel(ResponseStop::Integrity);
            // No response reader or producer was exposed. Cancellation still requires the
            // driver's real protocol/carrier join, but cannot await an input that never existed.
            handles.input.retired();
            return Err(FinalIntentError::Integrity);
        }
        let scope = Arc::new(ResponseScope {
            key,
            service: Arc::clone(&self.service),
            deadline,
            watch: handles.watch,
            input: handles.input,
            cancel: handles.cancel,
            publisher: handles.release,
            cancelled: AtomicBool::new(false),
            frozen: Mutex::new(None),
            state: tokio::sync::Mutex::new(FinalState::default()),
        });
        let plan = ResponsePlan {
            scope: Arc::clone(&scope),
            ordinal: 0,
            head: None,
            frozen: false,
        };
        Ok((plan, Arc::new(ResponseFinalizer { scope })))
    }
}

/// The sole response output owner's real publication plan; it is consumed by its terminal command.
pub(crate) struct ResponsePlan {
    scope: Arc<ResponseScope>,
    ordinal: u64,
    head: Option<Option<u16>>,
    frozen: bool,
}

impl ResponsePlan {
    fn next(&mut self) -> Result<(), FinalIntentError> {
        self.scope.check_live()?;
        self.ordinal = self
            .ordinal
            .checked_add(1)
            .ok_or(FinalIntentError::Capacity)?;
        Ok(())
    }

    /// Record the actual final head submission after response hooks and transforms.
    pub(crate) fn record_head(&mut self, status: Option<u16>) -> Result<(), FinalIntentError> {
        if self.head.is_some() {
            return Err(FinalIntentError::Integrity);
        }
        self.next()?;
        self.head = Some(status);
        Ok(())
    }

    /// Record each actual final body-frame submission, immediately before its queue wait.
    pub(crate) fn record_body(&mut self) -> Result<(), FinalIntentError> {
        self.next()
    }

    /// Record the actual final trailer submission, immediately before its queue wait.
    pub(crate) fn record_trailers(&mut self) -> Result<(), FinalIntentError> {
        self.next()
    }

    /// Freeze all output and reserve its real final operation ordinal before waiting on E_END.
    pub(crate) fn freeze(
        mut self,
        disposition: ResponseDisposition,
        stamp: ResponseIntentStamp,
    ) -> Result<FinalResponseIntent, FinalIntentError> {
        match disposition {
            ResponseDisposition::End { status } if self.head.flatten() != status => {
                return Err(FinalIntentError::Integrity)
            }
            ResponseDisposition::Refuse { head_sent, .. } if head_sent != self.head.is_some() => {
                return Err(FinalIntentError::Integrity)
            }
            _ => {}
        }
        self.next()?;
        let intent = FinalResponseIntent {
            key: self.scope.key,
            final_publication_ordinal: self.ordinal,
            disposition,
        };
        let key_id = self
            .scope
            .service
            .signer
            .key_id()
            .map_err(|_| FinalIntentError::Signer)?;
        let prepared = PreparedResponseIntent::new(intent, stamp, key_id)
            .map_err(|_| FinalIntentError::Integrity)?;
        let mut frozen = lock(&self.scope.frozen);
        if frozen.is_some() {
            return Err(FinalIntentError::Integrity);
        }
        self.scope
            .publisher
            .freeze(intent.key, intent.final_publication_ordinal)?;
        *frozen = Some(Frozen {
            intent,
            stamp,
            prepared,
        });
        self.frozen = true;
        Ok(intent)
    }
}

impl Drop for ResponsePlan {
    fn drop(&mut self) {
        if !self.frozen {
            self.scope.stop(ResponseStop::Cancelled);
        }
    }
}

struct Frozen {
    intent: FinalResponseIntent,
    stamp: ResponseIntentStamp,
    prepared: PreparedResponseIntent,
}

struct ResponseScope {
    key: ResponseKey,
    service: Arc<ResponseIntentService>,
    deadline: Instant,
    watch: DeliveryWatch,
    input: DeliveryInput,
    cancel: DeliveryCancel,
    publisher: ReleasePublisher,
    cancelled: AtomicBool,
    frozen: Mutex<Option<Frozen>>,
    state: tokio::sync::Mutex<FinalState>,
}

impl ResponseScope {
    fn check_live(&self) -> Result<(), FinalIntentError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(FinalIntentError::Cancelled);
        }
        if let Some(reason) = self.watch.cancellation() {
            return Err(reason.into());
        }
        if self.watch.snapshot().terminal.is_some() {
            return Err(FinalIntentError::Integrity);
        }
        if Instant::now() >= self.deadline {
            self.stop(ResponseStop::Deadline);
            return Err(FinalIntentError::Deadline);
        }
        Ok(())
    }

    fn stop(&self, reason: ResponseStop) {
        self.cancelled.store(true, Ordering::Release);
        self.cancel.cancel(reason);
    }
}

impl Drop for ResponseScope {
    fn drop(&mut self) {
        if !self.state.get_mut().published {
            self.cancel.cancel(ResponseStop::Cancelled);
        }
    }
}

#[derive(Default)]
struct FinalState {
    signature: Option<Vec<u8>>,
    run: Option<Arc<StagedRun>>,
    permit_issued: bool,
    published: bool,
}

/// Observation of the reserved control submission; neither case is a delivery receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleasePublication {
    Published,
    AlreadyPublished,
}

/// Root-private confirmation and publication authority retained by the native response supervisor.
pub(crate) struct ResponseFinalizer {
    scope: Arc<ResponseScope>,
}

// No Clone, Deserialize, Default, exposed fields or historical constructor.
struct ReleasePermit {
    owner: Arc<ResponseScope>,
    intent: FinalResponseIntent,
    carried: Carried,
    durability: Durability,
    consumed: bool,
}

impl Drop for ReleasePermit {
    fn drop(&mut self) {
        if !self.consumed {
            self.owner.stop(ResponseStop::Cancelled);
        }
    }
}

struct Waiter {
    owner: Arc<ResponseScope>,
    returned: bool,
}

impl Drop for Waiter {
    fn drop(&mut self) {
        if !self.returned {
            self.owner.stop(ResponseStop::Cancelled);
        }
    }
}

impl ResponseFinalizer {
    /// The immutable identity of this authentic admitted scope.
    pub(crate) fn key(&self) -> ResponseKey {
        self.scope.key
    }

    /// The original native read-side handle; this exposes no release authority.
    pub(crate) fn watch(&self) -> DeliveryWatch {
        self.scope.watch.clone()
    }

    /// The original input observer, retained through actual EOF and input retirement.
    pub(crate) fn input(&self) -> DeliveryInput {
        self.scope.input.clone()
    }

    /// The original cancellation endpoint; it never creates a terminal receipt.
    pub(crate) fn cancel(&self) -> DeliveryCancel {
        self.scope.cancel.clone()
    }

    /// The same journal used by this admitted node; it must match S9's captured stamp attachment.
    pub(crate) fn journal(&self) -> &Arc<RuntimeJournal> {
        &self.scope.service.journal
    }

    /// Confirm the frozen original and publish its one control, independently of held E_END.
    pub(crate) async fn finalize(
        &self,
        intent: FinalResponseIntent,
    ) -> Result<ReleasePublication, FinalIntentError> {
        let mut waiter = Waiter {
            owner: Arc::clone(&self.scope),
            returned: false,
        };
        let result =
            match tokio::time::timeout_at(self.scope.deadline, self.finalize_inner(intent)).await {
                Ok(result) => result,
                Err(_) => {
                    self.scope.stop(ResponseStop::Deadline);
                    Err(FinalIntentError::Deadline)
                }
            };
        waiter.returned = true;
        result
    }

    async fn finalize_inner(
        &self,
        intent: FinalResponseIntent,
    ) -> Result<ReleasePublication, FinalIntentError> {
        // This single driver lock survives in the scope across cancelled waiters and exact retries.
        let mut state = self.scope.state.lock().await;
        {
            let frozen = lock(&self.scope.frozen);
            if frozen.as_ref().map(|f| f.intent) != Some(intent) {
                return Err(FinalIntentError::Integrity);
            }
        }
        if state.published {
            return Ok(ReleasePublication::AlreadyPublished);
        }
        let permit = self.confirm_release_intent(intent, &mut state).await?;
        self.publish_release(permit, &mut state)?;
        Ok(ReleasePublication::Published)
    }

    async fn confirm_release_intent(
        &self,
        intent: FinalResponseIntent,
        state: &mut FinalState,
    ) -> Result<ReleasePermit, FinalIntentError> {
        self.scope.check_live()?;
        if state.permit_issued {
            return Err(FinalIntentError::Integrity);
        }
        if state.run.is_none() {
            if state.signature.is_none() {
                // A fixed stack copy avoids holding a synchronous lock across the signer wait.
                let prepared = {
                    let frozen = lock(&self.scope.frozen);
                    let frozen = frozen.as_ref().ok_or(FinalIntentError::Integrity)?;
                    PreparedResponseIntent::new(
                        frozen.intent,
                        frozen.stamp,
                        frozen.prepared.key_id(),
                    )
                    .map_err(|_| FinalIntentError::Integrity)?
                };
                let signature = self
                    .scope
                    .service
                    .signer
                    .sign_response_intent(&prepared)
                    .await
                    .map_err(|_| FinalIntentError::Signer)?;
                self.scope.check_live()?;
                state.signature = Some(signature);
            }
            let entry = {
                let frozen = lock(&self.scope.frozen);
                let frozen = frozen.as_ref().ok_or(FinalIntentError::Integrity)?;
                let signature = state
                    .signature
                    .as_deref()
                    .ok_or(FinalIntentError::Integrity)?;
                let body = frozen
                    .prepared
                    .signed_body(signature)
                    .map_err(|_| FinalIntentError::Signer)?;
                let verified = verify_response_intent(
                    &body,
                    self.scope.key.node,
                    frozen.stamp,
                    &self.scope.service.keys,
                )
                .map_err(|_| FinalIntentError::Signer)?;
                if verified.map(|record| record.intent) != Some(intent) {
                    return Err(FinalIntentError::Integrity);
                }
                Entry::new(RecordClass::Checkpoint, body)
                    .under(frozen.stamp.lease_epoch, frozen.stamp.policy_epoch)
                    .at(frozen.stamp.wall, frozen.stamp.mono)
            };
            self.scope.check_live()?;
            // No asynchronous crossing between staging and installing the exact retained original.
            state.run = Some(
                self.scope
                    .service
                    .journal
                    .stage_run(&[entry])
                    .map_err(|_| FinalIntentError::Journal)?,
            );
            state.signature = None;
        }
        let run = state.run.as_ref().ok_or(FinalIntentError::Integrity)?;
        self.scope
            .service
            .journal
            .confirm(run)
            .await
            .map_err(|_| FinalIntentError::Journal)?;
        self.scope.check_live()?;
        let carried = run.carried().next().ok_or(FinalIntentError::Integrity)?;
        if run.records().len() != 1 {
            return Err(FinalIntentError::Integrity);
        }
        state.permit_issued = true;
        Ok(ReleasePermit {
            owner: Arc::clone(&self.scope),
            intent,
            carried,
            durability: self.scope.service.journal.durability(),
            consumed: false,
        })
    }

    fn publish_release(
        &self,
        mut permit: ReleasePermit,
        state: &mut FinalState,
    ) -> Result<(), FinalIntentError> {
        self.scope.check_live()?;
        let run = state.run.as_ref().ok_or(FinalIntentError::Integrity)?;
        if !Arc::ptr_eq(&permit.owner, &self.scope)
            || permit.intent.key != self.scope.key
            || run.carried().next() != Some(permit.carried)
            || !self
                .scope
                .service
                .journal
                .is_confirmed(run)
                .map_err(|_| FinalIntentError::Journal)?
            || permit.durability != self.scope.service.journal.durability()
            || state.published
        {
            return Err(FinalIntentError::Integrity);
        }
        self.scope
            .publisher
            .publish(permit.intent.key, permit.intent.final_publication_ordinal)?;
        state.published = true;
        permit.consumed = true;
        Ok(())
    }
}
