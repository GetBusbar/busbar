// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admission-bound response plans and the one release of each response's terminal byte.
//!
//! Design 2 (owner, 18 Nov: "Off the path, wait_for_commit OFF by default"): no response signs,
//! and no ordinary response waits for a commit. The final response intent of release !578 (a
//! signed record, durably confirmed before every response's last byte) is retired: what a response
//! records is decided once, at registration ([`ResponseRecord`]):
//! - nothing, for a response with no principal, no usage and no decision of its own (a health
//!   check), or one whose unit's own line already records it;
//! - a count per (listener, reason) on its core, for a refusal of a request that has no identity;
//! - under `advanced.wait_for_commit`, a metered response's line on its core's outbox, and the
//!   release waits for the group commit that holds it.
//!
//! Records the retired intent wrote (`response.final-intent.v1`, each signed singly) keep
//! verifying by their own rule at boot ([`verify_history`]).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::caps::{ReasonCode, StepName};
pub(crate) use busbar_contract::response_delivery::{FinalResponseIntent, ResponseDisposition};
use busbar_contract::response_delivery::{ResponseKey, ResponseStop};
use busbar_core_connector::response_delivery::{
    DeliveryCancel, DeliveryInput, DeliveryWatch, ReleasePublisher, ResponseHandles,
};
use busbar_kernel::persistence::journal::runtime::RuntimeJournal;
use busbar_kernel_audit::response_intent::{
    is_response_intent, verify_response_intent, ResponseIntentStamp,
};
use busbar_kernel_audit::{AuditInputs, AuditKeySet};
use busbar_kernel_wal::journal::RecordClass;
use tokio::time::Instant;

use super::core_audit::CoreAudit;

/// Validate the retired intent records (version 1, signed singly) already read by boot under the
/// verified persisted key. This performs no journal scan and can never construct a live response.
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

/// A content-free refusal to prepare or publish this response's release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinalIntentError {
    Integrity,
    Capacity,
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
            Self::Integrity => "response identity or publication differs",
            Self::Capacity => "response admission capacity exhausted",
            Self::Cancelled => "response cancelled",
            Self::Deadline => "response deadline expired",
        })
    }
}

impl std::error::Error for FinalIntentError {}

/// WHAT A RESPONSE RECORDS, decided once at registration from its authority (design 2, A5, A7).
pub(crate) enum ResponseRecord {
    /// Nothing: no principal, no usage and no decision of its own, or its unit's own line records it.
    Nothing,
    /// A refusal of a request with no identity: one count on its core for (listener, step, reason).
    Counted {
        listener: Arc<str>,
        step: StepName,
        reason: ReasonCode,
    },
    /// `advanced.wait_for_commit`: this line goes to the core's outbox and the release waits for
    /// the group commit that holds it.
    Committed(Box<AuditInputs>),
}

/// One root service for this actual journal incarnation: response identities only.
pub(crate) struct ResponseIntentService {
    journal: Arc<RuntimeJournal>,
    incarnation: u64,
    connection_generation: AtomicU64,
}

impl ResponseIntentService {
    pub(crate) fn journal(&self) -> &Arc<RuntimeJournal> {
        &self.journal
    }

    pub(crate) fn incarnation(&self) -> u64 {
        self.incarnation
    }

    /// Construct once from the actual bound book.
    pub(crate) fn new(journal: Arc<RuntimeJournal>, incarnation: u64) -> Arc<Self> {
        Arc::new(Self {
            journal,
            incarnation,
            connection_generation: AtomicU64::new(0),
        })
    }

    /// Allocate an actual root connection identity on the core whose audit state `core` is.
    pub(crate) fn connection(
        self: &Arc<Self>,
        core: Arc<CoreAudit>,
    ) -> Result<ResponseConnection, FinalIntentError> {
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
            core,
        })
    }
}

/// A non-Clone root connection scope retained by its actual native connection owner.
pub(crate) struct ResponseConnection {
    service: Arc<ResponseIntentService>,
    generation: u64,
    stream: AtomicU64,
    core: Arc<CoreAudit>,
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
        record: ResponseRecord,
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
            core: Arc::clone(&self.core),
            deadline,
            watch: handles.watch,
            input: handles.input,
            cancel: handles.cancel,
            publisher: handles.release,
            cancelled: AtomicBool::new(false),
            frozen: Mutex::new(None),
            state: tokio::sync::Mutex::new(FinalState {
                record: Some(record),
                ticket: None,
                published: false,
            }),
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
        let mut frozen = lock(&self.scope.frozen);
        if frozen.is_some() {
            return Err(FinalIntentError::Integrity);
        }
        self.scope
            .publisher
            .freeze(intent.key, intent.final_publication_ordinal)?;
        *frozen = Some(intent);
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

struct ResponseScope {
    key: ResponseKey,
    core: Arc<CoreAudit>,
    deadline: Instant,
    watch: DeliveryWatch,
    input: DeliveryInput,
    cancel: DeliveryCancel,
    publisher: ReleasePublisher,
    cancelled: AtomicBool,
    frozen: Mutex<Option<FinalResponseIntent>>,
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

struct FinalState {
    /// What this response still has to record; taken by the first finalize that records it.
    record: Option<ResponseRecord>,
    /// The outbox ticket of a committed record handed over, awaited by a retry.
    ticket: Option<busbar_kernel::outbox::Ticket>,
    published: bool,
}

/// Observation of the reserved control submission; neither case is a delivery receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleasePublication {
    Published,
    AlreadyPublished,
}

/// Root-private publication authority retained by the native response supervisor.
pub(crate) struct ResponseFinalizer {
    scope: Arc<ResponseScope>,
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

    /// Record what this response records (nothing, a count, or under `wait_for_commit` a line
    /// whose group commit it awaits) and publish its one release, independently of held E_END.
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
        if *lock(&self.scope.frozen) != Some(intent) {
            return Err(FinalIntentError::Integrity);
        }
        if state.published {
            return Ok(ReleasePublication::AlreadyPublished);
        }
        self.scope.check_live()?;
        match state.record.take() {
            None | Some(ResponseRecord::Nothing) => {}
            Some(ResponseRecord::Counted {
                listener,
                step,
                reason,
            }) => {
                let status = match intent.disposition {
                    ResponseDisposition::End { status } => status.unwrap_or(0),
                    ResponseDisposition::Refuse { status, .. } => status,
                };
                self.scope
                    .core
                    .count_refusal(&listener, step, reason, status);
            }
            Some(ResponseRecord::Committed(mut line)) => {
                if let ResponseDisposition::End {
                    status: Some(status),
                }
                | ResponseDisposition::Refuse { status, .. } = intent.disposition
                {
                    line.unit.status = status;
                }
                state.ticket = Some(self.scope.core.records().append_and_ask(*line));
            }
        }
        if let Some(ticket) = state.ticket {
            // The one wait of this kind on a request: only under `advanced.wait_for_commit`.
            self.scope.core.records().committed(ticket).await;
            self.scope.check_live()?;
        }
        self.scope
            .publisher
            .publish(intent.key, intent.final_publication_ordinal)?;
        state.published = true;
        Ok(ReleasePublication::Published)
    }
}
