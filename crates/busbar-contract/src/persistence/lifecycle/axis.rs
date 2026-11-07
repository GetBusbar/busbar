// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Retained native capabilities. None grants a serving business facade.
use super::{Error, Id, OpenBinding, Request, Response, UpgradeRef};
use crate::persistence::{axis::OpenedBackend, PersistenceBackend};
use std::{future::Future, pin::Pin, sync::Arc};

/// Native session phase, independent of the semantic upgrade checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Door bound; no native inspection session yet.
    Bound,
    /// Read-only native session retained; ordinary OPEN is closed.
    Prepared,
    /// An inactive target is available only through its migration capability.
    Upgrading,
    /// Physical selection permits only checkpoint-bound recovery OPEN.
    RecoveryReady,
    /// Confirmed current checkpoint permits serving exposure.
    Open,
}
/// One immutable native response shared without duplicating protected source rows.
pub type BootstrapCall<'a> =
    Pin<Box<dyn Future<Output = Result<Arc<Response>, Error>> + Send + 'a>>;
/// A retained native preparation capability.
pub type Prepared = Arc<dyn PreparedStore>;
/// Door selection and preparation; ordinary OPEN is not executed.
pub type PrepareCall<'a> = Pin<Box<dyn Future<Output = Result<Prepared, Error>> + Send + 'a>>;
/// Existing primitive backend restricted to the retained inactive upgrade target.
pub trait MigrationTarget: PersistenceBackend {
    /// Durable upgrade whose session and target remain retained by this capability.
    fn upgrade_id(&self) -> Id;
}
/// Migration-only target, never an admitted serving facade.
pub type TargetBackend = Arc<dyn MigrationTarget>;
/// Obtain the target after an actual native Target response.
pub type TargetCall<'a> = Pin<Box<dyn Future<Output = Result<TargetBackend, Error>> + Send + 'a>>;
/// Exactly one OPEN of the retained native instance, including recovery-only OPEN.
pub type PreparedOpenCall<'a> =
    Pin<Box<dyn Future<Output = Result<OpenedBackend, Error>> + Send + 'a>>;
/// Session authority minted by the loader from the actual admitted native door.
/// Caller cancellation preserves the same immutable request and native operation;
/// no process-local token can recover authority after process loss.
pub trait PreparedStore: Send + Sync {
    /// Diagnostic phase; observing it grants no additional capability.
    fn phase(&self) -> Phase;
    /// Invoke a strict native request, retaining its exact bytes through replay.
    fn bootstrap(&self, request: Arc<Request>) -> BootstrapCall<'_>;
    /// Bind the existing primitives to this session's confirmed inactive generation.
    fn target(&self, upgrade: UpgradeRef) -> TargetCall<'_>;
    /// Adopt the same prepared instance into current or checkpoint-bound recovery OPEN.
    /// A recovery backend is usable only by the cold recovery owner.
    fn open(&self, binding: OpenBinding) -> PreparedOpenCall<'_>;
    /// Expose the same backend only after actual current/complete checkpoint confirmation.
    /// Recovery OPEN alone can never make this method succeed.
    fn serving(&self) -> Result<OpenedBackend, Error>;
}
