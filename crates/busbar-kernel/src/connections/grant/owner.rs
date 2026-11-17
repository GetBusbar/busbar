// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Concrete orchestration over the protected Store intent producer. No operation
//! retries a remote mint, and no recovered receipt reconstructs a request.
use super::*;
use crate::governance::at_rest::AtRestKeys;
use crate::persistence::{
    boot_identity::WriterRetirements,
    caller_intents::{CallerIntents, Outcome},
    facade::CoreStore,
};
use busbar_plugin_abi::host_side::caller::Caller;
use busbar_ports::auth::{AuthPort, Identity, OutboundAnswer, UpstreamIn};
use busbar_ports::{CallCx, PortError};

pub struct CallerGrantOwner {
    records: GrantRecords,
    intents: Arc<CallerIntents>,
}

/// Cached credential provenance contains no grant plaintext and no send right.
#[derive(Clone)]
pub struct GrantEpoch {
    key: GrantKey,
    epoch: u64,
}
impl GrantEpoch {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn key(&self) -> &GrantKey {
        &self.key
    }
}

/// The original BEGIN's immutable exact predicate; callback cannot reread and
/// overwrite a revoke/reconnect that happened during the remote login.
pub struct ConnectionBinding {
    owner: Arc<CallerGrantOwner>,
    key: GrantKey,
    prior: Option<GrantSnapshot>,
}

/// Only a definitely Applied MintStart constructs this non-Clone capability.
pub struct MintPermit {
    owner: Arc<CallerGrantOwner>,
    snapshot: GrantSnapshot,
    operation: [u8; 16],
}
pub struct CallerCredentialAnswer {
    pub answer: OutboundAnswer,
    pub epoch: GrantEpoch,
}

/// Host-created identity retained by the actual selected send and its permit.
/// This alone is not live-attempt authority: far_end must also consume its State
/// admission under the cancellation/retirement mutex after the Store await.
#[derive(Clone)]
pub struct DeliveryIdentity(Arc<()>);
impl Default for DeliveryIdentity {
    fn default() -> Self {
        Self::new()
    }
}
impl DeliveryIdentity {
    pub fn new() -> Self {
        Self(Arc::new(()))
    }
}
pub struct DeliveryPermit {
    identity: DeliveryIdentity,
    epoch: GrantEpoch,
}
impl DeliveryPermit {
    pub fn matches(&self, identity: &DeliveryIdentity) -> bool {
        Arc::ptr_eq(&self.identity.0, &identity.0)
    }
    /// Consumes the permit after the actual attempt owner accepted it. A caller
    /// must not call the connector merely because this identity matches.
    pub fn consume(self, identity: &DeliveryIdentity) -> Result<GrantEpoch, GrantError> {
        if !self.matches(identity) {
            return Err(GrantError::Stale);
        }
        Ok(self.epoch)
    }
}

impl CallerGrantOwner {
    /// Constructs real services, but does not publish them. Root must complete
    /// recovery and retain the writer/key barrier before enabling caller mode.
    pub fn new(
        store: Arc<CoreStore>,
        keys: &AtRestKeys,
        retirements: Arc<WriterRetirements>,
    ) -> Result<Arc<Self>, GrantError> {
        let codec = Arc::new(keys.caller_records(store.limits().scan_bytes)?);
        let records = GrantRecords::new(
            codec.clone(),
            store.info().dataset.0,
            store.info().atomic_domain,
        )?;
        let intents =
            CallerIntents::new(store, codec, retirements).map_err(|_| GrantError::Unavailable)?;
        Ok(Arc::new(Self { records, intents }))
    }
    pub async fn recover_page(&self) -> Result<bool, GrantError> {
        self.intents
            .recover_page()
            .await
            .map_err(|_| GrantError::Unavailable)
    }
    pub async fn maintain(&self, limit: usize) -> Result<usize, GrantError> {
        self.intents
            .maintain(limit)
            .await
            .map_err(|_| GrantError::Unavailable)
    }
    /// Caller and identity come from final native admission; upstream is selected
    /// frozen configuration, never a request-provided alias.
    pub fn key(
        plane: &Caller<'_>,
        identity: &Identity,
        upstream: &str,
    ) -> Result<GrantKey, GrantError> {
        if plane.kind != busbar_plugin_abi::types::KindCode::Plane {
            return Err(GrantError::Invalid);
        }
        GrantKey::new(plane.plugin, plane.name, identity.subject(), upstream)
    }
    async fn current(&self, key: &GrantKey) -> Result<Option<GrantSnapshot>, GrantError> {
        self.intents
            .read_current(key)
            .await
            .map_err(|_| GrantError::Unavailable)?
            .as_ref()
            .map(|row| self.records.decode(key, row))
            .transpose()
    }
    async fn apply(&self, change: ValidatedGrantChange) -> Result<GrantSnapshot, GrantError> {
        let key = change.key.clone();
        let successor = self.records.decode(&key, change.successor())?;
        let draft = self
            .intents
            .begin_operation()
            .map_err(|_| GrantError::Unavailable)?;
        let mut operation = draft
            .prepare(change)
            .await
            .map_err(|_| GrantError::Unavailable)?;
        match operation
            .drive()
            .await
            .map_err(|_| GrantError::Unavailable)?
        {
            Outcome::Applied => Ok(successor),
            Outcome::NoEffect | Outcome::Superseded => Err(GrantError::Stale),
            Outcome::Pending | Outcome::Reconcile => Err(GrantError::Unavailable),
        }
    }
    pub async fn load(&self, key: &GrantKey) -> Result<GrantEpoch, GrantError> {
        let snapshot = self
            .current(key)
            .await?
            .ok_or(GrantError::ConnectRequired)?;
        match snapshot.version.state {
            GrantState::Live => {}
            GrantState::Minting => return Err(GrantError::Unavailable),
            GrantState::ReconnectRequired | GrantState::Revoked => {
                return Err(GrantError::ConnectRequired)
            }
        }
        Ok(GrantEpoch {
            key: key.clone(),
            epoch: snapshot.version.epoch,
        })
    }
    pub async fn begin_connection(
        self: &Arc<Self>,
        key: GrantKey,
    ) -> Result<ConnectionBinding, GrantError> {
        let prior = self.current(&key).await?;
        Ok(ConnectionBinding {
            owner: self.clone(),
            key,
            prior,
        })
    }
    /// Explicit revoke creates a tombstone even if the initial grant was absent.
    pub async fn revoke(&self, key: &GrantKey) -> Result<(), GrantError> {
        let mut draft = self
            .intents
            .begin_operation()
            .map_err(|_| GrantError::Unavailable)?;
        // The keyed draft owns the shared local fence before its first Store
        // read; it may read through its own fence, but no competing call may.
        let row = draft
            .read_current(key)
            .await
            .map_err(|_| GrantError::Unavailable)?;
        let prior = row
            .as_ref()
            .map(|row| self.records.decode(key, row))
            .transpose()?;
        let change = self.records.revoke(key, prior.as_ref())?;
        let mut operation = draft
            .prepare(change)
            .await
            .map_err(|_| GrantError::Unavailable)?;
        match operation
            .drive()
            .await
            .map_err(|_| GrantError::Unavailable)?
        {
            Outcome::Applied => Ok(()),
            Outcome::NoEffect | Outcome::Superseded => Err(GrantError::Stale),
            Outcome::Pending | Outcome::Reconcile => Err(GrantError::Unavailable),
        }
    }
    pub async fn acquire_mint(
        self: &Arc<Self>,
        epoch: &GrantEpoch,
    ) -> Result<MintPermit, GrantError> {
        let prior = self
            .current(&epoch.key)
            .await?
            .ok_or(GrantError::Unavailable)?;
        if prior.version.epoch != epoch.epoch {
            return Err(GrantError::Stale);
        }
        let draft = self
            .intents
            .begin_operation()
            .map_err(|_| GrantError::Unavailable)?;
        let operation_id = draft.id();
        let change = self.records.start_mint(&prior, operation_id)?;
        let snapshot = self.records.decode(&prior.key, change.successor())?;
        let mut operation = draft
            .prepare(change)
            .await
            .map_err(|_| GrantError::Unavailable)?;
        match operation
            .drive()
            .await
            .map_err(|_| GrantError::Unavailable)?
        {
            Outcome::Applied => Ok(MintPermit {
                owner: self.clone(),
                snapshot,
                operation: operation_id,
            }),
            Outcome::NoEffect | Outcome::Superseded => Err(GrantError::Stale),
            Outcome::Pending | Outcome::Reconcile => Err(GrantError::Unavailable),
        }
    }
    pub async fn admit_delivery(
        &self,
        epoch: &GrantEpoch,
        identity: DeliveryIdentity,
    ) -> Result<DeliveryPermit, GrantError> {
        let prior = self
            .current(&epoch.key)
            .await?
            .ok_or(GrantError::Unavailable)?;
        self.apply(self.records.delivery(&prior, epoch.epoch)?)
            .await?;
        Ok(DeliveryPermit {
            identity,
            epoch: epoch.clone(),
        })
    }
}
impl ConnectionBinding {
    /// Only the native configured login completion may call this host method.
    /// It preserves the BEGIN predicate across cancellation/revoke/reconnect.
    pub async fn complete(self, grant: SecureVec) -> Result<GrantEpoch, GrantError> {
        let changed = self
            .owner
            .records
            .install(&self.key, self.prior.as_ref(), &grant)?;
        let applied = self.owner.apply(changed).await?;
        Ok(GrantEpoch {
            key: self.key,
            epoch: applied.version.epoch,
        })
    }
}
impl MintPermit {
    /// One actual port call. Consuming self prevents foreground/scope callers
    /// lending this remotely rotating grant twice. Cancellation leaves Minting.
    pub async fn mint(
        self,
        port: &dyn AuthPort,
        cx: CallCx,
        request: UpstreamIn<'_>,
    ) -> Result<CallerCredentialAnswer, GrantError> {
        let input = UpstreamIn {
            caller_grant: Some(&self.snapshot.grant),
            ..request
        };
        let mut answer = match port.outbound(cx, &input).await {
            Ok(answer) => answer,
            Err(error) => {
                let connect_required = matches!(
                    error,
                    PortError::Refused {
                        code: busbar_plugin_abi::fail::refused::R_CONNECT_REQUIRED,
                        ..
                    }
                );
                let change = if connect_required {
                    let mut change = self
                        .owner
                        .records
                        .revoke(&self.snapshot.key, Some(&self.snapshot))?;
                    change.purpose = GrantPurpose::RevokeCurrent;
                    change
                } else {
                    self.owner
                        .records
                        .reconnect_required(&self.snapshot, self.operation)?
                };
                // A failed settlement leaves Minting as a durable denial barrier.
                self.owner.apply(change).await?;
                return Err(if connect_required {
                    GrantError::ConnectRequired
                } else {
                    GrantError::Unavailable
                });
            }
        };
        let update = answer.grant_update.take();
        let change =
            self.owner
                .records
                .finish_mint(&self.snapshot, self.operation, update.as_deref())?;
        let applied = self.owner.apply(change).await?;
        Ok(CallerCredentialAnswer {
            answer,
            epoch: GrantEpoch {
                key: applied.key,
                epoch: applied.version.epoch,
            },
        })
    }
}
