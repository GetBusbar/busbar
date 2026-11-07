// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native core-format publication. Copying targets have control records but no
//! serving format; normal Startup therefore refuses them. No CoreStore is
//! constructed here: confirmed activation still requires Startup registration
//! followed by the composition root's recovery and hydration barrier.

use std::sync::Arc;

use async_trait::async_trait;
use busbar_contract::persistence::*;
use sha2::{Digest, Sha256};

use super::{Activation, ActivationChange, Error, Manifest, State};
use busbar_kernel::persistence::{
    facade::WriterAuthority,
    import_target::{target as native, ImportError},
};

/// Public bootstrap custody derives from the frozen, validated plan identity,
/// never its reported progress. A restart can reconstruct the exact empty-target
/// initializer before any serving format or cold owner binding exists.
pub struct BootstrapIds {
    pub authority: WriterAuthority,
    pub cold_writer: super::Id,
    pub initialize_operation: super::Id,
    pub cold_registration_operation: super::Id,
}

impl BootstrapIds {
    pub fn for_plan(plan: &Manifest, registry: &super::Registry) -> Result<Self, Error> {
        plan.validate(registry)?;
        if plan.target.format != super::CORE_FORMAT {
            return Err(Error::IdentityMismatch);
        }
        let derive = |domain: &[u8]| -> Result<super::Id, Error> {
            let mut hash = Sha256::new();
            hash.update(domain);
            hash.update(plan.plan_digest());
            let digest = hash.finalize();
            let id: super::Id = digest[..16].try_into().map_err(|_| Error::Corrupt)?;
            if id == [0; 16] {
                return Err(Error::Corrupt);
            }
            Ok(id)
        };
        let writer = derive(b"busbar.migration.bootstrap.writer.v1\0")?;
        let cold_writer = derive(b"busbar.migration.intent.writer.v1\0")?;
        if writer == cold_writer {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            authority: WriterAuthority {
                writer,
                writer_epoch: 1,
                execution_epoch: 1,
            },
            cold_writer,
            initialize_operation: derive(b"busbar.migration.bootstrap.operation.v1\0")?,
            cold_registration_operation: derive(b"busbar.migration.intent.registration.v1\0")?,
        })
    }
}

/// Migration-only bootstrap delegates to the current target owner.
pub struct TargetBootstrap(native::TargetBootstrap);
pub use native::BootstrapProgress;
impl TargetBootstrap {
    pub fn new(
        backend: Arc<dyn PersistenceBackend>,
        authority: WriterAuthority,
        operation: super::Id,
    ) -> Result<Self, Error> {
        native::TargetBootstrap::new(backend, authority, operation)
            .map(Self)
            .map_err(import_error)
    }
    pub async fn advance(&mut self) -> Result<BootstrapProgress, Error> {
        self.0.advance().await.map_err(import_error)
    }
}
pub struct CoreActivation {
    backend: Arc<dyn PersistenceBackend>,
}
impl CoreActivation {
    pub fn new(backend: Arc<dyn PersistenceBackend>) -> Self {
        Self { backend }
    }
}
#[async_trait]
impl Activation for CoreActivation {
    async fn prepare(
        &self,
        manifest: &Manifest,
        authority: WriterAuthority,
    ) -> Result<ActivationChange, Error> {
        if manifest.state != State::TargetVerified
            || manifest.target.dataset != self.backend.info().dataset.0
            || manifest.target.format != super::CORE_FORMAT
        {
            return Err(Error::IdentityMismatch);
        }
        let request = native::ActivationRequest {
            target: native::TargetIdentity::current(self.backend.info()).map_err(import_error)?,
            authority,
        };
        let change = native::prepare_activation(self.backend.as_ref(), &request)
            .await
            .map_err(import_error)?;
        Ok(ActivationChange {
            predicates: change.predicates,
            mutations: change.mutations,
        })
    }
}
pub(super) async fn require_offline(
    backend: &dyn PersistenceBackend,
    authority: WriterAuthority,
) -> Result<(), Error> {
    native::require_offline(backend, authority)
        .await
        .map_err(import_error)
}
pub(super) async fn activated_authority(
    backend: &dyn PersistenceBackend,
) -> Result<WriterAuthority, Error> {
    native::activated_authority(backend)
        .await
        .map_err(import_error)
}
pub(super) async fn offline_authority(
    backend: &dyn PersistenceBackend,
    writer: super::Id,
) -> Result<WriterAuthority, Error> {
    native::offline_authority(backend, writer)
        .await
        .map_err(import_error)
}
pub(crate) fn import_error(error: ImportError) -> Error {
    match error {
        ImportError::Bounds => Error::Bounds,
        ImportError::Corrupt => Error::Corrupt,
        ImportError::UnsupportedFormat => Error::UnsupportedPath,
        ImportError::Identity => Error::IdentityMismatch,
        ImportError::Authority => Error::FenceRequired,
        ImportError::Conflict => Error::Conflict,
        ImportError::ReconciliationRequired => Error::ReconciliationRequired,
        ImportError::Backend(f) => Error::Backend(f),
    }
}
