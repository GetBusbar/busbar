// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One retained document-publication owner around the actual startup candidate.
//! Prepare before App construction; publish only after its readiness receipt, before native Finish.
use super::{
    document_commit::{
        custody_locator, CheckpointCall, Checkpoints, EphemeralIntentProof, Inventory, Report,
    },
    documents::Documents,
};
use busbar_contract::{
    persistence::{axis::OpenedBackend, Durability, Failure},
    Secret,
};
use busbar_kernel::{durable::DurableFs, persistence::facade::CoreStore};
use busbar_migrations::{documents::StoreCheckpoints, Error, StartupUpgrade};
use sha2::{Digest, Sha256};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

const WAIT: Duration = Duration::from_secs(30);

/// These are the same backend and CoreStore already selected by native startup.
/// Authored locations come from the observed Documents inventory, not reconstructed file names.
pub struct Inputs {
    pub backend: OpenedBackend,
    pub core: Arc<CoreStore>,
    pub documents: Arc<Documents>,
    pub native_upgrade_id: [u8; 16],
    pub host: String,
    pub checkpoint_budget: usize,
    pub fs: Arc<dyn DurableFs>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareProgress {
    Pending,
    Ready,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishProgress {
    Pending,
    Complete,
}
/// Even Pending returns its custody owner. Resume this same value rather than constructing anew.
pub struct Preparation {
    pub publication: Publication,
    pub progress: PrepareProgress,
}

enum Prepared {
    Durable([u8; 32]),
    Ephemeral(Inventory, EphemeralIntentProof),
}
type Preparing = Pin<Box<dyn Future<Output = Result<Prepared, String>> + Send>>;
type Publishing = Pin<Box<dyn Future<Output = Result<Report, String>> + Send>>;

pub struct Publication {
    inputs: Inputs,
    scope: Option<[u8; 32]>,
    custody_id: Option<[u8; 16]>,
    checkpoints: Option<Arc<StoreCheckpoints>>,
    preparing: Option<Preparing>,
    prepared: Option<Prepared>,
    publishing: Option<Publishing>,
    readiness: Option<[u8; 32]>,
    report: Option<Report>,
    complete: bool,
}

impl Publication {
    pub async fn prepare(
        upgrade: &mut StartupUpgrade,
        inputs: Inputs,
    ) -> Result<Preparation, String> {
        if inputs.backend.info() != inputs.core.info() || inputs.native_upgrade_id == [0; 16] {
            return Err("document publication does not match the admitted startup backend".into());
        }
        let scope = if inputs.core.info().durability == Durability::Ephemeral {
            None
        } else {
            Some(custody_locator(&inputs.documents, &inputs.host)?)
        };
        let mut publication = Self {
            inputs,
            scope,
            custody_id: None,
            checkpoints: None,
            preparing: None,
            prepared: None,
            publishing: None,
            readiness: None,
            report: None,
            complete: false,
        };
        let progress = publication.prepare_more(upgrade).await?;
        Ok(Preparation {
            publication,
            progress,
        })
    }

    /// One bounded step. Native registration and checkpoint attempts remain owned across Pending.
    pub async fn prepare_more(
        &mut self,
        upgrade: &mut StartupUpgrade,
    ) -> Result<PrepareProgress, String> {
        if self.prepared.is_some() {
            return Ok(PrepareProgress::Ready);
        }
        if self.inputs.core.info().durability == Durability::Ephemeral {
            let (inventory, proof) =
                Inventory::prepare_ephemeral(&self.inputs.documents, self.inputs.fs.as_ref())?;
            inventory.materialize_ephemeral_secrets(&proof)?;
            self.prepared = Some(Prepared::Ephemeral(inventory, proof));
            return Ok(PrepareProgress::Ready);
        }
        if self.checkpoints.is_none() {
            if self.custody_id.is_none() {
                let found = match tokio::time::timeout(
                    WAIT,
                    StoreCheckpoints::discover(
                        self.inputs.backend.clone(),
                        self.scope.expect("durable document location bound"),
                        self.inputs.checkpoint_budget,
                    ),
                )
                .await
                {
                    Err(_) => return Ok(PrepareProgress::Pending),
                    Ok(Err(error)) if retryable(error) => return Ok(PrepareProgress::Pending),
                    Ok(Err(error)) => return Err(native_error(error)),
                    Ok(Ok(found)) => found,
                };
                self.custody_id = Some(match found {
                    Some(found) => found.migration,
                    None => {
                        let mut digest = Sha256::new();
                        digest.update(b"busbar.startup.document-custody.1\0");
                        digest.update(self.scope.expect("durable document location bound"));
                        digest.update(self.inputs.backend.info().dataset.0);
                        digest.update(self.inputs.native_upgrade_id);
                        let hash: [u8; 32] = digest.finalize().into();
                        hash[..16]
                            .try_into()
                            .expect("fixed document identity width")
                    }
                });
            }
            let custody_id = self.custody_id.expect("retained document identity");
            if custody_id == [0; 16] || custody_id == self.inputs.native_upgrade_id {
                return Err("document custody must have a dedicated nonzero identity".into());
            }
            let authority = self.inputs.core.authority().map_err(|_| {
                "admitted document writer authority could not be observed".to_string()
            })?;
            let custody = match tokio::time::timeout(
                WAIT,
                upgrade.document_custody(custody_id, authority, self.inputs.checkpoint_budget),
            )
            .await
            {
                Err(_) => return Ok(PrepareProgress::Pending),
                Ok(Err(error)) if retryable(error) => return Ok(PrepareProgress::Pending),
                Ok(Err(error)) => return Err(native_error(error)),
                Ok(Ok(None)) => return Ok(PrepareProgress::Pending),
                Ok(Ok(Some(custody))) => custody,
            };
            if custody.backend().info() != self.inputs.core.info()
                || custody.authority() != authority
                || custody.custody_id() != custody_id
            {
                return Err("document checkpoint custody belongs to another startup owner".into());
            }
            self.checkpoints = Some(Arc::new(
                StoreCheckpoints::new(
                    custody.backend(),
                    custody.authority(),
                    custody.intent(),
                    self.scope.expect("durable document location bound"),
                    self.inputs.checkpoint_budget,
                )
                .map_err(native_error)?,
            ));
        }
        let checkpoints = self
            .checkpoints
            .as_ref()
            .expect("checkpoint owner installed")
            .clone();
        if self.preparing.is_none() {
            let checkpoints = checkpoints.clone();
            let documents = self.inputs.documents.clone();
            let fs = self.inputs.fs.clone();
            let id = self.custody_id.expect("retained document identity");
            self.preparing = Some(Box::pin(async move {
                let (inventory, proof) =
                    Inventory::prepare(&documents, fs.as_ref(), checkpoints.as_ref(), id).await?;
                inventory.materialize_secrets(&proof)?;
                Ok(Prepared::Durable(inventory.digest()))
            }));
        }
        let result = tokio::time::timeout(
            WAIT,
            self.preparing
                .as_mut()
                .expect("retained document preparation")
                .as_mut(),
        )
        .await;
        match result {
            Err(_) => Ok(PrepareProgress::Pending),
            Ok(result) => {
                self.preparing = None;
                match result {
                    Ok(prepared) => {
                        self.prepared = Some(prepared);
                        Ok(PrepareProgress::Ready)
                    }
                    Err(_) if checkpoints.has_pending() => Ok(PrepareProgress::Pending),
                    Err(error) => Err(error),
                }
            }
        }
    }

    /// Call after the actual candidate's readiness receipt and before StartupUpgrade::finalize.
    /// A different receipt cannot take over an unfinished publication.
    pub async fn publish_complete(
        &mut self,
        readiness: [u8; 32],
    ) -> Result<PublishProgress, String> {
        if readiness == [0; 32] || self.readiness.is_some_and(|old| old != readiness) {
            return Err("document publication readiness changed".into());
        }
        self.readiness = Some(readiness);
        if self.complete {
            return Ok(PublishProgress::Complete);
        }
        match self
            .prepared
            .as_ref()
            .ok_or("documents were not prepared before application construction")?
        {
            Prepared::Ephemeral(inventory, proof) => {
                let report = inventory.ephemeral_report(proof)?;
                self.inputs.documents.finish_upgrade()?;
                self.report = Some(report);
                self.complete = true;
                Ok(PublishProgress::Complete)
            }
            Prepared::Durable(digest) => {
                let checkpoints = self
                    .checkpoints
                    .as_ref()
                    .expect("durable checkpoint owner")
                    .clone();
                if self.publishing.is_none() {
                    let checkpoints = checkpoints.clone();
                    let documents = self.inputs.documents.clone();
                    let fs = self.inputs.fs.clone();
                    let id = self.custody_id.expect("retained document identity");
                    let expected_digest = *digest;
                    self.publishing = Some(Box::pin(async move {
                        // Preparation already confirmed intent; disappearance is not a new import.
                        if StoreCheckpoints::load(checkpoints.as_ref(), id)
                            .await
                            .map_err(native_error)?
                            .is_none()
                        {
                            return Err("confirmed document checkpoint disappeared".into());
                        }
                        let (inventory, intent) =
                            Inventory::prepare(&documents, fs.as_ref(), checkpoints.as_ref(), id)
                                .await?;
                        if inventory.digest() != expected_digest {
                            return Err(
                                "prepared document inventory changed before publication".into()
                            );
                        }
                        let validated = inventory.validated(intent, checkpoints.as_ref()).await?;
                        inventory
                            .publish(validated, checkpoints.as_ref(), fs.as_ref(), &documents)
                            .await
                    }));
                }
                let result = tokio::time::timeout(
                    WAIT,
                    self.publishing
                        .as_mut()
                        .expect("retained publication")
                        .as_mut(),
                )
                .await;
                match result {
                    Err(_) => Ok(PublishProgress::Pending),
                    Ok(result) => {
                        self.publishing = None;
                        match result {
                            Err(_) if checkpoints.has_pending() => Ok(PublishProgress::Pending),
                            Err(error) => Err(error),
                            Ok(report) if !report.complete => {
                                self.report = Some(report);
                                Ok(PublishProgress::Pending)
                            }
                            Ok(report) => {
                                self.inputs.documents.finish_upgrade()?;
                                self.report = Some(report);
                                self.complete = true;
                                Ok(PublishProgress::Complete)
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn report(&self) -> Option<&Report> {
        self.report.as_ref()
    }
}

fn retryable(error: Error) -> bool {
    matches!(
        error,
        Error::IntentPending
            | Error::Backend(Failure::Unknown | Failure::Unavailable | Failure::Overloaded)
    )
}
fn native_error(error: Error) -> String {
    format!("document checkpoint persistence refused: {error:?}")
}

// The root owns this trait; the migration library owns all native checkpoint mechanics.
impl Checkpoints for StoreCheckpoints {
    fn durability(&self) -> Durability {
        StoreCheckpoints::durability(self)
    }
    fn load(&self, migration: [u8; 16]) -> CheckpointCall<'_, Option<Secret<Vec<u8>>>> {
        Box::pin(async move {
            loop {
                match StoreCheckpoints::load(self, migration).await {
                    Err(error) if checkpoint_retryable(error) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    result => return result.map_err(native_error),
                }
            }
        })
    }
    fn confirm<'a>(
        &'a self,
        migration: [u8; 16],
        protected: &'a Secret<Vec<u8>>,
    ) -> CheckpointCall<'a, Secret<Vec<u8>>> {
        Box::pin(async move {
            loop {
                match StoreCheckpoints::confirm(self, migration, protected).await {
                    Err(error) if checkpoint_retryable(error) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    result => return result.map_err(native_error),
                }
            }
        })
    }
    fn complete<'a>(
        &'a self,
        migration: [u8; 16],
        protected: &'a Secret<Vec<u8>>,
    ) -> CheckpointCall<'a, Secret<Vec<u8>>> {
        Box::pin(async move {
            loop {
                match StoreCheckpoints::complete(self, migration, protected).await {
                    Err(error) if checkpoint_retryable(error) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    result => return result.map_err(native_error),
                }
            }
        })
    }
}

// Keep transient checkpoint outcomes inside the same inventory continuation.
// A bounded-out caller retains both this future and the native exact candidate.
fn checkpoint_retryable(error: Error) -> bool {
    retryable(error) || matches!(error, Error::Backend(Failure::StaleScan))
}
