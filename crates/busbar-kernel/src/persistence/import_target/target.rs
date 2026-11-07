// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Current format bootstrap, authority projection and exact activation changes.

use super::ImportError as Error;
use crate::persistence::{facade::WriterAuthority, startup};
use busbar_contract::{persistence::*, Secret};
use std::sync::Arc;

pub const FORMAT_OWNER: [u8; 16] = *b"busbar.core.v1\0\0";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetIdentity {
    pub dataset: DatasetId,
    pub owner: [u8; 16],
    pub physical: u32,
    pub logical: u32,
    pub codec: u32,
}
impl TargetIdentity {
    pub fn current(info: BackendInfo) -> Result<Self, Error> {
        if info.dataset.0 == [0; 16] || info.physical_version != 1 {
            return Err(Error::Identity);
        }
        Ok(Self {
            dataset: info.dataset,
            owner: FORMAT_OWNER,
            physical: 1,
            logical: 1,
            codec: 1,
        })
    }
}
pub struct ActivationRequest {
    pub target: TargetIdentity,
    pub authority: WriterAuthority,
}
pub struct ActivationChange {
    pub predicates: Vec<Predicate>,
    pub mutations: Vec<Mutation>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatRecord {
    pub dataset: DatasetId,
    pub registrar: WriterAuthority,
}
impl FormatRecord {
    pub fn encode(self) -> [u8; 80] {
        startup::Manifest {
            dataset: self.dataset,
            registrar: self.registrar,
        }
        .encode()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let value = startup::Manifest::decode(bytes).map_err(|_| Error::UnsupportedFormat)?;
        Ok(Self {
            dataset: value.dataset,
            registrar: value.registrar,
        })
    }
}
pub fn manifest_address() -> Address {
    startup::manifest_address()
}
pub fn root_address() -> Address {
    startup::root_address()
}
pub fn writer_address(writer: [u8; 16]) -> Address {
    startup::writer_address(writer)
}

pub struct TargetBootstrap {
    backend: Arc<dyn PersistenceBackend>,
    authority: WriterAuthority,
    operation: [u8; 16],
    pending: Option<crate::persistence::commit::Attempt>,
}

impl TargetBootstrap {
    pub fn new(
        backend: Arc<dyn PersistenceBackend>,
        authority: WriterAuthority,
        operation: [u8; 16],
    ) -> Result<Self, Error> {
        if authority.writer == [0; 16]
            || authority.writer_epoch != 1
            || authority.execution_epoch != 1
            || operation == [0; 16]
        {
            return Err(Error::Identity);
        }
        Ok(Self {
            backend,
            authority,
            operation,
            pending: None,
        })
    }

    /// One bounded step; Ready grants migration authority only. Unknown keeps
    /// the original initialization candidate and operation identity in custody.
    pub async fn advance(&mut self) -> Result<BootstrapProgress, Error> {
        use crate::persistence::commit::{Attempt, SubmitResult};
        if let Some(attempt) = &self.pending {
            match attempt.submit().await {
                SubmitResult::Uncertain | SubmitResult::Busy => {
                    return Ok(BootstrapProgress::Pending)
                }
                SubmitResult::Reconcile => return Err(Error::ReconciliationRequired),
                SubmitResult::NoEffect(failure) => return Err(Error::Backend(failure)),
                SubmitResult::Decided(value) => match value.as_ref() {
                    Decision::Applied(_) => self.pending = None,
                    Decision::ConditionConflict => return Err(Error::Conflict),
                    _ => return Err(Error::ReconciliationRequired),
                },
            }
        }
        let values = read(
            self.backend.as_ref(),
            vec![
                startup::root_address(),
                startup::manifest_address(),
                startup::writer_address(self.authority.writer),
            ],
        )
        .await?;
        if values[1].is_some() {
            return Err(Error::Conflict);
        }
        let seal = crate::seal::lend();
        match (&values[0], &values[2]) {
            (Some(root), Some(writer)) => {
                if control::Dataset::decode(root.expose(&seal))
                    != Some(control::Dataset {
                        id: self.backend.info().dataset,
                        writer_epoch: self.authority.writer_epoch,
                    })
                    || control::Writer::decode(writer.expose(&seal))
                        != Some(control::Writer {
                            retired_through: 0,
                            admitted_through: 1,
                        })
                {
                    return Err(Error::Identity);
                }
                Ok(BootstrapProgress::Ready)
            }
            (None, None) => {
                let candidate = crate::persistence::fences::initialize(
                    self.backend.info().dataset,
                    self.authority.writer,
                    self.operation,
                )
                .map_err(|_| Error::Corrupt)?;
                self.pending = Some(
                    Attempt::new(candidate, self.backend.clone()).map_err(|_| Error::Identity)?,
                );
                Ok(BootstrapProgress::Advanced)
            }
            _ => Err(Error::Corrupt),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapProgress {
    Advanced,
    Pending,
    Ready,
}

pub async fn require_offline(
    backend: &dyn PersistenceBackend,
    authority: WriterAuthority,
) -> Result<(), Error> {
    let values = read(
        backend,
        vec![
            startup::root_address(),
            startup::manifest_address(),
            startup::writer_address(authority.writer),
        ],
    )
    .await?;
    let seal = crate::seal::lend();
    if values[1].is_some() {
        return Err(Error::Conflict);
    }
    if values[0]
        .as_ref()
        .and_then(|v| control::Dataset::decode(v.expose(&seal)))
        != Some(control::Dataset {
            id: backend.info().dataset,
            writer_epoch: authority.writer_epoch,
        })
        || !values[2]
            .as_ref()
            .and_then(|v| control::Writer::decode(v.expose(&seal)))
            .is_some_and(|w| w.admits(authority.execution_epoch))
    {
        return Err(Error::Authority);
    }
    Ok(())
}

pub async fn prepare_activation(
    backend: &dyn PersistenceBackend,
    request: &ActivationRequest,
) -> Result<ActivationChange, Error> {
    if request.target != TargetIdentity::current(backend.info())? {
        return Err(Error::Identity);
    }
    let authority = request.authority;
    let addresses = vec![
        startup::root_address(),
        startup::manifest_address(),
        startup::writer_address(authority.writer),
    ];
    let values = read(backend, addresses.clone()).await?;
    let seal = crate::seal::lend();
    let prior = values[0].as_ref().ok_or(Error::Corrupt)?;
    let root = control::Dataset::decode(prior.expose(&seal)).ok_or(Error::Corrupt)?;
    let writer_bytes = values[2].as_ref().ok_or(Error::Corrupt)?;
    let writer = control::Writer::decode(writer_bytes.expose(&seal)).ok_or(Error::Corrupt)?;
    if root.id != backend.info().dataset
        || root.writer_epoch != authority.writer_epoch
        || !writer.admits(authority.execution_epoch)
        || values[1].is_some()
    {
        return Err(Error::Conflict);
    }
    let epoch = authority.writer_epoch.checked_add(1).ok_or(Error::Bounds)?;
    let published = startup::Manifest {
        dataset: root.id,
        registrar: WriterAuthority {
            writer_epoch: epoch,
            ..authority
        },
    };
    Ok(ActivationChange {
        predicates: vec![
            Predicate {
                address: addresses[0].clone(),
                expected: ExpectedValue::Exact(prior.clone()),
            },
            Predicate {
                address: addresses[1].clone(),
                expected: ExpectedValue::Absent,
            },
            Predicate {
                address: addresses[2].clone(),
                expected: ExpectedValue::Exact(writer_bytes.clone()),
            },
        ],
        mutations: vec![
            Mutation::Put {
                address: addresses[0].clone(),
                value: Secret::new(
                    control::Dataset {
                        writer_epoch: epoch,
                        ..root
                    }
                    .encode()
                    .ok_or(Error::Corrupt)?
                    .to_vec(),
                ),
            },
            Mutation::Put {
                address: addresses[1].clone(),
                value: Secret::new(published.encode().to_vec()),
            },
        ],
    })
}

pub fn validate_activation(
    change: &ActivationChange,
    request: &ActivationRequest,
) -> Result<(), Error> {
    if change.predicates.len() != 3 || change.mutations.len() != 2 {
        return Err(Error::Bounds);
    }
    let seal = crate::seal::lend();
    let root = root_address();
    let prior = change
        .predicates
        .iter()
        .find_map(|p| match &p.expected {
            ExpectedValue::Exact(v) if p.address == root => {
                control::Dataset::decode(v.expose(&seal))
            }
            _ => None,
        })
        .ok_or(Error::Corrupt)?;
    let next = change
        .mutations
        .iter()
        .find_map(|m| match m {
            Mutation::Put { address, value } if *address == root => {
                control::Dataset::decode(value.expose(&seal))
            }
            _ => None,
        })
        .ok_or(Error::Corrupt)?;
    if prior.id != request.target.dataset
        || prior.writer_epoch != request.authority.writer_epoch
        || next.id != prior.id
        || prior.writer_epoch.checked_add(1) != Some(next.writer_epoch)
    {
        return Err(Error::Authority);
    }
    let format = manifest_address();
    let published = change
        .mutations
        .iter()
        .find_map(|m| match m {
            Mutation::Put { address, value } if *address == format => {
                FormatRecord::decode(value.expose(&seal)).ok()
            }
            _ => None,
        })
        .ok_or(Error::Corrupt)?;
    if published.dataset != prior.id
        || published.registrar
            != (WriterAuthority {
                writer_epoch: next.writer_epoch,
                ..request.authority
            })
        || !change
            .predicates
            .iter()
            .any(|p| p.address == format && matches!(p.expected, ExpectedValue::Absent))
    {
        return Err(Error::Authority);
    }
    let writer = writer_address(request.authority.writer);
    if !change.predicates.iter().any(|p| {
        p.address == writer
            && match &p.expected {
                ExpectedValue::Exact(v) => control::Writer::decode(v.expose(&seal))
                    .is_some_and(|w| w.admits(request.authority.execution_epoch)),
                _ => false,
            }
    }) {
        return Err(Error::Authority);
    }
    Ok(())
}
/// Activated restart reads the atomic format/root pair. Caller-supplied epochs
/// are not authority after cutover, including after a lost activation reply.
pub async fn activated_authority(
    backend: &dyn PersistenceBackend,
) -> Result<WriterAuthority, Error> {
    let values = read(
        backend,
        vec![startup::root_address(), startup::manifest_address()],
    )
    .await?;
    let seal = crate::seal::lend();
    let root = values[0]
        .as_ref()
        .and_then(|v| control::Dataset::decode(v.expose(&seal)))
        .ok_or(Error::Corrupt)?;
    let format = startup::Manifest::decode(values[1].as_ref().ok_or(Error::Corrupt)?.expose(&seal))
        .map_err(|_| Error::Corrupt)?;
    if root.id != backend.info().dataset
        || format.dataset != root.id
        || format.registrar.writer_epoch != root.writer_epoch
    {
        return Err(Error::Identity);
    }
    let writer = read(
        backend,
        vec![startup::writer_address(format.registrar.writer)],
    )
    .await?;
    if !writer[0]
        .as_ref()
        .and_then(|v| control::Writer::decode(v.expose(&seal)))
        .is_some_and(|w| w.admits(format.registrar.execution_epoch))
    {
        return Err(Error::Authority);
    }
    Ok(format.registrar)
}

pub async fn offline_authority(
    backend: &dyn PersistenceBackend,
    writer: [u8; 16],
) -> Result<WriterAuthority, Error> {
    let values = read(
        backend,
        vec![
            startup::root_address(),
            startup::manifest_address(),
            startup::writer_address(writer),
        ],
    )
    .await?;
    if values[1].is_some() {
        return Err(Error::Conflict);
    }
    let seal = crate::seal::lend();
    let root = values[0]
        .as_ref()
        .and_then(|v| control::Dataset::decode(v.expose(&seal)))
        .ok_or(Error::Authority)?;
    let state = values[2]
        .as_ref()
        .and_then(|v| control::Writer::decode(v.expose(&seal)))
        .ok_or(Error::Authority)?;
    if root.id != backend.info().dataset || !state.admits(state.admitted_through) {
        return Err(Error::ReconciliationRequired);
    }
    Ok(WriterAuthority {
        writer,
        writer_epoch: root.writer_epoch,
        execution_epoch: state.admitted_through,
    })
}

async fn read(
    backend: &dyn PersistenceBackend,
    addresses: Vec<Address>,
) -> Result<Vec<Option<Secret<Vec<u8>>>>, Error> {
    let count = addresses.len();
    match backend
        .read(Arc::new(Read {
            dataset: backend.info().dataset,
            addresses,
            time: None,
        }))
        .await
        .map_err(Error::Backend)?
    {
        ReadResult::Values {
            observed_at,
            values,
        } if observed_at.authority == backend.info().clock_authority && values.len() == count => {
            Ok(values)
        }
        _ => Err(Error::Corrupt),
    }
}
