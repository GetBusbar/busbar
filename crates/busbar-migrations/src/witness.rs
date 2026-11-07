// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable step witnesses survive receipt collection and checkpoint progress.
//! The body fingerprint excludes the witness itself to avoid a recursive hash;
//! the final native fingerprint still covers every witness byte and predicate.

use busbar_contract::{persistence::*, Secret};

use super::{Error, Id};

pub(super) fn address(migration: Id, operation: Id) -> Address {
    let mut key = Vec::with_capacity(33);
    key.push(b's');
    key.extend_from_slice(&migration);
    key.extend_from_slice(&operation);
    Address {
        namespace: super::coordinator::NAMESPACE,
        key,
    }
}

pub(super) fn attach(mut candidate: Candidate, migration: Id) -> Result<PreparedCandidate, Error> {
    let base = PreparedCandidate::new(copy(&candidate)).map_err(|_| Error::Corrupt)?;
    let marker = value(candidate.id, migration, base.fingerprint());
    let address = address(migration, candidate.id.operation);
    candidate.predicates.push(Predicate {
        address: address.clone(),
        expected: ExpectedValue::Absent,
    });
    candidate.mutations.push(Mutation::Put {
        address,
        value: Secret::new(marker),
    });
    PreparedCandidate::new(candidate).map_err(|_| Error::Corrupt)
}

pub(super) fn expected(
    candidate: &PreparedCandidate,
    migration: Id,
) -> Result<Secret<Vec<u8>>, Error> {
    let body = candidate.candidate();
    let address = address(migration, body.id.operation);
    if !body
        .predicates
        .iter()
        .any(|p| p.address == address && matches!(p.expected, ExpectedValue::Absent))
    {
        return Err(Error::ReconciliationRequired);
    }
    let marker = body
        .mutations
        .iter()
        .find_map(|m| match m {
            Mutation::Put {
                address: target,
                value,
            } if *target == address => Some(value),
            _ => None,
        })
        .ok_or(Error::ReconciliationRequired)?;
    let mut base = copy(body);
    base.predicates.retain(|p| p.address != address);
    base.mutations.retain(|m| match m {
        Mutation::Put {
            address: target, ..
        } => *target != address,
        _ => true,
    });
    let base = PreparedCandidate::new(base).map_err(|_| Error::Corrupt)?;
    if marker.expose(&crate::seal::lend()) != &value(body.id, migration, base.fingerprint()) {
        return Err(Error::Corrupt);
    }
    Ok(marker.clone())
}

fn value(id: AttemptId, migration: Id, fingerprint: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(120);
    bytes.extend_from_slice(b"BSMSTEP1");
    bytes.extend_from_slice(&id.dataset.0);
    bytes.extend_from_slice(&migration);
    bytes.extend_from_slice(&id.writer_epoch.to_le_bytes());
    bytes.extend_from_slice(&id.writer);
    bytes.extend_from_slice(&id.execution_epoch.to_le_bytes());
    bytes.extend_from_slice(&id.operation);
    bytes.extend_from_slice(&fingerprint);
    bytes
}

fn copy(body: &Candidate) -> Candidate {
    Candidate {
        id: body.id,
        codec: body.codec,
        predicates: body
            .predicates
            .iter()
            .map(|p| Predicate {
                address: p.address.clone(),
                expected: match &p.expected {
                    ExpectedValue::Absent => ExpectedValue::Absent,
                    ExpectedValue::Exact(value) => ExpectedValue::Exact(value.clone()),
                },
            })
            .collect(),
        mutations: body
            .mutations
            .iter()
            .map(|m| match m {
                Mutation::Put { address, value } => Mutation::Put {
                    address: address.clone(),
                    value: value.clone(),
                },
                Mutation::Delete(address) => Mutation::Delete(address.clone()),
                Mutation::DeleteRange {
                    namespace,
                    prefix,
                    exact_key_length,
                } => Mutation::DeleteRange {
                    namespace: *namespace,
                    prefix: prefix.clone(),
                    exact_key_length: *exact_key_length,
                },
            })
            .collect(),
        time: body.time,
        result: body.result.clone(),
    }
}
