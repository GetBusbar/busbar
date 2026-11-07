// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable NON-SECRET objects. Credential envelopes and other confidential
//! data MUST use their owner's replaceable inline records, never this API.
//! Generations are caller-assigned, never reused, and retained for cold fenced
//! maintenance; there is deliberately no online collection operation.

use std::{ops::Range, sync::Arc};

use busbar_contract::persistence::{
    Address, AttemptId, Candidate, DatasetId, ExpectedValue, Failure, InvalidCandidate, Mutation,
    NamespaceId, PersistenceBackend, Predicate, PreparedCandidate, Read, ReadResult,
    CANDIDATE_VERSION,
};
use busbar_contract::{plugin::KernelSeal, Secret};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Chunk payload size, independent of plane record limits.
pub const CHUNK_BYTES: usize = 64 * 1024;
const MAGIC: &[u8; 8] = b"BBOBJ01\0";
const MANIFEST_BYTES: usize = 72;
const CHUNK_KEY_BYTES: usize = 73;

/// A core-assigned binary object identity; no backend or text interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectId {
    pub dataset: DatasetId,
    pub namespace: NamespaceId,
    pub owner: [u8; 16],
    pub object: [u8; 16],
}

/// Content-free preparation, admission or read errors.
#[derive(Debug)]
pub enum ObjectError {
    Identity,
    Range,
    Budget,
    Allocation,
    Overflow,
    Corrupt,
    Backend(Failure),
    Candidate(InvalidCandidate),
}

#[derive(Debug, Clone, Copy)]
struct Manifest {
    generation: [u8; 16],
    total_len: u64,
    chunk_count: u64,
    digest: [u8; 32],
}
impl Manifest {
    fn encode(self) -> [u8; MANIFEST_BYTES] {
        let mut bytes = [0; MANIFEST_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(&self.generation);
        bytes[24..32].copy_from_slice(&self.total_len.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.chunk_count.to_le_bytes());
        bytes[40..].copy_from_slice(&self.digest);
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, ObjectError> {
        if bytes.len() != MANIFEST_BYTES || &bytes[..8] != MAGIC {
            return Err(ObjectError::Corrupt);
        }
        let manifest = Self {
            generation: bytes[8..24].try_into().map_err(|_| ObjectError::Corrupt)?,
            total_len: u64::from_le_bytes(
                bytes[24..32].try_into().map_err(|_| ObjectError::Corrupt)?,
            ),
            chunk_count: u64::from_le_bytes(
                bytes[32..40].try_into().map_err(|_| ObjectError::Corrupt)?,
            ),
            digest: bytes[40..].try_into().map_err(|_| ObjectError::Corrupt)?,
        };
        if manifest.generation == [0; 16] || manifest.chunk_count != count(manifest.total_len) {
            return Err(ObjectError::Corrupt);
        }
        Ok(manifest)
    }
}
fn count(length: u64) -> u64 {
    length / CHUNK_BYTES as u64 + u64::from(!length.is_multiple_of(CHUNK_BYTES as u64))
}
fn admit(required: usize, budget: usize) -> Result<(), ObjectError> {
    if required > budget {
        Err(ObjectError::Budget)
    } else {
        Ok(())
    }
}
fn add(a: usize, b: usize) -> Result<usize, ObjectError> {
    a.checked_add(b).ok_or(ObjectError::Overflow)
}
fn mul(a: usize, b: usize) -> Result<usize, ObjectError> {
    a.checked_mul(b).ok_or(ObjectError::Overflow)
}
fn copy(bytes: &[u8]) -> Result<Secret<Vec<u8>>, ObjectError> {
    let mut value = Zeroizing::new(Vec::new());
    value
        .try_reserve_exact(bytes.len())
        .map_err(|_| ObjectError::Allocation)?;
    value.extend_from_slice(bytes);
    Ok(Secret::new(std::mem::take(&mut *value)))
}
impl ObjectId {
    fn address(self, generation: Option<([u8; 16], u64)>) -> Result<Address, ObjectError> {
        let mut key = Vec::new();
        key.try_reserve_exact(if generation.is_some() {
            CHUNK_KEY_BYTES
        } else {
            49
        })
        .map_err(|_| ObjectError::Allocation)?;
        key.push(if generation.is_some() { b'c' } else { b'm' });
        key.extend_from_slice(&self.dataset.0);
        key.extend_from_slice(&self.owner);
        key.extend_from_slice(&self.object);
        if let Some((generation, index)) = generation {
            key.extend_from_slice(&generation);
            key.extend_from_slice(&index.to_be_bytes());
        }
        Ok(Address {
            namespace: self.namespace.0,
            key,
        })
    }
}

/// Unpublished immutable source; Debug never exposes its body.
#[derive(Debug)]
pub struct PreparedObject {
    id: ObjectId,
    manifest: Manifest,
    bytes: Secret<Vec<u8>>,
}
impl PreparedObject {
    /// Number of immutable chunks; empty objects need no chunk candidates.
    #[must_use]
    pub fn chunk_count(&self) -> u64 {
        self.manifest.chunk_count
    }

    /// Explicitly classify the source as NON-SECRET. Confidential credentials,
    /// including encrypted credential envelopes, are prohibited. The caller must
    /// supply a unique immutable nonzero generation (not a timestamp).
    /// Budget counts the copied payload; the borrowed source and stack are excluded.
    pub fn prepare_non_secret<S: KernelSeal + ?Sized>(
        id: ObjectId,
        generation: [u8; 16],
        source: &Secret<Vec<u8>>,
        allocation_budget: usize,
        seal: &S,
    ) -> Result<Self, ObjectError> {
        if generation == [0; 16] {
            return Err(ObjectError::Identity);
        }
        let source = source.expose(seal);
        admit(source.len(), allocation_budget)?;
        let total_len = u64::try_from(source.len()).map_err(|_| ObjectError::Overflow)?;
        Ok(Self {
            id,
            manifest: Manifest {
                generation,
                total_len,
                chunk_count: count(total_len),
                digest: Sha256::digest(source).into(),
            },
            bytes: copy(source)?,
        })
    }

    /// Build one immutable batch. Caller submits through `commit::Attempt`; no
    /// retry or dispatch occurs here. Budget covers owned payload/keys/descriptors,
    /// candidate validation scratch and Arc storage, excluding this source.
    pub fn chunk_candidate<S: KernelSeal + ?Sized>(
        &self,
        id: AttemptId,
        range: Range<u64>,
        allocation_budget: usize,
        seal: &S,
    ) -> Result<PreparedCandidate, ObjectError> {
        if id.dataset != self.id.dataset {
            return Err(ObjectError::Identity);
        }
        if range.start >= range.end || range.end > self.manifest.chunk_count {
            return Err(ObjectError::Range);
        }
        let n = usize::try_from(range.end - range.start).map_err(|_| ObjectError::Overflow)?;
        let start = usize::try_from(range.start)
            .map_err(|_| ObjectError::Overflow)?
            .checked_mul(CHUNK_BYTES)
            .ok_or(ObjectError::Overflow)?;
        let end = if range.end == self.manifest.chunk_count {
            self.bytes.expose(seal).len()
        } else {
            usize::try_from(range.end)
                .map_err(|_| ObjectError::Overflow)?
                .checked_mul(CHUNK_BYTES)
                .ok_or(ObjectError::Overflow)?
        };
        let scratch =
            Candidate::<busbar_contract::redacted::Kernel>::validation_workspace_bytes(n, n)
                .ok_or(ObjectError::Overflow)?;
        let mut required = add(
            end - start,
            mul(
                n,
                2 * CHUNK_KEY_BYTES
                    + std::mem::size_of::<Predicate>()
                    + std::mem::size_of::<Mutation>(),
            )?,
        )?;
        required = add(
            required,
            add(
                scratch,
                std::mem::size_of::<Candidate>() + 2 * std::mem::size_of::<usize>(),
            )?,
        )?;
        admit(required, allocation_budget)?;
        let mut candidate = Candidate {
            id,
            codec: CANDIDATE_VERSION,
            predicates: Vec::new(),
            mutations: Vec::new(),
            time: None,
            result: Secret::default(),
        };
        candidate
            .predicates
            .try_reserve_exact(n)
            .map_err(|_| ObjectError::Allocation)?;
        candidate
            .mutations
            .try_reserve_exact(n)
            .map_err(|_| ObjectError::Allocation)?;
        for (offset, index) in range.enumerate() {
            let from = add(start, mul(offset, CHUNK_BYTES)?)?;
            let to = end.min(add(from, CHUNK_BYTES)?);
            candidate.predicates.push(Predicate {
                address: self.id.address(Some((self.manifest.generation, index)))?,
                expected: ExpectedValue::Absent,
            });
            candidate.mutations.push(Mutation::Put {
                address: self.id.address(Some((self.manifest.generation, index)))?,
                value: copy(&self.bytes.expose(seal)[from..to])?,
            });
        }
        PreparedCandidate::new(candidate).map_err(ObjectError::Candidate)
    }

    /// Verify uploaded immutable chunks before a publication capability exists.
    pub async fn verify<S: KernelSeal + ?Sized>(
        &self,
        backend: &dyn PersistenceBackend,
        chunks_per_batch: usize,
        allocation_budget: usize,
        seal: &S,
    ) -> Result<VerifiedObject, ObjectError> {
        verify(
            self.id,
            self.manifest,
            backend,
            chunks_per_batch,
            allocation_budget,
            seal,
        )
        .await
    }
}

/// Exact verified opaque bytes plus the private publication capability.
#[derive(Debug)]
pub struct VerifiedObject {
    id: ObjectId,
    manifest: Manifest,
    bytes: Secret<Vec<u8>>,
}
impl VerifiedObject {
    /// Borrow bytes only through existing kernel seal custody.
    pub fn bytes(&self) -> &Secret<Vec<u8>> {
        &self.bytes
    }

    /// Append atomic manifest compare-and-put to the caller's index/receipt plan.
    /// Budget covers newly added manifest/key storage and any vector growth
    /// (existing candidate contents are excluded). Validation remains the caller's
    /// `PreparedCandidate::new` responsibility after all indexes are appended.
    pub fn append_publication(
        &self,
        candidate: &mut Candidate,
        expected: ExpectedValue,
        allocation_budget: usize,
    ) -> Result<(), ObjectError> {
        if candidate.id.dataset != self.id.dataset {
            return Err(ObjectError::Identity);
        }
        let predicates = candidate
            .predicates
            .len()
            .checked_add(1)
            .ok_or(ObjectError::Overflow)?;
        let mutations = candidate
            .mutations
            .len()
            .checked_add(1)
            .ok_or(ObjectError::Overflow)?;
        let predicate_growth = if candidate.predicates.capacity() < predicates {
            mul(predicates, std::mem::size_of::<Predicate>())?
        } else {
            0
        };
        let mutation_growth = if candidate.mutations.capacity() < mutations {
            mul(mutations, std::mem::size_of::<Mutation>())?
        } else {
            0
        };
        admit(
            add(MANIFEST_BYTES + 98, add(predicate_growth, mutation_growth)?)?,
            allocation_budget,
        )?;
        let address = self.id.address(None)?;
        let mutation_address = self.id.address(None)?;
        let value = copy(&self.manifest.encode())?;
        candidate
            .predicates
            .try_reserve_exact(1)
            .map_err(|_| ObjectError::Allocation)?;
        candidate
            .mutations
            .try_reserve_exact(1)
            .map_err(|_| ObjectError::Allocation)?;
        candidate.predicates.push(Predicate { address, expected });
        candidate.mutations.push(Mutation::Put {
            address: mutation_address,
            value,
        });
        Ok(())
    }
}

/// Read the manifest once, then retain its immutable generation across all reads.
/// Absence is only possible for a missing manifest, never a missing chunk.
pub async fn read_non_secret<S: KernelSeal + ?Sized>(
    id: ObjectId,
    backend: &dyn PersistenceBackend,
    chunks_per_batch: usize,
    allocation_budget: usize,
    seal: &S,
) -> Result<Option<VerifiedObject>, ObjectError> {
    check_backend(id, backend)?;
    if chunks_per_batch == 0 {
        return Err(ObjectError::Range);
    }
    admit(
        MANIFEST_BYTES
            + 49
            + std::mem::size_of::<Address>()
            + std::mem::size_of::<Option<Secret<Vec<u8>>>>()
            + std::mem::size_of::<Read>()
            + 2 * std::mem::size_of::<usize>(),
        allocation_budget,
    )?;
    let mut addresses = Vec::new();
    addresses
        .try_reserve_exact(1)
        .map_err(|_| ObjectError::Allocation)?;
    addresses.push(id.address(None)?);
    let values = read_values(id, backend, addresses).await?;
    let Some(value) = values.into_iter().next().ok_or(ObjectError::Corrupt)? else {
        return Ok(None);
    };
    let manifest = Manifest::decode(value.expose(seal))?;
    drop(value);
    verify(
        id,
        manifest,
        backend,
        chunks_per_batch,
        allocation_budget,
        seal,
    )
    .await
    .map(Some)
}
fn check_backend(id: ObjectId, backend: &dyn PersistenceBackend) -> Result<(), ObjectError> {
    if backend.info().dataset != id.dataset {
        Err(ObjectError::Identity)
    } else {
        Ok(())
    }
}
async fn read_values(
    id: ObjectId,
    backend: &dyn PersistenceBackend,
    addresses: Vec<Address>,
) -> Result<Vec<Option<Secret<Vec<u8>>>>, ObjectError> {
    let count = addresses.len();
    match backend
        .read(Arc::new(Read {
            dataset: id.dataset,
            addresses,
            time: None,
        }))
        .await
        .map_err(ObjectError::Backend)?
    {
        ReadResult::Values { values, .. } if values.len() == count => Ok(values),
        _ => Err(ObjectError::Corrupt),
    }
}
async fn verify<S: KernelSeal + ?Sized>(
    id: ObjectId,
    manifest: Manifest,
    backend: &dyn PersistenceBackend,
    chunks_per_batch: usize,
    allocation_budget: usize,
    seal: &S,
) -> Result<VerifiedObject, ObjectError> {
    check_backend(id, backend)?;
    if chunks_per_batch == 0 {
        return Err(ObjectError::Range);
    }
    let length = usize::try_from(manifest.total_len).map_err(|_| ObjectError::Overflow)?;
    let batch = chunks_per_batch
        .min(usize::try_from(manifest.chunk_count).map_err(|_| ObjectError::Overflow)?);
    // Bound requested response payload and descriptor/key workspace, in addition
    // to the retained output. Backend-owned internal allocations are excluded;
    // malformed oversized responses are rejected before copying any bytes.
    let workspace = mul(
        batch,
        CHUNK_BYTES
            + CHUNK_KEY_BYTES
            + std::mem::size_of::<Address>()
            + std::mem::size_of::<Option<Secret<Vec<u8>>>>(),
    )?;
    admit(
        add(
            length,
            add(
                workspace,
                std::mem::size_of::<Read>() + 2 * std::mem::size_of::<usize>(),
            )?,
        )?,
        allocation_budget,
    )?;
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(length)
        .map_err(|_| ObjectError::Allocation)?;
    let mut hash = Sha256::new();
    let mut index = 0;
    while index < manifest.chunk_count {
        let n = (manifest.chunk_count - index)
            .min(u64::try_from(chunks_per_batch).map_err(|_| ObjectError::Overflow)?);
        let mut addresses = Vec::new();
        addresses
            .try_reserve_exact(n as usize)
            .map_err(|_| ObjectError::Allocation)?;
        for offset in 0..n {
            addresses.push(id.address(Some((manifest.generation, index + offset)))?);
        }
        let values = read_values(id, backend, addresses).await?;
        for value in values {
            let value = value.ok_or(ObjectError::Corrupt)?;
            let bytes = value.expose(seal);
            let remaining = length
                .checked_sub(output.len())
                .ok_or(ObjectError::Corrupt)?;
            if bytes.len() != remaining.min(CHUNK_BYTES) {
                return Err(ObjectError::Corrupt);
            }
            hash.update(bytes);
            output.extend_from_slice(bytes);
        }
        index += n;
    }
    if output.len() != length || <[u8; 32]>::from(hash.finalize()) != manifest.digest {
        return Err(ObjectError::Corrupt);
    }
    Ok(VerifiedObject {
        id,
        manifest,
        bytes: Secret::new(std::mem::take(&mut *output)),
    })
}

#[cfg(test)]
#[path = "objects_tests.rs"]
mod tests;
